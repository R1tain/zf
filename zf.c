#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <netdb.h>
#include <linux/icmp.h>
#include <linux/if.h>
#include <dirent.h>
#include <pthread.h>
#include <stdarg.h>

#define SESSION_DIR "/var/run/zf_sessions"
#define LOG_FILE "/var/log/zf.log"
#define MAX_EVENTS 10
#define INITIAL_BUFFER_SIZE 4096
#define MAX_BUFFER_SIZE 65536
#define MAX_SESSIONS 100
#define MIN_INTERVAL 1
#define MIN_TIMEOUT 1
#define MAX_RETRIES 10

typedef struct {
    char id[64];
    pid_t pid;
    char ip_version[8];
    char local_addr[INET6_ADDRSTRLEN];
    int local_port;
    char remote_host[256];
    int remote_port;
    char protocols[16];
    int check_interval;
    int timeout;
} Session;

typedef struct {
    char *data;
    size_t size;
    size_t capacity;
} DynamicBuffer;

typedef struct {
    Session session;
    int running;
    FILE *log_fp;
    int control_fd;
    pthread_t check_thread;
    pthread_t quality_thread;
    struct {
        uint64_t active_connections;
        uint64_t total_connections;
        uint64_t bytes_transferred;
    } stats;
} PortForwarder;

static PortForwarder *global_f = NULL;

DynamicBuffer *create_buffer() {
    DynamicBuffer *buf = malloc(sizeof(DynamicBuffer));
    if (!buf) return NULL;
    buf->data = malloc(INITIAL_BUFFER_SIZE);
    if (!buf->data) { free(buf); return NULL; }
    buf->size = 0;
    buf->capacity = INITIAL_BUFFER_SIZE;
    return buf;
}

void resize_buffer(DynamicBuffer *buf, size_t new_size) {
    if (new_size > buf->capacity) {
        size_t new_capacity = buf->capacity * 2;
        if (new_capacity < new_size) new_capacity = new_size;
        if (new_capacity > MAX_BUFFER_SIZE) new_capacity = MAX_BUFFER_SIZE;
        char *new_data = realloc(buf->data, new_capacity);
        if (new_data) {
            buf->data = new_data;
            buf->capacity = new_capacity;
        }
    }
}

void free_buffer(DynamicBuffer *buf) {
    if (buf) {
        free(buf->data);
        free(buf);
    }
}

void log_message(PortForwarder *f, const char *fmt, ...) {
    time_t now = time(NULL);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    FILE *fp = f->log_fp ? f->log_fp : stderr;

    va_list args;
    va_start(args, fmt);
    char msg[1024];
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);

    fprintf(fp, "%s [%s] %s\n", timestamp, f->session.id, msg);
    if (fp != stderr) fflush(fp);
}

void delete_session(PortForwarder *f);

void cleanup(PortForwarder *f) {
    if (f->running) {
        f->running = 0;
        if (f->check_thread) {
            pthread_cancel(f->check_thread);
            pthread_join(f->check_thread, NULL);
            f->check_thread = 0;
        }
        if (f->quality_thread) {
            pthread_cancel(f->quality_thread);
            pthread_join(f->quality_thread, NULL);
            f->quality_thread = 0;
        }
        delete_session(f);
        if (f->control_fd >= 0) {
            close(f->control_fd);
            f->control_fd = -1;
        }
        if (f->log_fp && f->log_fp != stderr) {
            fclose(f->log_fp);
            f->log_fp = NULL;
        }
    }
}

void signal_handler(int sig) {
    if (global_f) {
        log_message(global_f, sig == SIGUSR1 ? "连接失败策略触发，终止会话" : "收到信号，终止会话");
        cleanup(global_f);
    }
    exit(0);
}

void print_help(int verbose) {
    printf("zf Port Forwarding Tool\n\n");
    printf("用法:\n");
    printf("  zf <ip_version> <local_addr>:<local_port> <remote_addr>:<remote_port> [-p protocols] [-c interval] [-t timeout]\n");
    printf("  zf -ls\n");
    printf("  zf -k <session_id>\n");
    printf("  zf -h [--verbose]\n\n");
    if (!verbose) {
        printf("使用 zf -h --verbose 查看详细帮助。\n");
        return;
    }
    printf("参数说明:\n");
    printf("  <ip_version>         : IP 协议版本，可选 v4（IPv4）、v6（IPv6）、both（IPv4 和 IPv6）。\n");
    printf("  <local_addr>:<local_port> : 本地监听地址和端口，如 0.0.0.0:8080，端口范围 1-65535。\n");
    printf("  <remote_addr>:<remote_port> : 远程目标地址和端口，如 example.com:80，端口范围 1-65535。\n");
    printf("  -p <protocols>       : 转发协议，可选 tcp、udp 或 tcp,udp（默认：tcp,udp）。\n");
    printf("  -c <interval>        : 检查远程主机连通性的间隔（秒，默认：30，最小：1）。\n");
    printf("                        - 若连续 10 次失败，终止会话。\n");
    printf("  -t <timeout>         : 连接空闲超时时间（秒，默认：0，无超时，最小：1）。\n");
    printf("                        - 超时后关闭连接，主进程继续监听。\n");
    printf("  -ls                  : 列出当前活动会话，包括连接数和流量统计。\n");
    printf("  -k <session_id>      : 终止指定会话，清理会话文件。\n");
    printf("  -h [--verbose]       : 显示帮助信息，--verbose 显示详细说明。\n");
    printf("\n示例:\n");
    printf("  zf v4 0.0.0.0:8080 example.com:80 -p tcp,udp -c 30 -t 30\n");
    printf("  zf -ls\n");
    printf("  zf -k 12345-0.0.0.0:8080-1623456789\n");
    printf("  zf -h --verbose\n");
    printf("\n日志存储在 /var/log/zf.log，由 /etc/logrotate.d/zf 管理（每周轮转，保留 4 个备份）。\n");
}

int create_socket(PortForwarder *f, const char *addr, int port, const char *ip_version, const char *proto) {
    int family = (strcmp(ip_version, "v6") == 0) ? AF_INET6 : AF_INET;
    int type = (strcmp(proto, "tcp") == 0) ? SOCK_STREAM : SOCK_DGRAM;
    int sock = socket(family, type, 0);
    if (sock < 0) {
        log_message(f, "创建套接字失败: %s", strerror(errno));
        return -1;
    }

    int opt = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        log_message(f, "设置 SO_REUSEADDR 失败: %s", strerror(errno));
        close(sock);
        return -1;
    }
#ifdef TCP_FASTOPEN
    if (strcmp(proto, "tcp") == 0) {
        if (setsockopt(sock, IPPROTO_TCP, TCP_FASTOPEN, &opt, sizeof(opt)) < 0) {
            log_message(f, "设置 TCP_FASTOPEN 失败: %s", strerror(errno));
        }
    }
#endif

    if (family == AF_INET) {
        struct sockaddr_in saddr = {0};
        saddr.sin_family = AF_INET;
        saddr.sin_port = htons(port);
        if (inet_pton(AF_INET, addr, &saddr.sin_addr) <= 0) {
            log_message(f, "无效的 IPv4 地址: %s", addr);
            close(sock);
            return -1;
        }
        if (bind(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
            log_message(f, "绑定地址失败: %s", strerror(errno));
            close(sock);
            return -1;
        }
    } else {
        struct sockaddr_in6 saddr = {0};
        saddr.sin6_family = AF_INET6;
        saddr.sin6_port = htons(port);
        if (inet_pton(AF_INET6, addr, &saddr.sin6_addr) <= 0) {
            log_message(f, "无效的 IPv6 地址: %s", addr);
            close(sock);
            return -1;
        }
        if (bind(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
            log_message(f, "绑定地址失败: %s", strerror(errno));
            close(sock);
            return -1;
        }
    }

    if (strcmp(proto, "tcp") == 0 && listen(sock, SOMAXCONN) < 0) {
        log_message(f, "监听失败: %s", strerror(errno));
        close(sock);
        return -1;
    }
    return sock;
}

int connect_remote(PortForwarder *f, const char *host, int port, const char *ip_version, const char *proto) {
    struct addrinfo hints = {0}, *res;
    hints.ai_family = (strcmp(ip_version, "v6") == 0) ? AF_INET6 : AF_INET;
    hints.ai_socktype = (strcmp(proto, "tcp") == 0) ? SOCK_STREAM : SOCK_DGRAM;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);
    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        log_message(f, "解析地址 %s 失败: %s", host, strerror(errno));
        return -1;
    }

    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) {
        log_message(f, "创建远程套接字失败: %s", strerror(errno));
        freeaddrinfo(res);
        return -1;
    }

    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        log_message(f, "连接远程主机 %s:%d 失败: %s", host, port, strerror(errno));
        close(sock);
        freeaddrinfo(res);
        return -1;
    }

    freeaddrinfo(res);
    return sock;
}

void handle_tcp_connection(PortForwarder *f, int client_fd, const char *remote_host, int remote_port, const char *ip_version) {
    int remote_fd = connect_remote(f, remote_host, remote_port, ip_version, "tcp");
    if (remote_fd < 0) {
        close(client_fd);
        return;
    }

    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        log_message(f, "无法创建 epoll: %s", strerror(errno));
        close(client_fd);
        close(remote_fd);
        return;
    }

    struct epoll_event ev, events[2];
    ev.events = EPOLLIN;
    ev.data.fd = client_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev);
    ev.data.fd = remote_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, remote_fd, &ev);

    DynamicBuffer *buf = create_buffer();
    if (!buf) {
        log_message(f, "无法分配缓冲区");
        close(epoll_fd);
        close(client_fd);
        close(remote_fd);
        return;
    }

    time_t last_activity = time(NULL);
    f->stats.total_connections++;
    f->stats.active_connections++;

    while (f->running) {
        int nfds = epoll_wait(epoll_fd, events, 2, f->session.timeout * 1000);
        if (nfds < 0) {
            if (errno == EINTR) continue;
            log_message(f, "epoll_wait 失败: %s", strerror(errno));
            break;
        } else if (nfds == 0 && f->session.timeout) {
            if (time(NULL) - last_activity >= f->session.timeout) {
                log_message(f, "TCP 连接空闲超时，关闭连接");
                break;
            }
            continue;
        }

        for (int i = 0; i < nfds; i++) {
            int fd = events[i].data.fd;
            int other_fd = (fd == client_fd) ? remote_fd : client_fd;
            resize_buffer(buf, INITIAL_BUFFER_SIZE);
            ssize_t n = read(fd, buf->data, buf->capacity);
            if (n <= 0) goto cleanup;
            if (write(other_fd, buf->data, n) <= 0) goto cleanup;
            last_activity = time(NULL);
            f->stats.bytes_transferred += n;
        }
    }

cleanup:
    f->stats.active_connections--;
    free_buffer(buf);
    close(client_fd);
    close(remote_fd);
    close(epoll_fd);
}

void handle_udp(PortForwarder *f, int local_fd, const char *remote_host, int remote_port, const char *ip_version) {
    int remote_fd = connect_remote(f, remote_host, remote_port, ip_version, "udp");
    if (remote_fd < 0) {
        close(local_fd);
        return;
    }

    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        log_message(f, "无法创建 epoll: %s", strerror(errno));
        close(local_fd);
        close(remote_fd);
        return;
    }

    struct epoll_event ev, events[2];
    ev.events = EPOLLIN;
    ev.data.fd = local_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, local_fd, &ev);
    ev.data.fd = remote_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, remote_fd, &ev);

    DynamicBuffer *buf = create_buffer();
    if (!buf) {
        log_message(f, "无法分配缓冲区");
        close(epoll_fd);
        close(local_fd);
        close(remote_fd);
        return;
    }

    struct sockaddr_storage client_addr;
    socklen_t addr_len = sizeof(client_addr);
    time_t last_activity = time(NULL);
    f->stats.total_connections++;
    f->stats.active_connections++;

    while (f->running) {
        int nfds = epoll_wait(epoll_fd, events, 2, f->session.timeout * 1000);
        if (nfds < 0) {
            if (errno == EINTR) continue;
            log_message(f, "epoll_wait 失败: %s", strerror(errno));
            break;
        } else if (nfds == 0 && f->session.timeout) {
            if (time(NULL) - last_activity >= f->session.timeout) {
                log_message(f, "UDP 连接空闲超时，关闭连接");
                break;
            }
            continue;
        }

        for (int i = 0; i < nfds; i++) {
            int fd = events[i].data.fd;
            resize_buffer(buf, INITIAL_BUFFER_SIZE);
            if (fd == local_fd) {
                ssize_t n = recvfrom(local_fd, buf->data, buf->capacity, 0, (struct sockaddr *)&client_addr, &addr_len);
                if (n <= 0) continue;
                if (send(remote_fd, buf->data, n, 0) <= 0) continue;
                f->stats.bytes_transferred += n;
            } else {
                ssize_t n = recv(remote_fd, buf->data, buf->capacity, 0);
                if (n <= 0) continue;
                if (sendto(local_fd, buf->data, n, 0, (struct sockaddr *)&client_addr, addr_len) <= 0) continue;
                f->stats.bytes_transferred += n;
            }
            last_activity = time(NULL);
        }
    }

    f->stats.active_connections--;
    free_buffer(buf);
    close(local_fd);
    close(remote_fd);
    close(epoll_fd);
}

int check_connection(PortForwarder *f) {
    int sock = connect_remote(f, f->session.remote_host, f->session.remote_port, f->session.ip_version, "tcp");
    if (sock < 0) {
        return 0;
    }
    struct timeval start, end;
    gettimeofday(&start, NULL);
    close(sock);
    gettimeofday(&end, NULL);
    double latency = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_usec - start.tv_usec) / 1000.0;
    char msg[64];
    snprintf(msg, sizeof(msg), "连接正常，延迟: %.2fms", latency);
    log_message(f, "%s", msg);
    return 1;
}

void *check_connection_thread(void *arg) {
    PortForwarder *f = (PortForwarder *)arg;
    pthread_cleanup_push((void (*)(void *))fclose, f->log_fp);
    int fail_count = 0;
    while (f->running) {
        if (!check_connection(f)) {
            fail_count++;
            log_message(f, "尝试重新连接...");
            if (fail_count >= MAX_RETRIES) {
                log_message(f, "连续 10 次连接失败，终止会话");
                f->running = 0;
                kill(getpid(), SIGUSR1);
                break;
            }
            sleep(5);
        } else {
            fail_count = 0;
            sleep(f->session.check_interval);
        }
    }
    pthread_cleanup_pop(1);
    return NULL;
}

void monitor_quality(PortForwarder *f) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        log_message(f, "无法创建 ICMP 套接字: %s", strerror(errno));
        return;
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, f->session.remote_host, &addr.sin_addr) <= 0) {
        log_message(f, "无效的远程地址: %s", f->session.remote_host);
        close(sock);
        return;
    }

    while (f->running) {
        struct icmphdr icmp = {0};
        icmp.type = ICMP_ECHO;
        icmp.un.echo.id = getpid() & 0xffff;
        icmp.un.echo.sequence = 1;
        icmp.checksum = 0;

        struct timeval start, end;
        gettimeofday(&start, NULL);
        if (sendto(sock, &icmp, sizeof(icmp), 0, (struct sockaddr *)&addr, sizeof(addr)) <= 0) {
            log_message(f, "ICMP 发送失败: %s", strerror(errno));
        } else {
            char buf[1500];
            if (recv(sock, buf, sizeof(buf), 0) > 0) {
                gettimeofday(&end, NULL);
                double latency = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_usec - start.tv_usec) / 1000.0;
                char msg[64];
                snprintf(msg, sizeof(msg), "链路质量: 延迟 %.2fms", latency);
                log_message(f, "%s", msg);
            } else {
                log_message(f, "ICMP 接收失败: %s", strerror(errno));
            }
        }
        sleep(60);
    }
    close(sock);
}

void *monitor_quality_thread(void *arg) {
    PortForwarder *f = (PortForwarder *)arg;
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        log_message(f, "无法创建 ICMP 套接字: %s", strerror(errno));
        return NULL;
    }
    pthread_cleanup_push((void (*)(void *))close, (void *)(intptr_t)sock);
    pthread_cleanup_push((void (*)(void *))fclose, f->log_fp);
    monitor_quality(f);
    pthread_cleanup_pop(1);
    pthread_cleanup_pop(1);
    return NULL;
}

void save_session(PortForwarder *f) {
    char path[256];
    snprintf(path, sizeof(path), "%s/%s.session", SESSION_DIR, f->session.id);
    FILE *fp = fopen(path, "w");
    if (!fp) {
        log_message(f, "无法保存会话: %s", strerror(errno));
        return;
    }
    fprintf(fp, "ID: %s\nPID: %d\nIPVersion: %s\nLocal: %s:%d\nRemote: %s:%d\nProtocols: %s\nTimeout: %d\n",
            f->session.id, f->session.pid, f->session.ip_version,
            f->session.local_addr, f->session.local_port,
            f->session.remote_host, f->session.remote_port,
            f->session.protocols, f->session.timeout);
    fclose(fp);
}

void delete_session(PortForwarder *f) {
    char session_path[256];
    char sock_path[256];
    snprintf(session_path, sizeof(session_path), "%s/%s.session", SESSION_DIR, f->session.id);
    snprintf(sock_path, sizeof(sock_path), "%s/%s.sock", SESSION_DIR, f->session.id);
    if (unlink(session_path) < 0 && errno != ENOENT) {
        log_message(f, "删除会话文件失败: %s", strerror(errno));
    }
    if (unlink(sock_path) < 0 && errno != ENOENT) {
        log_message(f, "删除套接字文件失败: %s", strerror(errno));
    }
}

void handle_control_socket(PortForwarder *f) {
    struct sockaddr_un client_addr;
    socklen_t addr_len = sizeof(client_addr);
    char buffer[16];

    while (f->running) {
        int client_fd = accept(f->control_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (client_fd < 0) {
            if (errno != EINTR) log_message(f, "接受控制连接失败: %s", strerror(errno));
            continue;
        }

        ssize_t n = read(client_fd, buffer, sizeof(buffer) - 1);
        if (n > 0) {
            buffer[n] = '\0';
            if (strcmp(buffer, "kill") == 0) {
                log_message(f, "收到关闭命令，终止会话");
                cleanup(f);
                exit(0);
            }
        }
        close(client_fd);
    }
}

int init_session(PortForwarder *f) {
    f->running = 1;
    f->control_fd = -1;
    f->check_thread = 0;
    f->quality_thread = 0;
    f->stats.active_connections = 0;
    f->stats.total_connections = 0;
    f->stats.bytes_transferred = 0;
    return 0;
}

void start_forwarding(PortForwarder *f) {
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        log_message(f, "无法创建 epoll: %s", strerror(errno));
        cleanup(f);
        exit(1);
    }

    char *protos[] = {NULL, NULL};
    int proto_count = 0;
    if (strstr(f->session.protocols, "tcp")) protos[proto_count++] = "tcp";
    if (strstr(f->session.protocols, "udp")) protos[proto_count++] = "udp";

    struct {
        int fd;
        char *proto;
        char *addr;
    } sockets[4];
    int socket_count = 0;

    const char *addrs[] = {f->session.local_addr, "::"};
    int addr_count = (strcmp(f->session.ip_version, "both") == 0) ? 2 : 1;
    if (strcmp(f->session.ip_version, "v6") == 0) addrs[0] = "::";

    for (int i = 0; i < addr_count; i++) {
        for (int j = 0; j < proto_count; j++) {
            int sock = create_socket(f, addrs[i], f->session.local_port, f->session.ip_version, protos[j]);
            if (sock >= 0) {
                sockets[socket_count].fd = sock;
                sockets[socket_count].proto = protos[j];
                sockets[socket_count].addr = (char *)addrs[i];
                socket_count++;
                struct epoll_event ev = {0};
                ev.events = EPOLLIN;
                ev.data.fd = sock;
                epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock, &ev);
            }
        }
    }

    char control_path[256];
    snprintf(control_path, sizeof(control_path), "%s/%s.sock", SESSION_DIR, f->session.id);
    unlink(control_path);
    f->control_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (f->control_fd < 0) {
        log_message(f, "创建控制套接字失败: %s", strerror(errno));
        close(epoll_fd);
        cleanup(f);
        exit(1);
    }

    struct sockaddr_un control_addr = {0};
    control_addr.sun_family = AF_UNIX;
    strncpy(control_addr.sun_path, control_path, sizeof(control_addr.sun_path) - 1);
    if (bind(f->control_fd, (struct sockaddr *)&control_addr, sizeof(control_addr)) < 0 ||
        listen(f->control_fd, 5) < 0) {
        log_message(f, "控制套接字启动失败: %s", strerror(errno));
        close(epoll_fd);
        close(f->control_fd);
        cleanup(f);
        exit(1);
    }

    struct epoll_event ev = {0};
    ev.events = EPOLLIN;
    ev.data.fd = f->control_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, f->control_fd, &ev);

    save_session(f);

    if (pthread_create(&f->check_thread, NULL, check_connection_thread, f) != 0) {
        log_message(f, "创建检查线程失败: %s", strerror(errno));
        close(epoll_fd);
        close(f->control_fd);
        cleanup(f);
        exit(1);
    }

    if (pthread_create(&f->quality_thread, NULL, monitor_quality_thread, f) != 0) {
        log_message(f, "创建监控线程失败: %s", strerror(errno));
        pthread_cancel(f->check_thread);
        close(epoll_fd);
        close(f->control_fd);
        cleanup(f);
        exit(1);
    }

    struct epoll_event events[MAX_EVENTS];
    while (f->running) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (nfds < 0) {
            if (errno == EINTR) continue;
            log_message(f, "epoll_wait 失败: %s", strerror(errno));
            break;
        }

        for (int i = 0; i < nfds; i++) {
            int fd = events[i].data.fd;
            if (fd == f->control_fd) {
                handle_control_socket(f);
            } else {
                for (int j = 0; j < socket_count; j++) {
                    if (fd == sockets[j].fd) {
                        if (strcmp(sockets[j].proto, "tcp") == 0) {
                            struct sockaddr_storage client_addr;
                            socklen_t addr_len = sizeof(client_addr);
                            int client_fd = accept(fd, (struct sockaddr *)&client_addr, &addr_len);
                            if (client_fd >= 0) {
                                pid_t pid = fork();
                                if (pid == 0) {
                                    close(epoll_fd);
                                    handle_tcp_connection(f, client_fd, f->session.remote_host,
                                                        f->session.remote_port, f->session.ip_version);
                                    exit(0);
                                }
                                close(client_fd);
                            }
                        } else {
                            pid_t pid = fork();
                            if (pid == 0) {
                                close(epoll_fd);
                                handle_udp(f, fd, f->session.remote_host,
                                         f->session.remote_port, f->session.ip_version);
                                exit(0);
                            }
                        }
                    }
                }
            }
        }
    }

    for (int i = 0; i < socket_count; i++) close(sockets[i].fd);
    close(epoll_fd);
    cleanup(f);
}

void list_sessions(PortForwarder *f) {
    DIR *dir = opendir(SESSION_DIR);
    if (!dir) {
        fprintf(stderr, "无法打开会话目录: %s\n", SESSION_DIR);
        exit(1);
    }

    printf("活动会话:\n");
    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir))) {
        if (strstr(entry->d_name, ".session")) {
            char path[512];
            snprintf(path, sizeof(path), "%s/%s", SESSION_DIR, entry->d_name);
            FILE *fp = fopen(path, "r");
            if (fp) {
                char line[512];
                while (fgets(line, sizeof(line), fp)) {
                    printf("%s", line);
                }
                printf("统计: 活跃连接=%lu，总连接=%lu，流量=%lu 字节\n",
                       f->stats.active_connections, f->stats.total_connections, f->stats.bytes_transferred);
                fclose(fp);
                count++;
            }
        }
    }
    if (count == 0) {
        printf("没有活动会话\n");
    }
    closedir(dir);
}

void kill_session(PortForwarder *f, const char *session_id) {
    char control_path[256];
    snprintf(control_path, sizeof(control_path), "%s/%s.sock", SESSION_DIR, session_id);

    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        fprintf(stderr, "创建控制套接字失败: %s\n", strerror(errno));
        exit(1);
    }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, control_path, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "无法连接会话 %s: %s\n", session_id, strerror(errno));
        close(sock);
        exit(1);
    }

    if (write(sock, "kill", 4) < 0) {
        fprintf(stderr, "发送关闭命令失败: %s\n", strerror(errno));
        close(sock);
        exit(1);
    }

    close(sock);
    printf("会话 %s 已关闭\n", session_id);
}

int parse_args(int argc, char *argv[], PortForwarder *f, int *list_sessions_flag, char **kill_session_id, int *help_flag, int *verbose_flag) {
    char *protocols = "tcp,udp";
    int check_interval = 30;
    int timeout = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-ls") == 0) {
            *list_sessions_flag = 1;
        } else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
            *kill_session_id = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            protocols = argv[++i];
        } else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            check_interval = atoi(argv[++i]);
            if (check_interval < MIN_INTERVAL) return -1;
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            timeout = atoi(argv[++i]);
            if (timeout < MIN_TIMEOUT) return -1;
        } else if (strcmp(argv[i], "-h") == 0) {
            *help_flag = 1;
        } else if (strcmp(argv[i], "--verbose") == 0) {
            *verbose_flag = 1;
        }
    }

    if (*help_flag || *list_sessions_flag || *kill_session_id) return 0;
    if (argc < 4) return -1;

    strncpy(f->session.ip_version, argv[1], sizeof(f->session.ip_version) - 1);
    if (strcmp(f->session.ip_version, "v4") != 0 &&
        strcmp(f->session.ip_version, "v6") != 0 &&
        strcmp(f->session.ip_version, "both") != 0) return -1;

    char *local = argv[2];
    char *local_addr = strtok(local, ":");
    char *local_port_str = strtok(NULL, ":");
    if (!local_addr || !local_port_str) return -1;
    f->session.local_port = atoi(local_port_str);
    if (f->session.local_port < 1 || f->session.local_port > 65535) return -1;
    strncpy(f->session.local_addr, local_addr, sizeof(f->session.local_addr) - 1);

    char *remote = argv[3];
    char *remote_host = strtok(remote, ":");
    char *remote_port_str = strtok(NULL, ":");
    if (!remote_host || !remote_port_str) return -1;
    f->session.remote_port = atoi(remote_port_str);
    if (f->session.remote_port < 1 || f->session.remote_port > 65535) return -1;
    strncpy(f->session.remote_host, remote_host, sizeof(f->session.remote_host) - 1);

    strncpy(f->session.protocols, protocols, sizeof(f->session.protocols) - 1);
    f->session.check_interval = check_interval;
    f->session.timeout = timeout;
    snprintf(f->session.id, sizeof(f->session.id), "%d-%s-%ld", getpid(), local, time(NULL));
    f->session.pid = getpid();

    return 0;
}

int main(int argc, char *argv[]) {
    PortForwarder f = {0};
    f.log_fp = fopen(LOG_FILE, "a");
    if (!f.log_fp) {
        fprintf(stderr, "无法打开日志文件 %s: %s\n", LOG_FILE, strerror(errno));
        f.log_fp = stderr;
    }
    global_f = &f;

    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGUSR1, signal_handler);

    int list_sessions_flag = 0;
    char *kill_session_id = NULL;
    int help_flag = 0;
    int verbose_flag = 0;

    if (parse_args(argc, argv, &f, &list_sessions_flag, &kill_session_id, &help_flag, &verbose_flag) < 0) {
        fprintf(stderr, "参数错误\n");
        print_help(verbose_flag);
        if (f.log_fp != stderr) fclose(f.log_fp);
        return 1;
    }

    if (help_flag) {
        print_help(verbose_flag);
        if (f.log_fp != stderr) fclose(f.log_fp);
        return 0;
    }

    if (list_sessions_flag) {
        list_sessions(&f);
        if (f.log_fp != stderr) fclose(f.log_fp);
        return 0;
    }

    if (kill_session_id) {
        kill_session(&f, kill_session_id);
        if (f.log_fp != stderr) fclose(f.log_fp);
        return 0;
    }

    if (init_session(&f) < 0) {
        log_message(&f, "初始化会话失败");
        if (f.log_fp != stderr) fclose(f.log_fp);
        return 1;
    }

    if (getenv("ZF_DAEMON") == NULL) {
        setenv("ZF_DAEMON", "1", 1);
        pid_t pid = fork();
        if (pid < 0) {
            log_message(&f, "无法创建守护进程: %s", strerror(errno));
            if (f.log_fp != stderr) fclose(f.log_fp);
            return 1;
        }
        if (pid > 0) {
            printf("会话 %s 已启动，PID: %d\n", f.session.id, pid);
            if (f.log_fp != stderr) fclose(f.log_fp);
            return 0;
        }
        umask(0);
        setsid();
        chdir("/");
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
    }

    start_forwarding(&f);
    return 0;
}
