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

#define SESSION_DIR "/var/run/zf_sessions"
#define LOG_FILE "/var/log/zf.log"
#define MAX_EVENTS 10
#define BUFFER_SIZE 8192
#define MAX_SESSIONS 100

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
    int timeout; // 超时时间（秒）
} Session;

typedef struct {
    Session session;
    int running;
    FILE *log_fp;
    int control_fd;
    pid_t check_pid;
    pid_t quality_pid;
} PortForwarder;

static PortForwarder *global_f = NULL;

void log_message(PortForwarder *f, const char *msg) {
    time_t now = time(NULL);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    fprintf(f->log_fp, "%s - %s\n", timestamp, msg);
    fflush(f->log_fp);
}

void cleanup(PortForwarder *f) {
    if (f->running) {
        f->running = 0;
        if (f->check_pid > 0) kill(f->check_pid, SIGTERM);
        if (f->quality_pid > 0) kill(f->quality_pid, SIGTERM);
        delete_session(f);
        if (f->control_fd >= 0) close(f->control_fd);
        if (f->log_fp) fclose(f->log_fp);
    }
}

void signal_handler(int sig) {
    if (global_f) {
        log_message(global_f, "收到信号，终止会话");
        cleanup(global_f);
    }
    exit(0);
}

int create_socket(const char *addr, int port, const char *ip_version, const char *proto) {
    int family = (strcmp(ip_version, "v6") == 0) ? AF_INET6 : AF_INET;
    int type = (strcmp(proto, "tcp") == 0) ? SOCK_STREAM : SOCK_DGRAM;
    int sock = socket(family, type, 0);
    if (sock < 0) return -1;

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef TCP_FASTOPEN
    if (strcmp(proto, "tcp") == 0) {
        setsockopt(sock, IPPROTO_TCP, TCP_FASTOPEN, &opt, sizeof(opt));
    }
#endif

    if (family == AF_INET) {
        struct sockaddr_in saddr = {0};
        saddr.sin_family = AF_INET;
        saddr.sin_port = htons(port);
        inet_pton(AF_INET, addr, &saddr.sin_addr);
        if (bind(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
            close(sock);
            return -1;
        }
    } else {
        struct sockaddr_in6 saddr = {0};
        saddr.sin6_family = AF_INET6;
        saddr.sin6_port = htons(port);
        inet_pton(AF_INET6, addr, &saddr.sin6_addr);
        if (bind(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
            close(sock);
            return -1;
        }
    }

    if (strcmp(proto, "tcp") == 0 && listen(sock, SOMAXCONN) < 0) {
        close(sock);
        return -1;
    }
    return sock;
}

int connect_remote(const char *host, int port, const char *ip_version, const char *proto) {
    struct addrinfo hints = {0}, *res;
    hints.ai_family = (strcmp(ip_version, "v6") == 0) ? AF_INET6 : AF_INET;
    hints.ai_socktype = (strcmp(proto, "tcp") == 0) ? SOCK_STREAM : SOCK_DGRAM;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);
    if (getaddrinfo(host, port_str, &hints, &res) != 0) return -1;

    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) {
        freeaddrinfo(res);
        return -1;
    }

    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        close(sock);
        freeaddrinfo(res);
        return -1;
    }

    freeaddrinfo(res);
    return sock;
}

void handle_tcp_connection(PortForwarder *f, int client_fd, const char *remote_host, int remote_port, const char *ip_version) {
    int remote_fd = connect_remote(remote_host, remote_port, ip_version, "tcp");
    if (remote_fd < 0) {
        log_message(f, "无法连接远程主机");
        close(client_fd);
        return;
    }

    char buffer[BUFFER_SIZE];
    fd_set read_fds;
    int max_fd = (client_fd > remote_fd) ? client_fd : remote_fd;
    time_t last_activity = time(NULL);

    while (f->running) {
        FD_ZERO(&read_fds);
        FD_SET(client_fd, &read_fds);
        FD_SET(remote_fd, &read_fds);

        struct timeval tv = { .tv_sec = f->session.timeout, .tv_usec = 0 };
        int ret = select(max_fd + 1, &read_fds, NULL, NULL, f->session.timeout ? &tv : NULL);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        } else if (ret == 0 && f->session.timeout) {
            if (time(NULL) - last_activity >= f->session.timeout) {
                log_message(f, "TCP 连接空闲超时，关闭连接");
                break; // 仅关闭当前连接
            }
            continue;
        }

        if (FD_ISSET(client_fd, &read_fds)) {
            ssize_t n = read(client_fd, buffer, BUFFER_SIZE);
            if (n <= 0) break;
            if (write(remote_fd, buffer, n) <= 0) break;
            last_activity = time(NULL);
        }

        if (FD_ISSET(remote_fd, &read_fds)) {
            ssize_t n = read(remote_fd, buffer, BUFFER_SIZE);
            if (n <= 0) break;
            if (write(client_fd, buffer, n) <= 0) break;
            last_activity = time(NULL);
        }
    }

    close(client_fd);
    close(remote_fd);
}

void handle_udp(PortForwarder *f, int local_fd, const char *remote_host, int remote_port, const char *ip_version) {
    int remote_fd = connect_remote(remote_host, remote_port, ip_version, "udp");
    if (remote_fd < 0) {
        log_message(f, "无法连接远程主机");
        close(local_fd);
        return;
    }

    char buffer[BUFFER_SIZE];
    struct sockaddr_storage client_addr;
    socklen_t addr_len = sizeof(client_addr);
    time_t last_activity = time(NULL);

    while (f->running) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(local_fd, &read_fds);
        FD_SET(remote_fd, &read_fds);
        int max_fd = (local_fd > remote_fd) ? local_fd : remote_fd;

        struct timeval tv = { .tv_sec = f->session.timeout, .tv_usec = 0 };
        int ret = select(max_fd + 1, &read_fds, NULL, NULL, f->session.timeout ? &tv : NULL);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        } else if (ret == 0 && f->session.timeout) {
            if (time(NULL) - last_activity >= f->session.timeout) {
                log_message(f, "UDP 连接空闲超时，关闭连接");
                break; // 仅关闭当前连接
            }
            continue;
        }

        if (FD_ISSET(local_fd, &read_fds)) {
            ssize_t n = recvfrom(local_fd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &addr_len);
            if (n <= 0) continue;
            if (send(remote_fd, buffer, n, 0) <= 0) continue;
            last_activity = time(NULL);
        }

        if (FD_ISSET(remote_fd, &read_fds)) {
            ssize_t n = recv(remote_fd, buffer, BUFFER_SIZE, 0);
            if (n <= 0) continue;
            if (sendto(local_fd, buffer, n, 0, (struct sockaddr *)&client_addr, addr_len) <= 0) continue;
            last_activity = time(NULL);
        }
    }

    close(local_fd);
    close(remote_fd);
}

int check_connection(PortForwarder *f) {
    int sock = connect_remote(f->session.remote_host, f->session.remote_port, f->session.ip_version, "tcp");
    if (sock < 0) {
        log_message(f, "连接远程主机失败");
        return 0;
    }
    struct timeval start, end;
    gettimeofday(&start, NULL);
    close(sock);
    gettimeofday(&end, NULL);
    double latency = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_usec - start.tv_usec) / 1000.0;
    char msg[64];
    snprintf(msg, sizeof(msg), "连接正常，延迟: %.2fms", latency);
    log_message(f, msg);
    return 1;
}

void monitor_quality(PortForwarder *f) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        log_message(f, "无法创建 ICMP 套接字");
        fclose(f->log_fp);
        exit(0);
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, f->session.remote_host, &addr.sin_addr);

    while (f->running) {
        struct icmphdr icmp = {0};
        icmp.type = ICMP_ECHO;
        icmp.un.echo.id = getpid() & 0xffff;
        icmp.un.echo.sequence = 1;
        icmp.checksum = 0; // 内核会计算校验和

        struct timeval start, end;
        gettimeofday(&start, NULL);
        if (sendto(sock, &icmp, sizeof(icmp), 0, (struct sockaddr *)&addr, sizeof(addr)) <= 0) {
            log_message(f, "ICMP 发送失败");
        } else {
            char buf[1500];
            if (recv(sock, buf, sizeof(buf), 0) > 0) {
                gettimeofday(&end, NULL);
                double latency = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_usec - start.tv_usec) / 1000.0;
                char msg[64];
                snprintf(msg, sizeof(msg), "链路质量: 延迟 %.2fms", latency);
                log_message(f, msg);
            } else {
                log_message(f, "ICMP 接收失败");
            }
        }
        sleep(60);
    }
    close(sock);
    fclose(f->log_fp);
    exit(0);
}

void save_session(PortForwarder *f) {
    char path[256];
    snprintf(path, sizeof(path), "%s/%s.session", SESSION_DIR, f->session.id);
    FILE *fp = fopen(path, "w");
    if (!fp) {
        log_message(f, "无法保存会话");
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
    unlink(session_path);
    unlink(sock_path);
}

void handle_control_socket(PortForwarder *f) {
    struct sockaddr_un client_addr;
    socklen_t addr_len = sizeof(client_addr);
    char buffer[16];

    while (f->running) {
        int client_fd = accept(f->control_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (client_fd < 0) continue;

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

void start_forwarding(PortForwarder *f) {
    f->running = 1;

    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        log_message(f, "无法创建 epoll");
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
            int sock = create_socket(addrs[i], f->session.local_port, f->session.ip_version, protos[j]);
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

    // 控制套接字
    char control_path[256];
    snprintf(control_path, sizeof(control_path), "%s/%s.sock", SESSION_DIR, f->session.id);
    unlink(control_path);
    f->control_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un control_addr = {0};
    control_addr.sun_family = AF_UNIX;
    strncpy(control_addr.sun_path, control_path, sizeof(control_addr.sun_path) - 1);
    if (bind(f->control_fd, (struct sockaddr *)&control_addr, sizeof(control_addr)) < 0 ||
        listen(f->control_fd, 5) < 0) {
        log_message(f, "控制套接字启动失败");
        close(epoll_fd);
        cleanup(f);
        exit(1);
    }
    struct epoll_event ev = {0};
    ev.events = EPOLLIN;
    ev.data.fd = f->control_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, f->control_fd, &ev);

    save_session(f);

    // 检查连接和监控质量
    f->check_pid = fork();
    if (f->check_pid == 0) {
        while (f->running) {
            if (!check_connection(f)) {
                log_message(f, "尝试重新连接...");
                sleep(5);
            } else {
                sleep(f->session.check_interval);
            }
        }
        fclose(f->log_fp);
        exit(0);
    }

    f->quality_pid = fork();
    if (f->quality_pid == 0) {
        monitor_quality(f);
        exit(0);
    }

    // 主事件循环
    struct epoll_event events[MAX_EVENTS];
    while (f->running) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
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
                                    close(epoll_fd); // 子进程不需要 epoll
                                    handle_tcp_connection(f, client_fd, f->session.remote_host,
                                                        f->session.remote_port, f->session.ip_version);
                                    exit(0);
                                }
                                close(client_fd);
                            }
                        } else {
                            pid_t pid = fork();
                            if (pid == 0) {
                                close(epoll_fd); // 子进程不需要 epoll
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

void list_sessions() {
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
            char path[512]; // 增加缓冲区大小
            snprintf(path, sizeof(path), "%s/%s", SESSION_DIR, entry->d_name);
            FILE *fp = fopen(path, "r");
            if (fp) {
                char line[512];
                while (fgets(line, sizeof(line), fp)) {
                    printf("%s", line);
                }
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

void kill_session(const char *session_id) {
    char control_path[256];
    snprintf(control_path, sizeof(control_path), "%s/%s.sock", SESSION_DIR, session_id);

    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
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

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("用法: zf <ip_version> <local_addr>:<local_port> <remote_addr>:<remote_port> [-p protocols] [-c interval] [-t timeout]\n");
        printf("示例: zf v4 0.0.0.0:8080 example.com:80 -p tcp,udp -c 30 -t 30\n");
        printf("其他命令: zf -ls (列出会话), zf -k <session_id> (关闭会话)\n");
        return 1;
    }

    PortForwarder f = {0};
    f.log_fp = fopen(LOG_FILE, "a");
    if (!f.log_fp) {
        fprintf(stderr, "无法打开日志文件: %s\n", LOG_FILE);
        return 1;
    }
    f.control_fd = -1;
    global_f = &f;

    // 设置信号处理
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    int list_sessions_flag = 0;
    char *kill_session_id = NULL;
    char *protocols = "tcp,udp";
    int check_interval = 30;
    int timeout = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-ls") == 0) {
            list_sessions_flag = 1;
        } else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
            kill_session_id = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            protocols = argv[++i];
        } else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            check_interval = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            timeout = atoi(argv[++i]);
        }
    }

    if (list_sessions_flag) {
        list_sessions();
        fclose(f.log_fp);
        return 0;
    }

    if (kill_session_id) {
        kill_session(kill_session_id);
        fclose(f.log_fp);
        return 0;
    }

    if (argc < 4) {
        fprintf(stderr, "缺少必要参数\n");
        fclose(f.log_fp);
        return 1;
    }

    strncpy(f.session.ip_version, argv[1], sizeof(f.session.ip_version) - 1);
    if (strcmp(f.session.ip_version, "v4") != 0 &&
        strcmp(f.session.ip_version, "v6") != 0 &&
        strcmp(f.session.ip_version, "both") != 0) {
        fprintf(stderr, "错误: ip_version 必须是 v4, v6 或 both\n");
        fclose(f.log_fp);
        return 1;
    }

    char *local = argv[2];
    char *local_addr = strtok(local, ":");
    char *local_port_str = strtok(NULL, ":");
    if (!local_addr || !local_port_str) {
        fprintf(stderr, "错误: 本地地址格式必须是 <addr>:<port>\n");
        fclose(f.log_fp);
        return 1;
    }
    f.session.local_port = atoi(local_port_str);
    if (f.session.local_port < 1 || f.session.local_port > 65535) {
        fprintf(stderr, "错误: 本地端口必须在 1-65535 之间\n");
        fclose(f.log_fp);
        return 1;
    }
    strncpy(f.session.local_addr, local_addr, sizeof(f.session.local_addr) - 1);

    char *remote = argv[3];
    char *remote_host = strtok(remote, ":");
    char *remote_port_str = strtok(NULL, ":");
    if (!remote_host || !remote_port_str) {
        fprintf(stderr, "错误: 远程地址格式必须是 <addr>:<port>\n");
        fclose(f.log_fp);
        return 1;
    }
    f.session.remote_port = atoi(remote_port_str);
    if (f.session.remote_port < 1 || f.session.remote_port > 65535) {
        fprintf(stderr, "错误: 远程端口必须在 1-65535 之间\n");
        fclose(f.log_fp);
        return 1;
    }
    strncpy(f.session.remote_host, remote_host, sizeof(f.session.remote_host) - 1);

    strncpy(f.session.protocols, protocols, sizeof(f.session.protocols) - 1);
    f.session.check_interval = check_interval;
    f.session.timeout = timeout;

    snprintf(f.session.id, sizeof(f.session.id), "%d-%s-%ld", getpid(), local, time(NULL));
    f.session.pid = getpid();

    // 守护进程
    if (getenv("ZF_DAEMON") == NULL) {
        setenv("ZF_DAEMON", "1", 1);
        pid_t pid = fork();
        if (pid < 0) {
            fprintf(stderr, "无法创建守护进程: %s\n", strerror(errno));
            fclose(f.log_fp);
            return 1;
        }
        if (pid > 0) {
            printf("会话 %s 已启动，PID: %d\n", f.session.id, pid);
            fclose(f.log_fp);
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
