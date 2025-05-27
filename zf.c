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
#define MAX_EVENTS 256 // [MODIFIED] Increased for async model
#define BUFFER_SIZE 8192 // [MODIFIED] A single buffer size
#define MAX_CONNECTIONS 1024 // [NEW] Max concurrent connections support

// [NEW] Structure to manage a single client-to-remote connection
typedef struct {
    int client_fd;
    int remote_fd;
    char buffer[BUFFER_SIZE];
    size_t buffer_len;
    time_t last_activity;
    int is_udp;
    struct sockaddr_storage udp_client_addr;
    socklen_t udp_client_addr_len;
} Connection;

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
    Session session;
    FILE *log_fp;
    int control_fd;
    pthread_t check_thread;
    pthread_t quality_thread;
    int epoll_fd;
    int *listen_fds;
    int listen_fd_count;
    Connection *connections; // [NEW] Pool of connection objects
    struct {
        uint64_t active_connections;
        uint64_t total_connections;
        uint64_t bytes_transferred;
    } stats;
} PortForwarder;

// [NEW] Global flag for safe signal handling
static volatile sig_atomic_t g_quit_flag = 0;
static PortForwarder *global_f = NULL; // For signal handler access

void log_message(PortForwarder *f, const char *fmt, ...);
void cleanup(PortForwarder *f);
void delete_session_files(const char* session_id, FILE *log_fp);

// [NEW] Make a socket non-blocking
int make_socket_non_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, flags) == -1) return -1;
    return 0;
}

// [MODIFIED] Signal handler is now async-signal-safe
void signal_handler(int sig) {
    g_quit_flag = 1;
}

// [NEW] Add fd to epoll
void epoll_add(int epoll_fd, int fd, void *ptr) {
    struct epoll_event ev = {0};
    ev.events = EPOLLIN | EPOLLET; // Use Edge Triggered
    ev.data.ptr = ptr;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev);
}

// [NEW] Remove connection and clean up
void close_connection(PortForwarder *f, int fd) {
    if (fd < 0 || fd >= MAX_CONNECTIONS || f->connections[fd].client_fd == -1) {
        return;
    }
    
    Connection *conn = &f->connections[fd];
    epoll_ctl(f->epoll_fd, EPOLL_CTL_DEL, conn->client_fd, NULL);
    if (conn->remote_fd != -1) {
        epoll_ctl(f->epoll_fd, EPOLL_CTL_DEL, conn->remote_fd, NULL);
        close(conn->remote_fd);
    }
    close(conn->client_fd);

    log_message(f, "Connection closed for fd %d", conn->client_fd);
    
    memset(conn, 0, sizeof(Connection));
    conn->client_fd = -1;
    conn->remote_fd = -1;
    f->stats.active_connections--;
}

void print_help(int verbose) {
    printf("zf Port Forwarding Tool (Rewritten Version)\n\n");
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
    printf("  <ip_version>         : IP 协议版本，可选 v4（IPv4）、v6（IPv6）。'both'模式已简化。\n");
    printf("  <local_addr>:<local_port> : 本地监听地址和端口，如 0.0.0.0:8080。\n");
    printf("  <remote_addr>:<remote_port> : 远程目标地址和端口，如 example.com:80。\n");
    printf("  -p <protocols>       : 转发协议，可选 tcp、udp (默认: tcp)。tcp,udp模式已简化。\n");
    printf("  -c <interval>        : (健康检查) 检查远程主机连通性的间隔（秒，默认：30）。\n");
    printf("  -t <timeout>         : 连接空闲超时时间（秒，默认：300，0为无超时）。\n");
    printf("  -ls                  : 列出当前活动会话，包括实时连接数和流量统计。\n");
    printf("  -k <session_id>      : 终止指定会话。\n");
    printf("  -h [--verbose]       : 显示帮助信息。\n");
}


// [MODIFIED] Create listening socket
int create_listen_socket(PortForwarder *f, const char *addr, int port, const char *ip_version, int sock_type) {
    int family = (strcmp(ip_version, "v6") == 0) ? AF_INET6 : AF_INET;
    int sock = socket(family, sock_type, 0);
    if (sock < 0) {
        log_message(f, "创建套接字失败: %s", strerror(errno));
        return -1;
    }

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    make_socket_non_blocking(sock);

    if (family == AF_INET) {
        struct sockaddr_in saddr = {0};
        saddr.sin_family = AF_INET;
        saddr.sin_port = htons(port);
        inet_pton(AF_INET, addr, &saddr.sin_addr);
        if (bind(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
            log_message(f, "绑定地址 %s:%d 失败: %s", addr, port, strerror(errno));
            close(sock);
            return -1;
        }
    } else { // AF_INET6
        struct sockaddr_in6 saddr = {0};
        saddr.sin6_family = AF_INET6;
        saddr.sin6_port = htons(port);
        inet_pton(AF_INET6, addr, &saddr.sin6_addr);
        if (bind(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
            log_message(f, "绑定地址 %s:%d 失败: %s", addr, port, strerror(errno));
            close(sock);
            return -1;
        }
    }

    if (sock_type == SOCK_STREAM && listen(sock, SOMAXCONN) < 0) {
        log_message(f, "监听失败: %s", strerror(errno));
        close(sock);
        return -1;
    }
    
    log_message(f, "成功监听于 %s:%d (%s)", addr, port, sock_type == SOCK_STREAM ? "TCP" : "UDP");
    return sock;
}

// [MODIFIED] connect_remote is now non-blocking
int connect_remote_non_blocking(PortForwarder *f, int sock_type) {
    struct addrinfo hints = {0}, *res, *rp;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = sock_type;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", f->session.remote_port);
    if (getaddrinfo(f->session.remote_host, port_str, &hints, &res) != 0) {
        log_message(f, "解析远程地址 %s 失败", f->session.remote_host);
        return -1;
    }

    int sock = -1;
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock < 0) continue;
        
        make_socket_non_blocking(sock);

        if (connect(sock, rp->ai_addr, rp->ai_addrlen) < 0) {
            if (errno == EINPROGRESS) {
                break; // Non-blocking connect started
            }
            close(sock);
            sock = -1;
        } else {
            break; // Connected immediately
        }
    }

    freeaddrinfo(res);
    if (rp == NULL) {
        log_message(f, "无法连接到远程主机 %s:%d", f->session.remote_host, f->session.remote_port);
        return -1;
    }
    return sock;
}

// [NEW] Handle new incoming TCP connection
void handle_new_tcp_connection(PortForwarder *f, int listen_fd) {
    struct sockaddr_storage client_addr;
    socklen_t addr_len = sizeof(client_addr);
    int client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &addr_len);
    if (client_fd < 0 || client_fd >= MAX_CONNECTIONS) {
        if(client_fd >= 0) close(client_fd);
        return;
    }

    make_socket_non_blocking(client_fd);
    int remote_fd = connect_remote_non_blocking(f, SOCK_STREAM);
    if (remote_fd < 0 || remote_fd >= MAX_CONNECTIONS) {
        close(client_fd);
        if(remote_fd >= 0) close(remote_fd);
        return;
    }

    Connection *conn = &f->connections[client_fd];
    conn->client_fd = client_fd;
    conn->remote_fd = remote_fd;
    conn->last_activity = time(NULL);
    conn->is_udp = 0;
    
    Connection *remote_conn = &f->connections[remote_fd];
    remote_conn->client_fd = remote_fd; // Use client_fd as key for remote side too
    remote_conn->remote_fd = client_fd;
    remote_conn->last_activity = time(NULL);

    epoll_add(f->epoll_fd, client_fd, conn);
    epoll_add(f->epoll_fd, remote_fd, remote_conn);

    f->stats.active_connections++;
    f->stats.total_connections++;
    log_message(f, "新TCP连接: client_fd=%d, remote_fd=%d", client_fd, remote_fd);
}


// [NEW] Relay data between two sockets
void relay_data(PortForwarder *f, Connection *conn, int from_fd, int to_fd) {
    ssize_t n;
    while ((n = read(from_fd, conn->buffer, BUFFER_SIZE)) > 0) {
        ssize_t written = write(to_fd, conn->buffer, n);
        if (written < 0) {
             if (errno != EAGAIN && errno != EWOULDBLOCK) {
                 close_connection(f, conn->client_fd);
             }
             return;
        }
        f->stats.bytes_transferred += written;
        conn->last_activity = time(NULL);
    }
    if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
        close_connection(f, conn->client_fd);
    }
}


// [NEW] Handle UDP data
void handle_udp_data(PortForwarder* f, int udp_listen_fd) {
    Connection* conn = &f->connections[udp_listen_fd];
    char buffer[BUFFER_SIZE];
    struct sockaddr_storage src_addr;
    socklen_t src_addr_len = sizeof(src_addr);
    
    ssize_t n = recvfrom(udp_listen_fd, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&src_addr, &src_addr_len);
    if (n > 0) {
        if (conn->remote_fd == -1) {
             conn->remote_fd = connect_remote_non_blocking(f, SOCK_DGRAM);
             if (conn->remote_fd < 0) return;
             // For UDP, we just have one "connection" object representing the listener
             conn->is_udp = 1;
             epoll_add(f->epoll_fd, conn->remote_fd, conn);
             f->stats.active_connections++; // Count the whole UDP forwarder as one connection
             f->stats.total_connections++;
        }
        memcpy(&conn->udp_client_addr, &src_addr, src_addr_len);
        conn->udp_client_addr_len = src_addr_len;
        
        send(conn->remote_fd, buffer, n, 0);
        f->stats.bytes_transferred += n;
        conn->last_activity = time(NULL);
    }
}

// [NEW] Handle data coming back from remote UDP socket
void handle_remote_udp_data(PortForwarder *f, Connection* conn) {
    char buffer[BUFFER_SIZE];
    ssize_t n = read(conn->remote_fd, buffer, BUFFER_SIZE);
    if (n > 0) {
        sendto(conn->client_fd, buffer, n, 0, (struct sockaddr*)&conn->udp_client_addr, conn->udp_client_addr_len);
        f->stats.bytes_transferred += n;
        conn->last_activity = time(NULL);
    }
}

// [MODIFIED] Health check remains in a thread
int check_connection(PortForwarder *f) { /* ... same as original, but use log_message ... */ return 1; }
void *check_connection_thread(void *arg) { /* ... same as original ... */ return NULL; }
void *monitor_quality_thread(void *arg) { /* ... same as original, but check for root ... */ return NULL; }


// [MODIFIED] Save session now includes correct PID
void save_session(PortForwarder *f) {
    f->session.pid = getpid(); // Get final PID
    snprintf(f->session.id, sizeof(f->session.id), "%s:%d-%ld", 
             f->session.local_addr, f->session.local_port, time(NULL));

    char path[256];
    snprintf(path, sizeof(path), "%s/%s.session", SESSION_DIR, f->session.id);
    FILE *fp = fopen(path, "w");
    if (!fp) return;
    fprintf(fp, "ID: %s\nPID: %d\nIPVersion: %s\nLocal: %s:%d\nRemote: %s:%d\nProtocols: %s\nTimeout: %d\n",
            f->session.id, f->session.pid, f->session.ip_version,
            f->session.local_addr, f->session.local_port,
            f->session.remote_host, f->session.remote_port,
            f->session.protocols, f->session.timeout);
    fclose(fp);
}

void delete_session_files(const char* session_id, FILE *log_fp) {
    char session_path[256], sock_path[256];
    snprintf(session_path, sizeof(session_path), "%s/%s.session", SESSION_DIR, session_id);
    snprintf(sock_path, sizeof(sock_path), "%s/%s.sock", SESSION_DIR, session_id);
    unlink(session_path);
    unlink(sock_path);
}

// [MODIFIED] Control socket handler now provides stats
void handle_control_connection(PortForwarder *f, int control_listen_fd) {
    int client_fd = accept(control_listen_fd, NULL, NULL);
    if (client_fd < 0) return;

    char buffer[16];
    ssize_t n = read(client_fd, buffer, sizeof(buffer) - 1);
    if (n > 0) {
        buffer[n] = '\0';
        if (strcmp(buffer, "kill") == 0) {
            log_message(f, "收到关闭命令，终止会话");
            g_quit_flag = 1;
        } else if (strcmp(buffer, "stats") == 0) {
            // Write stats back to the client
            write(client_fd, &f->stats, sizeof(f->stats));
        }
    }
    close(client_fd);
}

// [MODIFIED] Main forwarding loop is now the async epoll loop
void start_forwarding(PortForwarder *f) {
    // ... setup listening sockets, control socket, threads ...
    // Add them to epoll
    
    struct epoll_event events[MAX_EVENTS];
    while (!g_quit_flag) {
        int nfds = epoll_wait(f->epoll_fd, events, MAX_EVENTS, 1000); // 1s timeout to check quit flag
        if (nfds < 0) {
            if (errno == EINTR) continue;
            break; 
        }

        time_t now = time(NULL);

        for (int i = 0; i < nfds; i++) {
            void* ptr = events[i].data.ptr;
            int is_listen_sock = 0;
            for(int j=0; j<f->listen_fd_count; ++j) {
                if (f->listen_fds[j] == ((Connection*)ptr)->client_fd) {
                    is_listen_sock = 1;
                    if(((Connection*)ptr)->is_udp) handle_udp_data(f, f->listen_fds[j]);
                    else handle_new_tcp_connection(f, f->listen_fds[j]);
                    break;
                }
            }

            if(is_listen_sock) continue;
            
            if (((Connection*)ptr)->client_fd == f->control_fd) {
                 handle_control_connection(f, f->control_fd);
                 continue;
            }

            // Data from client or remote
            Connection *conn = (Connection*)ptr;
            int from_fd = conn->client_fd; // This is the key
            int to_fd = conn->remote_fd;
            
            if(conn->is_udp) { // Data coming back from remote UDP
                handle_remote_udp_data(f, conn);
            } else { // TCP data
                relay_data(f, conn, from_fd, to_fd);
            }
        }
        
        // Check for timeouts
        if (f->session.timeout > 0) {
            for (int i = 0; i < MAX_CONNECTIONS; i++) {
                if (f->connections[i].client_fd != -1 && !f->connections[i].is_udp) {
                    if (now - f->connections[i].last_activity > f->session.timeout) {
                        log_message(f, "连接超时 fd=%d", f->connections[i].client_fd);
                        close_connection(f, i);
                    }
                }
            }
        }
    }
}

// [MODIFIED] List sessions now gets live stats
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
            char path[512];
            snprintf(path, sizeof(path), "%s/%s", SESSION_DIR, entry->d_name);
            FILE *fp = fopen(path, "r");
            if (!fp) continue;
            
            count++;
            char line[512];
            char session_id[128] = {0};
            while (fgets(line, sizeof(line), fp)) {
                 printf("%s", line);
                 if (strncmp(line, "ID: ", 4) == 0) {
                     strncpy(session_id, line + 4, sizeof(session_id) - 1);
                     session_id[strcspn(session_id, "\n")] = 0; // trim newline
                 }
            }
            fclose(fp);

            // [NEW] IPC to get stats
            char sock_path[256];
            snprintf(sock_path, sizeof(sock_path), "%s/%s.sock", SESSION_DIR, session_id);
            int sock = socket(AF_UNIX, SOCK_STREAM, 0);
            if (sock >= 0) {
                struct sockaddr_un addr = {0};
                addr.sun_family = AF_UNIX;
                strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);
                if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
                    write(sock, "stats", 5);
                    struct {
                        uint64_t active_connections;
                        uint64_t total_connections;
                        uint64_t bytes_transferred;
                    } stats;
                    if (read(sock, &stats, sizeof(stats)) == sizeof(stats)) {
                         printf("统计: 活跃连接=%lu，总连接=%lu，流量=%lu 字节\n",
                                stats.active_connections, stats.total_connections, stats.bytes_transferred);
                    }
                }
                close(sock);
            }
            printf("----------------------------------------\n");
        }
    }
    if (count == 0) {
        printf("没有活动会话\n");
    }
    closedir(dir);
}

// [MODIFIED] Kill session remains mostly the same
void kill_session(const char *session_id) { /* ... as original ... */ }

// [MODIFIED] Safer argument parsing
int parse_args(int argc, char *argv[], PortForwarder *f, int *list_sessions_flag, char **kill_session_id, int *help_flag, int *verbose_flag) {
    if (argc < 2) { print_help(0); exit(1); }
    
    // ... argument parsing for flags -ls, -k, -h etc. ...
    
    // Check flags first
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-ls") == 0) { *list_sessions_flag = 1; return 0; }
        if (strcmp(argv[i], "-k") == 0) { *kill_session_id = argv[++i]; return 0; }
        // ...
    }

    if (argc < 4) return -1;

    // [NEW] Safer parsing logic without strtok
    char *local_colon = strchr(argv[2], ':');
    if (!local_colon) return -1;
    *local_colon = '\0';
    strncpy(f->session.local_addr, argv[2], sizeof(f->session.local_addr) - 1);
    f->session.local_port = atoi(local_colon + 1);
    *local_colon = ':'; // Restore argv

    // ... similar safe parsing for remote addr ...

    return 0;
}


int main(int argc, char *argv[]) {
    // ... initial setup ...

    // [MODIFIED] Setup signal handler with sigaction
    struct sigaction sa = {0};
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; // No SA_RESTART
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    // ... parse args ...

    if (list_sessions_flag) {
        list_sessions(); // Note: no PortForwarder struct needed for this
        return 0;
    }
    // ... handle kill_session, help ...

    // [MODIFIED] Daemonization logic comes before creating resources
    if (getenv("ZF_DAEMON") == NULL) {
        setenv("ZF_DAEMON", "1", 1);
        pid_t pid = fork();
        if (pid < 0) exit(1);
        if (pid > 0) {
            printf("守护进程已启动，PID: %d\n", pid);
            exit(0);
        }
        umask(0);
        setsid();
        chdir("/");
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
    }

    // Now, in the daemon, we can initialize everything
    // ... init PortForwarder f, open log, etc.
    
    // [MODIFIED] Session ID is generated *after* fork
    save_session(&f);

    start_forwarding(&f);

    cleanup(&f);
    log_message(&f, "会话 %s 已终止", f.session.id);
    if(f.log_fp != stderr) fclose(f.log_fp);

    return 0;
}

// NOTE: This rewritten code is a skeleton demonstrating the new architecture.
// Several functions like check_connection_thread, monitor_quality_thread, kill_session,
// and the full parse_args and main function logic need to be filled in from the
// original code, adapting them to the new structure where necessary.
