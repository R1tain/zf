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
#include <pthread.h>
#include <stdarg.h>
#include <dirent.h>

#define SESSION_DIR "/var/run/zf_sessions"
#define LOG_FILE "/var/log/zf.log"
#define MAX_EVENTS 256
#define BUFFER_SIZE 8192
#define MAX_SESSIONS 1024 // Max concurrent connections

typedef struct {
    char id[128];
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
    int fd_pair; // The other fd in the connection (client -> remote, remote -> client)
    time_t last_activity;
} ConnectionInfo;

typedef struct {
    Session session;
    FILE *log_fp;
    int control_fd;
    pthread_t check_thread;
    int epoll_fd;
    ConnectionInfo *connections;
    struct {
        uint64_t active_connections;
        uint64_t total_connections;
        uint64_t bytes_transferred;
    } stats;
} PortForwarder;

static volatile sig_atomic_t g_quit_flag = 0;

void log_message(PortForwarder *f, const char *level, const char *fmt, ...);
void delete_session_files(const char* session_id, FILE* log_fp);

void signal_handler(int sig) {
    g_quit_flag = 1;
}

int make_socket_non_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, flags) == -1) return -1;
    return 0;
}

void epoll_add(int epoll_fd, int fd) {
    struct epoll_event ev = {0};
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev);
}

void close_and_cleanup_connection(PortForwarder *f, int fd) {
    if (fd < 0 || fd >= MAX_SESSIONS || f->connections[fd].fd_pair == 0) return;

    int pair_fd = f->connections[fd].fd_pair;
    
    epoll_ctl(f->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
    close(fd);
    f->connections[fd].fd_pair = 0;
    
    if (pair_fd > 0 && f->connections[pair_fd].fd_pair != 0) {
        epoll_ctl(f->epoll_fd, EPOLL_CTL_DEL, pair_fd, NULL);
        close(pair_fd);
        f->connections[pair_fd].fd_pair = 0;
    }
    
    if (f->stats.active_connections > 0) f->stats.active_connections--;
    log_message(f, "INFO", "Connection closed for fd %d (pair %d)", fd, pair_fd);
}

void print_help(int verbose) {
    printf("zf Port Forwarding Tool\n\n");
    printf("Usage:\n");
    printf("  zf <ip_version> <local_addr>:<local_port> <remote_addr>:<remote_port> [options]\n");
    printf("  zf -ls | -k <session_id> | -h [--verbose]\n\n");
    if (!verbose) {
        printf("Use 'zf -h --verbose' for detailed help.\n");
        return;
    }
    printf("Options:\n");
    printf("  <ip_version>      IP version: v4, v6. (UDP not supported in this version)\n");
    printf("  -p <protocol>     Protocol: tcp (default). UDP is not supported.\n");
    printf("  -c <interval>     Health check interval for remote host (seconds, default: 30).\n");
    printf("  -t <timeout>      Idle connection timeout (seconds, default: 300).\n");
    printf("  -ls               List active sessions with live stats.\n");
    printf("  -k <session_id>   Kill a specific session.\n");
    printf("  -h [--verbose]    Show this help message.\n");
}

int create_listen_socket(PortForwarder *f) {
    int family = (strcmp(f->session.ip_version, "v6") == 0) ? AF_INET6 : AF_INET;
    int sock = socket(family, SOCK_STREAM, 0);
    if (sock < 0) {
        log_message(f, "ERROR", "Failed to create listen socket: %s", strerror(errno));
        return -1;
    }
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (family == AF_INET) {
        struct sockaddr_in saddr = {0};
        saddr.sin_family = AF_INET;
        saddr.sin_port = htons(f->session.local_port);
        inet_pton(AF_INET, f->session.local_addr, &saddr.sin_addr);
        if (bind(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
            log_message(f, "ERROR", "Bind to %s:%d failed: %s", f->session.local_addr, f->session.local_port, strerror(errno));
            close(sock);
            return -1;
        }
    } else {
        struct sockaddr_in6 saddr = {0};
        saddr.sin6_family = AF_INET6;
        saddr.sin6_port = htons(f->session.local_port);
        inet_pton(AF_INET6, f->session.local_addr, &saddr.sin6_addr);
        if (bind(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
             log_message(f, "ERROR", "Bind to %s:%d failed: %s", f->session.local_addr, f->session.local_port, strerror(errno));
            close(sock);
            return -1;
        }
    }
    if (listen(sock, SOMAXCONN) < 0) {
        log_message(f, "ERROR", "Listen failed: %s", strerror(errno));
        close(sock);
        return -1;
    }
    make_socket_non_blocking(sock);
    return sock;
}

int connect_remote(PortForwarder *f) {
    struct addrinfo hints = {0}, *res, *rp;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", f->session.remote_port);
    if (getaddrinfo(f->session.remote_host, port_str, &hints, &res) != 0) {
        log_message(f, "WARN", "Failed to resolve remote host %s", f->session.remote_host);
        return -1;
    }
    int sock = -1;
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock < 0) continue;
        if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(sock);
        sock = -1;
    }
    freeaddrinfo(res);
    return sock;
}

void *check_connection_thread(void *arg) {
    PortForwarder *f = (PortForwarder *)arg;
    while (!g_quit_flag) {
        int sock = connect_remote(f);
        if (sock < 0) {
            log_message(f, "WARN", "Health check failed: cannot connect to remote host %s:%d", f->session.remote_host, f->session.remote_port);
        } else {
            close(sock);
        }
        for (int i=0; i < f->session.check_interval && !g_quit_flag; ++i) {
            sleep(1);
        }
    }
    return NULL;
}

void handle_new_connection(PortForwarder *f, int listen_fd) {
    int client_fd = accept(listen_fd, NULL, NULL);
    if (client_fd < 0 || client_fd >= MAX_SESSIONS) {
        if (client_fd >= 0) close(client_fd);
        return;
    }
    int remote_fd = connect_remote(f);
    if (remote_fd < 0 || remote_fd >= MAX_SESSIONS) {
        close(client_fd);
        if(remote_fd >= 0) close(remote_fd);
        return;
    }
    make_socket_non_blocking(client_fd);
    make_socket_non_blocking(remote_fd);
    
    f->connections[client_fd].fd_pair = remote_fd;
    f->connections[client_fd].last_activity = time(NULL);
    f->connections[remote_fd].fd_pair = client_fd;
    f->connections[remote_fd].last_activity = time(NULL);
    
    epoll_add(f->epoll_fd, client_fd);
    epoll_add(f->epoll_fd, remote_fd);
    
    f->stats.active_connections++;
    f->stats.total_connections++;
    log_message(f, "INFO", "New connection: client_fd=%d, remote_fd=%d", client_fd, remote_fd);
}

void relay_data(PortForwarder *f, int from_fd) {
    int to_fd = f->connections[from_fd].fd_pair;
    if (to_fd <= 0) {
        close_and_cleanup_connection(f, from_fd);
        return;
    }
    char buffer[BUFFER_SIZE];
    ssize_t n;
    while ((n = read(from_fd, buffer, sizeof(buffer))) > 0) {
        ssize_t written = write(to_fd, buffer, n);
        if (written < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                close_and_cleanup_connection(f, from_fd);
            }
            return;
        }
        f->stats.bytes_transferred += written;
        f->connections[from_fd].last_activity = time(NULL);
        f->connections[to_fd].last_activity = time(NULL);
    }
    if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
        close_and_cleanup_connection(f, from_fd);
    }
}

void handle_control_connection(PortForwarder *f) {
    int client_fd = accept(f->control_fd, NULL, NULL);
    if (client_fd < 0) return;
    char buffer[16];
    ssize_t n = read(client_fd, buffer, sizeof(buffer) - 1);
    if (n > 0) {
        buffer[n] = '\0';
        if (strcmp(buffer, "kill") == 0) g_quit_flag = 1;
        else if (strcmp(buffer, "stats") == 0) write(client_fd, &f->stats, sizeof(f->stats));
    }
    close(client_fd);
}

void start_forwarding(PortForwarder *f) {
    int listen_fd = create_listen_socket(f);
    if (listen_fd < 0) return;

    f->epoll_fd = epoll_create1(0);
    f->connections = calloc(MAX_SESSIONS, sizeof(ConnectionInfo));
    epoll_add(f->epoll_fd, listen_fd);

    char sock_path[256];
    snprintf(sock_path, sizeof(sock_path), "%s/%s.sock", SESSION_DIR, f->session.id);
    unlink(sock_path);
    f->control_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un control_addr = {0};
    control_addr.sun_family = AF_UNIX;
    strncpy(control_addr.sun_path, sock_path, sizeof(control_addr.sun_path) - 1);
    if (bind(f->control_fd, (struct sockaddr *)&control_addr, sizeof(control_addr)) == 0 && listen(f->control_fd, 5) == 0) {
        make_socket_non_blocking(f->control_fd);
        epoll_add(f->epoll_fd, f->control_fd);
    } else {
        close(f->control_fd);
        f->control_fd = -1;
    }
    
    if (f->session.check_interval > 0) {
        pthread_create(&f->check_thread, NULL, check_connection_thread, f);
    }

    struct epoll_event events[MAX_EVENTS];
    while (!g_quit_flag) {
        int nfds = epoll_wait(f->epoll_fd, events, MAX_EVENTS, 1000);
        if (nfds < 0 && errno != EINTR) break;

        for (int i = 0; i < nfds; i++) {
            int fd = events[i].data.fd;
            if (fd == listen_fd) handle_new_connection(f, listen_fd);
            else if (fd == f->control_fd) handle_control_connection(f);
            else relay_data(f, fd);
        }
        
        if (f->session.timeout > 0) {
            time_t now = time(NULL);
            for (int i = 0; i < MAX_SESSIONS; i++) {
                if (f->connections[i].fd_pair > 0 && (now - f->connections[i].last_activity > f->session.timeout)) {
                    log_message(f, "INFO", "Connection timeout on fd %d", i);
                    close_and_cleanup_connection(f, i);
                }
            }
        }
    }

    if (f->check_thread) pthread_join(f->check_thread, NULL);
    if (listen_fd >= 0) close(listen_fd);
    if (f->control_fd >= 0) close(f->control_fd);
    free(f->connections);
    close(f->epoll_fd);
}

void list_sessions() {
    DIR *dir = opendir(SESSION_DIR);
    if (!dir) {
        fprintf(stderr, "Cannot open session directory %s\n", SESSION_DIR);
        return;
    }
    printf("Active Sessions:\n");
    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir))) {
        if (strstr(entry->d_name, ".session")) {
            char path[512], session_id[128] = {0};
            snprintf(path, sizeof(path), "%s/%s", SESSION_DIR, entry->d_name);
            FILE *fp = fopen(path, "r");
            if (!fp) continue;
            count++;
            printf("----------------------------------------\n");
            char line[256];
            while (fgets(line, sizeof(line), fp)) {
                 printf("%s", line);
                 if (strncmp(line, "ID: ", 4) == 0) {
                     strncpy(session_id, line + 4, sizeof(session_id) - 1);
                     session_id[strcspn(session_id, "\n")] = 0;
                 }
            }
            fclose(fp);
            
            char sock_path[256];
            snprintf(sock_path, sizeof(sock_path), "%s/%s.sock", SESSION_DIR, session_id);
            int sock = socket(AF_UNIX, SOCK_STREAM, 0);
            struct sockaddr_un addr = {0};
            addr.sun_family = AF_UNIX;
            strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);
            if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
                write(sock, "stats", 5);
                struct { uint64_t a, t, b; } stats;
                if (read(sock, &stats, sizeof(stats)) == sizeof(stats)) {
                     printf("Stats: Active=%lu, Total=%lu, Transferred=%lu bytes\n", stats.a, stats.t, stats.b);
                }
            }
            close(sock);
        }
    }
    if (count == 0) printf("No active sessions found.\n");
    closedir(dir);
}

void kill_session(const char *session_id) {
    char sock_path[256];
    snprintf(sock_path, sizeof(sock_path), "%s/%s.sock", SESSION_DIR, session_id);
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Failed to connect to session %s: %s\n", session_id, strerror(errno));
        close(sock);
        return;
    }
    if (write(sock, "kill", 4) < 0) {
        fprintf(stderr, "Failed to send kill command: %s\n", strerror(errno));
    } else {
        printf("Kill signal sent to session %s.\n", session_id);
    }
    close(sock);
    sleep(1);
    delete_session_files(session_id, stderr);
}

int parse_args(int argc, char *argv[], PortForwarder *f, int *action_flag, char **session_id) {
    f->session.timeout = 300;
    f->session.check_interval = 30;
    strcpy(f->session.protocols, "tcp");

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-ls") == 0) { *action_flag = 1; return 0; }
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--verbose") == 0) { *action_flag = 2; return 0; }
        if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) { *action_flag = 3; *session_id = argv[++i]; return 0; }
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) strncpy(f->session.protocols, argv[++i], sizeof(f->session.protocols)-1);
        if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) f->session.check_interval = atoi(argv[++i]);
        if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) f->session.timeout = atoi(argv[++i]);
    }
    if (argc < 4) return -1;
    
    strncpy(f->session.ip_version, argv[1], sizeof(f->session.ip_version)-1);
    
    char *local = strdup(argv[2]);
    char *local_colon = strchr(local, ':');
    if (!local_colon) { free(local); return -1; }
    *local_colon = '\0';
    strncpy(f->session.local_addr, local, sizeof(f->session.local_addr)-1);
    f->session.local_port = atoi(local_colon + 1);
    free(local);

    char *remote = strdup(argv[3]);
    char *remote_colon = strrchr(remote, ':');
    if (!remote_colon) { free(remote); return -1; }
    *remote_colon = '\0';
    strncpy(f->session.remote_host, remote, sizeof(f->session.remote_host)-1);
    f->session.remote_port = atoi(remote_colon + 1);
    free(remote);

    if (f->session.local_port <= 0 || f->session.remote_port <= 0) return -1;
    return 0;
}

void save_session(PortForwarder *f) {
    f->session.pid = getpid();
    snprintf(f->session.id, sizeof(f->session.id), "%s:%d-%ld", f->session.local_addr, f->session.local_port, time(NULL));
    char path[256];
    snprintf(path, sizeof(path), "%s/%s.session", SESSION_DIR, f->session.id);
    FILE *fp = fopen(path, "w");
    if (!fp) return;
    fprintf(fp, "ID: %s\nPID: %d\nIPVersion: %s\nLocal: %s:%d\nRemote: %s:%d\nProtocol: %s\nTimeout: %d\nCheckInterval: %d\n",
            f->session.id, f->session.pid, f->session.ip_version,
            f->session.local_addr, f->session.local_port,
            f->session.remote_host, f->session.remote_port,
            f->session.protocols, f->session.timeout, f->session.check_interval);
    fclose(fp);
}

void delete_session_files(const char* session_id, FILE *log_fp) {
    char session_path[256], sock_path[256];
    snprintf(session_path, sizeof(session_path), "%s/%s.session", SESSION_DIR, session_id);
    snprintf(sock_path, sizeof(sock_path), "%s/%s.sock", SESSION_DIR, session_id);
    if (unlink(session_path) < 0 && errno != ENOENT) {
        if(log_fp) fprintf(log_fp, "[WARN] Failed to delete session file: %s\n", strerror(errno));
    }
    if (unlink(sock_path) < 0 && errno != ENOENT) {
         if(log_fp) fprintf(log_fp, "[WARN] Failed to delete socket file: %s\n", strerror(errno));
    }
}

int main(int argc, char *argv[]) {
    PortForwarder f = {0};
    int action_flag = 0; // 0:run, 1:ls, 2:h, 3:k
    char *session_id = NULL;

    if (parse_args(argc, argv, &f, &action_flag, &session_id) < 0) {
        print_help(0);
        return 1;
    }

    if (action_flag == 1) { list_sessions(); return 0; }
    if (action_flag == 2) { print_help(1); return 0; }
    if (action_flag == 3) { kill_session(session_id); return 0; }

    if (getenv("ZF_DAEMON") == NULL) {
        pid_t pid = fork();
        if (pid < 0) { perror("fork"); return 1; }
        if (pid > 0) { printf("Session daemon started with PID %d.\n", pid); return 0; }
        umask(0);
        setsid();
        chdir("/");
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
        setenv("ZF_DAEMON", "1", 1);
    }
    
    f.log_fp = fopen(LOG_FILE, "a");
    if (!f.log_fp) exit(1);
    setvbuf(f.log_fp, NULL, _IOLBF, 0);

    struct sigaction sa = {0};
    sa.sa_handler = signal_handler;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    mkdir(SESSION_DIR, 0755);
    save_session(&f);
    log_message(&f, "INFO", "Session %s (PID: %d) started.", f.session.id, f.session.pid);

    start_forwarding(&f);
    
    log_message(&f, "INFO", "Session %s shutting down.", f.session.id);
    delete_session_files(f.session.id, f.log_fp);
    if (f.log_fp) fclose(f.log_fp);

    return 0;
}

void log_message(PortForwarder *f, const char *level, const char *fmt, ...) {
    time_t now = time(NULL);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    FILE *fp = f->log_fp ? f->log_fp : stderr;
    
    fprintf(fp, "%s [%s] [%s] ", timestamp, f->session.id, level);
    va_list args;
    va_start(args, fmt);
    vfprintf(fp, fmt, args);
    va_end(args);
    fprintf(fp, "\n");
}
