#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <netdb.h>
#include <pthread.h>
#include <stdarg.h>
#include <dirent.h>

#define SESSION_DIR "/var/run/zf_sessions"
#define LOG_FILE "/var/log/zf.log"
#define MAX_EVENTS_PARENT 5
#define MAX_EVENTS_PER_CHILD 2
#define BUFFER_SIZE 8192
#define MAX_RETRIES 10

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
    Session session;
    FILE *log_fp;
    pthread_t check_thread;
} PortForwarder;

static volatile sig_atomic_t g_quit_flag = 0;

void log_message(FILE *log_fp, const char *session_id, const char *level, const char *fmt, ...);
void delete_session_files(const char* session_id, FILE* log_fp);

void signal_handler_parent(int sig) {
    g_quit_flag = 1;
}

void signal_handler_child(int sig) {
    _exit(0);
}

void sigchld_handler(int sig) {
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

void print_help(int verbose) {
    printf("zf Port Forwarding Tool (Stable Forking Model)\n\n");
    printf("Usage:\n");
    printf("  zf <ip_version> <local_addr>:<local_port> <remote_addr>:<remote_port> [options]\n");
    printf("  zf -ls | -k <session_id> | -h [--verbose]\n\n");
    if (!verbose) {
        printf("Use 'zf -h --verbose' for detailed help.\n");
        return;
    }
    printf("Options:\n");
    printf("  <ip_version>      IP version: v4, v6.\n");
    printf("  -p <protocol>     Protocol: tcp (default). UDP is not supported in this version.\n");
    printf("  -c <interval>     Health check interval for remote host (seconds, default: 30).\n");
    printf("  -t <timeout>      Idle connection timeout (seconds, default: 300).\n");
    printf("  -ls               List active sessions.\n");
    printf("  -k <session_id>   Kill a specific session.\n");
    printf("  -h [--verbose]    Show this help message.\n");
}

int create_listen_socket(const Session *session, FILE *log_fp) {
    int family = (strcmp(session->ip_version, "v6") == 0) ? AF_INET6 : AF_INET;
    int sock = socket(family, SOCK_STREAM, 0);
    if (sock < 0) {
        log_message(log_fp, session->id, "ERROR", "Failed to create listen socket: %s", strerror(errno));
        return -1;
    }
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_storage saddr_storage = {0};
    if (family == AF_INET) {
        struct sockaddr_in *saddr = (struct sockaddr_in *)&saddr_storage;
        saddr->sin_family = AF_INET;
        saddr->sin_port = htons(session->local_port);
        inet_pton(AF_INET, session->local_addr, &saddr->sin_addr);
    } else {
        struct sockaddr_in6 *saddr = (struct sockaddr_in6 *)&saddr_storage;
        saddr->sin6_family = AF_INET6;
        saddr->sin6_port = htons(session->local_port);
        inet_pton(AF_INET6, session->local_addr, &saddr->sin6_addr);
    }
    if (bind(sock, (struct sockaddr *)&saddr_storage, family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)) < 0) {
        log_message(log_fp, session->id, "ERROR", "Bind to %s:%d failed: %s", session->local_addr, session->local_port, strerror(errno));
        close(sock);
        return -1;
    }
    if (listen(sock, SOMAXCONN) < 0) {
        log_message(log_fp, session->id, "ERROR", "Listen failed: %s", strerror(errno));
        close(sock);
        return -1;
    }
    return sock;
}

int connect_remote(const Session *session, FILE *log_fp) {
    struct addrinfo hints = {0}, *res, *rp;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", session->remote_port);
    int ret = getaddrinfo(session->remote_host, port_str, &hints, &res);
    if (ret != 0) {
        log_message(log_fp, session->id, "WARN", "Failed to resolve remote host %s: %s", session->remote_host, gai_strerror(ret));
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

void handle_tcp_connection(const Session *session, int client_fd, FILE *log_fp) {
    log_message(log_fp, session->id, "INFO", "Handling connection fd %d in child PID %d.", client_fd, getpid());
    int remote_fd = connect_remote(session, log_fp);
    if (remote_fd < 0) {
        close(client_fd);
        log_message(log_fp, session->id, "WARN", "Child PID %d failed to connect to remote, closing client fd %d.", getpid(), client_fd);
        return;
    }
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        close(client_fd);
        close(remote_fd);
        return;
    }
    struct epoll_event ev, events[MAX_EVENTS_PER_CHILD];
    ev.events = EPOLLIN;
    ev.data.fd = client_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev);
    ev.data.fd = remote_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, remote_fd, &ev);
    char buffer[BUFFER_SIZE];
    while (!g_quit_flag) {
        int timeout_ms = session->timeout > 0 ? session->timeout * 1000 : -1;
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS_PER_CHILD, timeout_ms);
        if (nfds < 0) { if (errno == EINTR) continue; break; }
        if (nfds == 0) { log_message(log_fp, session->id, "INFO", "Connection on fd %d idle timeout.", client_fd); break; }
        int quit_loop = 0;
        for (int i = 0; i < nfds; i++) {
            int from_fd = events[i].data.fd;
            int to_fd = (from_fd == client_fd) ? remote_fd : client_fd;
            ssize_t n_read = read(from_fd, buffer, BUFFER_SIZE);
            if (n_read <= 0) { quit_loop = 1; break; }
            ssize_t n_written_total = 0;
            while(n_written_total < n_read) {
                ssize_t n_written = write(to_fd, buffer + n_written_total, n_read - n_written_total);
                if (n_written <= 0) { quit_loop = 1; break; }
                n_written_total += n_written;
            }
            if(quit_loop) break;
        }
        if(quit_loop) break;
    }
    log_message(log_fp, session->id, "INFO", "Closing connection for fd %d in child PID %d.", client_fd, getpid());
    close(client_fd);
    close(remote_fd);
    close(epoll_fd);
}

void *check_connection_thread(void *arg) {
    PortForwarder *f = (PortForwarder *)arg;
    int fail_count = 0;
    log_message(f->log_fp, f->session.id, "INFO", "Health check thread started.");
    while (!g_quit_flag) {
        int sock = connect_remote(&f->session, f->log_fp);
        if (sock < 0) {
            fail_count++;
            log_message(f->log_fp, f->session.id, "WARN", "Health check failed (attempt %d/%d)", fail_count, MAX_RETRIES);
            if (fail_count >= MAX_RETRIES) {
                log_message(f->log_fp, f->session.id, "ERROR", "Health check failed %d times. Shutting down main process.", MAX_RETRIES);
                kill(f->session.pid, SIGTERM);
                break;
            }
        } else {
            if (fail_count > 0) log_message(f->log_fp, f->session.id, "INFO", "Health check successful, connection to remote host restored.");
            fail_count = 0;
            close(sock);
        }
        for (int i = 0; i < f->session.check_interval && !g_quit_flag; ++i) sleep(1);
    }
    return NULL;
}

void handle_control_request(int control_fd, FILE *log_fp, const char *session_id, pid_t pid) {
    int client_fd = accept(control_fd, NULL, NULL);
    if(client_fd < 0) return;
    char buffer[16];
    ssize_t n = read(client_fd, buffer, sizeof(buffer) - 1);
    if (n > 0) {
        buffer[n] = '\0';
        if (strcmp(buffer, "kill") == 0) {
            log_message(log_fp, session_id, "INFO", "Received kill command via control socket. Sending SIGTERM to PID %d.", pid);
            kill(pid, SIGTERM);
        }
    }
    close(client_fd);
}

void start_forwarding(PortForwarder *f) {
    int listen_fd = create_listen_socket(&f->session, f->log_fp);
    if (listen_fd < 0) return;

    char sock_path[256];
    snprintf(sock_path, sizeof(sock_path), "%s/%s.sock", SESSION_DIR, f->session.id);
    unlink(sock_path);
    int control_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un control_addr = {0};
    control_addr.sun_family = AF_UNIX;
    strncpy(control_addr.sun_path, sock_path, sizeof(control_addr.sun_path) - 1);
    if (bind(control_fd, (struct sockaddr *)&control_addr, sizeof(control_addr)) != 0 || listen(control_fd, 5) != 0) {
        log_message(f->log_fp, f->session.id, "ERROR", "Failed to setup control socket: %s", strerror(errno));
        close(control_fd);
        control_fd = -1;
    }

    int epoll_fd = epoll_create1(0);
    struct epoll_event ev, events[MAX_EVENTS_PARENT];
    ev.events = EPOLLIN;
    ev.data.fd = listen_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &ev);
    if (control_fd >= 0) {
        ev.data.fd = control_fd;
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, control_fd, &ev);
    }

    if (f->session.check_interval > 0) {
        if (pthread_create(&f->check_thread, NULL, check_connection_thread, f) != 0) {
            log_message(f->log_fp, f->session.id, "ERROR", "Failed to create health check thread. Exiting.");
            g_quit_flag = 1;
        }
    }
    
    log_message(f->log_fp, f->session.id, "INFO", "Main listener started on PID %d. Waiting for events...", getpid());
    while (!g_quit_flag) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS_PARENT, -1);
        if (nfds < 0) { if (errno == EINTR) continue; break; }

        for (int i=0; i < nfds; ++i) {
            int fd = events[i].data.fd;
            if (fd == listen_fd) {
                int client_fd = accept(listen_fd, NULL, NULL);
                if (client_fd >= 0) {
                    pid_t pid = fork();
                    if (pid == 0) { // Child process
                        struct sigaction sa_child = {0};
                        sa_child.sa_handler = signal_handler_child;
                        sigaction(SIGTERM, &sa_child, NULL);
                        sigaction(SIGINT, &sa_child, NULL);
                        close(listen_fd);
                        if (control_fd >= 0) close(control_fd);
                        if (f->check_thread) pthread_detach(f->check_thread);
                        handle_tcp_connection(&f->session, client_fd, f->log_fp);
                        fclose(f->log_fp);
                        exit(0);
                    }
                    close(client_fd); // Parent closes client fd
                }
            } else if (fd == control_fd) {
                handle_control_request(control_fd, f->log_fp, f->session.id, f->session.pid);
            }
        }
    }

    log_message(f->log_fp, f->session.id, "INFO", "Shutdown signal received. Cleaning up.");
    if (f->check_thread) {
        pthread_cancel(f->check_thread);
        pthread_join(f->check_thread, NULL);
    }
    close(listen_fd);
    if (control_fd >= 0) close(control_fd);
    close(epoll_fd);
    kill(0, SIGTERM);
}

void list_sessions() {
    DIR *dir = opendir(SESSION_DIR);
    if (!dir) { fprintf(stderr, "Cannot open session directory %s: %s\n", SESSION_DIR, strerror(errno)); return; }
    printf("Active Sessions:\n");
    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir))) {
        if (strstr(entry->d_name, ".session")) {
            char path[512];
            snprintf(path, sizeof(path), "%s/%s", SESSION_DIR, entry->d_name);
            FILE *fp = fopen(path, "r");
            if (!fp) continue;
            count++;
            printf("----------------------------------------\n");
            char line[256];
            while (fgets(line, sizeof(line), fp)) printf("%s", line);
            fclose(fp);
            printf("Note: Live stats are not available in this version.\n");
        }
    }
    if (count == 0) printf("No active sessions found.\n");
    closedir(dir);
}

void kill_session(const char *session_id) {
    char sock_path[256];
    snprintf(sock_path, sizeof(sock_path), "%s/%s.sock", SESSION_DIR, session_id);
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) { fprintf(stderr, "Failed to create control socket: %s\n", strerror(errno)); return; }
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Failed to connect to session %s: %s. It may not be running or the socket file is stale.\n", session_id, strerror(errno));
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

int parse_args(int argc, char *argv[], Session *session, int *action_flag, char **session_id_ptr, int *verbose_flag) {
    session->timeout = 300;
    session->check_interval = 30;
    strcpy(session->protocols, "tcp");
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-ls") == 0) { *action_flag = 1; return 0; }
        if (strcmp(argv[i], "-h") == 0) { *action_flag = 2; return 0; }
        if (strcmp(argv[i], "--verbose") == 0) { *verbose_flag = 1; *action_flag = 2; return 0;}
        if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) { *action_flag = 3; *session_id_ptr = argv[++i]; return 0; }
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) strncpy(session->protocols, argv[++i], sizeof(session->protocols)-1);
        if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) session->check_interval = atoi(argv[++i]);
        if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) session->timeout = atoi(argv[++i]);
    }
    if (*action_flag != 0) return 0;
    if (argc < 4) return -1;
    strncpy(session->ip_version, argv[1], sizeof(session->ip_version)-1);
    char *local_arg = strdup(argv[2]);
    char *local_colon = strchr(local_arg, ':');
    if (!local_colon) { free(local_arg); return -1; }
    *local_colon = '\0';
    strncpy(session->local_addr, local_arg, sizeof(session->local_addr)-1);
    session->local_port = atoi(local_colon + 1);
    free(local_arg);
    char *remote_arg = strdup(argv[3]);
    char *remote_colon = strrchr(remote_arg, ':');
    if (!remote_colon) { free(remote_arg); return -1; }
    *remote_colon = '\0';
    strncpy(session->remote_host, remote_arg, sizeof(session->remote_host)-1);
    session->remote_port = atoi(remote_colon + 1);
    free(remote_arg);
    if (session->local_port <= 0 || session->remote_port <= 0) return -1;
    return 0;
}

void save_session(const Session *session) {
    char path[256];
    snprintf(path, sizeof(path), "%s/%s.session", SESSION_DIR, session->id);
    FILE *fp = fopen(path, "w");
    if (!fp) return;
    fprintf(fp, "ID: %s\nPID: %d\nIPVersion: %s\nLocal: %s:%d\nRemote: %s:%d\nProtocol: %s\nTimeout: %d\nCheckInterval: %d\n",
            session->id, session->pid, session->ip_version,
            session->local_addr, session->local_port,
            session->remote_host, session->remote_port,
            session->protocols, session->timeout, session->check_interval);
    fclose(fp);
}

void delete_session_files(const char* session_id, FILE *log_fp) {
    char session_path[256], sock_path[256];
    snprintf(session_path, sizeof(session_path), "%s/%s.session", SESSION_DIR, session_id);
    snprintf(sock_path, sizeof(sock_path), "%s/%s.sock", SESSION_DIR, session_id);
    if (unlink(session_path) < 0 && errno != ENOENT) {
        log_message(log_fp, session_id, "WARN", "Failed to delete session file: %s", strerror(errno));
    }
    if (unlink(sock_path) < 0 && errno != ENOENT) {
         log_message(log_fp, session_id, "WARN", "Failed to delete socket file: %s", strerror(errno));
    }
}

void log_message(FILE *log_fp, const char *session_id, const char *level, const char *fmt, ...) {
    if (!log_fp) return;
    time_t now = time(NULL);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    fprintf(log_fp, "%s [%s] [%s] ", timestamp, session_id ? session_id : "NO_SESSION", level);
    va_list args;
    va_start(args, fmt);
    vfprintf(log_fp, fmt, args);
    va_end(args);
    fprintf(fp, "\n");
    fflush(fp);
}

int main(int argc, char *argv[]) {
    PortForwarder f = {0};
    int action_flag = 0;
    char *session_id_ptr = NULL;
    int verbose_flag = 0;

    if (parse_args(argc, argv, &f.session, &action_flag, &session_id_ptr, &verbose_flag) < 0) {
        fprintf(stderr, "Invalid arguments.\n");
        print_help(0);
        return 1;
    }

    if (action_flag == 1) { list_sessions(); return 0; }
    if (action_flag == 2) { print_help(verbose_flag); return 0; }
    if (action_flag == 3) { kill_session(session_id_ptr); return 0; }

    if (getenv("ZF_DAEMON") == NULL) {
        pid_t pid = fork();
        if (pid < 0) { perror("fork"); return 1; }
        if (pid > 0) { printf("Session daemon started with PID %d.\n", pid); return 0; }
        umask(0);
        if (setsid() < 0) exit(1);
        setenv("ZF_DAEMON", "1", 1);
        chdir("/");
        close(STDIN_FILENO); close(STDOUT_FILENO); close(STDERR_FILENO);
    }
    
    f.log_fp = fopen(LOG_FILE, "a");
    if (!f.log_fp) exit(1);
    setvbuf(f.log_fp, NULL, _IOLBF, 0);

    struct sigaction sa_term = {0}, sa_chld = {0};
    sa_term.sa_handler = signal_handler_parent;
    sigaction(SIGTERM, &sa_term, NULL);
    sigaction(SIGINT, &sa_term, NULL);
    sa_chld.sa_handler = sigchld_handler;
    sa_chld.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa_chld, NULL);

    f.session.pid = getpid();
    snprintf(f.session.id, sizeof(f.session.id), "%s:%d-%ld", f.session.local_addr, f.session.local_port, time(NULL));
    mkdir(SESSION_DIR, 0755);
    save_session(&f.session);

    start_forwarding(&f);
    
    log_message(f.log_fp, f.session.id, "INFO", "Session shutting down.");
    delete_session_files(f.session.id, f.log_fp);
    if (f.log_fp) fclose(f.log_fp);
    
    return 0;
}
