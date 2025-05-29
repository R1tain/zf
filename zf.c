/*                                                                   */
/*  zf – secure / stable port-forwarding daemon (May 2025 FINAL)      */
/*  ---------------------------------------------------------------- */
/*  Single-translation-unit; compiles on Ubuntu 22.04/24.04           */
/*      gcc -O2 -Wall -Wextra -pthread -o zf zf.c                     */
/*                                                                   */
/*                                                                   */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

/* ================== configurable ========================= */
#define SESSION_DIR "/var/run/zf_sessions"
#define LOG_FILE    "/var/log/zf.log"

/* ================== constants ============================ */
#define BUFFER_SIZE             8192
#define MAX_EVENTS_PARENT          5
#define MAX_EVENTS_PER_CHILD       4
#define MAX_RETRIES               10

static volatile sig_atomic_t g_quit_flag = 0;

/* ================== helpers ============================== */
static inline void set_cloexec(int fd){fcntl(fd,F_SETFD,fcntl(fd,F_GETFD)|FD_CLOEXEC);}
static inline void set_nonblock(int fd){fcntl(fd,F_SETFL,fcntl(fd,F_GETFL)|O_NONBLOCK);}
static inline void sanitize_id(char*s){for(char*p=s;*p;++p)if(!((*p>='A'&&*p<='Z')||(*p>='a'&&*p<='z')||(*p>='0'&&*p<='9')||*p=='-'||*p=='_'||*p=='.'))*p='_';}
static size_t safe_strcpy(char*d,size_t n,const char*s){size_t i=0;if(!n)return 0;while(i+1<n&&s[i]){d[i]=s[i];++i;}d[i]='\0';return i;}

/* ================== data ================================ */
typedef struct {
    char  id[128];
    pid_t pid;
    char  ip_version[8];
    char  local_addr[INET6_ADDRSTRLEN];
    int   local_port;
    char  remote_host[256];
    int   remote_port;
    int   check_interval;   /* s */
    int   timeout;          /* s idle */
} Session;

typedef struct {
    Session   session;
    FILE     *log_fp;
    pthread_t check_thread;
} PortForwarder;

/* ================== logging ============================= */
static FILE *g_log = NULL;
static void vlog(const char*sid,const char*lvl,const char*fmt,va_list ap){
    FILE*out=g_log?g_log:stderr;
    flockfile(out);
    char ts[32]; time_t now=time(NULL);
    strftime(ts,sizeof ts,"%Y-%m-%d %H:%M:%S",localtime(&now));
    fprintf(out,"%s [%s] [%s] ",ts,sid?sid:"INIT",lvl);
    vfprintf(out,fmt,ap); fputc('\n',out);
    funlockfile(out); fflush(out);
}
static void logm(const char*sid,const char*lvl,const char*fmt,...){va_list ap;va_start(ap,fmt);vlog(sid,lvl,fmt,ap);va_end(ap);}

/* ================== signal handlers ===================== */
static void sig_parent(int){g_quit_flag=1;}
static void sig_child_exit(int){while(waitpid(-1,NULL,WNOHANG)>0);}
static void sig_child_quit(int){_exit(0);}

/* ================== privilege drop ====================== */
static void drop_privileges(const char*user){
    if(geteuid()!=0) return;
    struct passwd*pw=getpwnam(user);
    if(!pw){logm(NULL,"WARN","User %s not found",user);return;}
    if(setgid(pw->pw_gid)||setuid(pw->pw_uid))
        logm(NULL,"WARN","Failed to drop privileges: %s",strerror(errno));
}

/* ================== networking helpers ================== */
static int create_listen_socket(const Session*s){
    int fam = strcmp(s->ip_version,"v6")?AF_INET:AF_INET6;
    int fd = socket(fam,SOCK_STREAM|SOCK_CLOEXEC,0); if(fd<0) return -1;
    int one=1; setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
    struct sockaddr_storage a={0};
    if(fam==AF_INET){
        struct sockaddr_in*v=(void*)&a;
        v->sin_family=AF_INET; v->sin_port=htons(s->local_port);
        if(inet_pton(AF_INET,s->local_addr,&v->sin_addr)!=1) return -2;
    }else{
        struct sockaddr_in6*v=(void*)&a;
        v->sin6_family=AF_INET6; v->sin6_port=htons(s->local_port);
        if(inet_pton(AF_INET6,s->local_addr,&v->sin6_addr)!=1) return -2;
    }
    if(bind(fd,(void*)&a,fam==AF_INET?sizeof(struct sockaddr_in):sizeof(struct sockaddr_in6))<0) return -3;
    if(listen(fd,SOMAXCONN)<0) return -4;
    set_nonblock(fd); return fd;
}

static int connect_remote(const Session*s){
    struct addrinfo h={0},*res=NULL,*rp; h.ai_socktype=SOCK_STREAM; h.ai_family=AF_UNSPEC;
    char port[16]; snprintf(port,sizeof port,"%d",s->remote_port);
    if(getaddrinfo(s->remote_host,port,&h,&res)!=0) return -1;
    int fd=-1;
    for(rp=res;rp;rp=rp->ai_next){
        fd=socket(rp->ai_family,rp->ai_socktype|SOCK_CLOEXEC,rp->ai_protocol); if(fd<0) continue;
        set_nonblock(fd);
        if(connect(fd,rp->ai_addr,rp->ai_addrlen)==0 || errno==EINPROGRESS) break;
        close(fd); fd=-1;
    }
    freeaddrinfo(res); return fd;
}

/* ================== child proxy loop ==================== */
static void proxy_loop(const Session *s, int cfd)
{
    int rfd = connect_remote(s);
    if (rfd < 0) { close(cfd); return; }

    set_nonblock(cfd);
    int ep = epoll_create1(EPOLL_CLOEXEC);

    struct epoll_event ev = { .events = EPOLLIN | EPOLLRDHUP | EPOLLERR };
    ev.data.fd = cfd; epoll_ctl(ep, EPOLL_CTL_ADD, cfd, &ev);
    ev.data.fd = rfd; epoll_ctl(ep, EPOLL_CTL_ADD, rfd, &ev);

    char buf[BUFFER_SIZE];
    bool quit = false;

    while (!quit && !g_quit_flag) {
        struct epoll_event e[MAX_EVENTS_PER_CHILD];
        int n = epoll_wait(ep, e, MAX_EVENTS_PER_CHILD, s->timeout * 1000);

        if (n == 0) {                       /* idle timeout */
            break;
        }
        if (n < 0) {
            if (errno == EINTR) continue;   /* 被信号打断 */
            break;
        }

        for (int i = 0; i < n; ++i) {
            int from = e[i].data.fd;
            int to   = (from == cfd) ? rfd : cfd;

            if (e[i].events & (EPOLLERR | EPOLLRDHUP | EPOLLHUP)) {
                quit = true; break;
            }

            if (e[i].events & EPOLLIN) {
                ssize_t r = read(from, buf, sizeof buf);
                if (r <= 0) { quit = true; break; }

                ssize_t off = 0;
                while (off < r) {
                    ssize_t w = write(to, buf + off, r - off);
                    if (w  > 0) off += w;
                    else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        /* 目标写缓冲满：简单退避 */
                        usleep(1000);
                    } else { quit = true; break; }
                }
            }
        }
    }

    shutdown(cfd, SHUT_RDWR); shutdown(rfd, SHUT_RDWR);
    close(cfd); close(rfd); close(ep);
}

/* ================== health check ======================== */
static void*health_thread(void*arg){
    PortForwarder*pf=arg; int fails=0;
    while(!g_quit_flag){
        int fd=connect_remote(&pf->session);
        if(fd<0){
            if(++fails>=MAX_RETRIES){
                logm(pf->session.id,"ERROR","remote unreachable – terminating");
                kill(pf->session.pid,SIGTERM); break;
            }
        }else{ fails=0; close(fd);}
        for(int i=0;i<pf->session.check_interval&&!g_quit_flag;++i) sleep(1);
    }
    return NULL;
}

/* ================== session files ======================= */
static void save_session(const Session*s){
    char p[256]; snprintf(p,sizeof p,"%s/%s.session",SESSION_DIR,s->id);
    FILE*f=fopen(p,"w"); if(!f) return;
    fprintf(f,"ID: %s\nPID: %d\nIPVersion: %s\nLocal: %s:%d\nRemote: %s:%d\nTimeout: %d\nCheckInterval: %d\n",
            s->id,s->pid,s->ip_version,s->local_addr,s->local_port,
            s->remote_host,s->remote_port,s->timeout,s->check_interval);
    fclose(f);
}
static void cleanup_files(const char*id){
    char p1[256],p2[256];
    snprintf(p1,sizeof p1,"%s/%s.session",SESSION_DIR,id);
    snprintf(p2,sizeof p2,"%s/%s.sock",SESSION_DIR,id);
    unlink(p1); unlink(p2);
}

/* ================== control socket ====================== */
static void handle_control(int ctrl_fd, const Session *s)
{
    int c = accept4(ctrl_fd, NULL, NULL, SOCK_CLOEXEC);
    if (c < 0) return;

    char buf[8] = {0};
    if (read(c, buf, sizeof buf - 1) < 0)
        perror("read");

    if (strcmp(buf, "kill") == 0)
        kill(s->pid, SIGTERM);

    close(c);
}


/* ================== utilities =========================== */
static void list_sessions(){
    DIR*dir=opendir(SESSION_DIR); if(!dir){perror("opendir"); return;}
    struct dirent*e; while((e=readdir(dir))){
        if(!strstr(e->d_name,".session")) continue;
        char p[512]; snprintf(p,sizeof p,"%s/%s",SESSION_DIR,e->d_name);
        FILE*f=fopen(p,"r"); if(!f) continue;
        printf("----------------------------\n");
        char line[256]; while(fgets(line,sizeof line,f)) printf("%s",line);
        fclose(f);
    }
    closedir(dir);
}

static void kill_session(const char *sid)
{
    char sockp[256];
    snprintf(sockp, sizeof sockp, "%s/%s.sock", SESSION_DIR, sid);

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) { perror("socket"); return; }

    struct sockaddr_un a = {0};
    a.sun_family = AF_UNIX;
    safe_strcpy(a.sun_path, sizeof a.sun_path, sockp);

    if (connect(fd, (void *)&a, sizeof a) < 0) {
        perror("connect"); close(fd); return;
    }

    if (write(fd, "kill", 4) < 0)
        perror("write");

    close(fd);
}


/* ================== argument parsing ==================== */
/* ------------------------------------------------------------- *
 * parse_args
 *   - 识别动作: 0=run, 1=-ls, 2=-h, 3=-k
 *   - 支持   : zf v4|v6 [<addr>:]port <remote_host:port> [options]
 *              若省略 <addr>:   → IPv4 默认 0.0.0.0，IPv6 默认 ::
 * ------------------------------------------------------------- */
static int parse_args(int argc, char **argv,
                      Session *s, int *act, char **kid)
{
    s->timeout        = 300;
    s->check_interval = 30;
    strcpy(s->ip_version, "v4");

    int idx = 1;

    /* ----------- 预处理动作 / 可能放前面的 -c/-t ----------- */
    while (idx < argc && argv[idx][0] == '-') {
        if (!strcmp(argv[idx], "-ls")) { *act = 1; return 0; }
        if (!strcmp(argv[idx], "-h"))  { *act = 2; return 0; }
        if (!strcmp(argv[idx], "-k") && idx + 1 < argc) {
            *act = 3; *kid = argv[++idx]; return 0;
        }
        if (!strcmp(argv[idx], "-c") && idx + 1 < argc)
            s->check_interval = atoi(argv[++idx]);
        else if (!strcmp(argv[idx], "-t") && idx + 1 < argc)
            s->timeout = atoi(argv[++idx]);
        else break;
        ++idx;
    }

    /* ---------- 必选 3 参数 ---------- */
    if (idx + 2 >= argc) {
        fprintf(stderr,
            "Usage: zf v4|v6 [<addr>:]port <remote_host:port> [options]\n");
        return -1;
    }
    if (strcmp(argv[idx], "v4") && strcmp(argv[idx], "v6")) {
        fprintf(stderr, "First arg must be v4 or v6\n"); return -1;
    }
    strcpy(s->ip_version, argv[idx++]);

    /* local 解析 (支持仅端口) */
    char *loc = argv[idx++];
    char *lp  = strchr(loc, ':');
    if (lp) { *lp = '\0';
              safe_strcpy(s->local_addr, sizeof s->local_addr, loc);
              s->local_port = atoi(lp + 1);
    } else { s->local_port = atoi(loc);
             if (!s->local_port || s->local_port > 65535){
                 fprintf(stderr,"Invalid port: %s\n",loc); return -1;}
             strcpy(s->local_addr,
                    strcmp(s->ip_version,"v6") ? "0.0.0.0" : "::"); }

    /* remote host:port */
    char *rem = argv[idx++];
    char *rp  = strrchr(rem, ':');
    if (!rp){ fprintf(stderr,"remote must be host:port\n"); return -1; }
    *rp = '\0';
    if (rem[0]=='['){
        safe_strcpy(s->remote_host,sizeof s->remote_host,rem+1);
        size_t l=strlen(s->remote_host);
        if (l && s->remote_host[l-1]==']') s->remote_host[l-1]='\0';
    } else safe_strcpy(s->remote_host,sizeof s->remote_host,rem);
    s->remote_port = atoi(rp+1);

    /* ----------- 二次扫描：允许 -c/-t 在后面出现 ----------- */
    while (idx < argc) {
        if (!strcmp(argv[idx], "-c") && idx + 1 < argc)
            s->check_interval = atoi(argv[++idx]);
        else if (!strcmp(argv[idx], "-t") && idx + 1 < argc)
            s->timeout = atoi(argv[++idx]);
        else {
            fprintf(stderr, "Unknown option: %s\n", argv[idx]);
            return -1;
        }
        ++idx;
    }

    /* 范围检查 */
    if (s->local_port<=0 || s->local_port>65535 ||
        s->remote_port<=0|| s->remote_port>65535){
        fprintf(stderr,"Port out of range 1-65535\n"); return -1;
    }
    return 0;
}

/* ---------- start_forwarding (父进程保持 root，无降权) --------- */

static void start_forwarding(PortForwarder *pf)
{
    int lfd = create_listen_socket(&pf->session);
    if (lfd < 0) {
        logm(pf->session.id, "ERROR", "listen failed: %s", strerror(errno));
        return;
    }

    /* ---------- 控制套接字 ---------- */
    char sockp[256];
    snprintf(sockp, sizeof sockp, "%s/%s.sock", SESSION_DIR, pf->session.id);
    unlink(sockp);

    int cfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un u = {0};
    u.sun_family = AF_UNIX;
    safe_strcpy(u.sun_path, sizeof u.sun_path, sockp);   /* ← 这里替换 */

    if (bind(cfd, (void *)&u, sizeof u) || listen(cfd, 5)) {
        logm(pf->session.id, "ERROR", "control socket bind/listen: %s", strerror(errno));
        close(lfd); close(cfd); return;
    }
    chmod(sockp, 0600);

    /* ---------- epoll & 线程 ---------- */
    int ep = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event ev = { .events = EPOLLIN };
    ev.data.fd = lfd; epoll_ctl(ep, EPOLL_CTL_ADD, lfd, &ev);
    ev.data.fd = cfd; epoll_ctl(ep, EPOLL_CTL_ADD, cfd, &ev);

    if (pf->session.check_interval > 0)
        pthread_create(&pf->check_thread, NULL, health_thread, pf);

    logm(pf->session.id, "INFO",
         "forwarder ready on %s:%d",
         pf->session.local_addr, pf->session.local_port);

    /* ---------- 事件循环 ---------- */
    while (!g_quit_flag) {
        struct epoll_event e[MAX_EVENTS_PARENT];
        int n = epoll_wait(ep, e, MAX_EVENTS_PARENT, -1);
        if (n < 0) { if (errno == EINTR) continue; break; }

        for (int i = 0; i < n; ++i) {
            if (e[i].data.fd == lfd) {
                int c = accept4(lfd, NULL, NULL, SOCK_CLOEXEC);
                if (c < 0) continue;

                pid_t pid = fork();
                if (pid == 0) {                    /* ── child ── */
                    if (geteuid() == 0) drop_privileges("nobody");
                    signal(SIGTERM, sig_child_quit);
                    signal(SIGINT,  sig_child_quit);
                    close(lfd); close(cfd); close(ep);
                    if (pf->check_thread) pthread_detach(pf->check_thread);
                    proxy_loop(&pf->session, c);
                    _exit(0);
                }
                close(c);                          /* parent */
            } else if (e[i].data.fd == cfd) {
                handle_control(cfd, &pf->session);
            }
        }
    }

    logm(pf->session.id, "INFO", "shutting down");
    if (pf->check_thread) pthread_cancel(pf->check_thread);
    close(lfd); close(cfd); close(ep);
}

/* ---------- end start_forwarding ------------------------- */


/* ----------------------- main (去掉父进程降权) ------------- */
int main(int argc, char **argv)
{
    struct rlimit rl = { .rlim_cur = 8192, .rlim_max = 8192 };
    setrlimit(RLIMIT_NOFILE, &rl);

    PortForwarder pf = {0};
    int act = 0;
    char *kid = NULL;

    mkdir(SESSION_DIR, 0700);

    if (parse_args(argc, argv, &pf.session, &act, &kid) < 0)
        return 1;

    if (act == 1) { list_sessions(); return 0; }
    if (act == 2) {
        puts("zf – secure port-forwarder\n"
             "\nUSAGE:\n"
             "  zf v4|v6 <local_addr:port> <remote_host:port> [options]\n"
             "\nOPTIONS:\n"
             "  -ls               List active sessions\n"
             "  -k <session_id>   Kill a session\n"
             "  -c <sec>          Health-check interval (default 30)\n"
             "  -t <sec>          Idle timeout (default 300)\n"
             "  -h                Show this help\n");
        return 0;
    }
    if (act == 3) { kill_session(kid); return 0; }

    /* —— daemonise —— */
    if (!getenv("ZF_DAEMON")) {
        pid_t p = fork(); if (p < 0) { perror("fork"); return 1; }
        if (p > 0) { printf("daemon pid %d\n", p); return 0; }
        setsid(); setenv("ZF_DAEMON", "1", 1);
        p = fork(); if (p > 0) _exit(0);

        if (chdir("/") < 0) perror("chdir");

        int null = open("/dev/null", O_RDWR);
        dup2(null, STDIN_FILENO);
        dup2(null, STDOUT_FILENO);
        dup2(null, STDERR_FILENO);
    }

    /* 日志初始化 */
    g_log = fopen(LOG_FILE, "a");
    if (!g_log) openlog("zf", LOG_PID | LOG_CONS, LOG_DAEMON);
    else        setvbuf(g_log, NULL, _IOLBF, 0);

    pf.session.pid = getpid();
    snprintf(pf.session.id, sizeof pf.session.id, "%s_%d-%ld",
             pf.session.local_addr, pf.session.local_port, time(NULL));
    sanitize_id(pf.session.id);
    save_session(&pf.session);

    struct sigaction sa = { .sa_handler = sig_parent };
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);

    struct sigaction sc = { .sa_handler = sig_child_exit,
                            .sa_flags   = SA_RESTART | SA_NOCLDSTOP };
    sigaction(SIGCHLD, &sc, NULL);

    logm(pf.session.id, "INFO", "daemon started pid %d", pf.session.pid);

    start_forwarding(&pf);

    logm(pf.session.id, "INFO", "daemon exiting");
    cleanup_files(pf.session.id);
    if (g_log) fclose(g_log);
    return 0;
}
/* --------------------- end main -------------------------- */
