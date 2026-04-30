#define _GNU_SOURCE

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <getopt.h>
#include <grp.h>
#include <netdb.h>
#include <pwd.h>
#include <rpc/pmap_clnt.h>
#include <rpc/rpc.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#ifndef ESTALE
#define ESTALE 116
#endif

#ifndef ENOATTR
#define ENOATTR ENODATA
#endif

#define NFS_PROGRAM 100003UL
#define MOUNT_PROGRAM 100005UL
#define NLM_PROGRAM 100021UL
#define NSM_PROGRAM 100024UL
#define MOUNTPROC_EXPORT 5
#define DEFAULT_TIMEOUT_SEC 5
#define DEFAULT_STALE_ITERATIONS 100
#define DEFAULT_BENCH_BYTES (4U * 1024U * 1024U)
#define MAX_EXPORTS 512
#define MAX_IDENTITIES 32
#define CMD_OUTPUT_LIMIT 8192
#define MAX_EVENTS 4096
#define MAX_RECOMMENDATIONS 128
#define MAX_MOUNTPOINTS 128
#define MAX_SUPP_GROUPS 64

struct options {
    int verbose;
    int no_mount;
    int keep_temp;
    int write_test;
    int timeout_sec;
    int command_timeout_sec;
    int stale_iterations;
    int bench_iterations;
    int json;
    int udp_checks;
    int nfs4_discovery;
    int mount_namespace;
    int address_family;
    size_t bench_bytes;
    gid_t supplemental_groups[MAX_SUPP_GROUPS];
    size_t supplemental_group_count;
    const char *json_path;
    const char *mount_options;
    const char *single_export;
    uid_t uids[MAX_IDENTITIES];
    gid_t gids[MAX_IDENTITIES];
    size_t identity_count;
};

struct rpc_service {
    unsigned long prog;
    unsigned long vers;
    unsigned long prot;
    unsigned long port;
};

struct rpc_services {
    struct rpc_service *items;
    size_t len;
    size_t cap;
};

struct export_item {
    char *path;
    char **groups;
    size_t group_count;
};

struct export_list {
    struct export_item items[MAX_EXPORTS];
    size_t count;
};

struct exportnode;
struct groupnode;
typedef struct exportnode *exports;
typedef struct groupnode *groups;

struct groupnode {
    char *gr_name;
    groups gr_next;
};

struct exportnode {
    char *ex_dir;
    groups ex_groups;
    exports ex_next;
};

struct mount_result {
    int mounted;
    int version;
    char mountpoint[4096];
};

static struct options opt = {
    .timeout_sec = DEFAULT_TIMEOUT_SEC,
    .command_timeout_sec = 30,
    .stale_iterations = DEFAULT_STALE_ITERATIONS,
    .bench_iterations = 10,
    .bench_bytes = DEFAULT_BENCH_BYTES,
    .write_test = 1,
    .nfs4_discovery = 1,
    .address_family = AF_UNSPEC,
};

struct report_event {
    char level[8];
    char message[512];
};

static struct report_event events[MAX_EVENTS];
static size_t event_count = 0;
static char recommendations[MAX_RECOMMENDATIONS][512];
static size_t recommendation_count = 0;
static char active_mountpoints[MAX_MOUNTPOINTS][4096];
static size_t active_mountpoint_count = 0;
static volatile sig_atomic_t received_signal = 0;
static int saved_stdout_fd = -1;
static char cleanup_base[128];
static int summary_ok = 0;
static int summary_warn = 0;
static int summary_fail = 0;

static void add_event(const char *level, const char *message) {
    if (event_count >= MAX_EVENTS) return;
    snprintf(events[event_count].level, sizeof(events[event_count].level), "%s", level);
    snprintf(events[event_count].message, sizeof(events[event_count].message), "%s", message);
    event_count++;
}

static void add_recommendation(const char *fmt, ...) {
    if (recommendation_count >= MAX_RECOMMENDATIONS) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(recommendations[recommendation_count], sizeof(recommendations[recommendation_count]), fmt, ap);
    va_end(ap);
    recommendation_count++;
}

static int important_ok_message(const char *msg) {
    return strstr(msg, "export(s) discovered") ||
           strstr(msg, "mounted ") ||
           strstr(msg, "no ESTALE") ||
           strstr(msg, "write+fsync benchmark") ||
           strstr(msg, "read benchmark") ||
           strstr(msg, "metadata latency benchmark") ||
           strstr(msg, "root_squash practical signal") ||
           strstr(msg, "using private mount namespace");
}

static void report_ok(const char *fmt, ...) {
    va_list ap;
    summary_ok++;
    char msg[512];
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    add_event("ok", msg);
    if (opt.verbose || important_ok_message(msg)) printf("[OK] %s\n", msg);
}

static void report_warn(const char *fmt, ...) {
    va_list ap;
    summary_warn++;
    char msg[512];
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    add_event("warn", msg);
    printf("[WARN] %s\n", msg);
}

static void report_fail(const char *fmt, ...) {
    va_list ap;
    summary_fail++;
    char msg[512];
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    add_event("fail", msg);
    printf("[FAIL] %s\n", msg);
}

static void report_info(const char *fmt, ...) {
    va_list ap;
    char msg[512];
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    add_event("info", msg);
    if (opt.verbose) printf("[INFO] %s\n", msg);
}

static void usage(const char *p) {
    printf("Usage: %s [OPTIONS] <server-ip-or-hostname>\n", p);
    printf("\nOptions:\n");
    printf("  -e, --export PATH          Test only this export. If omitted, exports are enumerated via mountd\n");
    printf("  -o, --mount-options OPTS   Extra mount options, e.g. ro,soft,timeo=30\n");
    printf("      --no-mount             Run network/RPC checks only\n");
    printf("      --keep-temp            Do not remove /tmp/nfsdoctor-* after tests\n");
    printf("      --read-only            Do not perform destructive write/create tests\n");
    printf("      --uid UID              Simulate access as UID. Repeatable, root required to switch UID\n");
    printf("      --gid GID              GID paired with the last --uid. Repeatable\n");
    printf("      --timeout SEC          Network/RPC timeout. Default: %d\n", DEFAULT_TIMEOUT_SEC);
    printf("      --command-timeout SEC  Timeout for mount/umount helper commands. Default: 30\n");
    printf("      --mount-namespace      Run mount tests inside a private mount namespace when possible\n");
    printf("      --json[=PATH]          Emit a machine-readable JSON report to PATH or stdout at the end\n");
    printf("      --groups G1,G2         Supplemental groups used by UID/GID simulation children\n");
    printf("      --udp                  Also probe RPC NULLPROC over UDP\n");
    printf("      --ipv4-only            Force IPv4 for direct TCP checks\n");
    printf("      --ipv6-only            Force IPv6 for direct TCP checks\n");
    printf("      --no-nfs4-discovery    Do not synthesize / for NFSv4-only pseudo-root discovery\n");
    printf("      --bench-iterations N   Metadata latency benchmark iterations. Default: 10\n");
    printf("      --stale-iterations N   stat/readdir iterations looking for ESTALE. Default: %d\n", DEFAULT_STALE_ITERATIONS);
    printf("      --bench-bytes BYTES    Bytes used in write/read latency benchmark. Default: %u\n", DEFAULT_BENCH_BYTES);
    printf("  -v, --verbose              Verbose output\n");
    printf("  -h, --help                 Show this help\n");
    printf("\nExit codes:\n");
    printf("  0 = no failures detected, 1 = warnings/failures detected, 2 = usage/runtime error\n");
}

static int parse_ulong_arg(const char *s, unsigned long *out) {
    char *end = NULL;
    errno = 0;
    unsigned long v = strtoul(s, &end, 10);
    if (errno || !end || *end != '\0') return -1;
    *out = v;
    return 0;
}

static int parse_groups_arg(const char *s) {
    char *copy = strdup(s);
    if (!copy) return -1;
    char *save = NULL;
    for (char *tok = strtok_r(copy, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        unsigned long value;
        if (parse_ulong_arg(tok, &value) != 0 || opt.supplemental_group_count >= MAX_SUPP_GROUPS) {
            free(copy);
            return -1;
        }
        opt.supplemental_groups[opt.supplemental_group_count++] = (gid_t)value;
    }
    free(copy);
    return 0;
}

static void add_identity(uid_t uid, gid_t gid) {
    if (opt.identity_count >= MAX_IDENTITIES) {
        report_warn("identity simulation limit reached (%d)", MAX_IDENTITIES);
        return;
    }
    opt.uids[opt.identity_count] = uid;
    opt.gids[opt.identity_count] = gid;
    opt.identity_count++;
}

static gid_t default_gid_for_uid(uid_t uid) {
    struct passwd *pw = getpwuid(uid);
    if (pw) return pw->pw_gid;
    return getgid();
}

static int tcp_connect_timeout(const char *host, int port, int timeout_sec) {
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *rp;
    char portstr[32];
    int last_errno = 0;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = opt.address_family;
    snprintf(portstr, sizeof(portstr), "%d", port);

    int gai = getaddrinfo(host, portstr, &hints, &res);
    if (gai != 0) {
        errno = EHOSTUNREACH;
        return -1;
    }

    for (rp = res; rp; rp = rp->ai_next) {
        int fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) {
            last_errno = errno;
            continue;
        }

        int flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        int rc = connect(fd, rp->ai_addr, rp->ai_addrlen);
        if (rc == 0) {
            close(fd);
            freeaddrinfo(res);
            return 0;
        }

        if (errno == EINPROGRESS) {
            fd_set wfds;
            struct timeval tv = { timeout_sec, 0 };
            FD_ZERO(&wfds);
            FD_SET(fd, &wfds);
            rc = select(fd + 1, NULL, &wfds, NULL, &tv);
            if (rc > 0) {
                int soerr = 0;
                socklen_t slen = sizeof(soerr);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen) == 0 && soerr == 0) {
                    close(fd);
                    freeaddrinfo(res);
                    return 0;
                }
                last_errno = soerr ? soerr : errno;
            } else if (rc == 0) {
                last_errno = ETIMEDOUT;
            } else {
                last_errno = errno;
            }
        } else {
            last_errno = errno;
        }

        close(fd);
    }

    freeaddrinfo(res);
    errno = last_errno ? last_errno : ECONNREFUSED;
    return -1;
}

static const char *proto_name(unsigned long proto) {
    if (proto == IPPROTO_TCP) return "tcp";
    if (proto == IPPROTO_UDP) return "udp";
    return "unknown";
}

static const char *rpc_program_name(unsigned long prog) {
    switch (prog) {
        case NFS_PROGRAM: return "nfs";
        case MOUNT_PROGRAM: return "mountd";
        case NLM_PROGRAM: return "lockd/nlm";
        case NSM_PROGRAM: return "statd/nsm";
        case PMAPPROG: return "rpcbind/portmapper";
        default: return "unknown";
    }
}

static void rpc_services_add(struct rpc_services *svc, unsigned long prog, unsigned long vers, unsigned long prot, unsigned long port) {
    if (svc->len == svc->cap) {
        size_t new_cap = svc->cap ? svc->cap * 2 : 32;
        struct rpc_service *new_items = realloc(svc->items, new_cap * sizeof(*new_items));
        if (!new_items) {
            report_fail("out of memory collecting RPC service map");
            return;
        }
        svc->items = new_items;
        svc->cap = new_cap;
    }
    svc->items[svc->len++] = (struct rpc_service){ prog, vers, prot, port };
}

static int rpc_services_has(const struct rpc_services *svc, unsigned long prog) {
    for (size_t i = 0; i < svc->len; i++) {
        if (svc->items[i].prog == prog) return 1;
    }
    return 0;
}

static int rpc_services_has_version(const struct rpc_services *svc, unsigned long prog, unsigned long vers) {
    for (size_t i = 0; i < svc->len; i++) {
        if (svc->items[i].prog == prog && svc->items[i].vers == vers) return 1;
    }
    return 0;
}

static int xdr_groupnode(XDR *xdrs, struct groupnode *objp);
static int xdr_exportnode(XDR *xdrs, struct exportnode *objp);

static bool_t xdr_void_proc(XDR *xdrs, ...) {
    (void)xdrs;
    return TRUE;
}

static int xdr_groups(XDR *xdrs, groups *objp) {
    return xdr_pointer(xdrs, (char **)objp, sizeof(struct groupnode), (xdrproc_t)xdr_groupnode);
}

static int xdr_exports(XDR *xdrs, exports *objp) {
    return xdr_pointer(xdrs, (char **)objp, sizeof(struct exportnode), (xdrproc_t)xdr_exportnode);
}

static int xdr_groupnode(XDR *xdrs, struct groupnode *objp) {
    return xdr_string(xdrs, &objp->gr_name, ~0U) && xdr_groups(xdrs, &objp->gr_next);
}

static int xdr_exportnode(XDR *xdrs, struct exportnode *objp) {
    return xdr_string(xdrs, &objp->ex_dir, ~0U) &&
           xdr_groups(xdrs, &objp->ex_groups) &&
           xdr_exports(xdrs, &objp->ex_next);
}

static CLIENT *rpc_client(const char *host, unsigned long prog, unsigned long vers, const char *proto) {
    CLIENT *cl = clnt_create(host, prog, vers, proto);
    if (!cl && opt.verbose) clnt_pcreateerror((char *)host);
    if (cl) {
        struct timeval tv = { opt.timeout_sec, 0 };
        clnt_control(cl, CLSET_TIMEOUT, (char *)&tv);
    }
    return cl;
}

static int rpc_null_call(const char *host, unsigned long prog, unsigned long vers, const char *proto, enum clnt_stat *out_stat) {
    CLIENT *cl = rpc_client(host, prog, vers, proto);
    if (!cl) return -1;
    struct timeval tv = { opt.timeout_sec, 0 };
    enum clnt_stat st = clnt_call(cl, NULLPROC, xdr_void_proc, NULL, xdr_void_proc, NULL, tv);
    if (out_stat) *out_stat = st;
    clnt_destroy(cl);
    return st == RPC_SUCCESS ? 0 : -1;
}

static void network_tests(const char *host) {
    if (opt.verbose) printf("\n[+] Network checks\n");

    if (tcp_connect_timeout(host, 111, opt.timeout_sec) == 0)
        report_ok("rpcbind TCP port 111 reachable");
    else {
        report_fail("rpcbind TCP port 111 unreachable: %s", strerror(errno));
        add_recommendation("TCP/111 is unreachable: check firewall, rpcbind status, routing, or whether the server is intentionally NFSv4-only.");
    }

    if (tcp_connect_timeout(host, 2049, opt.timeout_sec) == 0)
        report_ok("NFS TCP port 2049 reachable");
    else {
        report_fail("NFS TCP port 2049 unreachable: %s", strerror(errno));
        add_recommendation("TCP/2049 is unreachable: verify nfsd/ganesha is running and allowed through firewalls/security groups.");
    }
}

static void check_rpcbind(const char *host, struct rpc_services *svc) {
    if (opt.verbose) printf("\n[+] rpcbind / portmapper\n");

    struct addrinfo hints;
    struct addrinfo *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int gai = getaddrinfo(host, NULL, &hints, &res);
    if (gai != 0 || !res) {
        report_fail("cannot resolve %s as IPv4 for legacy portmapper query: %s", host, gai_strerror(gai));
        if (res) freeaddrinfo(res);
        return;
    }

    struct sockaddr_in addr = *(struct sockaddr_in *)res->ai_addr;
    addr.sin_port = htons(111);

    struct pmaplist *list = pmap_getmaps(&addr);
    freeaddrinfo(res);

    if (!list) {
        report_fail("cannot fetch RPC service map; rpcbind may be filtered or UDP-only behavior may be blocked");
        return;
    }

    report_ok("RPC service map fetched");
    for (struct pmaplist *p = list; p; p = p->pml_next) {
        rpc_services_add(svc, p->pml_map.pm_prog, p->pml_map.pm_vers, p->pml_map.pm_prot, p->pml_map.pm_port);
        if (opt.verbose) {
            report_info("program=%lu (%s) version=%lu proto=%s port=%lu",
                        p->pml_map.pm_prog,
                        rpc_program_name(p->pml_map.pm_prog),
                        p->pml_map.pm_vers,
                        proto_name(p->pml_map.pm_prot),
                        p->pml_map.pm_port);
        }
    }

    if (rpc_services_has(svc, NFS_PROGRAM)) report_ok("NFS service is registered in rpcbind");
    else report_warn("NFS service is not present in rpcbind map; NFSv4 may still answer on TCP/2049");

    if (rpc_services_has(svc, MOUNT_PROGRAM)) report_ok("mountd service is registered in rpcbind");
    else report_warn("mountd service not registered; NFSv3 exports/mount tests may fail, NFSv4 may still work");

    if (rpc_services_has(svc, NLM_PROGRAM)) report_ok("NLM/lockd service is registered");
    else {
        report_warn("NLM/lockd not registered; NFSv3 advisory locking may be unavailable or firewall-blocked");
        add_recommendation("NLM/lockd is missing: for NFSv3 locking, verify lockd ports and firewall rules; NFSv4 may not need separate lockd.");
    }

    if (rpc_services_has(svc, NSM_PROGRAM)) report_ok("NSM/statd service is registered");
    else {
        report_warn("NSM/statd not registered; NFSv3 lock recovery may be unavailable");
        add_recommendation("NSM/statd is missing: NFSv3 lock recovery can fail; start rpc.statd or open its firewall path.");
    }
}

static void check_nfs_versions(const char *host, const struct rpc_services *svc) {
    if (opt.verbose) printf("\n[+] NFS protocol versions\n");

    for (int v = 2; v <= 4; v++) {
        enum clnt_stat st = RPC_FAILED;
        if (rpc_null_call(host, NFS_PROGRAM, (unsigned long)v, "tcp", &st) == 0) {
            report_ok("NFS v%d answers NULLPROC over TCP", v);
        } else if (rpc_services_has_version(svc, NFS_PROGRAM, (unsigned long)v)) {
            report_warn("NFS v%d appears in rpcbind but NULLPROC over TCP failed: %s", v, clnt_sperrno(st));
        } else {
            if (v == 2) report_info("NFS v%d not detected", v);
            else report_warn("NFS v%d not detected", v);
        }

        if (opt.udp_checks) {
            enum clnt_stat ust = RPC_FAILED;
            if (rpc_null_call(host, NFS_PROGRAM, (unsigned long)v, "udp", &ust) == 0) report_ok("NFS v%d answers NULLPROC over UDP", v);
            else report_warn("NFS v%d UDP NULLPROC failed or filtered: %s", v, clnt_sperrno(ust));
        }
    }
}

static void check_mountd_versions(const char *host, const struct rpc_services *svc) {
    if (opt.verbose) printf("\n[+] mountd versions\n");

    for (int v = 1; v <= 3; v++) {
        enum clnt_stat st = RPC_FAILED;
        if (rpc_null_call(host, MOUNT_PROGRAM, (unsigned long)v, "tcp", &st) == 0) {
            report_ok("mountd v%d answers NULLPROC over TCP", v);
        } else if (rpc_services_has_version(svc, MOUNT_PROGRAM, (unsigned long)v)) {
            report_warn("mountd v%d appears in rpcbind but NULLPROC over TCP failed: %s", v, clnt_sperrno(st));
        } else {
            report_warn("mountd v%d not detected", v);
        }

        if (opt.udp_checks) {
            enum clnt_stat ust = RPC_FAILED;
            if (rpc_null_call(host, MOUNT_PROGRAM, (unsigned long)v, "udp", &ust) == 0) report_ok("mountd v%d answers NULLPROC over UDP", v);
            else report_warn("mountd v%d UDP NULLPROC failed or filtered: %s", v, clnt_sperrno(ust));
        }
    }
}

static void add_export_from_rpc(struct export_list *out, const char *path, groups gr) {
    if (!path || out->count >= MAX_EXPORTS) return;

    struct export_item *item = &out->items[out->count++];
    item->path = strdup(path);

    size_t group_count = 0;
    for (groups g = gr; g; g = g->gr_next) group_count++;
    item->groups = calloc(group_count ? group_count : 1, sizeof(char *));
    if (!item->groups) return;

    for (groups g = gr; g; g = g->gr_next) {
        item->groups[item->group_count++] = strdup(g->gr_name ? g->gr_name : "(null)");
    }
}

static void enumerate_exports(const char *host, struct export_list *out) {
    if (opt.verbose) printf("\n[+] Export enumeration\n");

    if (opt.single_export) {
        out->items[0].path = strdup(opt.single_export);
        out->items[0].groups = calloc(1, sizeof(char *));
        out->count = 1;
        report_info("using export supplied by user: %s", opt.single_export);
        return;
    }

    CLIENT *cl = rpc_client(host, MOUNT_PROGRAM, 3, "tcp");
    if (!cl) cl = rpc_client(host, MOUNT_PROGRAM, 1, "tcp");
    if (!cl) {
        report_fail("cannot contact mountd to enumerate exports; use --export PATH for NFSv4-only or filtered servers");
        add_recommendation("mountd is unavailable; if this is an NFSv4-only server, try --export / or keep NFSv4 pseudo-root discovery enabled.");
        if (opt.nfs4_discovery) {
            add_export_from_rpc(out, "/", NULL);
            report_info("NFSv4 pseudo-root discovery enabled: will try synthetic export / during mount tests");
        }
        return;
    }

    exports ex = NULL;
    struct timeval tv = { opt.timeout_sec, 0 };
    enum clnt_stat st = clnt_call(cl, MOUNTPROC_EXPORT,
                                      xdr_void_proc, NULL,
                                      (xdrproc_t)xdr_exports, (char *)&ex,
                                      tv);

    if (st != RPC_SUCCESS) {
        report_fail("mountd EXPORT call failed: %s", clnt_sperrno(st));
        clnt_destroy(cl);
        return;
    }

    for (exports e = ex; e; e = e->ex_next) add_export_from_rpc(out, e->ex_dir, e->ex_groups);

    if (out->count == 0) {
        report_warn("server returned an empty export list");
        if (opt.nfs4_discovery) {
            add_export_from_rpc(out, "/", NULL);
            report_info("NFSv4 pseudo-root discovery enabled: will try synthetic export / during mount tests");
        }
    } else {
        report_ok("%zu export(s) discovered", out->count);
        for (size_t i = 0; i < out->count; i++) {
            if (opt.verbose) {
                printf("  - %s", out->items[i].path);
                if (out->items[i].group_count) {
                    printf("  allowed clients/groups:");
                    for (size_t g = 0; g < out->items[i].group_count; g++) printf(" %s", out->items[i].groups[g]);
                }
                putchar('\n');
            }
        }
    }

    clnt_freeres(cl, (xdrproc_t)xdr_exports, (char *)&ex);
    clnt_destroy(cl);
}

static int run_command_capture(char *const argv[], char *output, size_t output_sz) {
    int pipefd[2];
    if (pipe(pipefd) != 0) return -1;

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        setpgid(0, 0);
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        execvp(argv[0], argv);
        fprintf(stderr, "execvp(%s) failed: %s\n", argv[0], strerror(errno));
        _exit(127);
    }

    setpgid(pid, pid);
    close(pipefd[1]);
    int flags = fcntl(pipefd[0], F_GETFL, 0);
    if (flags >= 0) fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);

    size_t used = 0;
    int status = 0;
    int child_done = 0;
    time_t deadline = time(NULL) + opt.command_timeout_sec;

    while (!child_done) {
        ssize_t n;
        while ((n = read(pipefd[0], output + used, output_sz > used + 1 ? output_sz - used - 1 : 0)) > 0) {
            used += (size_t)n;
            if (used >= output_sz - 1) break;
        }

        pid_t wr = waitpid(pid, &status, WNOHANG);
        if (wr == pid) {
            child_done = 1;
            break;
        }
        if (wr < 0 && errno != EINTR) break;

        if (time(NULL) >= deadline) {
            kill(-pid, SIGTERM);
            usleep(200000);
            kill(-pid, SIGKILL);
            while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
            if (output_sz) {
                snprintf(output + (used < output_sz ? used : output_sz - 1),
                         used < output_sz ? output_sz - used : 1,
                         "%scommand timed out after %d seconds",
                         used ? "\n" : "", opt.command_timeout_sec);
            }
            close(pipefd[0]);
            return 124;
        }

        fd_set rfds;
        struct timeval tv = {0, 100000};
        FD_ZERO(&rfds);
        FD_SET(pipefd[0], &rfds);
        (void)select(pipefd[0] + 1, &rfds, NULL, NULL, &tv);
    }

    ssize_t n;
    while ((n = read(pipefd[0], output + used, output_sz > used + 1 ? output_sz - used - 1 : 0)) > 0) {
        used += (size_t)n;
        if (used >= output_sz - 1) break;
    }
    if (output_sz) output[used < output_sz ? used : output_sz - 1] = '\0';
    close(pipefd[0]);

    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return -1;
}

static void register_mountpoint(const char *mountpoint) {
    if (active_mountpoint_count >= MAX_MOUNTPOINTS) return;
    snprintf(active_mountpoints[active_mountpoint_count], sizeof(active_mountpoints[active_mountpoint_count]), "%s", mountpoint);
    active_mountpoint_count++;
}

static void unregister_mountpoint(const char *mountpoint) {
    for (size_t i = 0; i < active_mountpoint_count; i++) {
        if (strcmp(active_mountpoints[i], mountpoint) == 0) {
            for (size_t j = i + 1; j < active_mountpoint_count; j++) {
                snprintf(active_mountpoints[j - 1], sizeof(active_mountpoints[j - 1]), "%s", active_mountpoints[j]);
            }
            active_mountpoint_count--;
            return;
        }
    }
}

static int make_dir(const char *path, mode_t mode) {
    if (mkdir(path, mode) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

static void compose_source(char *dst, size_t dst_sz, const char *host, const char *export_path) {
    snprintf(dst, dst_sz, "%s:%s", host, export_path);
}

static void compose_options(char *dst, size_t dst_sz, int version) {
    if (opt.mount_options && opt.mount_options[0]) {
        snprintf(dst, dst_sz, "vers=%d,%s", version, opt.mount_options);
    } else {
        snprintf(dst, dst_sz, "vers=%d", version);
    }
}

static int mount_export(const char *host, const char *export_path, const char *mountpoint, struct mount_result *mr) {
    char source[4096];
    char options[2048];
    char output[CMD_OUTPUT_LIMIT];

    memset(mr, 0, sizeof(*mr));
    snprintf(mr->mountpoint, sizeof(mr->mountpoint), "%s", mountpoint);
    compose_source(source, sizeof(source), host, export_path);

    int versions[] = {4, 3};
    for (size_t i = 0; i < sizeof(versions) / sizeof(versions[0]); i++) {
        compose_options(options, sizeof(options), versions[i]);
        char *argv[] = { "mount", "-t", "nfs", "-o", options, source, (char *)mountpoint, NULL };
        memset(output, 0, sizeof(output));

        if (opt.verbose) report_info("running: mount -t nfs -o %s %s %s", options, source, mountpoint);
        int rc = run_command_capture(argv, output, sizeof(output));
        if (rc == 0) {
            mr->mounted = 1;
            mr->version = versions[i];
            register_mountpoint(mountpoint);
            report_ok("mounted %s at %s with NFS v%d", source, mountpoint, versions[i]);
            return 0;
        }

        if (versions[i] == 4) report_warn("NFS v4 mount attempt failed for %s: %s", export_path, output[0] ? output : "no output");
        else report_fail("NFS v3 mount attempt failed for %s: %s", export_path, output[0] ? output : "no output");
    }

    return -1;
}

static int unmount_export(const char *mountpoint) {
    char output[CMD_OUTPUT_LIMIT];
    char *argv[] = { "umount", (char *)mountpoint, NULL };
    int rc = run_command_capture(argv, output, sizeof(output));
    if (rc == 0) {
        unregister_mountpoint(mountpoint);
        report_ok("unmounted %s", mountpoint);
        return 0;
    }

    report_warn("normal umount failed for %s: %s", mountpoint, output[0] ? output : "no output");
    char *lazy_argv[] = { "umount", "-l", (char *)mountpoint, NULL };
    rc = run_command_capture(lazy_argv, output, sizeof(output));
    if (rc == 0) {
        unregister_mountpoint(mountpoint);
        report_warn("lazy unmount succeeded for %s", mountpoint);
        return 0;
    }

    report_fail("lazy umount also failed for %s: %s", mountpoint, output[0] ? output : "no output");
    return -1;
}

static int unlink_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    (void)sb;
    (void)typeflag;
    (void)ftwbuf;
    if (remove(fpath) != 0 && errno != ENOENT) {
        fprintf(stderr, "[WARN] cleanup remove(%s) failed: %s\n", fpath, strerror(errno));
    }
    return 0;
}

static void cleanup_temp_tree(void) {
    if (!cleanup_base[0] || opt.keep_temp) return;
    nftw(cleanup_base, unlink_cb, 32, FTW_DEPTH | FTW_PHYS);
    cleanup_base[0] = '\0';
}

static void cleanup_all(void) {
    while (active_mountpoint_count > 0) {
        char mp[4096];
        snprintf(mp, sizeof(mp), "%s", active_mountpoints[active_mountpoint_count - 1]);
        (void)unmount_export(mp);
    }
    cleanup_temp_tree();
}

static void signal_handler(int sig) {
    received_signal = sig;
}

static void install_cleanup_handlers(void) {
    atexit(cleanup_all);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGHUP, signal_handler);
}

static double elapsed_ms(struct timespec a, struct timespec b) {
    return (double)(b.tv_sec - a.tv_sec) * 1000.0 + (double)(b.tv_nsec - a.tv_nsec) / 1000000.0;
}

static void test_basic_mount_info(const char *mountpoint) {
    struct stat st;
    if (stat(mountpoint, &st) == 0) {
        report_ok("stat mount root succeeded: inode=%lu mode=%o uid=%lu gid=%lu",
                  (unsigned long)st.st_ino, st.st_mode & 07777,
                  (unsigned long)st.st_uid, (unsigned long)st.st_gid);
    } else if (errno == ESTALE) {
        report_fail("stat mount root returned ESTALE (stale file handle)");
    } else {
        report_fail("stat mount root failed: %s", strerror(errno));
    }

    struct statvfs vfs;
    if (statvfs(mountpoint, &vfs) == 0) {
        unsigned long long total = (unsigned long long)vfs.f_blocks * vfs.f_frsize;
        unsigned long long avail = (unsigned long long)vfs.f_bavail * vfs.f_frsize;
        report_ok("statvfs succeeded: total=%llu bytes available=%llu bytes", total, avail);
    } else if (errno == ESTALE) {
        report_fail("statvfs returned ESTALE (stale file handle)");
    } else {
        report_warn("statvfs failed: %s", strerror(errno));
    }
}

static void test_directory_access(const char *mountpoint) {
    if (access(mountpoint, R_OK | X_OK) == 0) report_ok("directory read/traverse access allowed for current identity");
    else report_warn("directory read/traverse access denied for current identity: %s", strerror(errno));

    DIR *d = opendir(mountpoint);
    if (!d) {
        if (errno == ESTALE) report_fail("opendir returned ESTALE (stale file handle)");
        else report_warn("opendir failed: %s", strerror(errno));
        return;
    }

    int entries = 0;
    errno = 0;
    while (readdir(d) && entries < 32) entries++;
    if (errno == ESTALE) report_fail("readdir returned ESTALE (stale file handle)");
    else if (errno) report_warn("readdir failed after %d entries: %s", entries, strerror(errno));
    else report_ok("directory listing succeeded; sampled %d entries", entries);
    closedir(d);
}

static void test_acl(const char *mountpoint) {
    ssize_t sz = getxattr(mountpoint, "system.posix_acl_access", NULL, 0);
    if (sz > 0) report_ok("POSIX ACL detected on export root (%zd bytes)", sz);
    else if (sz == 0) report_info("POSIX ACL xattr exists but is empty");
    else if (errno == ENODATA || errno == ENOATTR) report_info("no POSIX ACL xattr detected on export root");
    else if (errno == EOPNOTSUPP || errno == ENOTSUP) report_info("ACL xattrs are not supported or hidden by this mount: %s", strerror(errno));
    else if (errno == EACCES || errno == EPERM) report_warn("cannot read ACL xattr due to permissions: %s", strerror(errno));
    else report_warn("ACL xattr probe failed: %s", strerror(errno));
}

static int fill_file(int fd, size_t bytes) {
    char buf[65536];
    memset(buf, 'N', sizeof(buf));
    size_t left = bytes;
    while (left) {
        size_t chunk = left < sizeof(buf) ? left : sizeof(buf);
        ssize_t w = write(fd, buf, chunk);
        if (w < 0) return -1;
        if (w == 0) return -1;
        left -= (size_t)w;
    }
    return 0;
}

static void make_test_path(char *dst, size_t dst_sz, const char *mountpoint, const char *suffix) {
    snprintf(dst, dst_sz, "%s/.nfsdoctor-%ld-%s", mountpoint, (long)getpid(), suffix);
}

static int cmp_double(const void *a, const void *b) {
    double da = *(const double *)a;
    double db = *(const double *)b;
    return (da > db) - (da < db);
}

static void test_metadata_latency(const char *mountpoint) {
    if (!opt.write_test || opt.bench_iterations <= 0) return;
    double *samples = calloc((size_t)opt.bench_iterations, sizeof(double));
    if (!samples) return;

    int completed = 0;
    for (int i = 0; i < opt.bench_iterations; i++) {
        char path[4096], renamed[8192];
        snprintf(path, sizeof(path), "%s/.nfsdoctor-meta-%ld-%d", mountpoint, (long)getpid(), i);
        snprintf(renamed, sizeof(renamed), "%s.renamed", path);
        struct timespec a, b;
        clock_gettime(CLOCK_MONOTONIC, &a);
        int fd = open(path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
        if (fd < 0) break;
        write(fd, "x", 1);
        close(fd);
        if (rename(path, renamed) != 0) { unlink(path); break; }
        if (unlink(renamed) != 0) break;
        clock_gettime(CLOCK_MONOTONIC, &b);
        samples[completed++] = elapsed_ms(a, b);
    }

    if (completed > 0) {
        qsort(samples, (size_t)completed, sizeof(double), cmp_double);
        double p50 = samples[completed / 2];
        double p95 = samples[(int)((completed - 1) * 0.95)];
        double p99 = samples[(int)((completed - 1) * 0.99)];
        report_ok("metadata latency benchmark create+rename+unlink: n=%d p50=%.2fms p95=%.2fms p99=%.2fms", completed, p50, p95, p99);
    } else {
        report_info("metadata latency benchmark skipped because no metadata write iteration completed");
    }
    free(samples);
}

static void test_write_read_perf_lock_root_squash(const char *mountpoint) {
    if (!opt.write_test) {
        report_info("write/read, locking, performance and root_squash practical tests skipped by --read-only");
        return;
    }

    char path[4096];
    make_test_path(path, sizeof(path), mountpoint, "io-test");

    struct timespec w0, w1, r0, r1;
    clock_gettime(CLOCK_MONOTONIC, &w0);
    int fd = open(path, O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0600);
    if (fd < 0) {
        if (errno == ESTALE) report_fail("creating test file returned ESTALE (stale file handle)");
        else report_warn("cannot create test file; export may be read-only or permission denied: %s", strerror(errno));
        add_recommendation("Create/write failed: check export ro/rw options, UNIX mode bits, ACLs, root_squash, idmapping, and server-side MAC policies.");
        return;
    }

    if (fill_file(fd, opt.bench_bytes) != 0) {
        if (errno == ESTALE) report_fail("write returned ESTALE (stale file handle)");
        else report_fail("write test failed: %s", strerror(errno));
        close(fd);
        unlink(path);
        return;
    }

    if (fsync(fd) != 0) report_warn("fsync failed: %s", strerror(errno));
    clock_gettime(CLOCK_MONOTONIC, &w1);

    struct flock fl;
    memset(&fl, 0, sizeof(fl));
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    if (fcntl(fd, F_SETLK, &fl) == 0) {
        report_ok("fcntl advisory write lock succeeded (basic NLM/NFSv4 locking path works for this file)");
        fl.l_type = F_UNLCK;
        (void)fcntl(fd, F_SETLK, &fl);
    } else {
        report_warn("fcntl advisory lock failed: %s", strerror(errno));
    }

    struct stat st;
    if (fstat(fd, &st) == 0) {
        if (geteuid() == 0) {
            if (st.st_uid == 0) report_ok("root_squash practical signal: file created by root is owned by uid 0 (likely no_root_squash for this client)");
            else {
                report_warn("root_squash practical signal: file created by root is owned by uid %lu gid %lu (root is likely squashed)",
                             (unsigned long)st.st_uid, (unsigned long)st.st_gid);
                add_recommendation("root_squash appears active: run tests as the application UID/GID with --uid/--gid to validate real access.");
            }
        } else {
            report_info("root_squash practical test requires running this tool as root; current euid=%lu", (unsigned long)geteuid());
        }
    } else if (errno == ESTALE) {
        report_fail("fstat test file returned ESTALE (stale file handle)");
    } else {
        report_warn("fstat test file failed: %s", strerror(errno));
    }

    lseek(fd, 0, SEEK_SET);
    char buf[65536];
    size_t left = opt.bench_bytes;
    clock_gettime(CLOCK_MONOTONIC, &r0);
    while (left) {
        size_t chunk = left < sizeof(buf) ? left : sizeof(buf);
        ssize_t n = read(fd, buf, chunk);
        if (n < 0) {
            if (errno == ESTALE) report_fail("read returned ESTALE (stale file handle)");
            else report_fail("readback failed: %s", strerror(errno));
            break;
        }
        if (n == 0) break;
        left -= (size_t)n;
    }
    clock_gettime(CLOCK_MONOTONIC, &r1);

    double write_ms = elapsed_ms(w0, w1);
    double read_ms = elapsed_ms(r0, r1);
    double mib = (double)opt.bench_bytes / (1024.0 * 1024.0);
    if (write_ms > 0.0) report_ok("write+fsync benchmark: %.2f MiB in %.2f ms (%.2f MiB/s)", mib, write_ms, mib / (write_ms / 1000.0));
    if (read_ms > 0.0) report_ok("read benchmark: %.2f MiB in %.2f ms (%.2f MiB/s)", mib, read_ms, mib / (read_ms / 1000.0));

    close(fd);
    if (unlink(path) == 0) report_ok("test file cleanup succeeded");
    else report_warn("test file cleanup failed: %s", strerror(errno));
}

static int child_identity_probe(const char *mountpoint, uid_t uid, gid_t gid) {
    if (opt.supplemental_group_count > 0 && setgroups(opt.supplemental_group_count, opt.supplemental_groups) != 0) _exit(12);
    if (setgid(gid) != 0) _exit(10);
    if (setuid(uid) != 0) _exit(11);

    if (access(mountpoint, R_OK | X_OK) != 0) _exit(20);
    if (!opt.write_test) _exit(0);

    char path[4096];
    snprintf(path, sizeof(path), "%s/.nfsdoctor-identity-%ld-%lu", mountpoint, (long)getpid(), (unsigned long)uid);
    int fd = open(path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
    if (fd < 0) _exit(errno == EACCES || errno == EPERM || errno == EROFS ? 21 : 22);
    if (write(fd, "x", 1) != 1) {
        close(fd);
        unlink(path);
        _exit(23);
    }
    close(fd);
    unlink(path);
    _exit(0);
}

static void test_identity_simulation(const char *mountpoint) {
    if (opt.verbose) printf("\n    [identity simulation]\n");
    int user_requested_identity = opt.identity_count > 0;
    if (opt.identity_count == 0) {
        add_identity(geteuid(), getegid());
        struct passwd *nobody = getpwnam("nobody");
        if (geteuid() == 0 && nobody) add_identity(nobody->pw_uid, nobody->pw_gid);
    }

    if (geteuid() != 0) {
        report_info("not running as root; UID/GID simulation is limited to current identity only");
    }

    for (size_t i = 0; i < opt.identity_count; i++) {
        uid_t uid = opt.uids[i];
        gid_t gid = opt.gids[i];
        if (uid != geteuid() && geteuid() != 0) {
            report_warn("cannot simulate uid=%lu gid=%lu without root", (unsigned long)uid, (unsigned long)gid);
            continue;
        }

        pid_t pid = fork();
        if (pid < 0) {
            report_warn("fork failed for identity simulation: %s", strerror(errno));
            continue;
        }
        if (pid == 0) child_identity_probe(mountpoint, uid, gid);

        int status = 0;
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
        int code = WIFEXITED(status) ? WEXITSTATUS(status) : 255;
        if (code == 0) report_ok("uid=%lu gid=%lu can traverse/read%s", (unsigned long)uid, (unsigned long)gid, opt.write_test ? " and create/write" : "");
        else if (code == 20) {
            if (user_requested_identity) report_warn("uid=%lu gid=%lu cannot traverse/read export root", (unsigned long)uid, (unsigned long)gid);
            else report_info("uid=%lu gid=%lu cannot traverse/read export root", (unsigned long)uid, (unsigned long)gid);
        } else if (code == 21) {
            if (user_requested_identity) report_warn("uid=%lu gid=%lu can read/traverse but cannot create/write", (unsigned long)uid, (unsigned long)gid);
            else report_info("uid=%lu gid=%lu can read/traverse but cannot create/write", (unsigned long)uid, (unsigned long)gid);
        } else if (code == 10 || code == 11 || code == 12) report_warn("failed to switch to uid=%lu gid=%lu groups=%zu for simulation", (unsigned long)uid, (unsigned long)gid, opt.supplemental_group_count);
        else report_warn("uid=%lu gid=%lu simulation failed with code %d", (unsigned long)uid, (unsigned long)gid, code);
    }
}

static void test_stale_loop(const char *mountpoint) {
    if (opt.verbose) printf("\n    [stale handle loop]\n");
    int estale_seen = 0;
    for (int i = 0; i < opt.stale_iterations; i++) {
        struct stat st;
        if (stat(mountpoint, &st) != 0) {
            if (errno == ESTALE) {
                estale_seen = 1;
                report_fail("ESTALE detected during stat loop at iteration %d", i + 1);
                break;
            }
            report_warn("stat loop failed at iteration %d: %s", i + 1, strerror(errno));
            break;
        }

        DIR *d = opendir(mountpoint);
        if (!d) {
            if (errno == ESTALE) {
                estale_seen = 1;
                report_fail("ESTALE detected during opendir loop at iteration %d", i + 1);
                break;
            }
            report_warn("opendir loop failed at iteration %d: %s", i + 1, strerror(errno));
            break;
        }
        errno = 0;
        (void)readdir(d);
        if (errno == ESTALE) {
            estale_seen = 1;
            report_fail("ESTALE detected during readdir loop at iteration %d", i + 1);
            closedir(d);
            break;
        }
        closedir(d);
    }

    if (!estale_seen) report_ok("no ESTALE observed in %d stat/readdir iterations", opt.stale_iterations);
}

static void diagnose_mounted_export(const char *export_path, const char *mountpoint) {
    if (opt.verbose) printf("\n[+] Mounted export diagnostics: %s at %s\n", export_path, mountpoint);
    test_basic_mount_info(mountpoint);
    test_directory_access(mountpoint);
    test_acl(mountpoint);
    test_identity_simulation(mountpoint);
    test_write_read_perf_lock_root_squash(mountpoint);
    test_metadata_latency(mountpoint);
    test_stale_loop(mountpoint);
}

static void free_exports(struct export_list *list) {
    for (size_t i = 0; i < list->count; i++) {
        free(list->items[i].path);
        for (size_t g = 0; g < list->items[i].group_count; g++) free(list->items[i].groups[g]);
        free(list->items[i].groups);
    }
    memset(list, 0, sizeof(*list));
}

static void json_escape(FILE *f, const char *s) {
    for (; s && *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '\\' || c == '"') fprintf(f, "\\%c", c);
        else if (c == '\n') fputs("\\n", f);
        else if (c == '\r') fputs("\\r", f);
        else if (c == '\t') fputs("\\t", f);
        else if (c < 32) fprintf(f, "\\u%04x", c);
        else fputc(c, f);
    }
}

static void enable_json_only_output(void) {
    if (!opt.json) return;
    fflush(stdout);
    saved_stdout_fd = dup(STDOUT_FILENO);
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
        dup2(devnull, STDOUT_FILENO);
        close(devnull);
    }
}

static void write_json_report(const char *host) {
    if (!opt.json) return;
    FILE *f = NULL;
    if (opt.json_path && strcmp(opt.json_path, "-") != 0) {
        f = fopen(opt.json_path, "w");
        if (!f) return;
    } else if (saved_stdout_fd >= 0) {
        f = fdopen(dup(saved_stdout_fd), "w");
        if (!f) return;
    } else {
        f = stdout;
    }

    time_t now = time(NULL);
    fprintf(f, "{\n");
    fprintf(f, "  \"tool\": \"nfsdiag\",\n");
    fprintf(f, "  \"host\": \""); json_escape(f, host); fprintf(f, "\",\n");
    fprintf(f, "  \"timestamp\": %ld,\n", (long)now);
    fprintf(f, "  \"summary\": {\"ok\": %d, \"warn\": %d, \"fail\": %d},\n", summary_ok, summary_warn, summary_fail);
    fprintf(f, "  \"options\": {\"timeout_sec\": %d, \"command_timeout_sec\": %d, \"stale_iterations\": %d, \"bench_bytes\": %zu, \"bench_iterations\": %d},\n",
            opt.timeout_sec, opt.command_timeout_sec, opt.stale_iterations, opt.bench_bytes, opt.bench_iterations);
    fprintf(f, "  \"events\": [\n");
    for (size_t i = 0; i < event_count; i++) {
        fprintf(f, "    {\"level\": \""); json_escape(f, events[i].level); fprintf(f, "\", \"message\": \""); json_escape(f, events[i].message); fprintf(f, "\"}%s\n", i + 1 == event_count ? "" : ",");
    }
    fprintf(f, "  ],\n");
    fprintf(f, "  \"recommendations\": [\n");
    for (size_t i = 0; i < recommendation_count; i++) {
        fprintf(f, "    \""); json_escape(f, recommendations[i]); fprintf(f, "\"%s\n", i + 1 == recommendation_count ? "" : ",");
    }
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");

    if (f != stdout) fclose(f);
}

static int setup_mount_namespace(void) {
    if (!opt.mount_namespace) return 0;
    if (unshare(CLONE_NEWNS) != 0) {
        report_warn("could not create private mount namespace: %s", strerror(errno));
        add_recommendation("Private mount namespace failed; run as root/CAP_SYS_ADMIN or disable --mount-namespace.");
        return -1;
    }
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
        report_warn("could not make mount namespace private: %s", strerror(errno));
        return -1;
    }
    report_ok("using private mount namespace for live mount diagnostics");
    return 0;
}

static void print_interpretation(void) {
    if (opt.verbose) {
        printf("\n[REPORT / interpretation]\n");
        printf("- Network/RPC failures usually indicate firewall, routing, rpcbind/mountd down, or service bound only to another protocol.\n");
        printf("- mountd/export failures indicate /etc/exports, exportfs state, client allowlist, or NFSv4-only configuration.\n");
        printf("- Permission/write failures after mount indicate export options, UNIX mode bits, ACLs, idmapping, root_squash, SELinux/AppArmor on server, or read-only export.\n");
        printf("- Locking warnings affect POSIX byte-range locks; for NFSv3 verify lockd/statd ports through firewalls.\n");
        printf("- ESTALE only appears when the server invalidates a handle during use; a clean loop means it was not reproduced now, not that it can never happen.\n");
        printf("- Performance numbers are a smoke test from this client and depend on cache, sync behavior, network, server load, and mount options.\n");
    }
    if (recommendation_count) {
        printf("\n[RECOMMENDATIONS]\n");
        for (size_t i = 0; i < recommendation_count; i++) printf("- %s\n", recommendations[i]);
    }
}

int main(int argc, char **argv) {
    static struct option long_opts[] = {
        {"export", required_argument, 0, 'e'},
        {"mount-options", required_argument, 0, 'o'},
        {"no-mount", no_argument, 0, 1000},
        {"keep-temp", no_argument, 0, 1001},
        {"read-only", no_argument, 0, 1002},
        {"uid", required_argument, 0, 1003},
        {"gid", required_argument, 0, 1004},
        {"timeout", required_argument, 0, 1005},
        {"stale-iterations", required_argument, 0, 1006},
        {"bench-bytes", required_argument, 0, 1007},
        {"command-timeout", required_argument, 0, 1008},
        {"mount-namespace", no_argument, 0, 1009},
        {"json", optional_argument, 0, 1010},
        {"groups", required_argument, 0, 1011},
        {"udp", no_argument, 0, 1012},
        {"ipv4-only", no_argument, 0, 1013},
        {"ipv6-only", no_argument, 0, 1014},
        {"no-nfs4-discovery", no_argument, 0, 1015},
        {"bench-iterations", required_argument, 0, 1016},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int c;
    while ((c = getopt_long(argc, argv, "e:o:vh", long_opts, NULL)) != -1) {
        unsigned long value;
        switch (c) {
            case 'e': opt.single_export = optarg; break;
            case 'o': opt.mount_options = optarg; break;
            case 'v': opt.verbose = 1; break;
            case 'h': usage(argv[0]); return 0;
            case 1000: opt.no_mount = 1; break;
            case 1001: opt.keep_temp = 1; break;
            case 1002: opt.write_test = 0; break;
            case 1003:
                if (parse_ulong_arg(optarg, &value) != 0) { fprintf(stderr, "invalid --uid: %s\n", optarg); return 2; }
                add_identity((uid_t)value, default_gid_for_uid((uid_t)value));
                break;
            case 1004:
                if (parse_ulong_arg(optarg, &value) != 0) { fprintf(stderr, "invalid --gid: %s\n", optarg); return 2; }
                if (opt.identity_count == 0) add_identity(geteuid(), (gid_t)value);
                else opt.gids[opt.identity_count - 1] = (gid_t)value;
                break;
            case 1005:
                if (parse_ulong_arg(optarg, &value) != 0 || value == 0 || value > 3600) { fprintf(stderr, "invalid --timeout: %s\n", optarg); return 2; }
                opt.timeout_sec = (int)value;
                break;
            case 1006:
                if (parse_ulong_arg(optarg, &value) != 0 || value > 1000000UL) { fprintf(stderr, "invalid --stale-iterations: %s\n", optarg); return 2; }
                opt.stale_iterations = (int)value;
                break;
            case 1007:
                if (parse_ulong_arg(optarg, &value) != 0 || value > (1024UL * 1024UL * 1024UL)) { fprintf(stderr, "invalid --bench-bytes: %s\n", optarg); return 2; }
                opt.bench_bytes = (size_t)value;
                break;
            case 1008:
                if (parse_ulong_arg(optarg, &value) != 0 || value == 0 || value > 3600) { fprintf(stderr, "invalid --command-timeout: %s\n", optarg); return 2; }
                opt.command_timeout_sec = (int)value;
                break;
            case 1009: opt.mount_namespace = 1; break;
            case 1010:
                opt.json = 1;
                opt.json_path = optarg ? optarg : "-";
                break;
            case 1011:
                if (parse_groups_arg(optarg) != 0) { fprintf(stderr, "invalid --groups: %s\n", optarg); return 2; }
                break;
            case 1012: opt.udp_checks = 1; break;
            case 1013: opt.address_family = AF_INET; break;
            case 1014: opt.address_family = AF_INET6; break;
            case 1015: opt.nfs4_discovery = 0; break;
            case 1016:
                if (parse_ulong_arg(optarg, &value) != 0 || value > 100000UL) { fprintf(stderr, "invalid --bench-iterations: %s\n", optarg); return 2; }
                opt.bench_iterations = (int)value;
                break;
            default:
                usage(argv[0]);
                return 2;
        }
    }

    if (optind >= argc) {
        usage(argv[0]);
        return 2;
    }

    const char *host = argv[optind];
    install_cleanup_handlers();
    enable_json_only_output();
    printf("nfsdiag: %s\n", host);

    struct rpc_services services = {0};
    struct export_list exports_found = {0};

    network_tests(host);
    check_rpcbind(host, &services);
    check_nfs_versions(host, &services);
    check_mountd_versions(host, &services);
    enumerate_exports(host, &exports_found);

    if (opt.no_mount) {
        report_info("mount and live filesystem diagnostics skipped by --no-mount");
        print_interpretation();
        printf("summary: ok=%d warn=%d fail=%d\n", summary_ok, summary_warn, summary_fail);
        write_json_report(host);
        free_exports(&exports_found);
        free(services.items);
        return summary_fail || summary_warn ? 1 : 0;
    }

    setup_mount_namespace();

    if (opt.verbose) printf("\n[+] Temporary mount workspace\n");
    snprintf(cleanup_base, sizeof(cleanup_base), "/tmp/nfsdoctor-XXXXXX");
    if (!mkdtemp(cleanup_base)) {
        report_fail("mkdtemp failed under /tmp: %s", strerror(errno));
        write_json_report(host);
        free_exports(&exports_found);
        free(services.items);
        return 2;
    }
    report_ok("created temporary workspace %s", cleanup_base);

    if (exports_found.count == 0) {
        report_fail("no exports available to mount; use --export PATH if the server is NFSv4-only or hides mountd");
    }

    for (size_t i = 0; i < exports_found.count; i++) {
        if (received_signal) {
            report_warn("received signal %d, stopping further mount diagnostics", received_signal);
            break;
        }
        char mp[256];
        snprintf(mp, sizeof(mp), "%s/export-%zu", cleanup_base, i + 1);
        if (make_dir(mp, 0700) != 0) {
            report_fail("cannot create mountpoint %s: %s", mp, strerror(errno));
            continue;
        }

        if (opt.verbose) printf("\n[+] Mount test for export %s\n", exports_found.items[i].path);
        struct mount_result mr;
        if (mount_export(host, exports_found.items[i].path, mp, &mr) == 0) {
            diagnose_mounted_export(exports_found.items[i].path, mp);
            if (unmount_export(mp) != 0) {
                report_warn("leaving mountpoint in place for safety: %s", mp);
                opt.keep_temp = 1;
            }
        }
    }

    if (opt.keep_temp) report_warn("temporary workspace kept at %s", cleanup_base);
    else {
        cleanup_temp_tree();
        report_ok("temporary workspace removed");
    }

    print_interpretation();
    printf("summary: ok=%d warn=%d fail=%d\n", summary_ok, summary_warn, summary_fail);
    write_json_report(host);

    free_exports(&exports_found);
    free(services.items);
    return summary_fail || summary_warn ? 1 : 0;
}
