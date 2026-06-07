#include "nfsdiag.h"

/* ---- XDR helpers ---- */

static int xdr_groupnode(XDR *xdrs, struct groupnode *objp);
static int xdr_exportnode(XDR *xdrs, struct exportnode *objp);

static bool_t xdr_void_proc(XDR *xdrs, ...) {
    (void)xdrs;
    return TRUE;
}

/* XDR recursion depth counter: prevents stack overflow from a malicious
 * server sending deeply nested export/group linked lists. */
static int xdr_depth = 0;

static int xdr_groups(XDR *xdrs, groups *objp) {
    if (xdr_depth >= MAX_XDR_DEPTH) return FALSE;
    xdr_depth++;
    int r = xdr_pointer(xdrs, (char **)objp, sizeof(struct groupnode),
                        (xdrproc_t)xdr_groupnode);
    xdr_depth--;
    return r;
}

static int xdr_exports_type(XDR *xdrs, exports *objp) {
    if (xdr_depth >= MAX_XDR_DEPTH) return FALSE;
    xdr_depth++;
    int r = xdr_pointer(xdrs, (char **)objp, sizeof(struct exportnode),
                        (xdrproc_t)xdr_exportnode);
    xdr_depth--;
    return r;
}

/* Sanitize a string received from RPC by replacing control characters.
 * Prevents terminal injection when printed in verbose mode and HTML injection
 * if the string ever reaches an HTML context without escaping. */
static void sanitize_xdr_string(char *s) {
    if (!s) return;
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c < 0x20 && c != '\t' && c != '\n')
            *s = '?';
    }
}

static int xdr_groupnode(XDR *xdrs, struct groupnode *objp) {
    int ok = xdr_string(xdrs, &objp->gr_name, MAX_XDR_GROUP_NAME) &&
             xdr_groups(xdrs, &objp->gr_next);
    if (ok) sanitize_xdr_string(objp->gr_name);
    return ok;
}

static int xdr_exportnode(XDR *xdrs, struct exportnode *objp) {
    int ok = xdr_string(xdrs, &objp->ex_dir, MAX_XDR_EXPORT_PATH) &&
             xdr_groups(xdrs, &objp->ex_groups) &&
             xdr_exports_type(xdrs, &objp->ex_next);
    if (ok) sanitize_xdr_string(objp->ex_dir);
    return ok;
}

/* ---- RPC timeout enforcement ---- */

static volatile sig_atomic_t rpc_timeout_fired = 0;
static void rpc_timeout_handler(int sig) { (void)sig; rpc_timeout_fired = 1; }

static void arm_rpc_timeout(struct sigaction *old) {
    rpc_timeout_fired = 0;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = rpc_timeout_handler;
    /* no SA_RESTART: blocking calls return EINTR on timeout */
    sigaction(SIGALRM, &sa, old);
    alarm((unsigned)(opt.timeout_sec + 1));
}

static void disarm_rpc_timeout(const struct sigaction *old) {
    alarm(0);
    if (old) sigaction(SIGALRM, old, NULL);
    rpc_timeout_fired = 0;
}

/* ---- RPC helpers ---- */

const char *rpc_program_name(unsigned long prog) {
    switch (prog) {
    case NFS_PROGRAM:   return "nfs";
    case MOUNT_PROGRAM: return "mountd";
    case NLM_PROGRAM:   return "lockd/nlm";
    case NSM_PROGRAM:   return "statd/nsm";
    case PMAPPROG:      return "rpcbind/portmapper";
    default:            return "unknown";
    }
}

void rpc_services_add(struct rpc_services *svc, unsigned long prog,
                      unsigned long vers, unsigned long prot, unsigned long port)
{
    if (svc->len == svc->cap) {
        size_t new_cap = svc->cap ? svc->cap * 2 : 32;
        struct rpc_service *ni = realloc(svc->items, new_cap * sizeof(*ni));
        if (!ni) {
            report_fail("out of memory collecting RPC service map");
            return;
        }
        svc->items = ni;
        svc->cap   = new_cap;
    }
    svc->items[svc->len++] = (struct rpc_service){prog, vers, prot, port};
}

int rpc_services_has(const struct rpc_services *svc, unsigned long prog) {
    for (size_t i = 0; i < svc->len; i++)
        if (svc->items[i].prog == prog) return 1;
    return 0;
}

int rpc_services_has_version(const struct rpc_services *svc, unsigned long prog,
                             unsigned long vers)
{
    for (size_t i = 0; i < svc->len; i++)
        if (svc->items[i].prog == prog && svc->items[i].vers == vers) return 1;
    return 0;
}

CLIENT *rpc_client(const char *host, unsigned long prog, unsigned long vers,
                   const char *proto)
{
    struct sigaction old;
    arm_rpc_timeout(&old);
    CLIENT *cl = clnt_create(host, prog, vers, proto);
    disarm_rpc_timeout(&old);
    if (!cl && opt.verbose) clnt_pcreateerror((char *)host);
    if (cl) {
        struct timeval tv = {opt.timeout_sec, 0};
        clnt_control(cl, CLSET_TIMEOUT, (char *)&tv);
    }
    return cl;
}

int rpc_null_call(const char *host, unsigned long prog, unsigned long vers,
                  const char *proto, enum clnt_stat *out_stat)
{
    CLIENT *cl = rpc_client(host, prog, vers, proto);
    if (!cl) return -1;
    struct timeval tv = {opt.timeout_sec, 0};
    enum clnt_stat st = clnt_call(cl, NULLPROC, xdr_void_proc, NULL,
                                   xdr_void_proc, NULL, tv);
    if (out_stat) *out_stat = st;
    clnt_destroy(cl);
    return st == RPC_SUCCESS ? 0 : -1;
}

/* ---- rpcbind query with IPv6 support ---- */

/*
 * pmap_getmaps() only works over IPv4. When the user selects IPv6
 * (or AF_UNSPEC resolves to IPv6) we fall back to probing individual
 * RPC programs via clnt_create(), which libtirpc supports over IPv6.
 */
static void probe_rpc_programs(const char *host, struct rpc_services *svc) {
    static const struct { unsigned long prog; int max_vers; } probes[] = {
        {NFS_PROGRAM,   4},
        {MOUNT_PROGRAM, 3},
        {NLM_PROGRAM,   4},
        {NSM_PROGRAM,   2},
    };

    for (size_t p = 0; p < sizeof(probes) / sizeof(probes[0]); p++) {
        for (int v = 1; v <= probes[p].max_vers; v++) {
            const char *protos[] = {"tcp", opt.udp_checks ? "udp" : NULL};
            for (int pi = 0; protos[pi]; pi++) {
                CLIENT *cl = clnt_create(host, probes[p].prog, (unsigned long)v,
                                         protos[pi]);
                if (cl) {
                    unsigned long prot = (strcmp(protos[pi], "tcp") == 0)
                                             ? IPPROTO_TCP : IPPROTO_UDP;
                    rpc_services_add(svc, probes[p].prog, (unsigned long)v, prot, 0);
                    clnt_destroy(cl);
                }
            }
        }
    }
}

void check_rpcbind(const char *host, struct rpc_services *svc) {
    if (opt.verbose) printf("\n[+] rpcbind / portmapper\n");

    /* try legacy portmapper only on IPv4 */
    if (opt.address_family != AF_INET6) {
        struct addrinfo hints;
        struct addrinfo *res = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        int gai = getaddrinfo(host, NULL, &hints, &res);
        if (gai == 0 && res) {
            struct sockaddr_in addr = *(struct sockaddr_in *)res->ai_addr;
            addr.sin_port = htons(RPCBIND_PORT);
            struct sigaction rpc_old;
            arm_rpc_timeout(&rpc_old);
            struct pmaplist *list = pmap_getmaps(&addr);
            disarm_rpc_timeout(&rpc_old);
            freeaddrinfo(res);

            if (list) {
                report_ok("RPC service map fetched");
                for (struct pmaplist *p = list; p; p = p->pml_next) {
                    rpc_services_add(svc, p->pml_map.pm_prog, p->pml_map.pm_vers,
                                     p->pml_map.pm_prot, p->pml_map.pm_port);
                    if (opt.verbose) {
                        report_info("program=%lu (%s) version=%lu proto=%s port=%lu",
                                    p->pml_map.pm_prog,
                                    rpc_program_name(p->pml_map.pm_prog),
                                    p->pml_map.pm_vers,
                                    proto_name(p->pml_map.pm_prot),
                                    p->pml_map.pm_port);
                    }
                }
                goto check_services;
            } else {
                report_fail("cannot fetch RPC service map via portmapper; "
                            "rpcbind may be filtered or UDP-only behavior may be blocked");
            }
        } else {
            if (res) freeaddrinfo(res);
        }
    }

    /* IPv6 path or portmapper fallback: probe programs individually */
    if (opt.address_family == AF_INET6) {
        report_info("IPv6 selected; using direct RPC probing instead of legacy portmapper");
    } else {
        report_info("portmapper query failed; falling back to direct RPC probing");
    }
    probe_rpc_programs(host, svc);
    if (svc->len > 0) report_ok("RPC services detected via direct probing");
    else report_fail("no RPC services detected via direct probing");

check_services:
    if (rpc_services_has(svc, NFS_PROGRAM))
        report_ok("NFS service is registered in rpcbind");
    else
        report_warn("NFS service is not present in rpcbind map; NFSv4 may still answer on TCP/2049");

    if (rpc_services_has(svc, MOUNT_PROGRAM))
        report_ok("mountd service is registered in rpcbind");
    else
        report_warn("mountd service not registered; NFSv3 exports/mount tests may fail, NFSv4 may still work");

    if (rpc_services_has(svc, NLM_PROGRAM))
        report_ok("NLM/lockd service is registered");
    else {
        report_warn("NLM/lockd not registered; NFSv3 advisory locking may be unavailable or firewall-blocked");
        add_recommendation("NLM/lockd is missing: for NFSv3 locking, verify lockd ports and firewall rules; NFSv4 may not need separate lockd.");
    }

    if (rpc_services_has(svc, NSM_PROGRAM))
        report_ok("NSM/statd service is registered");
    else {
        report_warn("NSM/statd not registered; NFSv3 lock recovery may be unavailable");
        add_recommendation("NSM/statd is missing: NFSv3 lock recovery can fail; start rpc.statd or open its firewall path.");
    }
}

/* ---- NFS version checks, including NFSv4.1/v4.2 detection ---- */

void check_nfs_versions(const char *host, const struct rpc_services *svc) {
    if (opt.verbose) printf("\n[+] NFS protocol versions\n");

    for (int v = 2; v <= 4; v++) {
        enum clnt_stat st = RPC_FAILED;
        if (rpc_null_call(host, NFS_PROGRAM, (unsigned long)v, "tcp", &st) == 0) {
            report_ok("NFS v%d answers NULLPROC over TCP", v);
            /* for v4, note that minor versions are negotiated at mount time */
            if (v == 4) {
                report_info("NFSv4 minor versions (4.1, 4.2) will be tested during mount");
            }
        } else if (rpc_services_has_version(svc, NFS_PROGRAM, (unsigned long)v)) {
            report_warn("NFS v%d appears in rpcbind but NULLPROC over TCP failed: %s",
                        v, clnt_sperrno(st));
        } else {
            if (v == 2) report_info("NFS v%d not detected", v);
            else report_warn("NFS v%d not detected", v);
        }

        if (opt.udp_checks) {
            enum clnt_stat ust = RPC_FAILED;
            if (rpc_null_call(host, NFS_PROGRAM, (unsigned long)v, "udp", &ust) == 0)
                report_ok("NFS v%d answers NULLPROC over UDP", v);
            else
                report_warn("NFS v%d UDP NULLPROC failed or filtered: %s",
                            v, clnt_sperrno(ust));
        }
    }
}

void check_mountd_versions(const char *host, const struct rpc_services *svc) {
    if (opt.verbose) printf("\n[+] mountd versions\n");

    for (int v = 1; v <= 3; v++) {
        enum clnt_stat st = RPC_FAILED;
        if (rpc_null_call(host, MOUNT_PROGRAM, (unsigned long)v, "tcp", &st) == 0) {
            report_ok("mountd v%d answers NULLPROC over TCP", v);
        } else if (rpc_services_has_version(svc, MOUNT_PROGRAM, (unsigned long)v)) {
            report_warn("mountd v%d appears in rpcbind but NULLPROC over TCP failed: %s",
                        v, clnt_sperrno(st));
        } else {
            report_warn("mountd v%d not detected", v);
        }

        if (opt.udp_checks) {
            enum clnt_stat ust = RPC_FAILED;
            if (rpc_null_call(host, MOUNT_PROGRAM, (unsigned long)v, "udp", &ust) == 0)
                report_ok("mountd v%d answers NULLPROC over UDP", v);
            else
                report_warn("mountd v%d UDP NULLPROC failed or filtered: %s",
                            v, clnt_sperrno(ust));
        }
    }
}

/* ---- export enumeration ---- */

static void add_export_from_rpc(struct export_list *out, const char *path, groups gr) {
    if (!path || out->count >= MAX_EXPORTS) return;
    char reason[256];
    if (validate_export_path(path, reason, sizeof(reason)) != 0) {
        report_warn("skipping invalid export path from server: %s", reason);
        return;
    }

    char *path_dup = strdup(path);
    if (!path_dup) return;

    size_t group_count = 0;
    for (groups g = gr; g; g = g->gr_next) group_count++;
    char **group_arr = calloc(group_count ? group_count : 1, sizeof(char *));
    if (!group_arr) { free(path_dup); return; }

    size_t gc = 0;
    for (groups g = gr; g; g = g->gr_next) {
        group_arr[gc] = strdup(g->gr_name ? g->gr_name : "(null)");
        if (!group_arr[gc]) {
            for (size_t i = 0; i < gc; i++) free(group_arr[i]);
            free(group_arr);
            free(path_dup);
            return;
        }
        gc++;
    }

    struct export_item *item = &out->items[out->count];
    item->path        = path_dup;
    item->groups      = group_arr;
    item->group_count = gc;
    out->count++;
}

void enumerate_exports(const char *host, struct export_list *out) {
    if (opt.verbose) printf("\n[+] Export enumeration\n");

    if (opt.single_export) {
        char *path_dup = strdup(opt.single_export);
        if (!path_dup) {
            report_fail("out of memory recording --export path");
            return;
        }
        out->items[0].path        = path_dup;
        out->items[0].groups      = calloc(1, sizeof(char *));
        out->items[0].group_count = 0;
        out->count = 1;
        report_info("using export supplied by user: %s", opt.single_export);
        return;
    }

    CLIENT *cl = rpc_client(host, MOUNT_PROGRAM, 3, "tcp");
    if (!cl) cl = rpc_client(host, MOUNT_PROGRAM, 2, "tcp");
    if (!cl) cl = rpc_client(host, MOUNT_PROGRAM, 1, "tcp");
    if (!cl) {
        report_fail("cannot contact mountd to enumerate exports; "
                    "use --export PATH for NFSv4-only or filtered servers");
        add_recommendation("mountd is unavailable; if this is an NFSv4-only server, "
                           "try --export / or keep NFSv4 pseudo-root discovery enabled.");
        if (opt.nfs4_discovery) {
            add_export_from_rpc(out, "/", NULL);
            report_info("NFSv4 pseudo-root discovery enabled: "
                        "will try synthetic export / during mount tests");
        }
        return;
    }

    exports ex = NULL;
    struct timeval tv = {opt.timeout_sec, 0};
    enum clnt_stat st = clnt_call(cl, MOUNTPROC_EXPORT,
                                  xdr_void_proc, NULL,
                                  (xdrproc_t)xdr_exports_type, (char *)&ex, tv);
    if (st != RPC_SUCCESS) {
        report_fail("mountd EXPORT call failed: %s", clnt_sperrno(st));
        clnt_destroy(cl);
        return;
    }

    for (exports e = ex; e; e = e->ex_next)
        add_export_from_rpc(out, e->ex_dir, e->ex_groups);

    if (out->count == 0) {
        report_warn("server returned an empty export list");
        if (opt.nfs4_discovery) {
            add_export_from_rpc(out, "/", NULL);
            report_info("NFSv4 pseudo-root discovery enabled: "
                        "will try synthetic export / during mount tests");
        }
    } else {
        report_ok("%zu export(s) discovered", out->count);
        for (size_t i = 0; i < out->count; i++) {
            if (opt.verbose) {
                printf("  - %s", out->items[i].path);
                if (out->items[i].group_count) {
                    printf("  allowed clients/groups:");
                    for (size_t g = 0; g < out->items[i].group_count; g++)
                        printf(" %s", out->items[i].groups[g]);
                }
                putchar('\n');
            }
        }
    }

    clnt_freeres(cl, (xdrproc_t)xdr_exports_type, (char *)&ex);
    clnt_destroy(cl);
}

void free_exports(struct export_list *list) {
    for (size_t i = 0; i < list->count; i++) {
        free(list->items[i].path);
        for (size_t g = 0; g < list->items[i].group_count; g++)
            free(list->items[i].groups[g]);
        free(list->items[i].groups);
    }
    memset(list, 0, sizeof(*list));
}
