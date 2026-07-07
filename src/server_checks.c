/* server_checks.c - pure analyzers for the server namespace checks.
 * No I/O and no report.c calls: unit-testable in isolation. */
#include "nfsdiag.h"

int parse_nfsd_versions(const char *buf, struct nfsd_versions *out) {
    out->v3 = out->v4 = out->v4_1 = out->v4_2 = -1;
    int seen = 0;
    const char *p = buf;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\n') p++;
        if (*p == '\0') break;
        if (*p != '+' && *p != '-')
            return -1;
        int on = (*p == '+');
        p++;
        if (strncmp(p, "4.2", 3) == 0)      { out->v4_2 = on; p += 3; }
        else if (strncmp(p, "4.1", 3) == 0) { out->v4_1 = on; p += 3; }
        else if (*p == '4')                 { out->v4 = on; p++; }
        else if (*p == '3')                 { out->v3 = on; p++; }
        else if (*p == '2')                 { p++; }   /* v2: obsolete, ignore */
        else return -1;
        seen = 1;
    }
    return seen ? 0 : -1;
}

int parse_nfsd_th_line(const char *buf, struct nfsd_th_stats *out) {
    out->threads = 0; out->busy_all = 0.0; out->valid = 0;
    const char *line = buf;
    while (line) {
        if (strncmp(line, "th ", 3) == 0)
            break;
        line = strchr(line, '\n');
        if (line) line++;
    }
    if (!line)
        return -1;
    char *end = NULL;
    out->threads = strtol(line + 3, &end, 10);
    if (end == line + 3 || out->threads < 0)
        return -1;
    /* last whitespace-separated token of the line is the all-busy bucket */
    const char *eol = strchr(line, '\n');
    size_t len = eol ? (size_t)(eol - line) : strlen(line);
    while (len > 0 && (line[len - 1] == ' ' || line[len - 1] == '\r')) len--;
    size_t start = len;
    while (start > 0 && line[start - 1] != ' ') start--;
    if (start > 3)
        out->busy_all = atof(line + start);
    out->valid = 1;
    return 0;
}

int tcp_table_has_listener(FILE *f, unsigned port) {
    char line[512];
    if (!fgets(line, sizeof(line), f))   /* header */
        return -1;
    while (fgets(line, sizeof(line), f)) {
        unsigned lport = 0, st = 0;
        /* "  sl: LOCALHEX:PORT REMHEX:PORT st ..." — hex fields */
        if (sscanf(line, " %*[0-9]: %*[0-9A-Fa-f]:%x %*[0-9A-Fa-f]:%*x %x",
                   &lport, &st) == 2 &&
            st == 0x0A && lport == port)
            return 1;
    }
    return 0;
}

static const struct { long magic; const char *name; const char *why; } fs_magics[] = {
    { 0xEF53,       "ext4",      NULL },
    { 0x58465342,   "xfs",       NULL },
    { 0x9123683E,   "btrfs",     NULL },
    { 0x2FC12FC1,   "zfs",       NULL },
    { 0x01021994,   "tmpfs",     "contents vanish on reboot and file handles change" },
    { 0x794C7630,   "overlayfs", "unstable file handles break NFS clients (ESTALE)" },
    { 0x6969,       "nfs",       "re-exporting an NFS mount needs explicit fsid and is fragile" },
    { 0x9FA0,       "proc",      "pseudo filesystem, not exportable data" },
};

const char *fs_type_name(long f_type) {
    for (size_t i = 0; i < sizeof(fs_magics) / sizeof(fs_magics[0]); i++)
        if (fs_magics[i].magic == f_type)
            return fs_magics[i].name;
    return "unknown";
}

int fs_type_unsuitable(long f_type, char *why, size_t whysz) {
    for (size_t i = 0; i < sizeof(fs_magics) / sizeof(fs_magics[0]); i++) {
        if (fs_magics[i].magic == f_type && fs_magics[i].why) {
            snprintf(why, whysz, "%s: %s", fs_magics[i].name, fs_magics[i].why);
            return 1;
        }
    }
    return 0;
}

int fs_type_acl_capable(long f_type) {
    return f_type == 0xEF53 ||        /* ext4  */
           f_type == 0x58465342 ||    /* xfs   */
           f_type == 0x9123683E ||    /* btrfs */
           f_type == 0x2FC12FC1;      /* zfs   */
}

/* Return a pointer to the first line in `buf` that starts with `prefix`
 * (after leading blanks), or NULL. */
static const char *find_line(const char *buf, const char *prefix) {
    size_t plen = strlen(prefix);
    const char *line = buf;
    while (line) {
        const char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (strncmp(p, prefix, plen) == 0)
            return p;
        line = strchr(line, '\n');
        if (line) line++;
    }
    return NULL;
}

int parse_nfsd_rc_line(const char *buf, struct nfsd_rc *out) {
    out->hits = out->misses = out->nocache = 0;
    out->valid = 0;
    const char *line = find_line(buf, "rc ");
    if (!line)
        return -1;
    if (sscanf(line + 3, "%ld %ld %ld", &out->hits, &out->misses,
               &out->nocache) < 2)
        return -1;
    out->valid = 1;
    return 0;
}

int parse_nfsd_rpc_line(const char *buf, struct nfsd_rpc *out) {
    out->calls = out->badcalls = 0;
    out->valid = 0;
    const char *line = find_line(buf, "rpc ");
    if (!line)
        return -1;
    if (sscanf(line + 4, "%ld %ld", &out->calls, &out->badcalls) < 2)
        return -1;
    out->valid = 1;
    return 0;
}

int count_proc_locks_buf(const char *buf, int *posix, int *flock, int *lease) {
    *posix = *flock = *lease = 0;
    int total = 0;
    const char *line = buf;
    while (line && *line) {
        char kind[16];
        /* "<n>: KIND ..." — skip the index and read the type token */
        if (sscanf(line, " %*d: %15s", kind) == 1) {
            if (strcmp(kind, "POSIX") == 0 || strcmp(kind, "OFDLCK") == 0)
                (*posix)++;
            else if (strcmp(kind, "FLOCK") == 0)
                (*flock)++;
            else if (strcmp(kind, "LEASE") == 0 || strcmp(kind, "DELEG") == 0)
                (*lease)++;
            total++;
        }
        line = strchr(line, '\n');
        if (line) line++;
    }
    return total;
}

int tcp_table_count_established(FILE *f, unsigned port) {
    char line[512];
    if (!fgets(line, sizeof(line), f))   /* header */
        return 0;
    int count = 0;
    while (fgets(line, sizeof(line), f)) {
        unsigned lport = 0, st = 0;
        if (sscanf(line, " %*[0-9]: %*[0-9A-Fa-f]:%x %*[0-9A-Fa-f]:%*x %x",
                   &lport, &st) == 2 &&
            st == 0x01 && lport == port)
            count++;
    }
    return count;
}

int parse_nfsd_client_info(const char *buf, struct nfsd_client_info *out) {
    memset(out, 0, sizeof(*out));
    out->minor_version = -1;
    out->callback_up = -1;
    int seen = 0;
    const char *line = buf;
    while (line && *line) {
        const char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (strncmp(p, "address:", 8) == 0) {
            const char *q = strchr(p, '"');
            if (q) {
                q++;
                size_t n = 0;
                while (q[n] && q[n] != '"' && n + 1 < sizeof(out->address)) {
                    out->address[n] = q[n];
                    n++;
                }
                out->address[n] = '\0';
                seen = 1;
            }
        } else if (strncmp(p, "minor version:", 14) == 0) {
            out->minor_version = atoi(p + 14);
            seen = 1;
        } else if (strncmp(p, "callback state:", 15) == 0) {
            const char *v = p + 15;
            while (*v == ' ' || *v == '\t') v++;
            out->callback_up = (strncmp(v, "UP", 2) == 0) ? 1 : 0;
            seen = 1;
        }
        line = strchr(line, '\n');
        if (line) line++;
    }
    return seen ? 0 : -1;
}

int count_nfsd_client_states(const char *buf, int *opens, int *locks,
                             int *delegs, int *layouts) {
    *opens = *locks = *delegs = *layouts = 0;
    int total = 0;
    const char *p = buf;
    while ((p = strstr(p, "type:")) != NULL) {
        p += 5;
        while (*p == ' ' || *p == '\t') p++;
        if (strncmp(p, "open", 4) == 0)        (*opens)++;
        else if (strncmp(p, "lock", 4) == 0)   (*locks)++;
        else if (strncmp(p, "deleg", 5) == 0)  (*delegs)++;
        else if (strncmp(p, "layout", 6) == 0) (*layouts)++;
        total++;
    }
    return total;
}

int usage_severity(unsigned long long total, unsigned long long freev) {
    if (total == 0)
        return -1;
    return (total - freev) * 10ULL > total * 9ULL ? 1 : 0;
}

static void idmapd_copy_value(char *dst, size_t sz, const char *val) {
    while (*val == ' ' || *val == '\t') val++;
    size_t n = 0;
    while (val[n] && val[n] != '\n' && val[n] != '\r' && n + 1 < sz) {
        dst[n] = val[n];
        n++;
    }
    while (n > 0 && (dst[n - 1] == ' ' || dst[n - 1] == '\t')) n--;
    dst[n] = '\0';
}

int parse_idmapd_conf(const char *buf, struct idmapd_conf *out) {
    memset(out, 0, sizeof(*out));
    const char *line = buf;
    while (line && *line) {
        while (*line == ' ' || *line == '\t') line++;
        if (*line != '#' && *line != ';' && *line != '[') {
            const char *eq = strchr(line, '=');
            const char *eol = strchr(line, '\n');
            if (eq && (!eol || eq < eol)) {
                char key[64];
                size_t k = 0;
                while (line + k < eq && k + 1 < sizeof(key)) {
                    key[k] = line[k];
                    k++;
                }
                while (k > 0 && (key[k - 1] == ' ' || key[k - 1] == '\t')) k--;
                key[k] = '\0';
                if (strcasecmp(key, "Domain") == 0) {
                    idmapd_copy_value(out->domain, sizeof(out->domain), eq + 1);
                    out->has_domain = out->domain[0] != '\0';
                } else if (strcasecmp(key, "Nobody-User") == 0) {
                    idmapd_copy_value(out->nobody_user, sizeof(out->nobody_user), eq + 1);
                } else if (strcasecmp(key, "Nobody-Group") == 0) {
                    idmapd_copy_value(out->nobody_group, sizeof(out->nobody_group), eq + 1);
                } else if (strcasecmp(key, "Method") == 0) {
                    idmapd_copy_value(out->method, sizeof(out->method), eq + 1);
                }
            }
        }
        line = strchr(line, '\n');
        if (line) line++;
    }
    return 0;
}

int krb5_conf_default_realm(const char *buf, char *out, size_t sz) {
    const char *line = buf;
    while (line && *line) {
        while (*line == ' ' || *line == '\t') line++;
        if (strncmp(line, "default_realm", 13) == 0) {
            const char *eq = strchr(line, '=');
            const char *eol = strchr(line, '\n');
            if (eq && (!eol || eq < eol)) {
                idmapd_copy_value(out, sz, eq + 1);
                if (out[0])
                    return 0;
            }
        }
        line = strchr(line, '\n');
        if (line) line++;
    }
    return -1;
}

int comm_matches(const char *comm, const char *name) {
    size_t n = strlen(comm);
    while (n > 0 && (comm[n - 1] == '\n' || comm[n - 1] == '\r')) n--;
    size_t want = strlen(name);
    if (want > 15) want = 15;   /* TASK_COMM_LEN-1: kernel truncates comm */
    return n == want && strncmp(comm, name, want) == 0;
}

/* ---- observability parsers ---- */

static long meminfo_field(const char *buf, const char *key) {
    const char *line = find_line(buf, key);
    if (!line)
        return -1;
    long v = -1;
    if (sscanf(line + strlen(key), " %ld", &v) != 1)
        return -1;
    return v;
}

int parse_meminfo_buf(const char *buf, struct meminfo_stats *out) {
    out->memtotal_kb = meminfo_field(buf, "MemTotal:");
    out->memavailable_kb = meminfo_field(buf, "MemAvailable:");
    out->slab_kb = meminfo_field(buf, "Slab:");
    out->sreclaimable_kb = meminfo_field(buf, "SReclaimable:");
    out->valid = out->memtotal_kb > 0;
    return out->valid ? 0 : -1;
}

#define RMTAB_DEDUP_CAP 1024

int parse_rmtab_buf(const char *buf, struct rmtab_stats *out) {
    out->entries = out->hosts = out->stale = out->duplicates = 0;
    static char seen_host[RMTAB_DEDUP_CAP][256];
    static char seen_pair[RMTAB_DEDUP_CAP][320];
    int nh = 0, np = 0;
    const char *line = buf;
    while (line && *line) {
        const char *nl = strchr(line, '\n');
        size_t len = nl ? (size_t)(nl - line) : strlen(line);
        if (len > 0 && line[0] != '#') {
            char tmp[320];
            size_t n = len < sizeof(tmp) - 1 ? len : sizeof(tmp) - 1;
            memcpy(tmp, line, n);
            tmp[n] = '\0';
            const char *c1 = strchr(tmp, ':');
            const char *c2 = c1 ? strrchr(tmp, ':') : NULL;
            if (c1 && c2 && c2 > c1) {
                out->entries++;
                if (atoi(c2 + 1) == 0)
                    out->stale++;
                char host[256], pair[320];
                size_t hl = (size_t)(c1 - tmp);
                if (hl > sizeof(host) - 1) hl = sizeof(host) - 1;
                memcpy(host, tmp, hl); host[hl] = '\0';
                size_t pl = (size_t)(c2 - tmp);
                if (pl > sizeof(pair) - 1) pl = sizeof(pair) - 1;
                memcpy(pair, tmp, pl); pair[pl] = '\0';
                int found = 0;
                for (int i = 0; i < nh; i++)
                    if (strcmp(seen_host[i], host) == 0) { found = 1; break; }
                if (!found && nh < RMTAB_DEDUP_CAP) {
                    snprintf(seen_host[nh++], 256, "%s", host);
                    out->hosts++;
                } else if (!found) {
                    out->hosts++;   /* over cap: count but stop deduping */
                }
                found = 0;
                for (int i = 0; i < np; i++)
                    if (strcmp(seen_pair[i], pair) == 0) { found = 1; break; }
                if (found)
                    out->duplicates++;
                else if (np < RMTAB_DEDUP_CAP)
                    snprintf(seen_pair[np++], 320, "%s", pair);
            }
        }
        line = nl ? nl + 1 : NULL;
    }
    return out->entries;
}

struct log_signature { const char *needle; int severity; const char *title; const char *advice; };

static const struct log_signature LOG_SIGNATURES[] = {
    { "lockd: cannot monitor", 1, "NLM cannot monitor a client (lockd)",
      "check rpc.statd (rpc-statd.service) and that /var/lib/nfs/sm is writable" },
    { "rpc.mountd", 1, "mountd refused a mount request",
      "client/export mismatch in /etc/exports; verify the client list and run exportfs -ra" },
    { "svc: failed to register", 1, "an RPC service failed to register with rpcbind",
      "ensure rpcbind is running before nfsd/mountd start" },
    { "nfsd: peername failed", 1, "nfsd could not resolve a client peer name",
      "usually a reset connection or reverse-DNS gap; check client connectivity" },
    { "too many open connections", 1, "nfsd hit its connection limit",
      "raise /proc/fs/nfsd/max_connections or investigate a client connection storm" },
    { "expire_client", 0, "an NFSv4 client lease expired and was reclaimed",
      "expected after a client crash or network partition; frequent events suggest lease/network trouble" },
    { "NFS4ERR_EXPIRED", 0, "clients hit NFS4ERR_EXPIRED (state lost)",
      "clients had to reclaim state; check for grace-period or lease-time issues" },
    { "not responding", 0, "kernel logged an NFS server 'not responding' event",
      "transient network or server stall; correlate with load and link health" },
};

int log_intel_scan(const char *buf, struct log_finding *out, int max) {
    size_t nsig = sizeof(LOG_SIGNATURES) / sizeof(LOG_SIGNATURES[0]);
    static int counts[sizeof(LOG_SIGNATURES) / sizeof(LOG_SIGNATURES[0])];
    for (size_t i = 0; i < nsig; i++) counts[i] = 0;

    const char *line = buf;
    while (line && *line) {
        const char *nl = strchr(line, '\n');
        size_t len = nl ? (size_t)(nl - line) : strlen(line);
        for (size_t i = 0; i < nsig; i++) {
            const char *needle = LOG_SIGNATURES[i].needle;
            size_t nlen = strlen(needle);
            for (size_t j = 0; j + nlen <= len; j++) {
                if (memcmp(line + j, needle, nlen) == 0) { counts[i]++; break; }
            }
        }
        line = nl ? nl + 1 : NULL;
    }

    int n = 0;
    for (size_t i = 0; i < nsig && n < max; i++) {
        if (counts[i] > 0) {
            out[n].title = LOG_SIGNATURES[i].title;
            out[n].advice = LOG_SIGNATURES[i].advice;
            out[n].severity = LOG_SIGNATURES[i].severity;
            out[n].count = counts[i];
            n++;
        }
    }
    return n;
}

/* ---- perf helpers ---- */

/* cppcheck-suppress unusedFunction ; used by ebpf_latency.c (excluded) + unit tests */
int hist_log2_bucket(unsigned long long ns) {
    unsigned long long us = ns / 1000ULL;
    int bucket = 0;
    while (us > 0 && bucket < 31) { us >>= 1; bucket++; }
    return bucket;
}

/* cppcheck-suppress unusedFunction ; used by ebpf_latency.c (excluded) + unit tests */
void fmt_client_ip(const unsigned char ip[16], int family, char *out, size_t sz) {
    if (family == 2) {           /* AF_INET */
        struct in_addr a;
        memcpy(&a, ip, 4);
        if (!inet_ntop(AF_INET, &a, out, (socklen_t)sz)) snprintf(out, sz, "?");
    } else if (family == 10) {   /* AF_INET6 */
        struct in6_addr a;
        memcpy(&a, ip, 16);
        if (!inet_ntop(AF_INET6, &a, out, (socklen_t)sz)) snprintf(out, sz, "?");
    } else {
        snprintf(out, sz, "unknown");
    }
}

int path_is_on_own_mount(const char *mounts_buf, const char *path) {
    const char *line = mounts_buf;
    while (line && *line) {
        char dev[256], mp[256];
        if (sscanf(line, "%255s %255s", dev, mp) == 2 && strcmp(mp, path) == 0)
            return 1;
        line = strchr(line, '\n');
        if (line) line++;
    }
    return 0;
}

int parse_ganesha_conf(const char *buf, struct ganesha_conf *out) {
    memset(out, 0, sizeof(*out));
    out->has_conf = buf[0] ? 1 : 0;
    const char *p = buf;
    while ((p = strstr(p, "EXPORT")) != NULL) {
        char c = (p == buf) ? ' ' : p[-1];
        int wordchar = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                       (c >= '0' && c <= '9') || c == '_';
        int boundary = !wordchar;
        const char *r = p + 6;
        while (*r == ' ' || *r == '\t' || *r == '\n' || *r == '\r') r++;
        if (boundary && *r == '{')
            out->export_count++;
        p += 6;
    }
    p = buf;
    while ((p = strstr(p, "FSAL")) != NULL && out->fsal_count < 8) {
        const char *nm = strstr(p + 4, "Name");
        const char *nextfsal = strstr(p + 4, "FSAL");
        if (nm && (!nextfsal || nm < nextfsal)) {
            const char *eq = strchr(nm, '=');
            if (eq) {
                eq++;
                while (*eq == ' ' || *eq == '\t') eq++;
                int k = 0;
                while (eq[k] && eq[k] != ';' && eq[k] != '\n' && eq[k] != '}' &&
                       eq[k] != ' ' && eq[k] != '\r' && k < 31) {
                    out->fsals[out->fsal_count][k] = eq[k];
                    k++;
                }
                out->fsals[out->fsal_count][k] = '\0';
                if (out->fsals[out->fsal_count][0])
                    out->fsal_count++;
            }
        }
        p += 4;
    }
    return out->export_count;
}

int parse_prometheus_gauge(const char *buf, const char *name, double *out) {
    size_t nlen = strlen(name);
    const char *line = buf;
    while (line && *line) {
        if (strncmp(line, name, nlen) == 0 && (line[nlen] == '{' || line[nlen] == ' ')) {
            const char *eol = strchr(line, '\n');
            size_t len = eol ? (size_t)(eol - line) : strlen(line);
            size_t end = len;
            while (end > 0 && (line[end - 1] == ' ' || line[end - 1] == '\r')) end--;
            size_t start = end;
            while (start > 0 && line[start - 1] != ' ') start--;
            if (start < end) { *out = atof(line + start); return 0; }
        }
        line = strchr(line, '\n');
        if (line) line++;
    }
    return -1;
}

int peer_verdict(const struct peer_client_findings *c, const struct peer_server *base,
                 const struct peer_server *final, char *msg, size_t msgsz) {
    double d_calls = final->rpc_calls - base->rpc_calls;
    double d_bad   = final->rpc_badcalls - base->rpc_badcalls;
    int slow = (c->min_write_mibs >= 0 && c->min_write_mibs < PEER_SLOW_MIBS) ||
               (c->min_read_mibs  >= 0 && c->min_read_mibs  < PEER_SLOW_MIBS);
    if ((c->fail > 0 || c->estale) && d_bad > 0) {
        snprintf(msg, msgsz, "paired: server-side - the server logged %.0f bad RPC call(s) "
                 "during your test (auth or malformed requests)", d_bad);
        return 1;
    }
    if (slow && d_calls > 0) {
        double d_hits = final->drc_hits - base->drc_hits;
        double d_miss = final->drc_misses - base->drc_misses;
        double ratio = (d_hits + d_miss) > 0 ? d_hits / (d_hits + d_miss) : 1.0;
        if (ratio < 0.5)
            snprintf(msg, msgsz, "paired: server-side - the server served %.0f ops during your "
                     "slow test with a low reply-cache hit rate (%.0f%%); it was the bottleneck",
                     d_calls, ratio * 100.0);
        else
            snprintf(msg, msgsz, "paired: the server served %.0f ops during your slow test at a "
                     "%.0f%% cache hit rate; check the network path too", d_calls, ratio * 100.0);
        return 1;
    }
    if (slow) {
        snprintf(msg, msgsz, "paired: client/network-side - the server saw little traffic during "
                 "your slow test; look at the network path or client");
        return 1;
    }
    snprintf(msg, msgsz, "paired: both sides healthy - %.0f ops served during the test, no bad calls",
             d_calls);
    return 0;
}
