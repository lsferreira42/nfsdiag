#include "nfsdiag.h"

static void set_reason(char *reason, size_t reason_sz, const char *msg) {
    if (reason && reason_sz)
        snprintf(reason, reason_sz, "%s", msg);
}

/* Strict base-10 unsigned parse: rejects empty strings, trailing garbage,
 * and out-of-range values. Callers must still range-check the result. */
int parse_ulong_arg(const char *s, unsigned long *out) {
    if (!s || *s == '\0') return -1;
    /* strtoul silently accepts sign characters and leading whitespace
     * ("-1" wraps to ULONG_MAX); only bare digits are valid here. */
    if (s[0] < '0' || s[0] > '9') return -1;
    char *end = NULL;
    errno = 0;
    unsigned long v = strtoul(s, &end, 10);
    if (errno || !end || end == s || *end != '\0') return -1;
    *out = v;
    return 0;
}

/* uid_t/gid_t are usually 32-bit unsigned, but parse_ulong_arg() accepts the
 * full unsigned long range. Reject values that would truncate on cast, plus
 * the reserved (uid_t)-1 / (gid_t)-1 sentinels used by the set*id() calls. */
int parse_uid_arg(const char *s, uid_t *out) {
    unsigned long value;
    if (parse_ulong_arg(s, &value) != 0) return -1;
    uid_t uid = (uid_t)value;
    if ((unsigned long)uid != value || uid == (uid_t)-1) return -1;
    *out = uid;
    return 0;
}

int parse_gid_arg(const char *s, gid_t *out) {
    unsigned long value;
    if (parse_ulong_arg(s, &value) != 0) return -1;
    gid_t gid = (gid_t)value;
    if ((unsigned long)gid != value || gid == (gid_t)-1) return -1;
    *out = gid;
    return 0;
}

/* Options whose following value can carry sensitive material — mount options
 * (paths, future sec= credentials) and local config/hook paths. Their values
 * are replaced with <redacted> in the evidence record. */
static int redacts_next_value(const char *arg) {
    return strcmp(arg, "-o") == 0 ||
           strcmp(arg, "--mount-options") == 0 ||
           strcmp(arg, "--config") == 0 ||
           strcmp(arg, "--on-fail-exec") == 0;
}

/* Returns the "--flag=" prefix length if arg is a redacted inline assignment
 * (e.g. "--config=/path"), else 0. */
static size_t redacted_inline_prefix(const char *arg) {
    static const char *flags[] = {"--mount-options=", "--config=", "--on-fail-exec=", NULL};
    for (size_t i = 0; flags[i]; i++) {
        size_t len = strlen(flags[i]);
        if (strncmp(arg, flags[i], len) == 0) return len;
    }
    return 0;
}

void redact_argv(char *dst, size_t dst_sz, int argc, char **argv) {
    if (!dst || dst_sz == 0) return;
    dst[0] = '\0';
    size_t used = 0;
    int redact_next = 0;
    for (int i = 0; i < argc; i++) {
        const char *arg = argv[i] ? argv[i] : "";
        char clean[512];
        size_t prefix = redacted_inline_prefix(arg);
        if (redact_next) {
            snprintf(clean, sizeof(clean), "<redacted>");
            redact_next = 0;
        } else if (redacts_next_value(arg)) {
            snprintf(clean, sizeof(clean), "%s", arg);
            redact_next = 1;
        } else if (prefix != 0) {
            snprintf(clean, sizeof(clean), "%.*s<redacted>", (int)prefix, arg);
        } else if (strncmp(arg, "-o", 2) == 0 && arg[2] != '\0') {
            snprintf(clean, sizeof(clean), "-o<redacted>");
        } else {
            size_t j = 0;
            for (const unsigned char *p = (const unsigned char *)arg; *p && j + 1 < sizeof(clean); p++)
                clean[j++] = (*p < 0x20 || *p == 0x7f) ? '?' : (char)*p;
            clean[j] = '\0';
        }
        int n = snprintf(dst + used, dst_sz - used, "%s%s", used ? " " : "", clean);
        if (n < 0 || (size_t)n >= dst_sz - used) break;
        used += (size_t)n;
    }
}

int validate_host_arg(const char *host, char *reason, size_t reason_sz) {
    if (!host || !host[0]) {
        set_reason(reason, reason_sz, "host is empty");
        return -1;
    }
    if (strlen(host) > 255) {
        set_reason(reason, reason_sz, "host is longer than 255 bytes");
        return -1;
    }
    for (const unsigned char *p = (const unsigned char *)host; *p; p++) {
        if (*p < 0x21 || *p == 0x7f) {
            set_reason(reason, reason_sz, "host contains whitespace or control characters");
            return -1;
        }
        if (*p == '/' || *p == '\\' || *p == ',' || *p == ';') {
            set_reason(reason, reason_sz, "host contains unsupported separators");
            return -1;
        }
    }
    return 0;
}

int validate_export_path(const char *path, char *reason, size_t reason_sz) {
    if (!path || !path[0]) {
        set_reason(reason, reason_sz, "export path is empty");
        return -1;
    }
    if (path[0] != '/') {
        set_reason(reason, reason_sz, "export path must be absolute");
        return -1;
    }
    if (strlen(path) >= MAX_XDR_EXPORT_PATH) {
        set_reason(reason, reason_sz, "export path is too long");
        return -1;
    }
    for (const unsigned char *p = (const unsigned char *)path; *p; p++) {
        if (*p < 0x20 || *p == 0x7f) {
            set_reason(reason, reason_sz, "export path contains control characters");
            return -1;
        }
    }
    if (strcmp(path, "/..") == 0 || strstr(path, "/../") || strstr(path, "/..") == path + strlen(path) - 3) {
        set_reason(reason, reason_sz, "export path must not contain '..' components");
        return -1;
    }
    return 0;
}

static int token_equals(const char *tok, const char *name) {
    size_t n = strlen(name);
    return strncmp(tok, name, n) == 0 && (tok[n] == '\0' || tok[n] == '=');
}

int validate_mount_options(const char *opts, int allow_risky,
                           char *reason, size_t reason_sz) {
    if (!opts || !opts[0]) return 0;
    if (strlen(opts) > 1800) {
        set_reason(reason, reason_sz, "mount options are too long");
        return -1;
    }
    for (const unsigned char *p = (const unsigned char *)opts; *p; p++) {
        if (*p < 0x21 || *p == 0x7f || *p == ';') {
            set_reason(reason, reason_sz, "mount options contain whitespace, control characters, or semicolon");
            return -1;
        }
    }

    /* strtok_r skips empty tokens, so catch them before tokenising */
    if (opts[0] == ',' || strstr(opts, ",,") || opts[strlen(opts) - 1] == ',') {
        set_reason(reason, reason_sz, "mount options contain an empty token");
        return -1;
    }

    char copy[2048];
    snprintf(copy, sizeof(copy), "%s", opts);
    char *save = NULL;
    for (const char *tok = strtok_r(copy, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        if (!allow_risky &&
            (token_equals(tok, "exec") || token_equals(tok, "suid") || token_equals(tok, "dev"))) {
            snprintf(reason, reason_sz,
                     "mount option '%s' is risky; pass --allow-risky-mount-options to permit it",
                     tok);
            return -1;
        }
    }
    return 0;
}

void warn_risky_mount_options(const char *opts) {
    if (!opts || !opts[0]) return;
    char copy[2048];
    snprintf(copy, sizeof(copy), "%s", opts);
    char *save = NULL;
    for (const char *tok = strtok_r(copy, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        if (token_equals(tok, "soft"))
            report_warn("mount option 'soft' can turn server stalls into application-visible I/O errors");
        else if (token_equals(tok, "nolock"))
            report_warn("mount option 'nolock' disables NFSv3 advisory locking checks");
        else if (token_equals(tok, "sec") && strcmp(tok, "sec=sys") == 0)
            report_info("mount option sec=sys uses AUTH_SYS; use --krb5 and sec=krb5* for Kerberos validation");
    }
}

/* Parse a --listen argument: "PORT", "ADDR:PORT", or "[V6ADDR]:PORT".
 * The bind address defaults to 127.0.0.1 so the exporter is never exposed
 * beyond the local host unless explicitly requested. */
int parse_listen_arg(const char *arg, char *addr_out, size_t addr_sz,
                     int *port_out, char *reason, size_t reason_sz) {
    if (!arg || !arg[0]) {
        set_reason(reason, reason_sz, "listen argument is empty");
        return -1;
    }
    char addr[256] = "127.0.0.1";
    const char *portstr;

    if (arg[0] == '[') {
        const char *close_b = strchr(arg, ']');
        if (!close_b || close_b == arg + 1 || close_b[1] != ':' || !close_b[2]) {
            set_reason(reason, reason_sz, "expected [V6ADDR]:PORT");
            return -1;
        }
        size_t alen = (size_t)(close_b - arg - 1);
        if (alen >= sizeof(addr)) {
            set_reason(reason, reason_sz, "listen address is too long");
            return -1;
        }
        memcpy(addr, arg + 1, alen);
        addr[alen] = '\0';
        portstr = close_b + 2;
    } else {
        const char *colon = strchr(arg, ':');
        if (colon && colon != strrchr(arg, ':')) {
            set_reason(reason, reason_sz, "IPv6 listen addresses need brackets: [ADDR]:PORT");
            return -1;
        }
        if (colon) {
            size_t alen = (size_t)(colon - arg);
            if (alen == 0) {
                set_reason(reason, reason_sz, "listen address is empty");
                return -1;
            }
            if (alen >= sizeof(addr)) {
                set_reason(reason, reason_sz, "listen address is too long");
                return -1;
            }
            memcpy(addr, arg, alen);
            addr[alen] = '\0';
            portstr = colon + 1;
        } else {
            portstr = arg;
        }
    }

    unsigned long port;
    if (parse_ulong_arg(portstr, &port) != 0 || port < 1 || port > 65535) {
        set_reason(reason, reason_sz, "listen port must be 1-65535");
        return -1;
    }
    snprintf(addr_out, addr_sz, "%s", addr);
    *port_out = (int)port;
    return 0;
}

const char *event_category_for_message(const char *level, const char *message) {
    (void)level;
    if (!message) return "general";
    if (strstr(message, "rpcbind") || strstr(message, "TCP port") || strstr(message, "Network"))
        return "network";
    if (strstr(message, "RPC") || strstr(message, "NFS v") || strstr(message, "mountd") ||
        strstr(message, "NLM") || strstr(message, "NSM"))
        return "rpc";
    if (strstr(message, "mount") || strstr(message, "umount") || strstr(message, "mountinfo") ||
        strstr(message, "mountstats"))
        return "mount";
    if (strstr(message, "Kerberos") || strstr(message, "klist") || strstr(message, "gssd") ||
        strstr(message, "sec="))
        return "auth";
    if (strstr(message, "permission") || strstr(message, "access") || strstr(message, "uid=") ||
        strstr(message, "gid=") || strstr(message, "root_squash") || strstr(message, "ACL"))
        return "permissions";
    if (strstr(message, "benchmark") || strstr(message, "latency") || strstr(message, "MiB/s") ||
        strstr(message, "retrans"))
        return "performance";
    if (strstr(message, "cleanup") || strstr(message, "temporary workspace") || strstr(message, "remove"))
        return "cleanup";
    if (strstr(message, "risky") || strstr(message, "dangerous") || strstr(message, "namespace") ||
        strstr(message, "capab"))
        return "security";
    return "general";
}

void event_check_id(char *dst, size_t dst_sz, const char *level,
                    const char *category, const char *message) {
    uint64_t h = 1469598103934665603ULL;
    const char *parts[] = {level ? level : "", category ? category : "", message ? message : ""};
    for (size_t p = 0; p < sizeof(parts) / sizeof(parts[0]); p++) {
        for (const unsigned char *s = (const unsigned char *)parts[p]; *s; s++) {
            h ^= (uint64_t)*s;
            h *= 1099511628211ULL;
        }
        h ^= 0xffU;
        h *= 1099511628211ULL;
    }
    snprintf(dst, dst_sz, "%s.%012llx", category ? category : "general",
             (unsigned long long)(h & 0xffffffffffffULL));
}

const char *event_remediation_for(const char *category, const char *message) {
    if (!category) return "";
    if (strcmp(category, "network") == 0)
        return "Check routing, firewall/security groups, service bind address, and server reachability.";
    if (strcmp(category, "rpc") == 0)
        return "Verify rpcbind, nfsd, mountd, lockd/statd registration and protocol/version firewall rules.";
    if (strcmp(category, "mount") == 0)
        return "Inspect export path, mount options, NFS client tools, namespace state, and server export policy.";
    if (strcmp(category, "auth") == 0)
        return "Check Kerberos tickets, rpc.gssd/gssproxy, keytab/realm configuration, clock sync, and sec= mount option.";
    if (strcmp(category, "permissions") == 0)
        return "Review export ro/rw mode, UNIX ownership, ACLs, idmapping, root_squash, and server MAC policy.";
    if (strcmp(category, "performance") == 0)
        return "Compare with a larger sample, review retransmissions/timeouts, network health, server load, and cache effects.";
    if (strcmp(category, "cleanup") == 0)
        return "Inspect temporary paths and active mounts; unmount leftovers before rerunning.";
    if (message && strstr(message, "dangerous"))
        return "Use dangerous filesystem probes only on disposable or explicitly approved exports.";
    return "";
}

int parse_peer_arg(const char *arg, char *host, size_t hostsz, int *port, int default_port) {
    *port = default_port;
    if (!arg || !*arg)
        return -1;
    if (arg[0] == '[') {                 /* [v6]:port */
        const char *end = strchr(arg, ']');
        if (!end) return -1;
        size_t n = (size_t)(end - (arg + 1));
        if (n == 0 || n + 1 > hostsz) return -1;
        memcpy(host, arg + 1, n); host[n] = '\0';
        if (end[1] == ':') {
            unsigned long p;
            if (parse_ulong_arg(end + 2, &p) != 0 || p == 0 || p > 65535) return -1;
            *port = (int)p;
        } else if (end[1] != '\0') {
            return -1;
        }
        return 0;
    }
    int colons = 0;
    for (const char *c = arg; *c; c++) if (*c == ':') colons++;
    if (colons == 1) {                   /* host:port */
        const char *colon = strchr(arg, ':');
        size_t n = (size_t)(colon - arg);
        if (n == 0 || n + 1 > hostsz) return -1;
        memcpy(host, arg, n); host[n] = '\0';
        unsigned long p;
        if (parse_ulong_arg(colon + 1, &p) != 0 || p == 0 || p > 65535) return -1;
        *port = (int)p;
        return 0;
    }
    if (strlen(arg) + 1 > hostsz) return -1;   /* plain host or bare v6 literal */
    snprintf(host, hostsz, "%s", arg);
    return 0;
}
