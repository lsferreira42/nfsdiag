/* server_exports.c - pure parsing/analysis helpers for `server --exports-audit`.
 *
 * No I/O and no report.c calls here: everything takes buffers and returns
 * codes so tests/unit-tests.c can link this file without the rest of the
 * server namespace.
 */
#include "nfsdiag.h"

int exports_parse_line(const char *line, int lineno, struct export_line *out,
                       char *err, size_t errsz) {
    const char *p = line;
    memset(out, 0, sizeof(*out));
    out->lineno = lineno;

    while (*p == ' ' || *p == '\t') p++;
    if (*p == '\0' || *p == '\n' || *p == '#')
        return 0;

    size_t n = 0;
    if (*p == '"') {                          /* quoted path */
        p++;
        while (*p && *p != '"' && n + 1 < sizeof(out->path))
            out->path[n++] = *p++;
        if (*p != '"') {
            snprintf(err, errsz, "line %d: unterminated quote in path", lineno);
            return -1;
        }
        p++;
    } else {
        while (*p && *p != ' ' && *p != '\t' && *p != '\n' &&
               n + 1 < sizeof(out->path))
            out->path[n++] = *p++;
    }
    out->path[n] = '\0';

    if (out->path[0] != '/') {
        snprintf(err, errsz, "line %d: export path must be absolute", lineno);
        return -1;
    }

    while (*p) {
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0' || *p == '\n' || *p == '#')
            break;
        if (out->client_count >= (int)(sizeof(out->clients) / sizeof(out->clients[0]))) {
            snprintf(err, errsz, "line %d: too many client entries", lineno);
            return -1;
        }
        char *dst = out->clients[out->client_count];
        size_t m = 0;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n' &&
               m + 1 < sizeof(out->clients[0]))
            dst[m++] = *p++;
        dst[m] = '\0';
        out->client_count++;
    }

    if (out->client_count == 0) {
        snprintf(err, errsz, "line %d: export '%s' has no client list "
                 "(exports to the world)", lineno, out->path);
        return -1;
    }
    return 1;
}

/* Match a whole option token inside "(opt,opt=value,...)": needle must be
 * delimited by '(' ',' ')' or '=' so e.g. "rw" does not match "rwsize". */
static int opts_contain(const char *opts, const char *needle) {
    size_t nl = strlen(needle);
    const char *q = opts;
    while ((q = strstr(q, needle)) != NULL) {
        int start_ok = (q == opts || q[-1] == ',' || q[-1] == '(');
        int end_ok = (q[nl] == '\0' || q[nl] == ',' || q[nl] == ')' || q[nl] == '=');
        if (start_ok && end_ok)
            return 1;
        q += nl;
    }
    return 0;
}

static void scan_emit(struct export_finding *out, int max, int *n,
                      int level, const char *fmt, ...) {
    if (*n >= max)
        return;
    va_list ap;
    va_start(ap, fmt);
    out[*n].level = level;
    vsnprintf(out[*n].msg, sizeof(out[*n].msg), fmt, ap);
    va_end(ap);
    (*n)++;
}

static void scan_token(const struct export_line *e, const char *token,
                       struct export_finding *out, int max, int *n) {
    const char *open = strchr(token, '(');
    if (!open)
        return;
    if (opts_contain(open, "subtree_check"))
        scan_emit(out, max, n, 1, "%s: subtree_check is legacy: it costs "
                  "performance and breaks file handles on renames; use "
                  "no_subtree_check", e->path);
    if (opts_contain(open, "insecure_locks") || opts_contain(open, "no_auth_nlm"))
        scan_emit(out, max, n, 1, "%s: insecure_locks skips lock request "
                  "authentication", e->path);
    if (opts_contain(open, "all_squash") && !strstr(open, "anonuid="))
        scan_emit(out, max, n, 0, "%s: all_squash without anonuid=/anongid= "
                  "maps everyone to nobody; set them explicitly if a shared "
                  "account is intended", e->path);
    if (opts_contain(open, "sec=sys") || strstr(open, "sec=sys:"))
        scan_emit(out, max, n, 0, "%s: sec=sys trusts client-side identities; "
                  "consider sec=krb5* where Kerberos is available", e->path);
    if (token[0] == '*' && opts_contain(open, "ro") && !opts_contain(open, "rw"))
        scan_emit(out, max, n, 0, "%s: read-only export to any host: confirm "
                  "world-readable data is intended", e->path);
}

int exports_security_scan(const struct export_line *entries, int n_entries,
                          struct export_finding *out, int max) {
    int n = 0;
    for (int i = 0; i < n_entries; i++) {
        for (int c = 0; c < entries[i].client_count; c++)
            scan_token(&entries[i], entries[i].clients[c], out, max, &n);

        for (int j = i + 1; j < n_entries; j++) {
            if (strcmp(entries[i].path, entries[j].path) == 0) {
                scan_emit(out, max, &n, 1, "%s: exported twice (lines %d and "
                          "%d); the kernel merges them and option conflicts "
                          "are silent", entries[i].path, entries[i].lineno,
                          entries[j].lineno);
            }
        }
    }
    /* nested exports: child under a parent that lacks crossmnt */
    for (int i = 0; i < n_entries; i++) {
        for (int j = 0; j < n_entries; j++) {
            if (i == j)
                continue;
            size_t plen = strlen(entries[i].path);
            if (strncmp(entries[j].path, entries[i].path, plen) == 0 &&
                entries[j].path[plen] == '/') {
                int parent_crossmnt = 0;
                for (int c = 0; c < entries[i].client_count; c++) {
                    const char *open = strchr(entries[i].clients[c], '(');
                    if (open && opts_contain(open, "crossmnt"))
                        parent_crossmnt = 1;
                }
                if (!parent_crossmnt)
                    scan_emit(out, max, &n, 0, "%s: nested under %s, which "
                              "lacks crossmnt; clients mounting the parent "
                              "will not traverse into it",
                              entries[j].path, entries[i].path);
            }
        }
    }
    return n;
}

int exports_client_risk(const char *token, char *why, size_t whysz) {
    const char *open = strchr(token, '(');
    const char *close = strrchr(token, ')');

    if (open == NULL && close == NULL) {
        /* bare hostname: server default options apply */
        return 0;
    }
    if (open == NULL || close == NULL || close < open ||
        strchr(open + 1, '(') != NULL) {
        snprintf(why, whysz, "malformed client token '%s'", token);
        return -1;
    }

    int wildcard = (open - token >= 1 && token[0] == '*');

    if (opts_contain(open, "no_root_squash")) {
        snprintf(why, whysz, "'%s': no_root_squash lets remote root act as "
                 "local root", token);
        return 1;
    }
    if (opts_contain(open, "insecure")) {
        snprintf(why, whysz, "'%s': 'insecure' accepts requests from "
                 "unprivileged source ports", token);
        return 1;
    }
    if (wildcard && opts_contain(open, "rw")) {
        snprintf(why, whysz, "'%s': read-write export to any host", token);
        return 1;
    }
    return 0;
}

int export_line_has_fsid(const struct export_line *e) {
    for (int i = 0; i < e->client_count; i++)
        if (strstr(e->clients[i], "fsid=") != NULL)
            return 1;
    return 0;
}
