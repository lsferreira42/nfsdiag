#include "nfsdiag.h"

/* Pure, dependency-light helpers shared across translation units and exercised
 * by tests/unit-tests.c. Nothing here may call report_*, fork, or touch global
 * option/report state, so the helpers stay unit-testable in isolation. */

/* mountstats per-op latency fields are cumulative milliseconds; average is
 * simply total/ops. (The old call site divided by 1000, treating ms as us.) */
double avg_per_op_ms(unsigned long total_ms, unsigned long ops) {
    if (ops == 0) return 0.0;
    return (double)total_ms / (double)ops;
}

/* Central policy: a missing legacy NFSv3-era service (mountd/NLM/NSM/NFSv3) is
 * only a warning when the server is not known to be NFSv4-only. */
int service_missing_is_warning(enum server_profile profile) {
    return profile != PROFILE_NFSV4_ONLY;
}

/* Strict bounded integer parse shared by the CLI and config-file parsers so the
 * accepted ranges never drift between the two. */
int parse_bounded_int(const char *s, unsigned long lo, unsigned long hi, int *out) {
    unsigned long v;
    if (parse_ulong_arg(s, &v) != 0) return -1;
    if (v < lo || v > hi) return -1;
    *out = (int)v;
    return 0;
}

/* Open path read-only refusing symlinks, and only if it is a regular file.
 * Used for report/baseline reads that may live in shared directories. */
FILE *fopen_regular_ro(const char *path) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) { close(fd); return NULL; }
    FILE *f = fdopen(fd, "r");
    /* fdopen() does not close the fd on failure */
    // cppcheck-suppress doubleFree
    if (!f) close(fd);
    return f;
}

/* Decode the \NNN octal escapes the kernel uses for spaces/tabs/newlines/
 * backslashes in /proc/self/mountinfo path fields. */
void mountinfo_unescape(char *dst, size_t dst_sz, const char *src) {
    if (!dst || dst_sz == 0) return;
    size_t j = 0;
    for (size_t i = 0; src && src[i] && j + 1 < dst_sz; i++) {
        if (src[i] == '\\' && src[i+1] >= '0' && src[i+1] <= '7' &&
            src[i+2] >= '0' && src[i+2] <= '7' &&
            src[i+3] >= '0' && src[i+3] <= '7') {
            int v = (src[i+1]-'0')*64 + (src[i+2]-'0')*8 + (src[i+3]-'0');
            dst[j++] = (char)v;
            i += 3;
        } else {
            dst[j++] = src[i];
        }
    }
    dst[j] = '\0';
}

/* Whole-token membership test for a comma-separated list. */
static int csv_has_token(const char *csv, const char *tok, size_t tok_len) {
    for (const char *p = csv; p && *p; ) {
        const char *comma = strchr(p, ',');
        size_t seg = comma ? (size_t)(comma - p) : strlen(p);
        if (seg == tok_len && strncmp(p, tok, tok_len) == 0) return 1;
        if (!comma) break;
        p = comma + 1;
    }
    return 0;
}

/* Append comma-separated tokens to dst, each only if absent from existing. */
void csv_append_missing(char *dst, size_t dst_sz, const char *tokens,
                        const char *existing) {
    for (const char *p = tokens; p && *p; ) {
        const char *comma = strchr(p, ',');
        size_t seg = comma ? (size_t)(comma - p) : strlen(p);
        if (seg > 0 && !csv_has_token(existing, p, seg)) {
            size_t used = strlen(dst);
            int n = snprintf(dst + used, dst_sz - used, "%s%.*s",
                             used ? "," : "", (int)seg, p);
            if (n < 0 || (size_t)n >= dst_sz - used) return; /* truncated */
        }
        if (!comma) break;
        p = comma + 1;
    }
}

/* Parse the HTTP request line "METHOD SP TARGET SP VERSION". Returns 1 only for
 * GET, writing the (control-char-free, bounded) target into path_out. Anything
 * malformed or non-GET returns 0. Operates on the raw buffer up to len bytes. */
int http_request_is_get(const char *req, size_t len, char *path_out, size_t path_sz) {
    if (!req || !path_out || path_sz == 0) return 0;
    if (len < 5 || strncmp(req, "GET ", 4) != 0) return 0;
    size_t i = 4;
    size_t j = 0;
    while (i < len && req[i] != ' ' && req[i] != '\r' && req[i] != '\n') {
        unsigned char c = (unsigned char)req[i];
        if (c < 0x20 || c == 0x7f) return 0;
        if (j + 1 < path_sz) path_out[j++] = (char)c;
        i++;
    }
    if (j == 0) return 0;
    path_out[j] = '\0';
    return 1;
}

/* Copy src into dst capping the payload at max_cols bytes, appending "..." when
 * truncated. Truncation backs up to a UTF-8 character boundary so the terminal
 * never receives a split multibyte sequence. dst_sz must be >= max_cols + 1. */
void utf8_truncate(char *dst, size_t dst_sz, const char *src, size_t max_cols) {
    if (!dst || dst_sz == 0) return;
    size_t len = src ? strlen(src) : 0;
    if (len <= max_cols) {
        snprintf(dst, dst_sz, "%s", src ? src : "");
        return;
    }
    /* Reserve 3 bytes for the ellipsis. */
    size_t keep = max_cols >= 3 ? max_cols - 3 : 0;
    /* Back up so we do not cut a multibyte sequence: continuation bytes are
     * 0b10xxxxxx (0x80..0xBF). */
    while (keep > 0 && ((unsigned char)src[keep] & 0xC0) == 0x80)
        keep--;
    if (keep + 4 > dst_sz) keep = dst_sz > 4 ? dst_sz - 4 : 0;
    memcpy(dst, src, keep);
    snprintf(dst + keep, dst_sz - keep, "...");
}
