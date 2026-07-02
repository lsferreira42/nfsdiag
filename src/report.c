#include "nfsdiag.h"

/* ---- internal tracking ---- */
struct report_event *events = NULL;
size_t event_count = 0;
static size_t event_capacity = 0;

char **recommendations = NULL;
size_t recommendation_count = 0;
static size_t recommendation_capacity = 0;

int    summary_ok   = 0;
int    summary_warn  = 0;
int    summary_fail  = 0;
int    saved_stdout_fd = -1;
int    current_export_idx = -1;
struct export_report *export_reports = NULL;
size_t export_report_count = 0;
size_t export_report_cap = 0;

/* Return a zeroed slot at idx, growing the heap array on demand up to
 * MAX_EXPORT_REPORTS, or NULL past the cap / on OOM. Callers must not hold a
 * returned pointer across another export_report_at() call (realloc may move). */
struct export_report *export_report_at(size_t idx) {
    if (idx >= MAX_EXPORT_REPORTS) return NULL;
    if (idx >= export_report_cap) {
        size_t ncap = export_report_cap ? export_report_cap : 8;
        while (ncap <= idx) ncap *= 2;
        if (ncap > MAX_EXPORT_REPORTS) ncap = MAX_EXPORT_REPORTS;
        struct export_report *n = realloc(export_reports, ncap * sizeof(*n));
        if (!n) return NULL;
        memset(n + export_report_cap, 0,
               (ncap - export_report_cap) * sizeof(*n));
        export_reports = n;
        export_report_cap = ncap;
    }
    return &export_reports[idx];
}
static time_t diagnostic_start = 0;
static int    colors_cached = -1;  /* -1 = unknown; recomputed per diagnostic run */

static void json_escape(FILE *f, const char *s);

/* ---- state reset (for watch/hosts-file) ---- */

void reset_diagnostic_state(void) {
    for (size_t i = 0; i < event_count; i++) {
        free(events[i].level);
        free(events[i].message);
    }
    event_count = 0;

    for (size_t i = 0; i < recommendation_count; i++)
        free(recommendations[i]);
    recommendation_count = 0;

    if (export_reports)
        memset(export_reports, 0, export_report_cap * sizeof(*export_reports));
    export_report_count = 0;
    summary_ok   = 0;
    summary_warn = 0;
    summary_fail = 0;
    current_export_idx = -1;
    diagnostic_start = time(NULL);
    colors_cached = -1;  /* stdout may have been redirected/restored */

    /* Restore stdout if it was redirected */
    if (saved_stdout_fd >= 0) {
        dup2(saved_stdout_fd, STDOUT_FILENO);
        close(saved_stdout_fd);
        saved_stdout_fd = -1;
    }
}

/* Exposed via nfsdiag.h and called from other translation units. cppcheck's
 * per-file analysis cannot see those callers, so it raises a false-positive
 * staticFunction (static-linkage) suggestion here. */
void add_event(const char *level, const char *message) {
    if (event_count >= event_capacity) {
        size_t new_cap = event_capacity == 0 ? 64 : event_capacity * 2;
        struct report_event *new_events = realloc(events, new_cap * sizeof(struct report_event));
        if (!new_events) return;
        events = new_events;
        event_capacity = new_cap;
    }
    char *lev = strdup(level);
    char *msg = strdup(message);
    if (!lev || !msg) { free(lev); free(msg); return; }
    events[event_count].level = lev;
    events[event_count].message = msg;
    snprintf(events[event_count].category, sizeof(events[event_count].category),
             "%s", event_category_for_message(lev, msg));
    event_check_id(events[event_count].check_id, sizeof(events[event_count].check_id),
                   lev, events[event_count].category, msg);
    snprintf(events[event_count].remediation, sizeof(events[event_count].remediation),
             "%s", event_remediation_for(events[event_count].category, msg));
    events[event_count].export_idx = current_export_idx;
    event_count++;

    /* Streaming NDJSON: emit the event immediately to the real stdout fd.
     * Render into a memstream then write once, avoiding a dup/fdopen/fclose per
     * event, and reuse json_escape for every field so escaping is consistent. */
    if (opt.output_fmt == OUTPUT_FMT_NDJSON) {
        int ofd = (saved_stdout_fd >= 0) ? saved_stdout_fd : STDOUT_FILENO;
        char *buf = NULL;
        size_t sz = 0;
        FILE *m = open_memstream(&buf, &sz);
        if (m) {
            fprintf(m, "{\"check_id\":\"");
            json_escape(m, events[event_count - 1].check_id);
            fprintf(m, "\",\"level\":\"");
            json_escape(m, lev);
            fprintf(m, "\",\"category\":\"");
            json_escape(m, events[event_count - 1].category);
            fprintf(m, "\",\"message\":\"");
            json_escape(m, msg);
            fprintf(m, "\",\"remediation\":\"");
            json_escape(m, events[event_count - 1].remediation);
            fprintf(m, "\",\"export_idx\":%d}\n", current_export_idx);
            fclose(m);
            if (buf) { (void)!write(ofd, buf, sz); free(buf); }
        }
    }
}

void add_recommendation(const char *fmt, ...) {
    char msg[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    for (size_t i = 0; i < recommendation_count; i++) {
        if (strcmp(recommendations[i], msg) == 0) return;
    }
    if (recommendation_count >= recommendation_capacity) {
        size_t new_cap = recommendation_capacity == 0 ? 16 : recommendation_capacity * 2;
        char **new_recs = realloc(recommendations, new_cap * sizeof(char *));
        if (!new_recs) return;
        recommendations = new_recs;
        recommendation_capacity = new_cap;
    }
    char *dup = strdup(msg);
    if (!dup) return;
    recommendations[recommendation_count++] = dup;
}

static int important_ok_message(const char *msg) {
    return strstr(msg, "export(s) discovered") ||
           strstr(msg, "mounted ") ||
           strstr(msg, "no ESTALE") ||
           strstr(msg, "write+fsync benchmark") ||
           strstr(msg, "read benchmark") ||
           strstr(msg, "metadata latency benchmark") ||
           strstr(msg, "root_squash practical signal") ||
           strstr(msg, "using private mount namespace") ||
           strstr(msg, "RPC stats delta") ||
           strstr(msg, "effective mount options");
}

static int use_colors(void) {
    /* Cached per run: stdout can be redirected/restored between runs
     * (watch/hosts-file, --json=-), so reset_diagnostic_state() invalidates it. */
    if (colors_cached < 0)
        colors_cached = isatty(fileno(stdout)) ? 1 : 0;
    return colors_cached;
}

#define ANSI_GREEN  "\033[32m"
#define ANSI_YELLOW "\033[33m"
#define ANSI_RED    "\033[31m"
#define ANSI_BLUE   "\033[34m"
#define ANSI_RESET  "\033[0m"

void report_ok(const char *fmt, ...) {
    va_list ap;
    summary_ok++;
    char msg[2048];
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    add_event("ok", msg);
    if (!opt.quiet && opt.output_fmt == OUTPUT_FMT_TEXT &&
        (opt.verbose || important_ok_message(msg))) {
        if (use_colors()) printf("%s[OK]%s %s\n", ANSI_GREEN, ANSI_RESET, msg);
        else printf("[OK] %s\n", msg);
    }
}

void report_warn(const char *fmt, ...) {
    va_list ap;
    summary_warn++;
    char msg[2048];
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    add_event("warn", msg);
    if (!opt.quiet && opt.output_fmt == OUTPUT_FMT_TEXT) {
        if (use_colors()) printf("%s[WARN]%s %s\n", ANSI_YELLOW, ANSI_RESET, msg);
        else printf("[WARN] %s\n", msg);
    }
}

void report_fail(const char *fmt, ...) {
    va_list ap;
    summary_fail++;
    char msg[2048];
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    add_event("fail", msg);
    if (!opt.quiet && opt.output_fmt == OUTPUT_FMT_TEXT) {
        if (use_colors()) printf("%s[FAIL]%s %s\n", ANSI_RED, ANSI_RESET, msg);
        else printf("[FAIL] %s\n", msg);
    }
}

void report_info(const char *fmt, ...) {
    va_list ap;
    char msg[2048];
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    add_event("info", msg);
    if (!opt.quiet && opt.verbose && opt.output_fmt == OUTPUT_FMT_TEXT) {
        if (use_colors()) printf("%s[INFO]%s %s\n", ANSI_BLUE, ANSI_RESET, msg);
        else printf("[INFO] %s\n", msg);
    }
}

/* Per-export status derived from that export's own events (export_idx == idx),
 * never from the global summary counters. */
static const char *export_status(size_t idx, int tested) {
    if (!tested) return "SKIP";
    int has_fail = 0, has_warn = 0;
    for (size_t e = 0; e < event_count; e++) {
        if (events[e].export_idx != (int)idx) continue;
        if (strcmp(events[e].level, "fail") == 0) has_fail = 1;
        else if (strcmp(events[e].level, "warn") == 0) has_warn = 1;
    }
    return has_fail ? "FAIL" : (has_warn ? "WARN" : "PASS");
}

/* ---- stdout suppression ---- */

void enable_report_only_output(void) {
    /* Suppress stdout only when a report is written to stdout ("-"),
     * or when ndjson is the output format (events go to stdout inline). */
    if (opt.output_fmt == OUTPUT_FMT_NDJSON) return; /* ndjson is streaming */
    int suppress = 0;
    if (opt.json && opt.json_path && strcmp(opt.json_path, "-") == 0) suppress = 1;
    if (opt.html && opt.html_path && strcmp(opt.html_path, "-") == 0) suppress = 1;
    if (!suppress) return;
    fflush(stdout);
    saved_stdout_fd = dup(STDOUT_FILENO);
    int devnull = open("/dev/null", O_WRONLY | O_CLOEXEC);
    if (devnull >= 0) {
        dup2(devnull, STDOUT_FILENO);
        close(devnull);
    }
}

/* ---- JSON output ---- */

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

static void json_write_system_info(FILE *f) {
    struct system_info si;
    collect_system_info(&si);
    fprintf(f, "  \"system_info\": {\n");
    fprintf(f, "    \"kernel\": \"");   json_escape(f, si.kernel);   fprintf(f, "\",\n");
    fprintf(f, "    \"hostname\": \""); json_escape(f, si.hostname); fprintf(f, "\",\n");
    fprintf(f, "    \"arch\": \"");     json_escape(f, si.arch);     fprintf(f, "\"\n");
    fprintf(f, "  },\n");
}

static void json_write_exports(FILE *f) {
    fprintf(f, "  \"exports\": [\n");
    for (size_t i = 0; i < export_report_count; i++) {
        struct export_report *r = &export_reports[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"path\": \"");          json_escape(f, r->path); fprintf(f, "\",\n");
        fprintf(f, "      \"nfs_version\": %d,\n", r->nfs_version);
        fprintf(f, "      \"nfs_minor_version\": %d,\n", r->nfs_minor_version);
        fprintf(f, "      \"tested\": %s,\n",      r->tested ? "true" : "false");
        fprintf(f, "      \"metrics\": {\n");
        fprintf(f, "        \"write_mib_s\": %.2f,\n",  r->write_mib_s);
        fprintf(f, "        \"read_mib_s\": %.2f,\n",   r->read_mib_s);
        fprintf(f, "        \"metadata_p50_ms\": %.2f,\n", r->meta_p50_ms);
        fprintf(f, "        \"metadata_p95_ms\": %.2f,\n", r->meta_p95_ms);
        fprintf(f, "        \"metadata_p99_ms\": %.2f,\n", r->meta_p99_ms);
        fprintf(f, "        \"metadata_iterations\": %d\n", r->meta_completed);
        fprintf(f, "      },\n");
        fprintf(f, "      \"tests\": {\n");
        fprintf(f, "        \"acl_posix\": %s,\n",         r->acl_posix ? "true" : "false");
        fprintf(f, "        \"acl_nfsv4\": %s,\n",         r->acl_nfsv4 ? "true" : "false");
        fprintf(f, "        \"lock_ok\": %s,\n",            r->lock_ok ? "true" : "false");
        fprintf(f, "        \"root_squash_detected\": %s,\n", r->root_squash_detected ? "true" : "false");
        fprintf(f, "        \"estale_seen\": %s\n",         r->estale_seen ? "true" : "false");
        fprintf(f, "      },\n");
        fprintf(f, "      \"effective_mount_options\": \""); json_escape(f, r->effective_mount_opts); fprintf(f, "\",\n");
        fprintf(f, "      \"events\": [\n");
        int first_ev = 1;
        for (size_t e = 0; e < event_count; e++) {
            if (events[e].export_idx != (int)i) continue;
            if (!first_ev) fprintf(f, ",\n");
            fprintf(f, "        {\"check_id\": \"");
            json_escape(f, events[e].check_id);
            fprintf(f, "\", \"level\": \"");
            json_escape(f, events[e].level);
            fprintf(f, "\", \"category\": \"");
            json_escape(f, events[e].category);
            fprintf(f, "\", \"severity\": \"");
            json_escape(f, events[e].level);
            fprintf(f, "\", \"message\": \"");
            json_escape(f, events[e].message);
            fprintf(f, "\", \"remediation\": \"");
            json_escape(f, events[e].remediation);
            fprintf(f, "\"}");
            first_ev = 0;
        }
        if (!first_ev) fprintf(f, "\n");
        fprintf(f, "      ]\n");
        fprintf(f, "    }%s\n", i + 1 == export_report_count ? "" : ",");
    }
    fprintf(f, "  ],\n");
}

static FILE *open_saved_stdout_stream(void) {
    int dupfd = dup(saved_stdout_fd);
    if (dupfd < 0) return NULL;
    FILE *f = fdopen(dupfd, "w");
    if (!f) {
        int orphan = dupfd;
        close(orphan);
    }
    return f;
}

static void json_emit(FILE *f, const char *host) {
    time_t now = time(NULL);
    if (diagnostic_start == 0) diagnostic_start = now;
    char iso[64] = {0};
    struct tm tm_utc;
    if (gmtime_r(&now, &tm_utc))
        strftime(iso, sizeof(iso), "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
    fprintf(f, "{\n");
    fprintf(f, "  \"schema_version\": \"2.0\",\n");
    fprintf(f, "  \"tool\": \"nfsdiag\",\n");
    fprintf(f, "  \"mode\": \"%s\",\n", nfsdiag_mode);
    fprintf(f, "  \"version\": \"" NFSDIAG_VERSION "\",\n");
    fprintf(f, "  \"host\": \""); json_escape(f, host); fprintf(f, "\",\n");
    fprintf(f, "  \"timestamp\": %ld,\n", (long)now);
    fprintf(f, "  \"timestamp_iso8601\": \""); json_escape(f, iso); fprintf(f, "\",\n");
    fprintf(f, "  \"duration_sec\": %ld,\n", (long)(now - diagnostic_start));
    fprintf(f, "  \"summary\": {\"ok\": %d, \"warn\": %d, \"fail\": %d},\n",
            summary_ok, summary_warn, summary_fail);
    fprintf(f, "  \"options\": {\"timeout_sec\": %d, \"command_timeout_sec\": %d, "
            "\"fs_timeout_sec\": %d, \"stale_iterations\": %d, \"bench_bytes\": %zu, "
            "\"bench_iterations\": %d, \"krb5\": %s},\n",
            opt.timeout_sec, opt.command_timeout_sec, opt.fs_timeout_sec,
            opt.stale_iterations, opt.bench_bytes, opt.bench_iterations,
            opt.krb5 ? "true" : "false");

    json_write_system_info(f);
    if (export_report_count > 0) json_write_exports(f);

    fprintf(f, "  \"events\": [\n");
    int first = 1;
    for (size_t i = 0; i < event_count; i++) {
        if (events[i].export_idx != -1) continue;
        if (!first) fprintf(f, ",\n");
        fprintf(f, "    {\"check_id\": \"");
        json_escape(f, events[i].check_id);
        fprintf(f, "\", \"level\": \"");
        json_escape(f, events[i].level);
        fprintf(f, "\", \"category\": \"");
        json_escape(f, events[i].category);
        fprintf(f, "\", \"severity\": \"");
        json_escape(f, events[i].level);
        fprintf(f, "\", \"message\": \"");
        json_escape(f, events[i].message);
        fprintf(f, "\", \"remediation\": \"");
        json_escape(f, events[i].remediation);
        fprintf(f, "\"}");
        first = 0;
    }
    if (!first) fprintf(f, "\n");
    fprintf(f, "  ],\n");

    fprintf(f, "  \"recommendations\": [\n");
    for (size_t i = 0; i < recommendation_count; i++) {
        fprintf(f, "    \"");
        json_escape(f, recommendations[i]);
        fprintf(f, "\"%s\n", i + 1 == recommendation_count ? "" : ",");
    }
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
}

void write_json_report(const char *host) {
    if (!opt.json) return;
    FILE *f = NULL;
    if (opt.json_path && strcmp(opt.json_path, "-") != 0) {
        int fd = open(opt.json_path,
                      O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (fd < 0) {
            fprintf(stderr, "[ERROR] cannot open JSON report %s: %s\n",
                    opt.json_path, strerror(errno));
            return;
        }
        f = fdopen(fd, "w");
        /* fdopen() does not close the fd on failure */
        // cppcheck-suppress doubleFree
        if (!f) { close(fd); return; }
    } else if (saved_stdout_fd >= 0) {
        f = open_saved_stdout_stream();
        if (!f) return;
    } else {
        f = stdout;
    }

    json_emit(f, host);
    if (f != stdout) fclose(f);
}

/* Write the JSON report to an explicit path regardless of --json flags.
 * Used by --diff-baseline to persist the current run. */
int write_json_report_file(const char *host, const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return -1;
    FILE *f = fdopen(fd, "w");
    /* fdopen() does not close the fd on failure */
    // cppcheck-suppress doubleFree
    if (!f) { close(fd); return -1; }
    json_emit(f, host);
    fclose(f);
    return 0;
}

/* ---- HTML output ---- */

static void html_escape(FILE *f, const char *s) {
    for (; s && *s; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
            case '<': fputs("&lt;", f); break;
            case '>': fputs("&gt;", f); break;
            case '&': fputs("&amp;", f); break;
            case '"': fputs("&quot;", f); break;
            default:
                if (c < 32 && c != '\t' && c != '\n')
                    fprintf(f, "&#%u;", c);  /* escape control chars */
                else
                    fputc(c, f);
                break;
        }
    }
}

void write_html_report(const char *host) {
    if (!opt.html) return;
    FILE *f = NULL;
    if (opt.html_path && strcmp(opt.html_path, "-") != 0) {
        int fd = open(opt.html_path,
                      O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (fd < 0) {
            fprintf(stderr, "[ERROR] cannot open HTML report %s: %s\n",
                    opt.html_path, strerror(errno));
            return;
        }
        f = fdopen(fd, "w");
        /* fdopen() does not close the fd on failure */
        // cppcheck-suppress doubleFree
        if (!f) { close(fd); return; }
    } else if (saved_stdout_fd >= 0) {
        f = open_saved_stdout_stream();
        if (!f) return;
    } else {
        f = stdout;
    }

    fprintf(f, "<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"UTF-8\">\n<title>nfsdiag report - ");
    html_escape(f, host);
    fprintf(f, "</title>\n");
    fprintf(f, "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">\n");
    fprintf(f, "<style>\n");
    fprintf(f, "body { font-family: sans-serif; margin: 2em; background: #f9f9f9; color: #333; }\n");
    fprintf(f, "h1, h2, h3 { color: #222; }\n");
    fprintf(f, ".card { background: #fff; padding: 1em; margin-bottom: 1em; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }\n");
    fprintf(f, ".ok { color: #155724; background-color: #d4edda; border-color: #c3e6cb; padding: 0.5em; margin: 0.2em 0; border-radius: 3px; }\n");
    fprintf(f, ".warn { color: #856404; background-color: #fff3cd; border-color: #ffeeba; padding: 0.5em; margin: 0.2em 0; border-radius: 3px; }\n");
    fprintf(f, ".fail { color: #721c24; background-color: #f8d7da; border-color: #f5c6cb; padding: 0.5em; margin: 0.2em 0; border-radius: 3px; }\n");
    fprintf(f, ".info { color: #004085; background-color: #cce5ff; border-color: #b8daff; padding: 0.5em; margin: 0.2em 0; border-radius: 3px; }\n");
    fprintf(f, "table { width: 100%%; border-collapse: collapse; margin-top: 1em; }\n");
    fprintf(f, "th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n");
    fprintf(f, "th { background-color: #f2f2f2; }\n");
    fprintf(f, "</style>\n</head>\n<body>\n");

    fprintf(f, "<h1>nfsdiag report for "); html_escape(f, host); fprintf(f, "</h1>\n");

    struct system_info si;
    collect_system_info(&si);
    fprintf(f, "<div class='card'><h2>System Info</h2>");
    fprintf(f, "<p><strong>Kernel:</strong> "); html_escape(f, si.kernel); fprintf(f, "<br>");
    fprintf(f, "<strong>Hostname:</strong> "); html_escape(f, si.hostname); fprintf(f, "<br>");
    fprintf(f, "<strong>Arch:</strong> "); html_escape(f, si.arch); fprintf(f, "</p></div>\n");

    fprintf(f, "<div class='card'><h2>Summary</h2>");
    fprintf(f, "<p><strong>OK:</strong> %d | <strong>Warnings:</strong> %d | <strong>Failures:</strong> %d</p></div>\n",
            summary_ok, summary_warn, summary_fail);

    if (export_report_count > 0) {
        fprintf(f, "<div class='card'><h2>Exports</h2>\n");
        fprintf(f, "<table><thead><tr><th>Export</th><th>NFS</th><th>Write MiB/s</th><th>Read MiB/s</th><th>Metadata p95</th><th>Status</th></tr></thead><tbody>\n");
        for (size_t i = 0; i < export_report_count; i++) {
            const struct export_report *r = &export_reports[i];
            fprintf(f, "<tr><td>");
            html_escape(f, r->path);
            fprintf(f, "</td><td>");
            if (r->nfs_version == 4 && r->nfs_minor_version > 0)
                fprintf(f, "%d.%d", r->nfs_version, r->nfs_minor_version);
            else if (r->nfs_version > 0)
                fprintf(f, "%d", r->nfs_version);
            else
                fprintf(f, "-");
            fprintf(f, "</td><td>%.2f</td><td>%.2f</td><td>%.2fms</td><td>%s</td></tr>\n",
                    r->write_mib_s, r->read_mib_s, r->meta_p95_ms,
                    export_status(i, r->tested));
        }
        fprintf(f, "</tbody></table>\n");
        for (size_t i = 0; i < export_report_count; i++) {
            struct export_report *r = &export_reports[i];
            fprintf(f, "<details open><summary><strong>Export: ");
            html_escape(f, r->path);
            fprintf(f, "</strong></summary>\n");
            fprintf(f, "<ul>\n");
            if (r->nfs_version == 4 && r->nfs_minor_version > 0)
                fprintf(f, "<li>NFS Version: %d.%d</li>\n", r->nfs_version, r->nfs_minor_version);
            else
                fprintf(f, "<li>NFS Version: %d</li>\n", r->nfs_version);
            fprintf(f, "<li>Tested: %s</li>\n", r->tested ? "Yes" : "No");
            fprintf(f, "<li>Write Speed: %.2f MiB/s</li>\n", r->write_mib_s);
            fprintf(f, "<li>Read Speed: %.2f MiB/s</li>\n", r->read_mib_s);
            fprintf(f, "<li>Metadata (p50/p95/p99): %.2fms / %.2fms / %.2fms</li>\n",
                    r->meta_p50_ms, r->meta_p95_ms, r->meta_p99_ms);
            fprintf(f, "</ul>\n");
            fprintf(f, "<h4>Events</h4>\n");
            for (size_t e = 0; e < event_count; e++) {
                if (events[e].export_idx != (int)i) continue;
                /* Use data-level attribute; don't inject level directly into class */
                fprintf(f, "<div class='");
                if (strcmp(events[e].level, "ok")   == 0) fputs("ok",   f);
                else if (strcmp(events[e].level, "warn") == 0) fputs("warn", f);
                else if (strcmp(events[e].level, "fail") == 0) fputs("fail", f);
                else fputs("info", f);
                fprintf(f, "'><strong>[");
                html_escape(f, events[e].level);
                fprintf(f, "]</strong> <code>");
                html_escape(f, events[e].check_id);
                fprintf(f, "</code> <em>");
                html_escape(f, events[e].category);
                fprintf(f, "</em> ");
                html_escape(f, events[e].message);
                if (events[e].remediation[0]) {
                    fprintf(f, "<br><small>");
                    html_escape(f, events[e].remediation);
                    fprintf(f, "</small>");
                }
                fprintf(f, "</div>\n");
            }
            fprintf(f, "</details>\n");
        }
        fprintf(f, "</div>\n");
    }

    fprintf(f, "<div class='card'><h2>Global Events</h2>\n");
    for (size_t i = 0; i < event_count; i++) {
        if (events[i].export_idx != -1) continue;
        const char *cls = "info";
        if (strcmp(events[i].level, "ok")   == 0) cls = "ok";
        else if (strcmp(events[i].level, "warn") == 0) cls = "warn";
        else if (strcmp(events[i].level, "fail") == 0) cls = "fail";
        fprintf(f, "<div class='%s'><strong>[", cls);
        html_escape(f, events[i].level);
        fprintf(f, "]</strong> <code>");
        html_escape(f, events[i].check_id);
        fprintf(f, "</code> <em>");
        html_escape(f, events[i].category);
        fprintf(f, "</em> ");
        html_escape(f, events[i].message);
        if (events[i].remediation[0]) {
            fprintf(f, "<br><small>");
            html_escape(f, events[i].remediation);
            fprintf(f, "</small>");
        }
        fprintf(f, "</div>\n");
    }
    fprintf(f, "</div>\n");

    if (recommendation_count > 0) {
        fprintf(f, "<div class='card'><h2>Recommendations</h2><ul>\n");
        for (size_t i = 0; i < recommendation_count; i++) {
            fprintf(f, "<li>"); html_escape(f, recommendations[i]); fprintf(f, "</li>\n");
        }
        fprintf(f, "</ul></div>\n");
    }

    fprintf(f, "</body>\n</html>\n");
    if (f != stdout) fclose(f);
}

/* ---- Table output ---- */

void write_table_report(const char *host) {
    if (opt.output_fmt != OUTPUT_FMT_TABLE) return;
    if (opt.quiet) return;

    /* Box-drawing characters (UTF-8) */
    const char *TL = "\xe2\x95\x94", *TR = "\xe2\x95\x97";
    const char *BL = "\xe2\x95\x9a", *BR = "\xe2\x95\x9d";
    const char *HL = "\xe2\x95\x90", *VL = "\xe2\x95\x91";
    const char *TM = "\xe2\x95\xa6", *BM = "\xe2\x95\xa9";
    const char *LM = "\xe2\x95\xa0", *RM = "\xe2\x95\xa3";
    const char *MM = "\xe2\x95\xac";

    /* Column widths: export, nfs_ver, write, read, meta_p95, locks, status */
    const int cw[] = {32, 7, 10, 10, 10, 6, 8};
    int ncols = 7;
    int total_width = 0;
    for (int i = 0; i < ncols; i++) total_width += cw[i] + 3;
    total_width++;

    /* Build a divider line */
    printf("\n");
    printf("%s", TL);
    for (int i = 0; i < ncols; i++) {
        for (int j = 0; j < cw[i] + 2; j++) printf("%s", HL);
        printf("%s", i < ncols - 1 ? TM : TR);
    }
    printf("\n");

    /* Header row */
    const char *headers[] = {"Export", "NFS Ver", "Write MiB/s", "Read MiB/s", "Meta p95ms", "Locks", "Status"};
    printf("%s", VL);
    for (int i = 0; i < ncols; i++)
        printf(" %-*s %s", cw[i], headers[i], VL);
    printf("\n");

    /* Separator after header */
    printf("%s", LM);
    for (int i = 0; i < ncols; i++) {
        for (int j = 0; j < cw[i] + 2; j++) printf("%s", HL);
        printf("%s", i < ncols - 1 ? MM : RM);
    }
    printf("\n");

    /* Data rows */
    if (export_report_count == 0) {
        printf("%s %-*s %s\n", VL, total_width - 4, "(no exports tested)", VL);
    } else {
        for (size_t i = 0; i < export_report_count; i++) {
            struct export_report *r = &export_reports[i];
            char ver[16];
            if (r->nfs_version == 4 && r->nfs_minor_version > 0)
                snprintf(ver, sizeof(ver), "4.%d", r->nfs_minor_version);
            else if (r->nfs_version > 0)
                snprintf(ver, sizeof(ver), "%d", r->nfs_version);
            else
                snprintf(ver, sizeof(ver), "-");

            char wbuf[12], rbuf[12], mbuf[12];
            if (r->write_mib_s > 0) snprintf(wbuf, sizeof(wbuf), "%.1f", r->write_mib_s);
            else snprintf(wbuf, sizeof(wbuf), "-");
            if (r->read_mib_s > 0) snprintf(rbuf, sizeof(rbuf), "%.1f", r->read_mib_s);
            else snprintf(rbuf, sizeof(rbuf), "-");
            if (r->meta_p95_ms > 0) snprintf(mbuf, sizeof(mbuf), "%.1f", r->meta_p95_ms);
            else snprintf(mbuf, sizeof(mbuf), "-");

            const char *locks = r->lock_ok ? "OK" : (r->tested ? "FAIL" : "-");
            const char *status = export_status(i, r->tested);

            /* Truncate path to fit column width */
            char path_trunc[64];
            utf8_truncate(path_trunc, sizeof(path_trunc), r->path, 32);

            printf("%s", VL);
            printf(" %-*s %s", cw[0], path_trunc, VL);
            printf(" %-*s %s", cw[1], ver,    VL);
            printf(" %-*s %s", cw[2], wbuf,   VL);
            printf(" %-*s %s", cw[3], rbuf,   VL);
            printf(" %-*s %s", cw[4], mbuf,   VL);
            printf(" %-*s %s", cw[5], locks,  VL);
            printf(" %-*s %s", cw[6], status, VL);
            printf("\n");
        }
    }

    /* Bottom border */
    printf("%s", BL);
    for (int i = 0; i < ncols; i++) {
        for (int j = 0; j < cw[i] + 2; j++) printf("%s", HL);
        printf("%s", i < ncols - 1 ? BM : BR);
    }
    printf("\n");

    printf("Host: %s | ok=%d warn=%d fail=%d\n\n", host, summary_ok, summary_warn, summary_fail);

    if (recommendation_count > 0) {
        printf("Recommendations:\n");
        for (size_t i = 0; i < recommendation_count; i++)
            printf("  • %s\n", recommendations[i]);
        printf("\n");
    }
}

/* ---- Prometheus / OpenMetrics output ---- */

static void prom_label_escape(FILE *f, const char *s) {
    for (; s && *s; s++) {
        if (*s == '"' || *s == '\\' || *s == '\n') fputc('\\', f);
        fputc(*s, f);
    }
}

static void prometheus_emit(FILE *f, const char *host) {
    fprintf(f, "# HELP nfsdiag_summary_ok Number of ok checks\n");
    fprintf(f, "# TYPE nfsdiag_summary_ok gauge\n");
    fprintf(f, "nfsdiag_summary_ok{host=\""); prom_label_escape(f, host); fprintf(f, "\"} %d\n", summary_ok);

    fprintf(f, "# HELP nfsdiag_summary_warn Number of warning checks\n");
    fprintf(f, "# TYPE nfsdiag_summary_warn gauge\n");
    fprintf(f, "nfsdiag_summary_warn{host=\""); prom_label_escape(f, host); fprintf(f, "\"} %d\n", summary_warn);

    fprintf(f, "# HELP nfsdiag_summary_fail Number of failed checks\n");
    fprintf(f, "# TYPE nfsdiag_summary_fail gauge\n");
    fprintf(f, "nfsdiag_summary_fail{host=\""); prom_label_escape(f, host); fprintf(f, "\"} %d\n", summary_fail);

    /* Per-export metric families. Each # HELP/# TYPE pair must appear exactly
     * once per metric name (duplicates are rejected by the exposition format),
     * so emit the header once and then one sample line per tested export. */
    int any_tested = 0;
    for (size_t i = 0; i < export_report_count; i++)
        if (export_reports[i].tested) { any_tested = 1; break; }

    if (any_tested) {
        struct {
            const char *name;
            const char *help;
            int is_float;
        } metrics[] = {
            {"nfsdiag_export_write_mib_s",  "Write throughput MiB/s",          1},
            {"nfsdiag_export_read_mib_s",   "Read throughput MiB/s",           1},
            {"nfsdiag_export_meta_p95_ms",  "Metadata latency p95 in ms",      1},
            {"nfsdiag_export_lock_ok",      "Advisory lock test passed (1=yes)", 0},
            {"nfsdiag_export_estale",       "ESTALE seen during test loop (1=yes)", 0},
            {"nfsdiag_export_nfs_version",  "NFS major version negotiated",    0},
        };

        for (size_t m = 0; m < sizeof(metrics) / sizeof(metrics[0]); m++) {
            fprintf(f, "# HELP %s %s\n", metrics[m].name, metrics[m].help);
            fprintf(f, "# TYPE %s gauge\n", metrics[m].name);
            for (size_t i = 0; i < export_report_count; i++) {
                const struct export_report *r = &export_reports[i];
                if (!r->tested) continue;
                fprintf(f, "%s{host=\"", metrics[m].name);
                prom_label_escape(f, host);
                fprintf(f, "\",export=\"");
                prom_label_escape(f, r->path);
                if (metrics[m].is_float) {
                    double v = 0;
                    if (m == 0) v = r->write_mib_s;
                    else if (m == 1) v = r->read_mib_s;
                    else v = r->meta_p95_ms;
                    fprintf(f, "\"} %.3f\n", v);
                } else {
                    int v = 0;
                    if (m == 3) v = r->lock_ok;
                    else if (m == 4) v = r->estale_seen;
                    else v = r->nfs_version;
                    fprintf(f, "\"} %d\n", v);
                }
            }
        }
    }

    fprintf(f, "# EOF\n");
}

void write_prometheus_report(const char *host) {
    if (opt.output_fmt != OUTPUT_FMT_PROMETHEUS) return;
    if (opt.quiet) return;
    prometheus_emit(stdout, host);
}

/* Render the Prometheus exposition into a malloc'd buffer for --listen.
 * Caller frees. */
char *prometheus_snapshot(const char *host) {
    char *buf = NULL;
    size_t sz = 0;
    FILE *f = open_memstream(&buf, &sz);
    if (!f) return NULL;
    prometheus_emit(f, host);
    fclose(f);
    return buf;
}

/* ---- JUnit XML output (for CI pipelines) ---- */

static void xml_escape(FILE *f, const char *s) {
    for (; s && *s; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
            case '<':  fputs("&lt;", f);   break;
            case '>':  fputs("&gt;", f);   break;
            case '&':  fputs("&amp;", f);  break;
            case '"':  fputs("&quot;", f); break;
            default:
                /* control characters are invalid in XML 1.0; drop them */
                if (c >= 0x20 || c == '\t' || c == '\n')
                    fputc(c, f);
                else
                    fputc(' ', f);
                break;
        }
    }
}

void write_junit_report(const char *host) {
    if (opt.output_fmt != OUTPUT_FMT_JUNIT) return;
    if (opt.quiet) return;
    FILE *f = stdout;

    char iso[64] = {0};
    time_t now = time(NULL);
    struct tm tm_utc;
    if (gmtime_r(&now, &tm_utc))
        strftime(iso, sizeof(iso), "%Y-%m-%dT%H:%M:%S", &tm_utc);

    size_t failures = 0, skipped = 0;
    for (size_t i = 0; i < event_count; i++) {
        if (strcmp(events[i].level, "fail") == 0) failures++;
        else if (strcmp(events[i].level, "warn") == 0) skipped++;
    }

    fprintf(f, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    fprintf(f, "<testsuite name=\"nfsdiag\" hostname=\"");
    xml_escape(f, host);
    fprintf(f, "\" tests=\"%zu\" failures=\"%zu\" skipped=\"%zu\" errors=\"0\" timestamp=\"%s\">\n",
            event_count, failures, skipped, iso);

    for (size_t i = 0; i < event_count; i++) {
        fprintf(f, "  <testcase classname=\"nfsdiag.");
        xml_escape(f, events[i].category);
        fprintf(f, "\" name=\"");
        xml_escape(f, events[i].check_id);
        fprintf(f, ": ");
        xml_escape(f, events[i].message);
        fprintf(f, "\"");
        if (strcmp(events[i].level, "fail") == 0) {
            fprintf(f, ">\n    <failure message=\"");
            xml_escape(f, events[i].message);
            fprintf(f, "\">");
            xml_escape(f, events[i].remediation);
            fprintf(f, "</failure>\n  </testcase>\n");
        } else if (strcmp(events[i].level, "warn") == 0) {
            fprintf(f, ">\n    <skipped message=\"");
            xml_escape(f, events[i].message);
            fprintf(f, "\"/>\n  </testcase>\n");
        } else {
            fprintf(f, "/>\n");
        }
    }
    fprintf(f, "</testsuite>\n");
}

void report_banner(const char *host) {
    if (opt.quiet) return;
    if (opt.output_fmt != OUTPUT_FMT_TEXT && opt.output_fmt != OUTPUT_FMT_TABLE) return;
    printf("nfsdiag %s: %s\n", NFSDIAG_VERSION, host);
}

void report_summary_line(void) {
    if (opt.quiet) return;
    if (opt.output_fmt != OUTPUT_FMT_TEXT && opt.output_fmt != OUTPUT_FMT_TABLE) return;
    printf("summary: ok=%d warn=%d fail=%d\n", summary_ok, summary_warn, summary_fail);
}

void print_interpretation(void) {
    if (opt.quiet) return;
    if (opt.output_fmt != OUTPUT_FMT_TEXT) return;
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
        for (size_t i = 0; i < recommendation_count; i++)
            printf("- %s\n", recommendations[i]);
    }
}
