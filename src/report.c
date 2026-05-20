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
struct export_report export_reports[MAX_EXPORT_REPORTS];
size_t export_report_count = 0;

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
    events[event_count].export_idx = current_export_idx;
    event_count++;
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
    static int cached = -1;
    if (cached == -1) {
        cached = isatty(fileno(stdout)) ? 1 : 0;
    }
    return cached;
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
    if (!opt.quiet && (opt.verbose || important_ok_message(msg))) {
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
    if (!opt.quiet) {
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
    if (!opt.quiet) {
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
    if (!opt.quiet && opt.verbose) {
        if (use_colors()) printf("%s[INFO]%s %s\n", ANSI_BLUE, ANSI_RESET, msg);
        else printf("[INFO] %s\n", msg);
    }
}

void report_progress(int current, int total, const char *msg) {
    if (opt.quiet) return;
    if (!use_colors()) return; /* Only show progress bar on interactive TTY */
    if (opt.json && saved_stdout_fd >= 0) return; /* Don't mess JSON output */
    
    int percent = (total > 0) ? (current * 100 / total) : 100;
    printf("\r  [%3d%%] %s", percent, msg);
    fflush(stdout);
    if (current == total) printf("\n");
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

void enable_report_only_output(void) {
    /* Suppress stdout only when a report is written to stdout ("-") */
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
            fprintf(f, "        {\"level\": \"");
            json_escape(f, events[e].level);
            fprintf(f, "\", \"message\": \"");
            json_escape(f, events[e].message);
            fprintf(f, "\"}");
            first_ev = 0;
        }
        if (!first_ev) fprintf(f, "\n");
        fprintf(f, "      ]\n");
        fprintf(f, "    }%s\n", i + 1 == export_report_count ? "" : ",");
    }
    fprintf(f, "  ],\n");
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
        if (!f) { close(fd); return; }
    } else if (saved_stdout_fd >= 0) {
        int dupfd = dup(saved_stdout_fd);
        if (dupfd < 0) return;
        f = fdopen(dupfd, "w");
        if (!f) { close(dupfd); return; }
    } else {
        f = stdout;
    }

    time_t now = time(NULL);
    fprintf(f, "{\n");
    fprintf(f, "  \"tool\": \"nfsdiag\",\n");
    fprintf(f, "  \"host\": \""); json_escape(f, host); fprintf(f, "\",\n");
    fprintf(f, "  \"timestamp\": %ld,\n", (long)now);
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

    /* global events (export_idx == -1) */
    fprintf(f, "  \"events\": [\n");
    int first = 1;
    for (size_t i = 0; i < event_count; i++) {
        if (events[i].export_idx != -1) continue;
        if (!first) fprintf(f, ",\n");
        fprintf(f, "    {\"level\": \"");
        json_escape(f, events[i].level);
        fprintf(f, "\", \"message\": \"");
        json_escape(f, events[i].message);
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

    if (f != stdout) fclose(f);
}

static void html_escape(FILE *f, const char *s) {
    for (; s && *s; s++) {
        switch (*s) {
            case '<': fputs("&lt;", f); break;
            case '>': fputs("&gt;", f); break;
            case '&': fputs("&amp;", f); break;
            case '"': fputs("&quot;", f); break;
            default: fputc(*s, f); break;
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
        if (!f) { close(fd); return; }
    } else if (saved_stdout_fd >= 0) {
        int dupfd = dup(saved_stdout_fd);
        if (dupfd < 0) return;
        f = fdopen(dupfd, "w");
        if (!f) { close(dupfd); return; }
    } else {
        f = stdout;
    }

    fprintf(f, "<!DOCTYPE html>\n<html>\n<head>\n<title>nfsdiag report - ");
    html_escape(f, host);
    fprintf(f, "</title>\n");
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
    fprintf(f, "<p><strong>OK:</strong> %d | <strong>Warnings:</strong> %d | <strong>Failures:</strong> %d</p></div>\n", summary_ok, summary_warn, summary_fail);

    if (export_report_count > 0) {
        fprintf(f, "<div class='card'><h2>Exports</h2>\n");
        for (size_t i = 0; i < export_report_count; i++) {
            struct export_report *r = &export_reports[i];
            fprintf(f, "<h3>Export: "); html_escape(f, r->path); fprintf(f, "</h3>\n");
            fprintf(f, "<ul>\n");
            if (r->nfs_version == 4 && r->nfs_minor_version > 0)
                fprintf(f, "<li>NFS Version: %d.%d</li>\n", r->nfs_version, r->nfs_minor_version);
            else
                fprintf(f, "<li>NFS Version: %d</li>\n", r->nfs_version);
            fprintf(f, "<li>Tested: %s</li>\n", r->tested ? "Yes" : "No");
            fprintf(f, "<li>Write Speed: %.2f MiB/s</li>\n", r->write_mib_s);
            fprintf(f, "<li>Read Speed: %.2f MiB/s</li>\n", r->read_mib_s);
            fprintf(f, "<li>Metadata (p50/p95/p99): %.2fms / %.2fms / %.2fms</li>\n", r->meta_p50_ms, r->meta_p95_ms, r->meta_p99_ms);
            fprintf(f, "</ul>\n");
            fprintf(f, "<h4>Events</h4>\n");
            for (size_t e = 0; e < event_count; e++) {
                if (events[e].export_idx != (int)i) continue;
                fprintf(f, "<div class='%s'><strong>[%s]</strong> ", events[e].level, events[e].level);
                html_escape(f, events[e].message);
                fprintf(f, "</div>\n");
            }
        }
        fprintf(f, "</div>\n");
    }

    fprintf(f, "<div class='card'><h2>Global Events</h2>\n");
    for (size_t i = 0; i < event_count; i++) {
        if (events[i].export_idx != -1) continue;
        fprintf(f, "<div class='%s'><strong>[%s]</strong> ", events[i].level, events[i].level);
        html_escape(f, events[i].message);
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

void print_interpretation(void) {
    if (opt.quiet) return;
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
