#include "nfsdiag.h"

/* ---- globals owned by main.c ---- */

struct options opt = {
    .timeout_sec        = DEFAULT_TIMEOUT_SEC,
    .command_timeout_sec = DEFAULT_COMMAND_TIMEOUT_SEC,
    .fs_timeout_sec     = DEFAULT_FS_TIMEOUT_SEC,
    .stale_iterations   = DEFAULT_STALE_ITERATIONS,
    .bench_iterations   = DEFAULT_BENCH_ITERATIONS,
    .bench_bytes        = DEFAULT_BENCH_BYTES,
    .write_test         = 1,
    .nfs4_discovery     = 1,
    .address_family     = AF_UNSPEC,
    .output_fmt         = OUTPUT_FMT_TEXT,
};

volatile sig_atomic_t received_signal = 0;
char cleanup_base[4096];

static char output_dir_json_path[4096];
static char output_dir_html_path[4096];
static char output_dir_evidence_path[4096];
static char output_dir_checksums_path[4096];
static char sanitized_argv[4096];

/* ---- cleanup ---- */

static int unlink_cb(const char *fpath, const struct stat *sb, int typeflag,
                      struct FTW *ftwbuf) {
    (void)sb; (void)typeflag; (void)ftwbuf;
    size_t base_len = strlen(cleanup_base);
    if (base_len == 0 ||
        strncmp(fpath, cleanup_base, base_len) != 0 ||
        (fpath[base_len] != '\0' && fpath[base_len] != '/')) {
        const char msg[] = "[WARN] cleanup: refused path outside workspace\n";
        if (write(STDERR_FILENO, msg, sizeof(msg) - 1) < 0) { /* best effort */ }
        return 0;
    }
    /* Use write() instead of fprintf() so this is safe from atexit context
     * even when stdio may be in an inconsistent state after a signal. */
    if (remove(fpath) != 0 && errno != ENOENT) {
        const char msg[] = "[WARN] cleanup: remove failed\n";
        if (write(STDERR_FILENO, msg, sizeof(msg) - 1) < 0) { /* best effort */ }
    }
    return 0;
}

static void cleanup_temp_tree(void) {
    if (!cleanup_base[0] || opt.keep_temp) return;
    nftw(cleanup_base, unlink_cb, 32, FTW_DEPTH | FTW_PHYS);
    cleanup_base[0] = '\0';
}

static void cleanup_all(void) {
    static int cleaned_up = 0;
    if (cleaned_up) return;
    cleaned_up = 1;

    /* Block signals while cleaning up to prevent re-entry */
    sigset_t full, old;
    sigfillset(&full);
    sigprocmask(SIG_BLOCK, &full, &old);

    while (active_mountpoint_count > 0) {
        char mp[4096];
        snprintf(mp, sizeof(mp), "%s", active_mountpoints[active_mountpoint_count - 1]);
        (void)unmount_export(mp);
    }
    cleanup_temp_tree();

    if (saved_stdout_fd >= 0) {
        close(saved_stdout_fd);
        saved_stdout_fd = -1;
    }

    sigprocmask(SIG_SETMASK, &old, NULL);
}

static void signal_handler(int sig) { received_signal = sig; }

static void install_cleanup_handlers(void) {
    atexit(cleanup_all);
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    /* no SA_RESTART: blocking syscalls return EINTR on signal */
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP,  &sa, NULL);
}

/* ---- CLI helpers ---- */

static int parse_groups_arg(const char *s) {
    char *copy = strdup(s);
    if (!copy) return -1;
    char *save = NULL;
    for (const char *tok = strtok_r(copy, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        gid_t gid;
        if (parse_gid_arg(tok, &gid) != 0 || opt.supplemental_group_count >= MAX_SUPP_GROUPS) {
            free(copy);
            return -1;
        }
        opt.supplemental_groups[opt.supplemental_group_count++] = gid;
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
    struct passwd pwd;
    struct passwd *pw = NULL;
    char buf[4096];
    if (getpwuid_r(uid, &pwd, buf, sizeof(buf), &pw) == 0 && pw)
        return pw->pw_gid;
    return getgid();
}

/* ---- TMPDIR validation ---- */

static const char *validated_tmpdir(void) {
    const char *td = getenv("TMPDIR");
    if (!td || !td[0]) return "/tmp";
    struct stat st;
    if (lstat(td, &st) != 0) return "/tmp";
    if (!S_ISDIR(st.st_mode)) return "/tmp";
    if ((st.st_mode & S_IWOTH) && !(st.st_mode & S_ISVTX) && st.st_uid != geteuid())
        return "/tmp";
    return td;
}

static int validate_created_workspace(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return -1;
    if (!S_ISDIR(st.st_mode)) return -1;
    if (st.st_uid != geteuid()) return -1;
    if ((st.st_mode & 0777) != 0700)
        chmod(path, 0700);
    return 0;
}

/* ---- simple config-file parser ---- */

/* Owned copies of config-supplied string values. opt.* may point either here
 * (freeable) or at argv (not freeable), so ownership is tracked separately
 * and freed before each overwrite. */
static char *config_bench_type = NULL;
static char *config_output_dir = NULL;

static void load_config_file(const char *path) {
    /* The config can enable dangerous behaviour (dangerous-fs-tests,
     * allow-risky-mount-options), so refuse files that another local user
     * could have written. Open + fstat avoids a check-then-use race. */
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        fprintf(stderr, "[WARN] cannot open config file %s: %s\n", path, strerror(errno));
        return;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        fprintf(stderr, "[WARN] config file %s is not a regular file; ignoring\n", path);
        close(fd);
        return;
    }
    if (st.st_uid != 0 && st.st_uid != geteuid()) {
        fprintf(stderr, "[WARN] config file %s not owned by root or current user; ignoring\n", path);
        close(fd);
        return;
    }
    if (st.st_mode & (S_IWGRP | S_IWOTH)) {
        fprintf(stderr, "[WARN] config file %s is group/world-writable; ignoring\n", path);
        close(fd);
        return;
    }
    FILE *f = fdopen(fd, "r");
    if (!f) {
        /* fdopen() does not close the fd on failure */
        // cppcheck-suppress doubleFree
        close(fd);
        return;
    }
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        /* strip newline and leading whitespace */
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        size_t len = strlen(p);
        while (len > 0 && (p[len-1] == '\n' || p[len-1] == '\r' || p[len-1] == ' '))
            p[--len] = '\0';
        if (!*p || *p == '#') continue;
        /* key = value */
        char *eq = strchr(p, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = p;
        const char *val = eq + 1;
        while (*key == ' ' || *key == '\t') key++;
        char *kend = key + strlen(key) - 1;
        while (kend > key && (*kend == ' ' || *kend == '\t')) *kend-- = '\0';
        while (*val == ' ' || *val == '\t') val++;

        unsigned long num;
        if (strcmp(key, "timeout") == 0 && parse_ulong_arg(val, &num) == 0 && num > 0 && num <= 3600)
            opt.timeout_sec = (int)num;
        else if (strcmp(key, "command-timeout") == 0 && parse_ulong_arg(val, &num) == 0 && num > 0 && num <= 3600)
            opt.command_timeout_sec = (int)num;
        else if (strcmp(key, "fs-timeout") == 0 && parse_ulong_arg(val, &num) == 0 && num > 0 && num <= 3600)
            opt.fs_timeout_sec = (int)num;
        else if (strcmp(key, "bench-bytes") == 0 && parse_ulong_arg(val, &num) == 0 && num > 0 && num <= (1024UL*1024UL*1024UL))
            opt.bench_bytes = (size_t)num;
        else if (strcmp(key, "bench-iterations") == 0 && parse_ulong_arg(val, &num) == 0 && num <= 100000)
            opt.bench_iterations = (int)num;
        else if (strcmp(key, "stale-iterations") == 0 && parse_ulong_arg(val, &num) == 0 && num <= 1000000)
            opt.stale_iterations = (int)num;
        else if (strcmp(key, "delay-ms") == 0 && parse_ulong_arg(val, &num) == 0 && num <= 600000)
            opt.delay_ms = (int)num;
        else if (strcmp(key, "quiet") == 0 && strcmp(val, "true") == 0)
            opt.quiet = 1;
        else if (strcmp(key, "verbose") == 0 && strcmp(val, "true") == 0)
            opt.verbose = 1;
        else if (strcmp(key, "output-format") == 0) {
            if (strcmp(val, "table") == 0)      opt.output_fmt = OUTPUT_FMT_TABLE;
            else if (strcmp(val, "ndjson") == 0) opt.output_fmt = OUTPUT_FMT_NDJSON;
            else if (strcmp(val, "prometheus") == 0) opt.output_fmt = OUTPUT_FMT_PROMETHEUS;
        } else if (strcmp(key, "bench-type") == 0) {
            if (strcmp(val, "internal") == 0 || strcmp(val, "fio") == 0) {
                char *dup = strdup(val);
                if (dup) {
                    free(config_bench_type);
                    config_bench_type = dup;
                    opt.bench_type = config_bench_type;
                }
            }
        } else if (strcmp(key, "mount-namespace") == 0 && strcmp(val, "true") == 0)
            opt.mount_namespace = 1;
        else if (strcmp(key, "no-mount-namespace") == 0 && strcmp(val, "true") == 0)
            opt.no_mount_namespace = 1;
        else if (strcmp(key, "dangerous-fs-tests") == 0 && strcmp(val, "true") == 0)
            opt.dangerous_fs_tests = 1;
        else if (strcmp(key, "allow-risky-mount-options") == 0 && strcmp(val, "true") == 0)
            opt.allow_risky_mount_options = 1;
        else if (strcmp(key, "output-dir") == 0) {
            char *dup = strdup(val);
            if (dup) {
                free(config_output_dir);
                config_output_dir = dup;
                opt.output_dir = config_output_dir;
            }
        }
        else if (strcmp(key, "krb5") == 0 && strcmp(val, "true") == 0)
            opt.krb5 = 1;
        else if (strcmp(key, "no-nfs4-discovery") == 0 && strcmp(val, "true") == 0)
            opt.nfs4_discovery = 0;
        else if (strcmp(key, "watch") == 0 && parse_ulong_arg(val, &num) == 0 && num <= 86400)
            opt.watch_interval = (int)num;
        else if (strcmp(key, "sweep") == 0 && strcmp(val, "true") == 0)
            opt.sweep = 1;
        else if (strcmp(key, "parallel") == 0 && parse_ulong_arg(val, &num) == 0 && num >= 1 && num <= MAX_PARALLEL)
            opt.parallel = (int)num;
        else if (strcmp(key, "listen") == 0) {
            char reason[256];
            if (parse_listen_arg(val, opt.listen_addr, sizeof(opt.listen_addr),
                                 &opt.listen_port, reason, sizeof(reason)) != 0)
                fprintf(stderr, "[WARN] config: ignoring invalid listen value '%s' (%s)\n",
                        val, reason);
        }
        else if (strcmp(key, "diff-baseline") == 0 && strcmp(val, "true") == 0)
            opt.diff_baseline = 1;
        /* Unknown keys are silently ignored for forward-compatibility */
    }
    fclose(f);
}

static int apply_profile(const char *profile) {
    if (!profile) return 0;
    opt.profile = profile;
    if (strcmp(profile, "quick") == 0) {
        opt.no_mount = 1;
        opt.timeout_sec = 3;
        opt.command_timeout_sec = 5;
        opt.stale_iterations = 5;
        opt.bench_iterations = 1;
        opt.bench_bytes = 1024 * 1024;
    } else if (strcmp(profile, "safe") == 0 || strcmp(profile, "readonly") == 0) {
        opt.write_test = 0;
        opt.dangerous_fs_tests = 0;
        opt.stale_iterations = 10;
    } else if (strcmp(profile, "full") == 0) {
        opt.dangerous_fs_tests = 1;
        opt.stale_iterations = DEFAULT_STALE_ITERATIONS;
        opt.bench_iterations = DEFAULT_BENCH_ITERATIONS;
    } else if (strcmp(profile, "performance") == 0) {
        opt.bench_bytes = 64U * 1024U * 1024U;
        opt.bench_iterations = 50;
        opt.stale_iterations = 10;
        opt.sweep = 1;
    } else if (strcmp(profile, "security") == 0) {
        opt.krb5 = 1;
        opt.write_test = 0;
        opt.dangerous_fs_tests = 0;
        opt.mount_namespace = 1;
    } else {
        fprintf(stderr, "invalid --profile: %s (valid: quick, safe, full, performance, security, readonly)\n", profile);
        return -1;
    }
    return 0;
}

static void remember_argv(int argc, char **argv) {
    redact_argv(sanitized_argv, sizeof(sanitized_argv), argc, argv);
}

static int prepare_output_dir(const char *host) {
    if (!opt.output_dir) return 0;
    if (mkdir(opt.output_dir, 0700) != 0 && errno != EEXIST) {
        fprintf(stderr, "Error: cannot create output dir %s: %s\n", opt.output_dir, strerror(errno));
        return -1;
    }
    /* Open the directory and operate on the fd: a path-based lstat+chmod pair
     * could be raced by swapping the directory for a symlink in between. */
    int dfd = open(opt.output_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dfd < 0) {
        fprintf(stderr, "Error: output dir is not a directory: %s\n", opt.output_dir);
        return -1;
    }
    struct stat st;
    if (fstat(dfd, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "Error: output dir is not a directory: %s\n", opt.output_dir);
        close(dfd);
        return -1;
    }
    if ((st.st_mode & 0777) & 0077)
        fchmod(dfd, 0700);
    close(dfd);

    char host_clean[256];
    size_t j = 0;
    for (const unsigned char *p = (const unsigned char *)host; *p && j + 1 < sizeof(host_clean); p++)
        host_clean[j++] = ((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
                           (*p >= '0' && *p <= '9') || *p == '.' || *p == '-' || *p == '_') ? (char)*p : '_';
    host_clean[j] = '\0';
    if (!host_clean[0]) snprintf(host_clean, sizeof(host_clean), "host");

    snprintf(output_dir_json_path, sizeof(output_dir_json_path), "%s/%s.json", opt.output_dir, host_clean);
    snprintf(output_dir_html_path, sizeof(output_dir_html_path), "%s/%s.html", opt.output_dir, host_clean);
    snprintf(output_dir_evidence_path, sizeof(output_dir_evidence_path), "%s/%s.evidence.txt", opt.output_dir, host_clean);
    snprintf(output_dir_checksums_path, sizeof(output_dir_checksums_path), "%s/SHA256SUMS", opt.output_dir);
    opt.json = 1;
    opt.html = 1;
    opt.json_path = output_dir_json_path;
    opt.html_path = output_dir_html_path;
    return 0;
}

/* Open an output file for writing without following symlinks and with
 * private permissions; required when running as root in shared directories. */
static FILE *fopen_private(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return NULL;
    FILE *f = fdopen(fd, "w");
    /* fdopen() does not close the fd on failure */
    // cppcheck-suppress doubleFree
    if (!f) close(fd);
    return f;
}

static void write_output_dir_evidence(const char *host) {
    if (!opt.output_dir) return;
    FILE *f = fopen_private(output_dir_evidence_path);
    if (!f) return;
    struct system_info si;
    collect_system_info(&si);
    fprintf(f, "tool=nfsdiag\nversion=%s\nhost=%s\nargv=%s\n", NFSDIAG_VERSION, host, sanitized_argv);
    fprintf(f, "kernel=%s\nhostname=%s\narch=%s\n", si.kernel, si.hostname, si.arch);
    fprintf(f, "summary_ok=%d\nsummary_warn=%d\nsummary_fail=%d\n", summary_ok, summary_warn, summary_fail);
    fprintf(f, "options=no_mount:%d write_test:%d timeout:%d command_timeout:%d fs_timeout:%d stale:%d bench_bytes:%zu profile:%s\n",
            opt.no_mount, opt.write_test, opt.timeout_sec, opt.command_timeout_sec,
            opt.fs_timeout_sec, opt.stale_iterations, opt.bench_bytes,
            opt.profile ? opt.profile : "");
    fclose(f);

    char output[CMD_OUTPUT_LIMIT];
    char *argv[] = {"sha256sum", output_dir_json_path, output_dir_html_path,
                    output_dir_evidence_path, NULL};
    if (run_command_capture(argv, output, sizeof(output)) == 0) {
        FILE *cf = fopen_private(output_dir_checksums_path);
        if (cf) {
            fputs(output, cf);
            fclose(cf);
        }
    }
}

static int extract_summary_value(const char *path, const char *key, long *out) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    /* Read the whole report: a fixed buffer silently truncated large reports
     * and made the summary unfindable. 64 MiB sanity cap. */
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long sz = ftell(f);
    if (sz < 0 || sz > (64L << 20)) { fclose(f); return -1; }
    rewind(f);
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return -1; }
    size_t n = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[n] = '\0';

    int rc = -1;
    /* Anchor the search inside the "summary" object so a key like "ok"
     * cannot be matched against event payloads elsewhere in the report. */
    const char *sum = strstr(buf, "\"summary\"");
    const char *obj_start = sum ? strchr(sum, '{') : NULL;
    const char *obj_end = obj_start ? strchr(obj_start, '}') : NULL;
    if (obj_end) {
        char needle[64];
        snprintf(needle, sizeof(needle), "\"%s\"", key);
        const char *p = strstr(obj_start, needle);
        if (p && p < obj_end) {
            p = strchr(p, ':');
            if (p && p < obj_end) {
                *out = strtol(p + 1, NULL, 10);
                rc = 0;
            }
        }
    }
    free(buf);
    return rc;
}

static int diff_reports(const char *a, const char *b) {
    long a_ok = 0, a_warn = 0, a_fail = 0, b_ok = 0, b_warn = 0, b_fail = 0;
    if (extract_summary_value(a, "ok", &a_ok) != 0 ||
        extract_summary_value(a, "warn", &a_warn) != 0 ||
        extract_summary_value(a, "fail", &a_fail) != 0 ||
        extract_summary_value(b, "ok", &b_ok) != 0 ||
        extract_summary_value(b, "warn", &b_warn) != 0 ||
        extract_summary_value(b, "fail", &b_fail) != 0) {
        fprintf(stderr, "Error: could not parse summary from both reports\n");
        return 2;
    }
    printf("nfsdiag diff\n");
    printf("ok:   %ld -> %ld (%+ld)\n", a_ok, b_ok, b_ok - a_ok);
    printf("warn: %ld -> %ld (%+ld)\n", a_warn, b_warn, b_warn - a_warn);
    printf("fail: %ld -> %ld (%+ld)\n", a_fail, b_fail, b_fail - a_fail);
    return (b_fail > a_fail || b_warn > a_warn) ? 1 : 0;
}

static int run_self_test(void) {
    char reason[256];
    int ok = 1;
    if (validate_host_arg("127.0.0.1", reason, sizeof(reason)) != 0) {
        fprintf(stderr, "self-test: host validation failed: %s\n", reason); ok = 0;
    }
    if (validate_export_path("/export", reason, sizeof(reason)) != 0) {
        fprintf(stderr, "self-test: export validation failed: %s\n", reason); ok = 0;
    }
    if (validate_mount_options("hard,timeo=30,retrans=2", 0, reason, sizeof(reason)) != 0) {
        fprintf(stderr, "self-test: mount option validation failed: %s\n", reason); ok = 0;
    }
    if (!check_dependencies()) ok = 0;
    printf("self-test %s\n", ok ? "passed" : "failed");
    return ok ? 0 : 2;
}

static void usage(const char *p) {
    printf("Usage: %s [OPTIONS] <server-ip-or-hostname>\n", p);
    printf("       %s diff <before.json> <after.json>   Compare two JSON reports\n", p);
    printf("\nDiagnostic options:\n");
    printf("  -e, --export PATH          Test only this export path (repeatable, up to %d)\n", MAX_CLI_EXPORTS);
    printf("  -o, --mount-options OPTS   Extra mount options passed to mount(8)\n");
    printf("      --no-mount             Run network/RPC checks only; skip all mounts\n");
    printf("      --dry-run              Print what would be done; skip mounts and fs tests\n");
    printf("      --read-only            Do not create or write test files\n");
    printf("      --uid UID              Simulate access as UID (repeatable, needs root)\n");
    printf("      --gid GID              GID paired with last --uid\n");
    printf("      --groups G1,G2         Supplemental GIDs for UID/GID simulation\n");
    printf("      --krb5                 Check Kerberos prerequisites and test sec=krb5/krb5i/krb5p mounts\n");
    printf("      --parallel N           Test up to N exports concurrently (1-%d). Default: 1\n", MAX_PARALLEL);
    printf("      --sweep                Benchmark rsize/wsize/nconnect combos and suggest mount options\n");
    printf("      --diff-baseline        Compare with the last saved run for this host, then update it\n");
    printf("      --udp                  Also probe RPC NULLPROC over UDP\n");
    printf("      --ipv4-only            Force IPv4 for direct TCP checks\n");
    printf("      --ipv6-only            Force IPv6 for direct TCP checks\n");
    printf("      --no-nfs4-discovery    Disable NFSv4 pseudo-root fallback\n");
    printf("      --mount-namespace      Use private mount namespace (needs root/CAP_SYS_ADMIN)\n");
    printf("      --no-mount-namespace   Disable automatic private mount namespace\n");
    printf("      --dangerous-fs-tests   Enable symlink/hardlink/FIFO/device-node probes (alias: --deep)\n");
    printf("      --allow-risky-mount-options\n");
    printf("                              Permit risky mount options such as exec/suid/dev\n");
    printf("                              and skip the default nosuid,nodev,noexec hardening\n");
    printf("      --profile NAME         quick, safe, full, performance, security, readonly\n");
    printf("      --hosts-file FILE      Read one host per line from FILE; run diagnostics for each\n");
    printf("      --watch SEC            Re-run diagnostics every SEC seconds until interrupted\n");
    printf("      --on-fail-exec SCRIPT  Execute SCRIPT when any test fails (env: NFSDIAG_HOST, NFSDIAG_LEVEL)\n");
    printf("      --config FILE          Load options from FILE (key=value, one per line)\n");
    printf("\nTimeout options:\n");
    printf("      --timeout SEC          Network/RPC connect timeout. Default: %d\n", DEFAULT_TIMEOUT_SEC);
    printf("      --command-timeout SEC  Timeout for mount/umount commands. Default: %d\n", DEFAULT_COMMAND_TIMEOUT_SEC);
    printf("      --fs-timeout SEC       Timeout for each filesystem test group. Default: %d\n", DEFAULT_FS_TIMEOUT_SEC);
    printf("      --delay-ms MS          Delay between testing each export (rate limit). Default: 0\n");
    printf("\nBenchmark options:\n");
    printf("      --bench-bytes BYTES    Bytes for read/write benchmark (1..1 GiB). Default: %u\n", DEFAULT_BENCH_BYTES);
    printf("      --bench-iterations N   Metadata latency iterations (0 disables). Default: %d\n", DEFAULT_BENCH_ITERATIONS);
    printf("      --bench-type TYPE      Benchmark engine: 'internal' or 'fio'. Default: internal\n");
    printf("      --stale-iterations N   ESTALE probe loop iterations (0 disables). Default: %d\n", DEFAULT_STALE_ITERATIONS);
    printf("\nOutput options:\n");
    printf("      --json[=PATH]          Emit JSON report to PATH (use '-' or omit for stdout)\n");
    printf("      --html[=PATH]          Emit HTML report to PATH (use '-' or omit for stdout)\n");
    printf("      --output-dir DIR       Write JSON, HTML, evidence and checksums to DIR\n");
    printf("      --output-format FMT    Terminal output: text (default), table, ndjson, prometheus, junit\n");
    printf("      --listen [ADDR:]PORT   Serve Prometheus metrics over HTTP; binds 127.0.0.1\n");
    printf("                              unless ADDR is given ([V6ADDR]:PORT for IPv6);\n");
    printf("                              re-runs diagnostics every --watch SEC (default 60)\n");
    printf("      --keep-temp            Keep temp workspace after tests\n");
    printf("  -v, --verbose              Show all diagnostic steps\n");
    printf("  -q, --quiet                Suppress human stdout (banner, checks, summary) in all formats\n");
    printf("  -V, --version              Print version and exit\n");
    printf("      --self-test            Validate local dependencies and pure helper checks\n");
    printf("  -h, --help                 Show this help\n");
    printf("\nExit codes: 0=pass  1=warn/fail  2=usage/runtime error\n");
    printf("Human stdout prints only for text/table formats; machine formats and --json=-/--html=-\n");
    printf("  emit only the structured document. --quiet removes human stdout in every case.\n");
}

/* ---- on-fail-exec hook ---- */

static void run_on_fail_exec(const char *host) {
    if (!opt.on_fail_exec || summary_fail == 0) return;
    /* Resolve and validate the script before forking: it runs with our
     * privileges (often root), so refuse scripts that another local user
     * could have replaced or modified. */
    char resolved[4096];
    if (resolve_command_path(opt.on_fail_exec, resolved, sizeof(resolved)) != 0) {
        fprintf(stderr, "[WARN] --on-fail-exec: cannot resolve %s\n", opt.on_fail_exec);
        return;
    }
    struct stat st;
    if (stat(resolved, &st) != 0 || !S_ISREG(st.st_mode)) {
        fprintf(stderr, "[WARN] --on-fail-exec: %s is not a regular file\n", resolved);
        return;
    }
    if (st.st_uid != 0 && st.st_uid != geteuid()) {
        fprintf(stderr, "[WARN] --on-fail-exec: refusing %s (not owned by root or current user)\n", resolved);
        return;
    }
    if (st.st_mode & (S_IWGRP | S_IWOTH)) {
        fprintf(stderr, "[WARN] --on-fail-exec: refusing %s (group/world-writable)\n", resolved);
        return;
    }
    /* Use execve in a child; never sh -c */
    pid_t pid = fork();
    if (pid < 0) return;
    if (pid == 0) {
        /* Set env vars describing the failure */
        setenv("NFSDIAG_HOST", host, 1);
        setenv("NFSDIAG_LEVEL", "fail", 1);
        char buf[32];
        snprintf(buf, sizeof(buf), "%d", summary_fail);
        setenv("NFSDIAG_FAIL_COUNT", buf, 1);
        snprintf(buf, sizeof(buf), "%d", summary_warn);
        setenv("NFSDIAG_WARN_COUNT", buf, 1);
        char env_host[512], env_fail[64], env_warn[64];
        snprintf(env_host, sizeof(env_host), "NFSDIAG_HOST=%s", host);
        snprintf(env_fail, sizeof(env_fail), "NFSDIAG_FAIL_COUNT=%d", summary_fail);
        snprintf(env_warn, sizeof(env_warn), "NFSDIAG_WARN_COUNT=%d", summary_warn);
        char *safe_env[] = {
            "PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin",
            "LANG=C",
            "LC_ALL=C",
            "NFSDIAG_LEVEL=fail",
            env_host,
            env_fail,
            env_warn,
            NULL
        };
        char *argv[] = {(char *)opt.on_fail_exec, NULL};
        execve(resolved, argv, safe_env);
        _exit(127);
    }
    int status;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
}

/* ---- per-export test body (shared by sequential and parallel paths) ---- */

/* Returns 1 when the unmount failed and the mountpoint was left in place. */
static int test_one_export(const char *host, const struct export_item *exp,
                           size_t idx, const char *mp) {
    if (idx < MAX_EXPORT_REPORTS) {
        struct export_report *rpt = &export_reports[idx];
        memset(rpt, 0, sizeof(*rpt));
        snprintf(rpt->path, sizeof(rpt->path), "%s", exp->path);
    }

    if (opt.verbose) printf("\n[+] Mount test for export %s\n", exp->path);
    struct mount_result mr;
    if (mount_export(host, exp->path, mp, &mr) != 0)
        return 0;
    if (idx < MAX_EXPORT_REPORTS) {
        export_reports[idx].nfs_version = mr.version;
        export_reports[idx].nfs_minor_version = mr.nfs_minor_version;
        export_reports[idx].tested = !opt.dry_run;
    }
    if (!opt.dry_run && idx < MAX_EXPORT_REPORTS) {
        diagnose_mounted_export(exp->path, mp, (int)idx, mr.version,
                                mr.nfs_minor_version);
        if (unmount_export(mp) != 0) {
            report_warn("leaving mountpoint in place for safety: %s", mp);
            return 1;
        }
    }
    return 0;
}

/* ---- parallel export workers (--parallel N) ----
 * Each worker forks, runs the full per-export diagnostics with stdout
 * suppressed, and streams its events/recommendations/report struct back over
 * a pipe; the parent replays them so summaries, reports, and output formats
 * behave exactly as in sequential mode. */

struct par_result_hdr {
    struct export_report rpt;
    int    have_rpt;
    int    unmount_failed;
    size_t n_events;
    size_t n_recs;
};

struct par_event_hdr {
    int    export_idx;
    size_t level_len;
    size_t msg_len;
};

static int write_full(int fd, const void *buf, size_t len) {
    const char *p = buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static int read_full(int fd, void *buf, size_t len) {
    char *p = buf;
    while (len > 0) {
        ssize_t n = read(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static void parallel_child(int wfd, const char *host,
                           const struct export_item *exp, size_t idx,
                           const char *mp) {
    /* The parent replays our events; suppress all direct output here. */
    opt.quiet = 1;
    opt.verbose = 0;
    opt.output_fmt = OUTPUT_FMT_TEXT;
    /* Never let this child's exit path touch the shared workspace or the
     * mountpoints of sibling workers. */
    cleanup_base[0] = '\0';
    active_mountpoint_count = 0;

    size_t ev0 = event_count, rec0 = recommendation_count;
    int unfail = test_one_export(host, exp, idx, mp);

    struct par_result_hdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    if (idx < MAX_EXPORT_REPORTS) {
        hdr.rpt = export_reports[idx];
        hdr.have_rpt = 1;
    }
    hdr.unmount_failed = unfail;
    hdr.n_events = event_count - ev0;
    hdr.n_recs = recommendation_count - rec0;
    if (write_full(wfd, &hdr, sizeof(hdr)) != 0) _exit(1);

    for (size_t e = ev0; e < event_count; e++) {
        struct par_event_hdr eh = {
            events[e].export_idx,
            strlen(events[e].level),
            strlen(events[e].message)
        };
        if (write_full(wfd, &eh, sizeof(eh)) != 0 ||
            write_full(wfd, events[e].level, eh.level_len) != 0 ||
            write_full(wfd, events[e].message, eh.msg_len) != 0)
            _exit(1);
    }
    for (size_t r = rec0; r < recommendation_count; r++) {
        size_t len = strlen(recommendations[r]);
        if (write_full(wfd, &len, sizeof(len)) != 0 ||
            write_full(wfd, recommendations[r], len) != 0)
            _exit(1);
    }
    close(wfd);
    _exit(0);
}

static void replay_event(int export_idx, const char *level, const char *msg) {
    int saved = current_export_idx;
    current_export_idx = export_idx;
    if (strcmp(level, "ok") == 0)        report_ok("%s", msg);
    else if (strcmp(level, "warn") == 0) report_warn("%s", msg);
    else if (strcmp(level, "fail") == 0) report_fail("%s", msg);
    else                                 report_info("%s", msg);
    current_export_idx = saved;
}

/* Returns the worker's unmount_failed flag, or -1 on a protocol error. */
static int merge_parallel_result(int fd, size_t idx) {
    struct par_result_hdr hdr;
    if (read_full(fd, &hdr, sizeof(hdr)) != 0) return -1;
    if (hdr.n_events > MAX_EVENTS || hdr.n_recs > MAX_RECOMMENDATIONS) return -1;
    if (hdr.have_rpt && idx < MAX_EXPORT_REPORTS)
        export_reports[idx] = hdr.rpt;

    for (size_t e = 0; e < hdr.n_events; e++) {
        struct par_event_hdr eh;
        char level[16], msg[4096];
        if (read_full(fd, &eh, sizeof(eh)) != 0) return -1;
        if (eh.level_len >= sizeof(level) || eh.msg_len >= sizeof(msg)) return -1;
        if (read_full(fd, level, eh.level_len) != 0) return -1;
        level[eh.level_len] = '\0';
        if (read_full(fd, msg, eh.msg_len) != 0) return -1;
        msg[eh.msg_len] = '\0';
        replay_event(eh.export_idx, level, msg);
    }
    for (size_t r = 0; r < hdr.n_recs; r++) {
        size_t len = 0;
        char rec[2048];
        if (read_full(fd, &len, sizeof(len)) != 0) return -1;
        if (len >= sizeof(rec)) return -1;
        if (read_full(fd, rec, len) != 0) return -1;
        rec[len] = '\0';
        add_recommendation("%s", rec);
    }
    return hdr.unmount_failed;
}

/* Headroom over the per-operation timeouts the child enforces itself, so the
 * watchdog only fires when a child is genuinely wedged (e.g. a hard NFS mount
 * that does not honour its own alarm). */
static int worker_deadline_sec(void) {
    long d = (long)opt.command_timeout_sec + opt.fs_timeout_sec + opt.timeout_sec + 30;
    if (opt.bench_iterations > 0) d += opt.fs_timeout_sec;
    if (d > 86400) d = 86400;
    return (int)d;
}

/* Wait until the worker's pipe has data or the deadline elapses. Returns 0 if
 * readable (the child finished the risky mount phase before writing), -1 on
 * timeout or interruption so the caller can kill a hung worker. */
static int wait_worker_ready(int fd, int deadline_sec) {
    struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
    time_t end = time(NULL) + deadline_sec;
    for (;;) {
        long remaining = (long)(end - time(NULL));
        if (remaining < 0) remaining = 0;
        int rc = poll(&pfd, 1, (int)(remaining * 1000));
        if (rc > 0) return 0;
        if (rc == 0) return -1;
        if (errno == EINTR) {
            if (received_signal) return -1;
            continue;
        }
        return -1;
    }
}

/* Run one export's diagnostics in a killable child so a wedged hard mount
 * cannot pin the main process. Returns 1 if the mountpoint must be kept
 * (unmount failed, worker killed, or no result), else 0. */
static int run_export_isolated(const char *host, const struct export_item *exp,
                               size_t idx, const char *mp) {
    int pfd[2];
    if (pipe(pfd) != 0) {
        report_fail("pipe failed for export worker: %s", strerror(errno));
        return 0;
    }
    register_mountpoint(mp);
    pid_t pid = fork();
    if (pid < 0) {
        close(pfd[0]);
        close(pfd[1]);
        unregister_mountpoint(mp);
        report_fail("fork failed for export worker: %s", strerror(errno));
        return 0;
    }
    if (pid == 0) {
        close(pfd[0]);
        parallel_child(pfd[1], host, exp, idx, mp);
        _exit(1);
    }
    close(pfd[1]);

    int deadline = worker_deadline_sec();
    int killed = wait_worker_ready(pfd[0], deadline) != 0;
    if (killed) kill(pid, SIGKILL);
    int unfail = killed ? -1 : merge_parallel_result(pfd[0], idx);
    close(pfd[0]);
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}

    if (killed) {
        report_fail("export %s exceeded the %ds worker deadline; killed a possibly hung mount",
                    exp->path, deadline);
        return 1;
    }
    if (unfail < 0) {
        report_warn("export worker for %s returned no result; mountpoint kept for cleanup",
                    exp->path);
        return 1;
    }
    if (unfail > 0) return 1;
    unregister_mountpoint(mp);
    return 0;
}

static void run_exports_parallel(const char *host, const struct export_list *ex) {
    struct worker {
        pid_t  pid;
        int    fd;
        size_t idx;
        char   mp[4096];
    } w[MAX_PARALLEL];

    size_t nworkers = (size_t)opt.parallel;
    if (nworkers > MAX_PARALLEL) nworkers = MAX_PARALLEL;
    report_info("testing %zu export(s) with up to %zu parallel workers",
                ex->count, nworkers);

    size_t i = 0;
    while (i < ex->count && !received_signal) {
        size_t batch = ex->count - i < nworkers ? ex->count - i : nworkers;
        size_t launched = 0;

        for (size_t b = 0; b < batch; b++) {
            size_t list_idx = i + b;
            char mp[4096];
            int mpn = snprintf(mp, sizeof(mp), "%s/export-%zu", cleanup_base,
                               list_idx + 1);
            if (mpn < 0 || (size_t)mpn >= sizeof(mp)) {
                report_fail("mountpoint path would be too long for export %zu",
                            list_idx + 1);
                continue;
            }
            if (make_dir(mp, 0700) != 0) {
                report_fail("cannot create mountpoint %s: %s", mp, strerror(errno));
                continue;
            }

            size_t idx = export_report_count;
            if (export_report_count < MAX_EXPORT_REPORTS) {
                struct export_report *rpt = &export_reports[idx];
                memset(rpt, 0, sizeof(*rpt));
                snprintf(rpt->path, sizeof(rpt->path), "%s",
                         ex->items[list_idx].path);
                export_report_count++;
            }

            int pfd[2];
            if (pipe(pfd) != 0) {
                report_fail("pipe failed for parallel worker: %s", strerror(errno));
                continue;
            }
            register_mountpoint(mp);
            pid_t pid = fork();
            if (pid < 0) {
                close(pfd[0]);
                close(pfd[1]);
                unregister_mountpoint(mp);
                report_fail("fork failed for parallel worker: %s", strerror(errno));
                continue;
            }
            if (pid == 0) {
                close(pfd[0]);
                parallel_child(pfd[1], host, &ex->items[list_idx], idx, mp);
                _exit(1); /* not reached */
            }
            close(pfd[1]);
            w[launched].pid = pid;
            w[launched].fd = pfd[0];
            w[launched].idx = idx;
            snprintf(w[launched].mp, sizeof(w[launched].mp), "%s", mp);
            launched++;

            if (opt.delay_ms > 0 && b + 1 < batch) {
                struct timespec delay = {
                    .tv_sec = opt.delay_ms / 1000,
                    .tv_nsec = (long)(opt.delay_ms % 1000) * 1000000L
                };
                nanosleep(&delay, NULL);
            }
        }

        int deadline = worker_deadline_sec();
        for (size_t k = 0; k < launched; k++) {
            int killed = wait_worker_ready(w[k].fd, deadline) != 0;
            if (killed) kill(w[k].pid, SIGKILL);
            int unfail = killed ? -1 : merge_parallel_result(w[k].fd, w[k].idx);
            close(w[k].fd);
            int status = 0;
            while (waitpid(w[k].pid, &status, 0) < 0 && errno == EINTR) {}
            if (killed) {
                report_fail("parallel export worker %zu exceeded the %ds deadline; "
                            "killed a possibly hung mount", w[k].idx + 1, deadline);
                opt.keep_temp = 1;
            } else if (unfail < 0) {
                report_warn("parallel worker for export %zu returned no result; "
                            "its mountpoint stays registered for cleanup", w[k].idx + 1);
                opt.keep_temp = 1;
            } else if (unfail > 0) {
                opt.keep_temp = 1; /* mountpoint stays registered */
            } else {
                unregister_mountpoint(w[k].mp);
            }
        }
        i += batch;
    }
}

/* ---- baseline history (--diff-baseline) ---- */

static void sanitize_host_filename(const char *host, char *out, size_t out_sz) {
    size_t j = 0;
    for (const unsigned char *p = (const unsigned char *)host;
         *p && j + 1 < out_sz; p++)
        out[j++] = ((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
                    (*p >= '0' && *p <= '9') || *p == '.' || *p == '-' ||
                    *p == '_') ? (char)*p : '_';
    out[j] = '\0';
    if (!out[0]) snprintf(out, out_sz, "host");
}

static void handle_diff_baseline(const char *host) {
    if (!opt.diff_baseline) return;

    char dir[4096];
    const char *data_home = getenv("XDG_DATA_HOME");
    if (data_home && data_home[0]) {
        snprintf(dir, sizeof(dir), "%s/nfsdiag", data_home);
        (void)mkdir(dir, 0700);
    } else {
        const char *home = getenv("HOME");
        if (!home || !home[0]) {
            fprintf(stderr, "[WARN] --diff-baseline: HOME not set; skipping baseline\n");
            return;
        }
        char parent[4096];
        snprintf(parent, sizeof(parent), "%s/.local", home);
        (void)mkdir(parent, 0700);
        snprintf(parent, sizeof(parent), "%s/.local/share", home);
        (void)mkdir(parent, 0700);
        snprintf(dir, sizeof(dir), "%s/.local/share/nfsdiag", home);
        (void)mkdir(dir, 0700);
    }

    char host_clean[256];
    sanitize_host_filename(host, host_clean, sizeof(host_clean));
    char path[4096];
    int n = snprintf(path, sizeof(path), "%s/%s.baseline.json", dir, host_clean);
    if (n < 0 || (size_t)n >= sizeof(path)) return;

    struct stat st;
    if (stat(path, &st) == 0) {
        long b_ok = 0, b_warn = 0, b_fail = 0;
        if (extract_summary_value(path, "ok", &b_ok) == 0 &&
            extract_summary_value(path, "warn", &b_warn) == 0 &&
            extract_summary_value(path, "fail", &b_fail) == 0) {
            printf("\n[BASELINE] previous: ok=%ld warn=%ld fail=%ld | "
                   "current: ok=%d warn=%d fail=%d (%+ld ok, %+ld warn, %+ld fail)\n",
                   b_ok, b_warn, b_fail, summary_ok, summary_warn, summary_fail,
                   (long)summary_ok - b_ok, (long)summary_warn - b_warn,
                   (long)summary_fail - b_fail);
            if (summary_fail > b_fail || summary_warn > b_warn)
                printf("[BASELINE] regression detected compared with the previous run\n");
        } else {
            fprintf(stderr, "[WARN] --diff-baseline: could not parse previous baseline %s\n", path);
        }
    } else {
        printf("\n[BASELINE] no previous baseline for %s; saving this run as the baseline\n", host);
    }

    if (write_json_report_file(host, path) != 0)
        fprintf(stderr, "[WARN] --diff-baseline: cannot write baseline %s: %s\n",
                path, strerror(errno));
}

/* ---- per-host diagnostics (extracted for watch/hosts-file support) ---- */

static int run_diagnostics_for_host(const char *host) {
    reset_diagnostic_state();

    char reason[256];
    if (validate_host_arg(host, reason, sizeof(reason)) != 0) {
        fprintf(stderr, "invalid host: %s\n", reason);
        return 2;
    }
    if (prepare_output_dir(host) != 0)
        return 2;

    enable_report_only_output();
    /* The banner is for humans: machine formats (ndjson, prometheus, junit)
     * must emit nothing on stdout besides the format itself, and --quiet
     * silences human stdout entirely. */
    if (!opt.quiet && (opt.output_fmt == OUTPUT_FMT_TEXT || opt.output_fmt == OUTPUT_FMT_TABLE))
        printf("nfsdiag %s: %s\n", NFSDIAG_VERSION, host);
    warn_risky_mount_options(opt.mount_options);

    check_client_daemons();
    if (opt.krb5) check_kerberos();

    struct rpc_services services = {0};
    struct export_list exports_found = {0};

    network_tests(host);
    check_rpcbind(host, &services);
    check_rpc_dynamic_ports(host, &services);
    fingerprint_server(&services);
    check_nfs_versions(host, &services);
    check_mountd_versions(host, &services);
    enumerate_exports(host, &exports_found);

    if (opt.no_mount) {
        report_info("mount and live filesystem diagnostics skipped by --no-mount");
        print_interpretation();
        if (!opt.quiet && (opt.output_fmt == OUTPUT_FMT_TEXT || opt.output_fmt == OUTPUT_FMT_TABLE))
            printf("summary: ok=%d warn=%d fail=%d\n", summary_ok, summary_warn, summary_fail);
        write_json_report(host);
        write_html_report(host);
        write_table_report(host);
        write_prometheus_report(host);
        write_junit_report(host);
        write_output_dir_evidence(host);
        handle_diff_baseline(host);
        free_exports(&exports_found);
        free(services.items);
        run_on_fail_exec(host);
        return summary_fail || summary_warn ? 1 : 0;
    }

    if (geteuid() == 0 && !opt.no_mount_namespace)
        opt.mount_namespace = 1;
    if (setup_mount_namespace() < 0 && opt.mount_namespace)
        report_warn("proceeding without private mount namespace; mounts will affect the global namespace");

    if (opt.verbose) printf("\n[+] Temporary mount workspace\n");
    const char *tmpdir = validated_tmpdir();
    snprintf(cleanup_base, sizeof(cleanup_base), "%s/nfsdiag-XXXXXX", tmpdir);
    if (!mkdtemp(cleanup_base)) {
        report_fail("mkdtemp failed under %s: %s", tmpdir, strerror(errno));
        write_json_report(host);
        free_exports(&exports_found);
        free(services.items);
        return 2;
    }
    if (validate_created_workspace(cleanup_base) != 0) {
        report_fail("temporary workspace failed ownership or permission validation: %s", cleanup_base);
        write_json_report(host);
        free_exports(&exports_found);
        free(services.items);
        return 2;
    }
    report_ok("created temporary workspace %s", cleanup_base);

    if (exports_found.count == 0)
        report_fail("no exports available to mount; use --export PATH if the server is NFSv4-only or hides mountd");

    struct rpc_stats rpc_before, rpc_after;
    capture_rpc_stats(&rpc_before);

    if (opt.parallel > 1 && exports_found.count > 1 && !opt.dry_run) {
        run_exports_parallel(host, &exports_found);
    } else {
        for (size_t i = 0; i < exports_found.count; i++) {
            if (i > 0 && opt.delay_ms > 0) {
                struct timespec delay = {
                    .tv_sec = opt.delay_ms / 1000,
                    .tv_nsec = (long)(opt.delay_ms % 1000) * 1000000L
                };
                nanosleep(&delay, NULL);
            }
            if (received_signal) {
                report_warn("received signal %d, stopping further mount diagnostics", received_signal);
                break;
            }
            char mp[4096];
            int mpn = snprintf(mp, sizeof(mp), "%s/export-%zu", cleanup_base, i + 1);
            if (mpn < 0 || (size_t)mpn >= sizeof(mp)) {
                report_fail("mountpoint path would be too long for export %zu", i + 1);
                continue;
            }
            if (make_dir(mp, 0700) != 0) {
                report_fail("cannot create mountpoint %s: %s", mp, strerror(errno));
                continue;
            }

            size_t idx = export_report_count;
            if (export_report_count < MAX_EXPORT_REPORTS) {
                struct export_report *rpt = &export_reports[idx];
                memset(rpt, 0, sizeof(*rpt));
                snprintf(rpt->path, sizeof(rpt->path), "%s", exports_found.items[i].path);
                export_report_count++;
            }
            /* dry-run cannot block (no real mount), so keep it in-process; real
             * mounts run in a killable worker so a hung hard mount cannot pin
             * the main process. */
            int keep = opt.dry_run
                ? test_one_export(host, &exports_found.items[i], idx, mp)
                : run_export_isolated(host, &exports_found.items[i], idx, mp);
            if (keep) opt.keep_temp = 1;
        }
    }

    /* Kerberos flavor probing and the mount option sweep run after the main
     * pass so their extra mounts do not disturb the per-export diagnostics. */
    if (opt.krb5 && !opt.dry_run && exports_found.count > 0 && !received_signal)
        test_krb5_mount_flavors(host, exports_found.items[0].path, cleanup_base);

    if (opt.sweep && !opt.dry_run && opt.write_test && !received_signal) {
        size_t s;
        for (s = 0; s < export_report_count; s++)
            if (export_reports[s].tested && export_reports[s].nfs_version > 0)
                break;
        if (s < export_report_count) {
            char vers[16];
            if (export_reports[s].nfs_version == 4 && export_reports[s].nfs_minor_version > 0)
                snprintf(vers, sizeof(vers), "4.%d", export_reports[s].nfs_minor_version);
            else
                snprintf(vers, sizeof(vers), "%d", export_reports[s].nfs_version);
            sweep_mount_options(host, export_reports[s].path, cleanup_base, vers);
        } else {
            report_info("mount option sweep skipped: no export was mounted successfully");
        }
    }

    capture_rpc_stats(&rpc_after);
    report_rpc_stats_diff(&rpc_before, &rpc_after);

    if (opt.keep_temp) report_warn("temporary workspace kept at %s", cleanup_base);
    else { cleanup_temp_tree(); report_ok("temporary workspace removed"); }

    print_interpretation();
    if (!opt.quiet && (opt.output_fmt == OUTPUT_FMT_TEXT || opt.output_fmt == OUTPUT_FMT_TABLE))
        printf("summary: ok=%d warn=%d fail=%d\n", summary_ok, summary_warn, summary_fail);
    write_json_report(host);
    write_html_report(host);
    write_table_report(host);
    write_prometheus_report(host);
    write_junit_report(host);
    write_output_dir_evidence(host);
    handle_diff_baseline(host);

    run_on_fail_exec(host);

    free_exports(&exports_found);
    free(services.items);
    return summary_fail || summary_warn ? 1 : 0;
}

/* ---- embedded Prometheus exporter (--listen [ADDR:]PORT) ---- */

static int run_listen_mode(const char *host) {
    int port = opt.listen_port;
    /* Default to loopback: the exporter has no authentication, so exposing
     * it beyond the local host must be an explicit decision. */
    const char *addr = opt.listen_addr[0] ? opt.listen_addr : "127.0.0.1";
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%d", port);

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_PASSIVE | AI_NUMERICSERV;
    int gai = getaddrinfo(addr, portstr, &hints, &res);
    if (gai != 0) {
        fprintf(stderr, "Error: cannot resolve listen address %s: %s\n",
                addr, gai_strerror(gai));
        return 2;
    }
    int s = -1;
    int bind_errno = 0;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s < 0) { bind_errno = errno; continue; }
        int on = 1;
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
        if (ai->ai_family == AF_INET6) {
            /* "[::]:PORT" keeps the historical dual-stack behaviour */
            int off = 0;
            setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));
        }
        if (bind(s, ai->ai_addr, ai->ai_addrlen) == 0) break;
        bind_errno = errno;
        close(s);
        s = -1;
    }
    freeaddrinfo(res);
    if (s < 0) {
        fprintf(stderr, "Error: cannot bind %s port %d: %s\n",
                addr, port, strerror(bind_errno));
        return 2;
    }
    if (listen(s, 16) != 0) {
        fprintf(stderr, "Error: listen failed on %s port %d: %s\n",
                addr, port, strerror(errno));
        close(s);
        return 2;
    }
    signal(SIGPIPE, SIG_IGN);

    int interval = opt.watch_interval > 0 ? opt.watch_interval : 60;
    printf("[listen] serving Prometheus metrics on %s port %d, refreshing every %ds\n",
           addr, port, interval);

    char *snapshot = NULL;
    int overall = 0;
    while (!received_signal) {
        int rc = run_diagnostics_for_host(host);
        if (rc > overall) overall = rc;
        free(snapshot);
        snapshot = prometheus_snapshot(host);
        size_t snap_len = snapshot ? strlen(snapshot) : 0;

        time_t next = time(NULL) + interval;
        while (!received_signal && time(NULL) < next) {
            struct pollfd pfd = { .fd = s, .events = POLLIN };
            int pr = poll(&pfd, 1, 500);
            if (pr <= 0) continue;
            int c = accept(s, NULL, NULL);
            if (c < 0) continue;
            char req[1024];
            if (read(c, req, sizeof(req)) < 0) { /* request body is irrelevant */ }
            char hdr[256];
            int hl = snprintf(hdr, sizeof(hdr),
                              "HTTP/1.0 200 OK\r\n"
                              "Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n"
                              "Content-Length: %zu\r\n"
                              "Connection: close\r\n\r\n", snap_len);
            if (hl > 0) {
                (void)send(c, hdr, (size_t)hl, MSG_NOSIGNAL);
                if (snapshot)
                    (void)send(c, snapshot, snap_len, MSG_NOSIGNAL);
            }
            close(c);
        }
    }
    free(snapshot);
    close(s);
    return overall;
}

int main(int argc, char **argv) {
    /* Pin the C locale so number parsing/formatting in reports and parsers is
     * independent of the caller's environment (decimal point, thousands
     * grouping, collation). nfsdiag emits ASCII/UTF-8 bytes directly, so this
     * does not affect rendering. */
    setlocale(LC_ALL, "C");

    remember_argv(argc, argv);
    if (argc == 4 && strcmp(argv[1], "diff") == 0)
        return diff_reports(argv[2], argv[3]);

    static struct option long_opts[] = {
        {"export",           required_argument, 0, 'e'},
        {"mount-options",    required_argument, 0, 'o'},
        {"no-mount",         no_argument,       0, 1000},
        {"keep-temp",        no_argument,       0, 1001},
        {"read-only",        no_argument,       0, 1002},
        {"dry-run",          no_argument,       0, 1019},
        {"uid",              required_argument, 0, 1003},
        {"gid",              required_argument, 0, 1004},
        {"timeout",          required_argument, 0, 1005},
        {"stale-iterations", required_argument, 0, 1006},
        {"bench-bytes",      required_argument, 0, 1007},
        {"bench-type",       required_argument, 0, 1022},
        {"command-timeout",  required_argument, 0, 1008},
        {"mount-namespace",  no_argument,       0, 1009},
        {"json",             optional_argument, 0, 1010},
        {"html",             optional_argument, 0, 1021},
        {"groups",           required_argument, 0, 1011},
        {"udp",              no_argument,       0, 1012},
        {"ipv4-only",        no_argument,       0, 1013},
        {"ipv6-only",        no_argument,       0, 1014},
        {"no-nfs4-discovery",no_argument,       0, 1015},
        {"bench-iterations", required_argument, 0, 1016},
        {"fs-timeout",       required_argument, 0, 1017},
        {"delay-ms",         required_argument, 0, 1020},
        {"krb5",             no_argument,       0, 1018},
        {"hosts-file",       required_argument, 0, 1023},
        {"watch",            required_argument, 0, 1024},
        {"on-fail-exec",     required_argument, 0, 1025},
        {"config",           required_argument, 0, 1026},
        {"output-format",    required_argument, 0, 1027},
        {"allow-risky-mount-options", no_argument, 0, 1028},
        {"dangerous-fs-tests", no_argument,      0, 1029},
        {"deep",             no_argument,       0, 1029},
        {"no-mount-namespace", no_argument,     0, 1030},
        {"profile",          required_argument, 0, 1031},
        {"output-dir",       required_argument, 0, 1032},
        {"self-test",        no_argument,       0, 1033},
        {"sweep",            no_argument,       0, 1034},
        {"parallel",         required_argument, 0, 1035},
        {"listen",           required_argument, 0, 1036},
        {"diff-baseline",    no_argument,       0, 1037},
        {"verbose",          no_argument,       0, 'v'},
        {"quiet",            no_argument,       0, 'q'},
        {"version",          no_argument,       0, 'V'},
        {"help",             no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    /*
     * CLI parsing uses fprintf(stderr) directly (not report_fail) because the
     * report subsystem is not yet initialised at this point. report_fail would
     * crash or produce garbled output since events[] is still NULL.
     */

    /* Process --config first so that CLI flags can override it.
     * Both "--config FILE" and "--config=FILE" forms must be recognised. */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            load_config_file(argv[i + 1]);
            break;
        }
        if (strncmp(argv[i], "--config=", 9) == 0) {
            load_config_file(argv[i] + 9);
            break;
        }
    }

    int c;
    while ((c = getopt_long(argc, argv, "e:o:vqVh", long_opts, NULL)) != -1) {
        unsigned long value;
        switch (c) {
        case 'e':
            if (opt.cli_export_count >= MAX_CLI_EXPORTS) {
                fprintf(stderr, "too many --export paths (max %d)\n", MAX_CLI_EXPORTS);
                return 2;
            }
            opt.cli_exports[opt.cli_export_count++] = optarg;
            break;
        case 'o': opt.mount_options = optarg; break;
        case 'v': opt.verbose = 1; break;
        case 'q': opt.quiet = 1; break;
        case 'V': printf("nfsdiag %s\n", NFSDIAG_VERSION); return 0;
        case 'h': usage(argv[0]); return 0;
        case 1000: opt.no_mount = 1; break;
        case 1001: opt.keep_temp = 1; break;
        case 1002: opt.write_test = 0; break;
        case 1019: opt.dry_run = 1; break;
        case 1003: {
            uid_t uid;
            if (parse_uid_arg(optarg, &uid) != 0) { fprintf(stderr, "invalid --uid: %s (expected 0..%lu)\n", optarg, (unsigned long)((uid_t)-1 - 1)); return 2; }
            add_identity(uid, default_gid_for_uid(uid));
            break;
        }
        case 1004: {
            gid_t gid;
            if (parse_gid_arg(optarg, &gid) != 0) { fprintf(stderr, "invalid --gid: %s (expected 0..%lu)\n", optarg, (unsigned long)((gid_t)-1 - 1)); return 2; }
            if (opt.identity_count == 0) add_identity(geteuid(), gid);
            else opt.gids[opt.identity_count - 1] = gid;
            break;
        }
        case 1005:
            if (parse_ulong_arg(optarg, &value) != 0 || value == 0 || value > 3600) { fprintf(stderr, "invalid --timeout: %s (1-3600 seconds)\n", optarg); return 2; }
            opt.timeout_sec = (int)value;
            break;
        case 1006:
            if (parse_ulong_arg(optarg, &value) != 0 || value > 1000000UL) { fprintf(stderr, "invalid --stale-iterations: %s (0-1000000)\n", optarg); return 2; }
            opt.stale_iterations = (int)value;
            break;
        case 1007:
            if (parse_ulong_arg(optarg, &value) != 0 || value == 0 || value > (1024UL * 1024UL * 1024UL)) { fprintf(stderr, "invalid --bench-bytes: %s (1-1073741824 bytes; use --bench-iterations 0 to skip the benchmark)\n", optarg); return 2; }
            opt.bench_bytes = (size_t)value;
            break;
        case 1022:
            if (strcmp(optarg, "internal") != 0 && strcmp(optarg, "fio") != 0) {
                fprintf(stderr, "invalid --bench-type: %s (valid values: internal, fio)\n", optarg);
                return 2;
            }
            opt.bench_type = optarg;
            break;
        case 1008:
            if (parse_ulong_arg(optarg, &value) != 0 || value == 0 || value > 3600) { fprintf(stderr, "invalid --command-timeout: %s (1-3600 seconds)\n", optarg); return 2; }
            opt.command_timeout_sec = (int)value;
            break;
        case 1009: opt.mount_namespace = 1; break;
        case 1010:
            opt.json = 1;
            opt.json_path = optarg ? optarg : "-";
            break;
        case 1021:
            opt.html = 1;
            opt.html_path = optarg ? optarg : "-";
            break;
        case 1011:
            if (parse_groups_arg(optarg) != 0) { fprintf(stderr, "invalid --groups: %s (comma-separated GIDs, max 64)\n", optarg); return 2; }
            break;
        case 1012: opt.udp_checks = 1; break;
        case 1013: opt.address_family = AF_INET; break;
        case 1014: opt.address_family = AF_INET6; break;
        case 1015: opt.nfs4_discovery = 0; break;
        case 1016:
            if (parse_ulong_arg(optarg, &value) != 0 || value > 100000UL) { fprintf(stderr, "invalid --bench-iterations: %s (0-100000)\n", optarg); return 2; }
            opt.bench_iterations = (int)value;
            break;
        case 1017:
            if (parse_ulong_arg(optarg, &value) != 0 || value == 0 || value > 3600) { fprintf(stderr, "invalid --fs-timeout: %s (1-3600 seconds)\n", optarg); return 2; }
            opt.fs_timeout_sec = (int)value;
            break;
        case 1020:
            if (parse_ulong_arg(optarg, &value) != 0 || value > 600000) { fprintf(stderr, "invalid --delay-ms: %s (0-600000 ms)\n", optarg); return 2; }
            opt.delay_ms = (int)value;
            break;
        case 1018: opt.krb5 = 1; break;
        case 1023: opt.hosts_file = optarg; break;
        case 1024:
            if (parse_ulong_arg(optarg, &value) != 0 || value < 1 || value > 86400) { fprintf(stderr, "invalid --watch: %s (1-86400 seconds)\n", optarg); return 2; }
            opt.watch_interval = (int)value;
            break;
        case 1025: opt.on_fail_exec = optarg; break;
        case 1026: /* already processed above */ break;
        case 1027:
            if (strcmp(optarg, "text") == 0)      opt.output_fmt = OUTPUT_FMT_TEXT;
            else if (strcmp(optarg, "table") == 0) opt.output_fmt = OUTPUT_FMT_TABLE;
            else if (strcmp(optarg, "ndjson") == 0) opt.output_fmt = OUTPUT_FMT_NDJSON;
            else if (strcmp(optarg, "prometheus") == 0) opt.output_fmt = OUTPUT_FMT_PROMETHEUS;
            else if (strcmp(optarg, "junit") == 0) opt.output_fmt = OUTPUT_FMT_JUNIT;
            else { fprintf(stderr, "invalid --output-format: %s (valid: text, table, ndjson, prometheus, junit)\n", optarg); return 2; }
            break;
        case 1028: opt.allow_risky_mount_options = 1; break;
        case 1029: opt.dangerous_fs_tests = 1; break;
        case 1030: opt.no_mount_namespace = 1; opt.mount_namespace = 0; break;
        case 1031:
            if (apply_profile(optarg) != 0) return 2;
            break;
        case 1032: opt.output_dir = optarg; break;
        case 1033: opt.self_test = 1; break;
        case 1034: opt.sweep = 1; break;
        case 1035:
            if (parse_ulong_arg(optarg, &value) != 0 || value < 1 || value > MAX_PARALLEL) {
                fprintf(stderr, "invalid --parallel: %s (1-%d)\n", optarg, MAX_PARALLEL);
                return 2;
            }
            opt.parallel = (int)value;
            break;
        case 1036: {
            char reason[256];
            if (parse_listen_arg(optarg, opt.listen_addr, sizeof(opt.listen_addr),
                                 &opt.listen_port, reason, sizeof(reason)) != 0) {
                fprintf(stderr, "invalid --listen: %s (%s)\n", optarg, reason);
                return 2;
            }
            break;
        }
        case 1037: opt.diff_baseline = 1; break;
        default:
            usage(argv[0]);
            return 2;
        }
    }

    if (opt.self_test)
        return run_self_test();

    if (opt.mount_options) {
        char reason[256];
        if (validate_mount_options(opt.mount_options, opt.allow_risky_mount_options,
                                   reason, sizeof(reason)) != 0) {
            fprintf(stderr, "invalid --mount-options: %s\n", reason);
            return 2;
        }
    }
    for (size_t x = 0; x < opt.cli_export_count; x++) {
        char reason[256];
        if (validate_export_path(opt.cli_exports[x], reason, sizeof(reason)) != 0) {
            fprintf(stderr, "invalid --export %s: %s\n", opt.cli_exports[x], reason);
            return 2;
        }
    }

    /* Must have either a positional host argument or --hosts-file */
    if (!opt.hosts_file && optind >= argc) { usage(argv[0]); return 2; }

    /* pre-flight dependency check */
    if (!check_dependencies()) return 2;

    if (opt.bench_type && strcmp(opt.bench_type, "fio") == 0) {
        char output[CMD_OUTPUT_LIMIT];
        char *fio_argv[] = {"fio", "--version", NULL};
        if (run_command_capture(fio_argv, output, sizeof(output)) != 0) {
            fprintf(stderr, "Error: --bench-type=fio requested but 'fio' is not installed or not in PATH.\n");
            return 2;
        }
    }

    install_cleanup_handlers();

    /* ---- hosts-file mode ---- */
    if (opt.hosts_file) {
        if (opt.listen_port > 0)
            fprintf(stderr, "[WARN] --listen is ignored in --hosts-file mode\n");
        if (optind < argc)
            fprintf(stderr, "[WARN] positional host '%s' ignored because --hosts-file was given\n",
                    argv[optind]);
        FILE *hf = fopen(opt.hosts_file, "r");
        if (!hf) {
            fprintf(stderr, "Error: cannot open hosts file %s: %s\n", opt.hosts_file, strerror(errno));
            return 2;
        }
        int overall_rc = 0;
        char hostline[1024];
        while (fgets(hostline, sizeof(hostline), hf)) {
            /* strip whitespace */
            char *h = hostline;
            while (*h == ' ' || *h == '\t') h++;
            size_t hlen = strlen(h);
            while (hlen > 0 && (h[hlen-1] == '\n' || h[hlen-1] == '\r' || h[hlen-1] == ' '))
                h[--hlen] = '\0';
            if (!*h || *h == '#') continue;
            if (received_signal) { fprintf(stderr, "signal received, stopping\n"); break; }
            int rc = run_diagnostics_for_host(h);
            if (rc > overall_rc) overall_rc = rc;
        }
        fclose(hf);
        return overall_rc;
    }

    const char *host = argv[optind];

    /* ---- embedded exporter mode (--listen) ---- */
    if (opt.listen_port > 0)
        return run_listen_mode(host);

    /* ---- watch mode ---- */
    if (opt.watch_interval > 0) {
        int overall_rc = 0;
        int iteration = 0;
        while (!received_signal) {
            if (iteration > 0) {
                /* Clear screen on subsequent iterations */
                printf("\033[2J\033[H");
                printf("[watch] iteration %d (every %ds, Ctrl-C to stop)\n", iteration + 1, opt.watch_interval);
            }
            iteration++;
            int rc = run_diagnostics_for_host(host);
            if (rc > overall_rc) overall_rc = rc;
            if (received_signal) break;
            /* Sleep in small increments to catch signals promptly */
            for (int s = 0; s < opt.watch_interval && !received_signal; s++)
                sleep(1);
        }
        return overall_rc;
    }

    return run_diagnostics_for_host(host);
}
