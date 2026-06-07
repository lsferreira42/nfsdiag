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
        (void)write(STDERR_FILENO, msg, sizeof(msg) - 1);
        return 0;
    }
    /* Use write() instead of fprintf() so this is safe from atexit context
     * even when stdio may be in an inconsistent state after a signal. */
    if (remove(fpath) != 0 && errno != ENOENT) {
        const char msg[] = "[WARN] cleanup: remove failed\n";
        (void)write(STDERR_FILENO, msg, sizeof(msg) - 1);
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

static int parse_ulong_arg(const char *s, unsigned long *out) {
    if (!s || *s == '\0') return -1;
    char *end = NULL;
    errno = 0;
    unsigned long v = strtoul(s, &end, 10);
    if (errno || !end || end == s || *end != '\0') return -1;
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

static void load_config_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "[WARN] cannot open config file %s: %s\n", path, strerror(errno));
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
        char *key = p, *val = eq + 1;
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
        else if (strcmp(key, "bench-bytes") == 0 && parse_ulong_arg(val, &num) == 0 && num <= (1024UL*1024UL*1024UL))
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
            if (strcmp(val, "internal") == 0 || strcmp(val, "fio") == 0)
                opt.bench_type = strdup(val);
        } else if (strcmp(key, "mount-namespace") == 0 && strcmp(val, "true") == 0)
            opt.mount_namespace = 1;
        else if (strcmp(key, "no-mount-namespace") == 0 && strcmp(val, "true") == 0)
            opt.no_mount_namespace = 1;
        else if (strcmp(key, "dangerous-fs-tests") == 0 && strcmp(val, "true") == 0)
            opt.dangerous_fs_tests = 1;
        else if (strcmp(key, "allow-risky-mount-options") == 0 && strcmp(val, "true") == 0)
            opt.allow_risky_mount_options = 1;
        else if (strcmp(key, "output-dir") == 0)
            opt.output_dir = strdup(val);
        else if (strcmp(key, "krb5") == 0 && strcmp(val, "true") == 0)
            opt.krb5 = 1;
        else if (strcmp(key, "no-nfs4-discovery") == 0 && strcmp(val, "true") == 0)
            opt.nfs4_discovery = 0;
        else if (strcmp(key, "watch") == 0 && parse_ulong_arg(val, &num) == 0 && num <= 86400)
            opt.watch_interval = (int)num;
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
    sanitized_argv[0] = '\0';
    size_t used = 0;
    for (int i = 0; i < argc; i++) {
        const char *arg = argv[i] ? argv[i] : "";
        char clean[512];
        size_t j = 0;
        for (const unsigned char *p = (const unsigned char *)arg; *p && j + 1 < sizeof(clean); p++) {
            clean[j++] = (*p < 0x20 || *p == 0x7f) ? '?' : (char)*p;
        }
        clean[j] = '\0';
        int n = snprintf(sanitized_argv + used, sizeof(sanitized_argv) - used,
                         "%s%s", used ? " " : "", clean);
        if (n < 0 || (size_t)n >= sizeof(sanitized_argv) - used) break;
        used += (size_t)n;
    }
}

static int prepare_output_dir(const char *host) {
    if (!opt.output_dir) return 0;
    if (mkdir(opt.output_dir, 0700) != 0 && errno != EEXIST) {
        fprintf(stderr, "Error: cannot create output dir %s: %s\n", opt.output_dir, strerror(errno));
        return -1;
    }
    struct stat st;
    if (lstat(opt.output_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "Error: output dir is not a directory: %s\n", opt.output_dir);
        return -1;
    }
    if ((st.st_mode & 0777) & 0077)
        chmod(opt.output_dir, 0700);

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

static void write_output_dir_evidence(const char *host) {
    if (!opt.output_dir) return;
    FILE *f = fopen(output_dir_evidence_path, "w");
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
        FILE *cf = fopen(output_dir_checksums_path, "w");
        if (cf) {
            fputs(output, cf);
            fclose(cf);
        }
    }
}

static int extract_summary_value(const char *path, const char *key, long *out) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char buf[65536];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    char *p = strstr(buf, needle);
    if (!p) return -1;
    p = strchr(p, ':');
    if (!p) return -1;
    *out = strtol(p + 1, NULL, 10);
    return 0;
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
    printf("\nDiagnostic options:\n");
    printf("  -e, --export PATH          Test only this export path\n");
    printf("  -o, --mount-options OPTS   Extra mount options passed to mount(8)\n");
    printf("      --no-mount             Run network/RPC checks only; skip all mounts\n");
    printf("      --dry-run              Print what would be done; skip mounts and fs tests\n");
    printf("      --read-only            Do not create or write test files\n");
    printf("      --uid UID              Simulate access as UID (repeatable, needs root)\n");
    printf("      --gid GID              GID paired with last --uid\n");
    printf("      --groups G1,G2         Supplemental GIDs for UID/GID simulation\n");
    printf("      --krb5                 Check Kerberos prerequisites (ticket, gssd)\n");
    printf("      --udp                  Also probe RPC NULLPROC over UDP\n");
    printf("      --ipv4-only            Force IPv4 for direct TCP checks\n");
    printf("      --ipv6-only            Force IPv6 for direct TCP checks\n");
    printf("      --no-nfs4-discovery    Disable NFSv4 pseudo-root fallback\n");
    printf("      --mount-namespace      Use private mount namespace (needs root/CAP_SYS_ADMIN)\n");
    printf("      --no-mount-namespace   Disable automatic private mount namespace\n");
    printf("      --dangerous-fs-tests   Enable symlink/hardlink/FIFO/device-node probes\n");
    printf("      --allow-risky-mount-options\n");
    printf("                              Permit risky mount options such as exec/suid/dev\n");
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
    printf("      --bench-bytes BYTES    Bytes for read/write benchmark. Default: %u\n", DEFAULT_BENCH_BYTES);
    printf("      --bench-iterations N   Metadata latency iterations. Default: %d\n", DEFAULT_BENCH_ITERATIONS);
    printf("      --bench-type TYPE      Benchmark engine: 'internal' or 'fio'. Default: internal\n");
    printf("      --stale-iterations N   ESTALE probe loop iterations. Default: %d\n", DEFAULT_STALE_ITERATIONS);
    printf("\nOutput options:\n");
    printf("      --json[=PATH]          Emit JSON report to PATH (use '-' or omit for stdout)\n");
    printf("      --html[=PATH]          Emit HTML report to PATH (use '-' or omit for stdout)\n");
    printf("      --output-dir DIR       Write JSON, HTML, evidence and checksums to DIR\n");
    printf("      --output-format FMT    Terminal output: text (default), table, ndjson, prometheus\n");
    printf("      --keep-temp            Keep temp workspace after tests\n");
    printf("  -v, --verbose              Show all diagnostic steps\n");
    printf("  -q, --quiet                Suppress stdout (combine with --json=FILE or --html=FILE)\n");
    printf("  -V, --version              Print version and exit\n");
    printf("      --self-test            Validate local dependencies and pure helper checks\n");
    printf("  -h, --help                 Show this help\n");
    printf("\nExit codes: 0=pass  1=warn/fail  2=usage/runtime error\n");
    printf("Stdout suppression: active only when --json=- or --html=- (report to stdout).\n");
    printf("  Use --quiet to suppress stdout when writing a report to a file.\n");
}

/* ---- on-fail-exec hook ---- */

static void run_on_fail_exec(const char *host) {
    if (!opt.on_fail_exec || summary_fail == 0) return;
    /* Use execvp in a child; never sh -c */
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
        char resolved[4096];
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
        if (resolve_command_path(opt.on_fail_exec, resolved, sizeof(resolved)) != 0)
            _exit(127);
        execve(resolved, argv, safe_env);
        _exit(127);
    }
    int status;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
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

    printf("nfsdiag %s: %s\n", NFSDIAG_VERSION, host);
    enable_report_only_output();
    warn_risky_mount_options(opt.mount_options);

    check_client_daemons();
    if (opt.krb5) check_kerberos();

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
        write_html_report(host);
        write_table_report(host);
        write_prometheus_report(host);
        write_output_dir_evidence(host);
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
    snprintf(cleanup_base, sizeof(cleanup_base), "%s/nfsdoctor-XXXXXX", tmpdir);
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

    for (size_t i = 0; i < exports_found.count; i++) {
        if (i > 0 && opt.delay_ms > 0)
            usleep((useconds_t)opt.delay_ms * 1000);
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

        if (export_report_count < MAX_EXPORT_REPORTS) {
            struct export_report *rpt = &export_reports[export_report_count];
            memset(rpt, 0, sizeof(*rpt));
            snprintf(rpt->path, sizeof(rpt->path), "%s", exports_found.items[i].path);
        }

        if (opt.verbose) printf("\n[+] Mount test for export %s\n", exports_found.items[i].path);
        struct mount_result mr;
        if (mount_export(host, exports_found.items[i].path, mp, &mr) == 0) {
            if (export_report_count < MAX_EXPORT_REPORTS) {
                export_reports[export_report_count].nfs_version = mr.version;
                export_reports[export_report_count].nfs_minor_version = mr.nfs_minor_version;
                export_reports[export_report_count].tested = !opt.dry_run;
            }
            size_t idx = export_report_count;
            if (export_report_count < MAX_EXPORT_REPORTS) export_report_count++;

            if (!opt.dry_run) {
                diagnose_mounted_export(exports_found.items[i].path, mp,
                                        (int)idx, mr.version, mr.nfs_minor_version);
                if (unmount_export(mp) != 0) {
                    report_warn("leaving mountpoint in place for safety: %s", mp);
                    opt.keep_temp = 1;
                }
            }
        } else {
            if (export_report_count < MAX_EXPORT_REPORTS) export_report_count++;
        }
    }

    capture_rpc_stats(&rpc_after);
    report_rpc_stats_diff(&rpc_before, &rpc_after);

    if (opt.keep_temp) report_warn("temporary workspace kept at %s", cleanup_base);
    else { cleanup_temp_tree(); report_ok("temporary workspace removed"); }

    print_interpretation();
    printf("summary: ok=%d warn=%d fail=%d\n", summary_ok, summary_warn, summary_fail);
    write_json_report(host);
    write_html_report(host);
    write_table_report(host);
    write_prometheus_report(host);
    write_output_dir_evidence(host);

    run_on_fail_exec(host);

    free_exports(&exports_found);
    free(services.items);
    return summary_fail || summary_warn ? 1 : 0;
}

int main(int argc, char **argv) {
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

    /* Process --config first so that CLI flags can override it */
    for (int i = 1; i < argc - 1; i++) {
        if (strcmp(argv[i], "--config") == 0) {
            load_config_file(argv[i + 1]);
            break;
        }
    }

    int c;
    while ((c = getopt_long(argc, argv, "e:o:vqVh", long_opts, NULL)) != -1) {
        unsigned long value;
        switch (c) {
        case 'e': opt.single_export = optarg; break;
        case 'o': opt.mount_options = optarg; break;
        case 'v': opt.verbose = 1; break;
        case 'q': opt.quiet = 1; break;
        case 'V': printf("nfsdiag %s\n", NFSDIAG_VERSION); return 0;
        case 'h': usage(argv[0]); return 0;
        case 1000: opt.no_mount = 1; break;
        case 1001: opt.keep_temp = 1; break;
        case 1002: opt.write_test = 0; break;
        case 1019: opt.dry_run = 1; break;
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
        case 1022:
            if (strcmp(optarg, "internal") != 0 && strcmp(optarg, "fio") != 0) {
                fprintf(stderr, "invalid --bench-type: %s (valid values: internal, fio)\n", optarg);
                return 2;
            }
            opt.bench_type = optarg;
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
        case 1021:
            opt.html = 1;
            opt.html_path = optarg ? optarg : "-";
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
        case 1017:
            if (parse_ulong_arg(optarg, &value) != 0 || value == 0 || value > 3600) { fprintf(stderr, "invalid --fs-timeout: %s\n", optarg); return 2; }
            opt.fs_timeout_sec = (int)value;
            break;
        case 1020:
            if (parse_ulong_arg(optarg, &value) != 0 || value > 600000) { fprintf(stderr, "invalid --delay-ms: %s\n", optarg); return 2; }
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
            else { fprintf(stderr, "invalid --output-format: %s (valid: text, table, ndjson, prometheus)\n", optarg); return 2; }
            break;
        case 1028: opt.allow_risky_mount_options = 1; break;
        case 1029: opt.dangerous_fs_tests = 1; break;
        case 1030: opt.no_mount_namespace = 1; opt.mount_namespace = 0; break;
        case 1031:
            if (apply_profile(optarg) != 0) return 2;
            break;
        case 1032: opt.output_dir = optarg; break;
        case 1033: opt.self_test = 1; break;
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
    if (opt.single_export) {
        char reason[256];
        if (validate_export_path(opt.single_export, reason, sizeof(reason)) != 0) {
            fprintf(stderr, "invalid --export: %s\n", reason);
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
