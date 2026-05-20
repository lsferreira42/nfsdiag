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
};

volatile sig_atomic_t received_signal = 0;
char cleanup_base[128];

/* ---- cleanup ---- */

static int unlink_cb(const char *fpath, const struct stat *sb, int typeflag,
                      struct FTW *ftwbuf) {
    (void)sb; (void)typeflag; (void)ftwbuf;
    if (remove(fpath) != 0 && errno != ENOENT)
        fprintf(stderr, "[WARN] cleanup remove(%s) failed: %s\n", fpath, strerror(errno));
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
    printf("      --keep-temp            Keep temp workspace after tests\n");
    printf("  -v, --verbose              Show all diagnostic steps\n");
    printf("  -q, --quiet                Suppress stdout (combine with --json=FILE or --html=FILE)\n");
    printf("  -V, --version              Print version and exit\n");
    printf("  -h, --help                 Show this help\n");
    printf("\nExit codes: 0=pass  1=warn/fail  2=usage/runtime error\n");
    printf("Stdout suppression: active only when --json=- or --html=- (report to stdout).\n");
    printf("  Use --quiet to suppress stdout when writing a report to a file.\n");
}

int main(int argc, char **argv) {
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
        default:
            usage(argv[0]);
            return 2;
        }
    }

    if (optind >= argc) { usage(argv[0]); return 2; }

    const char *host = argv[optind];

    /* pre-flight dependency check */
    if (!check_dependencies()) return 2;

    if (opt.bench_type && strcmp(opt.bench_type, "fio") == 0) {
        char output[CMD_OUTPUT_LIMIT];
        char *fio_argv[] = {"fio", "--version", NULL};
        if (run_command_capture(fio_argv, output, sizeof(output)) != 0) {
            fprintf(stderr, "Error: --bench-type=fio requested but 'fio' is not installed or not in PATH.\n");
            fprintf(stderr, "Please install 'fio' and try again.\n");
            return 2;
        }
    }

    install_cleanup_handlers();
    printf("nfsdiag %s: %s\n", NFSDIAG_VERSION, host);
    enable_report_only_output();

    /* client-side checks */
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
        free_exports(&exports_found);
        free(services.items);
        return summary_fail || summary_warn ? 1 : 0;
    }

    if (setup_mount_namespace() < 0 && opt.mount_namespace)
        report_warn("proceeding without private mount namespace; mounts will affect the global namespace");

    if (opt.verbose) printf("\n[+] Temporary mount workspace\n");
    const char *tmpdir = getenv("TMPDIR");
    if (!tmpdir || !tmpdir[0]) tmpdir = "/tmp";
    snprintf(cleanup_base, sizeof(cleanup_base), "%s/nfsdoctor-XXXXXX", tmpdir);
    if (!mkdtemp(cleanup_base)) {
        report_fail("mkdtemp failed under /tmp: %s", strerror(errno));
        write_json_report(host);
        free_exports(&exports_found);
        free(services.items);
        return 2;
    }
    report_ok("created temporary workspace %s", cleanup_base);

    if (exports_found.count == 0)
        report_fail("no exports available to mount; use --export PATH if the server is NFSv4-only or hides mountd");

    /* capture RPC stats before mount tests (item 7) */
    struct rpc_stats rpc_before, rpc_after;
    capture_rpc_stats(&rpc_before);

    for (size_t i = 0; i < exports_found.count; i++) {
        if (i > 0 && opt.delay_ms > 0) {
            usleep((useconds_t)opt.delay_ms * 1000);
        }
        if (received_signal) {
            report_warn("received signal %d, stopping further mount diagnostics", received_signal);
            break;
        }
        char mp[4096];
        snprintf(mp, sizeof(mp), "%s/export-%zu", cleanup_base, i + 1);
        if (make_dir(mp, 0700) != 0) {
            report_fail("cannot create mountpoint %s: %s", mp, strerror(errno));
            continue;
        }

        /* init export report */
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
                diagnose_mounted_export(exports_found.items[i].path, mp, (int)idx);
                if (unmount_export(mp) != 0) {
                    report_warn("leaving mountpoint in place for safety: %s", mp);
                    opt.keep_temp = 1;
                }
            }
        } else {
            if (export_report_count < MAX_EXPORT_REPORTS) export_report_count++;
        }
    }

    /* capture RPC stats after mount tests (item 7) */
    capture_rpc_stats(&rpc_after);
    report_rpc_stats_diff(&rpc_before, &rpc_after);

    if (opt.keep_temp) report_warn("temporary workspace kept at %s", cleanup_base);
    else { cleanup_temp_tree(); report_ok("temporary workspace removed"); }

    print_interpretation();
    printf("summary: ok=%d warn=%d fail=%d\n", summary_ok, summary_warn, summary_fail);
    write_json_report(host);
    write_html_report(host);

    free_exports(&exports_found);
    free(services.items);
    return summary_fail || summary_warn ? 1 : 0;
}
