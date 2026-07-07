#include "../src/nfsdiag.h"

static int failures = 0;

void report_warn(const char *fmt, ...) { (void)fmt; }
void report_info(const char *fmt, ...) { (void)fmt; }

static void expect_ok(int cond, const char *name) {
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", name);
        failures++;
    }
}

static void test_parse_ulong_arg(void) {
    unsigned long v = 0;

    expect_ok(parse_ulong_arg("0", &v) == 0 && v == 0, "ulong: zero");
    expect_ok(parse_ulong_arg("65535", &v) == 0 && v == 65535, "ulong: plain number");
    expect_ok(parse_ulong_arg("", &v) != 0, "ulong: reject empty");
    expect_ok(parse_ulong_arg(NULL, &v) != 0, "ulong: reject NULL");
    expect_ok(parse_ulong_arg("12x", &v) != 0, "ulong: reject trailing garbage");
    expect_ok(parse_ulong_arg("x12", &v) != 0, "ulong: reject leading garbage");
    expect_ok(parse_ulong_arg("1 2", &v) != 0, "ulong: reject inner space");
    expect_ok(parse_ulong_arg("-1", &v) != 0, "ulong: reject negative");
    expect_ok(parse_ulong_arg("99999999999999999999999999", &v) != 0,
              "ulong: reject overflow");
}

static void test_parse_id_arg(void) {
    uid_t uid = 0;
    gid_t gid = 0;

    expect_ok(parse_uid_arg("0", &uid) == 0 && uid == 0, "uid: zero");
    expect_ok(parse_uid_arg("1000", &uid) == 0 && uid == 1000, "uid: plain");
    expect_ok(parse_uid_arg("4294967294", &uid) == 0 && uid == 4294967294u,
              "uid: largest valid 32-bit value");
    expect_ok(parse_uid_arg("4294967295", &uid) != 0,
              "uid: reject reserved (uid_t)-1");
    expect_ok(parse_uid_arg("4294967296", &uid) != 0,
              "uid: reject value that truncates on cast");
    expect_ok(parse_uid_arg("-1", &uid) != 0, "uid: reject negative");
    expect_ok(parse_uid_arg("12x", &uid) != 0, "uid: reject trailing garbage");

    expect_ok(parse_gid_arg("0", &gid) == 0 && gid == 0, "gid: zero");
    expect_ok(parse_gid_arg("4294967295", &gid) != 0,
              "gid: reject reserved (gid_t)-1");
    expect_ok(parse_gid_arg("4294967296", &gid) != 0,
              "gid: reject value that truncates on cast");
}

static void test_redact_argv(void) {
    char out[4096];

    char *a1[] = {"nfsdiag", "-o", "vers=4,sec=krb5p", "host"};
    redact_argv(out, sizeof(out), 4, a1);
    expect_ok(strstr(out, "krb5p") == NULL && strstr(out, "-o <redacted>") != NULL,
              "redact: -o value");

    char *a2[] = {"nfsdiag", "--mount-options=vers=4,sec=krb5p", "host"};
    redact_argv(out, sizeof(out), 3, a2);
    expect_ok(strstr(out, "krb5p") == NULL &&
              strstr(out, "--mount-options=<redacted>") != NULL,
              "redact: --mount-options= inline");

    char *a3[] = {"nfsdiag", "--config", "/etc/secret.conf", "host"};
    redact_argv(out, sizeof(out), 4, a3);
    expect_ok(strstr(out, "secret.conf") == NULL && strstr(out, "--config <redacted>") != NULL,
              "redact: --config path");

    char *a4[] = {"nfsdiag", "--on-fail-exec=/opt/hooks/page.sh", "host"};
    redact_argv(out, sizeof(out), 3, a4);
    expect_ok(strstr(out, "page.sh") == NULL &&
              strstr(out, "--on-fail-exec=<redacted>") != NULL,
              "redact: --on-fail-exec= inline");

    char *a5[] = {"nfsdiag", "--no-mount", "192.168.0.1"};
    redact_argv(out, sizeof(out), 3, a5);
    expect_ok(strcmp(out, "nfsdiag --no-mount 192.168.0.1") == 0,
              "redact: non-sensitive args preserved");

    char *a6[] = {"nfsdiag", "host\x01\x1bname"};
    redact_argv(out, sizeof(out), 2, a6);
    expect_ok(strstr(out, "\x01") == NULL && strstr(out, "\x1b") == NULL &&
              strstr(out, "host??name") != NULL,
              "redact: control bytes stripped");
}

static void test_validate_host(void) {
    char reason[256];

    expect_ok(validate_host_arg("nfs.example.com", reason, sizeof(reason)) == 0,
              "host: valid hostname");
    expect_ok(validate_host_arg("192.168.0.1", reason, sizeof(reason)) == 0,
              "host: valid IPv4");
    expect_ok(validate_host_arg("fd00::1", reason, sizeof(reason)) == 0,
              "host: valid IPv6");
    expect_ok(validate_host_arg("bad host", reason, sizeof(reason)) != 0,
              "host: reject whitespace");
    expect_ok(validate_host_arg("bad/path", reason, sizeof(reason)) != 0,
              "host: reject slash");
    expect_ok(validate_host_arg("", reason, sizeof(reason)) != 0,
              "host: reject empty");
    expect_ok(validate_host_arg("a,b", reason, sizeof(reason)) != 0,
              "host: reject comma");
}

static void test_validate_export(void) {
    char reason[256];

    expect_ok(validate_export_path("/export/data", reason, sizeof(reason)) == 0,
              "export: valid path");
    expect_ok(validate_export_path("relative", reason, sizeof(reason)) != 0,
              "export: reject relative");
    expect_ok(validate_export_path("/export/../secret", reason, sizeof(reason)) != 0,
              "export: reject parent component");
    expect_ok(validate_export_path("/export/..", reason, sizeof(reason)) != 0,
              "export: reject trailing parent");
    expect_ok(validate_export_path("/exp\x01ort", reason, sizeof(reason)) != 0,
              "export: reject control char");
}

static void test_validate_mount_options(void) {
    char reason[256];

    expect_ok(validate_mount_options("hard,timeo=30,retrans=2", 0, reason, sizeof(reason)) == 0,
              "mountopts: valid set");
    expect_ok(validate_mount_options("exec", 0, reason, sizeof(reason)) != 0,
              "mountopts: reject risky");
    expect_ok(validate_mount_options("exec", 1, reason, sizeof(reason)) == 0,
              "mountopts: allow risky explicitly");
    /* exact token matching: 'noexec' must not be confused with 'exec' */
    expect_ok(validate_mount_options("noexec,nosuid", 0, reason, sizeof(reason)) == 0,
              "mountopts: noexec is not exec");
    expect_ok(validate_mount_options("hard,,soft", 0, reason, sizeof(reason)) != 0,
              "mountopts: reject empty token");
    expect_ok(validate_mount_options("a;b", 0, reason, sizeof(reason)) != 0,
              "mountopts: reject semicolon");
}

static void test_parse_listen_arg(void) {
    char addr[256];
    char reason[256];
    int port = 0;

    expect_ok(parse_listen_arg("9100", addr, sizeof(addr), &port, reason, sizeof(reason)) == 0 &&
              port == 9100 && strcmp(addr, "127.0.0.1") == 0,
              "listen: bare port defaults to loopback");
    expect_ok(parse_listen_arg("0.0.0.0:9100", addr, sizeof(addr), &port, reason, sizeof(reason)) == 0 &&
              port == 9100 && strcmp(addr, "0.0.0.0") == 0,
              "listen: explicit wildcard v4");
    expect_ok(parse_listen_arg("[::1]:9100", addr, sizeof(addr), &port, reason, sizeof(reason)) == 0 &&
              port == 9100 && strcmp(addr, "::1") == 0,
              "listen: bracketed v6");
    expect_ok(parse_listen_arg("[::]:80", addr, sizeof(addr), &port, reason, sizeof(reason)) == 0 &&
              port == 80 && strcmp(addr, "::") == 0,
              "listen: bracketed v6 wildcard");
    expect_ok(parse_listen_arg("metrics.local:9100", addr, sizeof(addr), &port, reason, sizeof(reason)) == 0 &&
              strcmp(addr, "metrics.local") == 0,
              "listen: hostname form");
    expect_ok(parse_listen_arg("0", addr, sizeof(addr), &port, reason, sizeof(reason)) != 0,
              "listen: reject port 0");
    expect_ok(parse_listen_arg("65536", addr, sizeof(addr), &port, reason, sizeof(reason)) != 0,
              "listen: reject port > 65535");
    expect_ok(parse_listen_arg("::1:9100", addr, sizeof(addr), &port, reason, sizeof(reason)) != 0,
              "listen: reject unbracketed v6");
    expect_ok(parse_listen_arg("[::1]9100", addr, sizeof(addr), &port, reason, sizeof(reason)) != 0,
              "listen: reject missing colon after bracket");
    expect_ok(parse_listen_arg(":9100", addr, sizeof(addr), &port, reason, sizeof(reason)) != 0,
              "listen: reject empty address");
    expect_ok(parse_listen_arg("localhost:", addr, sizeof(addr), &port, reason, sizeof(reason)) != 0,
              "listen: reject empty port");
    expect_ok(parse_listen_arg("localhost:abc", addr, sizeof(addr), &port, reason, sizeof(reason)) != 0,
              "listen: reject non-numeric port");
}

static void test_event_metadata(void) {
    char id1[MAX_CHECK_ID], id2[MAX_CHECK_ID], id3[MAX_CHECK_ID];

    event_check_id(id1, sizeof(id1), "warn", "network", "rpcbind TCP port 111 unreachable");
    event_check_id(id2, sizeof(id2), "warn", "network", "rpcbind TCP port 111 unreachable");
    event_check_id(id3, sizeof(id3), "fail", "network", "rpcbind TCP port 111 unreachable");
    expect_ok(strcmp(id1, id2) == 0 && strstr(id1, "network.") == id1,
              "event: stable id");
    expect_ok(strcmp(id1, id3) != 0,
              "event: level changes id");

    expect_ok(strcmp(event_category_for_message("fail", "Kerberos ticket missing"), "auth") == 0,
              "category: auth");
    expect_ok(strcmp(event_category_for_message("warn", "rpcbind TCP port 111 unreachable"), "network") == 0,
              "category: network");
    expect_ok(strcmp(event_category_for_message("fail", "mount attempt failed"), "mount") == 0,
              "category: mount");
    expect_ok(strcmp(event_category_for_message("warn", "root_squash practical signal"), "permissions") == 0,
              "category: permissions");
    expect_ok(strcmp(event_category_for_message("warn", "write benchmark below threshold"), "performance") == 0,
              "category: performance");
    expect_ok(strcmp(event_category_for_message("info", "completely unrelated text"), "general") == 0,
              "category: general fallback");

    expect_ok(event_remediation_for("network", "")[0] != '\0',
              "remediation: network non-empty");
    expect_ok(event_remediation_for("auth", "")[0] != '\0',
              "remediation: auth non-empty");
    expect_ok(event_remediation_for("general", "")[0] == '\0',
              "remediation: general empty");
}

static void test_service_missing_severity(void) {
    expect_ok(service_missing_is_warning(PROFILE_NFSV4_ONLY) == 0,
              "severity: v4-only missing legacy svc is info");
    expect_ok(service_missing_is_warning(PROFILE_NFSV3_ONLY) == 1,
              "severity: v3 missing svc is warn");
    expect_ok(service_missing_is_warning(PROFILE_UNKNOWN) == 1,
              "severity: unknown profile stays conservative (warn)");
}

static void test_parse_bounded_int(void) {
    int out = -1;
    expect_ok(parse_bounded_int("5", 1, 3600, &out) == 0 && out == 5,
              "bounded: in range");
    expect_ok(parse_bounded_int("0", 1, 3600, &out) != 0, "bounded: below lo");
    expect_ok(parse_bounded_int("3601", 1, 3600, &out) != 0, "bounded: above hi");
    expect_ok(parse_bounded_int("-1", 0, 10, &out) != 0, "bounded: reject negative");
    expect_ok(parse_bounded_int("7x", 0, 10, &out) != 0, "bounded: reject garbage");
}

static void test_fopen_regular_ro(void) {
    char tmpl[] = "/tmp/nfsdiag-ut-XXXXXX";
    int fd = mkstemp(tmpl);
    expect_ok(fd >= 0, "fopen_ro: created temp regular file");
    if (fd >= 0) { (void)write(fd, "hi\n", 3); close(fd); }
    FILE *f = fopen_regular_ro(tmpl);
    expect_ok(f != NULL, "fopen_ro: opens a regular file");
    if (f) fclose(f);

    expect_ok(fopen_regular_ro("/tmp/nfsdiag-ut-does-not-exist-zzz") == NULL,
              "fopen_ro: missing file -> NULL");
    expect_ok(fopen_regular_ro("/tmp") == NULL, "fopen_ro: directory rejected");
    if (fd >= 0) unlink(tmpl);
}

static void test_mountinfo_unescape(void) {
    char out[64];
    mountinfo_unescape(out, sizeof(out), "/mnt/no-escape");
    expect_ok(strcmp(out, "/mnt/no-escape") == 0, "unescape: plain unchanged");

    mountinfo_unescape(out, sizeof(out), "/mnt/with\\040space");
    expect_ok(strcmp(out, "/mnt/with space") == 0, "unescape: \\040 -> space");

    mountinfo_unescape(out, sizeof(out), "/a\\011b\\134c");
    expect_ok(strcmp(out, "/a\tb\\c") == 0, "unescape: tab and backslash");
}

static void test_csv_append_missing(void) {
    char out[128];
    snprintf(out, sizeof(out), "vers=4");
    csv_append_missing(out, sizeof(out), "nosuid,nodev,noexec", "vers=4");
    expect_ok(strcmp(out, "vers=4,nosuid,nodev,noexec") == 0,
              "csv: appends all when none present");

    snprintf(out, sizeof(out), "vers=4");
    csv_append_missing(out, sizeof(out), "nosuid,nodev,noexec", "vers=4,nosuid");
    expect_ok(strcmp(out, "vers=4,nodev,noexec") == 0,
              "csv: skips token already in existing");
}

static void test_http_request_is_get(void) {
    char path[64];
    const char *g = "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n";
    expect_ok(http_request_is_get(g, strlen(g), path, sizeof(path)) == 1 &&
              strcmp(path, "/metrics") == 0, "http: GET /metrics parsed");

    const char *p = "POST /metrics HTTP/1.1\r\n\r\n";
    expect_ok(http_request_is_get(p, strlen(p), path, sizeof(path)) == 0,
              "http: POST rejected");

    const char *junk = "garbage";
    expect_ok(http_request_is_get(junk, strlen(junk), path, sizeof(path)) == 0,
              "http: malformed rejected");

    const char *root = "GET / HTTP/1.0\r\n\r\n";
    expect_ok(http_request_is_get(root, strlen(root), path, sizeof(path)) == 1 &&
              strcmp(path, "/") == 0, "http: GET / parsed");
}

static void test_avg_per_op_ms(void) {
    expect_ok(avg_per_op_ms(0, 0) == 0.0, "rtt: zero ops -> 0");
    expect_ok(avg_per_op_ms(1000, 10) == 100.0, "rtt: 1000ms/10ops = 100ms");
    expect_ok(avg_per_op_ms(5, 0) == 0.0, "rtt: ops=0 never divides");
}

static void test_utf8_truncate(void) {
    char out[64];
    utf8_truncate(out, sizeof(out), "/short", 32);
    expect_ok(strcmp(out, "/short") == 0, "utf8: short path unchanged");

    utf8_truncate(out, sizeof(out), "/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 32);
    expect_ok(strlen(out) == 32 && strcmp(out + 29, "...") == 0,
              "utf8: ascii truncates to 32 with ellipsis");

    const char *cjk = "/\xe4\xb8\xad\xe6\x96\x87" /* CJK */
                      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    utf8_truncate(out, sizeof(out), cjk, 32);
    expect_ok(strlen(out) <= 32 && strcmp(out + strlen(out) - 3, "...") == 0,
              "utf8: cjk truncation keeps ellipsis and bounded length");
}

static void test_exports_parse_line(void) {
    struct export_line e;
    char err[256];

    expect_ok(exports_parse_line("# comment", 1, &e, err, sizeof(err)) == 0,
              "exports: comment skipped");
    expect_ok(exports_parse_line("   ", 2, &e, err, sizeof(err)) == 0,
              "exports: blank skipped");

    expect_ok(exports_parse_line("/srv/nfs 10.0.0.0/24(rw,sync)", 3, &e,
                                 err, sizeof(err)) == 1 &&
              strcmp(e.path, "/srv/nfs") == 0 && e.client_count == 1 &&
              strcmp(e.clients[0], "10.0.0.0/24(rw,sync)") == 0,
              "exports: simple line");

    expect_ok(exports_parse_line("\"/srv/with space\" host1(ro) host2(rw)", 4,
                                 &e, err, sizeof(err)) == 1 &&
              strcmp(e.path, "/srv/with space") == 0 && e.client_count == 2,
              "exports: quoted path, two clients");

    expect_ok(exports_parse_line("/srv/nfs", 5, &e, err, sizeof(err)) == -1,
              "exports: path without clients is an error");
    expect_ok(exports_parse_line("relative/path host(rw)", 6, &e,
                                 err, sizeof(err)) == -1,
              "exports: relative path is an error");
    expect_ok(exports_parse_line("\"/unterminated host(rw)", 7, &e,
                                 err, sizeof(err)) == -1,
              "exports: unterminated quote is an error");
}

static void test_exports_client_risk(void) {
    char why[256];

    expect_ok(exports_client_risk("10.0.0.0/24(rw,sync,root_squash)", why,
                                  sizeof(why)) == 0,
              "risk: sane entry is fine");
    expect_ok(exports_client_risk("*(rw,no_root_squash)", why, sizeof(why)) == 1,
              "risk: no_root_squash flagged");
    expect_ok(exports_client_risk("*(rw)", why, sizeof(why)) == 1,
              "risk: world-writable wildcard flagged");
    expect_ok(exports_client_risk("host(insecure)", why, sizeof(why)) == 1,
              "risk: insecure flagged");
    expect_ok(exports_client_risk("host(ro)(rw)", why, sizeof(why)) == -1,
              "risk: malformed token rejected");
    expect_ok(exports_client_risk("host", why, sizeof(why)) == 0,
              "risk: bare host (default options) accepted");
}

static void test_parse_nfsd_versions(void) {
    struct nfsd_versions v;

    expect_ok(parse_nfsd_versions("-2 +3 +4 +4.1 -4.2", &v) == 0 &&
              v.v3 == 1 && v.v4 == 1 && v.v4_1 == 1 && v.v4_2 == 0,
              "versions: mixed line");
    expect_ok(parse_nfsd_versions("+3 +4", &v) == 0 &&
              v.v3 == 1 && v.v4 == 1 && v.v4_1 == -1 && v.v4_2 == -1,
              "versions: absent minors default to -1");
    expect_ok(parse_nfsd_versions("", &v) == -1, "versions: empty is error");
    expect_ok(parse_nfsd_versions("garbage here", &v) == -1,
              "versions: garbage is error");
}

static void test_parse_nfsd_th_line(void) {
    struct nfsd_th_stats th;

    expect_ok(parse_nfsd_th_line(
        "rc 0 0 0\nth 8 0 0.000 0.000 0.000 0.000 0.000 0.000 0.000 0.000 0.000 12.500\n",
        &th) == 0 && th.threads == 8 && th.valid &&
        th.busy_all > 12.4 && th.busy_all < 12.6,
        "th: parses count and last bucket");
    expect_ok(parse_nfsd_th_line("rc 0 0 0\nio 1 2\n", &th) == -1,
              "th: missing line is error");
    expect_ok(parse_nfsd_th_line("th 4 0\n", &th) == 0 && th.threads == 4 &&
              th.busy_all == 0.0,
              "th: short line still yields count");
}

static void test_comm_matches(void) {
    expect_ok(comm_matches("rpc.mountd\n", "rpc.mountd") == 1, "comm: exact + newline");
    expect_ok(comm_matches("rpc.mountd", "rpc.mountd") == 1, "comm: exact");
    expect_ok(comm_matches("rpc.mountd2", "rpc.mountd") == 0, "comm: no prefix match");
    expect_ok(comm_matches("rpcbind\n", "rpc.mountd") == 0, "comm: different");
    /* kernel truncates comm to 15 chars: a 16+ char name matches its prefix */
    expect_ok(comm_matches("rpc.svcgssd-ver", "rpc.svcgssd-verylong") == 1,
              "comm: 15-char kernel truncation");
}

static void test_tcp_table_has_listener(void) {
    const char *table =
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 00000000:0801 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 100 1 0 10 0\n"
        "   1: 0100007F:0016 00000000:0000 01 00000000:00000000 00:00000000 00000000     0        0 200 1 0 10 0\n";
    FILE *f = fmemopen((void *)table, strlen(table), "r");
    expect_ok(f && tcp_table_has_listener(f, 2049) == 1, "tcp: finds 2049 LISTEN");
    if (f) fclose(f);
    f = fmemopen((void *)table, strlen(table), "r");
    expect_ok(f && tcp_table_has_listener(f, 22) == 0,
              "tcp: port 22 present but ESTABLISHED, not LISTEN");
    if (f) fclose(f);
    f = fmemopen((void *)table, strlen(table), "r");
    expect_ok(f && tcp_table_has_listener(f, 111) == 0, "tcp: absent port");
    if (f) fclose(f);
}

static void test_fs_type_helpers(void) {
    char why[128];

    expect_ok(strcmp(fs_type_name(0xEF53), "ext4") == 0, "fstype: ext4 magic");
    expect_ok(strcmp(fs_type_name(0x58465342), "xfs") == 0, "fstype: xfs magic");
    expect_ok(strcmp(fs_type_name(0x123456), "unknown") == 0, "fstype: unmapped");

    expect_ok(fs_type_unsuitable(0x01021994, why, sizeof(why)) == 1,
              "fstype: tmpfs unsuitable");
    expect_ok(fs_type_unsuitable(0x794c7630, why, sizeof(why)) == 1,
              "fstype: overlayfs unsuitable");
    expect_ok(fs_type_unsuitable(0x6969, why, sizeof(why)) == 1,
              "fstype: nfs re-export flagged");
    expect_ok(fs_type_unsuitable(0xEF53, why, sizeof(why)) == 0,
              "fstype: ext4 fine");
}

static void test_usage_severity(void) {
    expect_ok(usage_severity(100, 50) == 0, "usage: half free is ok");
    expect_ok(usage_severity(100, 9) == 1, "usage: 91% used warns");
    expect_ok(usage_severity(100, 10) == 0, "usage: exactly 90% used is ok");
    expect_ok(usage_severity(0, 0) == -1, "usage: zero total unknown");
}

static void test_exports_security_scan(void) {
    struct export_line e[4];
    struct export_finding f[16];
    char err[256];

    /* subtree_check + insecure_locks + all_squash without anonuid */
    expect_ok(exports_parse_line("/srv/a host1(rw,subtree_check,insecure_locks,all_squash)",
                                 1, &e[0], err, sizeof(err)) == 1,
              "secscan: fixture line 1 parses");
    int n = exports_security_scan(e, 1, f, 16);
    int has_subtree = 0, has_locks = 0, has_allsquash = 0;
    for (int i = 0; i < n; i++) {
        if (strstr(f[i].msg, "subtree_check"))   has_subtree = 1;
        if (strstr(f[i].msg, "insecure_locks"))  has_locks = 1;
        if (strstr(f[i].msg, "all_squash"))      has_allsquash = 1;
    }
    expect_ok(has_subtree && has_locks && has_allsquash,
              "secscan: token findings emitted");

    /* duplicate path + nested export without crossmnt */
    expect_ok(exports_parse_line("/srv/a host2(rw)", 2, &e[1], err, sizeof(err)) == 1 &&
              exports_parse_line("/srv/a/deep host3(rw)", 3, &e[2], err, sizeof(err)) == 1,
              "secscan: fixture lines 2-3 parse");
    n = exports_security_scan(e, 3, f, 16);
    int has_dup = 0, has_nested = 0;
    for (int i = 0; i < n; i++) {
        if (strstr(f[i].msg, "exported twice")) has_dup = 1;
        if (strstr(f[i].msg, "crossmnt"))       has_nested = 1;
    }
    expect_ok(has_dup && has_nested, "secscan: cross-entry findings emitted");

    /* clean entry yields nothing */
    expect_ok(exports_parse_line("/srv/clean 10.0.0.0/24(rw,sync,root_squash,no_subtree_check)",
                                 1, &e[3], err, sizeof(err)) == 1,
              "secscan: clean line parses");
    expect_ok(exports_security_scan(&e[3], 1, f, 16) == 0,
              "secscan: clean entry has no findings");
}

static void test_parse_idmapd_conf(void) {
    struct idmapd_conf c;

    expect_ok(parse_idmapd_conf(
        "[General]\nVerbosity = 0\nDomain = example.com\n"
        "[Mapping]\nNobody-User = nobody\nNobody-Group = nobody\n"
        "[Translation]\nMethod = nsswitch\n", &c) == 0 &&
        c.has_domain && strcmp(c.domain, "example.com") == 0 &&
        strcmp(c.nobody_user, "nobody") == 0 &&
        strcmp(c.method, "nsswitch") == 0,
        "idmapd: full file parses");

    expect_ok(parse_idmapd_conf("[General]\nVerbosity = 0\n", &c) == 0 &&
              !c.has_domain,
              "idmapd: missing Domain flagged");

    expect_ok(parse_idmapd_conf("Domain=nospace.example\n", &c) == 0 &&
              c.has_domain && strcmp(c.domain, "nospace.example") == 0,
              "idmapd: no-space form and no section accepted");
}

static void test_krb5_conf_default_realm(void) {
    char realm[128];

    expect_ok(krb5_conf_default_realm(
        "[libdefaults]\n default_realm = EXAMPLE.COM\n dns_lookup_kdc = true\n",
        realm, sizeof(realm)) == 0 && strcmp(realm, "EXAMPLE.COM") == 0,
        "krb5: default_realm parsed");
    expect_ok(krb5_conf_default_realm("[libdefaults]\n dns_lookup_kdc = true\n",
                                      realm, sizeof(realm)) == -1,
              "krb5: missing realm is error");
}

static void test_fs_type_acl_capable(void) {
    expect_ok(fs_type_acl_capable(0xEF53) == 1, "aclcap: ext4");
    expect_ok(fs_type_acl_capable(0x58465342) == 1, "aclcap: xfs");
    expect_ok(fs_type_acl_capable(0x01021994) == 0, "aclcap: tmpfs no");
    expect_ok(fs_type_acl_capable(0x123456) == 0, "aclcap: unknown no");
}

static void test_parse_nfsd_rc_line(void) {
    struct nfsd_rc rc;
    expect_ok(parse_nfsd_rc_line("rc 900 100 5\nfh 0 0 0\n", &rc) == 0 &&
              rc.hits == 900 && rc.misses == 100 && rc.nocache == 5 && rc.valid,
              "rc: parses hits/misses/nocache");
    expect_ok(parse_nfsd_rc_line("io 1 2\n", &rc) == -1, "rc: missing line is error");
}

static void test_parse_nfsd_rpc_line(void) {
    struct nfsd_rpc r;
    expect_ok(parse_nfsd_rpc_line("net 5 0 5 1\nrpc 1000 3 0 0 0\n", &r) == 0 &&
              r.calls == 1000 && r.badcalls == 3 && r.valid,
              "rpc: parses calls and badcalls");
    expect_ok(parse_nfsd_rpc_line("net 5 0 5 1\n", &r) == -1, "rpc: missing line is error");
}

static void test_count_proc_locks_buf(void) {
    int posix = -1, flock = -1, lease = -1;
    const char *buf =
        "1: POSIX  ADVISORY  WRITE 100 00:23:1 0 EOF\n"
        "2: FLOCK  ADVISORY  READ 101 00:23:2 0 EOF\n"
        "3: POSIX  ADVISORY  READ 102 00:23:3 0 EOF\n"
        "4: LEASE  ACTIVE    READ 103 00:23:4 0 EOF\n";
    expect_ok(count_proc_locks_buf(buf, &posix, &flock, &lease) == 4 &&
              posix == 2 && flock == 1 && lease == 1,
              "locks: counts by type");
}

static void test_tcp_table_count_established(void) {
    const char *table =
        "  sl  local_address rem_address   st ...\n"
        "   0: 00000000:0801 0A000001:1234 01 ...\n"
        "   1: 00000000:0801 0A000002:5678 01 ...\n"
        "   2: 00000000:0801 00000000:0000 0A ...\n";
    FILE *f = fmemopen((void *)table, strlen(table), "r");
    expect_ok(f && tcp_table_count_established(f, 2049) == 2,
              "tcp: counts established on 2049 (not LISTEN)");
    if (f) fclose(f);
}

static void test_parse_nfsd_client_info(void) {
    struct nfsd_client_info ci;
    const char *buf =
        "clientid: 0x1234\n"
        "address: \"10.0.0.5:0\"\n"
        "status: confirmed\n"
        "minor version: 2\n"
        "callback state: UP\n";
    expect_ok(parse_nfsd_client_info(buf, &ci) == 0 &&
              strcmp(ci.address, "10.0.0.5:0") == 0 &&
              ci.minor_version == 2 && ci.callback_up == 1,
              "client info: parses address/minor/callback");

    const char *down =
        "address: \"10.0.0.6:0\"\nminor version: 1\ncallback state: DOWN\n";
    expect_ok(parse_nfsd_client_info(down, &ci) == 0 &&
              ci.minor_version == 1 && ci.callback_up == 0,
              "client info: callback DOWN detected");
}

static void test_count_nfsd_client_states(void) {
    int opens = -1, locks = -1, delegs = -1, layouts = -1;
    const char *buf =
        "- 0x01: { type: open, access: rw }\n"
        "- 0x02: { type: open, access: r }\n"
        "- 0x03: { type: lock }\n"
        "- 0x04: { type: deleg, access: r }\n"
        "- 0x05: { type: layout }\n";
    expect_ok(count_nfsd_client_states(buf, &opens, &locks, &delegs, &layouts) == 5 &&
              opens == 2 && locks == 1 && delegs == 1 && layouts == 1,
              "client states: counts by type");
}

static void test_parse_meminfo_buf(void) {
    struct meminfo_stats m;
    const char *buf =
        "MemTotal:       15743684 kB\n"
        "MemFree:         2955080 kB\n"
        "MemAvailable:    9791408 kB\n"
        "Slab:            1149180 kB\n"
        "SReclaimable:     686684 kB\n";
    expect_ok(parse_meminfo_buf(buf, &m) == 0 && m.valid &&
              m.memtotal_kb == 15743684 && m.memavailable_kb == 9791408 &&
              m.slab_kb == 1149180 && m.sreclaimable_kb == 686684,
              "meminfo: parses totals");
    expect_ok(parse_meminfo_buf("MemFree: 1 kB\n", &m) == -1,
              "meminfo: no MemTotal is error");
}

static void test_parse_rmtab_buf(void) {
    struct rmtab_stats r;
    const char *buf =
        "10.0.0.1:/srv/data:1\n"
        "10.0.0.2:/srv/data:0\n"     /* stale */
        "10.0.0.1:/srv/data:1\n"     /* duplicate host:path */
        "10.0.0.3:/srv/home:2\n";
    expect_ok(parse_rmtab_buf(buf, &r) == 4 && r.entries == 4 &&
              r.hosts == 3 && r.stale == 1 && r.duplicates == 1,
              "rmtab: counts entries, hosts, stale, dups");
    expect_ok(parse_rmtab_buf("", &r) == 0 && r.entries == 0,
              "rmtab: empty is zero");
}

static void test_log_intel_scan(void) {
    struct log_finding f[16];
    const char *buf =
        "May  1 10:00:01 srv kernel: lockd: cannot monitor 10.0.0.5\n"
        "May  1 10:00:02 srv rpc.mountd[9]: refused mount request from 10.0.0.6\n"
        "May  1 10:00:03 srv kernel: lockd: cannot monitor 10.0.0.7\n"
        "May  1 10:00:04 srv systemd: started something harmless\n";
    int n = log_intel_scan(buf, f, 16);
    expect_ok(n == 2, "log-intel: two distinct signatures matched");
    int lockd_count = 0;
    for (int i = 0; i < n; i++)
        if (strstr(f[i].title, "monitor")) lockd_count = f[i].count;
    expect_ok(lockd_count == 2, "log-intel: counts repeated lockd lines");
    expect_ok(log_intel_scan("nothing interesting here\n", f, 16) == 0,
              "log-intel: clean log yields no findings");
}

static void test_hist_log2_bucket(void) {
    expect_ok(hist_log2_bucket(500) == 0,     "hist: <1us -> bucket 0");
    expect_ok(hist_log2_bucket(1000) == 1,    "hist: 1us -> bucket 1");
    expect_ok(hist_log2_bucket(2000) == 2,    "hist: 2us -> bucket 2");
    expect_ok(hist_log2_bucket(3000) == 2,    "hist: 3us -> bucket 2");
    expect_ok(hist_log2_bucket(4000) == 3,    "hist: 4us -> bucket 3");
    expect_ok(hist_log2_bucket(1000000000ULL) >= 20, "hist: 1s -> high bucket");
}

static void test_fmt_client_ip(void) {
    unsigned char v4[16] = { 10, 0, 0, 5 };
    char out[64];
    fmt_client_ip(v4, 2, out, sizeof(out));
    expect_ok(strcmp(out, "10.0.0.5") == 0, "fmt: IPv4");
    unsigned char v6[16] = { 0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1 };
    fmt_client_ip(v6, 10, out, sizeof(out));
    expect_ok(strstr(out, "2001:db8") != NULL && strstr(out, "::1") != NULL, "fmt: IPv6");
}

static void test_export_line_has_fsid(void) {
    struct export_line e; char err[128];
    exports_parse_line("/srv 10.0.0.0/24(rw,fsid=1,sync)\n", 1, &e, err, sizeof(err));
    expect_ok(export_line_has_fsid(&e) == 1, "fsid: present");
    exports_parse_line("/srv 10.0.0.0/24(rw,sync)\n", 1, &e, err, sizeof(err));
    expect_ok(export_line_has_fsid(&e) == 0, "fsid: absent");
}

static void test_path_is_on_own_mount(void) {
    const char *m =
        "/dev/root / ext4 rw 0 0\n"
        "/dev/sdb /var/lib/nfs ext4 rw 0 0\n"
        "sunrpc /var/lib/nfs/rpc_pipefs rpc_pipefs rw 0 0\n";
    expect_ok(path_is_on_own_mount(m, "/var/lib/nfs") == 1, "mount: own mount");
    expect_ok(path_is_on_own_mount("/dev/root / ext4 rw 0 0\n", "/var/lib/nfs") == 0,
              "mount: on rootfs");
}

static void test_parse_ganesha_conf(void) {
    struct ganesha_conf g;
    const char *buf =
        "EXPORT {\n Export_Id = 1;\n Path = /data;\n FSAL { Name = VFS; }\n}\n"
        "EXPORT {\n Export_Id = 2;\n Path = /ceph;\n FSAL { Name = CEPH; }\n}\n";
    expect_ok(parse_ganesha_conf(buf, &g) == 2 && g.export_count == 2,
              "ganesha: two EXPORT blocks");
    int have_vfs = 0, have_ceph = 0;
    for (int i = 0; i < g.fsal_count; i++) {
        if (strcmp(g.fsals[i], "VFS") == 0) have_vfs = 1;
        if (strcmp(g.fsals[i], "CEPH") == 0) have_ceph = 1;
    }
    expect_ok(have_vfs && have_ceph, "ganesha: FSAL VFS and CEPH");
}

static void test_parse_peer_arg(void) {
    char h[256]; int p;
    expect_ok(parse_peer_arg("192.168.0.21", h, sizeof(h), &p, 9100) == 0 &&
              strcmp(h, "192.168.0.21") == 0 && p == 9100, "peer: host only");
    expect_ok(parse_peer_arg("srv:9200", h, sizeof(h), &p, 9100) == 0 &&
              strcmp(h, "srv") == 0 && p == 9200, "peer: host:port");
    expect_ok(parse_peer_arg("[::1]:9300", h, sizeof(h), &p, 9100) == 0 &&
              strcmp(h, "::1") == 0 && p == 9300, "peer: bracketed v6");
    expect_ok(parse_peer_arg("fe80::1", h, sizeof(h), &p, 9100) == 0 &&
              strcmp(h, "fe80::1") == 0 && p == 9100, "peer: bare v6 -> default port");
    expect_ok(parse_peer_arg("", h, sizeof(h), &p, 9100) == -1, "peer: empty is error");
}

static void test_parse_prometheus_gauge(void) {
    const char *buf =
        "# HELP nfsdiag_server_drc_hits Reply cache hits\n"
        "# TYPE nfsdiag_server_drc_hits gauge\n"
        "nfsdiag_server_drc_hits{host=\"x\"} 900\n"
        "nfsdiag_server_rpc_badcalls{host=\"x\"} 7\n";
    double v = -1;
    expect_ok(parse_prometheus_gauge(buf, "nfsdiag_server_drc_hits", &v) == 0 && v == 900,
              "gauge: drc_hits");
    expect_ok(parse_prometheus_gauge(buf, "nfsdiag_server_rpc_badcalls", &v) == 0 && v == 7,
              "gauge: badcalls");
    expect_ok(parse_prometheus_gauge(buf, "nfsdiag_server_missing", &v) == -1,
              "gauge: absent");
}

static void test_peer_verdict(void) {
    char msg[512];
    struct peer_server base = {0}, fin = {0};
    struct peer_client_findings f1 = { .fail = 2, .estale = 0, .min_write_mibs = -1, .min_read_mibs = -1 };
    base.rpc_badcalls = 0; fin.rpc_badcalls = 3; fin.rpc_calls = 100;
    expect_ok(peer_verdict(&f1, &base, &fin, msg, sizeof(msg)) == 1 &&
              strstr(msg, "server-side") && strstr(msg, "bad RPC"), "verdict: server bad calls");
    struct peer_server b2 = {0}, f2 = {0};
    struct peer_client_findings f3 = { .fail = 0, .estale = 0, .min_write_mibs = 3.0, .min_read_mibs = 5.0 };
    f2.rpc_calls = 0;
    expect_ok(peer_verdict(&f3, &b2, &f2, msg, sizeof(msg)) == 1 &&
              strstr(msg, "client/network-side"), "verdict: network side");
    struct peer_server b3 = {0}, f4 = {0};
    struct peer_client_findings f5 = { .fail = 0, .estale = 0, .min_write_mibs = 500.0, .min_read_mibs = 500.0 };
    f4.rpc_calls = 1000;
    expect_ok(peer_verdict(&f5, &b3, &f4, msg, sizeof(msg)) == 0 &&
              strstr(msg, "both sides healthy"), "verdict: healthy");
}

int main(void) {
    test_avg_per_op_ms();
    test_utf8_truncate();
    test_http_request_is_get();
    test_service_missing_severity();
    test_parse_bounded_int();
    test_fopen_regular_ro();
    test_mountinfo_unescape();
    test_csv_append_missing();
    test_parse_ulong_arg();
    test_parse_id_arg();
    test_redact_argv();
    test_validate_host();
    test_validate_export();
    test_validate_mount_options();
    test_parse_listen_arg();
    test_event_metadata();
    test_exports_parse_line();
    test_exports_client_risk();
    test_parse_nfsd_versions();
    test_parse_nfsd_th_line();
    test_comm_matches();
    test_tcp_table_has_listener();
    test_fs_type_helpers();
    test_usage_severity();
    test_exports_security_scan();
    test_parse_idmapd_conf();
    test_krb5_conf_default_realm();
    test_fs_type_acl_capable();
    test_parse_nfsd_rc_line();
    test_parse_nfsd_rpc_line();
    test_count_proc_locks_buf();
    test_tcp_table_count_established();
    test_parse_nfsd_client_info();
    test_count_nfsd_client_states();
    test_parse_meminfo_buf();
    test_parse_rmtab_buf();
    test_log_intel_scan();
    test_hist_log2_bucket();
    test_fmt_client_ip();
    test_export_line_has_fsid();
    test_path_is_on_own_mount();
    test_parse_ganesha_conf();
    test_parse_peer_arg();
    test_parse_prometheus_gauge();
    test_peer_verdict();

    if (failures) {
        fprintf(stderr, "unit-tests failed: %d\n", failures);
        return 1;
    }
    printf("unit-tests passed\n");
    return 0;
}
