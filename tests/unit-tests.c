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

    if (failures) {
        fprintf(stderr, "unit-tests failed: %d\n", failures);
        return 1;
    }
    printf("unit-tests passed\n");
    return 0;
}
