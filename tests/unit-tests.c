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

int main(void) {
    test_parse_ulong_arg();
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
