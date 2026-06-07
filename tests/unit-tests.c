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

int main(void) {
    char reason[256];
    char id1[MAX_CHECK_ID], id2[MAX_CHECK_ID];

    expect_ok(validate_host_arg("nfs.example.com", reason, sizeof(reason)) == 0,
              "valid hostname");
    expect_ok(validate_host_arg("bad host", reason, sizeof(reason)) != 0,
              "reject host whitespace");
    expect_ok(validate_host_arg("bad/path", reason, sizeof(reason)) != 0,
              "reject host slash");

    expect_ok(validate_export_path("/export/data", reason, sizeof(reason)) == 0,
              "valid export");
    expect_ok(validate_export_path("relative", reason, sizeof(reason)) != 0,
              "reject relative export");
    expect_ok(validate_export_path("/export/../secret", reason, sizeof(reason)) != 0,
              "reject parent export component");

    expect_ok(validate_mount_options("hard,timeo=30,retrans=2", 0, reason, sizeof(reason)) == 0,
              "valid mount options");
    expect_ok(validate_mount_options("exec", 0, reason, sizeof(reason)) != 0,
              "reject risky mount option");
    expect_ok(validate_mount_options("exec", 1, reason, sizeof(reason)) == 0,
              "allow risky mount option explicitly");

    event_check_id(id1, sizeof(id1), "warn", "network", "rpcbind TCP port 111 unreachable");
    event_check_id(id2, sizeof(id2), "warn", "network", "rpcbind TCP port 111 unreachable");
    expect_ok(strcmp(id1, id2) == 0 && strstr(id1, "network.") == id1,
              "stable event id");
    expect_ok(strcmp(event_category_for_message("fail", "Kerberos ticket missing"), "auth") == 0,
              "event category auth");
    expect_ok(event_remediation_for("network", "")[0] != '\0',
              "network remediation");

    if (failures) {
        fprintf(stderr, "unit-tests failed: %d\n", failures);
        return 1;
    }
    printf("unit-tests passed\n");
    return 0;
}
