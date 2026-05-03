#include "nfsdiag.h"

/* ---- dependency checks ---- */

static int command_exists(const char *cmd) {
    char check[512];
    snprintf(check, sizeof(check), "command -v %s >/dev/null 2>&1", cmd);
    return system(check) == 0;
}

int check_dependencies(void) {
    int ok = 1;

    if (!opt.no_mount) {
        if (!command_exists("mount.nfs") && !command_exists("mount")) {
            fprintf(stderr, "[FATAL] mount/mount.nfs not found. Install nfs-common (Debian/Ubuntu) or nfs-utils (Fedora/RHEL).\n");
            ok = 0;
        }
        if (!command_exists("umount")) {
            fprintf(stderr, "[FATAL] umount not found.\n");
            ok = 0;
        }
    }

    if (opt.krb5 && !command_exists("klist")) {
        fprintf(stderr, "[FATAL] klist not found. Install krb5-user (Debian/Ubuntu) or krb5-workstation (Fedora/RHEL) for --krb5 support.\n");
        ok = 0;
    }

    return ok;
}

/* ---- client daemon checks (item 8) ---- */

void check_client_daemons(void) {
    if (opt.verbose) printf("\n[+] Client daemon checks\n");

    char output[CMD_OUTPUT_LIMIT];

    /* check rpcbind */
    char *rpcbind_argv[] = {"systemctl", "is-active", "--quiet", "rpcbind.service", NULL};
    int rc = run_command_capture(rpcbind_argv, output, sizeof(output));
    if (rc == 0) report_ok("rpcbind.service is active on this client");
    else report_warn("rpcbind.service is not active on this client; some RPC operations may fail");

    /* check nfs-client.target */
    char *nfs_argv[] = {"systemctl", "is-active", "--quiet", "nfs-client.target", NULL};
    rc = run_command_capture(nfs_argv, output, sizeof(output));
    if (rc == 0) report_ok("nfs-client.target is active on this client");
    else report_warn("nfs-client.target is not active; NFS mounts may fail");

    /* check rpc.idmapd or nfsidmap (NFSv4 id mapping) */
    char *idmapd_argv[] = {"systemctl", "is-active", "--quiet", "nfs-idmapd.service", NULL};
    rc = run_command_capture(idmapd_argv, output, sizeof(output));
    if (rc == 0) report_ok("nfs-idmapd.service is active (NFSv4 id mapping available)");
    else report_info("nfs-idmapd.service not active; NFSv4 id mapping may use alternative or kernel-based mapping");

    /* check rpc.gssd if kerberos requested */
    if (opt.krb5) {
        char *gssd_argv[] = {"systemctl", "is-active", "--quiet", "rpc-gssd.service", NULL};
        rc = run_command_capture(gssd_argv, output, sizeof(output));
        if (rc == 0) report_ok("rpc-gssd.service is active (Kerberos NFS support available)");
        else {
            report_fail("rpc-gssd.service is not active; Kerberos NFS authentication will not work");
            add_recommendation("rpc-gssd is not running: start rpc-gssd.service and ensure /etc/krb5.keytab or gssproxy is configured.");
        }
    }
}

/* ---- Kerberos detection (item 10) ---- */

void check_kerberos(void) {
    if (!opt.krb5) return;
    if (opt.verbose) printf("\n[+] Kerberos detection\n");

    char output[CMD_OUTPUT_LIMIT];
    char *klist_argv[] = {"klist", "-s", NULL};
    int rc = run_command_capture(klist_argv, output, sizeof(output));
    if (rc == 0) {
        report_ok("valid Kerberos ticket found (klist -s succeeded)");

        /* show ticket info */
        char *klist_info_argv[] = {"klist", NULL};
        memset(output, 0, sizeof(output));
        rc = run_command_capture(klist_info_argv, output, sizeof(output));
        if (rc == 0 && output[0]) report_info("Kerberos tickets:\n%s", output);
    } else {
        report_fail("no valid Kerberos ticket found (klist -s failed)");
        add_recommendation("No Kerberos ticket: run kinit to obtain a ticket before testing with --krb5.");
    }
}

/* ---- RPC stats from /proc/net/rpc/nfs (item 7) ---- */

int capture_rpc_stats(struct rpc_stats *out) {
    memset(out, 0, sizeof(*out));

    FILE *f = fopen("/proc/net/rpc/nfs", "r");
    if (!f) {
        out->valid = 0;
        return -1;
    }

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "net ", 4) == 0) {
            sscanf(line, "net %lu %lu %lu",
                   &out->net_count, &out->net_udp, &out->net_tcp);
        } else if (strncmp(line, "rpc ", 4) == 0) {
            sscanf(line, "rpc %lu %lu %lu",
                   &out->rpc_calls, &out->rpc_retrans, &out->rpc_auth_refresh);
        }
    }
    fclose(f);
    out->valid = 1;
    return 0;
}

void report_rpc_stats_diff(const struct rpc_stats *before, const struct rpc_stats *after) {
    if (!before->valid || !after->valid) {
        report_info("RPC stats diff unavailable (/proc/net/rpc/nfs not readable before or after tests)");
        return;
    }

    unsigned long calls = after->rpc_calls - before->rpc_calls;
    unsigned long retrans = after->rpc_retrans - before->rpc_retrans;
    unsigned long auth = after->rpc_auth_refresh - before->rpc_auth_refresh;

    report_ok("RPC stats delta: calls=%lu retransmits=%lu auth_refresh=%lu", calls, retrans, auth);

    if (retrans > 0) {
        report_warn("RPC retransmissions detected during test (%lu)", retrans);
        add_recommendation("RPC retransmissions occurred: check network stability, NFS server load, and timeout/retrans mount options.");
    }
    if (auth > 0) {
        report_info("RPC auth refreshes during test: %lu (normal for Kerberos/AUTH_SYS renewal)", auth);
    }
}

/* ---- /proc/self/mountstats parsing (item 12) ---- */

void parse_mountstats(const char *mountpoint) {
    FILE *f = fopen("/proc/self/mountstats", "r");
    if (!f) {
        report_info("cannot read /proc/self/mountstats: %s", strerror(errno));
        return;
    }

    char line[2048];
    int found = 0;
    int in_section = 0;

    while (fgets(line, sizeof(line), f)) {
        /* device lines start with "device " */
        if (strncmp(line, "device ", 7) == 0) {
            if (strstr(line, mountpoint)) {
                found = 1;
                in_section = 1;
                if (opt.verbose) report_info("mountstats for %s: %s", mountpoint, line);
            } else {
                in_section = 0;
            }
            continue;
        }

        if (!in_section) continue;

        /* parse per-operation stats */
        char *trimmed = line;
        while (*trimmed == ' ' || *trimmed == '\t') trimmed++;

        /* look for key operations: READ, WRITE, GETATTR, LOOKUP, ACCESS */
        char opname[64];
        unsigned long ops = 0, trans = 0, timeouts = 0;
        unsigned long bytes_sent = 0, bytes_recv = 0;
        unsigned long queue_us = 0, rtt_us = 0, exec_us = 0;

        if (sscanf(trimmed, "%63s %lu %lu %lu %lu %lu %lu %lu %lu",
                   opname, &ops, &trans, &timeouts, &bytes_sent, &bytes_recv,
                   &queue_us, &rtt_us, &exec_us) >= 2) {
            /* strip trailing colon */
            size_t len = strlen(opname);
            if (len > 0 && opname[len - 1] == ':') {
                opname[len - 1] = '\0';
            }
            
            /* look for pNFS operations */
            if (ops > 0 && (strcmp(opname, "LAYOUTGET") == 0 ||
                            strcmp(opname, "LAYOUTCOMMIT") == 0 ||
                            strcmp(opname, "LAYOUTRETURN") == 0)) {
                report_info("pNFS active: mountstats shows %lu %s operations", ops, opname);
            }

            /* only report interesting operations with activity */
            if (ops > 0 && (strcmp(opname, "READ") == 0 ||
                            strcmp(opname, "WRITE") == 0 ||
                            strcmp(opname, "GETATTR") == 0 ||
                            strcmp(opname, "LOOKUP") == 0 ||
                            strcmp(opname, "ACCESS") == 0)) {
                double avg_rtt = ops > 0 ? (double)rtt_us / (double)ops / 1000.0 : 0;
                report_info("mountstats %s ops=%lu trans=%lu timeouts=%lu avg_rtt=%.2fms",
                           opname, ops, trans, timeouts, avg_rtt);
                if (timeouts > 0) {
                    report_warn("mountstats shows %lu timeouts for %s",
                               timeouts, opname);
                }
            }
        }
    }

    fclose(f);
    if (!found) report_info("mountstats entry not found for %s", mountpoint);
}

/* ---- mount options verification via /proc/self/mountinfo (item 13) ---- */

void verify_mount_options(const char *mountpoint, struct export_report *report) {
    FILE *f = fopen("/proc/self/mountinfo", "r");
    if (!f) {
        report_info("cannot read /proc/self/mountinfo: %s", strerror(errno));
        return;
    }

    char line[4096];
    while (fgets(line, sizeof(line), f)) {
        /* format: id parent major:minor root mount_point mount_options optional ... - type source super_options */
        char mp[4096], mount_opts[2048], fstype[256], source[4096], super_opts[2048];
        int id, parent, n;
        unsigned int major, minor;
        char root[4096];

        n = sscanf(line, "%d %d %u:%u %4095s %4095s %2047s",
                   &id, &parent, &major, &minor, root, mp, mount_opts);
        if (n < 7) continue;
        if (strcmp(mp, mountpoint) != 0) continue;

        /* find the " - " separator for fs type and super options */
        char *sep = strstr(line, " - ");
        if (!sep) continue;
        if (sscanf(sep + 3, "%255s %4095s %2047s", fstype, source, super_opts) < 2)
            continue;

        char combined[4096];
        snprintf(combined, sizeof(combined), "%s,%s", mount_opts, super_opts);
        snprintf(report->effective_mount_opts, sizeof(report->effective_mount_opts), "%.2047s", combined);

        report_ok("effective mount options for %s: %s", mountpoint, combined);

        /* check for notable options */
        if (strstr(combined, "hard")) report_info("mount is 'hard' (will retry indefinitely on server failure)");
        if (strstr(combined, "soft")) report_info("mount is 'soft' (will return errors on timeout)");
        if (strstr(combined, "noatime")) report_info("noatime is set (reduces GETATTR calls)");
        if (strstr(combined, "nconnect")) report_info("nconnect detected (multiple TCP connections per mount)");

        fclose(f);
        return;
    }

    fclose(f);
    report_info("mountinfo entry not found for %s", mountpoint);
}

/* ---- system info collection ---- */

void collect_system_info(struct system_info *si) {
    memset(si, 0, sizeof(*si));
    struct utsname u;
    if (uname(&u) == 0) {
        snprintf(si->kernel, sizeof(si->kernel), "%.255s %.255s", u.sysname, u.release);
        snprintf(si->hostname, sizeof(si->hostname), "%.255s", u.nodename);
        snprintf(si->arch, sizeof(si->arch), "%.63s", u.machine);
    }
}
