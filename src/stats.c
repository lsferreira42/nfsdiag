#include "nfsdiag.h"

/* ---- dependency checks ---- */

static int command_exists(const char *cmd) {
    char resolved[4096];
    return resolve_command_path(cmd, resolved, sizeof(resolved)) == 0;
}

static const char *detected_distro_family(void) {
    static char family[32];
    if (family[0]) return family;
    FILE *f = fopen("/etc/os-release", "r");
    if (!f) {
        snprintf(family, sizeof(family), "unknown");
        return family;
    }
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "ID=", 3) == 0 || strncmp(line, "ID_LIKE=", 8) == 0) {
            if (strstr(line, "debian") || strstr(line, "ubuntu")) {
                snprintf(family, sizeof(family), "debian");
                break;
            }
            if (strstr(line, "fedora") || strstr(line, "rhel") || strstr(line, "centos")) {
                snprintf(family, sizeof(family), "rhel");
                break;
            }
            if (strstr(line, "alpine")) {
                snprintf(family, sizeof(family), "alpine");
                break;
            }
        }
    }
    fclose(f);
    if (!family[0]) snprintf(family, sizeof(family), "unknown");
    return family;
}

static const char *nfs_client_package_hint(void) {
    const char *family = detected_distro_family();
    if (strcmp(family, "debian") == 0) return "Install nfs-common.";
    if (strcmp(family, "rhel") == 0) return "Install nfs-utils.";
    if (strcmp(family, "alpine") == 0) return "Install nfs-utils.";
    return "Install your distribution's NFS client package.";
}

int check_dependencies(void) {
    int ok = 1;

    if (!opt.no_mount) {
        if (!command_exists("mount.nfs") && !command_exists("mount")) {
            fprintf(stderr, "[FATAL] mount/mount.nfs not found. %s\n", nfs_client_package_hint());
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

/* ---- client daemon checks ---- */

void check_client_daemons(void) {
    if (opt.verbose) printf("\n[+] Client daemon checks\n");

    /* skip systemd-specific checks on non-systemd systems */
    if (!command_exists("systemctl")) {
        report_info("systemctl not found; client daemon checks skipped (non-systemd system)");
        return;
    }

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

/* ---- Kerberos detection ---- */

void check_kerberos(void) {
    if (!opt.krb5) return;
    if (opt.verbose) printf("\n[+] Kerberos detection\n");

    char output[CMD_OUTPUT_LIMIT];
    if (access("/etc/krb5.conf", R_OK) == 0)
        report_ok("Kerberos config found at /etc/krb5.conf");
    else
        report_warn("Kerberos config /etc/krb5.conf is not readable: %s", strerror(errno));

    if (access("/etc/krb5.keytab", R_OK) == 0)
        report_info("Kerberos keytab /etc/krb5.keytab is readable");
    else
        report_info("Kerberos keytab /etc/krb5.keytab not readable or absent: %s", strerror(errno));

    if (command_exists("gssproxy")) {
        char *gssproxy_argv[] = {"systemctl", "is-active", "--quiet", "gssproxy.service", NULL};
        if (command_exists("systemctl") && run_command_capture(gssproxy_argv, output, sizeof(output)) == 0)
            report_ok("gssproxy.service is active");
        else
            report_info("gssproxy binary exists; service state not active or unavailable");
    }

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

    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) == 0)
        report_info("client realtime clock available for Kerberos skew checks: %ld", (long)ts.tv_sec);
}

/* ---- RPC stats from /proc/net/rpc/nfs ---- */

int capture_rpc_stats(struct rpc_stats *out) {
    memset(out, 0, sizeof(*out));

    FILE *f = fopen("/proc/net/rpc/nfs", "r");
    if (!f) {
        out->valid = 0;
        return -1;
    }
    int rc = capture_rpc_stats_stream(f, out);
    fclose(f);
    return rc;
}

int capture_rpc_stats_stream(FILE *f, struct rpc_stats *out) {
    char line[1024];
    int net_ok = 0, rpc_ok = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "net ", 4) == 0) {
            net_ok = (sscanf(line, "net %lu %lu %lu",
                       &out->net_count, &out->net_udp, &out->net_tcp) == 3);
        } else if (strncmp(line, "rpc ", 4) == 0) {
            rpc_ok = (sscanf(line, "rpc %lu %lu %lu",
                       &out->rpc_calls, &out->rpc_retrans, &out->rpc_auth_refresh) == 3);
        }
    }
    out->valid = net_ok && rpc_ok;
    return out->valid ? 0 : -1;
}

void report_rpc_stats_diff(const struct rpc_stats *before, const struct rpc_stats *after) {
    if (!before->valid || !after->valid) {
        report_info("RPC stats diff unavailable (/proc/net/rpc/nfs not readable before or after tests)");
        return;
    }

    unsigned long calls, retrans, auth;
    if (after->rpc_calls >= before->rpc_calls)
        calls = after->rpc_calls - before->rpc_calls;
    else { report_warn("RPC call counter reset or wrapped during test"); calls = 0; }
    if (after->rpc_retrans >= before->rpc_retrans)
        retrans = after->rpc_retrans - before->rpc_retrans;
    else { report_warn("RPC retrans counter reset or wrapped during test"); retrans = 0; }
    if (after->rpc_auth_refresh >= before->rpc_auth_refresh)
        auth = after->rpc_auth_refresh - before->rpc_auth_refresh;
    else { report_warn("RPC auth_refresh counter reset or wrapped during test"); auth = 0; }

    report_ok("RPC stats delta: calls=%lu retransmits=%lu auth_refresh=%lu", calls, retrans, auth);

    if (retrans > 0) {
        report_warn("RPC retransmissions detected during test (%lu)", retrans);
        add_recommendation("RPC retransmissions occurred: check network stability, NFS server load, and timeout/retrans mount options.");
    }
    if (auth > 0) {
        report_info("RPC auth refreshes during test: %lu (normal for Kerberos/AUTH_SYS renewal)", auth);
    }
}

/* ---- /proc/self/mountstats parsing ---- */

void parse_mountstats(const char *mountpoint) {
    FILE *f = fopen("/proc/self/mountstats", "r");
    if (!f) {
        report_info("cannot read /proc/self/mountstats: %s", strerror(errno));
        return;
    }
    parse_mountstats_stream(f, mountpoint);
    fclose(f);
}

void parse_mountstats_stream(FILE *f, const char *mountpoint) {
    char line[2048];
    int found = 0;
    int in_section = 0;

    while (fgets(line, sizeof(line), f)) {
        /* device lines start with "device " */
        if (strncmp(line, "device ", 7) == 0) {
            /* Parse "device <src> mounted on <mp> with fstype <type>" exactly */
            char *mop = strstr(line, " mounted on ");
            int matched = 0;
            if (mop) {
                char *mp_start = mop + 12;
                const char *mp_end = strstr(mp_start, " with fstype");
                if (mp_end) {
                    size_t mp_len = (size_t)(mp_end - mp_start);
                    char dev_mp[4096] = {0};
                    if (mp_len < sizeof(dev_mp)) {
                        memcpy(dev_mp, mp_start, mp_len);
                        matched = (strcmp(dev_mp, mountpoint) == 0);
                    }
                }
            }
            if (matched) {
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
        const char *trimmed = line;
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
                double avg_rtt = (double)rtt_us / (double)ops / 1000.0;
                report_info("mountstats %s ops=%lu trans=%lu timeouts=%lu avg_rtt=%.2fms",
                           opname, ops, trans, timeouts, avg_rtt);
                if (timeouts > 0) {
                    report_warn("mountstats shows %lu timeouts for %s",
                               timeouts, opname);
                }
            }
        }
    }

    if (!found) report_info("mountstats entry not found for %s", mountpoint);
}

/* ---- mount options verification via /proc/self/mountinfo ---- */

void verify_mount_options(const char *mountpoint, struct export_report *report) {
    FILE *f = fopen("/proc/self/mountinfo", "r");
    if (!f) {
        report_info("cannot read /proc/self/mountinfo: %s", strerror(errno));
        return;
    }
    verify_mount_options_stream(f, mountpoint, report);
    fclose(f);
}

void verify_mount_options_stream(FILE *f, const char *mountpoint,
                                 struct export_report *report) {
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
        const char *sep = strstr(line, " - ");
        if (!sep) continue;
        if (sscanf(sep + 3, "%255s %4095s %2047s", fstype, source, super_opts) < 2)
            continue;

        char combined[4097]; /* 2048 + comma + 2048 */
        int cn = snprintf(combined, sizeof(combined), "%s,%s", mount_opts, super_opts);
        if (cn < 0 || (size_t)cn >= sizeof(combined))
            report_warn("effective mount options were truncated; some options may not be shown");
        snprintf(report->effective_mount_opts, sizeof(report->effective_mount_opts), "%.2047s", combined);

        report_ok("effective mount options for %s: %s", mountpoint, combined);

        /* check for notable options — compare exact comma-separated tokens */
        char opt_copy[4097];
        snprintf(opt_copy, sizeof(opt_copy), "%s", combined);
        char *save_opt = NULL;
        int has_hard = 0, has_soft = 0, has_noatime = 0, has_nconnect = 0;
        for (const char *tok = strtok_r(opt_copy, ",", &save_opt); tok;
             tok = strtok_r(NULL, ",", &save_opt)) {
            if (strcmp(tok, "hard")    == 0) has_hard    = 1;
            if (strcmp(tok, "soft")    == 0) has_soft    = 1;
            if (strcmp(tok, "noatime") == 0) has_noatime = 1;
            /* nconnect=N: check prefix */
            if (strncmp(tok, "nconnect", 8) == 0 &&
                (tok[8] == '\0' || tok[8] == '=')) has_nconnect = 1;
        }
        if (has_hard)     report_info("mount is 'hard' (will retry indefinitely on server failure)");
        if (has_soft)     report_info("mount is 'soft' (will return errors on timeout)");
        if (has_noatime)  report_info("noatime is set (reduces GETATTR calls)");
        if (has_nconnect) report_info("nconnect detected (multiple TCP connections per mount)");

        return;
    }

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

/* ---- /proc/fs/nfsfs/servers check ---- */

void check_nfsfs_servers(const char *mountpoint) {
    (void)mountpoint; /* used for context only */

    FILE *f = fopen("/proc/fs/nfsfs/servers", "r");
    if (!f) {
        /* Not all kernels expose this; silently skip */
        return;
    }

    char line[512];
    int header_skipped = 0;
    while (fgets(line, sizeof(line), f)) {
        /* Skip the header line ("NV SERVER PORT USE HOSTNAME") */
        if (!header_skipped) { header_skipped = 1; continue; }

        /* Kernel format (fs/nfs/client.c nfs_server_list_show):
         *   NV SERVER   PORT USE HOSTNAME
         *   v4 7f000001  801   1 127.0.0.1
         * Fields: protocol version, hex address, hex port, usecount, hostname.
         * (This file does not expose lease time.) */
        char nv[8] = {0}, addr[64] = {0}, port[16] = {0}, hostname[128] = {0};
        int use = 0;

        int n = sscanf(line, "%7s %63s %15s %d %127s", nv, addr, port, &use, hostname);
        if (n < 5) continue;

        report_info("NFS server %s: protocol=%s active_mounts=%d",
                    hostname[0] ? hostname : "(unknown)", nv, use);
    }
    fclose(f);
}
