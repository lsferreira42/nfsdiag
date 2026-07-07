/* server.c - `nfsdiag server`: diagnose the local NFS server.
 *
 * This namespace runs on the NFS server itself. Each check reports through
 * report.c so JSON/HTML/exit-code behaviour matches the client namespace.
 */
#include "nfsdiag.h"
#include <errno.h>
#include <getopt.h>
#include <sys/vfs.h>

struct server_options server_opt = {
    .exports_audit = 0,
    .exports_file  = "/etc/exports",
    .root          = "/",
    .verbose       = 0,
    .quiet         = 0,
};

static void server_usage(FILE *f) {
    fprintf(f, "Usage: nfsdiag server [OPTIONS]\n");
    fprintf(f, "\nRuns diagnostics on the local NFS server. At least one check is required.\n");
    fprintf(f, "\nChecks:\n");
    fprintf(f, "      --all                  Run every server check\n");
    fprintf(f, "      --daemons              Check nfsd, rpcbind, mountd, statd, idmapd and gss daemons\n");
    fprintf(f, "      --exports-audit        Audit /etc/exports and the live export table\n");
    fprintf(f, "      --ports-firewall       Check NFS listeners and firewall rules for the NFS ports\n");
    fprintf(f, "      --idmap-check          Validate idmapd.conf domain and nobody mapping\n");
    fprintf(f, "      --krb5-server          Validate server-side Kerberos: keytab, realm, gss daemons, clock\n");
    fprintf(f, "      --acl-check            Verify POSIX ACL support on the filesystem under each export\n");
    fprintf(f, "      --squash-check         Mount each export from localhost and verify root squashing\n");
    fprintf(f, "                              (intrusive: mounts and writes; not included in --all; needs root)\n");
    fprintf(f, "      --security-audit       Deep exports analysis: legacy/risky options, duplicates, nesting\n");
    fprintf(f, "      --storage-health       Inspect the filesystem under each export (space, inodes, type)\n");
    fprintf(f, "      --version-matrix       Report enabled NFS versions, lease/grace times, block size\n");
    fprintf(f, "      --sysctl-advisor       Inspect nfsd thread starvation and network tunables\n");
    fprintf(f, "      --rpc-stats            Analyze /proc/net/rpc/nfsd: reply cache, bad calls, traffic\n");
    fprintf(f, "      --locks                Summarize held locks, NFSv4 lease/grace, NLM/NSM registration\n");
    fprintf(f, "      --clients              Inventory connected NFSv4 clients and their callback state\n");
    fprintf(f, "      --client-states        Count NFSv4 opens/locks/delegations/layouts per client\n");
    fprintf(f, "      --latency-profile      eBPF: per-op nfsd latency histogram (needs root and an eBPF build)\n");
    fprintf(f, "      --per-client-trace     eBPF: per-client nfsd ops and average latency\n");
    fprintf(f, "      --backend-bench        Benchmark the storage under each export (raw disk ceiling)\n");
    fprintf(f, "      --capture              Capture NFS traffic on port 2049 with tcpdump\n");
    fprintf(f, "      --duration SEC         Sampling window for latency/per-client/capture (default 10)\n");
    fprintf(f, "      --ha-check             Validate HA: fsid, shared NFS state, pacemaker resources\n");
    fprintf(f, "      --ganesha-check        Detect nfs-ganesha vs kernel nfsd and container/k8s context\n");
    fprintf(f, "      --memory-pressure      Assess memory pressure on the DRC and dentry/inode caches\n");
    fprintf(f, "      --rmtab-audit          Detect stale rmtab/NSM entries that bloat sm-notify\n");
    fprintf(f, "      --log-intel            Correlate nfsd/mountd/statd log messages with known issues\n");
    fprintf(f, "\nCheck options:\n");
    fprintf(f, "      --exports-file FILE    Exports file to audit. Default: /etc/exports\n");
    fprintf(f, "      --audit-trail          Capture config snapshots and checksums into --output-dir\n");
    fprintf(f, "\nOutput options:\n");
    fprintf(f, "      --root DIR             Read /proc and /etc under DIR (e.g. an extracted sosreport)\n");
    fprintf(f, "      --json[=PATH]          Emit JSON report to PATH (use '-' or omit for stdout)\n");
    fprintf(f, "      --html[=PATH]          Emit HTML report to PATH (use '-' or omit for stdout)\n");
    fprintf(f, "      --output-format FMT    Terminal output: text (default), table, ndjson, prometheus, junit\n");
    fprintf(f, "      --output-dir DIR       Write JSON, HTML, evidence and checksums to DIR\n");
    fprintf(f, "      --watch SEC            Re-run the selected checks every SEC seconds until interrupted\n");
    fprintf(f, "      --listen [ADDR:]PORT   Serve Prometheus server metrics over HTTP; binds 127.0.0.1\n");
    fprintf(f, "  -v, --verbose              Show all diagnostic steps\n");
    fprintf(f, "  -q, --quiet                Suppress human stdout\n");
    fprintf(f, "  -V, --version              Print version and exit\n");
    fprintf(f, "  -h, --help                 Show this help\n");
    fprintf(f, "\nExit codes: 0=pass  1=warn/fail  2=usage/runtime error\n");
}

static const char *server_rooted(char *buf, size_t sz, const char *abs_path) {
    if (strcmp(server_opt.root, "/") == 0)
        return abs_path;
    snprintf(buf, sz, "%s%s", server_opt.root, abs_path);
    return buf;
}

/* Read a small rooted file into buf. 0 = ok, -1 = missing/unreadable. */
static int server_read_file(const char *abs_path, char *buf, size_t sz) {
    char pbuf[4352];
    FILE *f = fopen(server_rooted(pbuf, sizeof(pbuf), abs_path), "r");
    if (!f) return -1;
    size_t n = fread(buf, 1, sz - 1, f);
    fclose(f);
    buf[n] = '\0';
    return 0;
}

static void report_version_state(const char *name, int state) {
    if (state == 1)      report_ok("%s: enabled", name);
    else if (state == 0) report_info("%s: disabled", name);
    else                 report_info("%s: not reported by this kernel", name);
}

static void server_check_version_matrix(void) {
    char buf[512];
    if (server_read_file("/proc/fs/nfsd/versions", buf, sizeof(buf)) != 0) {
        report_warn("version matrix: nfsd not loaded (no /proc/fs/nfsd/versions); "
                    "start nfs-server or modprobe nfsd");
        return;
    }
    struct nfsd_versions v;
    if (parse_nfsd_versions(buf, &v) != 0) {
        report_warn("version matrix: cannot parse /proc/fs/nfsd/versions: '%s'", buf);
        return;
    }
    report_version_state("NFSv3", v.v3);
    report_version_state("NFSv4", v.v4);
    report_version_state("NFSv4.1", v.v4_1);
    report_version_state("NFSv4.2", v.v4_2);
    if (v.v3 != 1 && v.v4 != 1)
        report_warn("no NFS version is enabled");

    long threads, lease, grace, blksz;
    if (server_read_file("/proc/fs/nfsd/threads", buf, sizeof(buf)) == 0 &&
        (threads = atol(buf)) >= 0)
        report_info("nfsd threads: %ld", threads);
    if (server_read_file("/proc/fs/nfsd/nfsv4leasetime", buf, sizeof(buf)) == 0 &&
        (lease = atol(buf)) > 0)
        report_ok("NFSv4 lease time: %lds", lease);
    if (server_read_file("/proc/fs/nfsd/nfsv4gracetime", buf, sizeof(buf)) == 0 &&
        (grace = atol(buf)) > 0)
        report_info("NFSv4 grace time: %lds", grace);
    if (server_read_file("/proc/fs/nfsd/max_block_size", buf, sizeof(buf)) == 0 &&
        (blksz = atol(buf)) > 0)
        report_info("max block size: %ld bytes", blksz);
}

static int server_live(void) { return strcmp(server_opt.root, "/") == 0; }

static int server_proc_has_comm(const char *name) {
    char pbuf[4352];
    DIR *d = opendir(server_rooted(pbuf, sizeof(pbuf), "/proc"));
    if (!d) return -1;
    const struct dirent *de;
    int found = 0;
    while (!found && (de = readdir(d)) != NULL) {
        if (de->d_name[0] < '1' || de->d_name[0] > '9')
            continue;
        char comm_path[512], comm[64];
        snprintf(comm_path, sizeof(comm_path), "/proc/%s/comm", de->d_name);
        if (server_read_file(comm_path, comm, sizeof(comm)) == 0 &&
            comm_matches(comm, name))
            found = 1;
    }
    closedir(d);
    return found;
}

static void server_report_daemon(const char *name, int required) {
    int r = server_proc_has_comm(name);
    if (r == 1)
        report_ok("%s: running", name);
    else if (r == 0 && required)
        report_warn("%s: not running", name);
    else if (r == 0)
        report_info("%s: not running", name);
    else
        report_warn("%s: cannot scan /proc for processes", name);
}

static void server_check_daemons(void) {
    char buf[64];
    long threads = -1;
    if (server_read_file("/proc/fs/nfsd/threads", buf, sizeof(buf)) == 0)
        threads = atol(buf);
    if (threads > 0)
        report_ok("kernel nfsd: running with %ld threads", threads);
    else
        report_fail("kernel nfsd: not running (start nfs-server)");

    server_report_daemon("rpcbind", 1);
    server_report_daemon("rpc.mountd", 1);
    server_report_daemon("rpc.statd", 1);
    server_report_daemon("rpc.idmapd", 0);
    if (server_proc_has_comm("gssproxy") != 1 &&
        server_proc_has_comm("rpc.svcgssd") != 1)
        report_info("gssproxy/rpc.svcgssd: not running (only needed for sec=krb5*)");
    else
        report_ok("gssproxy or rpc.svcgssd: running");

    if (!server_live()) {
        report_info("rpcbind registration check skipped under --root");
        return;
    }
    struct rpc_services svc = {0};
    if (rpcb_dump_services("127.0.0.1", &svc) != 0) {
        report_warn("rpcbind: cannot dump local service registrations");
        return;
    }
    report_ok("rpcbind: answering on localhost");
    if (rpc_services_has(&svc, NFS_PROGRAM))
        report_ok("nfs program registered in rpcbind");
    else
        report_warn("nfs program not registered in rpcbind");
    if (rpc_services_has(&svc, MOUNT_PROGRAM))
        report_ok("mountd program registered in rpcbind");
    else
        report_warn("mountd program not registered in rpcbind (NFSv3 mounts will fail)");
    if (!rpc_services_has(&svc, NLM_PROGRAM))
        report_info("nlockmgr not registered (fine on NFSv4-only servers)");
    if (!rpc_services_has(&svc, NSM_PROGRAM))
        report_info("status (NSM) not registered (fine on NFSv4-only servers)");
    free(svc.items);
}

static int server_port_listening(unsigned port) {
    char pbuf[4352];
    int found = 0;
    const char *tables[] = { "/proc/net/tcp", "/proc/net/tcp6" };
    for (size_t i = 0; i < 2 && !found; i++) {
        FILE *f = fopen(server_rooted(pbuf, sizeof(pbuf), tables[i]), "r");
        if (!f) continue;
        if (tcp_table_has_listener(f, port) == 1)
            found = 1;
        fclose(f);
    }
    return found;
}

static void server_report_port(const char *name, unsigned port, int required) {
    if (server_port_listening(port)) {
        report_ok("%s port %u: listening", name, port);
    } else if (required) {
        report_fail("%s port %u: not listening", name, port);
    } else {
        report_info("%s port %u: not listening", name, port);
    }
}

static void server_check_ports_firewall(void) {
    server_report_port("nfs", NFS_PORT, 1);
    server_report_port("rpcbind", RPCBIND_PORT, 1);

    if (!server_live()) {
        report_info("dynamic port and firewall check skipped under --root");
        return;
    }

    struct rpc_services svc = {0};
    if (rpcb_dump_services("127.0.0.1", &svc) == 0) {
        for (size_t i = 0; i < svc.len; i++) {
            if (svc.items[i].prog != MOUNT_PROGRAM &&
                svc.items[i].prog != NLM_PROGRAM &&
                svc.items[i].prog != NSM_PROGRAM)
                continue;
            if (svc.items[i].prot != IPPROTO_TCP || svc.items[i].port == 0)
                continue;
            report_info("%s registered on tcp port %lu (dynamic unless pinned in "
                        "/etc/nfs.conf)", rpc_program_name(svc.items[i].prog),
                        svc.items[i].port);
        }
        free(svc.items);
    }

    /* Firewall: best effort, never a verdict when inconclusive. */
    char out[CMD_OUTPUT_LIMIT];
    char *nft[] = {"nft", "list", "ruleset", NULL};
    char *fwd[] = {"firewall-cmd", "--list-all", NULL};
    if (run_command_capture(fwd, out, sizeof(out)) == 0) {
        if (strstr(out, "nfs") || strstr(out, "2049"))
            report_ok("firewalld: nfs service/port present in the active zone");
        else
            report_warn("firewalld is active but the nfs service is not in the "
                        "active zone (firewall-cmd --add-service=nfs)");
    } else if (run_command_capture(nft, out, sizeof(out)) == 0) {
        if (strstr(out, "2049"))
            report_ok("nftables: a rule mentions port 2049");
        else if (strstr(out, "drop") || strstr(out, "reject"))
            report_warn("nftables has drop/reject rules and none mentions 2049; "
                        "verify NFS ports are allowed");
        else
            report_info("nftables ruleset present; no NFS-specific rule found");
    } else {
        report_info("no firewalld or nft tooling found; firewall check skipped");
    }
}

#define ADVISOR_MIN_SOCK_BUF (16 * 1024 * 1024)

static void server_check_sysctl_advisor(void) {
    char buf[2048];
    struct nfsd_th_stats th;

    if (server_read_file("/proc/net/rpc/nfsd", buf, sizeof(buf)) != 0 ||
        parse_nfsd_th_line(buf, &th) != 0) {
        report_warn("sysctl advisor: no nfsd RPC stats (/proc/net/rpc/nfsd); "
                    "is the NFS server running?");
    } else {
        if (th.busy_all > 1.0) {
            report_warn("all %ld nfsd threads busy for %.1fs since boot: "
                        "requests queued waiting for a thread", th.threads, th.busy_all);
            add_recommendation("increase nfsd threads (echo N > /proc/fs/nfsd/threads "
                               "or RPCNFSDCOUNT); current: %ld", th.threads);
        } else {
            report_ok("nfsd threads: %ld, no starvation recorded", th.threads);
        }
        if (server_live()) {
            long cpus = sysconf(_SC_NPROCESSORS_ONLN);
            if (cpus > 0 && th.threads > 0 && th.threads < cpus)
                report_info("nfsd threads (%ld) below CPU count (%ld); busy servers "
                            "usually run at least one thread per CPU", th.threads, cpus);
        }
    }

    long rmem = -1, wmem = -1;
    if (server_read_file("/proc/sys/net/core/rmem_max", buf, sizeof(buf)) == 0)
        rmem = atol(buf);
    if (server_read_file("/proc/sys/net/core/wmem_max", buf, sizeof(buf)) == 0)
        wmem = atol(buf);
    if (rmem >= 0 && rmem < ADVISOR_MIN_SOCK_BUF) {
        report_warn("net.core.rmem_max=%ld is low for NFS servers", rmem);
        add_recommendation("raise net.core.rmem_max to at least %d", ADVISOR_MIN_SOCK_BUF);
    } else if (rmem >= ADVISOR_MIN_SOCK_BUF) {
        report_ok("net.core.rmem_max: %ld", rmem);
    }
    if (wmem >= 0 && wmem < ADVISOR_MIN_SOCK_BUF) {
        report_warn("net.core.wmem_max=%ld is low for NFS servers", wmem);
        add_recommendation("raise net.core.wmem_max to at least %d", ADVISOR_MIN_SOCK_BUF);
    } else if (wmem >= ADVISOR_MIN_SOCK_BUF) {
        report_ok("net.core.wmem_max: %ld", wmem);
    }

    long blksz;
    if (server_read_file("/proc/fs/nfsd/max_block_size", buf, sizeof(buf)) == 0 &&
        (blksz = atol(buf)) > 0 && blksz < 1048576)
        report_info("max_block_size=%ld; 1 MiB is typical for modern networks", blksz);
}

static void server_check_exports_audit(void) {
    char pbuf[4352];
    FILE *f = fopen(server_rooted(pbuf, sizeof(pbuf), server_opt.exports_file), "r");
    if (!f) {
        report_fail("exports: cannot open %s: %s", server_opt.exports_file,
                    strerror(errno));
        return;
    }

    int findings = 0, entries = 0;
    char line[1024], err[256], why[256];
    struct export_line e;
    int lineno = 0;

    while (fgets(line, sizeof(line), f)) {
        lineno++;
        int r = exports_parse_line(line, lineno, &e, err, sizeof(err));
        if (r == 0)
            continue;
        if (r == -1) {
            report_fail("exports: %s", err);
            findings++;
            continue;
        }
        entries++;
        for (int i = 0; i < e.client_count; i++) {
            int risk = exports_client_risk(e.clients[i], why, sizeof(why));
            if (risk == 1) {
                report_warn("exports %s: %s", e.path, why);
                findings++;
            } else if (risk == -1) {
                report_fail("exports %s line %d: %s", e.path, e.lineno, why);
                findings++;
            } else if (server_opt.verbose) {
                report_info("exports %s: %s ok", e.path, e.clients[i]);
            }
        }
    }
    fclose(f);

    if (entries == 0 && findings == 0)
        report_warn("exports: %s defines no exports", server_opt.exports_file);
    else if (findings == 0)
        report_ok("exports: %d entr%s audited, no findings",
                  entries, entries == 1 ? "y" : "ies");
}

static void server_storage_inspect(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        report_fail("export %s: directory missing (%s)", path, strerror(errno));
        return;
    }
    if (!S_ISDIR(st.st_mode)) {
        report_fail("export %s: not a directory", path);
        return;
    }

    struct statfs sfs;
    if (statfs(path, &sfs) == 0) {
        char why[256];
        const char *name = fs_type_name((long)sfs.f_type);
        if (fs_type_unsuitable((long)sfs.f_type, why, sizeof(why)))
            report_warn("export %s: %s", path, why);
        else
            report_ok("export %s: on %s", path, name);
    }

    struct statvfs vfs;
    if (statvfs(path, &vfs) != 0) {
        report_warn("export %s: statvfs failed: %s", path, strerror(errno));
        return;
    }
    unsigned long long total = (unsigned long long)vfs.f_blocks * vfs.f_frsize;
    unsigned long long freeb = (unsigned long long)vfs.f_bavail * vfs.f_frsize;
    int sev = usage_severity(vfs.f_blocks, vfs.f_bavail);
    if (sev == 1)
        report_warn("export %s: over 90%% full (%.1f GiB free of %.1f GiB)",
                    path, freeb / 1073741824.0, total / 1073741824.0);
    else if (sev == 0)
        report_ok("export %s: %.1f GiB free of %.1f GiB",
                  path, freeb / 1073741824.0, total / 1073741824.0);
    int isev = usage_severity(vfs.f_files, vfs.f_favail);
    if (isev == 1)
        report_warn("export %s: over 90%% of inodes used", path);
}

static void server_check_storage_health(void) {
    char pbuf[4352];
    FILE *f = fopen(server_rooted(pbuf, sizeof(pbuf), server_opt.exports_file), "r");
    if (!f) {
        report_warn("storage health: cannot open %s: %s",
                    server_opt.exports_file, strerror(errno));
        return;
    }
    char line[1024], err[256];
    struct export_line e;
    int lineno = 0, entries = 0;
    while (fgets(line, sizeof(line), f)) {
        lineno++;
        if (exports_parse_line(line, lineno, &e, err, sizeof(err)) != 1)
            continue;   /* syntax problems belong to --exports-audit */
        entries++;
        if (server_live())
            server_storage_inspect(e.path);
        else
            report_info("export %s: live filesystem inspection skipped under --root",
                        e.path);
    }
    fclose(f);
    if (entries == 0)
        report_warn("storage health: no exports found in %s", server_opt.exports_file);
}

#define SECURITY_SCAN_MAX_ENTRIES 512
#define SECURITY_SCAN_MAX_FINDINGS 256

static void server_check_security_audit(void) {
    char pbuf[4352];
    FILE *f = fopen(server_rooted(pbuf, sizeof(pbuf), server_opt.exports_file), "r");
    if (!f) {
        report_warn("security audit: cannot open %s: %s",
                    server_opt.exports_file, strerror(errno));
        return;
    }
    static struct export_line entries[SECURITY_SCAN_MAX_ENTRIES];
    static struct export_finding findings[SECURITY_SCAN_MAX_FINDINGS];
    char line[1024], err[256];
    int lineno = 0, n = 0;
    while (n < SECURITY_SCAN_MAX_ENTRIES && fgets(line, sizeof(line), f)) {
        lineno++;
        if (exports_parse_line(line, lineno, &entries[n], err, sizeof(err)) == 1)
            n++;
    }
    fclose(f);

    int found = exports_security_scan(entries, n, findings,
                                      SECURITY_SCAN_MAX_FINDINGS);
    for (int i = 0; i < found; i++) {
        if (findings[i].level == 1)
            report_warn("security: %s", findings[i].msg);
        else
            report_info("security: %s", findings[i].msg);
    }
    if (found == 0 && n > 0)
        report_ok("security audit: %d export entr%s, no findings",
                  n, n == 1 ? "y" : "ies");
    else if (n == 0)
        report_warn("security audit: no parseable exports in %s",
                    server_opt.exports_file);
}

/* 1 when `user` exists in the (rooted) /etc/passwd, 0 when not, -1 unreadable */
static int server_passwd_has_user(const char *user) {
    char pbuf[4352];
    FILE *f = fopen(server_rooted(pbuf, sizeof(pbuf), "/etc/passwd"), "r");
    if (!f) return -1;
    char line[512];
    size_t ulen = strlen(user);
    int found = 0;
    while (!found && fgets(line, sizeof(line), f)) {
        if (strncmp(line, user, ulen) == 0 && line[ulen] == ':')
            found = 1;
    }
    fclose(f);
    return found;
}

static void server_check_idmap(void) {
    char buf[4096];
    if (server_read_file("/etc/idmapd.conf", buf, sizeof(buf)) != 0) {
        report_info("idmap: no /etc/idmapd.conf; defaults in effect (NFSv4 "
                    "domain falls back to the DNS domain)");
        return;
    }
    struct idmapd_conf c;
    parse_idmapd_conf(buf, &c);

    if (!c.has_domain) {
        report_info("idmap: Domain not set in idmapd.conf; the DNS domain is "
                    "used — fine only if client and server agree");
    } else {
        report_ok("idmap: Domain = %s", c.domain);
        if (server_live()) {
            char host[256];
            if (gethostname(host, sizeof(host)) == 0) {
                host[sizeof(host) - 1] = '\0';
                const char *dot = strchr(host, '.');
                if (dot && strcasecmp(dot + 1, c.domain) != 0)
                    report_warn("idmap: Domain (%s) differs from this host's DNS "
                                "domain (%s); mismatched domains map users to "
                                "nobody", c.domain, dot + 1);
            }
        }
    }
    if (c.method[0])
        report_info("idmap: translation method: %s", c.method);
    if (c.nobody_user[0]) {
        int r = server_passwd_has_user(c.nobody_user);
        if (r == 0)
            report_warn("idmap: Nobody-User '%s' does not exist in /etc/passwd",
                        c.nobody_user);
        else if (r == 1)
            report_ok("idmap: Nobody-User '%s' exists", c.nobody_user);
    }
}

static void server_check_krb5(void) {
    char buf[4096], pbuf[4352];

    if (server_read_file("/etc/krb5.conf", buf, sizeof(buf)) != 0) {
        report_info("krb5: no /etc/krb5.conf; Kerberos NFS (sec=krb5*) is not "
                    "configured on this server");
        return;
    }
    char realm[128];
    if (krb5_conf_default_realm(buf, realm, sizeof(realm)) == 0)
        report_ok("krb5: default realm %s", realm);
    else
        report_info("krb5: krb5.conf present but no default_realm set");

    struct stat st;
    if (stat(server_rooted(pbuf, sizeof(pbuf), "/etc/krb5.keytab"), &st) != 0) {
        report_warn("krb5: no /etc/krb5.keytab; the server needs an nfs/ "
                    "principal keytab for sec=krb5* exports");
    } else {
        if (st.st_mode & (S_IRGRP | S_IROTH))
            report_warn("krb5: /etc/krb5.keytab is readable by group/others "
                        "(mode %o)", st.st_mode & 07777);
        else
            report_ok("krb5: keytab present with sane permissions");
    }

    if (!server_live()) {
        report_info("krb5: principal listing and clock check skipped under --root");
        return;
    }

    char out[CMD_OUTPUT_LIMIT];
    char *klist[] = {"klist", "-k", "/etc/krb5.keytab", NULL};
    if (run_command_capture(klist, out, sizeof(out)) == 0) {
        if (strstr(out, "nfs/"))
            report_ok("krb5: nfs/ principal present in the keytab");
        else
            report_warn("krb5: keytab has no nfs/ principal; kadmin: "
                        "addprinc -randkey nfs/$(hostname -f)");
    } else if (stat("/etc/krb5.keytab", &st) == 0) {
        report_info("krb5: cannot list keytab (klist missing or unreadable keytab)");
    }

    char *tdctl[] = {"timedatectl", "show", "--property=NTPSynchronized", NULL};
    if (run_command_capture(tdctl, out, sizeof(out)) == 0) {
        if (strstr(out, "NTPSynchronized=yes"))
            report_ok("krb5: system clock is NTP-synchronized");
        else
            report_warn("krb5: clock not NTP-synchronized; Kerberos rejects "
                        "requests beyond the allowed skew");
    }

    if (server_proc_has_comm("gssproxy") == 1 ||
        server_proc_has_comm("rpc.svcgssd") == 1)
        report_ok("krb5: gssproxy or rpc.svcgssd is running");
    else
        report_warn("krb5: neither gssproxy nor rpc.svcgssd is running; "
                    "sec=krb5* mounts will fail");
}

/* Iterate parseable exports entries, calling fn(path) for each. Returns the
 * number of entries seen, or -1 when the exports file cannot be opened. */
static int server_foreach_export(void (*fn)(const char *path)) {
    char pbuf[4352];
    FILE *f = fopen(server_rooted(pbuf, sizeof(pbuf), server_opt.exports_file), "r");
    if (!f)
        return -1;
    char line[1024], err[256];
    struct export_line e;
    int lineno = 0, entries = 0;
    while (fgets(line, sizeof(line), f)) {
        lineno++;
        if (exports_parse_line(line, lineno, &e, err, sizeof(err)) != 1)
            continue;
        entries++;
        fn(e.path);
    }
    fclose(f);
    return entries;
}

static void server_acl_inspect(const char *path) {
    struct statfs sfs;
    if (statfs(path, &sfs) != 0) {
        report_warn("acl %s: cannot stat filesystem: %s", path, strerror(errno));
        return;
    }
    const char *name = fs_type_name((long)sfs.f_type);
    if (!fs_type_acl_capable((long)sfs.f_type)) {
        report_warn("acl %s: %s does not support POSIX ACLs; NFSv4 ACL "
                    "operations will fail or be mapped away", path, name);
        return;
    }
    /* Non-destructive probe: reading the ACL xattr distinguishes "fs mounted
     * without ACL support" (ENOTSUP) from "supported, none set" (ENODATA). */
    char aclbuf[4];
    ssize_t r = getxattr(path, "system.posix_acl_access", aclbuf, 0);
    if (r < 0 && errno == ENOTSUP)
        report_warn("acl %s: filesystem is %s but ACLs are disabled on this "
                    "mount (noacl?)", path, name);
    else
        report_ok("acl %s: POSIX ACLs available on %s", path, name);
}

static void server_check_acl(void) {
    if (!server_live()) {
        report_info("acl check: live probes skipped under --root");
        return;
    }
    char toolpath[4096];
    if (resolve_command_path("getfacl", toolpath, sizeof(toolpath)) != 0)
        report_info("acl check: getfacl not installed; clients may still use "
                    "ACLs, but local inspection needs the acl package");
    int n = server_foreach_export(server_acl_inspect);
    if (n < 0)
        report_warn("acl check: cannot open %s: %s", server_opt.exports_file,
                    strerror(errno));
    else if (n == 0)
        report_warn("acl check: no exports found in %s", server_opt.exports_file);
}

static void server_squash_inspect(const char *path) {
    char mp[4096];
    const char *tmpdir = getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
    snprintf(mp, sizeof(mp), "%s/nfsdiag-squash-XXXXXX", tmpdir);
    if (!mkdtemp(mp)) {
        report_warn("squash %s: mkdtemp failed: %s", path, strerror(errno));
        return;
    }
    struct mount_result mr;
    if (mount_export("127.0.0.1", path, mp, &mr) != 0 || !mr.mounted) {
        report_warn("squash %s: cannot mount 127.0.0.1:%s locally; is the "
                    "export served to localhost?", path, path);
        rmdir(mp);
        return;
    }

    char probe[4352];
    snprintf(probe, sizeof(probe), "%s/.nfsdiag-squash-%ld", mp, (long)getpid());
    int fd = open(probe, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) {
        report_info("squash %s: cannot create a probe file as root (%s) — "
                    "the export may be read-only", path, strerror(errno));
    } else {
        struct stat st;
        if (fstat(fd, &st) == 0) {
            if (st.st_uid == 0)
                report_warn("squash %s: file created by root is owned by uid 0 "
                            "— no_root_squash is in effect", path);
            else if (st.st_uid == 65534)
                report_ok("squash %s: root is squashed to nobody (uid 65534)",
                          path);
            else
                report_info("squash %s: root maps to uid %lu (anonuid)",
                            path, (unsigned long)st.st_uid);
        }
        close(fd);
        unlink(probe);
    }
    unmount_export(mp);
    rmdir(mp);
}

static void server_check_squash(void) {
    if (!server_live()) {
        report_info("squash check: skipped under --root (needs live mounts)");
        return;
    }
    if (geteuid() != 0) {
        report_warn("squash check: requires root to mount the exports locally");
        return;
    }
    int n = server_foreach_export(server_squash_inspect);
    if (n < 0)
        report_warn("squash check: cannot open %s: %s", server_opt.exports_file,
                    strerror(errno));
    else if (n == 0)
        report_warn("squash check: no exports found in %s", server_opt.exports_file);
}

static int server_copy_config(const char *abs_src, const char *dst) {
    char pbuf[4352];
    FILE *in = fopen(server_rooted(pbuf, sizeof(pbuf), abs_src), "r");
    if (!in)
        return -1;
    int fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        fclose(in);
        return -1;
    }
    FILE *out = fdopen(fd, "w");
    if (!out) {
        /* fdopen() leaves fd open on failure, so closing it here is correct. */
        // cppcheck-suppress doubleFree
        close(fd);
        fclose(in);
        return -1;
    }
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0)
        fwrite(buf, 1, n, out);
    fclose(in);
    fclose(out);
    return 0;
}

static void server_write_audit_trail(void) {
    const char *sources[] = {
        server_opt.exports_file, "/etc/nfs.conf", "/etc/idmapd.conf",
        "/etc/krb5.conf",
    };
    char *sha_argv[sizeof(sources) / sizeof(sources[0]) + 2];
    static char copies[sizeof(sources) / sizeof(sources[0])][4096];
    int argc = 0;
    sha_argv[argc++] = (char *)"sha256sum";

    for (size_t i = 0; i < sizeof(sources) / sizeof(sources[0]); i++) {
        const char *base = strrchr(sources[i], '/');
        base = base ? base + 1 : sources[i];
        snprintf(copies[i], sizeof(copies[i]), "%s/config-%s",
                 opt.output_dir, base);
        if (server_copy_config(sources[i], copies[i]) == 0) {
            report_info("audit trail: captured %s", sources[i]);
            sha_argv[argc++] = copies[i];
        }
    }
    sha_argv[argc] = NULL;
    if (argc == 1) {
        report_warn("audit trail: no configuration files found to capture");
        return;
    }

    char output[CMD_OUTPUT_LIMIT];
    if (run_command_capture(sha_argv, output, sizeof(output)) != 0) {
        report_warn("audit trail: sha256sum failed; checksums not written");
        return;
    }
    char sumpath[4352];
    snprintf(sumpath, sizeof(sumpath), "%s/CONFIG.SHA256SUMS", opt.output_dir);
    int fd = open(sumpath, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        report_warn("audit trail: cannot write %s: %s", sumpath, strerror(errno));
        return;
    }
    FILE *f = fdopen(fd, "w");
    /* fdopen() does not close the fd on failure */
    // cppcheck-suppress doubleFree
    if (!f) {
        close(fd);
        return;
    }
    fputs(output, f);
    fclose(f);
    report_ok("audit trail: config snapshots and checksums in %s", opt.output_dir);
}

static void server_check_rpc_stats(void) {
    char buf[4096];
    if (server_read_file("/proc/net/rpc/nfsd", buf, sizeof(buf)) != 0) {
        report_warn("rpc stats: no /proc/net/rpc/nfsd; is the NFS server running?");
        return;
    }

    struct nfsd_rc rc;
    if (parse_nfsd_rc_line(buf, &rc) == 0) {
        long lookups = rc.hits + rc.misses;
        if (lookups > 0) {
            double rate = 100.0 * (double)rc.hits / (double)lookups;
            report_ok("rpc stats: reply cache hit rate %.1f%% "
                      "(%ld hits, %ld misses, %ld uncached)",
                      rate, rc.hits, rc.misses, rc.nocache);
        } else {
            report_info("rpc stats: reply cache idle (no cacheable requests yet)");
        }
    }

    struct nfsd_rpc r;
    if (parse_nfsd_rpc_line(buf, &r) == 0) {
        if (r.badcalls > 0)
            report_warn("rpc stats: %ld bad RPC calls out of %ld "
                        "(auth failures or malformed requests)",
                        r.badcalls, r.calls);
        else
            report_ok("rpc stats: %ld RPC calls, no bad calls", r.calls);
    }

    const char *net = strstr(buf, "\nnet ");
    if (net) {
        long total = 0, udp = 0, tcp = 0;
        if (sscanf(net + 5, "%ld %ld %ld", &total, &udp, &tcp) >= 3)
            report_info("rpc stats: %ld packets (%ld UDP, %ld TCP)",
                        total, udp, tcp);
    }
    const char *io = strstr(buf, "\nio ");
    if (io) {
        long rd = 0, wr = 0;
        if (sscanf(io + 4, "%ld %ld", &rd, &wr) == 2)
            report_info("rpc stats: %ld bytes read, %ld bytes written", rd, wr);
    }
}

static void server_check_locks(void) {
    char buf[65536];
    if (server_read_file("/proc/locks", buf, sizeof(buf)) == 0) {
        int posix = 0, flock = 0, lease = 0;
        int total = count_proc_locks_buf(buf, &posix, &flock, &lease);
        report_ok("locks: %d held (%d POSIX, %d flock, %d lease/delegation)",
                  total, posix, flock, lease);
    } else {
        report_warn("locks: cannot read /proc/locks");
    }

    char small[64];
    long lease_time = -1, grace_time = -1;
    if (server_read_file("/proc/fs/nfsd/nfsv4leasetime", small, sizeof(small)) == 0)
        lease_time = atol(small);
    if (server_read_file("/proc/fs/nfsd/nfsv4gracetime", small, sizeof(small)) == 0)
        grace_time = atol(small);
    if (lease_time > 0 && grace_time > 0)
        report_info("locks: NFSv4 lease %lds, grace %lds (clients reclaim locks "
                    "within the grace window after a restart)",
                    lease_time, grace_time);

    if (!server_live()) {
        report_info("locks: NLM/NSM registration check skipped under --root");
        return;
    }
    struct rpc_services svc = {0};
    if (rpcb_dump_services("127.0.0.1", &svc) == 0) {
        if (rpc_services_has(&svc, NLM_PROGRAM))
            report_ok("locks: nlockmgr registered (NFSv3 locking available)");
        else
            report_info("locks: nlockmgr not registered (fine on NFSv4-only servers)");
        if (!rpc_services_has(&svc, NSM_PROGRAM))
            report_info("locks: status monitor (NSM) not registered");
        free(svc.items);
    }
}

/* List entries of a rooted directory into names[][256]. Returns the count,
 * or -1 when the directory cannot be opened. Skips "." and "..". */
static int server_glob_dir(const char *abs_dir, char names[][256], int max) {
    char pbuf[4352];
    DIR *d = opendir(server_rooted(pbuf, sizeof(pbuf), abs_dir));
    if (!d)
        return -1;
    const struct dirent *de;
    int n = 0;
    while (n < max && (de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.')
            continue;
        snprintf(names[n], 256, "%s", de->d_name);
        n++;
    }
    closedir(d);
    return n;
}

#define SERVER_MAX_CLIENTS 4096
#define CLIENT_STATES_OPEN_WARN 10000
#define CLIENT_STATES_DELEG_WARN 1000
#define MEMPRESS_AVAIL_WARN_PCT 10
#define VFS_CACHE_PRESSURE_HIGH 100
#define SWAPPINESS_SERVER_HIGH  10
#define LOG_INTEL_MAX_FINDINGS  16

static void server_check_clients(void) {
    static char ids[SERVER_MAX_CLIENTS][256];
    int n = server_glob_dir("/proc/fs/nfsd/clients", ids, SERVER_MAX_CLIENTS);
    if (n < 0) {
        report_info("clients: no /proc/fs/nfsd/clients (nfsd not running or "
                    "no NFSv4 clients)");
    } else if (n == 0) {
        report_ok("clients: no NFSv4 clients currently connected");
    } else {
        report_ok("clients: %d NFSv4 client%s connected", n, n == 1 ? "" : "s");
        for (int i = 0; i < n; i++) {
            char path[512], buf[4096];
            snprintf(path, sizeof(path), "/proc/fs/nfsd/clients/%.255s/info", ids[i]);
            if (server_read_file(path, buf, sizeof(buf)) != 0)
                continue;
            struct nfsd_client_info ci;
            if (parse_nfsd_client_info(buf, &ci) != 0)
                continue;
            if (ci.callback_up == 0)
                report_warn("clients: %s (NFSv4.%d) has callback DOWN; "
                            "delegations and layouts will be recalled by "
                            "timeout, not notification", ci.address,
                            ci.minor_version < 0 ? 0 : ci.minor_version);
            else
                report_info("clients: %s (NFSv4.%d, callback up)", ci.address,
                            ci.minor_version < 0 ? 0 : ci.minor_version);
        }
    }

    if (!server_live())
        return;
    char pbuf[4352];
    int established = 0;
    const char *tables[] = { "/proc/net/tcp", "/proc/net/tcp6" };
    for (size_t i = 0; i < 2; i++) {
        FILE *f = fopen(server_rooted(pbuf, sizeof(pbuf), tables[i]), "r");
        if (!f) continue;
        established += tcp_table_count_established(f, NFS_PORT);
        fclose(f);
    }
    report_info("clients: %d established TCP connection%s on port 2049",
                established, established == 1 ? "" : "s");
}

static void server_check_client_states(void) {
    static char ids[SERVER_MAX_CLIENTS][256];
    int n = server_glob_dir("/proc/fs/nfsd/clients", ids, SERVER_MAX_CLIENTS);
    if (n < 0) {
        report_info("client states: no /proc/fs/nfsd/clients (nfsd not running "
                    "or no NFSv4 clients)");
        return;
    }
    if (n == 0) {
        report_ok("client states: no NFSv4 clients holding state");
        return;
    }
    long t_opens = 0, t_locks = 0, t_delegs = 0, t_layouts = 0;
    for (int i = 0; i < n; i++) {
        char path[512];
        static char buf[262144];   /* states files can be large on busy servers */
        snprintf(path, sizeof(path), "/proc/fs/nfsd/clients/%.255s/states", ids[i]);
        if (server_read_file(path, buf, sizeof(buf)) != 0)
            continue;
        int opens = 0, locks = 0, delegs = 0, layouts = 0;
        count_nfsd_client_states(buf, &opens, &locks, &delegs, &layouts);
        t_opens += opens; t_locks += locks;
        t_delegs += delegs; t_layouts += layouts;
        if (opens > CLIENT_STATES_OPEN_WARN)
            report_warn("client states: client %s holds %d opens; a client "
                        "leaking file handles can exhaust server memory",
                        ids[i], opens);
        if (delegs > CLIENT_STATES_DELEG_WARN)
            report_warn("client states: client %s holds %d delegations",
                        ids[i], delegs);
    }
    report_ok("client states: %ld opens, %ld locks, %ld delegations, "
              "%ld layouts across %d client%s",
              t_opens, t_locks, t_delegs, t_layouts, n, n == 1 ? "" : "s");
}

static long server_read_long(const char *abs_path) {
    char buf[64];
    if (server_read_file(abs_path, buf, sizeof(buf)) != 0)
        return -1;
    return atol(buf);
}

static void server_check_memory_pressure(void) {
    char buf[8192];
    if (server_read_file("/proc/meminfo", buf, sizeof(buf)) == 0) {
        struct meminfo_stats m;
        if (parse_meminfo_buf(buf, &m) == 0) {
            long pct = m.memavailable_kb >= 0 && m.memtotal_kb > 0
                       ? (m.memavailable_kb * 100) / m.memtotal_kb : -1;
            if (pct >= 0 && pct < MEMPRESS_AVAIL_WARN_PCT) {
                report_warn("memory pressure: only %ld%% available (%ld of %ld MiB); "
                            "low memory shrinks the reply cache and dentry/inode caches",
                            pct, m.memavailable_kb / 1024, m.memtotal_kb / 1024);
                add_recommendation("free memory or lower workload; NFS metadata "
                                   "performance degrades sharply under memory pressure");
            } else if (pct >= 0) {
                report_ok("memory pressure: %ld%% available (%ld of %ld MiB)",
                          pct, m.memavailable_kb / 1024, m.memtotal_kb / 1024);
            }
            if (m.slab_kb > 0)
                report_info("memory pressure: %ld MiB in slab (%ld MiB reclaimable)",
                            m.slab_kb / 1024, m.sreclaimable_kb / 1024);
        }
    } else {
        report_warn("memory pressure: cannot read /proc/meminfo");
    }

    if (server_read_file("/proc/net/rpc/nfsd", buf, sizeof(buf)) == 0) {
        struct nfsd_rc rc;
        if (parse_nfsd_rc_line(buf, &rc) == 0 && (rc.hits + rc.misses + rc.nocache) > 0) {
            long uncacheable = rc.nocache, cacheable = rc.hits + rc.misses;
            if (uncacheable > cacheable)
                report_info("memory pressure: DRC bypassed by most requests "
                            "(%ld uncached vs %ld cacheable); this is normal for "
                            "read-heavy NFSv4 traffic", uncacheable, cacheable);
        }
    }

    long vcp = server_read_long("/proc/sys/vm/vfs_cache_pressure");
    if (vcp > VFS_CACHE_PRESSURE_HIGH) {
        report_info("memory pressure: vm.vfs_cache_pressure=%ld reclaims dentry/inode "
                    "caches aggressively; NFS servers benefit from a lower value", vcp);
        add_recommendation("consider vm.vfs_cache_pressure=%d to retain metadata caches",
                           VFS_CACHE_PRESSURE_HIGH);
    }
    long sw = server_read_long("/proc/sys/vm/swappiness");
    if (sw > SWAPPINESS_SERVER_HIGH)
        report_info("memory pressure: vm.swappiness=%ld; servers usually prefer a low "
                    "value to keep caches resident", sw);
    long dr = server_read_long("/proc/sys/vm/dirty_ratio");
    if (dr > 0)
        report_info("memory pressure: vm.dirty_ratio=%ld%% (writeback backlog cap)", dr);
}

static void server_check_rmtab_audit(void) {
    char buf[65536];
    if (server_read_file("/var/lib/nfs/rmtab", buf, sizeof(buf)) != 0) {
        report_info("rmtab audit: no /var/lib/nfs/rmtab (normal on NFSv4-only or "
                    "freshly booted servers)");
        return;
    }
    struct rmtab_stats r;
    parse_rmtab_buf(buf, &r);
    if (r.entries == 0) {
        report_ok("rmtab audit: rmtab is empty");
    } else {
        report_ok("rmtab audit: %d entries, %d distinct client%s", r.entries,
                  r.hosts, r.hosts == 1 ? "" : "s");
        if (r.stale > 0) {
            report_warn("rmtab audit: %d stale entr%s (count 0) linger in rmtab; "
                        "these drive needless sm-notify traffic on reboot",
                        r.stale, r.stale == 1 ? "y" : "ies");
            add_recommendation("prune stale rmtab entries (stop nfs-mountd, clear "
                               "/var/lib/nfs/rmtab, restart) during a maintenance window");
        }
        if (r.duplicates > 0)
            report_info("rmtab audit: %d duplicate host:path line%s", r.duplicates,
                        r.duplicates == 1 ? "" : "s");
    }

    static char names[256][256];
    int sm = server_glob_dir("/var/lib/nfs/sm", names, 256);
    if (sm >= 0) {
        if (sm > r.hosts && r.hosts > 0)
            report_warn("rmtab audit: NSM monitors %d host%s but rmtab lists %d; "
                        "orphaned sm/ entries cause sm-notify storms at boot",
                        sm, sm == 1 ? "" : "s", r.hosts);
        else
            report_info("rmtab audit: NSM monitors %d host%s", sm, sm == 1 ? "" : "s");
    }
}

static void server_check_log_intel(void) {
    static char buf[262144];
    size_t used = 0;
    buf[0] = '\0';

    if (server_live()) {
        char *const jk[] = { "journalctl", "-kb", "--no-pager", "-q", NULL };
        char out[131072];
        if (run_command_capture(jk, out, sizeof(out)) == 0)
            used += (size_t)snprintf(buf + used, sizeof(buf) - used, "%s", out);
        char *const ju[] = { "journalctl", "-u", "nfs-server", "-u", "nfs-mountd",
                             "-u", "rpc-statd", "--no-pager", "-q", "-n", "2000", NULL };
        if (used < sizeof(buf) - 1 && run_command_capture(ju, out, sizeof(out)) == 0)
            used += (size_t)snprintf(buf + used, sizeof(buf) - used, "%s", out);
    }
    if (used == 0) {
        /* offline (--root) or no journalctl: fall back to /var/log/messages */
        if (server_read_file("/var/log/messages", buf, sizeof(buf)) == 0)
            used = strlen(buf);
    }
    if (used == 0) {
        report_info("log intel: no journal or /var/log/messages to scan");
        return;
    }

    struct log_finding f[LOG_INTEL_MAX_FINDINGS];
    int n = log_intel_scan(buf, f, LOG_INTEL_MAX_FINDINGS);
    if (n == 0) {
        report_ok("log intel: no known NFS problem signatures found");
        return;
    }
    for (int i = 0; i < n; i++) {
        if (f[i].severity == 1)
            report_warn("log intel: %s (%dx)", f[i].title, f[i].count);
        else
            report_info("log intel: %s (%dx)", f[i].title, f[i].count);
        add_recommendation("%s", f[i].advice);
    }
}

static void metric_label_escape(FILE *f, const char *s) {
    for (; *s; s++) {
        if (*s == '\\' || *s == '"') fputc('\\', f);
        if (*s == '\n') { fputs("\\n", f); continue; }
        fputc(*s, f);
    }
}

static void metric_gauge_l(FILE *f, const char *name, const char *help,
                           const char *host, long v) {
    fprintf(f, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name);
    fprintf(f, "%s{host=\"", name);
    metric_label_escape(f, host);
    fprintf(f, "\"} %ld\n", v);
}

static void metric_gauge_f(FILE *f, const char *name, const char *help,
                           const char *host, double v) {
    fprintf(f, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name);
    fprintf(f, "%s{host=\"", name);
    metric_label_escape(f, host);
    fprintf(f, "\"} %.3f\n", v);
}

void server_metrics_emit(FILE *f, const char *host) {
    char buf[8192];
    if (server_read_file("/proc/net/rpc/nfsd", buf, sizeof(buf)) == 0) {
        struct nfsd_th_stats th;
        if (parse_nfsd_th_line(buf, &th) == 0) {
            metric_gauge_l(f, "nfsdiag_server_nfsd_threads",
                           "Number of nfsd threads", host, th.threads);
            metric_gauge_f(f, "nfsdiag_server_nfsd_threads_busy_seconds",
                           "Seconds all nfsd threads were busy since boot", host, th.busy_all);
        }
        struct nfsd_rc rc;
        if (parse_nfsd_rc_line(buf, &rc) == 0) {
            metric_gauge_l(f, "nfsdiag_server_drc_hits",
                           "Reply cache hits", host, rc.hits);
            metric_gauge_l(f, "nfsdiag_server_drc_misses",
                           "Reply cache misses", host, rc.misses);
            metric_gauge_l(f, "nfsdiag_server_drc_nocache",
                           "Requests that bypassed the reply cache", host, rc.nocache);
        }
        struct nfsd_rpc rp;
        if (parse_nfsd_rpc_line(buf, &rp) == 0) {
            metric_gauge_l(f, "nfsdiag_server_rpc_calls",
                           "Total RPC calls served", host, rp.calls);
            metric_gauge_l(f, "nfsdiag_server_rpc_badcalls",
                           "Bad RPC calls (auth failures or malformed)", host, rp.badcalls);
        }
    }
    if (server_read_file("/proc/locks", buf, sizeof(buf)) == 0) {
        int p = 0, fl = 0, le = 0;
        long n = count_proc_locks_buf(buf, &p, &fl, &le);
        metric_gauge_l(f, "nfsdiag_server_locks_held", "Locks held (/proc/locks)", host, n);
    }
    {
        static char ids[SERVER_MAX_CLIENTS][256];
        int n = server_glob_dir("/proc/fs/nfsd/clients", ids, SERVER_MAX_CLIENTS);
        if (n >= 0)
            metric_gauge_l(f, "nfsdiag_server_clients",
                           "Connected NFSv4 clients", host, n);
    }
    if (server_live()) {
        char pbuf[4352];
        int established = 0;
        const char *tables[] = { "/proc/net/tcp", "/proc/net/tcp6" };
        for (size_t i = 0; i < 2; i++) {
            FILE *tf = fopen(server_rooted(pbuf, sizeof(pbuf), tables[i]), "r");
            if (!tf) continue;
            established += tcp_table_count_established(tf, NFS_PORT);
            fclose(tf);
        }
        metric_gauge_l(f, "nfsdiag_server_tcp_established_2049",
                       "Established TCP connections on port 2049", host, established);
    }
    metric_gauge_l(f, "nfsdiag_server_snapshot_unixtime",
                   "Unix time when this snapshot was collected", host, (long)time(NULL));
    fprintf(f, "# EOF\n");
}

char *server_prometheus_snapshot(const char *host) {
    char *buf = NULL;
    size_t sz = 0;
    FILE *f = open_memstream(&buf, &sz);
    if (!f) return NULL;
    server_metrics_emit(f, host);
    fclose(f);
    return buf;
}

#define BACKEND_BENCH_BYTES (64UL * 1024UL * 1024UL)

static void backend_bench_one(const char *path) {
    if (!server_live()) {
        report_info("backend bench %s: skipped under --root (needs the live filesystem)", path);
        return;
    }
    double w = 0, r = 0;
    char err[256];
    if (storage_benchmark(path, BACKEND_BENCH_BYTES, NULL, &w, &r, err, sizeof(err)) != 0) {
        report_warn("backend bench %s: %s", path, err);
        return;
    }
    report_ok("backend bench %s: write %.1f MiB/s, read %.1f MiB/s (raw disk ceiling; "
              "compare with NFS throughput to locate the bottleneck)", path, w, r);
}

static void server_check_backend_bench(void) {
    int n = server_foreach_export(backend_bench_one);
    if (n == 0)
        report_info("backend bench: no exports found to benchmark");
}

static int command_on_path(const char *name) {
    const char *p = getenv("PATH");
    if (!p) return 0;
    char dir[512];
    while (*p) {
        size_t i = 0;
        while (*p && *p != ':' && i < sizeof(dir) - 1) dir[i++] = *p++;
        dir[i] = '\0';
        if (*p == ':') p++;
        if (i == 0) continue;
        char full[1024];
        snprintf(full, sizeof(full), "%s/%s", dir, name);
        if (access(full, X_OK) == 0) return 1;
    }
    return 0;
}

static void server_check_capture(void) {
    if (!server_live()) {
        report_info("capture: skipped under --root (needs the live network)");
        return;
    }
    if (!command_on_path("tcpdump")) {
        report_info("capture: tcpdump not found; install it to capture NFS traffic");
        return;
    }
    if (geteuid() != 0) {
        report_warn("capture: needs root to capture packets");
        return;
    }
    int dur = opt.duration > 0 ? opt.duration : 10;
    char pcap[4096];
    if (opt.output_dir)
        snprintf(pcap, sizeof(pcap), "%s/nfs-capture.pcap", opt.output_dir);
    else
        snprintf(pcap, sizeof(pcap), "/tmp/nfsdiag-nfs-capture.%d.pcap", (int)getpid());
    char durs[16];
    snprintf(durs, sizeof(durs), "%d", dur);
    report_info("capture: capturing NFS traffic on port 2049 for %ds -> %s", dur, pcap);
    char out[CMD_OUTPUT_LIMIT];
    char *argv[] = {"timeout", durs, "tcpdump", "-i", "any", "-n", "-w", pcap,
                    "port", "2049", NULL};
    run_command_capture(argv, out, sizeof(out));
    report_ok("capture: saved %s", pcap);
    if (command_on_path("tshark")) {
        char rfile[4096 + 8], tout[CMD_OUTPUT_LIMIT];
        snprintf(rfile, sizeof(rfile), "-r%s", pcap);
        char *targv[] = {"tshark", rfile, "-q", "-z", "io,phs", NULL};
        if (run_command_capture(targv, tout, sizeof(tout)) == 0)
            report_info("capture: protocol summary available (tshark -r %s -q -z io,phs)", pcap);
    } else {
        report_info("capture: install tshark for automatic analysis of %s", pcap);
    }
}

#define HA_MAX_ENTRIES 512

static void server_check_ha(void) {
    char pbuf[4352];
    FILE *f = fopen(server_rooted(pbuf, sizeof(pbuf), server_opt.exports_file), "r");
    if (f) {
        static struct export_line entries[HA_MAX_ENTRIES];
        char line[1024], err[256];
        int lineno = 0, n = 0, missing = 0;
        while (n < HA_MAX_ENTRIES && fgets(line, sizeof(line), f)) {
            lineno++;
            if (exports_parse_line(line, lineno, &entries[n], err, sizeof(err)) == 1)
                n++;
        }
        fclose(f);
        for (int i = 0; i < n; i++) {
            if (!export_line_has_fsid(&entries[i])) {
                missing++;
                report_warn("ha: export %s has no explicit fsid=; filehandles differ "
                            "between HA nodes and clients hit ESTALE on failover",
                            entries[i].path);
            }
        }
        if (n > 0 && missing == 0)
            report_ok("ha: all %d export(s) set an explicit fsid=", n);
    } else {
        report_warn("ha: cannot open %s: %s", server_opt.exports_file, strerror(errno));
    }

    char buf[65536];
    if (server_read_file("/proc/mounts", buf, sizeof(buf)) == 0) {
        if (path_is_on_own_mount(buf, "/var/lib/nfs"))
            report_ok("ha: /var/lib/nfs is on its own mount (state can live on shared storage)");
        else
            report_warn("ha: /var/lib/nfs is on the root filesystem; NFS state (rmtab, sm, "
                        "v4recovery, grace) will not migrate on failover");
    }

    char small[64];
    long lease = -1, grace = -1;
    if (server_read_file("/proc/fs/nfsd/nfsv4leasetime", small, sizeof(small)) == 0)
        lease = atol(small);
    if (server_read_file("/proc/fs/nfsd/nfsv4gracetime", small, sizeof(small)) == 0)
        grace = atol(small);
    if (lease > 0 && grace > 0)
        report_info("ha: NFSv4 lease %lds, grace %lds; the v4recovery dir must be on shared "
                    "storage for clients to reclaim locks after failover", lease, grace);

    if (!server_live()) {
        report_info("ha: pacemaker check skipped under --root");
        return;
    }
    char out[CMD_OUTPUT_LIMIT];
    char *pcs[] = {"pcs", "status", NULL};
    if (run_command_capture(pcs, out, sizeof(out)) == 0) {
        if (strstr(out, "nfsserver") || strstr(out, "exportfs"))
            report_ok("ha: pacemaker NFS resources found (nfsserver/exportfs)");
        else
            report_info("ha: pacemaker is running but exposes no NFS resources");
    } else {
        report_info("ha: no pacemaker/pcs found (standalone server?)");
    }
}

static void server_check_ganesha(void) {
    char buf[8192];
    int kernel_nfsd = (server_read_file("/proc/fs/nfsd/versions", buf, sizeof(buf)) == 0);
    int ganesha_proc = (server_proc_has_comm("ganesha.nfsd") == 1);
    static char cbuf[65536];
    int ganesha_conf = (server_read_file("/etc/ganesha/ganesha.conf", cbuf, sizeof(cbuf)) == 0);

    if (ganesha_proc || ganesha_conf) {
        report_ok("ganesha: nfs-ganesha detected (%s%s%s)",
                  ganesha_proc ? "process" : "",
                  (ganesha_proc && ganesha_conf) ? ", " : "",
                  ganesha_conf ? "ganesha.conf" : "");
        if (ganesha_conf) {
            struct ganesha_conf gc;
            parse_ganesha_conf(cbuf, &gc);
            report_info("ganesha: %d EXPORT block(s) in ganesha.conf", gc.export_count);
            for (int i = 0; i < gc.fsal_count; i++)
                report_info("ganesha: FSAL %s", gc.fsals[i]);
        }
        report_info("ganesha: /proc/fs/nfsd-based checks (daemons, version-matrix, "
                    "rpc-stats, clients, locks, memory-pressure) do not apply to "
                    "userland ganesha");
    } else if (kernel_nfsd) {
        report_ok("ganesha: kernel nfsd in use (no nfs-ganesha detected)");
    } else {
        report_info("ganesha: no NFS server detected (neither kernel nfsd nor ganesha)");
    }

    char rp[4352];
    struct stat st;
    int in_container = 0;
    if (stat(server_rooted(rp, sizeof(rp), "/.dockerenv"), &st) == 0)
        in_container = 1;
    if (stat(server_rooted(rp, sizeof(rp), "/run/secrets/kubernetes.io"), &st) == 0) {
        in_container = 1;
        report_info("ganesha: Kubernetes environment detected (/run/secrets/kubernetes.io)");
    }
    if (in_container)
        report_info("ganesha: running in a container; dynamic ports and host /proc "
                    "visibility differ from a bare-metal NFS server");
    else
        report_ok("ganesha: not running in a container");
}

static int server_run_checks(void) {
    char host[256];
    if (gethostname(host, sizeof(host)) != 0)
        snprintf(host, sizeof(host), "localhost");
    host[sizeof(host) - 1] = '\0';

    if (prepare_output_dir(host) != 0)
        return 2;
    enable_report_only_output();
    report_banner(host);

    /* fixed order: daemons, version-matrix, ports-firewall, exports-audit,
     * storage-health, sysctl-advisor */
    if (server_opt.daemons)
        server_check_daemons();
    if (server_opt.version_matrix)
        server_check_version_matrix();
    if (server_opt.ports_firewall)
        server_check_ports_firewall();
    if (server_opt.exports_audit)
        server_check_exports_audit();
    if (server_opt.security_audit)
        server_check_security_audit();
    if (server_opt.idmap_check)
        server_check_idmap();
    if (server_opt.krb5_server)
        server_check_krb5();
    if (server_opt.acl_check)
        server_check_acl();
    if (server_opt.squash_check)
        server_check_squash();
    if (server_opt.audit_trail)
        server_write_audit_trail();
    if (server_opt.storage_health)
        server_check_storage_health();
    if (server_opt.sysctl_advisor)
        server_check_sysctl_advisor();
    if (server_opt.rpc_stats)
        server_check_rpc_stats();
    if (server_opt.locks)
        server_check_locks();
    if (server_opt.clients)
        server_check_clients();
    if (server_opt.client_states)
        server_check_client_states();
    if (server_opt.memory_pressure)
        server_check_memory_pressure();
    if (server_opt.rmtab_audit)
        server_check_rmtab_audit();
    if (server_opt.log_intel)
        server_check_log_intel();
    if (server_opt.latency_profile || server_opt.per_client_trace) {
#ifdef NFSDIAG_ENABLE_EBPF
        int dur = opt.duration > 0 ? opt.duration : 10;
        nfsdiag_ebpf_latency_run(dur, server_opt.latency_profile,
                                 server_opt.per_client_trace);
#else
        report_info("perf: --latency-profile/--per-client-trace require an "
                    "--enable-ebpf build");
#endif
    }
    if (server_opt.backend_bench)
        server_check_backend_bench();
    if (server_opt.capture)
        server_check_capture();
    if (server_opt.ha_check)
        server_check_ha();
    if (server_opt.ganesha_check)
        server_check_ganesha();

    report_summary_line();
    write_json_report(host);
    write_html_report(host);
    write_table_report(host);
    write_prometheus_report(host);
    write_junit_report(host);
    write_output_dir_evidence(host);
    return (summary_warn + summary_fail) > 0 ? 1 : 0;
}

int server_main(int argc, char **argv) {
    static struct option long_opts[] = {
        {"all",           no_argument,       0, 2008},
        {"exports-audit", no_argument,       0, 2000},
        {"exports-file",  required_argument, 0, 2001},
        {"daemons",       no_argument,       0, 2003},
        {"ports-firewall", no_argument,      0, 2004},
        {"storage-health", no_argument,      0, 2005},
        {"security-audit", no_argument,      0, 2020},
        {"idmap-check",   no_argument,       0, 2021},
        {"krb5-server",   no_argument,       0, 2022},
        {"acl-check",     no_argument,       0, 2023},
        {"squash-check",  no_argument,       0, 2024},
        {"audit-trail",   no_argument,       0, 2025},
        {"rpc-stats",     no_argument,       0, 2030},
        {"locks",         no_argument,       0, 2031},
        {"clients",       no_argument,       0, 2032},
        {"client-states", no_argument,       0, 2033},
        {"memory-pressure", no_argument,     0, 2034},
        {"rmtab-audit",   no_argument,       0, 2035},
        {"log-intel",     no_argument,       0, 2036},
        {"watch",         required_argument, 0, 2040},
        {"listen",        required_argument, 0, 2041},
        {"ebpf-selftest", no_argument,       0, 2050},
        {"latency-profile",  no_argument,    0, 2051},
        {"per-client-trace", no_argument,    0, 2052},
        {"backend-bench",    no_argument,    0, 2053},
        {"capture",          no_argument,    0, 2054},
        {"duration",         required_argument, 0, 2055},
        {"ha-check",         no_argument,       0, 2056},
        {"ganesha-check",    no_argument,       0, 2057},
        {"version-matrix", no_argument,      0, 2002},
        {"sysctl-advisor", no_argument,      0, 2006},
        {"root",          required_argument, 0, 2007},
        {"json",          optional_argument, 0, 2010},
        {"html",          optional_argument, 0, 2011},
        {"output-format", required_argument, 0, 2012},
        {"output-dir",    required_argument, 0, 2013},
        {"verbose",       no_argument,       0, 'v'},
        {"quiet",         no_argument,       0, 'q'},
        {"version",       no_argument,       0, 'V'},
        {"help",          no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    remember_argv(argc, argv);

    int c;
    optind = 1;   /* argv was shifted by the dispatcher */
    while ((c = getopt_long(argc, argv, "vqVh", long_opts, NULL)) != -1) {
        switch (c) {
        case 2000: server_opt.exports_audit = 1; break;
        case 2001: server_opt.exports_file = optarg; break;
        case 2002: server_opt.version_matrix = 1; break;
        case 2003: server_opt.daemons = 1; break;
        case 2004: server_opt.ports_firewall = 1; break;
        case 2005: server_opt.storage_health = 1; break;
        case 2020: server_opt.security_audit = 1; break;
        case 2021: server_opt.idmap_check = 1; break;
        case 2022: server_opt.krb5_server = 1; break;
        case 2023: server_opt.acl_check = 1; break;
        case 2024: server_opt.squash_check = 1; break;
        case 2025: server_opt.audit_trail = 1; break;
        case 2030: server_opt.rpc_stats = 1; break;
        case 2031: server_opt.locks = 1; break;
        case 2032: server_opt.clients = 1; break;
        case 2033: server_opt.client_states = 1; break;
        case 2034: server_opt.memory_pressure = 1; break;
        case 2035: server_opt.rmtab_audit = 1; break;
        case 2036: server_opt.log_intel = 1; break;
        case 2040: {
            unsigned long num;
            if (parse_ulong_arg(optarg, &num) != 0 || num > 86400) {
                fprintf(stderr, "nfsdiag server: invalid --watch value '%s'\n", optarg);
                return 2;
            }
            opt.watch_interval = (int)num;
            break;
        }
        case 2041: {
            char reason[128];
            if (parse_listen_arg(optarg, opt.listen_addr, sizeof(opt.listen_addr),
                                 &opt.listen_port, reason, sizeof(reason)) != 0) {
                fprintf(stderr, "nfsdiag server: invalid --listen value '%s' (%s)\n",
                        optarg, reason);
                return 2;
            }
            break;
        }
        case 2050: server_opt.ebpf_selftest = 1; break;
        case 2051: server_opt.latency_profile = 1; break;
        case 2052: server_opt.per_client_trace = 1; break;
        case 2053: server_opt.backend_bench = 1; break;
        case 2054: server_opt.capture = 1; break;
        case 2056: server_opt.ha_check = 1; break;
        case 2057: server_opt.ganesha_check = 1; break;
        case 2055: {
            unsigned long num;
            if (parse_ulong_arg(optarg, &num) != 0 || num < 1 || num > 3600) {
                fprintf(stderr, "nfsdiag server: invalid --duration '%s'\n", optarg);
                return 2;
            }
            opt.duration = (int)num;
            break;
        }
        case 2008:
            /* --squash-check stays opt-in (it mounts and writes) and
             * --audit-trail only makes sense with --output-dir. */
            server_opt.daemons = server_opt.version_matrix = 1;
            server_opt.ports_firewall = server_opt.exports_audit = 1;
            server_opt.storage_health = server_opt.sysctl_advisor = 1;
            server_opt.security_audit = server_opt.idmap_check = 1;
            server_opt.krb5_server = server_opt.acl_check = 1;
            server_opt.rpc_stats = server_opt.locks = 1;
            server_opt.clients = server_opt.client_states = 1;
            server_opt.memory_pressure = server_opt.rmtab_audit = 1;
            server_opt.log_intel = 1;
            break;
        case 2006: server_opt.sysctl_advisor = 1; break;
        case 2007: server_opt.root = optarg; break;
        case 2010: opt.json = 1; opt.json_path = optarg ? optarg : "-"; break;
        case 2011: opt.html = 1; opt.html_path = optarg ? optarg : "-"; break;
        case 2012:
            if (strcmp(optarg, "text") == 0)            opt.output_fmt = OUTPUT_FMT_TEXT;
            else if (strcmp(optarg, "table") == 0)      opt.output_fmt = OUTPUT_FMT_TABLE;
            else if (strcmp(optarg, "ndjson") == 0)     opt.output_fmt = OUTPUT_FMT_NDJSON;
            else if (strcmp(optarg, "prometheus") == 0) opt.output_fmt = OUTPUT_FMT_PROMETHEUS;
            else if (strcmp(optarg, "junit") == 0)      opt.output_fmt = OUTPUT_FMT_JUNIT;
            else { fprintf(stderr, "invalid --output-format: %s\n", optarg); return 2; }
            break;
        case 2013: opt.output_dir = optarg; break;
        case 'v': server_opt.verbose = 1; break;
        case 'q': server_opt.quiet = 1; break;
        case 'V': printf("nfsdiag %s\n", NFSDIAG_VERSION); return 0;
        case 'h': server_usage(stdout); return 0;
        default: return 2;
        }
    }
    if (optind < argc) {
        fprintf(stderr, "nfsdiag server: unexpected argument '%s'\n", argv[optind]);
        return 2;
    }
    if (server_opt.ebpf_selftest) {
#ifdef NFSDIAG_ENABLE_EBPF
        if (nfsdiag_ebpf_selftest() == 0) {
            printf("eBPF: BPF object loaded and verified\n");
            return 0;
        }
        return 1;
#else
        fprintf(stderr, "eBPF support not compiled in "
                        "(build with ./configure --enable-ebpf)\n");
        return 2;
#endif
    }
    int metrics_mode = (opt.output_fmt == OUTPUT_FMT_PROMETHEUS) || (opt.listen_port > 0);
    if (!metrics_mode &&
        !server_opt.exports_audit && !server_opt.version_matrix &&
        !server_opt.sysctl_advisor && !server_opt.daemons &&
        !server_opt.ports_firewall && !server_opt.storage_health &&
        !server_opt.security_audit && !server_opt.idmap_check &&
        !server_opt.krb5_server && !server_opt.acl_check &&
        !server_opt.squash_check && !server_opt.rpc_stats &&
        !server_opt.locks && !server_opt.clients &&
        !server_opt.client_states && !server_opt.memory_pressure &&
        !server_opt.rmtab_audit && !server_opt.log_intel &&
        !server_opt.latency_profile && !server_opt.per_client_trace &&
        !server_opt.backend_bench && !server_opt.capture &&
        !server_opt.ha_check && !server_opt.ganesha_check) {
        fprintf(stderr, "nfsdiag server: no check selected (try --exports-audit)\n\n");
        server_usage(stderr);
        return 2;
    }
    if (server_opt.audit_trail && !opt.output_dir) {
        fprintf(stderr, "nfsdiag server: --audit-trail requires --output-dir\n");
        return 2;
    }
    if (strcmp(server_opt.root, "/") != 0) {
        struct stat st;
        if (server_opt.root[0] != '/' || stat(server_opt.root, &st) != 0 ||
            !S_ISDIR(st.st_mode)) {
            fprintf(stderr, "nfsdiag server: --root %s is not an existing absolute directory\n",
                    server_opt.root);
            return 2;
        }
    }

    /* pre-flight: an unreadable exports file is a usage error (rc 2),
     * consistent with the client's --hosts-file handling */
    if (server_opt.exports_audit) {
        char pbuf[4352];
        const char *path = server_rooted(pbuf, sizeof(pbuf), server_opt.exports_file);
        FILE *probe = fopen(path, "r");
        if (!probe) {
            fprintf(stderr, "nfsdiag server: cannot open %s: %s\n", path, strerror(errno));
            return 2;
        }
        fclose(probe);
    }

    /* The report layer (report.c) prints through the client opt globals.
     * Server checks report state ("NFSv4.1: enabled"), so ok/info lines are
     * the content: print them by default instead of the client's compact
     * filter. server_opt.verbose still gates per-entry detail lines. */
    opt.quiet = server_opt.quiet;
    opt.verbose = 1;

    if (opt.output_fmt == OUTPUT_FMT_PROMETHEUS && opt.listen_port == 0 &&
        opt.watch_interval == 0) {
        char host[256];
        if (gethostname(host, sizeof(host)) != 0)
            snprintf(host, sizeof(host), "localhost");
        host[sizeof(host) - 1] = '\0';
        server_metrics_emit(stdout, host);
        return 0;
    }

    if (opt.listen_port > 0) {
        char host[256];
        if (gethostname(host, sizeof(host)) != 0)
            snprintf(host, sizeof(host), "localhost");
        host[sizeof(host) - 1] = '\0';
        return run_metrics_listener(host, server_prometheus_snapshot);
    }
    if (opt.watch_interval > 0) {
        int overall = 0, iteration = 0;
        while (!received_signal) {
            if (iteration > 0) {
                printf("\033[2J\033[H");
                printf("[watch] iteration %d (every %ds, Ctrl-C to stop)\n",
                       iteration + 1, opt.watch_interval);
            }
            iteration++;
            int rc = server_run_checks();
            if (rc > overall) overall = rc;
            if (received_signal) break;
            for (int s = 0; s < opt.watch_interval && !received_signal; s++)
                sleep(1);
        }
        return overall;
    }

    return server_run_checks();
}
