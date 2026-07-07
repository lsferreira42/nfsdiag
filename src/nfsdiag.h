#ifndef NFSDIAG_H
#define NFSDIAG_H

#define NFSDIAG_VERSION "0.22.0"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <getopt.h>
#include <grp.h>
#include <locale.h>
#include <netdb.h>
#include <poll.h>
#include <pwd.h>
#include <sys/prctl.h>
#include <rpc/pmap_clnt.h>
#include <rpc/rpc.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#ifndef ESTALE
#define ESTALE 116
#endif

#ifndef ENOATTR
#define ENOATTR ENODATA
#endif

/* ---- RPC program numbers ---- */
#define NFS_PROGRAM        100003UL
#define MOUNT_PROGRAM      100005UL
#define NLM_PROGRAM        100021UL
#define NSM_PROGRAM        100024UL
#define MOUNTPROC_EXPORT   5

/* ---- well-known ports ---- */
#define RPCBIND_PORT 111
#define NFS_PORT     2049

/* ---- defaults ---- */
#define DEFAULT_TIMEOUT_SEC          5
#define DEFAULT_STALE_ITERATIONS     100
#define DEFAULT_BENCH_BYTES          (4U * 1024U * 1024U)
#define DEFAULT_FS_TIMEOUT_SEC       30
#define DEFAULT_COMMAND_TIMEOUT_SEC  30
#define DEFAULT_BENCH_ITERATIONS     10

/* ---- XDR string limits ---- */
#define MAX_XDR_EXPORT_PATH  4096
#define MAX_XDR_GROUP_NAME   256

/* ---- XDR list decode limits (iterative decoder; bounds allocations) ---- */
#define MAX_XDR_EXPORT_NODES 2048
#define MAX_XDR_GROUP_NODES  8192

/* ---- limits ---- */
#define MAX_EXPORTS          512
#define MAX_CLI_EXPORTS      64
#define MAX_PARALLEL         32
#define MAX_IDENTITIES       32
#define CMD_OUTPUT_LIMIT     8192
#define MAX_EVENTS           4096
#define MAX_RECOMMENDATIONS  128
#define MAX_MOUNTPOINTS      128
#define MAX_SUPP_GROUPS      64
#define MAX_EXPORT_REPORTS   512
#define MAX_NFS_VERSIONS     5
#define MAX_HOSTS            256
#define MAX_CHECK_ID         64
#define MAX_EVENT_CATEGORY   32
#define MAX_EVENT_REMEDIATION 256

/* ---- NFS mount version strings ---- */
extern const char *nfs_version_cascade[];

/* ---- output format ---- */
typedef enum {
    OUTPUT_FMT_TEXT       = 0,
    OUTPUT_FMT_TABLE      = 1,
    OUTPUT_FMT_NDJSON     = 2,
    OUTPUT_FMT_PROMETHEUS = 3,
    OUTPUT_FMT_JUNIT      = 4,
} output_fmt_t;

/* ---- structs ---- */

struct options {
    int verbose;
    int no_mount;
    int dry_run;
    int keep_temp;
    int quiet;
    int delay_ms;
    int write_test;
    int timeout_sec;
    int command_timeout_sec;
    int fs_timeout_sec;
    int stale_iterations;
    int bench_iterations;
    int json;
    int udp_checks;
    int nfs4_discovery;
    int mount_namespace;
    int no_mount_namespace;
    int allow_risky_mount_options;
    int dangerous_fs_tests;
    int self_test;
    int address_family;
    int krb5;
    int watch_interval;            /* 0 = disabled; >0 = seconds between runs  */
    int sweep;                     /* benchmark rsize/wsize/nconnect combos    */
    int parallel;                  /* >1 = concurrent export workers           */
    int listen_port;               /* >0 = serve Prometheus metrics over HTTP  */
    char listen_addr[256];         /* bind address; empty = 127.0.0.1          */
    char peer_host[256];           /* --peer HOST[:PORT]; empty = disabled     */
    int  peer_port;
    int duration;                  /* sampling window for perf checks (seconds) */
    int diff_baseline;             /* compare with and update saved baseline   */
    size_t bench_bytes;
    gid_t supplemental_groups[MAX_SUPP_GROUPS];
    size_t supplemental_group_count;
    const char *json_path;
    int html;
    const char *html_path;
    const char *bench_type;
    const char *mount_options;
    const char *cli_exports[MAX_CLI_EXPORTS];  /* --export, repeatable */
    size_t cli_export_count;
    const char *hosts_file;        /* path to file with one host per line      */
    const char *on_fail_exec;      /* script to exec when any test fails       */
    const char *config_file;       /* path to configuration file               */
    const char *output_dir;        /* directory for JSON/HTML/evidence bundle  */
    const char *profile;           /* quick/safe/full/performance/security     */
    output_fmt_t output_fmt;       /* text / table / ndjson / prometheus       */
    uid_t uids[MAX_IDENTITIES];
    gid_t gids[MAX_IDENTITIES];
    size_t identity_count;
};

struct rpc_service {
    unsigned long prog;
    unsigned long vers;
    unsigned long prot;
    unsigned long port;
};

struct rpc_services {
    struct rpc_service *items;
    size_t len;
    size_t cap;
};

struct export_item {
    char *path;
    char **groups;
    size_t group_count;
};

struct export_list {
    struct export_item items[MAX_EXPORTS];
    size_t count;
};

struct exportnode;
struct groupnode;
typedef struct exportnode *exports;
typedef struct groupnode  *groups;

struct groupnode {
    char   *gr_name;
    groups  gr_next;
};

struct exportnode {
    char    *ex_dir;
    groups   ex_groups;
    exports  ex_next;
};

struct mount_result {
    int  mounted;
    int  version;
    int  nfs_minor_version;
    char mountpoint[4096];
};

struct report_event {
    char *level;
    char *message;
    char check_id[MAX_CHECK_ID];
    char category[MAX_EVENT_CATEGORY];
    char remediation[MAX_EVENT_REMEDIATION];
    int  export_idx;   /* -1 = global */
};

struct export_report {
    char   path[4096];
    int    nfs_version;
    int    nfs_minor_version;
    int    tested;
    double write_mib_s;
    double read_mib_s;
    double meta_p50_ms;
    double meta_p95_ms;
    double meta_p99_ms;
    int    meta_completed;
    int    lock_ok;
    int    root_squash_detected;
    int    estale_seen;
    int    acl_posix;
    int    acl_nfsv4;
    char   effective_mount_opts[2048];
};

struct rpc_stats {
    unsigned long net_count;
    unsigned long net_udp;
    unsigned long net_tcp;
    unsigned long rpc_calls;
    unsigned long rpc_retrans;
    unsigned long rpc_auth_refresh;
    int valid;
};

struct system_info {
    char kernel[256];
    char hostname[256];
    char arch[64];
};

/* ---- globals (defined in their respective .c) ---- */

extern struct options      opt;
extern struct report_event *events;
extern size_t              event_count;
extern char                **recommendations;
extern size_t              recommendation_count;
extern char                active_mountpoints[][4096];
extern size_t              active_mountpoint_count;
extern volatile sig_atomic_t received_signal;
extern int                 saved_stdout_fd;
extern char                cleanup_base[];
extern int                 summary_ok;
extern int                 summary_warn;
extern int                 summary_fail;
extern int                 current_export_idx;
extern struct export_report *export_reports;
extern size_t              export_report_count;
extern size_t              export_report_cap;
struct export_report *export_report_at(size_t idx);

/* ---- main.c dispatcher entry points ---- */

extern const char *nfsdiag_mode;   /* "client" or "server", set by main() */
int client_main(int argc, char **argv);
int server_main(int argc, char **argv);
int diff_reports(const char *a, const char *b);

/* client.c helpers shared with the server namespace */
void remember_argv(int argc, char **argv);
int  prepare_output_dir(const char *host);
void write_output_dir_evidence(const char *host);

/* ---- server.c (`nfsdiag server` namespace) ---- */

struct server_options {
    int exports_audit;
    const char *exports_file;
    const char *root;              /* prefix for /proc and /etc reads */
    int daemons;
    int version_matrix;
    int ports_firewall;
    int storage_health;
    int sysctl_advisor;
    int security_audit;
    int idmap_check;
    int krb5_server;
    int acl_check;
    int squash_check;
    int audit_trail;
    int rpc_stats;
    int locks;
    int clients;
    int client_states;
    int memory_pressure;
    int log_intel;
    int rmtab_audit;
    int ebpf_selftest;
    int latency_profile;
    int per_client_trace;
    int backend_bench;
    int capture;
    int ha_check;
    int ganesha_check;
    int verbose;
    int quiet;
};
extern struct server_options server_opt;

/* Emit Prometheus gauges for the local NFS server (reads /proc, honors --root). */
void server_metrics_emit(FILE *f, const char *host);
char *server_prometheus_snapshot(const char *host);

/* ---- serve.c (shared HTTP metrics listener) ---- */
int run_metrics_listener(const char *host, char *(*refresh)(const char *host));

/* eBPF self-test (defined in src/ebpf.c only when built with --enable-ebpf). */
int nfsdiag_ebpf_selftest(void);

/* Attach nfsd kprobes, sample for duration_s, then report latency histograms
 * (want_hist) and/or per-client stats (want_client). Only in --enable-ebpf builds. */
int nfsdiag_ebpf_latency_run(int duration_s, int want_hist, int want_client);

/* Write+read a temp file in dir to measure the raw storage ceiling.
 * engine: NULL/"internal" = built-in loop; "fio" = fio with --direct=1.
 * Returns 0 (MiB/s written to write_mibs and read_mibs; -1.0 each for fio),
 * -1 on error. */
int storage_benchmark(const char *dir, size_t bytes, const char *engine,
                      double *write_mibs, double *read_mibs, char *err, size_t errsz);

/* ---- server_exports.c (pure helpers for --exports-audit) ---- */

struct export_line {
    char path[512];
    char clients[8][256];   /* "host(opt,opt)" tokens, already split      */
    int  client_count;
    int  lineno;
};
/* Parse one line of /etc/exports. Returns: 1 = parsed into *out,
 * 0 = blank/comment (skip), -1 = syntax error (message in err). */
int exports_parse_line(const char *line, int lineno, struct export_line *out,
                       char *err, size_t errsz);
/* Inspect one "host(options)" token. Returns 0 = fine, 1 = risky
 * (human-readable reason in why), -1 = malformed token. */
int exports_client_risk(const char *token, char *why, size_t whysz);

/* 1 if any client token of this export carries an explicit fsid= option. */
int export_line_has_fsid(const struct export_line *e);

/* Deep security scan across parsed exports entries (--security-audit).
 * level: 0 = info, 1 = warn. Returns the number of findings written. */
struct export_finding { int level; char msg[300]; };
int exports_security_scan(const struct export_line *entries, int n_entries,
                          struct export_finding *out, int max);

/* ---- server_checks.c (pure analyzers for server checks) ---- */

struct nfsd_versions { int v3, v4, v4_1, v4_2; };   /* 1 on, 0 off, -1 absent */
/* Parse /proc/fs/nfsd/versions ("-2 +3 +4 +4.1 -4.2"). 0 = ok, -1 = unparseable. */
int parse_nfsd_versions(const char *buf, struct nfsd_versions *out);

struct nfsd_th_stats { long threads; double busy_all; int valid; };
/* Parse the "th" line of /proc/net/rpc/nfsd. busy_all = seconds all threads
 * were busy (the histogram's last bucket). 0 = ok, -1 = no th line. */
int parse_nfsd_th_line(const char *buf, struct nfsd_th_stats *out);

/* 1 when a /proc/<pid>/comm buffer matches name (trailing newline ignored;
 * comm is truncated by the kernel to 15 chars, so compare up to that). */
int comm_matches(const char *comm, const char *name);

struct idmapd_conf {
    int  has_domain;
    char domain[256];
    char nobody_user[64];
    char nobody_group[64];
    char method[128];
};
/* Parse idmapd.conf-style INI content. Always returns 0 (missing keys
 * simply stay empty); sections are ignored, keys are matched globally. */
int parse_idmapd_conf(const char *buf, struct idmapd_conf *out);

/* Extract default_realm from krb5.conf content. 0 = found, -1 = absent. */
int krb5_conf_default_realm(const char *buf, char *out, size_t sz);

/* rpc.c: local rpcbind dump, exported for the server namespace */
int rpcb_dump_services(const char *host, struct rpc_services *svc);

/* 1 if a LISTEN socket (st 0A) on local port `port` exists in a
 * /proc/net/tcp[6]-format stream; 0 if not; -1 on read error. */
int tcp_table_has_listener(FILE *f, unsigned port);

/* Map statfs.f_type to a name ("ext4", "xfs", ...); "unknown" if unmapped. */
const char *fs_type_name(long f_type);
/* 1 = unsuitable to export (reason in why), 0 = fine. */
int fs_type_unsuitable(long f_type, char *why, size_t whysz);
/* 0 = ok, 1 = warn (>90% used), -1 = unknown (total == 0). */
int usage_severity(unsigned long long total, unsigned long long freev);
/* 1 when the filesystem type is known to support POSIX ACLs. */
int fs_type_acl_capable(long f_type);

/* ---- live-state parsers (all pure, /proc formats) ---- */

/* Reply cache line of /proc/net/rpc/nfsd: "rc <hits> <misses> <nocache>". */
struct nfsd_rc { long hits, misses, nocache; int valid; };
int parse_nfsd_rc_line(const char *buf, struct nfsd_rc *out);

/* RPC line of /proc/net/rpc/nfsd: "rpc <calls> <badcalls> ...". */
struct nfsd_rpc { long calls, badcalls; int valid; };
int parse_nfsd_rpc_line(const char *buf, struct nfsd_rpc *out);

/* Count /proc/locks entries by type (2nd column). Returns total. */
int count_proc_locks_buf(const char *buf, int *posix, int *flock, int *lease);

/* Count ESTABLISHED sockets (st 01) on local `port` in a /proc/net/tcp table. */
int tcp_table_count_established(FILE *f, unsigned port);

/* One /proc/fs/nfsd/clients/<id>/info file. */
struct nfsd_client_info { char address[128]; int minor_version; int callback_up; };
int parse_nfsd_client_info(const char *buf, struct nfsd_client_info *out);

/* Count states in a /proc/fs/nfsd/clients/<id>/states file. Returns total. */
int count_nfsd_client_states(const char *buf, int *opens, int *locks,
                             int *delegs, int *layouts);

/* ---- observability parsers (pure) ---- */

struct meminfo_stats { long memtotal_kb, memavailable_kb, slab_kb, sreclaimable_kb; int valid; };
/* Parse /proc/meminfo lines "Key:  <n> kB". 0 = ok, -1 = MemTotal absent. */
int parse_meminfo_buf(const char *buf, struct meminfo_stats *out);

struct rmtab_stats { int entries, hosts, stale, duplicates; };
/* Parse rmtab lines "host:/export:count". count 0 = stale. Distinct hosts and
 * duplicate host:path lines counted up to an internal cap. Returns entries. */
int parse_rmtab_buf(const char *buf, struct rmtab_stats *out);

struct log_finding { const char *title; const char *advice; int severity; int count; };
/* Scan log text (journal/messages) for known NFS server problem signatures.
 * severity: 0 = info, 1 = warn; count = matching lines. Returns findings (0..max). */
int log_intel_scan(const char *buf, struct log_finding *out, int max);

/* ---- perf helpers (pure) ---- */
/* Latency histogram bucket for a duration in ns: 0 for <1us, else
 * floor(log2(microseconds))+1, capped at 31. Mirrors the BPF side. */
int hist_log2_bucket(unsigned long long ns);
/* Format a client IP (AF_INET=2 uses ip[0..3], AF_INET6=10 uses ip[0..15]). */
void fmt_client_ip(const unsigned char ip[16], int family, char *out, size_t sz);

/* ---- HA / ganesha helpers (pure) ---- */
/* 1 if /proc/mounts (mounts_buf) has a mount whose mountpoint is exactly path. */
int path_is_on_own_mount(const char *mounts_buf, const char *path);

struct ganesha_conf { int has_conf; int export_count; char fsals[8][32]; int fsal_count; };
/* Parse ganesha.conf: count EXPORT{} blocks and FSAL names. Returns export_count. */
int parse_ganesha_conf(const char *buf, struct ganesha_conf *out);

/* ---- paired-mode helpers (pure) ---- */
struct peer_server { double snapshot_unixtime, rpc_calls, rpc_badcalls, drc_hits,
                     drc_misses, drc_nocache, tcp_established, nfsd_threads; int valid; };
struct peer_client_findings { int fail; int estale; double min_write_mibs; double min_read_mibs; };
/* Extract a Prometheus gauge value ("name{...} VALUE"). 0 = found, -1 = absent. */
int parse_prometheus_gauge(const char *buf, const char *name, double *out);
/* Headline verdict from client findings + two server snapshots. Returns level
 * (0 = ok/info, 1 = warn); message written to msg. */
int peer_verdict(const struct peer_client_findings *c, const struct peer_server *base,
                 const struct peer_server *final, char *msg, size_t msgsz);

/* ---- peer.c (paired-mode HTTP client) ---- */
int peer_fetch_metrics(const char *host, int port, char *buf, size_t sz);
void peer_parse_server(const char *buf, struct peer_server *out);

/* ---- report.c ---- */

void add_event(const char *level, const char *message);
void add_recommendation(const char *fmt, ...);
void report_ok(const char *fmt, ...);
void report_warn(const char *fmt, ...);
void report_fail(const char *fmt, ...);
void report_info(const char *fmt, ...);
void enable_report_only_output(void);
void reset_diagnostic_state(void);
void write_json_report(const char *host);
int  write_json_report_file(const char *host, const char *path);
void write_html_report(const char *host);
void write_table_report(const char *host);
void write_prometheus_report(const char *host);
void write_junit_report(const char *host);
char *prometheus_snapshot(const char *host);
void print_interpretation(void);
void report_banner(const char *host);
void report_summary_line(void);

/* ---- network.c ---- */

int         tcp_connect_timeout(const char *host, int port, int timeout_sec);
void        network_tests(const char *host);
void        check_rpc_dynamic_ports(const char *host, const struct rpc_services *svc);
const char *proto_name(unsigned long proto);

/* ---- rpc.c ---- */

const char *rpc_program_name(unsigned long prog);
void    rpc_services_add(struct rpc_services *svc, unsigned long prog,
                         unsigned long vers, unsigned long prot, unsigned long port);
int     rpc_services_has(const struct rpc_services *svc, unsigned long prog);
int     rpc_services_has_version(const struct rpc_services *svc, unsigned long prog,
                                 unsigned long vers);
CLIENT *rpc_client(const char *host, unsigned long prog, unsigned long vers,
                   const char *proto);
int     rpc_null_call(const char *host, unsigned long prog, unsigned long vers,
                      const char *proto, enum clnt_stat *out_stat);
void    check_rpcbind(const char *host, struct rpc_services *svc);
void    check_nfs_versions(const char *host, const struct rpc_services *svc);
void    check_mountd_versions(const char *host, const struct rpc_services *svc);
void    enumerate_exports(const char *host, struct export_list *out);
void    free_exports(struct export_list *list);
void    fingerprint_server(const struct rpc_services *svc);

/* Server profile drives whether a missing legacy service (mountd, NLM, NSM,
 * NFSv3) is a warning or just expected context. Computed from the rpcbind map
 * in check_rpcbind() and reused by fingerprint_server(). */
enum server_profile {
    PROFILE_UNKNOWN = 0,   /* no map or ambiguous: keep conservative warnings */
    PROFILE_NFSV4_ONLY,    /* NFSv4 present, no NFSv3/mountd: v3 services optional */
    PROFILE_NFSV3_ONLY,    /* NFSv3 present, no NFSv4 */
    PROFILE_MIXED          /* both NFSv3 and NFSv4 advertised */
};
extern enum server_profile detected_profile;
enum server_profile classify_server_profile(const struct rpc_services *svc);

/* ---- mount.c ---- */

int  run_command_capture(char *const argv[], char *output, size_t output_sz);
int  resolve_command_path(const char *cmd, char *out, size_t out_sz);
void register_mountpoint(const char *mountpoint);
void unregister_mountpoint(const char *mountpoint);
int  make_dir(const char *path, mode_t mode);
int  mount_export(const char *host, const char *export_path,
                  const char *mountpoint, struct mount_result *mr);
int  unmount_export(const char *mountpoint);
int  setup_mount_namespace(void);
void close_inherited_fds(int keep1, int keep2);
void sweep_mount_options(const char *host, const char *export_path,
                         const char *workspace, const char *vers);
void test_krb5_mount_flavors(const char *host, const char *export_path,
                             const char *workspace);

/* ---- tests.c ---- */

void diagnose_mounted_export(const char *export_path, const char *mountpoint,
                             int export_idx, int nfs_version, int nfs_minor);

/* ---- exit codes for identity simulation ---- */
enum child_exit_code {
    CHILD_OK                = 0,
    CHILD_SETGID_FAIL       = 10,
    CHILD_SETUID_FAIL       = 11,
    CHILD_SETGROUPS_FAIL    = 12,
    CHILD_ACCESS_DENIED     = 20,
    CHILD_CREATE_DENIED     = 21,
    CHILD_OPEN_ERROR        = 22,
    CHILD_WRITE_ERROR       = 23,
};

/* ---- stats.c ---- */

int  check_dependencies(void);
void check_client_daemons(void);
void check_kerberos(void);
int  capture_rpc_stats(struct rpc_stats *out);
/* Stream variants take an open FILE* so fuzzers can drive the production
 * parsers over fmemopen() buffers; they neither open nor close the stream. */
int  capture_rpc_stats_stream(FILE *f, struct rpc_stats *out);
void report_rpc_stats_diff(const struct rpc_stats *before,
                           const struct rpc_stats *after);
void parse_mountstats_stream(FILE *f, const char *mountpoint);
void verify_mount_options(const char *mountpoint, struct export_report *report);
void verify_mount_options_stream(FILE *f, const char *mountpoint,
                                 struct export_report *report);
void collect_system_info(struct system_info *si);
void check_nfsfs_servers(const char *mountpoint);

/* ---- validation.c ---- */

int parse_ulong_arg(const char *s, unsigned long *out);
int parse_uid_arg(const char *s, uid_t *out);
int parse_gid_arg(const char *s, gid_t *out);
void redact_argv(char *dst, size_t dst_sz, int argc, char **argv);
int validate_host_arg(const char *host, char *reason, size_t reason_sz);
int validate_export_path(const char *path, char *reason, size_t reason_sz);
int validate_mount_options(const char *opts, int allow_risky,
                           char *reason, size_t reason_sz);
int parse_listen_arg(const char *arg, char *addr_out, size_t addr_sz,
                     int *port_out, char *reason, size_t reason_sz);

#define PEER_DEFAULT_PORT 9100
#define PEER_SLOW_MIBS    20.0
#define PEER_SKEW_WARN    30.0
/* Parse "HOST", "HOST:PORT" or "[v6]:PORT" into host/port (port defaults). 0/-1. */
int parse_peer_arg(const char *arg, char *host, size_t hostsz, int *port, int default_port);
void warn_risky_mount_options(const char *opts);
const char *event_category_for_message(const char *level, const char *message);
void event_check_id(char *dst, size_t dst_sz, const char *level,
                    const char *category, const char *message);
const char *event_remediation_for(const char *category, const char *message);

/* ---- util.c (pure, unit-tested helpers) ---- */

double avg_per_op_ms(unsigned long total_ms, unsigned long ops);
void utf8_truncate(char *dst, size_t dst_sz, const char *src, size_t max_cols);
int http_request_is_get(const char *req, size_t len, char *path_out, size_t path_sz);
int parse_bounded_int(const char *s, unsigned long lo, unsigned long hi, int *out);
int service_missing_is_warning(enum server_profile profile);
FILE *fopen_regular_ro(const char *path);
void mountinfo_unescape(char *dst, size_t dst_sz, const char *src);
void csv_append_missing(char *dst, size_t dst_sz, const char *tokens,
                        const char *existing);

#endif /* NFSDIAG_H */
