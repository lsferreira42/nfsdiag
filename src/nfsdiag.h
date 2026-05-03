#ifndef NFSDIAG_H
#define NFSDIAG_H

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <getopt.h>
#include <grp.h>
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

/* ---- defaults ---- */
#define DEFAULT_TIMEOUT_SEC        5
#define DEFAULT_STALE_ITERATIONS   100
#define DEFAULT_BENCH_BYTES        (4U * 1024U * 1024U)
#define DEFAULT_FS_TIMEOUT_SEC     30

/* ---- limits ---- */
#define MAX_EXPORTS          512
#define MAX_IDENTITIES       32
#define CMD_OUTPUT_LIMIT     8192
#define MAX_EVENTS           4096
#define MAX_RECOMMENDATIONS  128
#define MAX_MOUNTPOINTS      128
#define MAX_SUPP_GROUPS      64
#define MAX_EXPORT_REPORTS   512
#define MAX_NFS_VERSIONS     5

/* ---- NFS mount version strings ---- */
extern const char *nfs_version_cascade[];

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
    int address_family;
    int krb5;
    size_t bench_bytes;
    gid_t supplemental_groups[MAX_SUPP_GROUPS];
    size_t supplemental_group_count;
    const char *json_path;
    int html;
    const char *html_path;
    const char *bench_type;
    const char *mount_options;
    const char *single_export;
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
    char mountpoint[4096];
};

struct report_event {
    char *level;
    char *message;
    int  export_idx;   /* -1 = global */
};

struct export_report {
    char   path[4096];
    int    nfs_version;
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
extern struct export_report export_reports[];
extern size_t              export_report_count;

/* ---- report.c ---- */

void add_event(const char *level, const char *message);
void add_recommendation(const char *fmt, ...);
void report_ok(const char *fmt, ...);
void report_warn(const char *fmt, ...);
void report_fail(const char *fmt, ...);
void report_info(const char *fmt, ...);
void report_progress(int current, int total, const char *msg);
void enable_json_only_output(void);
void write_json_report(const char *host);
void write_html_report(const char *host);
void print_interpretation(void);

/* ---- network.c ---- */

int         tcp_connect_timeout(const char *host, int port, int timeout_sec);
void        network_tests(const char *host);
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

/* ---- mount.c ---- */

int  run_command_capture(char *const argv[], char *output, size_t output_sz);
void register_mountpoint(const char *mountpoint);
void unregister_mountpoint(const char *mountpoint);
int  make_dir(const char *path, mode_t mode);
int  mount_export(const char *host, const char *export_path,
                  const char *mountpoint, struct mount_result *mr);
int  unmount_export(const char *mountpoint);
int  setup_mount_namespace(void);
void close_inherited_fds(int keep1, int keep2);

/* ---- tests.c ---- */

void diagnose_mounted_export(const char *export_path, const char *mountpoint,
                             int export_idx);

/* ---- exit codes for identity simulation (item 15) ---- */
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
void report_rpc_stats_diff(const struct rpc_stats *before,
                           const struct rpc_stats *after);
void parse_mountstats(const char *mountpoint);
void verify_mount_options(const char *mountpoint, struct export_report *report);
void collect_system_info(struct system_info *si);

#endif /* NFSDIAG_H */
