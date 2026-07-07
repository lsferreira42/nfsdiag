#include "nfsdiag.h"

#ifdef NFSDIAG_ENABLE_EBPF
#include "bpf/nfsdiag.skel.h"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define NR_OPS 3
#define HIST_BUCKETS 32

static const char *op_name(int op) {
    switch (op) { case 0: return "read"; case 1: return "write"; default: return "commit"; }
}

static void print_histogram(int map_fd) {
    for (int op = 0; op < NR_OPS; op++) {
        unsigned long long total = 0, buckets[HIST_BUCKETS] = {0};
        for (int b = 0; b < HIST_BUCKETS; b++) {
            unsigned int key = (unsigned int)(op * HIST_BUCKETS + b);
            unsigned long long v = 0;
            if (bpf_map_lookup_elem(map_fd, &key, &v) == 0) { buckets[b] = v; total += v; }
        }
        if (total == 0) { report_info("latency %s: no samples", op_name(op)); continue; }
        report_ok("latency %s: %llu ops", op_name(op), total);
        for (int b = 0; b < HIST_BUCKETS; b++) {
            if (!buckets[b]) continue;
            unsigned long long lo = b == 0 ? 0 : (1ULL << (b - 1));
            unsigned long long hi = b == 0 ? 0 : ((1ULL << b) - 1);
            int bars = (int)(buckets[b] * 40 / total);
            char bar[41]; memset(bar, '#', (size_t)bars); bar[bars] = '\0';
            if (b == 0)
                report_info("  <1us         : %8llu %s", buckets[b], bar);
            else
                report_info("  %6llu-%6llu us: %8llu %s", lo, hi, buckets[b], bar);
        }
    }
}

struct client_key { unsigned char family; unsigned char addr[16]; };
struct client_val { unsigned long long ops; unsigned long long total_ns; };
struct client_row { struct client_key k; struct client_val v; };

static int by_ops_desc(const void *a, const void *b) {
    const struct client_row *ra = a, *rb = b;
    if (ra->v.ops < rb->v.ops) return 1;
    if (ra->v.ops > rb->v.ops) return -1;
    return 0;
}

static void print_clients(int map_fd) {
    struct client_row rows[4096];
    int n = 0;
    struct client_key key, next;
    int has = (bpf_map_get_next_key(map_fd, NULL, &next) == 0);
    while (has && n < 4096) {
        struct client_val v = {0};
        if (bpf_map_lookup_elem(map_fd, &next, &v) == 0) {
            rows[n].k = next; rows[n].v = v; n++;
        }
        key = next;
        has = (bpf_map_get_next_key(map_fd, &key, &next) == 0);
    }
    if (n == 0) { report_info("per-client: no NFS read/write/commit seen"); return; }
    qsort(rows, (size_t)n, sizeof(rows[0]), by_ops_desc);
    report_ok("per-client: %d client(s) active", n);
    for (int i = 0; i < n; i++) {
        char ip[64];
        fmt_client_ip(rows[i].k.addr, rows[i].k.family, ip, sizeof(ip));
        double avg_us = rows[i].v.ops ? (double)rows[i].v.total_ns / (double)rows[i].v.ops / 1000.0 : 0.0;
        report_info("  %-40s %8llu ops  avg %.1f us", ip, rows[i].v.ops, avg_us);
    }
}

int nfsdiag_ebpf_latency_run(int duration_s, int want_hist, int want_client) {
    struct nfsdiag_bpf *skel = nfsdiag_bpf__open_and_load();
    if (!skel) {
        report_warn("perf: BPF load failed: %s (needs root or CAP_BPF)", strerror(errno));
        return -1;
    }
    /* Attach each kprobe independently: not every nfsd symbol exists on every
     * kernel (e.g. nfsd_iter_read), so we tolerate individual misses and only
     * fail if nothing attached. */
    struct bpf_program *progs[] = {
        skel->progs.kp_nfsd_read,  skel->progs.krp_nfsd_read,
        skel->progs.kp_splice_read, skel->progs.krp_splice_read,
        skel->progs.kp_iter_read,  skel->progs.krp_iter_read,
        skel->progs.kp_nfsd_write, skel->progs.krp_nfsd_write,
        skel->progs.kp_vfs_write,  skel->progs.krp_vfs_write,
        skel->progs.kp_nfsd_commit, skel->progs.krp_nfsd_commit,
    };
    int attached = 0;
    for (size_t i = 0; i < sizeof(progs) / sizeof(progs[0]); i++) {
        if (bpf_program__attach(progs[i]) != NULL)
            attached++;
    }
    if (attached == 0) {
        report_warn("perf: no nfsd kprobes could be attached (is the nfsd module loaded?)");
        nfsdiag_bpf__destroy(skel);
        return -1;
    }
    report_info("perf: sampling nfsd read/write/commit for %ds (Ctrl-C to stop early)", duration_s);
    for (int i = 0; i < duration_s && !received_signal; i++)
        sleep(1);
    if (want_hist)
        print_histogram(bpf_map__fd(skel->maps.op_hist));
    if (want_client)
        print_clients(bpf_map__fd(skel->maps.client_stats));
    nfsdiag_bpf__destroy(skel);
    return 0;
}
#endif
