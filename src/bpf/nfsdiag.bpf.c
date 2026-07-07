// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define OP_READ   0
#define OP_WRITE  1
#define OP_COMMIT 2
#define NR_OPS    3
#define HIST_BUCKETS 32

struct start_t { __u64 ts; __u32 op; __u8 family; __u8 addr[16]; };
struct client_key { __u8 family; __u8 addr[16]; };
struct client_val { __u64 ops; __u64 total_ns; };

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct start_t);
} starts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, NR_OPS * HIST_BUCKETS);
    __type(key, __u32);
    __type(value, __u64);
} op_hist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct client_key);
    __type(value, struct client_val);
} client_stats SEC(".maps");

static __always_inline void record_start(struct svc_rqst *rqstp, __u32 op)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct start_t s = {};
    s.ts = bpf_ktime_get_ns();
    s.op = op;
    __u16 fam = 0;
    bpf_core_read(&fam, sizeof(fam), &rqstp->rq_addr.ss_family);
    s.family = (__u8)fam;
    if (fam == 2) {
        struct sockaddr_in *si = (struct sockaddr_in *)&rqstp->rq_addr;
        bpf_core_read(&s.addr, 4, &si->sin_addr);
    } else if (fam == 10) {
        struct sockaddr_in6 *si6 = (struct sockaddr_in6 *)&rqstp->rq_addr;
        bpf_core_read(&s.addr, 16, &si6->sin6_addr);
    }
    bpf_map_update_elem(&starts, &id, &s, BPF_ANY);
}

static __always_inline void record_end(void)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct start_t *s = bpf_map_lookup_elem(&starts, &id);
    if (!s)
        return;
    __u64 delta = bpf_ktime_get_ns() - s->ts;
    __u64 us = delta / 1000;
    __u32 bucket = 0;
    while (us > 0 && bucket < HIST_BUCKETS - 1) { us >>= 1; bucket++; }
    if (s->op < NR_OPS) {
        __u32 idx = s->op * HIST_BUCKETS + bucket;
        __u64 *cnt = bpf_map_lookup_elem(&op_hist, &idx);
        if (cnt)
            __sync_fetch_and_add(cnt, 1);
    }
    struct client_key ck = {};
    ck.family = s->family;
    __builtin_memcpy(ck.addr, s->addr, 16);
    struct client_val *cv = bpf_map_lookup_elem(&client_stats, &ck);
    if (cv) {
        __sync_fetch_and_add(&cv->ops, 1);
        __sync_fetch_and_add(&cv->total_ns, delta);
    } else {
        struct client_val nv = { .ops = 1, .total_ns = delta };
        bpf_map_update_elem(&client_stats, &ck, &nv, BPF_ANY);
    }
    bpf_map_delete_elem(&starts, &id);
}

/* Read path: nfsd_read (NFSv2/3 wrapper) plus nfsd_splice_read / nfsd_iter_read
 * (the NFSv4 hot paths). Write path: nfsd_write (v3) plus nfsd_vfs_write (v4).
 * On v3 the wrapper calls the inner function (nesting): the inner start
 * overwrites the key and the inner return consumes it, so each op yields one
 * sample. On v4 only the inner probe fires. Not all symbols exist on every
 * kernel, so userspace attaches each probe independently and tolerates misses. */

SEC("kprobe/nfsd_read")
int BPF_KPROBE(kp_nfsd_read, struct svc_rqst *rqstp) { record_start(rqstp, OP_READ); return 0; }
SEC("kretprobe/nfsd_read")
int BPF_KRETPROBE(krp_nfsd_read) { record_end(); return 0; }

SEC("kprobe/nfsd_splice_read")
int BPF_KPROBE(kp_splice_read, struct svc_rqst *rqstp) { record_start(rqstp, OP_READ); return 0; }
SEC("kretprobe/nfsd_splice_read")
int BPF_KRETPROBE(krp_splice_read) { record_end(); return 0; }

SEC("kprobe/nfsd_iter_read")
int BPF_KPROBE(kp_iter_read, struct svc_rqst *rqstp) { record_start(rqstp, OP_READ); return 0; }
SEC("kretprobe/nfsd_iter_read")
int BPF_KRETPROBE(krp_iter_read) { record_end(); return 0; }

SEC("kprobe/nfsd_write")
int BPF_KPROBE(kp_nfsd_write, struct svc_rqst *rqstp) { record_start(rqstp, OP_WRITE); return 0; }
SEC("kretprobe/nfsd_write")
int BPF_KRETPROBE(krp_nfsd_write) { record_end(); return 0; }

SEC("kprobe/nfsd_vfs_write")
int BPF_KPROBE(kp_vfs_write, struct svc_rqst *rqstp) { record_start(rqstp, OP_WRITE); return 0; }
SEC("kretprobe/nfsd_vfs_write")
int BPF_KRETPROBE(krp_vfs_write) { record_end(); return 0; }

SEC("kprobe/nfsd_commit")
int BPF_KPROBE(kp_nfsd_commit, struct svc_rqst *rqstp) { record_start(rqstp, OP_COMMIT); return 0; }
SEC("kretprobe/nfsd_commit")
int BPF_KRETPROBE(krp_nfsd_commit) { record_end(); return 0; }
