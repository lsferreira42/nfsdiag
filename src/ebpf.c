#include "nfsdiag.h"

#ifdef NFSDIAG_ENABLE_EBPF
#include "bpf/nfsdiag.skel.h"

/* Open and load (verify) the embedded BPF object. Attach is not needed to
 * prove the toolchain end-to-end. Requires CAP_BPF/root to load. */
int nfsdiag_ebpf_selftest(void) {
    struct nfsdiag_bpf *skel = nfsdiag_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "eBPF: BPF load failed: %s\n", strerror(errno));
        return -1;
    }
    nfsdiag_bpf__destroy(skel);
    return 0;
}
#endif
