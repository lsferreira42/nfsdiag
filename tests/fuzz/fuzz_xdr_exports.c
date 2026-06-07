/*
 * Fuzzer: XDR exports list parser (rpc.c / mountd EXPORT reply).
 *
 * Build:
 *   clang -O1 -g -fsanitize=fuzzer,address \
 *     -I../../src $(pkg-config --cflags libtirpc) \
 *     fuzz_xdr_exports.c -o fuzz_xdr_exports \
 *     $(pkg-config --libs libtirpc)
 *
 * Run (5 s corpus):
 *   ./fuzz_xdr_exports -max_total_time=5 corpus/
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <rpc/xdr.h>
#include <rpc/types.h>

/* Declaration pulled from rpc.c to keep the fuzzer self-contained. */
struct groupnode {
    char           *gr_name;
    struct groupnode *gr_next;
};
struct exportnode {
    char            *ex_dir;
    struct groupnode *ex_groups;
    struct exportnode *ex_next;
};

static bool_t xdr_groupnode(XDR *xdrs, struct groupnode **gp);
static bool_t xdr_exportnode(XDR *xdrs, struct exportnode **ep);

/* Minimal XDR helpers mirroring rpc.c. */
static bool_t xdr_groupnode(XDR *xdrs, struct groupnode **gp) {
    *gp = NULL;
    return xdr_pointer(xdrs, (char **)gp, sizeof(struct groupnode),
                       (xdrproc_t)xdr_groupnode);
}
static bool_t xdr_exportnode(XDR *xdrs, struct exportnode **ep) {
    *ep = NULL;
    return xdr_pointer(xdrs, (char **)ep, sizeof(struct exportnode),
                       (xdrproc_t)xdr_exportnode);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    XDR xdrs;
    xdrmem_create(&xdrs, (char *)data, (unsigned int)size, XDR_DECODE);
    struct exportnode *ep = NULL;
    xdr_exportnode(&xdrs, &ep);
    xdr_destroy(&xdrs);
    return 0;
}
