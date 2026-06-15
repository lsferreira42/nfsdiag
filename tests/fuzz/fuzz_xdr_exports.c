/*
 * Fuzzer: XDR exports list parser — exercises the REAL decoder in src/rpc.c
 * (xdr_exports_type), including the XDR_FREE path that clnt_freeres() runs.
 *
 * rpc.c is included directly so the static decoder is reachable; its
 * report/option dependencies are stubbed below.
 *
 * Build:
 *   clang -O1 -g -fsanitize=fuzzer,address \
 *     $(pkg-config --cflags libtirpc) -D_GNU_SOURCE \
 *     fuzz_xdr_exports.c -o fuzz_xdr_exports \
 *     $(pkg-config --libs libtirpc)
 *
 * Run (5 s corpus):
 *   ./fuzz_xdr_exports -max_total_time=5 corpus/
 */

#include "../../src/rpc.c"

/* ---- stubs for symbols rpc.c pulls from other modules ---- */
struct options opt;
int current_export_idx = -1;
void report_ok(const char *fmt, ...)   { (void)fmt; }
void report_warn(const char *fmt, ...) { (void)fmt; }
void report_fail(const char *fmt, ...) { (void)fmt; }
void report_info(const char *fmt, ...) { (void)fmt; }
void add_recommendation(const char *fmt, ...) { (void)fmt; }
int tcp_connect_timeout(const char *host, int port, int timeout_sec) {
    (void)host; (void)port; (void)timeout_sec; return -1;
}
const char *proto_name(unsigned long proto) { (void)proto; return "?"; }

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    XDR xdrs;
    exports ex = NULL;

    xdrmem_create(&xdrs, (char *)data, (unsigned int)size, XDR_DECODE);
    xdr_exports_type(&xdrs, &ex);
    xdr_destroy(&xdrs);

    /* Mirror clnt_freeres(): run the decoder's XDR_FREE path. */
    XDR fxdrs;
    memset(&fxdrs, 0, sizeof(fxdrs));
    fxdrs.x_op = XDR_FREE;
    xdr_exports_type(&fxdrs, &ex);
    return 0;
}
