/*
 * Fuzzer: /proc/net/rpc/nfs parser — exercises the REAL parser in
 * src/stats.c (capture_rpc_stats_stream) over an fmemopen() buffer.
 *
 * Build:
 *   clang -O1 -g -fsanitize=fuzzer,address -I../../src \
 *     $(pkg-config --cflags libtirpc) -D_GNU_SOURCE \
 *     fuzz_rpcstats.c -o fuzz_rpcstats $(pkg-config --libs libtirpc)
 *
 * Run:
 *   ./fuzz_rpcstats -max_total_time=5 corpus/
 */

#include "../../src/stats.c"

struct options opt;
void report_ok(const char *fmt, ...)   { (void)fmt; }
void report_warn(const char *fmt, ...) { (void)fmt; }
void report_fail(const char *fmt, ...) { (void)fmt; }
void report_info(const char *fmt, ...) { (void)fmt; }
void add_recommendation(const char *fmt, ...) { (void)fmt; }
int resolve_command_path(const char *cmd, char *out, size_t out_sz) {
    (void)cmd; (void)out; (void)out_sz; return -1;
}
int run_command_capture(char *const argv[], char *output, size_t output_sz) {
    (void)argv; if (output && output_sz) output[0] = '\0'; return -1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FILE *f = fmemopen((void *)data, size, "r");
    if (!f) return 0;
    struct rpc_stats st;
    capture_rpc_stats_stream(f, &st);
    fclose(f);
    return 0;
}
