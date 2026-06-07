/*
 * Fuzzer: /proc/net/rpc/nfs stats parser (stats.c).
 *
 * Build:
 *   clang -O1 -g -fsanitize=fuzzer,address \
 *     fuzz_rpcstats.c -o fuzz_rpcstats
 *
 * Run:
 *   ./fuzz_rpcstats -max_total_time=5 corpus/
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void parse_rpcstats_buf(const char *buf, size_t len) {
    char line[512];
    size_t i = 0;
    while (i < len) {
        size_t j = 0;
        while (i < len && buf[i] != '\n' && j < sizeof(line) - 1)
            line[j++] = buf[i++];
        if (i < len && buf[i] == '\n') i++;
        line[j] = '\0';

        /* Mimic the sscanf patterns from stats.c read_rpc_stats(). */
        char label[64];
        unsigned long v1 = 0, v2 = 0, v3 = 0, v4 = 0, v5 = 0;
        if (sscanf(line, "%63s %lu %lu %lu %lu %lu", label, &v1, &v2, &v3, &v4, &v5) >= 2) {
            if (strcmp(label, "rpc") == 0) {
                (void)v1; (void)v2; (void)v3;
            }
        }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *buf = malloc(size + 1);
    if (!buf) return 0;
    memcpy(buf, data, size);
    buf[size] = '\0';
    parse_rpcstats_buf(buf, size);
    free(buf);
    return 0;
}
