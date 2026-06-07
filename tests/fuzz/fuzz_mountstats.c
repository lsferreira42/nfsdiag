/*
 * Fuzzer: /proc/self/mountstats parser (stats.c).
 *
 * Build:
 *   clang -O1 -g -fsanitize=fuzzer,address \
 *     -I../../src $(pkg-config --cflags libtirpc) \
 *     fuzz_mountstats.c -o fuzz_mountstats \
 *     $(pkg-config --libs libtirpc)
 *
 * Run:
 *   ./fuzz_mountstats -max_total_time=5 corpus/
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Reproduce the mountstats parsing loop from stats.c without side-effects. */
static void parse_mountstats_buf(const char *buf, size_t len) {
    char line[512];
    size_t i = 0;
    while (i < len) {
        size_t j = 0;
        while (i < len && buf[i] != '\n' && j < sizeof(line) - 1)
            line[j++] = buf[i++];
        if (i < len && buf[i] == '\n') i++;
        line[j] = '\0';

        /* Mimic the sscanf patterns in stats.c */
        unsigned long long ops = 0, retrans = 0, major = 0, minor = 0;
        char opname[64];
        if (sscanf(line, " %63s %llu %*u %*u %*u %*u %llu", opname, &ops, &retrans) == 3) {
            (void)ops; (void)retrans;
        }
        if (sscanf(line, " nfs4_statfs: %llu %llu", &major, &minor) == 2) {
            (void)major; (void)minor;
        }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Null-terminate a copy so sscanf is safe. */
    char *buf = malloc(size + 1);
    if (!buf) return 0;
    memcpy(buf, data, size);
    buf[size] = '\0';
    parse_mountstats_buf(buf, size);
    free(buf);
    return 0;
}
