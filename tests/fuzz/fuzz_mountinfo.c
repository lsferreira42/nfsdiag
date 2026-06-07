/*
 * Fuzzer: /proc/self/mountinfo parser (main.c / mount option verification).
 *
 * Build:
 *   clang -O1 -g -fsanitize=fuzzer,address \
 *     fuzz_mountinfo.c -o fuzz_mountinfo
 *
 * Run:
 *   ./fuzz_mountinfo -max_total_time=5 corpus/
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void parse_mountinfo_buf(const char *buf, size_t len) {
    char line[1024];
    size_t i = 0;
    while (i < len) {
        size_t j = 0;
        while (i < len && buf[i] != '\n' && j < sizeof(line) - 1)
            line[j++] = buf[i++];
        if (i < len && buf[i] == '\n') i++;
        line[j] = '\0';

        /* Mimic the sscanf pattern from mount.c verify_mount_options(). */
        int mid = 0, parent = 0;
        unsigned maj = 0, min = 0;
        char root[256], mpt[256], opts[256], tags[256], fstype[64], src[256], super[256];
        if (sscanf(line,
                   "%d %d %u:%u %255s %255s %255s %255s %63s %255s %255s",
                   &mid, &parent, &maj, &min,
                   root, mpt, opts, tags, fstype, src, super) >= 7) {
            (void)mid; (void)parent; (void)maj; (void)min;
        }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *buf = malloc(size + 1);
    if (!buf) return 0;
    memcpy(buf, data, size);
    buf[size] = '\0';
    parse_mountinfo_buf(buf, size);
    free(buf);
    return 0;
}
