#include "nfsdiag.h"

static double bench_ms(struct timespec a, struct timespec b) {
    return (double)(b.tv_sec - a.tv_sec) * 1000.0 +
           (double)(b.tv_nsec - a.tv_nsec) / 1000000.0;
}

int storage_benchmark(const char *dir, size_t bytes, const char *engine,
                      double *write_mibs, double *read_mibs, char *err, size_t errsz) {
    *write_mibs = *read_mibs = 0.0;
    char path[4096];
    snprintf(path, sizeof(path), "%s/.nfsdiag-backend-bench.%d", dir, (int)getpid());
    int fd = open(path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) { snprintf(err, errsz, "cannot create file in %s: %s", dir, strerror(errno)); return -1; }

    if (engine && strcmp(engine, "fio") == 0) {
        char fsz[64], ffile[4096 + 16], out[CMD_OUTPUT_LIMIT];
        snprintf(fsz, sizeof(fsz), "--size=%zu", bytes);
        snprintf(ffile, sizeof(ffile), "--filename=%s", path);
        char *wargv[] = {"fio","--name=nfsdiag-backend","--ioengine=sync","--rw=write",
                         "--bs=1M","--direct=1",fsz,ffile,"--minimal",NULL};
        if (run_command_capture(wargv, out, sizeof(out)) != 0) {
            snprintf(err, errsz, "fio write failed"); close(fd); unlink(path); return -1;
        }
        char *rargv[] = {"fio","--name=nfsdiag-backend","--ioengine=sync","--rw=read",
                         "--bs=1M","--direct=1",fsz,ffile,"--minimal",NULL};
        run_command_capture(rargv, out, sizeof(out));
        *write_mibs = -1.0; *read_mibs = -1.0;
        close(fd); unlink(path); return 0;
    }

    char buf[65536];
    memset(buf, 0xa5, sizeof(buf));
    size_t left = bytes;
    struct timespec w0, w1, r0, r1;
    clock_gettime(CLOCK_MONOTONIC, &w0);
    while (left) {
        size_t c = left < sizeof(buf) ? left : sizeof(buf);
        ssize_t n = write(fd, buf, c);
        if (n < 0) { snprintf(err, errsz, "write: %s", strerror(errno)); close(fd); unlink(path); return -1; }
        left -= (size_t)n;
    }
    fsync(fd);
    clock_gettime(CLOCK_MONOTONIC, &w1);
    posix_fadvise(fd, 0, (off_t)bytes, POSIX_FADV_DONTNEED);
    lseek(fd, 0, SEEK_SET);
    left = bytes;
    clock_gettime(CLOCK_MONOTONIC, &r0);
    while (left) {
        size_t c = left < sizeof(buf) ? left : sizeof(buf);
        ssize_t n = read(fd, buf, c);
        if (n < 0) { snprintf(err, errsz, "read: %s", strerror(errno)); close(fd); unlink(path); return -1; }
        if (n == 0) break;
        left -= (size_t)n;
    }
    clock_gettime(CLOCK_MONOTONIC, &r1);
    double mib = (double)bytes / (1024.0 * 1024.0);
    double wm = bench_ms(w0, w1), rm = bench_ms(r0, r1);
    if (wm > 0.0) *write_mibs = mib / (wm / 1000.0);
    if (rm > 0.0) *read_mibs = mib / (rm / 1000.0);
    close(fd); unlink(path);
    return 0;
}
