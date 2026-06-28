#include "nfsdiag.h"

static double elapsed_ms(struct timespec a, struct timespec b) {
    return (double)(b.tv_sec - a.tv_sec) * 1000.0 +
           (double)(b.tv_nsec - a.tv_nsec) / 1000000.0;
}

static int fill_file(int fd, size_t bytes) {
    char buf[65536];
    memset(buf, 'N', sizeof(buf));
    size_t left = bytes;
    while (left) {
        size_t chunk = left < sizeof(buf) ? left : sizeof(buf);
        ssize_t w = write(fd, buf, chunk);
        if (w <= 0) return -1;
        left -= (size_t)w;
    }
    return 0;
}

static int g_random_degraded = 0;

static uint32_t test_random(void) {
    uint32_t rnd = 0;
    if (getrandom(&rnd, sizeof(rnd), 0) < 0) {
        int rfd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
        ssize_t got = -1;
        if (rfd >= 0) {
            got = read(rfd, &rnd, sizeof(rnd));
            close(rfd);
        }
        if (got != (ssize_t)sizeof(rnd)) {
            rnd = (uint32_t)(time(NULL) ^ getpid());
            g_random_degraded = 1;
        }
    }
    return rnd;
}

static void make_test_path(char *dst, size_t sz, const char *mp, const char *sfx) {
    /* Add random bytes to make test paths unpredictable even in shared
     * exports, preventing timing-based symlink pre-creation by other users. */
    snprintf(dst, sz, "%s/.nfsdiag-%ld-%08x-%s", mp, (long)getpid(), test_random(), sfx);
}

static void cleanup_test_path(const char *path) {
    if (!path || !path[0]) return;
    if (unlink(path) != 0 && errno != ENOENT)
        report_warn("test path cleanup failed for %s: %s", path, strerror(errno));
}

static int cmp_double(const void *a, const void *b) {
    double da = *(const double *)a, db = *(const double *)b;
    return (da > db) - (da < db);
}

/* ---- FS timeout ---- */
static volatile sig_atomic_t fs_timeout_fired = 0;
static void fs_timeout_handler(int sig) { (void)sig; fs_timeout_fired = 1; }

static void arm_fs_timeout(struct sigaction *old) {
    if (opt.fs_timeout_sec <= 0) return;
    fs_timeout_fired = 0;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = fs_timeout_handler;
    sigaction(SIGALRM, &sa, old);
    alarm((unsigned)opt.fs_timeout_sec);
}

static void disarm_fs_timeout(const struct sigaction *old) {
    /* Mirror arm_fs_timeout(): when arming was skipped, *old was never
     * filled in and must not be passed to sigaction(). */
    if (opt.fs_timeout_sec <= 0) return;
    alarm(0);
    if (old) sigaction(SIGALRM, old, NULL);
    fs_timeout_fired = 0;
}

static void test_basic_mount_info(const char *mp) {
    struct stat st;
    if (stat(mp, &st) == 0)
        report_ok("stat mount root succeeded: inode=%lu mode=%o uid=%lu gid=%lu",
                  (unsigned long)st.st_ino, st.st_mode & 07777,
                  (unsigned long)st.st_uid, (unsigned long)st.st_gid);
    else if (errno == ESTALE)
        report_fail("stat mount root returned ESTALE (stale file handle)");
    else
        report_fail("stat mount root failed: %s", strerror(errno));

    struct statvfs vfs;
    if (statvfs(mp, &vfs) == 0) {
        unsigned long long total = (unsigned long long)vfs.f_blocks * vfs.f_frsize;
        unsigned long long avail = (unsigned long long)vfs.f_bavail * vfs.f_frsize;
        report_ok("statvfs succeeded: total=%llu bytes available=%llu bytes", total, avail);
    } else if (errno == ESTALE)
        report_fail("statvfs returned ESTALE (stale file handle)");
    else
        report_warn("statvfs failed: %s", strerror(errno));
}

static void test_directory_access(const char *mp) {
    if (access(mp, R_OK | X_OK) == 0)
        report_ok("directory read/traverse access allowed for current identity");
    else
        report_warn("directory read/traverse access denied for current identity: %s", strerror(errno));

    DIR *d = opendir(mp);
    if (!d) {
        if (errno == ESTALE) report_fail("opendir returned ESTALE (stale file handle)");
        else report_warn("opendir failed: %s", strerror(errno));
        return;
    }
    int entries = 0;
    errno = 0;
    while (readdir(d) && entries < 32) entries++;
    if (errno == ESTALE) report_fail("readdir returned ESTALE (stale file handle)");
    else if (errno) report_warn("readdir failed after %d entries: %s", entries, strerror(errno));
    else report_ok("directory listing succeeded; sampled %d entries", entries);
    closedir(d);
}

/* ---- ACL with NFSv4 support ---- */
static void test_acl(const char *mp, struct export_report *rpt) {
    ssize_t sz = getxattr(mp, "system.posix_acl_access", NULL, 0);
    if (sz > 0) { report_ok("POSIX ACL detected on export root (%zd bytes)", sz); rpt->acl_posix = 1; }
    else if (sz == 0) report_info("POSIX ACL xattr exists but is empty");
    else if (errno == ENODATA || errno == ENOATTR) report_info("no POSIX ACL xattr detected on export root");
    else if (errno == EOPNOTSUPP || errno == ENOTSUP) report_info("ACL xattrs are not supported or hidden by this mount: %s", strerror(errno));
    else if (errno == EACCES || errno == EPERM) report_warn("cannot read ACL xattr due to permissions: %s", strerror(errno));
    else report_warn("ACL xattr probe failed: %s", strerror(errno));

    sz = getxattr(mp, "system.nfs4_acl", NULL, 0);
    if (sz > 0) { report_ok("NFSv4 ACL detected on export root (%zd bytes)", sz); rpt->acl_nfsv4 = 1; }
    else if (sz == 0) report_info("NFSv4 ACL xattr exists but is empty");
    else if (errno == ENODATA || errno == ENOATTR) report_info("no NFSv4 ACL xattr detected on export root");
    else if (errno == EOPNOTSUPP || errno == ENOTSUP) report_info("NFSv4 ACL xattrs not supported by this mount: %s", strerror(errno));
    else report_info("NFSv4 ACL xattr probe: %s", strerror(errno));
}

static void test_metadata_latency(const char *mp, struct export_report *rpt) {
    if (!opt.write_test || opt.bench_iterations <= 0) return;
    double *samples = calloc((size_t)opt.bench_iterations, sizeof(double));
    if (!samples) return;

    struct sigaction old_sa;
    arm_fs_timeout(&old_sa);
    int completed = 0;
    for (int i = 0; i < opt.bench_iterations && !fs_timeout_fired; i++) {
        char path[4096], renamed[8192];
        char sfx[32];
        snprintf(sfx, sizeof(sfx), "meta-%d", i);
        make_test_path(path, sizeof(path), mp, sfx);
        snprintf(renamed, sizeof(renamed), "%s.renamed", path);
        struct timespec a, b;
        clock_gettime(CLOCK_MONOTONIC, &a);
        int fd = open(path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (fd < 0) break;
        if (write(fd, "x", 1) < 0) { close(fd); cleanup_test_path(path); break; }
        close(fd);
        if (rename(path, renamed) != 0) { cleanup_test_path(path); break; }
        if (unlink(renamed) != 0) { cleanup_test_path(renamed); break; }
        clock_gettime(CLOCK_MONOTONIC, &b);
        samples[completed++] = elapsed_ms(a, b);
    }
    disarm_fs_timeout(&old_sa);
    if (fs_timeout_fired) report_warn("metadata latency benchmark timed out after %d seconds", opt.fs_timeout_sec);
    if (completed > 0) {
        qsort(samples, (size_t)completed, sizeof(double), cmp_double);
        
        double p50, p95, p99;
        const double ps[] = {0.50, 0.95, 0.99};
        double *res[] = {&p50, &p95, &p99};

        for (int p = 0; p < 3; p++) {
            if (completed == 1) {
                *res[p] = samples[0];
            } else {
                double idx = (completed - 1) * ps[p];
                int i = (int)idx;
                if (i + 1 < completed) {
                    double frac = idx - i;
                    *res[p] = samples[i] + frac * (samples[i + 1] - samples[i]);
                } else
                    *res[p] = samples[i];
            }
        }
        
        report_ok("metadata latency benchmark create+rename+unlink: n=%d p50=%.2fms p95=%.2fms p99=%.2fms", completed, p50, p95, p99);
        rpt->meta_p50_ms = p50; rpt->meta_p95_ms = p95; rpt->meta_p99_ms = p99; rpt->meta_completed = completed;
    } else {
        report_info("metadata latency benchmark skipped because no iteration completed");
    }
    free(samples);
}

static void test_write_read_benchmark(const char *mp, struct export_report *rpt) {
    if (!opt.write_test) {
        report_info("write/read benchmark skipped by --read-only");
        return;
    }
    if (opt.bench_bytes < 4U * 1024U * 1024U)
        report_warn("benchmark sample is small (%zu bytes); treat throughput as smoke-test signal, not capacity", opt.bench_bytes);
    char path[4096];
    make_test_path(path, sizeof(path), mp, "io-bench");
    struct sigaction old_sa;
    arm_fs_timeout(&old_sa);

    int fd = open(path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        disarm_fs_timeout(&old_sa);
        if (errno == ESTALE) report_fail("creating test file returned ESTALE");
        else report_warn("cannot create test file; export may be read-only or permission denied: %s", strerror(errno));
        add_recommendation("Create/write failed: check export ro/rw options, UNIX mode bits, ACLs, root_squash, idmapping, and server-side MAC policies.");
        return;
    }

    if (opt.bench_type && strcmp(opt.bench_type, "fio") == 0) {
        char fio_size[64], fio_file[4096 + 16];
        int rs = snprintf(fio_size, sizeof(fio_size), "--size=%zu", opt.bench_bytes);
        int rf = snprintf(fio_file, sizeof(fio_file), "--filename=%s", path);
        if (rs < 0 || (size_t)rs >= sizeof(fio_size) ||
            rf < 0 || (size_t)rf >= sizeof(fio_file)) {
            report_warn("fio argument construction truncated; skipping fio benchmark");
            close(fd); cleanup_test_path(path); disarm_fs_timeout(&old_sa); return;
        }
        char output[CMD_OUTPUT_LIMIT];
        char *fio_write_argv[] = {"fio", "--name=nfsdiag", "--ioengine=sync",
                                  "--rw=write", "--bs=1M", fio_size, fio_file,
                                  "--output-format=json", NULL};
        if (run_command_capture(fio_write_argv, output, sizeof(output)) == 0) {
            report_ok("fio write benchmark completed (check JSON for full stats)");
            rpt->write_mib_s = -1.0;
        } else {
            report_warn("fio write benchmark failed");
        }
        char *fio_read_argv[] = {"fio", "--name=nfsdiag", "--ioengine=sync",
                                 "--rw=read", "--bs=1M", fio_size, fio_file,
                                 "--output-format=json", NULL};
        if (run_command_capture(fio_read_argv, output, sizeof(output)) == 0) {
            report_ok("fio read benchmark completed (check JSON for full stats)");
            rpt->read_mib_s = -1.0;
        } else {
            report_warn("fio read benchmark failed");
        }
    } else {
        struct timespec w0, w1, r0, r1;
        clock_gettime(CLOCK_MONOTONIC, &w0);
        if (fs_timeout_fired || fill_file(fd, opt.bench_bytes) != 0) {
            if (fs_timeout_fired) report_warn("write benchmark timed out after %d seconds", opt.fs_timeout_sec);
            else if (errno == ESTALE) report_fail("write returned ESTALE");
            else if (errno == EDQUOT) report_fail("write failed: Disk quota exceeded (EDQUOT)");
            else if (errno == ENOSPC) report_fail("write failed: No space left on device (ENOSPC)");
            else report_fail("write test failed: %s", strerror(errno));
            close(fd); cleanup_test_path(path); disarm_fs_timeout(&old_sa); return;
        }
        if (fsync(fd) != 0) report_warn("fsync failed: %s", strerror(errno));
        clock_gettime(CLOCK_MONOTONIC, &w1);

        /* Drop the just-written pages from the client page cache so the
         * readback exercises the server instead of local memory. */
        int cache_dropped =
            posix_fadvise(fd, 0, (off_t)opt.bench_bytes, POSIX_FADV_DONTNEED) == 0;

        lseek(fd, 0, SEEK_SET);
        char buf[65536];
        size_t left = opt.bench_bytes;
        clock_gettime(CLOCK_MONOTONIC, &r0);
        while (left && !fs_timeout_fired) {
            size_t chunk = left < sizeof(buf) ? left : sizeof(buf);
            ssize_t n = read(fd, buf, chunk);
            if (n < 0) {
                if (errno == ESTALE) report_fail("read returned ESTALE");
                else report_fail("readback failed: %s", strerror(errno));
                break;
            }
            if (n == 0) break;
            left -= (size_t)n;
        }
        clock_gettime(CLOCK_MONOTONIC, &r1);

        double write_ms = elapsed_ms(w0, w1), read_ms = elapsed_ms(r0, r1);
        double mib = (double)opt.bench_bytes / (1024.0 * 1024.0);
        if (write_ms > 0.0) {
            rpt->write_mib_s = mib / (write_ms / 1000.0);
            report_ok("write+fsync benchmark: %.2f MiB in %.2f ms (%.2f MiB/s)", mib, write_ms, rpt->write_mib_s);
        }
        if (read_ms > 0.0) {
            rpt->read_mib_s = mib / (read_ms / 1000.0);
            report_ok("read benchmark: %.2f MiB in %.2f ms (%.2f MiB/s)%s", mib, read_ms,
                      rpt->read_mib_s,
                      cache_dropped ? "" : " [may include client page cache]");
        }
    }

    disarm_fs_timeout(&old_sa);
    close(fd);
    cleanup_test_path(path);
}

static void test_advisory_lock(const char *mp, struct export_report *rpt) {
    if (!opt.write_test) return;
    char path[4096];
    make_test_path(path, sizeof(path), mp, "lock-test");
    struct sigaction old_sa;
    arm_fs_timeout(&old_sa);

    int fd = open(path, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        disarm_fs_timeout(&old_sa);
        report_info("advisory lock test skipped: cannot create file: %s", strerror(errno));
        return;
    }
    if (write(fd, "x", 1) < 0) {
        close(fd); cleanup_test_path(path); disarm_fs_timeout(&old_sa); return;
    }

    struct flock fl;
    memset(&fl, 0, sizeof(fl));
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    if (fcntl(fd, F_SETLK, &fl) == 0) {
        report_ok("fcntl advisory write lock succeeded (basic NLM/NFSv4 locking path works)");
        rpt->lock_ok = 1;
        fl.l_type = F_UNLCK;
        (void)fcntl(fd, F_SETLK, &fl);
    } else {
        report_warn("fcntl advisory lock failed: %s", strerror(errno));
    }

    disarm_fs_timeout(&old_sa);
    close(fd);
    cleanup_test_path(path);
}

static void test_root_squash(const char *mp, struct export_report *rpt) {
    if (!opt.write_test) return;
    char path[4096];
    make_test_path(path, sizeof(path), mp, "squash-test");
    struct sigaction old_sa;
    arm_fs_timeout(&old_sa);

    int fd = open(path, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        disarm_fs_timeout(&old_sa);
        report_info("root_squash test skipped: cannot create file: %s", strerror(errno));
        return;
    }
    if (write(fd, "x", 1) < 0) {
        close(fd); cleanup_test_path(path); disarm_fs_timeout(&old_sa); return;
    }

    struct stat st;
    if (fstat(fd, &st) == 0) {
        if (geteuid() == 0) {
            if (st.st_uid == 0) {
                report_ok("root_squash practical signal: file created by root is owned by uid 0 (likely no_root_squash)");
            } else {
                report_warn("root_squash practical signal: file created by root is owned by uid %lu gid %lu (root is likely squashed)",
                            (unsigned long)st.st_uid, (unsigned long)st.st_gid);
                rpt->root_squash_detected = 1;
                int has_nonroot_identity = 0;
                for (size_t i = 0; i < opt.identity_count; i++) {
                    if (opt.uids[i] != 0) { has_nonroot_identity = 1; break; }
                }
                if (opt.identity_count == 0) {
                    add_recommendation("root_squash appears active: run tests as the application UID/GID with --uid/--gid to validate real access.");
                } else if (!has_nonroot_identity) {
                    add_recommendation("root_squash appears active and the only simulated identity is uid 0; root is exactly the identity that gets squashed. Re-run with the application's non-root --uid/--gid to validate real access.");
                } else {
                    report_info("root_squash appears active; real access is being validated via the non-root --uid/--gid identity simulation");
                }
            }
        } else {
            report_info("root_squash practical test requires root; current euid=%lu", (unsigned long)geteuid());
        }
    } else if (errno == ESTALE) {
        report_fail("fstat test file returned ESTALE");
    } else {
        report_warn("fstat test file failed: %s", strerror(errno));
    }

    disarm_fs_timeout(&old_sa);
    close(fd);
    cleanup_test_path(path);
}

static void test_special_files(const char *mp) {
    if (!opt.write_test) return;
    if (!opt.dangerous_fs_tests) {
        report_info("special file probes skipped; pass --dangerous-fs-tests for symlink/hardlink/FIFO/device-node tests");
        return;
    }
    struct sigaction old_sa;
    arm_fs_timeout(&old_sa);
    char path1[4096], path2[4096];
    make_test_path(path1, sizeof(path1), mp, "symlink-target");
    make_test_path(path2, sizeof(path2), mp, "symlink");
    
    if (symlink(path1, path2) == 0) {
        report_ok("symlink creation succeeded");
        cleanup_test_path(path2);
    } else {
        report_info("symlink creation failed: %s", strerror(errno));
    }
    
    int fd = open(path1, O_CREAT | O_WRONLY | O_NOFOLLOW, 0600);
    if (fd >= 0) {
        close(fd);
        if (link(path1, path2) == 0) {
            report_ok("hardlink creation succeeded");
            cleanup_test_path(path2);
        } else {
            report_info("hardlink creation failed: %s", strerror(errno));
        }
        cleanup_test_path(path1);
    }
    
    make_test_path(path1, sizeof(path1), mp, "fifo");
    if (mkfifo(path1, 0600) == 0) {
        report_ok("mkfifo succeeded");
        cleanup_test_path(path1);
    } else {
        report_info("mkfifo failed: %s", strerror(errno));
    }
    
    make_test_path(path1, sizeof(path1), mp, "device");
    if (mknod(path1, S_IFCHR | 0600, makedev(1, 3)) == 0) { /* /dev/null major/minor */
        report_ok("mknod succeeded (device node creation allowed)");
        cleanup_test_path(path1);
    } else {
        report_info("mknod failed: %s (expected if root_squash or server blocks it)", strerror(errno));
    }

    disarm_fs_timeout(&old_sa);
}

static void test_xattr_support(const char *mp) {
    if (!opt.write_test) return;
    struct sigaction old_sa;
    arm_fs_timeout(&old_sa);
    char path[4096];
    make_test_path(path, sizeof(path), mp, "xattr");
    int fd = open(path, O_CREAT | O_WRONLY | O_NOFOLLOW, 0600);
    if (fd < 0) { disarm_fs_timeout(&old_sa); return; }
    close(fd);

    const char *attrs[] = {"user.test", "trusted.test", "security.selinux"};
    for (int i = 0; i < 3; i++) {
        if (setxattr(path, attrs[i], "1", 1, 0) == 0) {
            report_ok("setxattr %s succeeded", attrs[i]);
        } else {
            if (errno == ENOTSUP || errno == EOPNOTSUPP) {
                report_info("xattr %s not supported by this mount/server", attrs[i]);
            } else if (errno == EACCES || errno == EPERM) {
                report_info("setxattr %s denied by permissions", attrs[i]);
            } else {
                report_warn("setxattr %s failed: %s", attrs[i], strerror(errno));
            }
        }
    }
    cleanup_test_path(path);
    disarm_fs_timeout(&old_sa);
}

static void test_copy_file_range(const char *mp) {
    if (!opt.write_test) return;
    struct sigaction old_sa;
    arm_fs_timeout(&old_sa);
    char path1[4096], path2[4096];
    make_test_path(path1, sizeof(path1), mp, "cfr-src");
    make_test_path(path2, sizeof(path2), mp, "cfr-dst");

    int fd1 = open(path1, O_CREAT | O_WRONLY | O_NOFOLLOW, 0600);
    if (fd1 < 0) { disarm_fs_timeout(&old_sa); return; }
    if (write(fd1, "testdata", 8) != 8) { close(fd1); cleanup_test_path(path1); disarm_fs_timeout(&old_sa); return; }
    close(fd1);

    fd1 = open(path1, O_RDONLY | O_NOFOLLOW);
    int fd2 = open(path2, O_CREAT | O_WRONLY | O_NOFOLLOW, 0600);
    if (fd1 >= 0 && fd2 >= 0) {
        loff_t off_in = 0, off_out = 0;
        ssize_t ret = copy_file_range(fd1, &off_in, fd2, &off_out, 8, 0);
        if (ret == 8) {
            report_ok("copy_file_range succeeded (server-side copy enabled or emulated)");
        } else if (ret < 0) {
            if (errno == ENOSYS || errno == EXDEV || errno == EOPNOTSUPP) {
                report_info("copy_file_range not supported: %s", strerror(errno));
            } else {
                report_warn("copy_file_range failed: %s", strerror(errno));
            }
        }
    }
    if (fd1 >= 0) close(fd1);
    if (fd2 >= 0) close(fd2);
    cleanup_test_path(path1);
    cleanup_test_path(path2);
    disarm_fs_timeout(&old_sa);
}

static void test_fallocate_odirect(const char *mp) {
    if (!opt.write_test) return;
    struct sigaction old_sa;
    arm_fs_timeout(&old_sa);
    char path[4096];
    make_test_path(path, sizeof(path), mp, "falloc");
    int fd = open(path, O_CREAT | O_RDWR | O_DIRECT | O_NOFOLLOW, 0600);
    if (fd >= 0) {
        report_ok("O_DIRECT flag accepted by mount (page cache bypass may be available)");
        if (fallocate(fd, 0, 0, 1024 * 1024) == 0) {
            report_ok("fallocate succeeded (pre-allocation supported)");
        } else {
            if (errno == EOPNOTSUPP || errno == ENOSYS)
                report_info("fallocate not supported");
            else
                report_warn("fallocate failed: %s", strerror(errno));
        }
        close(fd);
    } else {
        if (errno == EINVAL)
            report_info("O_DIRECT open failed (EINVAL, likely unsupported by mount/kernel)");
        else
            report_warn("O_DIRECT open failed: %s", strerror(errno));
    }
    cleanup_test_path(path);
    disarm_fs_timeout(&old_sa);
}

static void test_close_to_open(const char *mp) {
    if (!opt.write_test) return;
    struct sigaction old_sa;
    arm_fs_timeout(&old_sa);
    char path[4096];
    make_test_path(path, sizeof(path), mp, "cto");
    int fd = open(path, O_CREAT | O_WRONLY | O_NOFOLLOW, 0600);
    if (fd < 0) { disarm_fs_timeout(&old_sa); return; }
    if (write(fd, "test", 4) != 4) { close(fd); cleanup_test_path(path); disarm_fs_timeout(&old_sa); return; }
    close(fd);

    fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd >= 0) {
        char buf[8] = {0};
        if (read(fd, buf, 4) == 4 && memcmp(buf, "test", 4) == 0) {
            report_ok("close-to-open cache consistency verified");
        } else {
            report_fail("close-to-open cache consistency check failed");
        }
        close(fd);
    }
    cleanup_test_path(path);
    disarm_fs_timeout(&old_sa);
}

static int child_identity_probe(const char *mp, uid_t uid, gid_t gid) {
    prctl(PR_SET_PDEATHSIG, SIGKILL);
    close_inherited_fds(-1, -1);

    /* Clear ambient capabilities before setuid so the child does not
     * inherit capabilities from the parent (available since Linux 4.3).
     * Failure is non-fatal — we proceed without ambient cap clearing. */
    prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);

    /* Always reset supplemental groups: without this the child keeps the
     * parent's (typically root's) groups and the access checks pass for
     * identities that would be denied in reality. */
    if (opt.supplemental_group_count > 0) {
        if (setgroups(opt.supplemental_group_count, opt.supplemental_groups) != 0) _exit(CHILD_SETGROUPS_FAIL);
    } else if (geteuid() == 0 && setgroups(1, &gid) != 0) {
        _exit(CHILD_SETGROUPS_FAIL);
    }
    if (setgid(gid) != 0) _exit(CHILD_SETGID_FAIL);
    if (setuid(uid) != 0) _exit(CHILD_SETUID_FAIL);
    if (access(mp, R_OK | X_OK) != 0) _exit(CHILD_ACCESS_DENIED);
    if (!opt.write_test) _exit(CHILD_OK);
    char path[4096];
    make_test_path(path, sizeof(path), mp, "identity");
    int fd = open(path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) _exit(errno == EACCES || errno == EPERM || errno == EROFS ? CHILD_CREATE_DENIED : CHILD_OPEN_ERROR);
    if (write(fd, "x", 1) != 1) { close(fd); unlink(path); _exit(CHILD_WRITE_ERROR); }
    close(fd); unlink(path); _exit(CHILD_OK);
}

static void test_identity_simulation(const char *mp) {
    if (opt.verbose) printf("\n    [identity simulation]\n");
    int user_req = opt.identity_count > 0;
    size_t saved = opt.identity_count;
    if (opt.identity_count == 0) {
        opt.uids[0] = geteuid(); opt.gids[0] = getegid(); opt.identity_count = 1;
        struct passwd pwd;
        struct passwd *nobody = NULL;
        char nbuf[4096];
        if (getpwnam_r("nobody", &pwd, nbuf, sizeof(nbuf), &nobody) != 0)
            nobody = NULL;
        if (geteuid() == 0 && nobody) { opt.uids[1] = nobody->pw_uid; opt.gids[1] = nobody->pw_gid; opt.identity_count = 2; }
    }
    if (geteuid() != 0) report_info("not running as root; UID/GID simulation is limited to current identity only");
    for (size_t i = 0; i < opt.identity_count; i++) {
        uid_t uid = opt.uids[i]; gid_t gid = opt.gids[i];
        if (uid != geteuid() && geteuid() != 0) { report_warn("cannot simulate uid=%lu gid=%lu without root", (unsigned long)uid, (unsigned long)gid); continue; }
        if (opt.supplemental_group_count > 0 && geteuid() != 0) {
            report_warn("supplemental groups for uid=%lu require root; skipping group simulation",
                        (unsigned long)uid);
            continue;
        }
        pid_t pid = fork();
        if (pid < 0) { report_warn("fork failed for identity simulation: %s", strerror(errno)); continue; }
        if (pid == 0) child_identity_probe(mp, uid, gid);
        int status = 0;
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
        int code = WIFEXITED(status) ? WEXITSTATUS(status) : 255;
        if (code == CHILD_OK) report_ok("uid=%lu gid=%lu can traverse/read%s", (unsigned long)uid, (unsigned long)gid, opt.write_test ? " and create/write" : "");
        else if (code == CHILD_ACCESS_DENIED) { if (user_req) report_warn("uid=%lu gid=%lu cannot traverse/read export root", (unsigned long)uid, (unsigned long)gid); else report_info("uid=%lu gid=%lu cannot traverse/read export root", (unsigned long)uid, (unsigned long)gid); }
        else if (code == CHILD_CREATE_DENIED) { if (user_req) report_warn("uid=%lu gid=%lu can read/traverse but cannot create/write", (unsigned long)uid, (unsigned long)gid); else report_info("uid=%lu gid=%lu can read/traverse but cannot create/write", (unsigned long)uid, (unsigned long)gid); }
        else if (code == CHILD_SETGID_FAIL || code == CHILD_SETUID_FAIL || code == CHILD_SETGROUPS_FAIL) report_warn("failed to switch to uid=%lu gid=%lu for simulation", (unsigned long)uid, (unsigned long)gid);
        else report_warn("uid=%lu gid=%lu simulation failed with code %d", (unsigned long)uid, (unsigned long)gid, code);
    }
    if (saved == 0) opt.identity_count = 0;
}

static void test_stale_loop(const char *mp, struct export_report *rpt) {
    if (opt.stale_iterations <= 0) {
        report_info("ESTALE probe skipped (--stale-iterations 0)");
        return;
    }
    if (opt.verbose) printf("\n    [stale handle loop]\n");
    int estale_seen = 0;
    for (int i = 0; i < opt.stale_iterations; i++) {
        struct stat st;
        if (stat(mp, &st) != 0) {
            if (errno == ESTALE) { estale_seen = 1; report_fail("ESTALE detected during stat loop at iteration %d", i + 1); break; }
            report_warn("stat loop failed at iteration %d: %s", i + 1, strerror(errno)); break;
        }
        DIR *d = opendir(mp);
        if (!d) {
            if (errno == ESTALE) { estale_seen = 1; report_fail("ESTALE detected during opendir loop at iteration %d", i + 1); break; }
            report_warn("opendir loop failed at iteration %d: %s", i + 1, strerror(errno)); break;
        }
        errno = 0; (void)readdir(d);
        if (errno == ESTALE) { estale_seen = 1; report_fail("ESTALE detected during readdir loop at iteration %d", i + 1); closedir(d); break; }
        closedir(d);
    }
    if (estale_seen) rpt->estale_seen = 1;
    if (!estale_seen) report_ok("no ESTALE observed in %d stat/readdir iterations", opt.stale_iterations);
}

/* ---- Long filenames and special character test ---- */

/* Create-and-remove a single probe file. O_EXCL guarantees we never open or
 * unlink a file we did not create, so a pre-existing user file at the same
 * path (extremely unlikely given the random component) is left untouched. */
static void probe_special_name(const char *path, const char *what) {
    int fd = open(path, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, 0600);
    if (fd >= 0) {
        report_ok("%s created successfully", what);
        close(fd);
        cleanup_test_path(path);
    } else if (errno == ENAMETOOLONG) {
        report_info("%s rejected (ENAMETOOLONG): server/export limits name length", what);
    } else if (errno == EEXIST) {
        report_info("%s skipped: generated path already exists, not overwriting", what);
    } else {
        report_info("%s: %s", what, strerror(errno));
    }
}

static void test_long_filenames(const char *mp) {
    if (!opt.write_test) return;
    struct sigaction old_sa;
    arm_fs_timeout(&old_sa);

    char rnd[9];
    snprintf(rnd, sizeof(rnd), "%08x", test_random());

    /* 255-byte filename (ENAMETOOLONG on some servers). Keep the length at the
     * 255-byte limit being tested but embed the random prefix so the path is
     * still unpredictable. */
    char longname[4096];
    char part[256];
    memset(part, 'a', 255);
    memcpy(part, rnd, 8);
    part[255] = '\0';
    snprintf(longname, sizeof(longname), "%s/%s", mp, part);
    probe_special_name(longname, "255-byte filename");

    char spacename[4096];
    snprintf(spacename, sizeof(spacename), "%s/nfsdiag test file with spaces %s", mp, rnd);
    probe_special_name(spacename, "filename with spaces");

    /* UTF-8 multibyte filename (ñ, 中文) */
    char utf8name[4096];
    snprintf(utf8name, sizeof(utf8name), "%s/nfsdiag-\xc3\xb1-\xe4\xb8\xad\xe6\x96\x87-%s", mp, rnd);
    probe_special_name(utf8name, "UTF-8 multibyte filename");

    /* Filename with colon and at-sign (Windows interop relevant) */
    char specialname[4096];
    snprintf(specialname, sizeof(specialname), "%s/nfsdiag@host:port-%s", mp, rnd);
    probe_special_name(specialname, "filename with colon and at-sign");

    disarm_fs_timeout(&old_sa);
}

/* ---- NFSv4 delegation detection ---- */

/* Encourage the server to hand out a delegation by opening and reading a file.
 * Run before reading mountstats; DELEGRETURN activity then shows up there. */
static void delegation_probe(const char *mp, int nfs_version) {
    if (nfs_version < 4 || !opt.write_test) return;
    struct sigaction old_sa;
    arm_fs_timeout(&old_sa);
    char path[4096];
    make_test_path(path, sizeof(path), mp, "deleg-probe");
    int fd = open(path, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd >= 0) {
        if (write(fd, "x", 1) == 1) {
            char b;
            lseek(fd, 0, SEEK_SET);
            if (read(fd, &b, 1) < 0) { /* only the NFS ops matter, not the data */ }
        }
        close(fd);
        cleanup_test_path(path);
    }
    disarm_fs_timeout(&old_sa);
}

/* Parse the DELEGRETURN counter for mp from an already-open mountstats stream.
 * Does not open or close the stream so the same read can also feed
 * parse_mountstats_stream(). */
static void delegation_from_stream(FILE *f, const char *mp, int nfs_version) {
    if (nfs_version < 4) return;

    char line[2048];
    int in_section = 0, seen = 0;
    unsigned long deleg_ops = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "device ", 7) == 0) {
            /* Match the section for this mountpoint exactly, the same way
             * parse_mountstats() does. */
            char *mop = strstr(line, " mounted on ");
            int matched = 0;
            if (mop) {
                char *s = mop + 12;
                const char *e = strstr(s, " with fstype");
                if (e) {
                    size_t len = (size_t)(e - s);
                    char dev_mp[4096] = {0};
                    if (len < sizeof(dev_mp)) {
                        memcpy(dev_mp, s, len);
                        matched = (strcmp(dev_mp, mp) == 0);
                    }
                }
            }
            in_section = matched;
            continue;
        }
        if (!in_section) continue;
        const char *t = line;
        while (*t == ' ' || *t == '\t') t++;
        if (strncmp(t, "DELEGRETURN:", 12) == 0) {
            sscanf(t + 12, " %lu", &deleg_ops);
            seen = 1;
            break;
        }
    }

    if (!seen)
        report_info("NFSv4 delegation state not exposed for this mount (no DELEGRETURN counter in mountstats)");
    else if (deleg_ops > 0)
        report_ok("NFSv4 delegations in use on this mount (DELEGRETURN ops=%lu)", deleg_ops);
    else
        report_info("NFSv4 delegations not observed during test (DELEGRETURN ops=0); server may not grant them or none were recalled");
}

void diagnose_mounted_export(const char *export_path, const char *mountpoint,
                             int export_idx, int nfs_version, int nfs_minor) {
    if (opt.verbose) printf("\n[+] Mounted export diagnostics: %s at %s\n", export_path, mountpoint);
    current_export_idx = export_idx;
    if (g_random_degraded && opt.write_test) {
        report_warn("no secure entropy source; disabling write tests for safety on %s",
                    export_path);
        opt.write_test = 0;
    }
    struct export_report *rpt = &export_reports[export_idx];
    test_basic_mount_info(mountpoint);
    test_directory_access(mountpoint);
    test_acl(mountpoint, rpt);
    test_identity_simulation(mountpoint);
    test_write_read_benchmark(mountpoint, rpt);
    test_advisory_lock(mountpoint, rpt);
    test_root_squash(mountpoint, rpt);
    test_special_files(mountpoint);
    test_long_filenames(mountpoint);
    test_xattr_support(mountpoint);
    test_copy_file_range(mountpoint);
    test_fallocate_odirect(mountpoint);
    test_close_to_open(mountpoint);
    /* Encourage a delegation before the metadata/stale phases, then read
     * /proc/self/mountstats once for both delegation state and op stats. */
    delegation_probe(mountpoint, nfs_version);
    test_metadata_latency(mountpoint, rpt);
    test_stale_loop(mountpoint, rpt);
    FILE *ms = fopen("/proc/self/mountstats", "r");
    if (ms) {
        delegation_from_stream(ms, mountpoint, nfs_version);
        rewind(ms);
        parse_mountstats_stream(ms, mountpoint);
        fclose(ms);
    } else {
        report_info("cannot read /proc/self/mountstats: %s", strerror(errno));
    }
    verify_mount_options(mountpoint, rpt);
    check_nfsfs_servers(mountpoint);
    (void)nfs_minor; /* stored in export_report already */
    current_export_idx = -1;
}
