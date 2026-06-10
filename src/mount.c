#include "nfsdiag.h"

/* ---- globals owned by mount.c ---- */

const char *nfs_version_cascade[] = {"4.2", "4.1", "4", "3", NULL};

char   active_mountpoints[MAX_MOUNTPOINTS][4096];
size_t active_mountpoint_count = 0;

/* ---- FD leak prevention ---- */

void close_inherited_fds(int keep1, int keep2) {
    DIR *d = opendir("/proc/self/fd");
    if (d) {
        int dfd = dirfd(d);
        const struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (ent->d_name[0] == '.') continue;
            int fd = atoi(ent->d_name);
            if (fd > STDERR_FILENO && fd != dfd && fd != keep1 && fd != keep2)
                close(fd);
        }
        closedir(d);
    } else {
        /* Use the actual table size, not an arbitrary cap of 4096.
         * getdtablesize() returns RLIMIT_NOFILE which can be much higher. */
        long max_fd = getdtablesize();
        if (max_fd < 0) max_fd = sysconf(_SC_OPEN_MAX);
        if (max_fd < 0) max_fd = 1024;
        for (int fd = STDERR_FILENO + 1; fd < (int)max_fd; fd++) {
            if (fd != keep1 && fd != keep2) close(fd);
        }
    }
}

/* ---- command execution with poll() ---- */

int resolve_command_path(const char *cmd, char *out, size_t out_sz) {
    if (!cmd || !cmd[0] || !out || out_sz == 0) return -1;
    if (strchr(cmd, '/')) {
        if (access(cmd, X_OK) == 0) {
            snprintf(out, out_sz, "%s", cmd);
            return 0;
        }
        return -1;
    }

    static const char *trusted_dirs[] = {
        "/usr/sbin", "/usr/bin", "/sbin", "/bin", "/usr/local/sbin", "/usr/local/bin"
    };
    for (size_t i = 0; i < sizeof(trusted_dirs) / sizeof(trusted_dirs[0]); i++) {
        char full[4096];
        if (snprintf(full, sizeof(full), "%s/%s", trusted_dirs[i], cmd) >= (int)sizeof(full))
            continue;
        if (access(full, X_OK) == 0) {
            snprintf(out, out_sz, "%s", full);
            return 0;
        }
    }
    return -1;
}

/* Replace control characters (except newline/tab) in captured output so
 * command- or server-controlled bytes cannot inject terminal escape
 * sequences when the text is later printed or logged. */
static void sanitize_cmd_output(char *s) {
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c < 0x20 && c != '\n' && c != '\t')
            *s = '?';
    }
}

int run_command_capture(char *const argv[], char *output, size_t output_sz) {
    int pipefd[2];
    if (output_sz == 0) return -1;
    if (pipe(pipefd) != 0) return -1;

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        char resolved[4096];
        static char *const safe_env[] = {
            "PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin",
            "LANG=C",
            "LC_ALL=C",
            NULL
        };
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        setpgid(0, 0);
        close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0) _exit(127);
        if (dup2(pipefd[1], STDERR_FILENO) < 0) _exit(127);
        close(pipefd[1]);
        close_inherited_fds(-1, -1);
        if (resolve_command_path(argv[0], resolved, sizeof(resolved)) != 0)
            _exit(127);
        execve(resolved, argv, safe_env);
        _exit(127);
    }

    setpgid(pid, pid);
    close(pipefd[1]);
    int flags = fcntl(pipefd[0], F_GETFL, 0);
    if (flags >= 0) fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);

    size_t used = 0;
    int status = 0;
    time_t deadline = time(NULL) + opt.command_timeout_sec;

    for (;;) {
        ssize_t n;
        do {
            if (used < output_sz - 1) {
                n = read(pipefd[0], output + used, output_sz - used - 1);
                if (n > 0) used += (size_t)n;
            } else {
                char discard[4096];
                n = read(pipefd[0], discard, sizeof(discard));
            }
        } while (n > 0);
        if (n < 0 && errno != EAGAIN && errno != EINTR) break;

        pid_t wr = waitpid(pid, &status, WNOHANG);
        if (wr == pid) break;
        if (wr < 0 && errno != EINTR) break;

        if (time(NULL) >= deadline) {
            kill(-pid, SIGTERM);
            struct timespec grace = { .tv_sec = 0, .tv_nsec = 200000000L };
            nanosleep(&grace, NULL);
            kill(-pid, SIGKILL);
            while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
            if (output_sz) {
                snprintf(output + (used < output_sz ? used : output_sz - 1),
                         used < output_sz ? output_sz - used : 1,
                         "%scommand timed out after %d seconds",
                         used ? "\n" : "", opt.command_timeout_sec);
                sanitize_cmd_output(output);
            }
            close(pipefd[0]);
            return 124;
        }

        struct pollfd pfd = {.fd = pipefd[0], .events = POLLIN};
        (void)poll(&pfd, 1, 100);
    }

    /* drain remaining output after child exits */
    ssize_t n;
    do {
        if (used < output_sz - 1) {
            n = read(pipefd[0], output + used, output_sz - used - 1);
            if (n > 0) used += (size_t)n;
        } else {
            char discard[4096];
            n = read(pipefd[0], discard, sizeof(discard));
        }
    } while (n > 0);
    if (output_sz) {
        output[used < output_sz ? used : output_sz - 1] = '\0';
        sanitize_cmd_output(output);
    }
    close(pipefd[0]);

    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return -1;
}

/* ---- mountpoint tracking ---- */

/* Exposed via nfsdiag.h and called from other translation units. cppcheck's
 * per-file analysis cannot see those callers, so it raises a false-positive
 * staticFunction (static-linkage) suggestion here. */
void register_mountpoint(const char *mountpoint) {
    if (active_mountpoint_count >= MAX_MOUNTPOINTS) return;
    snprintf(active_mountpoints[active_mountpoint_count],
             sizeof(active_mountpoints[active_mountpoint_count]),
             "%s", mountpoint);
    active_mountpoint_count++;
}

/* Exposed via nfsdiag.h and called from other translation units. cppcheck's
 * per-file analysis cannot see those callers, so it raises a false-positive
 * staticFunction (static-linkage) suggestion here. */
void unregister_mountpoint(const char *mountpoint) {
    for (size_t i = 0; i < active_mountpoint_count; i++) {
        if (strcmp(active_mountpoints[i], mountpoint) == 0) {
            for (size_t j = i + 1; j < active_mountpoint_count; j++) {
                snprintf(active_mountpoints[j - 1],
                         sizeof(active_mountpoints[j - 1]),
                         "%s", active_mountpoints[j]);
            }
            active_mountpoint_count--;
            return;
        }
    }
}

int make_dir(const char *path, mode_t mode) {
    if (mkdir(path, mode) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

static void compose_source(char *dst, size_t dst_sz, const char *host,
                            const char *export_path) {
    /* IPv6 literals need brackets: [addr]:export */
    if (strchr(host, ':') && host[0] != '[')
        snprintf(dst, dst_sz, "[%s]:%s", host, export_path);
    else
        snprintf(dst, dst_sz, "%s:%s", host, export_path);
}

static void compose_options(char *dst, size_t dst_sz, const char *version) {
    /* Default hardening: the server is untrusted, so block setuid binaries,
     * device nodes and direct execution from the mount. Skipped only when the
     * user explicitly accepts risk via --allow-risky-mount-options. */
    const char *hardening = opt.allow_risky_mount_options ? "" : ",nosuid,nodev,noexec";
    if (opt.mount_options && opt.mount_options[0])
        snprintf(dst, dst_sz, "vers=%s%s,%s", version, hardening, opt.mount_options);
    else
        snprintf(dst, dst_sz, "vers=%s%s", version, hardening);
}

/* ---- mount with NFSv4.2/4.1/4/3 cascade ---- */

int mount_export(const char *host, const char *export_path,
                 const char *mountpoint, struct mount_result *mr)
{
    char source[4096];
    char options[2048];
    char output[CMD_OUTPUT_LIMIT];

    memset(mr, 0, sizeof(*mr));
    snprintf(mr->mountpoint, sizeof(mr->mountpoint), "%s", mountpoint);
    compose_source(source, sizeof(source), host, export_path);

    for (int i = 0; nfs_version_cascade[i]; i++) {
        const char *ver = nfs_version_cascade[i];
        compose_options(options, sizeof(options), ver);
        char *argv[] = {"mount", "-t", "nfs", "-o", options,
                        source, (char *)mountpoint, NULL};
        memset(output, 0, sizeof(output));

        if (opt.verbose)
            report_info("running: mount -t nfs -o %s %s %s", options, source,
                        mountpoint);
        if (opt.dry_run) {
            report_ok("dry-run: would mount %s at %s with NFS v%s", source, mountpoint, ver);
            mr->mounted = 1;
            if (ver[0] == '4') {
                mr->version = 4;
                mr->nfs_minor_version = (ver[1] == '.' && ver[2] != '\0') ? atoi(&ver[2]) : 0;
            } else {
                mr->version = atoi(ver);
                mr->nfs_minor_version = 0;
            }
            return 0;
        }
        int rc = run_command_capture(argv, output, sizeof(output));
        if (rc == 0) {
            mr->mounted = 1;
            if (ver[0] == '4') {
                mr->version = 4;
                mr->nfs_minor_version = (ver[1] == '.' && ver[2] != '\0') ? atoi(&ver[2]) : 0;
            } else {
                mr->version = atoi(ver);
                mr->nfs_minor_version = 0;
            }
            register_mountpoint(mountpoint);
            report_ok("mounted %s at %s with NFS v%s", source, mountpoint, ver);
            return 0;
        }

        if (ver[0] == '4')
            report_warn("NFS v%s mount attempt failed for %s: %s",
                        ver, export_path, output[0] ? output : "no output");
        else
            report_fail("NFS v%s mount attempt failed for %s: %s",
                        ver, export_path, output[0] ? output : "no output");
    }

    return -1;
}

int unmount_export(const char *mountpoint) {
    if (opt.dry_run) {
        report_ok("dry-run: would unmount %s", mountpoint);
        return 0;
    }
    char output[CMD_OUTPUT_LIMIT];
    char *argv[] = {"umount", (char *)mountpoint, NULL};
    int rc = run_command_capture(argv, output, sizeof(output));
    if (rc == 0) {
        unregister_mountpoint(mountpoint);
        report_ok("unmounted %s", mountpoint);
        return 0;
    }

    report_warn("normal umount failed for %s: %s", mountpoint,
                output[0] ? output : "no output");
    char *lazy_argv[] = {"umount", "-l", (char *)mountpoint, NULL};
    rc = run_command_capture(lazy_argv, output, sizeof(output));
    if (rc == 0) {
        unregister_mountpoint(mountpoint);
        report_warn("lazy unmount succeeded for %s", mountpoint);
        return 0;
    }

    report_fail("lazy umount also failed for %s: %s", mountpoint,
                output[0] ? output : "no output");
    return -1;
}

/* ---- mount option sweep (rsize/wsize/nconnect benchmark) ---- */

static volatile sig_atomic_t sweep_timeout_fired = 0;
static void sweep_timeout_handler(int sig) { (void)sig; sweep_timeout_fired = 1; }

static double sweep_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1000000.0;
}

/* Time a write+fsync and a cache-dropped read of bench_bytes inside mp.
 * Returns 0 on success with rates in MiB/s, -1 on failure/timeout. */
static int sweep_benchmark(const char *mp, double *write_mib_s, double *read_mib_s) {
    char path[4352];
    snprintf(path, sizeof(path), "%s/.nfsdiag-sweep-%ld", mp, (long)getpid());

    struct sigaction sa, old;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sweep_timeout_handler;
    sweep_timeout_fired = 0;
    sigaction(SIGALRM, &sa, &old);
    alarm((unsigned)(opt.fs_timeout_sec > 0 ? opt.fs_timeout_sec : 30));

    int rc = -1;
    int fd = open(path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd >= 0) {
        char buf[65536];
        memset(buf, 'S', sizeof(buf));
        size_t left = opt.bench_bytes;
        double w0 = sweep_now_ms();
        while (left && !sweep_timeout_fired) {
            size_t chunk = left < sizeof(buf) ? left : sizeof(buf);
            ssize_t w = write(fd, buf, chunk);
            if (w <= 0) break;
            left -= (size_t)w;
        }
        if (left == 0 && fsync(fd) == 0 && !sweep_timeout_fired) {
            double w1 = sweep_now_ms();
            (void)posix_fadvise(fd, 0, (off_t)opt.bench_bytes, POSIX_FADV_DONTNEED);
            lseek(fd, 0, SEEK_SET);
            left = opt.bench_bytes;
            double r0 = sweep_now_ms();
            while (left && !sweep_timeout_fired) {
                size_t chunk = left < sizeof(buf) ? left : sizeof(buf);
                ssize_t r = read(fd, buf, chunk);
                if (r <= 0) break;
                left -= (size_t)r;
            }
            double r1 = sweep_now_ms();
            if (left == 0 && !sweep_timeout_fired) {
                double mib = (double)opt.bench_bytes / (1024.0 * 1024.0);
                if (w1 > w0) *write_mib_s = mib / ((w1 - w0) / 1000.0);
                if (r1 > r0) *read_mib_s = mib / ((r1 - r0) / 1000.0);
                rc = 0;
            }
        }
        close(fd);
        unlink(path);
    }

    alarm(0);
    sigaction(SIGALRM, &old, NULL);
    sweep_timeout_fired = 0;
    return rc;
}

void sweep_mount_options(const char *host, const char *export_path,
                         const char *workspace, const char *vers) {
    static const char *combos[] = {
        "rsize=65536,wsize=65536",
        "rsize=262144,wsize=262144",
        "rsize=1048576,wsize=1048576",
        "rsize=1048576,wsize=1048576,nconnect=4",
        "rsize=1048576,wsize=1048576,nconnect=8",
    };
    const size_t ncombos = sizeof(combos) / sizeof(combos[0]);

    if (opt.verbose) printf("\n[+] Mount option sweep for %s\n", export_path);
    report_info("mount option sweep started on %s (%zu combinations, %zu bytes each)",
                export_path, ncombos, opt.bench_bytes);

    char source[4096];
    compose_source(source, sizeof(source), host, export_path);

    int best = -1;
    double best_score = -1.0, best_w = 0.0, best_r = 0.0;

    for (size_t i = 0; i < ncombos; i++) {
        if (received_signal) break;
        char mp[4096];
        int n = snprintf(mp, sizeof(mp), "%s/sweep-%zu", workspace, i);
        if (n < 0 || (size_t)n >= sizeof(mp)) continue;
        if (make_dir(mp, 0700) != 0) continue;

        char options[2048];
        snprintf(options, sizeof(options), "vers=%s,nosuid,nodev,noexec,%s",
                 vers, combos[i]);
        char output[CMD_OUTPUT_LIMIT];
        char *argv[] = {"mount", "-t", "nfs", "-o", options, source, mp, NULL};
        if (run_command_capture(argv, output, sizeof(output)) != 0) {
            report_info("sweep: mount with %s failed (server or kernel may not support it)", combos[i]);
            continue;
        }
        register_mountpoint(mp);

        double w = 0.0, r = 0.0;
        if (sweep_benchmark(mp, &w, &r) == 0) {
            report_ok("sweep %s: write %.1f MiB/s, read %.1f MiB/s", combos[i], w, r);
            if (w + r > best_score) {
                best_score = w + r;
                best = (int)i;
                best_w = w;
                best_r = r;
            }
        } else {
            report_warn("sweep: benchmark with %s did not complete", combos[i]);
        }

        if (unmount_export(mp) != 0)
            opt.keep_temp = 1;
    }

    if (best >= 0) {
        report_ok("sweep best result: %s (write %.1f MiB/s, read %.1f MiB/s)",
                  combos[best], best_w, best_r);
        add_recommendation("Mount option sweep suggests: -o vers=%s,%s "
                           "(measured write %.1f MiB/s, read %.1f MiB/s from this client).",
                           vers, combos[best], best_w, best_r);
    } else {
        report_warn("mount option sweep could not complete any combination");
    }
}

/* ---- Kerberos security flavor mount tests ---- */

void test_krb5_mount_flavors(const char *host, const char *export_path,
                             const char *workspace) {
    static const char *flavors[] = {"krb5", "krb5i", "krb5p"};

    if (opt.mount_options && strstr(opt.mount_options, "sec=")) {
        report_info("Kerberos flavor probing skipped: explicit sec= already present in --mount-options");
        return;
    }
    if (opt.verbose) printf("\n[+] Kerberos security flavors for %s\n", export_path);

    char source[4096];
    compose_source(source, sizeof(source), host, export_path);

    int any = 0;
    for (size_t i = 0; i < sizeof(flavors) / sizeof(flavors[0]); i++) {
        if (received_signal) break;
        char mp[4096];
        int n = snprintf(mp, sizeof(mp), "%s/krb5-%s", workspace, flavors[i]);
        if (n < 0 || (size_t)n >= sizeof(mp)) continue;
        if (make_dir(mp, 0700) != 0) continue;

        char options[256];
        snprintf(options, sizeof(options), "vers=4,nosuid,nodev,noexec,sec=%s",
                 flavors[i]);
        char output[CMD_OUTPUT_LIMIT];
        char *argv[] = {"mount", "-t", "nfs", "-o", options, source, mp, NULL};
        if (run_command_capture(argv, output, sizeof(output)) == 0) {
            register_mountpoint(mp);
            report_ok("Kerberos mount with sec=%s succeeded", flavors[i]);
            any = 1;
            if (unmount_export(mp) != 0)
                opt.keep_temp = 1;
        } else {
            report_info("Kerberos mount with sec=%s failed: %s", flavors[i],
                        output[0] ? output : "no output");
        }
    }

    if (!any) {
        report_warn("no Kerberos security flavor (krb5/krb5i/krb5p) could be mounted");
        add_recommendation("Kerberos mounts failed for every flavor: verify the export's sec= list, "
                           "the server keytab (nfs/<fqdn>), rpc.gssd on the client, and clock sync.");
    }
}

int setup_mount_namespace(void) {
    if (!opt.mount_namespace) return 0;
    if (unshare(CLONE_NEWNS) != 0) {
        report_warn("could not create private mount namespace: %s",
                    strerror(errno));
        add_recommendation("Private mount namespace failed; "
                           "run as root/CAP_SYS_ADMIN or disable --mount-namespace.");
        return -1;
    }
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
        report_warn("could not make mount namespace private: %s",
                    strerror(errno));
        return -1;
    }
    report_ok("using private mount namespace for live mount diagnostics");
    return 0;
}
