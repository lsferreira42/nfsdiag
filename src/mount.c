#include "nfsdiag.h"

/* ---- globals owned by mount.c ---- */

const char *nfs_version_cascade[] = {"4.2", "4.1", "4", "3", NULL};

char   active_mountpoints[MAX_MOUNTPOINTS][4096];
size_t active_mountpoint_count = 0;

/* ---- FD leak prevention (item 4) ---- */

void close_inherited_fds(int keep1, int keep2) {
    DIR *d = opendir("/proc/self/fd");
    if (d) {
        int dfd = dirfd(d);
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (ent->d_name[0] == '.') continue;
            int fd = atoi(ent->d_name);
            if (fd > STDERR_FILENO && fd != dfd && fd != keep1 && fd != keep2)
                close(fd);
        }
        closedir(d);
    } else {
        long max_fd = sysconf(_SC_OPEN_MAX);
        if (max_fd < 0 || max_fd > 4096) max_fd = 4096;
        for (int fd = STDERR_FILENO + 1; fd < (int)max_fd; fd++) {
            if (fd != keep1 && fd != keep2) close(fd);
        }
    }
}

/* ---- command execution with poll() (item 5) ---- */

int run_command_capture(char *const argv[], char *output, size_t output_sz) {
    int pipefd[2];
    if (pipe(pipefd) != 0) return -1;

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        setpgid(0, 0);
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        close_inherited_fds(-1, -1);
        execvp(argv[0], argv);
        fprintf(stderr, "execvp(%s) failed: %s\n", argv[0], strerror(errno));
        _exit(127);
    }

    setpgid(pid, pid);
    close(pipefd[1]);
    int flags = fcntl(pipefd[0], F_GETFL, 0);
    if (flags >= 0) fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);

    size_t used = 0;
    int status = 0;
    int child_done = 0;
    time_t deadline = time(NULL) + opt.command_timeout_sec;

    while (!child_done) {
        ssize_t n;
        while ((n = read(pipefd[0], output + used,
                         output_sz > used + 1 ? output_sz - used - 1 : 0)) > 0) {
            used += (size_t)n;
            if (used >= output_sz - 1) break;
        }
        if (n < 0 && errno != EAGAIN && errno != EINTR) break;

        pid_t wr = waitpid(pid, &status, WNOHANG);
        if (wr == pid) { child_done = 1; break; }
        if (wr < 0 && errno != EINTR) break;

        if (time(NULL) >= deadline) {
            kill(-pid, SIGTERM);
            usleep(200000);
            kill(-pid, SIGKILL);
            while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
            if (output_sz) {
                snprintf(output + (used < output_sz ? used : output_sz - 1),
                         used < output_sz ? output_sz - used : 1,
                         "%scommand timed out after %d seconds",
                         used ? "\n" : "", opt.command_timeout_sec);
            }
            close(pipefd[0]);
            return 124;
        }

        struct pollfd pfd = {.fd = pipefd[0], .events = POLLIN};
        (void)poll(&pfd, 1, 100);
    }

    /* drain remaining output after child exits */
    ssize_t n;
    while ((n = read(pipefd[0], output + used,
                     output_sz > used + 1 ? output_sz - used - 1 : 0)) > 0) {
        used += (size_t)n;
        if (used >= output_sz - 1) break;
    }
    if (output_sz) output[used < output_sz ? used : output_sz - 1] = '\0';
    close(pipefd[0]);

    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return -1;
}

/* ---- mountpoint tracking ---- */

void register_mountpoint(const char *mountpoint) {
    if (active_mountpoint_count >= MAX_MOUNTPOINTS) return;
    snprintf(active_mountpoints[active_mountpoint_count],
             sizeof(active_mountpoints[active_mountpoint_count]),
             "%s", mountpoint);
    active_mountpoint_count++;
}

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
    snprintf(dst, dst_sz, "%s:%s", host, export_path);
}

static void compose_options(char *dst, size_t dst_sz, const char *version) {
    if (opt.mount_options && opt.mount_options[0])
        snprintf(dst, dst_sz, "vers=%s,%s", version, opt.mount_options);
    else
        snprintf(dst, dst_sz, "vers=%s", version);
}

/* ---- mount with NFSv4.2/4.1/4/3 cascade (item 11) ---- */

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
            if (ver[0] == '4') mr->version = 4; else mr->version = atoi(ver);
            return 0;
        }
        int rc = run_command_capture(argv, output, sizeof(output));
        if (rc == 0) {
            mr->mounted = 1;
            /* parse major version for report */
            if (ver[0] == '4') mr->version = 4;
            else mr->version = atoi(ver);
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
