#include "nfsdiag.h"

const char *proto_name(unsigned long proto) {
    if (proto == IPPROTO_TCP) return "tcp";
    if (proto == IPPROTO_UDP) return "udp";
    return "unknown";
}

/* Exposed via nfsdiag.h and called from other translation units. cppcheck's
 * per-file analysis cannot see those callers, so it raises a false-positive
 * staticFunction (static-linkage) suggestion here. */
/* Connect with timeout and return the connected fd (or -1). The fd is needed
 * by callers that inspect socket properties such as the path MTU. */
static int tcp_connect_fd(const char *host, int port, int timeout_sec,
                          int *out_family) {
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *rp;
    char portstr[32];
    int last_errno = 0;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = opt.address_family;
    snprintf(portstr, sizeof(portstr), "%d", port);

    int gai = getaddrinfo(host, portstr, &hints, &res);
    if (gai != 0) {
        errno = EHOSTUNREACH;
        return -1;
    }

    for (rp = res; rp; rp = rp->ai_next) {
        int fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) {
            last_errno = errno;
            continue;
        }

        int flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        int rc = connect(fd, rp->ai_addr, rp->ai_addrlen);
        if (rc == 0) {
            if (out_family) *out_family = rp->ai_family;
            freeaddrinfo(res);
            return fd;
        }

        if (errno == EINPROGRESS) {
            struct pollfd pfd = { .fd = fd, .events = POLLOUT };
            rc = poll(&pfd, 1, timeout_sec * 1000);
            if (rc > 0) {
                int soerr = 0;
                socklen_t slen = sizeof(soerr);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen) == 0 && soerr == 0) {
                    if (out_family) *out_family = rp->ai_family;
                    freeaddrinfo(res);
                    return fd;
                }
                last_errno = soerr ? soerr : errno;
            } else if (rc == 0) {
                last_errno = ETIMEDOUT;
            } else {
                last_errno = errno;
            }
        } else {
            last_errno = errno;
        }

        close(fd);
    }

    freeaddrinfo(res);
    errno = last_errno ? last_errno : ECONNREFUSED;
    return -1;
}

int tcp_connect_timeout(const char *host, int port, int timeout_sec) {
    int fd = tcp_connect_fd(host, port, timeout_sec, NULL);
    if (fd < 0) return -1;
    close(fd);
    return 0;
}

/* ---- TCP connect latency and path MTU ---- */

static void measure_connect_latency(const char *host, int port) {
    enum { SAMPLES = 3 };
    double total = 0, lo = 0, hi = 0;
    int n = 0;
    for (int i = 0; i < SAMPLES; i++) {
        struct timespec a, b;
        clock_gettime(CLOCK_MONOTONIC, &a);
        int fd = tcp_connect_fd(host, port, opt.timeout_sec, NULL);
        clock_gettime(CLOCK_MONOTONIC, &b);
        if (fd < 0) break;
        close(fd);
        double ms = (double)(b.tv_sec - a.tv_sec) * 1000.0 +
                    (double)(b.tv_nsec - a.tv_nsec) / 1000000.0;
        if (n == 0 || ms < lo) lo = ms;
        if (n == 0 || ms > hi) hi = ms;
        total += ms;
        n++;
    }
    if (n > 0)
        report_ok("TCP connect latency to port %d: min=%.2fms avg=%.2fms max=%.2fms (%d samples; includes name resolution)",
                  port, lo, total / n, hi, n);
}

static void report_path_mtu(const char *host, int port) {
    int family = AF_UNSPEC;
    int fd = tcp_connect_fd(host, port, opt.timeout_sec, &family);
    if (fd < 0) return;
    int mtu = 0;
    socklen_t len = sizeof(mtu);
    int rc = -1;
    if (family == AF_INET6)
        rc = getsockopt(fd, IPPROTO_IPV6, IPV6_MTU, &mtu, &len);
    else
        rc = getsockopt(fd, IPPROTO_IP, IP_MTU, &mtu, &len);
    close(fd);
    if (rc == 0 && mtu > 0) {
        report_info("path MTU towards server (via port %d): %d bytes", port, mtu);
        if (mtu < 1500)
            report_warn("path MTU %d is below 1500; fragmentation or tunnel overhead may hurt NFS throughput", mtu);
    }
}

void network_tests(const char *host) {
    if (opt.verbose) printf("\n[+] Network checks\n");

    /* Resolve once up front so DNS problems are reported with the real
     * getaddrinfo error instead of a generic "unreachable" for every port. */
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = opt.address_family;
    int gai = getaddrinfo(host, NULL, &hints, &res);
    if (gai != 0) {
        report_fail("cannot resolve %s: %s", host, gai_strerror(gai));
        add_recommendation("Name resolution failed: check DNS/hosts entries, search domains, "
                           "and the address family forced by --ipv4-only/--ipv6-only.");
        return;
    }
    freeaddrinfo(res);

    if (tcp_connect_timeout(host, RPCBIND_PORT, opt.timeout_sec) == 0)
        report_ok("rpcbind TCP port %d reachable", RPCBIND_PORT);
    else {
        report_fail("rpcbind TCP port %d unreachable: %s", RPCBIND_PORT, strerror(errno));
        add_recommendation("TCP/%d is unreachable: check firewall, rpcbind status, routing, or whether the server is intentionally NFSv4-only.", RPCBIND_PORT);
    }

    if (tcp_connect_timeout(host, NFS_PORT, opt.timeout_sec) == 0) {
        report_ok("NFS TCP port %d reachable", NFS_PORT);
        measure_connect_latency(host, NFS_PORT);
        report_path_mtu(host, NFS_PORT);
    } else {
        report_fail("NFS TCP port %d unreachable: %s", NFS_PORT, strerror(errno));
        add_recommendation("TCP/%d is unreachable: verify nfsd/ganesha is running and allowed through firewalls/security groups.", NFS_PORT);
    }
}

/* ---- dynamic RPC service ports (lockd/statd/mountd) ----
 * A firewall that only allows 111/2049 silently breaks NFSv3 locking and
 * mount; test the actual registered ports from the rpcbind map. */
void check_rpc_dynamic_ports(const char *host, const struct rpc_services *svc) {
    static const unsigned long progs[] = {MOUNT_PROGRAM, NLM_PROGRAM, NSM_PROGRAM};

    for (size_t p = 0; p < sizeof(progs) / sizeof(progs[0]); p++) {
        unsigned long port = 0;
        for (size_t i = 0; i < svc->len; i++) {
            if (svc->items[i].prog == progs[p] &&
                svc->items[i].prot == IPPROTO_TCP &&
                svc->items[i].port > 0 && svc->items[i].port <= 65535) {
                port = svc->items[i].port;
                break;
            }
        }
        if (port == 0 || port == NFS_PORT || port == RPCBIND_PORT) continue;

        if (tcp_connect_timeout(host, (int)port, opt.timeout_sec) == 0) {
            report_ok("%s TCP port %lu reachable", rpc_program_name(progs[p]), port);
        } else {
            report_warn("%s registered on TCP port %lu but the port is unreachable: %s",
                        rpc_program_name(progs[p]), port, strerror(errno));
            add_recommendation("A registered RPC service port is firewalled: NFSv3 mount/locking needs "
                               "mountd, lockd, and statd ports open in addition to 111 and 2049.");
        }
    }
}
