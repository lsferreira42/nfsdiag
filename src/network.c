#include "nfsdiag.h"

const char *proto_name(unsigned long proto) {
    if (proto == IPPROTO_TCP) return "tcp";
    if (proto == IPPROTO_UDP) return "udp";
    return "unknown";
}

int tcp_connect_timeout(const char *host, int port, int timeout_sec) {
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
            close(fd);
            freeaddrinfo(res);
            return 0;
        }

        if (errno == EINPROGRESS) {
            struct pollfd pfd = { .fd = fd, .events = POLLOUT };
            rc = poll(&pfd, 1, timeout_sec * 1000);
            if (rc > 0) {
                int soerr = 0;
                socklen_t slen = sizeof(soerr);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen) == 0 && soerr == 0) {
                    close(fd);
                    freeaddrinfo(res);
                    return 0;
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

void network_tests(const char *host) {
    if (opt.verbose) printf("\n[+] Network checks\n");

    if (tcp_connect_timeout(host, 111, opt.timeout_sec) == 0)
        report_ok("rpcbind TCP port 111 reachable");
    else {
        report_fail("rpcbind TCP port 111 unreachable: %s", strerror(errno));
        add_recommendation("TCP/111 is unreachable: check firewall, rpcbind status, routing, or whether the server is intentionally NFSv4-only.");
    }

    if (tcp_connect_timeout(host, 2049, opt.timeout_sec) == 0)
        report_ok("NFS TCP port 2049 reachable");
    else {
        report_fail("NFS TCP port 2049 unreachable: %s", strerror(errno));
        add_recommendation("TCP/2049 is unreachable: verify nfsd/ganesha is running and allowed through firewalls/security groups.");
    }
}
