#include "nfsdiag.h"

/* Minimal HTTP GET of /metrics from a peer `nfsdiag server --listen` exporter.
 * Strips the response headers, leaving the Prometheus body in buf. 0/-1. */
int peer_fetch_metrics(const char *host, int port, char *buf, size_t sz) {
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%d", port);
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, portstr, &hints, &res) != 0)
        return -1;
    int fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        struct timeval to = { .tv_sec = 5, .tv_usec = 0 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &to, sizeof(to));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &to, sizeof(to));
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0)
            break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0)
        return -1;
    char req[256];
    int rl = snprintf(req, sizeof(req),
                      "GET /metrics HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n", host);
    if (rl <= 0 || send(fd, req, (size_t)rl, MSG_NOSIGNAL) < 0) {
        close(fd);
        return -1;
    }
    size_t total = 0;
    ssize_t n;
    while (total < sz - 1 && (n = recv(fd, buf + total, sz - 1 - total, 0)) > 0)
        total += (size_t)n;
    close(fd);
    buf[total] = '\0';
    char *body = strstr(buf, "\r\n\r\n");
    if (body)
        memmove(buf, body + 4, strlen(body + 4) + 1);
    return total > 0 ? 0 : -1;
}

void peer_parse_server(const char *buf, struct peer_server *out) {
    memset(out, 0, sizeof(*out));
    double v;
    if (parse_prometheus_gauge(buf, "nfsdiag_server_rpc_calls", &v) == 0)          { out->rpc_calls = v; out->valid = 1; }
    if (parse_prometheus_gauge(buf, "nfsdiag_server_rpc_badcalls", &v) == 0)         out->rpc_badcalls = v;
    if (parse_prometheus_gauge(buf, "nfsdiag_server_drc_hits", &v) == 0)             out->drc_hits = v;
    if (parse_prometheus_gauge(buf, "nfsdiag_server_drc_misses", &v) == 0)           out->drc_misses = v;
    if (parse_prometheus_gauge(buf, "nfsdiag_server_drc_nocache", &v) == 0)          out->drc_nocache = v;
    if (parse_prometheus_gauge(buf, "nfsdiag_server_tcp_established_2049", &v) == 0)  out->tcp_established = v;
    if (parse_prometheus_gauge(buf, "nfsdiag_server_nfsd_threads", &v) == 0)         out->nfsd_threads = v;
    if (parse_prometheus_gauge(buf, "nfsdiag_server_snapshot_unixtime", &v) == 0)     out->snapshot_unixtime = v;
}
