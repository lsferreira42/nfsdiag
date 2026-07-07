#include "nfsdiag.h"

/* Shared HTTP metrics listener. refresh(host) returns a malloc'd Prometheus
 * snapshot (caller frees). Serves /metrics and / until a signal arrives,
 * re-collecting every --watch seconds (default 60). Returns 0 on clean exit,
 * 2 on a bind/listen error. Extracted from the client's exporter so the
 * server namespace can reuse it with a different snapshot source. */
int run_metrics_listener(const char *host, char *(*refresh)(const char *host)) {
    int port = opt.listen_port;
    /* Default to loopback: the exporter has no authentication, so exposing
     * it beyond the local host must be an explicit decision. */
    const char *addr = opt.listen_addr[0] ? opt.listen_addr : "127.0.0.1";
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%d", port);

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_PASSIVE | AI_NUMERICSERV;
    int gai = getaddrinfo(addr, portstr, &hints, &res);
    if (gai != 0) {
        fprintf(stderr, "Error: cannot resolve listen address %s: %s\n",
                addr, gai_strerror(gai));
        return 2;
    }
    int s = -1;
    int bind_errno = 0;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s < 0) { bind_errno = errno; continue; }
        int on = 1;
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
        if (ai->ai_family == AF_INET6) {
            /* "[::]:PORT" keeps the historical dual-stack behaviour */
            int off = 0;
            setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));
        }
        if (bind(s, ai->ai_addr, ai->ai_addrlen) == 0) break;
        bind_errno = errno;
        close(s);
        s = -1;
    }
    freeaddrinfo(res);
    if (s < 0) {
        fprintf(stderr, "Error: cannot bind %s port %d: %s\n",
                addr, port, strerror(bind_errno));
        return 2;
    }
    if (listen(s, 16) != 0) {
        fprintf(stderr, "Error: listen failed on %s port %d: %s\n",
                addr, port, strerror(errno));
        close(s);
        return 2;
    }
    struct sigaction pipe_sa;
    memset(&pipe_sa, 0, sizeof(pipe_sa));
    pipe_sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &pipe_sa, NULL);

    int interval = opt.watch_interval > 0 ? opt.watch_interval : 60;
    printf("[listen] serving Prometheus metrics on %s port %d, refreshing every %ds\n",
           addr, port, interval);

    char *snapshot = NULL;
    while (!received_signal) {
        free(snapshot);
        snapshot = refresh(host);
        size_t snap_len = snapshot ? strlen(snapshot) : 0;

        time_t next = time(NULL) + interval;
        while (!received_signal && time(NULL) < next) {
            struct pollfd pfd = { .fd = s, .events = POLLIN };
            int pr = poll(&pfd, 1, 500);
            if (pr <= 0) continue;
            int c = accept4(s, NULL, NULL, SOCK_CLOEXEC);
            if (c < 0) continue;
            /* Bound how long a slow or silent client can hold the accept loop. */
            struct timeval cto = { .tv_sec = 5, .tv_usec = 0 };
            setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &cto, sizeof(cto));
            setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &cto, sizeof(cto));

            char req[1024];
            ssize_t rn = recv(c, req, sizeof(req) - 1, 0);
            char path[256] = {0};
            int is_get = rn > 0 &&
                http_request_is_get(req, (size_t)rn, path, sizeof(path));
            int metrics = is_get &&
                (strcmp(path, "/metrics") == 0 || strcmp(path, "/") == 0);

            char hdr[256];
            if (metrics) {
                int hl = snprintf(hdr, sizeof(hdr),
                                  "HTTP/1.0 200 OK\r\n"
                                  "Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n"
                                  "Content-Length: %zu\r\n"
                                  "Connection: close\r\n\r\n", snap_len);
                if (hl > 0) {
                    (void)send(c, hdr, (size_t)hl, MSG_NOSIGNAL);
                    if (snapshot) (void)send(c, snapshot, snap_len, MSG_NOSIGNAL);
                }
            } else {
                const char *body = is_get ? "404 not found\n" : "405 method not allowed\n";
                const char *status = is_get ? "404 Not Found" : "405 Method Not Allowed";
                int hl = snprintf(hdr, sizeof(hdr),
                                  "HTTP/1.0 %s\r\n"
                                  "Content-Type: text/plain; charset=utf-8\r\n"
                                  "Content-Length: %zu\r\n"
                                  "Connection: close\r\n\r\n", status, strlen(body));
                if (hl > 0) {
                    (void)send(c, hdr, (size_t)hl, MSG_NOSIGNAL);
                    (void)send(c, body, strlen(body), MSG_NOSIGNAL);
                }
            }
            close(c);
        }
    }
    free(snapshot);
    close(s);
    return 0;
}
