# syntax=docker/dockerfile:1
# Multi-stage build: compile on Alpine, copy minimal runtime image.
# Usage:
#   docker build -f packaging/Dockerfile -t nfsdiag .
#   docker run --rm --privileged nfsdiag <server>
#
# Published image: ghcr.io/lsferreira42/nfsdiag

FROM alpine:3.24 AS builder

RUN apk add --no-cache gcc musl-dev make pkgconf libtirpc-dev

WORKDIR /src
COPY . .
RUN make "CFLAGS=-O2 -Wall -Wextra -Werror" rebuild

FROM alpine:3.24

LABEL org.opencontainers.image.title="nfsdiag" \
      org.opencontainers.image.description="Client-side NFS diagnostic tool" \
      org.opencontainers.image.url="https://www.nfsdiag.org" \
      org.opencontainers.image.source="https://github.com/lsferreira42/nfsdiag" \
      org.opencontainers.image.licenses="MIT"

RUN apk add --no-cache libtirpc nfs-utils

COPY --from=builder /src/nfsdiag /usr/local/bin/nfsdiag
COPY --from=builder /src/LICENSE /usr/share/licenses/nfsdiag/LICENSE
COPY --from=builder /src/docs/nfsdiag.8 /usr/share/man/man8/nfsdiag.8

ENTRYPOINT ["/usr/local/bin/nfsdiag"]
