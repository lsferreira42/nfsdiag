# syntax=docker/dockerfile:1
# Multi-stage build: compile on Alpine, copy minimal runtime image.
# Usage:
#   docker build -f packaging/Dockerfile -t nfsdiag .
#   docker run --rm --privileged nfsdiag <server>
#
# Published image: ghcr.io/lsferreira42/nfsdiag

FROM alpine:3.21 AS builder

RUN apk add --no-cache gcc musl-dev make pkgconf libtirpc-dev

WORKDIR /src
COPY . .
RUN make "CFLAGS=-O2 -Wall -Wextra -Werror" rebuild

FROM alpine:3.21

RUN apk add --no-cache libtirpc nfs-utils

COPY --from=builder /src/nfsdiag /usr/local/bin/nfsdiag

ENTRYPOINT ["/usr/local/bin/nfsdiag"]
