#!/bin/sh
set -eu
mkdir -p /run/rpcbind
rpcbind -w
exec sleep infinity
