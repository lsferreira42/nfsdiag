#!/bin/sh
# TEST-ONLY entrypoint for nfs-doctor fixture containers.
# This script uses insecure NFS export options (wildcard, insecure, no_root_squash).
# NEVER use this configuration or these exports in a production environment.
set -eu

mkdir -p /run/rpcbind /run/lock /var/lib/nfs /var/lib/nfs/rpc_pipefs /proc/fs/nfsd /export

# Docker overlay filesystems generally cannot be exported by kernel NFS.
# Export a tmpfs by default so fixtures work on ordinary Docker hosts.
if [ "${MOUNT_TMPFS_EXPORT:-1}" != "0" ]; then
    mount -t tmpfs -o "${TMPFS_OPTIONS:-mode=0777}" tmpfs /export 2>/dev/null || true
fi

fixture_target="/export"
if [ -n "${EXPORT_SUBDIR:-}" ]; then
    fixture_target="/export/${EXPORT_SUBDIR}"
fi
mkdir -p "${fixture_target}" 2>/dev/null || true
printf '%s\n' "${EXPORT_MARKER:-nfs-doctor-fixture}" > "${fixture_target}/README.txt" 2>/dev/null || true
chown "${EXPORT_OWNER:-root:root}" "${fixture_target}" 2>/dev/null || true
chmod "${EXPORT_MODE:-0777}" "${fixture_target}" 2>/dev/null || true

if [ -n "${NETEM:-}" ]; then
    tc qdisc add dev eth0 root netem ${NETEM} || echo "[fixture] failed to apply netem: ${NETEM}"
fi

if [ -n "${STALE_LOOP_PATH:-}" ]; then
    (
        while true; do
            if [ -d "${STALE_LOOP_PATH}" ]; then
                mv "${STALE_LOOP_PATH}" "${STALE_LOOP_PATH}.old" 2>/dev/null || true
                mkdir -p "${STALE_LOOP_PATH}" 2>/dev/null || true
                rm -rf "${STALE_LOOP_PATH}.old" 2>/dev/null || true
            fi
            sleep "${STALE_LOOP_INTERVAL:-1}"
        done
    ) &
fi

mount -t nfsd nfsd /proc/fs/nfsd 2>/dev/null || true
rpcbind -w

if [ "${NO_STATD:-0}" != "1" ]; then
    rpc.statd --no-notify || true
fi

rpc.nfsd --no-udp "${NFSD_THREADS:-8}"
exportfs -rav
exec rpc.mountd --foreground --no-udp
