#!/bin/sh
# Signal handling and post-run cleanup, without root or a real NFS server.
# Covers the unprivileged paths: a --watch loop must stop promptly on SIGINT
# and SIGTERM, and no run may leave an nfsdiag temporary workspace behind.
set -eu

BIN=${NFSDIAG_BIN:-./nfsdiag}
[ -x "$BIN" ] || { echo "[SKIP] $BIN not found" >&2; exit 0; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

fail=0
note() { echo "[FAIL] $1" >&2; fail=1; }

count_workspaces() { find "$TMP" -maxdepth 1 -name 'nfsdiag-*' -type d 2>/dev/null | wc -l; }

# A --watch loop keeps running until signalled; it must exit within a couple of
# seconds of the signal, not hang.
test_signal() {
    sig=$1
    TMPDIR="$TMP" "$BIN" client --no-mount --watch 1 --quiet --json=/dev/null 127.0.0.1 \
        >/dev/null 2>&1 &
    pid=$!
    sleep 2
    kill -"$sig" "$pid" 2>/dev/null || true
    # Give the handler a moment, then confirm the process is gone.
    waited=0
    while kill -0 "$pid" 2>/dev/null; do
        sleep 1
        waited=$((waited + 1))
        if [ "$waited" -ge 5 ]; then
            note "watch loop did not exit within 5s of SIG$sig"
            kill -9 "$pid" 2>/dev/null || true
            break
        fi
    done
    wait "$pid" 2>/dev/null || true
}

test_signal INT
test_signal TERM

# A plain --no-mount run must not leave a temporary workspace behind.
TMPDIR="$TMP" "$BIN" client --no-mount --quiet --json=/dev/null 127.0.0.1 >/dev/null 2>&1 || true
left=$(count_workspaces)
[ "$left" -eq 0 ] || note "$left nfsdiag temp workspace(s) left in TMPDIR after a clean run"

if [ "$fail" -eq 0 ]; then
    echo "[OK] signal handling and cleanup behave on the unprivileged paths"
fi
exit "$fail"
