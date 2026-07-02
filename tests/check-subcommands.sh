#!/bin/sh
# Verify subcommand dispatch: client/server/diff/help/version and the
# deprecated legacy alias. Run from repo root with a built ./nfsdiag:
# sh tests/check-subcommands.sh
set -eu

BIN=${NFSDIAG_BIN:-./nfsdiag}
fail=0

expect_rc() { # expect_rc <name> <expected-rc> <actual-rc>
    if [ "$3" -ne "$2" ]; then
        echo "[FAIL] $1: expected rc=$2 got rc=$3"; fail=1
    fi
}

# 1. top-level help lists the subcommands, rc 0
out=$("$BIN" --help); rc=$?
expect_rc "top-level --help rc" 0 "$rc"
echo "$out" | grep -q "client"  || { echo "[FAIL] --help missing 'client'"; fail=1; }
echo "$out" | grep -q "server"  || { echo "[FAIL] --help missing 'server'"; fail=1; }
echo "$out" | grep -q "diff"    || { echo "[FAIL] --help missing 'diff'"; fail=1; }

# 2. 'help' word form behaves like --help
"$BIN" help >/dev/null; expect_rc "help word rc" 0 $?

# 3. client --help shows the client options, rc 0
out=$("$BIN" client --help); rc=$?
expect_rc "client --help rc" 0 "$rc"
echo "$out" | grep -q -- "--mount-options" || { echo "[FAIL] client --help missing --mount-options"; fail=1; }
echo "$out" | grep -q "nfsdiag client" || { echo "[FAIL] client usage must say 'nfsdiag client'"; fail=1; }

# 4. version: both spellings, rc 0, same output
v1=$("$BIN" --version); v2=$("$BIN" version)
[ "$v1" = "$v2" ] || { echo "[FAIL] --version and version differ"; fail=1; }

# 5. unknown subcommand that cannot be a host-less legacy call -> rc 2
"$BIN" frobnicate 2>/dev/null && rc=0 || rc=$?
expect_rc "unknown subcommand rc" 2 "$rc"

# 6. legacy alias still works and warns on stderr
err=$("$BIN" --dry-run --no-mount 127.0.0.1 2>&1 >/dev/null) || true
echo "$err" | grep -qi "deprecated" || { echo "[FAIL] legacy alias must warn 'deprecated' on stderr"; fail=1; }

# 7. legacy alias warning suppressed by --quiet
err=$("$BIN" --dry-run --no-mount --quiet 127.0.0.1 2>&1 >/dev/null) || true
echo "$err" | grep -qi "deprecated" && { echo "[FAIL] --quiet must suppress deprecation warning"; fail=1; }

# 8. no arguments at all -> usage on stderr, rc 2 (same as today)
"$BIN" 2>/dev/null && rc=0 || rc=$?
expect_rc "no-args rc" 2 "$rc"

# 9. diff subcommand still dispatches (bad files -> nonzero, but not usage error text)
"$BIN" diff /nonexistent-a.json /nonexistent-b.json 2>/dev/null && rc=0 || rc=$?
[ "$rc" -ne 0 ] || { echo "[FAIL] diff with missing files must fail"; fail=1; }

# 10. server --help exists, mentions the audit flag, says 'nfsdiag server', rc 0
out=$("$BIN" server --help); rc=$?
expect_rc "server --help rc" 0 "$rc"
echo "$out" | grep -q -- "--exports-audit" || { echo "[FAIL] server --help missing --exports-audit"; fail=1; }
echo "$out" | grep -q "nfsdiag server" || { echo "[FAIL] server usage must say 'nfsdiag server'"; fail=1; }

# 11. server with no action -> usage on stderr, rc 2
"$BIN" server 2>/dev/null && rc=0 || rc=$?
expect_rc "server no-action rc" 2 "$rc"

# 12. server rejects client-only flags
"$BIN" server --mount-options rw 2>/dev/null && rc=0 || rc=$?
expect_rc "server rejects client flag rc" 2 "$rc"

# 13. exports-audit: clean file -> rc 0
tmp=$(mktemp)
cat > "$tmp" <<'EOF'
# fileserver exports
/srv/data 10.0.0.0/24(rw,sync,root_squash)
/srv/pub  10.0.0.0/24(ro)
EOF
"$BIN" server --exports-audit --exports-file "$tmp" >/dev/null 2>&1 && rc=0 || rc=$?
expect_rc "audit clean file rc" 0 "$rc"

# 14. exports-audit: risky options -> rc 1 and finding mentions no_root_squash
cat > "$tmp" <<'EOF'
/srv/data *(rw,no_root_squash)
EOF
out=$("$BIN" server --exports-audit --exports-file "$tmp" 2>&1) && rc=0 || rc=$?
expect_rc "audit risky file rc" 1 "$rc"
echo "$out" | grep -q "no_root_squash" || { echo "[FAIL] audit must name no_root_squash"; fail=1; }

# 15. exports-audit: syntax error -> rc 1 with line number
cat > "$tmp" <<'EOF'
relative/path host(rw)
EOF
out=$("$BIN" server --exports-audit --exports-file "$tmp" 2>&1) && rc=0 || rc=$?
expect_rc "audit syntax error rc" 1 "$rc"
echo "$out" | grep -q "line 1" || { echo "[FAIL] audit must report the line number"; fail=1; }

# 16. exports-audit: missing file -> rc 2
"$BIN" server --exports-audit --exports-file /nonexistent 2>/dev/null && rc=0 || rc=$?
expect_rc "audit missing file rc" 2 "$rc"
rm -f "$tmp"

[ "$fail" -eq 0 ] && echo "[OK] subcommand dispatch behaves"
exit "$fail"
