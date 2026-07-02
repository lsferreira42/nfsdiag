#!/bin/sh
# Golden consistency oracle for the structured outputs. Instead of a brittle
# byte-for-byte snapshot (the event set depends on the host's rpcbind/NFS
# state), this asserts the invariants that must hold in every environment:
# the four renderers agree on the counters, the event stream is well-formed,
# check_ids are stable across runs, and the exit code follows the summary.
#
# Scenario snapshots with real success/warn/fail events live in the docker
# fixtures (tests/run-fixture-tests.sh), which need a real NFS server.
set -eu

BIN=${NFSDIAG_BIN:-./nfsdiag}
HOST=127.0.0.1

if [ ! -x "$BIN" ]; then
    echo "[SKIP] $BIN not found; build it first" >&2
    exit 0
fi
for tool in jq xmllint; do
    command -v "$tool" >/dev/null 2>&1 || { echo "[SKIP] $tool not installed" >&2; exit 0; }
done

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# nfsdiag exits 1 when the run has warnings/failures (expected for localhost).
run() { "$BIN" client --no-mount --timeout 2 "$@" "$HOST" 2>/dev/null || true; }
run --json=-               >"$work/r.json"
run --output-format ndjson >"$work/r.ndjson"
run --output-format junit  >"$work/r.junit"
run --output-format prometheus >"$work/r.prom"

fail=0
note() { echo "[FAIL] $1" >&2; fail=1; }

jq empty "$work/r.json" || note "JSON is not valid"
xmllint --noout "$work/r.junit" || note "JUnit is not valid XML"

ok=$(jq '.summary.ok'   "$work/r.json")
warn=$(jq '.summary.warn' "$work/r.json")
failc=$(jq '.summary.fail' "$work/r.json")
total=$(jq '.events | length' "$work/r.json")

# Every event carries the six required fields and a valid level.
bad=$(jq '[.events[] | select(
        (((has("check_id") and has("level") and has("category") and
           has("severity") and has("message") and has("remediation"))) | not)
        or (([.level] | inside(["ok","warn","fail","info"])) | not)
      )] | length' "$work/r.json")
[ "$bad" = "0" ] || note "JSON has $bad malformed events"

# NDJSON: one valid object per event.
ndlines=$(grep -c . "$work/r.ndjson" || true)
[ "$ndlines" = "$total" ] || note "NDJSON line count ($ndlines) != JSON events ($total)"
grep -c . "$work/r.ndjson" >/dev/null && while IFS= read -r line; do
    [ -z "$line" ] && continue
    printf '%s' "$line" | jq empty || note "NDJSON line is not valid JSON: $line"
done <"$work/r.ndjson"

# JUnit counters mirror the summary.
jtests=$(sed -n 's/.*<testsuite[^>]*tests="\([0-9]*\)".*/\1/p' "$work/r.junit")
jfail=$(sed -n 's/.*<testsuite[^>]*failures="\([0-9]*\)".*/\1/p' "$work/r.junit")
jskip=$(sed -n 's/.*<testsuite[^>]*skipped="\([0-9]*\)".*/\1/p' "$work/r.junit")
[ "$jtests" = "$total" ] || note "JUnit tests ($jtests) != JSON events ($total)"
[ "$jfail" = "$failc" ] || note "JUnit failures ($jfail) != summary fail ($failc)"
[ "$jskip" = "$warn" ]  || note "JUnit skipped ($jskip) != summary warn ($warn)"

# Prometheus gauges mirror the summary.
pok=$(sed -n 's/^nfsdiag_summary_ok{[^}]*} \([0-9]*\)/\1/p'   "$work/r.prom")
pwarn=$(sed -n 's/^nfsdiag_summary_warn{[^}]*} \([0-9]*\)/\1/p' "$work/r.prom")
pfail=$(sed -n 's/^nfsdiag_summary_fail{[^}]*} \([0-9]*\)/\1/p' "$work/r.prom")
[ "$pok" = "$ok" ]     || note "Prometheus ok ($pok) != summary ok ($ok)"
[ "$pwarn" = "$warn" ] || note "Prometheus warn ($pwarn) != summary warn ($warn)"
[ "$pfail" = "$failc" ] || note "Prometheus fail ($pfail) != summary fail ($failc)"

# check_ids are deterministic across runs.
run --json=- >"$work/r2.json"
ids1=$(jq -S '[.events[].check_id]' "$work/r.json")
ids2=$(jq -S '[.events[].check_id]' "$work/r2.json")
[ "$ids1" = "$ids2" ] || note "check_ids are not stable across runs"

# The deprecated no-subcommand alias produces the same stdout as `client`
# (the deprecation warning goes to stderr and must not leak into stdout).
"$BIN" --no-mount --timeout 2 --json=- "$HOST" 2>/dev/null >"$work/legacy.json" || true
legacy_ids=$(jq -S '[.events[].check_id]' "$work/legacy.json")
[ "$legacy_ids" = "$ids1" ] || note "legacy alias output differs from 'client' output"

# Exit code follows the summary.
rc=0
"$BIN" client --no-mount --timeout 2 "$HOST" >/dev/null 2>&1 || rc=$?
if [ "$warn" -gt 0 ] || [ "$failc" -gt 0 ]; then
    [ "$rc" = "1" ] || note "exit code $rc, expected 1 with warn/fail present"
else
    [ "$rc" = "0" ] || note "exit code $rc, expected 0 with a clean run"
fi

if [ "$fail" -eq 0 ]; then
    echo "[OK] structured outputs agree (events=$total ok=$ok warn=$warn fail=$failc)"
fi
exit "$fail"
