#!/bin/sh
# Validate the JSON report against docs/nfsdiag.schema.json.
# Prefers a real JSON Schema validator (python3 + jsonschema); falls back to a
# structural check with jq so the test still catches missing/renamed keys when
# jsonschema is not installed.
set -eu

BIN=${NFSDIAG_BIN:-./nfsdiag}
SCHEMA=docs/nfsdiag.schema.json

if [ ! -x "$BIN" ]; then
    echo "[SKIP] $BIN not found; build it first" >&2
    exit 0
fi

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

# nfsdiag exits non-zero when the run contains warnings/failures, which is
# expected for a localhost probe; we only care that valid JSON was produced.
"$BIN" client --no-mount --json=- 127.0.0.1 >"$tmp" 2>/dev/null || true
if [ ! -s "$tmp" ]; then
    echo "[FAIL] $BIN produced no JSON output" >&2
    exit 1
fi

if command -v python3 >/dev/null 2>&1 && \
   python3 -c 'import jsonschema' >/dev/null 2>&1; then
    python3 - "$SCHEMA" "$tmp" <<'PY'
import json, sys
import jsonschema

schema = json.load(open(sys.argv[1]))
doc = json.load(open(sys.argv[2]))
jsonschema.validate(doc, schema)
print("[OK] JSON report validates against", sys.argv[1])
PY
    exit 0
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "[SKIP] neither python3+jsonschema nor jq available" >&2
    exit 0
fi

# Fallback: assert the required top-level keys exist and the schema_version is
# the one the schema pins.
missing=$(jq -r '
  ["schema_version","tool","version","host","timestamp","timestamp_iso8601",
   "duration_sec","summary","options","system_info","events","recommendations"]
  - keys
  | join(",")' "$tmp")
if [ -n "$missing" ]; then
    echo "[FAIL] JSON report missing keys: $missing" >&2
    exit 1
fi

ver=$(jq -r '.schema_version' "$tmp")
if [ "$ver" != "2.0" ]; then
    echo "[FAIL] schema_version is '$ver', expected '2.0'" >&2
    exit 1
fi

echo "[OK] JSON report has the expected top-level structure (jq fallback)"
