#!/bin/sh
# Server-namespace checks against synthetic /proc//etc fixtures via --root.
# Run from repo root with a built ./nfsdiag: sh tests/check-server.sh
set -eu

BIN=${NFSDIAG_BIN:-./nfsdiag}
fail=0
expect_rc() {
    if [ "$3" -ne "$2" ]; then
        echo "[FAIL] $1: expected rc=$2 got rc=$3"; fail=1
    fi
}

root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
mkdir -p "$root/etc"
cat > "$root/etc/exports" <<'EOF'
/srv/data 10.0.0.0/24(rw,sync,root_squash)
EOF

# 1. --json=- carries mode:server and host, rc 0 for a clean audit
out=$("$BIN" server --exports-audit --root "$root" --json=- --quiet) && rc=0 || rc=$?
expect_rc "audit --json rc" 0 "$rc"
echo "$out" | grep -q '"mode": "server"' || { echo "[FAIL] json missing mode:server"; fail=1; }
echo "$out" | grep -q '"tool": "nfsdiag"' || { echo "[FAIL] json missing tool"; fail=1; }

# 2. default banner is the unified one (hostname, not the old audit banner)
out=$("$BIN" server --exports-audit --root "$root")
echo "$out" | grep -q "^nfsdiag .*: $(hostname)" || { echo "[FAIL] unified banner missing"; fail=1; }

# 3. --quiet suppresses banner and summary
out=$("$BIN" server --exports-audit --root "$root" --quiet)
echo "$out" | grep -q "summary:" && { echo "[FAIL] --quiet must suppress summary"; fail=1; }

# 4. --output-format junit emits XML on stdout, no banner
out=$("$BIN" server --exports-audit --root "$root" --output-format=junit)
echo "$out" | grep -q "<testsuite" || { echo "[FAIL] junit output missing"; fail=1; }
echo "$out" | grep -q "^nfsdiag " && { echo "[FAIL] junit must not print banner"; fail=1; }

# 5. --output-dir writes json+html+evidence+checksums
oda=$(mktemp -d)
"$BIN" server --exports-audit --root "$root" --output-dir "$oda" --quiet >/dev/null 2>&1 || true
set -- "$oda"/*.json; [ -e "$1" ] || { echo "[FAIL] output-dir json missing"; fail=1; }
set -- "$oda"/*.html; [ -e "$1" ] || { echo "[FAIL] output-dir html missing"; fail=1; }
[ -e "$oda/SHA256SUMS" ]          || { echo "[FAIL] output-dir checksums missing"; fail=1; }
rm -rf "$oda"

# 6. --root must exist
"$BIN" server --exports-audit --root /nonexistent-root 2>/dev/null && rc=0 || rc=$?
expect_rc "bad --root rc" 2 "$rc"

# 7. version-matrix reads the synthetic /proc/fs/nfsd
mkdir -p "$root/proc/fs/nfsd"
printf -- "-2 +3 +4 +4.1 -4.2\n" > "$root/proc/fs/nfsd/versions"
echo 8    > "$root/proc/fs/nfsd/threads"
echo 90   > "$root/proc/fs/nfsd/nfsv4leasetime"
echo 15   > "$root/proc/fs/nfsd/nfsv4gracetime"
echo 1048576 > "$root/proc/fs/nfsd/max_block_size"
out=$("$BIN" server --version-matrix --root "$root") && rc=0 || rc=$?
expect_rc "version-matrix rc" 0 "$rc"
echo "$out" | grep -q "NFSv4.1: enabled"  || { echo "[FAIL] matrix missing v4.1"; fail=1; }
echo "$out" | grep -q "NFSv4.2: disabled" || { echo "[FAIL] matrix missing v4.2 state"; fail=1; }
echo "$out" | grep -q "lease time: 90s"   || { echo "[FAIL] matrix missing lease"; fail=1; }

# 8. version-matrix without nfsd -> warn, rc 1
root2=$(mktemp -d)
out=$("$BIN" server --version-matrix --root "$root2" 2>&1) && rc=0 || rc=$?
expect_rc "matrix no-nfsd rc" 1 "$rc"
echo "$out" | grep -qi "nfsd not loaded" || { echo "[FAIL] matrix must explain missing nfsd"; fail=1; }
rm -rf "$root2"

# 9. sysctl-advisor: starvation and low rmem flagged, rc 1
mkdir -p "$root/proc/net/rpc" "$root/proc/sys/net/core"
printf 'rc 0 0 0\nth 2 0 0.000 0.000 0.000 0.000 0.000 0.000 0.000 0.000 0.000 55.100\n' \
    > "$root/proc/net/rpc/nfsd"
echo 212992 > "$root/proc/sys/net/core/rmem_max"
echo 212992 > "$root/proc/sys/net/core/wmem_max"
out=$("$BIN" server --sysctl-advisor --root "$root" 2>&1) && rc=0 || rc=$?
expect_rc "sysctl-advisor rc" 1 "$rc"
echo "$out" | grep -qi "all .* threads busy" || { echo "[FAIL] advisor must flag thread starvation"; fail=1; }
echo "$out" | grep -qi "rmem_max"            || { echo "[FAIL] advisor must mention rmem_max"; fail=1; }

# 10. daemons: finds mountd by comm, flags missing statd, rc 1
mkdir -p "$root/proc/101" "$root/proc/202"
printf 'rpc.mountd\n' > "$root/proc/101/comm"
printf 'rpcbind\n'    > "$root/proc/202/comm"
out=$("$BIN" server --daemons --root "$root" 2>&1) && rc=0 || rc=$?
expect_rc "daemons rc" 1 "$rc"
echo "$out" | grep -q "rpc.mountd: running"   || { echo "[FAIL] daemons must find mountd"; fail=1; }
echo "$out" | grep -q "rpc.statd: not running" || { echo "[FAIL] daemons must flag statd"; fail=1; }
echo "$out" | grep -qi "rpcbind registration check skipped" || { echo "[FAIL] daemons must skip rpc dump under --root"; fail=1; }

# 11. ports: 2049 listening, 111 not -> fail on rpcbind port, rc 1
mkdir -p "$root/proc/net"
cat > "$root/proc/net/tcp" <<'TCPEOF'
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0801 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 100 1 0 10 0
TCPEOF
printf '  sl  local_address rem_address st\n' > "$root/proc/net/tcp6"
out=$("$BIN" server --ports-firewall --root "$root" 2>&1) && rc=0 || rc=$?
expect_rc "ports rc" 1 "$rc"
echo "$out" | grep -q "port 2049: listening"     || { echo "[FAIL] ports must see 2049"; fail=1; }
echo "$out" | grep -q "port 111: not listening"  || { echo "[FAIL] ports must flag 111"; fail=1; }
echo "$out" | grep -qi "firewall check skipped"  || { echo "[FAIL] firewall must skip under --root"; fail=1; }

# 12. storage-health under --root: parses exports, skips live statvfs
out=$("$BIN" server --storage-health --root "$root" 2>&1) && rc=0 || rc=$?
echo "$out" | grep -q "/srv/data" || { echo "[FAIL] storage must list the export"; fail=1; }
echo "$out" | grep -qi "filesystem inspection skipped" || { echo "[FAIL] storage must skip statvfs under --root"; fail=1; }

# 13. storage-health live: current directory's fs is inspectable
tmpexports=$(mktemp)
printf '%s 127.0.0.1(ro)\n' "$(pwd)" > "$tmpexports"
out=$("$BIN" server --storage-health --exports-file "$tmpexports" 2>&1) && rc=0 || rc=$?
echo "$out" | grep -q "free" || { echo "[FAIL] storage live must report space"; fail=1; }
rm -f "$tmpexports"

# 14. --all runs every check in order
out=$("$BIN" server --all --root "$root" 2>&1) && rc=0 || rc=$?
echo "$out" | grep -q "kernel nfsd"      || { echo "[FAIL] --all must run daemons"; fail=1; }
echo "$out" | grep -q "NFSv4.1"          || { echo "[FAIL] --all must run version-matrix"; fail=1; }
echo "$out" | grep -q "port 2049"        || { echo "[FAIL] --all must run ports"; fail=1; }
echo "$out" | grep -q "exports"          || { echo "[FAIL] --all must run exports-audit"; fail=1; }
echo "$out" | grep -qi "threads"         || { echo "[FAIL] --all must run sysctl-advisor"; fail=1; }
echo "$out" | grep -qi "security" || { echo "[FAIL] --all must run security-audit"; fail=1; }
echo "$out" | grep -qi "idmap"           || { echo "[FAIL] --all must run idmap-check"; fail=1; }
echo "$out" | grep -qi "krb5"            || { echo "[FAIL] --all must run krb5-server"; fail=1; }
echo "$out" | grep -qi "acl"             || { echo "[FAIL] --all must run acl-check"; fail=1; }
echo "$out" | grep -qi "rpc stats"       || { echo "[FAIL] --all must run rpc-stats"; fail=1; }
echo "$out" | grep -q "locks:"           || { echo "[FAIL] --all must run locks"; fail=1; }
echo "$out" | grep -q "clients:"         || { echo "[FAIL] --all must run clients"; fail=1; }
echo "$out" | grep -qi "client states"   || { echo "[FAIL] --all must run client-states"; fail=1; }
echo "$out" | grep -qi "memory pressure" || { echo "[FAIL] --all must run memory-pressure"; fail=1; }
echo "$out" | grep -qi "rmtab audit"     || { echo "[FAIL] --all must run rmtab-audit"; fail=1; }
echo "$out" | grep -qi "log intel"       || { echo "[FAIL] --all must run log-intel"; fail=1; }
echo "$out" | grep -qi "squash check"    && { echo "[FAIL] --all must NOT run squash-check"; fail=1; }

# 15. security-audit: deep findings, rc 1
cat > "$root/etc/exports" <<'SECEOF'
/srv/data 10.0.0.0/24(rw,sync,root_squash)
/srv/dup  host1(rw,subtree_check)
/srv/dup  host2(ro)
/srv/dup/nested host3(rw)
SECEOF
out=$("$BIN" server --security-audit --root "$root" 2>&1) && rc=0 || rc=$?
expect_rc "security-audit rc" 1 "$rc"
echo "$out" | grep -q "subtree_check"   || { echo "[FAIL] audit must flag subtree_check"; fail=1; }
echo "$out" | grep -q "exported twice"  || { echo "[FAIL] audit must flag duplicate export"; fail=1; }
echo "$out" | grep -q "crossmnt"        || { echo "[FAIL] audit must flag nested export"; fail=1; }
cat > "$root/etc/exports" <<'SECEOF'
/srv/data 10.0.0.0/24(rw,sync,root_squash)
SECEOF

# 16. idmap-check: domain reported, nobody-user missing from passwd -> warn
cat > "$root/etc/idmapd.conf" <<'IDEOF'
[General]
Domain = lab.example.com
[Mapping]
Nobody-User = nfsnobody
Nobody-Group = nfsnobody
IDEOF
printf 'root:x:0:0:root:/root:/bin/sh\n' > "$root/etc/passwd"
out=$("$BIN" server --idmap-check --root "$root" 2>&1) && rc=0 || rc=$?
expect_rc "idmap rc" 1 "$rc"
echo "$out" | grep -q "lab.example.com" || { echo "[FAIL] idmap must report the domain"; fail=1; }
echo "$out" | grep -q "nfsnobody"       || { echo "[FAIL] idmap must flag missing nobody-user"; fail=1; }

# 17. idmap-check: missing idmapd.conf -> info, rc 0
root3=$(mktemp -d)
mkdir -p "$root3/etc"
out=$("$BIN" server --idmap-check --root "$root3" 2>&1) && rc=0 || rc=$?
expect_rc "idmap defaults rc" 0 "$rc"
echo "$out" | grep -qi "defaults" || { echo "[FAIL] idmap must mention defaults"; fail=1; }
rm -rf "$root3"

# 18. krb5-server: conf present, keytab missing -> warn + live steps skipped
cat > "$root/etc/krb5.conf" <<'K5EOF'
[libdefaults]
 default_realm = LAB.EXAMPLE.COM
K5EOF
out=$("$BIN" server --krb5-server --root "$root" 2>&1) && rc=0 || rc=$?
expect_rc "krb5 rc" 1 "$rc"
echo "$out" | grep -q "LAB.EXAMPLE.COM" || { echo "[FAIL] krb5 must report the realm"; fail=1; }
echo "$out" | grep -qi "keytab" || { echo "[FAIL] krb5 must flag missing keytab"; fail=1; }
echo "$out" | grep -qi "skipped under --root" || { echo "[FAIL] krb5 must skip live steps"; fail=1; }

# 19. acl-check: live probe on the current directory's fs
tmpexports=$(mktemp)
printf '%s 127.0.0.1(ro)\n' "$(pwd)" > "$tmpexports"
out=$("$BIN" server --acl-check --exports-file "$tmpexports" 2>&1) && rc=0 || rc=$?
echo "$out" | grep -qi "acl" || { echo "[FAIL] acl-check must mention ACLs"; fail=1; }
rm -f "$tmpexports"

# 20. acl-check under --root: skipped with explanation
out=$("$BIN" server --acl-check --root "$root" 2>&1) && rc=0 || rc=$?
echo "$out" | grep -qi "skipped under --root" || { echo "[FAIL] acl-check must skip under --root"; fail=1; }

# 21. squash-check without root privileges -> explains the requirement
if [ "$(id -u)" -ne 0 ]; then
    out=$("$BIN" server --squash-check 2>&1) && rc=0 || rc=$?
    expect_rc "squash non-root rc" 1 "$rc"
    echo "$out" | grep -qi "requires root" || { echo "[FAIL] squash-check must require root"; fail=1; }
fi

# 22. audit-trail: copies configs into --output-dir with checksums
oda=$(mktemp -d)
"$BIN" server --exports-audit --audit-trail --root "$root" --output-dir "$oda" --quiet >/dev/null 2>&1 || true
[ -e "$oda/config-exports" ]         || { echo "[FAIL] audit-trail must copy the exports file"; fail=1; }
[ -e "$oda/config-idmapd.conf" ]     || { echo "[FAIL] audit-trail must copy idmapd.conf"; fail=1; }
[ -e "$oda/CONFIG.SHA256SUMS" ]      || { echo "[FAIL] audit-trail must write CONFIG.SHA256SUMS"; fail=1; }
rm -rf "$oda"

# 23. audit-trail without --output-dir -> usage error
"$BIN" server --exports-audit --audit-trail --root "$root" 2>/dev/null && rc=0 || rc=$?
expect_rc "audit-trail no dir rc" 2 "$rc"

# 24. rpc-stats: reply cache rate + bad calls flagged, rc 1
cat > "$root/proc/net/rpc/nfsd" <<'RPCEOF'
rc 900 100 5
net 1000 200 800 3
rpc 5000 7 0 0 0
io 111 222
RPCEOF
out=$("$BIN" server --rpc-stats --root "$root" 2>&1) && rc=0 || rc=$?
expect_rc "rpc-stats rc" 1 "$rc"
echo "$out" | grep -qi "reply cache hit rate" || { echo "[FAIL] rpc-stats must report cache rate"; fail=1; }
echo "$out" | grep -qi "bad RPC calls"        || { echo "[FAIL] rpc-stats must flag bad calls"; fail=1; }

# 25. rpc-stats: no /proc/net/rpc/nfsd -> warn, rc 1
root4=$(mktemp -d)
out=$("$BIN" server --rpc-stats --root "$root4" 2>&1) && rc=0 || rc=$?
expect_rc "rpc-stats no-nfsd rc" 1 "$rc"
echo "$out" | grep -qi "is the NFS server running" || { echo "[FAIL] rpc-stats must explain missing nfsd"; fail=1; }
rm -rf "$root4"

# 26. locks: counts held locks by type from /proc/locks, rc 0
cat > "$root/proc/locks" <<'LKEOF'
1: POSIX  ADVISORY  WRITE 1200 00:1c:1234 0 EOF
2: FLOCK  ADVISORY  WRITE 1201 00:1c:1235 0 EOF
3: DELEG  ACTIVE    READ  1202 00:1c:1236 0 EOF
LKEOF
out=$("$BIN" server --locks --root "$root" 2>&1) && rc=0 || rc=$?
expect_rc "locks rc" 0 "$rc"
echo "$out" | grep -q "locks: 3 held" || { echo "[FAIL] locks must count held locks"; fail=1; }
echo "$out" | grep -qi "grace"        || { echo "[FAIL] locks must report lease/grace"; fail=1; }

# 27. clients: lists NFSv4 client, flags callback DOWN, rc 1
mkdir -p "$root/proc/fs/nfsd/clients/1"
cat > "$root/proc/fs/nfsd/clients/1/info" <<'CLEOF'
clientid: 0x1
address: "10.0.0.5:1010"
status: confirmed
name: "Linux NFSv4.1 client"
minor version: 1
callback state: DOWN
CLEOF
out=$("$BIN" server --clients --root "$root" 2>&1) && rc=0 || rc=$?
expect_rc "clients rc" 1 "$rc"
echo "$out" | grep -q "10.0.0.5:1010"  || { echo "[FAIL] clients must list the client address"; fail=1; }
echo "$out" | grep -qi "callback DOWN" || { echo "[FAIL] clients must flag callback DOWN"; fail=1; }

# 28. clients: no clients dir -> info, rc 0
root5=$(mktemp -d)
out=$("$BIN" server --clients --root "$root5" 2>&1) && rc=0 || rc=$?
expect_rc "clients no-dir rc" 0 "$rc"
echo "$out" | grep -qi "no /proc/fs/nfsd/clients" || { echo "[FAIL] clients must explain missing dir"; fail=1; }
rm -rf "$root5"

# 29. client-states: aggregates opens/locks/delegations/layouts, rc 0
cat > "$root/proc/fs/nfsd/clients/1/states" <<'STEOF'
- 0x0001: { type: open, access: rw }
- 0x0002: { type: lock }
- 0x0003: { type: deleg }
- 0x0004: { type: layout }
STEOF
out=$("$BIN" server --client-states --root "$root" 2>&1) && rc=0 || rc=$?
expect_rc "client-states rc" 0 "$rc"
echo "$out" | grep -q "1 opens"       || { echo "[FAIL] client-states must count opens"; fail=1; }
echo "$out" | grep -qi "delegations"  || { echo "[FAIL] client-states must report delegations"; fail=1; }

# 30. memory-pressure: low MemAvailable -> warn, rc 1
mkdir -p "$root/proc" "$root/proc/sys/vm"
cat > "$root/proc/meminfo" <<'MIEOF'
MemTotal:       1000000 kB
MemFree:          50000 kB
MemAvailable:     50000 kB
Slab:            200000 kB
SReclaimable:    100000 kB
MIEOF
echo 200 > "$root/proc/sys/vm/vfs_cache_pressure"
echo 60  > "$root/proc/sys/vm/swappiness"
out=$("$BIN" server --memory-pressure --root "$root" 2>&1) && rc=0 || rc=$?
expect_rc "memory-pressure rc" 1 "$rc"
echo "$out" | grep -qi "only 5% available"     || { echo "[FAIL] mempress must flag low avail"; fail=1; }
echo "$out" | grep -qi "vfs_cache_pressure"    || { echo "[FAIL] mempress must mention vfs_cache_pressure"; fail=1; }

# 31. rmtab-audit: stale entry flagged, rc 1
mkdir -p "$root/var/lib/nfs/sm"
cat > "$root/var/lib/nfs/rmtab" <<'RMEOF'
10.0.0.1:/srv/data:1
10.0.0.2:/srv/data:0
RMEOF
: > "$root/var/lib/nfs/sm/10.0.0.1"
out=$("$BIN" server --rmtab-audit --root "$root" 2>&1) && rc=0 || rc=$?
expect_rc "rmtab-audit rc" 1 "$rc"
echo "$out" | grep -qi "2 entries"    || { echo "[FAIL] rmtab must count entries"; fail=1; }
echo "$out" | grep -qi "stale"        || { echo "[FAIL] rmtab must flag stale"; fail=1; }

# 32. rmtab-audit: no rmtab -> info, rc 0
root6=$(mktemp -d)
out=$("$BIN" server --rmtab-audit --root "$root6" 2>&1) && rc=0 || rc=$?
expect_rc "rmtab no-file rc" 0 "$rc"
echo "$out" | grep -qi "no /var/lib/nfs/rmtab" || { echo "[FAIL] rmtab must explain missing file"; fail=1; }
rm -rf "$root6"

# 33. log-intel: known signature in /var/log/messages -> warn, rc 1
mkdir -p "$root/var/log"
cat > "$root/var/log/messages" <<'LGEOF'
May  1 10:00:01 srv kernel: lockd: cannot monitor 10.0.0.5
May  1 10:00:02 srv systemd: nothing to see
LGEOF
out=$("$BIN" server --log-intel --root "$root" 2>&1) && rc=0 || rc=$?
expect_rc "log-intel rc" 1 "$rc"
echo "$out" | grep -qi "cannot monitor\|NLM cannot monitor" || { echo "[FAIL] log-intel must surface lockd signature"; fail=1; }

# 34. log-intel: clean log -> ok, rc 0
root7=$(mktemp -d); mkdir -p "$root7/var/log"
printf 'May 1 srv systemd: all good\n' > "$root7/var/log/messages"
out=$("$BIN" server --log-intel --root "$root7" 2>&1) && rc=0 || rc=$?
expect_rc "log-intel clean rc" 0 "$rc"
echo "$out" | grep -qi "no known NFS problem" || { echo "[FAIL] log-intel clean must say so"; fail=1; }
rm -rf "$root7"

# 35. server metrics one-shot: prometheus gauges from /proc fixtures
mkdir -p "$root/proc/net/rpc" "$root/proc/fs/nfsd/clients/1"
printf 'rc 900 100 5\nnet 1 0 1 0\nrpc 5000 7 0 0 0\nth 8 0 0.0 0.0 0.0 0.0 0.0 0.0 0.0 0.0 0.0 12.5\n' \
    > "$root/proc/net/rpc/nfsd"
printf '1: POSIX ADVISORY WRITE 1 00:1c:1 0 EOF\n' > "$root/proc/locks"
out=$("$BIN" server --output-format prometheus --root "$root" 2>&1) && rc=0 || rc=$?
expect_rc "server prometheus rc" 0 "$rc"
echo "$out" | grep -q "nfsdiag_server_nfsd_threads{host=" || { echo "[FAIL] metrics missing nfsd_threads"; fail=1; }
echo "$out" | grep -q "nfsdiag_server_drc_hits{.*} 900"    || { echo "[FAIL] metrics missing drc_hits"; fail=1; }
echo "$out" | grep -q "nfsdiag_server_rpc_badcalls{.*} 7"  || { echo "[FAIL] metrics missing rpc_badcalls"; fail=1; }
echo "$out" | grep -q "nfsdiag_server_locks_held{.*} 1"    || { echo "[FAIL] metrics missing locks_held"; fail=1; }
echo "$out" | grep -q "nfsdiag_server_clients{.*} 1"       || { echo "[FAIL] metrics missing clients"; fail=1; }
echo "$out" | grep -q "^# EOF"                             || { echo "[FAIL] metrics missing EOF"; fail=1; }
echo "$out" | grep -q "nfsdiag_server_snapshot_unixtime{"  || { echo "[FAIL] metrics missing snapshot_unixtime"; fail=1; }
echo "$out" | grep -q "^nfsdiag " && { echo "[FAIL] prometheus must not print banner"; fail=1; }

# 36. --watch with bad value -> usage error rc 2
"$BIN" server --daemons --watch notanumber --root "$root" 2>/dev/null && rc=0 || rc=$?
expect_rc "server bad --watch rc" 2 "$rc"

# 37. --listen with bad value -> usage error rc 2
"$BIN" server --listen notaport 2>/dev/null && rc=0 || rc=$?
expect_rc "server bad --listen rc" 2 "$rc"

# 40. ha-check: export without fsid + /var/lib/nfs on rootfs -> warns
cat > "$root/etc/exports" <<'HAEOF'
/srv/data 10.0.0.0/24(rw,sync,root_squash)
HAEOF
mkdir -p "$root/proc"
printf '/dev/root / ext4 rw 0 0\n' > "$root/proc/mounts"
out=$("$BIN" server --ha-check --root "$root" 2>&1) && rc=0 || rc=$?
expect_rc "ha-check rc" 1 "$rc"
echo "$out" | grep -qi "no explicit fsid" || { echo "[FAIL] ha-check must flag missing fsid"; fail=1; }
echo "$out" | grep -qi "root filesystem"  || { echo "[FAIL] ha-check must flag /var/lib/nfs on rootfs"; fail=1; }

# 41. ganesha-check: ganesha.conf present -> detects ganesha + counts EXPORTs
mkdir -p "$root/etc/ganesha"
cat > "$root/etc/ganesha/ganesha.conf" <<'GEOF'
EXPORT {
  Export_Id = 1;
  Path = /data;
  FSAL { Name = VFS; }
}
GEOF
out=$("$BIN" server --ganesha-check --root "$root" 2>&1) && rc=0 || rc=$?
expect_rc "ganesha-check rc" 0 "$rc"
echo "$out" | grep -qi "nfs-ganesha detected" || { echo "[FAIL] ganesha-check must detect ganesha"; fail=1; }
echo "$out" | grep -qi "1 EXPORT block"        || { echo "[FAIL] ganesha-check must count EXPORTs"; fail=1; }

# 42. ganesha-check: kernel nfsd fixture, no ganesha -> reports kernel nfsd
root8=$(mktemp -d); mkdir -p "$root8/proc/fs/nfsd"
printf -- "-2 +3 +4 +4.1 -4.2\n" > "$root8/proc/fs/nfsd/versions"
out=$("$BIN" server --ganesha-check --root "$root8" 2>&1) && rc=0 || rc=$?
expect_rc "ganesha kernel rc" 0 "$rc"
echo "$out" | grep -qi "kernel nfsd in use" || { echo "[FAIL] ganesha-check must report kernel nfsd"; fail=1; }
echo "$out" | grep -qi "not running in a container" || { echo "[FAIL] ganesha-check must report container state"; fail=1; }
rm -rf "$root8"

[ "$fail" -eq 0 ] && echo "[OK] server namespace output behaves"
exit "$fail"
