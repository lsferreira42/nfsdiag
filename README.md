# nfs-doctor (nfsdiag)

**Website:** [www.nfsdiag.org](https://www.nfsdiag.org) · **Releases:** [github.com/lsferreira42/nfsdiag/releases/latest](https://github.com/lsferreira42/nfsdiag/releases/latest)

`nfs-doctor` is a small command line tool written in C to help debug NFS servers from the client side.

The idea is simple: you give one IP or hostname, and the tool checks the things that usually break in NFS: network, rpcbind, NFS versions, mountd, exports, permissions, root squash, locking, stale handles and some basic performance.

It is not magic, and it will not replace a good server side analysis. But it helps a lot to understand if the problem is network, NFS config, permissions, UID/GID mapping, or something more strange.

---

## What this tool does

Today `nfs-doctor` can do these checks:

- test if `rpcbind` TCP port `111` is reachable
- test if NFS TCP port `2049` is reachable
- query the RPC service map from rpcbind (supports IPv6 fallback)
- detect registered NFS, mountd, lockd/NLM and statd/NSM services
- test NFS v2, v3 and v4 with RPC `NULLPROC` (including v4.1 and v4.2 hints)
- test mountd v1, v2 and v3
- optionally test RPC over UDP with `--udp`
- enumerate exports using mountd
- check client prerequisite daemons (nfs-client.target, rpc.gssd, nfs-idmapd)
- detect Kerberos tickets and configuration with `--krb5`
- mount exports automatically under `/tmp/nfsdoctor-*`
- try NFS v4.2 first, then fallback to v4.1, v4, and v3
- parse and verify effective mount options from `/proc/self/mountinfo`
- capture RPC stats (retransmissions, auth refreshes) before and after tests
- extract deep latency metrics from `/proc/self/mountstats`
- run filesystem checks after mount (close-to-open consistency, special files, quotas)
- test read/traverse permission
- test directory listing
- test POSIX ACLs, NFSv4 ACLs, generic xattrs, and SELinux contexts
- test create/write/read/fsync when allowed (with configurable timeouts)
- test advanced I/O operations: `copy_file_range`, `fallocate`, and `O_DIRECT`
- test advisory locks with `fcntl`
- detect practical `root_squash` behavior
- simulate UID/GID access with `prctl` termination safety
- simulate supplemental groups with `--groups`
- run metadata latency test with create/rename/unlink
- run stale file handle loop looking for `ESTALE`
- check for pNFS layouts via `/proc/self/mountstats`
- run external `fio` benchmarks alongside internal smoke tests
- safely handle temporary files, mounts and folders using `O_NOFOLLOW`
- perform safe audits with `--dry-run` and rate limiting (`--delay-ms`)
- generate hierarchical JSON reports for automation (NFS minor version tracked)
- generate standalone HTML reports with inline CSS (`--html`)
- output colored text and progress bars on interactive terminals
- run Docker fixture tests for regression checks (all 14 fixtures included)

By default the output is compact. If you want all details, use `--verbose`.

---

## Important note

NFS problems are very environment dependent. The result can change because of:

- firewall rules
- server export options
- NFS version
- kernel client state
- UID/GID mapping
- root squash
- ACLs
- SELinux/AppArmor on server
- server load
- stale file handles that only happen during real use

So, if the tool says no `ESTALE` happened, it means only that the tool did not reproduce it during the test window. It does not mean the problem can never happen.

---

## Build requirements

On Debian or Ubuntu:

```sh
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libtirpc-dev
```

On Fedora/RHEL style distros:

```sh
sudo dnf install -y gcc make pkgconf-pkg-config libtirpc-devel
```

For live mount tests you also need NFS client tools.

Debian or Ubuntu:

```sh
sudo apt-get install -y nfs-common
```

Fedora/RHEL style distros:

```sh
sudo dnf install -y nfs-utils
```

---

## Build

Normal build:

```sh
make
```

Clean and rebuild:

```sh
make rebuild
```

Small self-check:

```sh
make check
```

Install:

```sh
sudo make install
```

Install in another prefix:

```sh
make PREFIX=/opt/nfs-doctor install
```

Uninstall:

```sh
sudo make uninstall
```

Manual compile, if you want:

```sh
gcc -O2 -Wall -Wextra -D_GNU_SOURCE -I/usr/include/tirpc \
    src/main.c src/mount.c src/network.c src/report.c \
    src/rpc.c src/stats.c src/tests.c \
    -ltirpc -o nfsdiag
```

---

## Packaging

Packages are placed in `build/` after each build target.

Build a Debian/Ubuntu `.deb`:

```sh
make deb
```

Build a Fedora/RHEL `.rpm` (requires `rpm-build`):

```sh
make rpm
```

Build an Alpine `.apk` (requires Docker):

```sh
make apk
```

Build all formats at once:

```sh
make packages
```

---

## GitHub release

`make release` builds all packages, creates an annotated git tag, pushes it,
and uploads the resulting `.deb`, `.rpm`, and `.apk` to a GitHub release using
the `gh` CLI. The working directory must be clean before running.

```sh
make release
```

Automated releases also run via GitHub Actions whenever a `v*` tag is pushed.
The workflow builds DEB on Ubuntu, RPM in a Fedora container, and APK via
Docker, then creates the release with all three packages attached. See
`.github/workflows/release.yml`.

---

## Version bumping

The version lives in `VERSION` and is mirrored in `src/nfsdiag.h` and all
packaging files. Use these targets to bump it atomically:

```sh
make bump-version-bugfix   # 0.2.0 → 0.2.1
make bump-version-minor    # 0.2.0 → 0.3.0
make bump-version-major    # 0.2.0 → 1.0.0
```

Each target rewrites `VERSION`, `src/nfsdiag.h` (`NFSDIAG_VERSION`),
`packaging/nfsdiag.control`, `packaging/nfsdiag.spec`, and
`packaging/Dockerfile.apk` in one shot.

---

## Basic usage

Full diagnostic:

```sh
sudo ./nfsdiag 192.168.1.10
```

Verbose mode:

```sh
sudo ./nfsdiag --verbose 192.168.1.10
```

Only network and RPC checks, without mounting anything:

```sh
./nfsdiag --no-mount 192.168.1.10
```

Test only one export:

```sh
sudo ./nfsdiag --export /data 192.168.1.10
```

Pass mount options:

```sh
sudo ./nfsdiag --mount-options soft,timeo=30,retrans=2 192.168.1.10
```

Do not create/write test files:

```sh
sudo ./nfsdiag --read-only 192.168.1.10
```

Keep the temp folder for manual inspection:

```sh
sudo ./nfsdiag --keep-temp 192.168.1.10
```

---

## Output style

Default output is clean and short. For example, in a healthy server it can be something like:

```text
nfsdiag 0.2.0: 192.168.0.21
[OK] 1 export(s) discovered
summary: ok=13 warn=0 fail=0
```

If you want to see all probe steps, use:

```sh
./nfsdiag --verbose 192.168.0.21
```

Warnings and failures always appear in normal mode. Informational and low-level OK messages only appear in verbose mode.

---

## JSON output

For automation, use JSON.

JSON to stdout (diagnostic text is suppressed):

```sh
./nfsdiag --json 192.168.1.10
# or equivalently:
./nfsdiag --json=- 192.168.1.10
```

JSON to file (diagnostic text still appears on stdout normally):

```sh
./nfsdiag --json=report.json 192.168.1.10
```

To suppress stdout when writing JSON to a file, combine with `--quiet`:

```sh
./nfsdiag --quiet --json=report.json 192.168.1.10
```

The JSON includes:

- tool name and version
- host
- timestamp
- system information (kernel, hostname, arch)
- summary (ok, warn, fail)
- options used
- exports (hierarchical list of mount tests with performance metrics, ACLs, NFS major and minor version)
- global events
- recommendations

---

## HTML output

For human-readable reports that can be easily shared or attached to tickets, use HTML:

```sh
./nfsdiag --html=report.html 192.168.1.10
```

HTML to stdout (diagnostic text is suppressed):

```sh
./nfsdiag --html=- 192.168.1.10
```

The generated HTML is standalone with inline CSS. Reports are written with mode `0600` and without following symlinks (`O_NOFOLLOW`).

---

## UID/GID and permission tests

Simulate one UID/GID:

```sh
sudo ./nfsdiag --uid 1000 --gid 1000 192.168.1.10
```

Simulate more than one identity:

```sh
sudo ./nfsdiag --uid 1000 --gid 1000 --uid 65534 --gid 65534 192.168.1.10
```

Simulate supplemental groups:

```sh
sudo ./nfsdiag --uid 1000 --gid 1000 --groups 10,20,30 192.168.1.10
```

This is useful because many NFS problems are not really NFS protocol problems. Many times it is UID, GID, groups, ACL, or root squash.

---

## Performance and stale handle tests

Change write/read test size:

```sh
sudo ./nfsdiag --bench-bytes 167772160 192.168.1.10
```

Change metadata latency iterations:

```sh
sudo ./nfsdiag --bench-iterations 500 192.168.1.10
```

Change stale handle loop:

```sh
sudo ./nfsdiag --stale-iterations 1000 192.168.1.10
```

Run benchmarks using `fio` instead of the internal C loop (requires `fio` installed):

```sh
sudo ./nfsdiag --bench-type=fio 192.168.1.10
```

The performance test is only a smoke test. It is not a replacement for full benchmarking, though enabling `fio` provides more accurate storage baseline metrics.

---

## Safety options

Timeout for external commands like `mount` and `umount`:

```sh
sudo ./nfsdiag --command-timeout 15 192.168.1.10
```

Delay between testing each export (rate limiting):

```sh
sudo ./nfsdiag --delay-ms 500 192.168.1.10
```

Simulate the tool execution without actually mounting or modifying anything:

```sh
./nfsdiag --dry-run 192.168.1.10
```

Try to isolate live mounts in a private mount namespace:

```sh
sudo ./nfsdiag --mount-namespace 192.168.1.10
```

This needs root or `CAP_SYS_ADMIN`.

---

## Network/protocol options

Probe UDP RPC too:

```sh
./nfsdiag --no-mount --udp 192.168.1.10
```

Force IPv4 direct TCP checks:

```sh
./nfsdiag --ipv4-only --no-mount 192.168.1.10
```

Force IPv6 direct TCP checks:

```sh
./nfsdiag --ipv6-only --no-mount nfs-server.example.com
```

Disable NFSv4 pseudo-root fallback:

```sh
sudo ./nfsdiag --no-nfs4-discovery 192.168.1.10
```

The NFSv4 fallback is useful when the server is NFSv4-only and mountd is not available.

---

## Command line reference

```text
Usage: nfsdiag [OPTIONS] <server-ip-or-hostname>

Diagnostic options:
  -e, --export PATH          Test only this export path
  -o, --mount-options OPTS   Extra mount options passed to mount(8)
      --no-mount             Run network/RPC checks only; skip all mounts
      --dry-run              Print what would be done; skip mounts and fs tests
      --read-only            Do not create or write test files
      --uid UID              Simulate access as UID (repeatable, needs root)
      --gid GID              GID paired with last --uid
      --groups G1,G2         Supplemental GIDs for UID/GID simulation
      --krb5                 Check Kerberos prerequisites (ticket, gssd)
      --udp                  Also probe RPC NULLPROC over UDP
      --ipv4-only            Force IPv4 for direct TCP checks
      --ipv6-only            Force IPv6 for direct TCP checks
      --no-nfs4-discovery    Disable NFSv4 pseudo-root fallback
      --mount-namespace      Use private mount namespace (needs root/CAP_SYS_ADMIN)

Timeout options:
      --timeout SEC          Network/RPC connect timeout. Default: 5
      --command-timeout SEC  Timeout for mount/umount commands. Default: 30
      --fs-timeout SEC       Timeout for each filesystem test group. Default: 30
      --delay-ms MS          Delay between testing each export (rate limit). Default: 0

Benchmark options:
      --bench-bytes BYTES    Bytes for read/write benchmark. Default: 4194304
      --bench-iterations N   Metadata latency iterations. Default: 10
      --bench-type TYPE      Benchmark engine: 'internal' or 'fio'. Default: internal
      --stale-iterations N   ESTALE probe loop iterations. Default: 100

Output options:
      --json[=PATH]          Emit JSON report to PATH (use '-' or omit for stdout)
      --html[=PATH]          Emit HTML report to PATH (use '-' or omit for stdout)
      --keep-temp            Keep temp workspace after tests
  -v, --verbose              Show all diagnostic steps
  -q, --quiet                Suppress stdout (combine with --json=FILE or --html=FILE)
  -V, --version              Print version and exit
  -h, --help                 Show this help

Exit codes: 0=pass  1=warn/fail  2=usage/runtime error

Stdout suppression: active only when --json=- or --html=- (report to stdout).
  Use --quiet to suppress stdout when writing a report to a file.
```

---

## Exit codes

- `0`: no warnings or failures
- `1`: warning or failure found
- `2`: usage error or local runtime error

Warnings return `1` because in automation they usually need attention.

---

## Docker fixtures

The project has Docker fixtures to reproduce bad NFS situations.

List fixtures:

```sh
make docker-list
```

Build all fixtures:

```sh
make docker-build-all
```

Build one fixture:

```sh
make docker-build-read-only-export
```

Run automated fixture tests:

```sh
make test-fixtures
```

Run only one test:

```sh
make test-fixture-rpcbind-unreachable
```

Some tests need root because they do real NFS mounts from the host. If the host cannot run kernel NFS inside Docker, the test runner skips those cases instead of failing everything.

> **Warning:** Docker fixture configurations use wildcard clients, `insecure`, and `no_root_squash`
> intentionally to simulate test scenarios. These settings are **test-only** and must **never** be
> used in production. Each `exports.*` file in `dockerfiles/common/` carries this warning.

The current fixture set includes:

- `rpcbind-unreachable`
- `nfs-port-unreachable`
- `rpc-map-missing-nfs`
- `mountd-unavailable`
- `empty-exports`
- `mount-denied`
- `permission-denied`
- `acl-unsupported`
- `identity-denied`
- `read-only-export`
- `root-squash`
- `locking-missing`
- `stale-handle`
- `slow-performance`

---

## What changed in v0.2.0

Security and crash fixes:

- `strdup()` return now checked in `add_event()` and `add_recommendation()` — prevents NULL dereference under OOM
- Report files opened with `O_NOFOLLOW | O_CREAT | 0600` — prevents symlink attacks when running as root
- XDR string limits applied to export paths (4096 bytes) and group names (256 bytes) — prevents memory exhaustion from malicious servers
- `fio` benchmarks now use `execvp` argv array instead of `sh -c` — eliminates unnecessary shell injection surface
- Numeric CLI arguments reject empty strings — `--uid=` is now an error, not silent zero

Behavioral fixes:

- `--json=file` no longer suppresses stdout; use `--quiet` to suppress explicitly
- `--html=-` (HTML to stdout) now suppresses diagnostic text correctly
- `--dry-run` no longer runs filesystem diagnostics on local temp dir
- Write/read benchmark, advisory lock, and root_squash detection are now independent tests, each with its own timeout and temp file
- `enumerate_exports()` now tries mountd v2 between v3 and v1
- IPv6 literal addresses get brackets in mount source (`[addr]:/export`)
- NFS minor version (4.1, 4.2) now tracked in JSON and HTML reports

Robustness:

- Pipe drain continues discarding data when output buffer is full — no more stall-until-timeout on large command output
- `dup2()` return checked in child process
- `sscanf()` return checked when parsing `/proc/net/rpc/nfs`
- RPC counter wrap/reset detected when computing stats delta
- `clnt_create()` and `pmap_getmaps()` protected with SIGALRM-based timeout
- Report buffer increased from 512 to 2048 bytes — long error messages no longer truncate silently
- Mountpoint option detection uses exact comma-separated token matching
- Mountstats section matched by exact mountpoint field, not substring
- Signal handlers installed without `SA_RESTART` for more responsive interruption

Constants and consistency:

- `RPCBIND_PORT`, `NFS_PORT`, `DEFAULT_COMMAND_TIMEOUT_SEC`, `DEFAULT_BENCH_ITERATIONS` defined in `nfsdiag.h`
- Mountpoint buffer changed from 256 to 4096 bytes
- Test runner now uses `mktemp` instead of predictable `/tmp` filenames
- All 14 fixtures now included in `ALL_FIXTURES` (was 9)

Portability and other:

- `TMPDIR` environment variable respected for temp workspace location
- Client daemon checks skipped gracefully on non-systemd systems
- `TEST_TIMEOUT` now applied to each `nfsdiag` invocation in the test runner
- `--version` / `-V` flag added
- CLI options reorganised into logical groups (Diagnostic / Timeout / Benchmark / Output)
- All default values shown in `--help` using named constants
- Fixture `exports.*` files and entrypoint marked with "TEST-ONLY" comments

---

## Security notes

Be careful when running against production exports.

By default the tool may create hidden `.nfsdoctor-*` files to test write/read behavior. If you do not want this, use:

```sh
--read-only
```

Also, UID/GID simulation requires root because the tool uses `setgid`, `setgroups`, and `setuid` in child processes.

---

## Limitations

Some things are impossible to guarantee from the client side:

- `ESTALE` only appears if the handle becomes stale during the test
- SELinux/AppArmor problems can look only like generic permission denied
- ACL info depends on what the NFS client exposes
- performance numbers are only smoke-test values
- Docker NFS fixtures depend on host kernel and Docker privileges

So use this tool as a fast diagnostic helper, not as the only source of truth.
