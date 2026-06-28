# nfsdiag

**Website:** [www.nfsdiag.org](https://www.nfsdiag.org) · **Releases:** [github.com/lsferreira42/nfsdiag/releases/latest](https://github.com/lsferreira42/nfsdiag/releases/latest)

[![CI](https://github.com/lsferreira42/nfsdiag/actions/workflows/ci.yml/badge.svg)](https://github.com/lsferreira42/nfsdiag/actions/workflows/ci.yml)
[![Deploy website to Cloudflare](https://github.com/lsferreira42/nfsdiag/actions/workflows/deploy-website.yml/badge.svg)](https://github.com/lsferreira42/nfsdiag/actions/workflows/deploy-website.yml)

`nfsdiag` is a command-line NFS diagnostic tool written in C. You give it an IP or hostname, and it checks everything that usually breaks in NFS: network reachability, rpcbind, NFS versions, mountd, exports, permissions, root squash, locking, stale handles, and performance.

It is not magic, and it will not replace a good server-side analysis. But it narrows down whether the problem is network, NFS config, permissions, UID/GID mapping, or something stranger.

---

## What this tool does

- test if `rpcbind` TCP port `111` is reachable
- test if NFS TCP port `2049` is reachable
- query the RPC service map from rpcbind (rpcbind v3/v4 DUMP with native IPv6, plus legacy portmapper)
- measure TCP connect latency and path MTU towards the server
- verify that dynamically registered mountd/lockd/statd ports are reachable through firewalls
- fingerprint the server implementation heuristically from its RPC service layout
- detect registered NFS, mountd, lockd/NLM and statd/NSM services
- test NFS v2, v3 and v4 with RPC `NULLPROC` (including v4.1 and v4.2 hints)
- test mountd v1, v2 and v3; optionally probe RPC over UDP
- enumerate exports using mountd
- check client prerequisite daemons (nfs-client.target, rpc.gssd, nfs-idmapd)
- detect Kerberos tickets and configuration with `--krb5`, and test which sec=krb5/krb5i/krb5p flavors actually mount
- mount exports automatically, trying NFSv4.2 → 4.1 → 4 → 3 in cascade
- test selected exports only with repeatable `--export`, or several exports concurrently with `--parallel N`
- benchmark rsize/wsize/nconnect combinations with `--sweep` and suggest mount options
- parse and verify effective mount options from `/proc/self/mountinfo`
- capture RPC stats (retransmissions, auth refreshes) before and after tests
- extract deep latency metrics from `/proc/self/mountstats`
- read NFS server info from `/proc/fs/nfsfs/servers` (protocol version, active mount count)
- run filesystem checks after mount: close-to-open consistency, special files, quotas
- test read/traverse permission, directory listing
- test POSIX ACLs, NFSv4 ACLs, generic xattrs, and SELinux contexts
- test create/write/read/fsync; advanced I/O: `copy_file_range`, `fallocate`, `O_DIRECT`
- test advisory locks with `fcntl`
- detect practical `root_squash` behavior
- simulate UID/GID access with supplemental groups
- run metadata latency benchmark (create/rename/unlink)
- run stale file handle loop looking for `ESTALE`
- test long filenames (255-byte), special characters (spaces, colons, UTF-8 multibyte)
- detect NFSv4 delegation activity via `/proc/self/mountstats` (DELEGRETURN operations)
- check for pNFS layouts via `/proc/self/mountstats`
- run external `fio` benchmarks alongside internal smoke tests
- generate JSON and HTML reports; stream NDJSON; emit Prometheus metrics or JUnit XML
- serve Prometheus metrics continuously over HTTP with `--listen [ADDR:]PORT` (binds 127.0.0.1 by default)
- keep a per-host baseline and compare each run against it with `--diff-baseline`
- emit event categories, stable `check_id` values and remediation text for automation
- write evidence bundles with `--output-dir`
- compare two JSON reports with `nfsdiag diff`
- run local dependency/helper validation with `--self-test`
- run Docker fixture tests for regression checks (14 scenarios)

By default the output is compact. Use `--verbose` to see all probe steps.

---

## Important note

NFS problems are very environment-dependent. Results can change because of firewall rules, server export options, NFS version, kernel client state, UID/GID mapping, root squash, ACLs, SELinux/AppArmor on the server, server load, or stale file handles that only appear during real use.

If the tool says no `ESTALE` happened, it only means the tool did not reproduce it during the test window.

---

## Quick start (OCI image)

No compilation needed:

```sh
docker run --rm --privileged ghcr.io/lsferreira42/nfsdiag 192.168.1.10
```

The image is published to `ghcr.io/lsferreira42/nfsdiag` as `:latest` and `:vX.Y.Z` on each release.

---

## Build requirements

**Debian / Ubuntu:**
```sh
sudo apt-get install -y build-essential pkg-config libtirpc-dev nfs-common
```

**Fedora / RHEL:**
```sh
sudo dnf install -y gcc make pkgconf-pkg-config libtirpc-devel nfs-utils
```

---

## Build

```sh
make                    # build
make check              # unit tests plus CLI self-check
make strict             # build with extra warnings as errors (-Wconversion etc.)
make compile-commands   # generate compile_commands.json (needs 'bear')
make sbom               # minimal SPDX-style SBOM in build/
sudo make install       # install binary, man page and shell completions to /usr/local
```

Override prefix:
```sh
make PREFIX=/opt/nfsdiag install
```

Manual compile:
```sh
gcc -O2 -Wall -Wextra -D_GNU_SOURCE -I/usr/include/tirpc \
    src/main.c src/mount.c src/network.c src/report.c \
    src/rpc.c src/stats.c src/tests.c src/validation.c src/util.c \
    -ltirpc -o nfsdiag
```

---

## Packaging

```sh
make deb        # Debian/Ubuntu .deb → build/
make rpm        # Fedora/RHEL .rpm   → build/
make apk        # Alpine .apk (needs Docker) → build/
make packages   # all three
```

Additional packaging templates live under `packaging/`:

- `packaging/Dockerfile` for the OCI image
- `packaging/homebrew/nfsdiag.rb`
- `packaging/aur/PKGBUILD`
- `flake.nix`

Pre-built binaries (amd64 and arm64), packages, SBOM, checksums and provenance
are attached to GitHub releases.

---

## Basic usage

```sh
sudo ./nfsdiag 192.168.1.10          # full diagnostic
./nfsdiag --verbose 192.168.1.10     # show all steps
./nfsdiag --no-mount 192.168.1.10    # network/RPC only, no mounts
sudo ./nfsdiag --export /data 192.168.1.10   # one export only
sudo ./nfsdiag --read-only 192.168.1.10      # skip write/create tests
sudo ./nfsdiag --dry-run 192.168.1.10        # print what would run, do nothing
./nfsdiag --self-test                         # local dependency/helper checks
```

Profiles provide safer presets:

```sh
sudo ./nfsdiag --profile quick 192.168.1.10
sudo ./nfsdiag --profile safe 192.168.1.10
sudo ./nfsdiag --profile full 192.168.1.10
sudo ./nfsdiag --profile performance 192.168.1.10
sudo ./nfsdiag --profile security 192.168.1.10
```

---

## Output formats

Default output is tagged text (`[OK]`, `[WARN]`, `[FAIL]`, `[INFO]`).

**Summary table** (box-drawing, per-export columns):
```sh
sudo ./nfsdiag --output-format=table 192.168.1.10
```

**Streaming NDJSON** (one JSON object per event — ideal for log pipelines):
```sh
sudo ./nfsdiag --output-format=ndjson 192.168.1.10 | jq 'select(.level=="fail")'
```

**Prometheus / OpenMetrics** (emitted at end of run):
```sh
sudo ./nfsdiag --output-format=prometheus 192.168.1.10
```

---

## JSON and HTML reports

JSON to stdout (diagnostic text suppressed):
```sh
./nfsdiag --json 192.168.1.10
```

JSON to file (diagnostic text still on stdout):
```sh
./nfsdiag --json=report.json 192.168.1.10
```

HTML report:
```sh
./nfsdiag --html=report.html 192.168.1.10
```

Suppress stdout when writing to file:
```sh
./nfsdiag --quiet --json=report.json 192.168.1.10
```

Reports include tool version, host, timestamp, system info, per-export results (NFS version, latency, throughput, ACLs), global events, and recommendations.
The JSON schema includes `schema_version`, `timestamp_iso8601`, `duration_sec`,
event `category`, stable `check_id`, `severity`, and remediation text.

Evidence bundle:
```sh
sudo ./nfsdiag --output-dir ./nfsdiag-report 192.168.1.10
```

This writes JSON, HTML, evidence text and `SHA256SUMS` for the generated files.

Compare two JSON reports:
```sh
./nfsdiag diff before.json after.json
```

---

## Watch mode

Re-run diagnostics every N seconds (Ctrl-C to stop):
```sh
sudo ./nfsdiag --watch 60 192.168.1.10
```

The terminal is cleared between iterations. All pending mounts are cleaned up on SIGINT.

---

## Multi-host batch

Run against a list of hosts:
```sh
sudo ./nfsdiag --hosts-file /etc/nfs-servers.txt --json=audit.json
```

File format: one host per line; lines starting with `#` are comments. Use `--delay-ms` to rate-limit between hosts.

---

## On-failure hook

Execute a script whenever any test fails:
```sh
sudo ./nfsdiag --on-fail-exec /usr/local/bin/alert.sh 192.168.1.10
```

The script receives: `NFSDIAG_HOST`, `NFSDIAG_LEVEL`, `NFSDIAG_FAIL_COUNT`, `NFSDIAG_WARN_COUNT`. It is invoked through a resolved trusted path with a minimal environment, never via a shell.

---

## Config file

Persist options in a key=value file:
```sh
sudo ./nfsdiag --config /etc/nfsdiag.conf 192.168.1.10
```

Example `nfsdiag.conf`:
```ini
timeout = 10
bench_bytes = 8388608
uid = 1000
gid = 1000
```

CLI flags override config-file values.

---

## UID/GID and permission tests

```sh
sudo ./nfsdiag --uid 1000 --gid 1000 192.168.1.10
sudo ./nfsdiag --uid 1000 --gid 1000 --uid 65534 --gid 65534 192.168.1.10
sudo ./nfsdiag --uid 1000 --gid 1000 --groups 10,20,30 192.168.1.10
```

---

## Performance and stale handle tests

```sh
sudo ./nfsdiag --bench-bytes 167772160 192.168.1.10
sudo ./nfsdiag --bench-iterations 500 192.168.1.10
sudo ./nfsdiag --bench-type=fio 192.168.1.10       # requires fio installed
sudo ./nfsdiag --stale-iterations 1000 192.168.1.10
```

---

## Safety options

```sh
sudo ./nfsdiag --command-timeout 15 192.168.1.10
sudo ./nfsdiag --delay-ms 500 192.168.1.10
sudo ./nfsdiag --mount-namespace 192.168.1.10      # explicit namespace
sudo ./nfsdiag --no-mount-namespace 192.168.1.10   # opt out of automatic namespace
sudo ./nfsdiag --dangerous-fs-tests 192.168.1.10   # enable symlink/hardlink/FIFO/device probes
sudo ./nfsdiag --allow-risky-mount-options -o exec 192.168.1.10
```

---

## Network/protocol options

```sh
./nfsdiag --no-mount --udp 192.168.1.10
./nfsdiag --ipv4-only --no-mount 192.168.1.10
./nfsdiag --ipv6-only --no-mount nfs-server.example.com
sudo ./nfsdiag --no-nfs4-discovery 192.168.1.10
```

---

## Shell completions

`sudo make install` already places the bash, zsh, and fish completions. To load them without installing, source them manually:
```sh
source completions/nfsdiag.bash          # bash
fpath=(completions $fpath)               # zsh (add to .zshrc before compinit)
cp completions/nfsdiag.fish ~/.config/fish/completions/
```

---

## Man page

```sh
man docs/nfsdiag.8           # view locally
```

`sudo make install` installs the man page to the system man path.

---

## Command line reference

```text
Usage: nfsdiag [OPTIONS] <server-ip-or-hostname>
       nfsdiag diff <before.json> <after.json>   Compare two JSON reports

Diagnostic options:
  -e, --export PATH          Test only this export path (repeatable, up to 64)
  -o, --mount-options OPTS   Extra mount options passed to mount(8)
      --no-mount             Run network/RPC checks only; skip all mounts
      --dry-run              Print what would be done; skip mounts and fs tests
      --read-only            Do not create or write test files
      --uid UID              Simulate access as UID (repeatable, needs root)
      --gid GID              GID paired with last --uid
      --groups G1,G2         Supplemental GIDs for UID/GID simulation
      --krb5                 Check Kerberos prerequisites and test sec=krb5/krb5i/krb5p mounts
      --parallel N           Test up to N exports concurrently (1-32). Default: 1
      --sweep                Benchmark rsize/wsize/nconnect combos and suggest mount options
      --diff-baseline        Compare with the last saved run for this host, then update it
      --udp                  Also probe RPC NULLPROC over UDP
      --ipv4-only            Force IPv4 for direct TCP checks
      --ipv6-only            Force IPv6 for direct TCP checks
      --no-nfs4-discovery    Disable NFSv4 pseudo-root fallback
      --mount-namespace      Use private mount namespace (needs root/CAP_SYS_ADMIN)
      --no-mount-namespace   Disable automatic private mount namespace
      --dangerous-fs-tests   Enable symlink/hardlink/FIFO/device-node probes (alias: --deep)
      --allow-risky-mount-options
                              Permit risky mount options such as exec/suid/dev
                              and skip the default nosuid,nodev,noexec hardening
      --profile NAME         quick, safe, full, performance, security, readonly
      --hosts-file FILE      Read one host per line from FILE
      --watch SEC            Re-run diagnostics every SEC seconds until Ctrl-C
      --on-fail-exec SCRIPT  Execute SCRIPT via trusted path when any test fails
      --config FILE          Load options from FILE (key=value) before CLI args

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
      --output-dir DIR       Write JSON, HTML, evidence and checksums to DIR
      --output-format FMT    Terminal output format: text (default), table, ndjson, prometheus, junit
      --listen [ADDR:]PORT   Serve Prometheus metrics over HTTP; binds 127.0.0.1
                              unless ADDR is given ([V6ADDR]:PORT for IPv6);
                              re-runs diagnostics every --watch SEC (default 60)
      --keep-temp            Keep temp workspace after tests
  -v, --verbose              Show all diagnostic steps
  -q, --quiet                Suppress stdout (combine with --json=FILE or --html=FILE)
  -V, --version              Print version and exit
      --self-test            Validate local dependencies and helper checks
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

Warnings return `1` because in automation they usually need attention. The code
reflects the highest severity across the whole run and is the same regardless of
output format. With `--no-mount` only the network/RPC/export checks count; with
`--parallel` every worker's results are merged first. `nfsdiag diff` returns `1`
when the second report has more warnings or failures than the first.

---

## Docker fixtures

The project has Docker fixtures to reproduce bad NFS situations.

```sh
make docker-build-all          # build all fixture images
make test-fixtures             # run all fixture tests
make test-fixture-root-squash  # run one fixture
make test-fixtures-list        # list available fixtures
```

Some tests need root for real kernel NFS mounts. If the host kernel cannot run NFS inside Docker, those cases are skipped.

> **Warning:** fixture configurations use wildcard clients, `insecure`, and `no_root_squash` intentionally.
> These settings are **test-only** and must **never** be used in production.

Available fixtures: `rpcbind-unreachable`, `nfs-port-unreachable`, `rpc-map-missing-nfs`,
`mountd-unavailable`, `empty-exports`, `mount-denied`, `permission-denied`, `acl-unsupported`,
`identity-denied`, `read-only-export`, `root-squash`, `locking-missing`, `stale-handle`, `slow-performance`.

---

## Security notes

`nfsdiag` is designed to run as root. Key mitigations:

- **Non-destructive by default:** nfsdiag only creates and removes its own
  uniquely-named test files (random component + `O_CREAT|O_EXCL`); it never
  reads, modifies, or deletes pre-existing data in an export. `--read-only`,
  `--dry-run`, and the `safe`/`readonly` profiles skip writing entirely.
- **Default mount options:** exports are mounted `vers=<n>,nosuid,nodev,noexec`.
  The hardening flags block setuid binaries, device nodes, and execution from an
  untrusted server; disable them only with `--allow-risky-mount-options`.
  `timeo`/`retrans` are left at kernel defaults and the mount stays `hard`
  (a user-supplied `soft` is warned about) — hangs are bounded by a killable
  per-export worker and `--command-timeout` instead of risking I/O errors on a
  `soft` mount. nfsdiag does not force `ro`, because it tests writes by design;
  use `--read-only` to skip all writes.
- Mount operations run in a private mount namespace to avoid polluting the global namespace.
- Host, export path and mount options are validated before network or mount activity.
- Risky mount options require `--allow-risky-mount-options`.
- Identity simulation always resets supplemental groups so results reflect the simulated user, not root.
- `--on-fail-exec` scripts and `--config` files are refused if not owned by root/current user or if group/world-writable.
- Output from external commands is sanitised for terminal escape sequences before display.
- Symlink, hardlink, FIFO and device-node probes require `--dangerous-fs-tests`.
- External commands are resolved from trusted directories and run with a minimal environment.
- Report files are created with `O_NOFOLLOW` and mode `0600`.
- Test file paths include cryptographically random bytes (`getrandom()`) to prevent symlink attacks.
- XDR strings from the server are sanitised for control characters before display.
- HTML reports include a Content-Security-Policy header; all server-supplied strings are HTML-escaped.
- `TMPDIR` is validated for ownership and world-writability before use.
- Child processes that simulate UID/GID clear ambient capabilities before `setuid()`.

To avoid creating test files in exports, use `--read-only`.

---

## Version bumping

```sh
make bump-version-bugfix   # 0.5.0 → 0.5.1
make bump-version-minor    # 0.5.0 → 0.6.0
make bump-version-major    # 0.5.0 → 1.0.0
```

Each target updates `VERSION`, `src/nfsdiag.h`, and all packaging files atomically.

---

## Limitations

- `ESTALE` only appears if the handle becomes stale during the test window
- SELinux/AppArmor problems can look like generic permission denied
- ACL info depends on what the NFS client exposes
- Performance numbers are smoke-test values, not full benchmarks
- Docker fixture tests depend on host kernel and Docker privileges
- The `--listen` Prometheus exporter has no authentication or TLS; it binds
  `127.0.0.1` by default and should only be exposed behind a trusted network
  or reverse proxy

---

## Support policy

- **Scope:** Linux only. `nfsdiag` parses `/proc/self/mountstats`,
  `/proc/self/mountinfo`, `/proc/net/rpc/nfs` and `/proc/fs/nfsfs/servers` and
  drives `mount.nfs`, so it does not run on macOS or BSD.
- **Architectures:** prebuilt binaries and packages are published for `amd64`
  and `arm64`. Other architectures can build from source.
- **Distributions:** built and CI-tested on Ubuntu LTS, Debian, Fedora and
  Alpine (glibc and musl). Packaged for Debian/Ubuntu (`.deb`), Fedora/RHEL
  (`.rpm`), Alpine (`.apk`), Arch (AUR) and Nix; the Homebrew formula targets
  Linuxbrew.
- **Runtime requirements:** `nfs-utils`/`nfs-common` (for `mount.nfs`),
  `rpcbind` on the server side for NFSv3 discovery, and `libtirpc`. Full mount
  diagnostics need root (or `CAP_SYS_ADMIN`); `--no-mount`, `--self-test`,
  `--help` and `--version` work as an unprivileged user.
- **JSON stability:** the `--json` output follows the schema in
  [docs/nfsdiag.schema.json](docs/nfsdiag.schema.json); see
  [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) for the 1.x stability rules.

### Supported platform matrix

| Platform | Arch | Package | CI |
|----------|------|---------|----|
| Ubuntu LTS / Debian | amd64, arm64 | `.deb` | build + install smoke |
| Fedora / RHEL-like | amd64, arm64 | `.rpm` | build + install smoke |
| Alpine (musl) | amd64 | `.apk` | build + install smoke |
| Arch Linux | amd64 | AUR `PKGBUILD` | makepkg + namcap |
| Any with Nix | amd64 | `flake.nix` | `nix flake check` |
| Linuxbrew | amd64, arm64 | `packaging/homebrew` | — |

macOS and BSD are not supported (Linux `/proc` and `mount.nfs` are required).
Minimum toolchain: a C11 compiler, `libtirpc`, and a kernel new enough to expose
`/proc/self/mountstats`.

---

## Benchmark scope

The `--bench-*` options run a small write+fsync / cache-dropped read and a
metadata-latency loop. They are a **smoke test from this client**, not a
capacity benchmark: results depend on cache, sync behaviour, network, server
load, and mount options. The default sample is 4 MiB (`--bench-bytes`) over a
few iterations (`--bench-iterations`, `--stale-iterations`); a warning is
emitted when the sample is too small to be meaningful. Set
`--bench-iterations 0` to skip throughput/latency entirely, or `--read-only` to
mount without writing. For real performance baselines, use `fio`
(`--bench-type=fio`) or a dedicated benchmark and treat nfsdiag's numbers as a
reachability/sanity signal.

---

## Project files

- [LICENSE](LICENSE) — MIT.
- [SECURITY.md](SECURITY.md) — how to report a vulnerability; verifying downloads.
- [CHANGELOG.md](CHANGELOG.md) — release history.
- [CONTRIBUTING.md](CONTRIBUTING.md) — build, test and release workflow.
- [docs/nfsdiag.8](docs/nfsdiag.8) — man page.
- [docs/nfsdiag.schema.json](docs/nfsdiag.schema.json) — JSON report schema.
- [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) — 1.x stability policy.
- [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) — adversary model and mitigations.
- [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md) — CI, Prometheus, JUnit, `--diff` recipes.
