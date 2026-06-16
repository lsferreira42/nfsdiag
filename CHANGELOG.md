# Changelog

All notable changes to nfsdiag are documented in this file. This is the
canonical changelog; `website/docs.html#changelog` mirrors it.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.10.1] - 2026-06-16

### Changed
- Trimmed the CI to the build, static-analysis, sanitizer, fuzz, rootless
  fixture, output-format, CodeQL, and coverage jobs.

## [0.10.0] - 2026-06-12

Pre-1.0 hardening release: project governance files, packaging completeness,
release-pipeline automation, machine-output correctness, and a much larger
CI gate.

### Added
- `LICENSE` (MIT), `SECURITY.md` (vulnerability reporting policy), and this
  `CHANGELOG.md`.
- `nfsdiag diff` subcommand is now documented in `--help`.
- `--listen` accepts an optional bind address: `--listen [ADDR:]PORT`
  (IPv6 literals in brackets: `--listen [::1]:9100`).

- deb/rpm/apk packages now ship the man page, bash/zsh/fish completions, and
  the license file alongside the binary; the OCI image carries OCI labels,
  the license, and the man page.
- CI: cppcheck reinstated, ASan/UBSan + valgrind job, fuzz smoke run,
  shellcheck, machine-output validation (jq/xmllint), privileged fixture job,
  coverage artifact, version-consistency and CLI/docs-parity checks
  (`tests/check-versions.sh`, `tests/check-cli-docs.sh`).
- Release artifacts get signed Sigstore provenance attestations
  (`gh attestation verify`); GitHub Actions pinned by commit SHA with
  dependabot updates.

### Changed
- `--listen` now binds to `127.0.0.1` by default instead of all interfaces.
  Use `--listen 0.0.0.0:PORT` (or another address) to expose the exporter.
- `--deep` alias for `--dangerous-fs-tests` is now documented.
- `make release` only validates and pushes the tag; the release workflow is
  the single publisher of artifacts. `make update-release-checksums` refreshes
  the Homebrew/AUR tarball sha256 after the tag exists.
- The Nix flake moved to the repository root (`flake.nix`) and now builds in
  pure evaluation mode (`src = self`, `PREFIX` via `placeholder`).
- Parser error messages now include the valid range
  (e.g. `invalid --timeout: 0 (1-3600 seconds)`).

### Fixed
- The XDR exports fuzz harness now exercises the real `xdr_exports_type`
  decoder from `src/rpc.c` (including the `XDR_FREE` path) instead of a
  divergent copy, and runs leak-clean under libFuzzer+ASan.
- Machine-readable outputs are now clean: the `nfsdiag <version>: <host>`
  banner and the `summary:` line no longer leak into `--json=-`,
  `--output-format ndjson/prometheus/junit` streams (they corrupted JSON,
  NDJSON, and JUnit XML parsers).
- Numeric arguments no longer accept negative values via `strtoul` wrap
  (`timeout=-1` in a config file used to become 4294967295).
- `validate_mount_options` now actually rejects empty tokens (`hard,,soft`);
  the previous check was unreachable.
- glibc `warn_unused_result` build failures with `-Werror` on newer GCC
  (`(void)read/write` casts replaced with explicit checks).
- cppcheck false-positive `doubleFree` findings around `fdopen()` failure
  paths suppressed inline; analysis is version-stable again.

## [0.9.0] - 2026-06-10

Feature release: parallel export testing, mount option sweep, Kerberos flavor
probing, JUnit output, embedded Prometheus exporter, baseline comparison,
deeper network diagnostics, server fingerprinting, and native IPv6 rpcbind —
on top of security hardening and correctness fixes.

### Added
- `--export` is repeatable (up to 64 paths) to test a chosen subset of exports.
- `--parallel N` — test up to 32 exports concurrently in forked workers,
  results merged into the normal reports.
- `--sweep` — benchmark rsize/wsize/nconnect combinations on a working export
  and recommend the best mount options (also enabled by `--profile performance`).
- `--krb5` also mounts with `sec=krb5`, `krb5i`, and `krb5p` to report which
  flavors the server accepts.
- `--output-format junit` — JUnit XML for CI pipelines (fail → failure,
  warn → skipped).
- `--listen PORT` — embedded HTTP exporter serving Prometheus metrics,
  refreshing diagnostics every `--watch` seconds.
- `--diff-baseline` — per-host baseline under `~/.local/share/nfsdiag`,
  reporting regressions against the previous run.
- Network checks measure TCP connect latency and path MTU, and verify
  reachability of dynamically registered mountd/lockd/statd ports.
- Heuristic server implementation fingerprint from the RPC service layout
  (knfsd-style, NFSv4-only, fixed-port appliance, v3-only).
- rpcbind v3/v4 DUMP support: full service map with real ports over IPv6,
  replacing blind program probing when available.

### Security
- Exports are mounted with `nosuid,nodev,noexec` by default;
  `--allow-risky-mount-options` disables the hardening.
- Identity simulation always resets supplemental groups before `setuid()`.
- Evidence and SHA256SUMS files in `--output-dir` are created with
  `O_NOFOLLOW` and mode 0600.
- Output captured from external commands is sanitised for terminal escape
  sequences before display.
- `--on-fail-exec` and `--config` refuse files not owned by root/current user
  or writable by group/others.
- Benchmark test file is created with `O_EXCL` (hardlink pre-creation window
  closed); random test paths fall back to `/dev/urandom` before the weak
  time/pid fallback.
- Mount-options values are redacted from the argv recorded in the evidence
  file.
- `--output-dir` permission fix-up uses `open(O_DIRECTORY|O_NOFOLLOW)` +
  `fchmod` (TOCTOU removed).

### Fixed
- Export/group XDR lists are decoded iteratively — servers with more than ~32
  exports no longer fail enumeration; node budgets still bound allocations.
- `--config=FILE` (equals form) is recognised.
- Partially decoded export lists are freed when the mountd EXPORT call fails.
- Read benchmark drops the client page cache before reading back; if the
  cache cannot be dropped the result is labelled.
- Filesystem-timeout disarm no longer touches an uninitialised sigaction.
- Colour output re-evaluated per line (watch/hosts-file modes after stdout
  redirection).
- `nfsdiag diff` reads whole reports instead of truncating at 64 KiB; summary
  parsing is anchored to the summary object.
- Metadata latency test files use the same randomised naming as other tests.
- DNS failures report the real `getaddrinfo` error per port.
- Config-supplied bench-type/output-dir strings no longer leak on reload.

## [0.8.0] - skipped

Version number 0.8.0 was skipped; no release carries it.

## [0.7.0] - 2026-06-09

Maintenance release: fixture, wording, and robustness fixes. No new features.

### Fixed
- Docker fixture images (`read-only-export`, `rpcbind-unreachable`) and the
  kernel NFS entrypoint hardened; fixture docs updated.
- Wording and message consistency across modules.
- Minor robustness fixes in mount handling, report generation, and stats
  parsing.
- CI workflow cleanup; `make bump-packaging` extended to cover the website.

## [0.6.1] - 2026-06-08

Release tooling: `make release` publishes every artifact it can build.

### Added
- `make release` uploads the standalone binary, SBOM, and a SHA256SUMS file
  alongside the deb/rpm/apk packages.
- `make binary-dist` stages a versioned, arch-named binary in `build/`.
- `make packages` also produces the standalone binary.

## [0.6.0] - 2026-06-08

Correctness release.

### Fixed
- NFSv4 delegation detection rewritten to read DELEGRETURN activity from
  `/proc/self/mountstats` (the previous `/proc/fs/nfsfs/volumes` match never
  fired).
- `/proc/fs/nfsfs/servers` parsing fixed to the real
  `NV SERVER PORT USE HOSTNAME` format.
- Per-export status in HTML/table reports reflects each export's own events
  instead of the global counters.
- Prometheus output emits each `# HELP`/`# TYPE` once.
- All filesystem probes run under the `--fs-timeout` guard.
- `--hosts-file` warns when a positional host is also supplied and ignored.
- `--export` path allocation failure handled.
- Watch-mode banner text corrected.

## [0.5.0] - 2026-06-07

Major feature release.

### Added
- `--output-format table/ndjson/prometheus` terminal output modes.
- `--watch SEC` continuous monitoring with clean SIGINT handling.
- `--hosts-file FILE` batch diagnostics across a fleet.
- `--on-fail-exec SCRIPT` execvp-based failure hook.
- `--config FILE` persistent key=value configuration.
- Long filename test (255-byte names, spaces, colons, UTF-8 multibyte).
- NFSv4 delegation detection; `/proc/fs/nfsfs/servers` parsing.
- OCI image at `ghcr.io/lsferreira42/nfsdiag`.
- Shell completions (bash/zsh/fish) and man page `docs/nfsdiag.8`.
- CI matrix (Ubuntu 24.04, Fedora 41, Debian 12, Alpine 3.21), ASan+UBSan
  job, cppcheck and clang-tidy jobs, linux-arm64 release binary, fuzzer
  stubs, `make coverage`.

### Security
- `getrandom()` random test paths, ambient capability clearing, XDR depth
  limit, TMPDIR validation, HTML CSP header.
- `cleanup_all()` async-signal-safety fix.

## [0.4.1] - 2026-06-05

Website and CI/CD infrastructure; no changes to diagnostic behaviour
(www.nfsdiag.org, Cloudflare Workers deploy workflow, `make clean` fix).

## [0.3.0] - 2026-06-04

Packaging and release infrastructure: `make deb/rpm/apk`, `make release`,
`make bump-version-*`, release workflow on `v*` tags, `VERSION` file as the
single source of truth.

## [0.2.0] - 2026-06-03

Security, behavioural, and reliability fixes.

### Security
- `strdup()` returns checked in `add_event()`/`add_recommendation()`.
- Report files opened with `O_NOFOLLOW|O_CREAT|0600`.
- XDR string limits for export paths (4096 B) and group names (256 B).
- fio benchmarks use execvp argv arrays instead of `sh -c`.
- Numeric CLI arguments reject empty strings.

### Fixed
- `--json=file` no longer suppresses stdout (use `--quiet`); `--html=-`
  suppresses diagnostic text correctly.
- `--dry-run` no longer runs filesystem diagnostics.
- Write/read benchmark, advisory lock, and root_squash split into independent
  tests with separate timeouts.
- mountd v2 tried between v3 and v1; IPv6 literals bracketed in mount source.
- Pipe drain continues into a discard buffer when the output buffer is full.
- `dup2()`/`sscanf()` returns checked; RPC counter wrap detected;
  `clnt_create()`/`pmap_getmaps()` under SIGALRM timeout.
- Exact token matching for mount options and mountstats sections.
- Signal handlers installed without `SA_RESTART`.
- All 14 fixtures in `ALL_FIXTURES`; test runner uses `mktemp`; `TMPDIR`
  respected; client daemon checks degrade gracefully on non-systemd systems.

### Added
- `-V, --version`; CLI options reorganised into logical groups.

## [0.1.0] - 2026-06-02

Initial public release.
