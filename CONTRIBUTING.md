# Contributing to nfsdiag

Thanks for helping improve nfsdiag. This project is a C command-line tool that
can run as root and mount NFS exports, so correctness and safety matter.

## Building

Install the build dependencies (see README "Build requirements"), then:

```sh
make rebuild     # full build
make check       # unit tests + CLI self-check
```

Before opening a PR, run the aggregate gate (build + tests + static analysis +
shell lint):

```sh
make release-check
```

It expands to the warnings-as-errors build, `make check`, `make cppcheck` and
`make shellcheck`. `make check` itself runs the unit tests plus these oracles,
which you can also run individually:

```sh
sh tests/check-versions.sh        # version strings agree across the tree
sh tests/check-json-schema.sh     # JSON report matches docs/nfsdiag.schema.json
sh tests/check-output-golden.sh   # JSON/NDJSON/JUnit/Prometheus agree on counters
sh tests/check-cli-docs.sh        # --help mirrored in README, man, website, completions
sh tests/check-website.sh         # website HTML + internal links
sh tests/check-signals.sh         # SIGINT/SIGTERM handling and post-run cleanup
```

Use focused changes. Keep diagnostics conservative by default and require an
explicit flag for probes that create unusual filesystem objects or change risk.

## Tests

- `make check` runs the unit tests (`tests/unit-tests.c`), the consistency
  oracles above, and a local self-test.
- `make test-fixtures` runs the 14 Docker failure fixtures. Ten of them mount
  real NFS exports and need root on the host plus the `nfs`/`nfsd` kernel
  modules: `sudo modprobe nfs nfsd && sudo make test-fixtures`. The runner
  skips scenarios the host cannot support, asserts the expected exit code, that
  the JSON stream is clean, and that no temp files are left in the export. To
  reproduce one scenario by hand, build its image and run nfsdiag against it:
  `make docker-build-root-squash && sudo make test-fixture-root-squash`.
- `make -C tests/fuzz run-all` builds the libFuzzer harnesses (clang required)
  and runs each for 5 seconds — the same smoke run CI does. The harnesses drive
  the real production parsers. Knobs: `FUZZ_SANITIZERS` (default `address`; set
  `address,undefined` locally, or empty under ptrace/sandboxes where
  LeakSanitizer aborts) and `FUZZ_RUNS` (default `-max_total_time=5`).

When changing parser, report, mount, or RPC behavior, add a targeted unit,
fixture, or fuzz regression where practical.

## Security and safety

- Diagnostics are non-destructive by default in the sense that nfsdiag only
  creates and removes its own uniquely-named files; it never modifies
  pre-existing data. Anything that writes inside an export must keep that
  property (random name + `O_CREAT|O_EXCL`), or be gated behind an explicit
  flag. `--read-only`/`--dry-run` and the `safe`/`readonly` profiles must keep
  the export untouched.
- See `docs/THREAT-MODEL.md` for the adversary model and `SECURITY.md` for
  reporting. Changes to RPC/XDR parsing, mount handling, or rendering of
  server-controlled strings deserve a fuzz or unit regression.

## CLI and documentation rules

`--help` (the `usage()` function in `src/main.c`) is the source of truth for
the CLI. Any flag you add or change must also land in: `README.md` (command
line reference), `docs/nfsdiag.8`, `website/docs.html` (`#cli` table), and the
three completions in `completions/`. `tests/check-cli-docs.sh` verifies this.

## Versioning and changelog

- `VERSION` is the single source of truth; `make bump-version-{bugfix,minor,major}`
  bumps it and propagates it everywhere (`make bump-packaging`). Never edit
  version strings by hand.
- Document user-visible changes under `[Unreleased]` in `CHANGELOG.md` and
  mirror release entries in `website/docs.html#changelog`.

## Releases (maintainer)

1. `make bump-version-minor` (or bugfix/major), review, commit.
2. `make release` — validates the tree and pushes the `vX.Y.Z` tag; the GitHub
   release workflow builds and publishes all artifacts.
3. After the release exists: `make update-release-checksums`, commit the
   Homebrew formula and PKGBUILD.

## Pull Requests

Include:

- What changed.
- Why it is safe.
- How it was tested.
- Any compatibility impact for CLI flags, JSON schema, packages, or reports.

## Security issues

Do not open public issues for vulnerabilities — see [SECURITY.md](SECURITY.md).
