# Contributing to nfsdiag

Thanks for helping improve nfsdiag. This project is a C command-line tool that
can run as root and mount NFS exports, so correctness and safety matter.

## Building

Install the build dependencies (see README "Build requirements"), then:

```sh
make rebuild     # full build
make check       # unit tests + CLI self-check
```

Before opening a PR, make sure the same gates CI runs pass locally:

```sh
make "CFLAGS=-O2 -Wall -Wextra -Werror" rebuild   # warnings are errors
make cppcheck                                      # static analysis
sh tests/check-versions.sh                         # version strings agree
sh tests/check-cli-docs.sh                         # --help mirrored in docs
shellcheck tests/*.sh dockerfiles/common/*.sh      # shell scripts
```

Use focused changes. Keep diagnostics conservative by default and require an
explicit flag for probes that create unusual filesystem objects or change risk.

## Tests

- `make check` runs unit tests (`tests/unit-tests.c`) and a local self-test.
- `make test-fixtures` runs the 14 Docker failure fixtures. Ten of them mount
  real NFS exports and need root on the host plus the `nfs`/`nfsd` kernel
  modules: `sudo modprobe nfs nfsd && sudo make test-fixtures`. The runner
  skips scenarios the host cannot support.
- `make -C tests/fuzz run-all` builds the libFuzzer harnesses (clang required)
  and runs each for 5 seconds — the same smoke run CI does.

When changing parser, report, mount, or RPC behavior, add a targeted unit,
fixture, or fuzz regression where practical.

## CLI and documentation rules

`--help` (the `usage()` function in `src/main.c`) is the source of truth for
the CLI. Any flag you add or change must also land in: `README.md` (command
line reference), `docs/nfsdiag.8`, `website/docs.html` (`#cli` table), and the
three completions in `completions/`. CI enforces this with
`tests/check-cli-docs.sh`.

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
