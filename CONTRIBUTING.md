# Contributing to nfsdiag

Thanks for helping improve nfsdiag. This project is a C command-line tool that
can run as root and mount NFS exports, so correctness and safety matter.

## Development

```sh
make rebuild
make check
```

Use focused changes. Keep diagnostics conservative by default and require an
explicit flag for probes that create unusual filesystem objects or change risk.

## Tests

- `make check` runs unit tests and a local self-test.
- `make test-fixtures` runs Docker-based NFS failure fixtures.
- `tests/fuzz/` contains fuzz harnesses for parser-style code.

When changing parser, report, mount, or RPC behavior, add a targeted unit,
fixture, or fuzz regression where practical.

## Pull Requests

Include:

- What changed.
- Why it is safe.
- How it was tested.
- Any compatibility impact for CLI flags, JSON schema, packages, or reports.
