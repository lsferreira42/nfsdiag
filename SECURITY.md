# Security Policy

nfsdiag is typically run as root and mounts remote filesystems, so security
reports are taken seriously and handled with priority.

## Supported versions

| Version | Supported |
|---------|-----------|
| latest release | yes |
| older releases | no — please upgrade to the latest release first |

## Reporting a vulnerability

**Do not open a public GitHub issue for security problems.**

Report vulnerabilities through one of these channels:

1. **GitHub private vulnerability reporting** (preferred):
   [github.com/lsferreira42/nfsdiag/security/advisories/new](https://github.com/lsferreira42/nfsdiag/security/advisories/new)
2. **Email**: leandrodsferreira@gmail.com — put `[nfsdiag security]` in the
   subject line.

Please include: the version (`nfsdiag --version`), the platform, a minimal
reproduction, and the impact you believe it has (e.g. privilege escalation,
information disclosure, denial of service against the client).

## What to expect

- **Acknowledgement** within 7 days.
- **Assessment and fix plan** within 30 days for confirmed issues.
- Fixes ship as a new release; the advisory is published after the release is
  available. You will be credited unless you ask not to be.

## Verifying downloads

Every release attaches `SHA256SUMS`, a source-level SBOM (`*.spdx.json`, scope
described in `SBOM-SCOPE.txt`), and signed Sigstore build-provenance
attestations for the binaries and packages.

```sh
# Checksums
sha256sum -c SHA256SUMS

# Signed provenance (needs the GitHub CLI)
gh attestation verify nfsdiag-linux-amd64 --repo lsferreira42/nfsdiag
```

A post-publish CI job re-downloads the published binary, checks its checksum,
runs `--self-test`, and verifies the attestation, so a broken release fails
visibly.

## Scope

In scope:

- Anything reachable by a **malicious or compromised NFS server** (RPC/XDR
  parsing, export enumeration, mount handling, output rendering of
  server-controlled strings).
- Local privilege issues when nfsdiag runs as root (symlink following,
  predictable temp paths, unsafe report/evidence file handling, hook and
  config file execution).
- The published packages, container image, and release pipeline.

Out of scope:

- Vulnerabilities in the NFS servers being diagnosed.
- Issues that require an already-root local attacker.
- The website (static content), unless it affects the integrity of downloads
  or documentation that drives unsafe behaviour.
