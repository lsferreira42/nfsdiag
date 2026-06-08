Name:           nfsdiag
Version:        0.6.1
Release:        1%{?dist}
Summary:        NFS diagnostic tool

License:        MIT
URL:            https://github.com/lsferreira42/nfsdiag

BuildRequires:  make, gcc, pkgconf, libtirpc-devel
Requires:       libtirpc
Suggests:       nfs-utils

%description
nfsdiag is a command-line NFS diagnostic tool. It tests NFS servers from the
client side, identifying network, RPC, protocol, permission, authentication,
and performance issues across multiple exports.

%install
mkdir -p %{buildroot}/usr/bin
install -m 755 %{srcdir}/nfsdiag %{buildroot}/usr/bin/nfsdiag

%files
/usr/bin/nfsdiag

%changelog
* Sun Jun 07 2026 Leandro Ferreira <leandrodsferreira@gmail.com> - 0.6.1-1
- make release now publishes the standalone binary, SBOM, and checksums alongside packages
* Sun Jun 07 2026 Leandro Ferreira <leandrodsferreira@gmail.com> - 0.6.0-1
- Fixed delegation/server-info detection, per-export status, Prometheus output, and fs-test timeouts
* Sun Jun 07 2026 Leandro Ferreira <leandrodsferreira@gmail.com> - 0.5.0-1
- Hardened diagnostics, richer reports, completions, man page, and CI checks
