Name:           nfsdiag
Version:        0.10.0
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
mkdir -p %{buildroot}%{_mandir}/man8
install -m 644 %{srcdir}/docs/nfsdiag.8 %{buildroot}%{_mandir}/man8/nfsdiag.8
mkdir -p %{buildroot}%{_datadir}/bash-completion/completions
install -m 644 %{srcdir}/completions/nfsdiag.bash %{buildroot}%{_datadir}/bash-completion/completions/nfsdiag
mkdir -p %{buildroot}%{_datadir}/zsh/site-functions
install -m 644 %{srcdir}/completions/nfsdiag.zsh %{buildroot}%{_datadir}/zsh/site-functions/_nfsdiag
mkdir -p %{buildroot}%{_datadir}/fish/vendor_completions.d
install -m 644 %{srcdir}/completions/nfsdiag.fish %{buildroot}%{_datadir}/fish/vendor_completions.d/nfsdiag.fish
install -D -m 644 %{srcdir}/LICENSE %{buildroot}%{_defaultlicensedir}/nfsdiag/LICENSE

%files
/usr/bin/nfsdiag
%{_mandir}/man8/nfsdiag.8*
%{_datadir}/bash-completion/completions/nfsdiag
%{_datadir}/zsh/site-functions/_nfsdiag
%{_datadir}/fish/vendor_completions.d/nfsdiag.fish
%license %{_defaultlicensedir}/nfsdiag/LICENSE

%changelog
* Fri Jun 12 2026 Leandro Ferreira <leandrodsferreira@gmail.com> - 0.10.0-1
- See CHANGELOG.md for details
* Wed Jun 10 2026 Leandro Ferreira <leandrodsferreira@gmail.com> - 0.9.0-1
- Parallel export testing, mount option sweep, krb5 flavor probing, JUnit output, embedded Prometheus exporter, baseline diff, and security hardening
* Tue Jun 09 2026 Leandro Ferreira <leandrodsferreira@gmail.com> - 0.7.0-1
- Fixture, wording, and robustness fixes (0.8.0 was skipped; no release carries it)
* Sun Jun 07 2026 Leandro Ferreira <leandrodsferreira@gmail.com> - 0.6.1-1
- make release now publishes the standalone binary, SBOM, and checksums alongside packages
* Sun Jun 07 2026 Leandro Ferreira <leandrodsferreira@gmail.com> - 0.6.0-1
- Fixed delegation/server-info detection, per-export status, Prometheus output, and fs-test timeouts
* Sun Jun 07 2026 Leandro Ferreira <leandrodsferreira@gmail.com> - 0.5.0-1
- Hardened diagnostics, richer reports, completions, man page, and CI checks
