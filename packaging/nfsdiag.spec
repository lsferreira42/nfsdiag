Name:           nfsdiag
Version:        0.4.1
Release:        1%{?dist}
Summary:        NFS diagnostic tool

License:        MIT
URL:            https://github.com/lsferreira42/nfsdiag

BuildRequires:  make, gcc, pkgconf, libtirpc-devel
Requires:       libtirpc
Suggests:       nfs-utils

%description
nfs-doctor (nfsdiag) is a command-line NFS diagnostic tool. It tests NFS
servers from the client side, identifying network, RPC, protocol, permission,
and performance issues across multiple exports.

%install
mkdir -p %{buildroot}/usr/bin
install -m 755 %{srcdir}/nfsdiag %{buildroot}/usr/bin/nfsdiag

%files
/usr/bin/nfsdiag

%changelog
* Wed May 20 2026 Leandro Ferreira <leandrodsferreira@gmail.com> - 0.2.0-1
- Initial release
