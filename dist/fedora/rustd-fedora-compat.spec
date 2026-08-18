Name:           rustd-fedora-compat
Version:        0.1.2
Release:        1%{?dist}
Summary:        Fedora RPM transaction compatibility frontends backed by RustD
License:        LGPL-2.1-or-later
URL:            https://github.com/SisyphusAeolides/rustd
Source0:        rustd-%{version}.tar.gz

BuildRequires:  bash
Requires:       rustd%{?_isa} = %{version}-%{release}
Conflicts:      systemd
Conflicts:      systemd-udev

%description
Fedora transaction compatibility entry points for RPM scriptlets and existing
packaging conventions. Every service-manager operation is delegated to RustD's
native tools. This package deliberately does not declare Provides: systemd;
Fedora's cutover preflight must prove that no unresolved package-level systemd
consumer remains before the systemd RPM is removed.

%prep
%autosetup -n rustd-%{version}

%build
# Shell frontends are architecture-independent source, but this RPM is kept on
# the native architecture because it has an exact-version dependency on RustD.
for file in dist/fedora/compat/*; do
    bash -n "$file"
done

%check
bash tests/fedora-transaction-compat.sh

%install
install -d %{buildroot}%{_bindir} %{buildroot}%{_prefix}/lib/systemd
install -m0755 dist/fedora/compat/systemctl %{buildroot}%{_bindir}/systemctl
install -m0755 dist/fedora/compat/systemd-tmpfiles %{buildroot}%{_bindir}/systemd-tmpfiles
install -m0755 dist/fedora/compat/systemd-sysusers %{buildroot}%{_bindir}/systemd-sysusers
install -m0755 dist/fedora/compat/udevadm %{buildroot}%{_bindir}/udevadm
install -m0755 dist/fedora/compat/systemd-update-helper %{buildroot}%{_prefix}/lib/systemd/systemd-update-helper
install -m0755 dist/fedora/compat/systemd-sysctl %{buildroot}%{_prefix}/lib/systemd/systemd-sysctl
install -m0755 dist/fedora/compat/systemd-binfmt %{buildroot}%{_prefix}/lib/systemd/systemd-binfmt

%files
%license LICENSE*
%{_bindir}/systemctl
%{_bindir}/systemd-tmpfiles
%{_bindir}/systemd-sysusers
%{_bindir}/udevadm
%{_prefix}/lib/systemd/systemd-update-helper
%{_prefix}/lib/systemd/systemd-sysctl
%{_prefix}/lib/systemd/systemd-binfmt

%changelog
* Tue Aug 18 2026 Kenny Glowner <SisyphusAeolides@pm.me> - 0.1.2-1
- Package Fedora transaction compatibility frontends backed by RustD
