%{!?systemd_compat_evr:%global systemd_compat_evr 0:0-0}

Name:           rustd-fedora-compat
Version:        0.1.2
Release:        1%{?dist}
Summary:        Fedora RPM transaction compatibility frontends backed by RustD
License:        LGPL-2.1-or-later
URL:            https://github.com/SisyphusAeolides/rustd
Source0:        rustd-%{version}.tar.gz

BuildRequires:  bash
Requires:       rustd%{?_isa} = %{version}-%{release}
Requires:       rustd-compat-libs%{?_isa} = %{version}-%{release}
Requires:       dracut
Provides:       systemd = %{systemd_compat_evr}
Provides:       systemd-udev = %{systemd_compat_evr}
Conflicts:      systemd
Conflicts:      systemd-udev

%description
Fedora transaction compatibility entry points, the overlapping Fedora init
pathname, and package capabilities backed by RustD. The exact dependency on
rustd-compat-libs makes the package-level systemd/systemd-udev capability
replacement fail closed until RustD's measured Fedora ABI compatibility package
can be built and installed. Legacy executable paths required by Fedora package
scripts and dracut resolve to RustD code.

%prep
%autosetup -n rustd-%{version}

%build
# Shell frontends are architecture-independent source, but this RPM is kept on
# the native architecture because it has exact-version RustD dependencies.
for file in dist/fedora/compat/*; do
    bash -n "$file"
done

%check
bash tests/fedora-transaction-compat.sh
grep -Fq 'omit_dracutmodules+=' dist/fedora/90-rustd-dracut.conf
grep -Fq 'force_add_dracutmodules+=' dist/fedora/90-rustd-dracut.conf

%install
install -d %{buildroot}%{_bindir} \
           %{buildroot}%{_sbindir} \
           %{buildroot}%{_prefix}/lib/systemd \
           %{buildroot}%{_prefix}/lib/dracut/dracut.conf.d
install -m0755 dist/fedora/compat/systemctl %{buildroot}%{_bindir}/systemctl
install -m0755 dist/fedora/compat/systemd-tmpfiles %{buildroot}%{_bindir}/systemd-tmpfiles
install -m0755 dist/fedora/compat/systemd-sysusers %{buildroot}%{_bindir}/systemd-sysusers
install -m0755 dist/fedora/compat/udevadm %{buildroot}%{_bindir}/udevadm
install -m0755 dist/fedora/compat/systemd-update-helper %{buildroot}%{_prefix}/lib/systemd/systemd-update-helper
install -m0755 dist/fedora/compat/systemd-sysctl %{buildroot}%{_prefix}/lib/systemd/systemd-sysctl
install -m0755 dist/fedora/compat/systemd-binfmt %{buildroot}%{_prefix}/lib/systemd/systemd-binfmt
ln -s ../lib/rustd/rustd %{buildroot}%{_sbindir}/init
ln -s ../rustd/rustd-udevd %{buildroot}%{_prefix}/lib/systemd/systemd-udevd
install -m0644 dist/fedora/90-rustd-dracut.conf \
    %{buildroot}%{_prefix}/lib/dracut/dracut.conf.d/90-rustd.conf

%files
%license LICENSE*
%{_bindir}/systemctl
%{_bindir}/systemd-tmpfiles
%{_bindir}/systemd-sysusers
%{_bindir}/udevadm
%{_sbindir}/init
%{_prefix}/lib/systemd/systemd-update-helper
%{_prefix}/lib/systemd/systemd-sysctl
%{_prefix}/lib/systemd/systemd-binfmt
%{_prefix}/lib/systemd/systemd-udevd
%{_prefix}/lib/dracut/dracut.conf.d/90-rustd.conf

%changelog
* Tue Aug 18 2026 Kenny Glowner <SisyphusAeolides@pm.me> - 0.1.2-1
- Own Fedora's overlapping init path only during the exclusive swap
- Provide exact Fedora manager and udev compatibility capabilities
- Route dracut's legacy udev daemon path to RustD
