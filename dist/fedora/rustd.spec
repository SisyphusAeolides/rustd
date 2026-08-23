# EL/RHEL's shebang mangler rewrites /bin/bash to /usr/bin/bash even though
# the bash RPM provides only /bin/bash. Preserve the cutover tool's satisfiable
# interpreter dependency.
%global __brp_mangle_shebangs %{nil}

Name:           rustd
Version:        0.1.2
Release:        1%{?dist}
Summary:        RustD native Linux init and service manager
License:        LGPL-2.1-or-later
URL:            https://github.com/SisyphusAeolides/rustd
Source0:        rustd-%{version}.tar.gz

BuildRequires:  cargo >= 1.75
BuildRequires:  rust >= 1.75
BuildRequires:  gcc
BuildRequires:  gcc-gfortran
BuildRequires:  make
BuildRequires:  python3
BuildRequires:  pam-devel
BuildRequires:  pkgconfig(dbus-1)

Requires:       /usr/bin/dbus-daemon
Requires:       %{name}-cutover-tools%{?_isa} = %{version}-%{release}

%description
RustD is the native PID 1, service manager, device manager, journal, login
manager, and supporting userspace for an exclusive RustD Linux installation.
The main package owns Fedora protocol files that overlap the outgoing manager
stack and is installed only during the final exclusive transaction. The
nonconflicting cutover-tools subpackage is staged first so authentication and
name service can be migrated and validated without removing systemd.

%package cutover-tools
Summary:        Nonconflicting Fedora authentication cutover tools
Requires:       authselect
Requires:       python3
Requires:       rustd-resolved-nss%{?_isa} >= 0.2.3

%description cutover-tools
The RustD PAM module and fail-closed authselect migration helper. This package
contains no systemd-owned pathname and can be staged on a running Fedora system
before the exclusive PID 1 and compatibility-package transaction.

%package devel
Summary:        Development files for RustD native libraries
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description devel
Headers, pkg-config files, and linker names for RustD's native shared-library
API. The systemd/udev compatibility SONAMEs are packaged separately.

%prep
%autosetup -n rustd-%{version}
test -f Cargo.lock
test -f scripts/fedora-cutover-gate.sh
test -f dist/fedora/compat/rustd-fedora-cutover

%build
export CARGO_NET_OFFLINE=true
%make_build build pam-module libs

%check
export CARGO_NET_OFFLINE=true
make check-native check-packaging check-libs
bash -n scripts/fedora-cutover-gate.sh \
    scripts/fedora-vm-guest-cutover.sh \
    dist/fedora/compat/rustd-fedora-cutover

%install
export CARGO_NET_OFFLINE=true
export APPARMORDIR=%{_datadir}/rustd/apparmor
make DESTDIR=%{buildroot} \
     PREFIX=%{_prefix} \
     LIBDIR=%{_libdir} \
     PKGCONFIGDIR=%{_libdir}/pkgconfig \
     PAMLIBDIR=%{_libdir}/security \
     install
install -Dm0755 dist/fedora/compat/rustd-fedora-cutover \
    %{buildroot}%{_sbindir}/rustd-fedora-cutover

%files
%license LICENSE*
%doc README.md
%{_bindir}/rust*
%{_prefix}/lib/rustd/
%{_prefix}/lib/tmpfiles.d/rustd.conf
%{_datadir}/dbus-1/system-services/*.service
%{_datadir}/dbus-1/system.d/*.conf
%{_datadir}/polkit-1/actions/*.policy
%{_datadir}/rustd/apparmor/
%{_libdir}/librustd_service.so.1
%{_libdir}/librustd_journal.so.1
%{_libdir}/librustd_device.so.1
%{_libdir}/librustd_login.so.1
%{_libdir}/librustd_manager.so.1

%files cutover-tools
%license LICENSE*
%{_sbindir}/rustd-fedora-cutover
%{_libdir}/security/pam_rustd.so

%files devel
%{_includedir}/rustd/
%{_libdir}/pkgconfig/rustd-*.pc
%{_libdir}/librustd_service.so
%{_libdir}/librustd_journal.so
%{_libdir}/librustd_device.so
%{_libdir}/librustd_login.so
%{_libdir}/librustd_manager.so

%changelog
* Tue Aug 18 2026 Kenny Glowner <SisyphusAeolides@pm.me> - 0.1.2-1
- Split nonconflicting PAM and authselect cutover tooling
- Keep PID 1 and Fedora compatibility path ownership in the exclusive phase
- Add Fedora native RustD package for staged and exclusive cutover testing
