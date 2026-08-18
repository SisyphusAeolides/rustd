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

%description
RustD is the native PID 1, service manager, device manager, journal, login
manager, and supporting userspace for an exclusive RustD Linux installation.
This package intentionally does not claim the RPM capability "systemd" and is
safe to stage alongside Fedora's systemd package for VM certification. The
path-owning Fedora compatibility package performs the final conflict/swap only
after all release gates pass.

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

%build
export CARGO_NET_OFFLINE=true
%make_build build pam-module libs

%check
export CARGO_NET_OFFLINE=true
make check-native check-packaging check-libs
bash -n scripts/fedora-cutover-gate.sh

%install
export CARGO_NET_OFFLINE=true
export APPARMORDIR=%{_datadir}/rustd/apparmor
make DESTDIR=%{buildroot} \
     PREFIX=%{_prefix} \
     LIBDIR=%{_libdir} \
     PKGCONFIGDIR=%{_libdir}/pkgconfig \
     PAMLIBDIR=%{_libdir}/security \
     install

# Fedora boots RustD directly. Do not point init at a systemd-named binary.
install -d %{buildroot}%{_sbindir}
ln -s ../lib/rustd/rustd %{buildroot}%{_sbindir}/init

%files
%license LICENSE*
%doc README.md
%{_sbindir}/init
%{_bindir}/rust*
%{_prefix}/lib/rustd/
%{_prefix}/lib/tmpfiles.d/rustd.conf
%{_datadir}/dbus-1/system-services/*.service
%{_datadir}/dbus-1/system.d/*.conf
%{_datadir}/polkit-1/actions/*.policy
%{_datadir}/rustd/apparmor/
%{_libdir}/security/pam_rustd.so
%{_libdir}/librustd_service.so.1
%{_libdir}/librustd_journal.so.1
%{_libdir}/librustd_device.so.1
%{_libdir}/librustd_login.so.1
%{_libdir}/librustd_manager.so.1

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
- Add Fedora native RustD package for staged and exclusive cutover testing
