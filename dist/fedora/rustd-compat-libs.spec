%{!?systemd_compat_evr:%global systemd_compat_evr 0:0-0}

Name:           rustd-compat-libs
Version:        0.1.2
Release:        1%{?dist}
Summary:        Fedora libsystemd/libudev compatibility libraries backed by RustD
License:        LGPL-2.1-or-later
URL:            https://github.com/SisyphusAeolides/rustd
Source0:        rustd-%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  gcc-gfortran
BuildRequires:  make
BuildRequires:  python3
BuildRequires:  pkgconfig(dbus-1)
BuildRequires:  dbus-daemon
BuildRequires:  pkgconfig(json-c)

Requires:       rustd%{?_isa} = %{version}-%{release}
Provides:       systemd-libs = %{systemd_compat_evr}
Provides:       libsystemd = %{systemd_compat_evr}
Provides:       libudev = %{systemd_compat_evr}
Conflicts:      systemd-libs

%description
RustD-owned runtime compatibility SONAMEs for Fedora binaries already linked to
libsystemd.so.0 or libudev.so.1. The build and check phases require RustD's
measured compatibility surface to be 184/184 with zero unsupported or missing
definitions. It does not provide the package-level "systemd" capability.

%prep
%autosetup -n rustd-%{version}

%build
python3 scripts/check-compat-source-readiness.py \
    --report target/compat-readiness.json --require-complete
%make_build compat

%check
make check-compat
python3 scripts/check-compat-source-readiness.py \
    --report target/compat-readiness-check.json --require-complete
! readelf -d build/libs/libsystemd.so.0 | grep -F 'Shared library: [libsystemd'
! grep -R -n --include='*.c' --include='*.h' '#include <systemd/' libs/compat include/rustd

%install
install -d %{buildroot}%{_libdir}
install -m0755 build/libs/libsystemd.so.0 %{buildroot}%{_libdir}/libsystemd.so.0
install -m0755 build/libs/libudev.so.1 %{buildroot}%{_libdir}/libudev.so.1
bash scripts/check-compat-libs.sh %{buildroot}%{_prefix}

%files
%license LICENSE*
%{_libdir}/libsystemd.so.0
%{_libdir}/libudev.so.1

%changelog
* Tue Aug 18 2026 Kenny Glowner <SisyphusAeolides@pm.me> - 0.1.2-1
- Add fail-closed Fedora compatibility library package
