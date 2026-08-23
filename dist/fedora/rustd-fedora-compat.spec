%{!?systemd_compat_evr:%global systemd_compat_evr 0:0-0}
# This subpackage contains only shell frontends and symlinks.  Disable RPM's
# automatic debuginfo split so platforms whose macros emit an empty
# debugsource file list (Rocky/RHEL) do not reject the otherwise valid RPM.
%global debug_package %{nil}

Name:           rustd-fedora-compat
Version:        0.1.2
Release:        1%{?dist}
Summary:        Fedora RPM transaction compatibility frontends backed by RustD
License:        LGPL-2.1-or-later
URL:            https://github.com/SisyphusAeolides/rustd
Source0:        rustd-%{version}.tar.gz

BuildRequires:  bash
BuildRequires:  gcc
Requires:       rustd%{?_isa} = %{version}-%{release}
Requires:       rustd-cutover-tools%{?_isa} = %{version}-%{release}
Requires:       rustd-compat-libs%{?_isa} = %{version}-%{release}
Requires:       dracut
Provides:       systemd = %{systemd_compat_evr}
Provides:       systemd%{?_isa} = %{systemd_compat_evr}
Provides:       systemd-udev = %{systemd_compat_evr}
Provides:       systemd-udev%{?_isa} = %{systemd_compat_evr}
Provides:       systemd-pam = %{systemd_compat_evr}
Provides:       systemd-pam%{?_isa} = %{systemd_compat_evr}
Provides:       systemd-units = %{systemd_compat_evr}
Provides:       systemd-sysv = 206
Provides:       udev = %{systemd_compat_evr}
Provides:       udev%{?_isa} = %{systemd_compat_evr}
Obsoletes:      systemd <= %{systemd_compat_evr}
Obsoletes:      systemd-udev <= %{systemd_compat_evr}
Obsoletes:      systemd-pam <= %{systemd_compat_evr}

%description
Fedora transaction compatibility entry points and package capabilities backed
by RustD. The exact dependency on rustd-compat-libs makes the package-level
systemd/systemd-udev capability replacement fail closed until RustD's measured
Fedora ABI compatibility package can be built and installed. Legacy executable
paths required by Fedora package scripts and dracut resolve to RustD code.
The pre-transaction guard refuses the exclusive swap unless the separately
staged RustD PAM/NSS migration is active and valid.

%prep
%autosetup -n rustd-%{version}

%build
# Shell frontends are architecture-independent source, but this RPM is kept on
# the native architecture because it has exact-version RustD dependencies.
for file in dist/fedora/compat/*; do
    [[ $file == *.c ]] || bash -n "$file"
done
%{__cc} %{build_cflags} %{build_ldflags} \
    dist/fedora/compat/rustd-shutdown.c -o rustd-shutdown

%check
bash tests/fedora-transaction-compat.sh
grep -Fq 'omit_dracutmodules+=' dist/fedora/90-rustd-dracut.conf
grep -Fq 'force_add_dracutmodules+=' dist/fedora/90-rustd-dracut.conf
grep -Fq 'install_items+=" /usr/bin/rustudevadm "' dist/fedora/90-rustd-dracut.conf
grep -Eq 'omit_dracutmodules\+=".*[[:space:]]rngd([[:space:]]|$)' \
    dist/fedora/90-rustd-dracut.conf
grep -Eq 'omit_dracutmodules\+=".*[[:space:]]memstrack([[:space:]]|$)' \
    dist/fedora/90-rustd-dracut.conf
for name in halt poweroff reboot shutdown telinit runlevel; do
    ln -s rustd-shutdown "$name"
done
test "$(RUSTD_SHUTDOWN_DRY_RUN=1 ./halt)" = poweroff
test "$(RUSTD_SHUTDOWN_DRY_RUN=1 ./poweroff)" = poweroff
test "$(RUSTD_SHUTDOWN_DRY_RUN=1 ./reboot)" = reboot
test "$(RUSTD_SHUTDOWN_DRY_RUN=1 ./shutdown -r now)" = reboot
test "$(RUSTD_SHUTDOWN_DRY_RUN=1 ./shutdown -P now)" = poweroff
test "$(RUSTD_SHUTDOWN_DRY_RUN=1 ./telinit 6)" = reboot
test "$(RUSTD_SHUTDOWN_DRY_RUN=1 ./telinit 0)" = poweroff
test "$(RUSTD_SHUTDOWN_DRY_RUN=1 ./runlevel)" = 'N N'
rm -f halt poweroff reboot shutdown telinit runlevel

%install
install -d %{buildroot}%{_bindir} \
           %{buildroot}%{_sbindir} \
           %{buildroot}%{_prefix}/lib/rustd \
           %{buildroot}%{_prefix}/lib/systemd \
           %{buildroot}%{_prefix}/lib/dracut/dracut.conf.d
install -m0755 dist/fedora/compat/systemctl %{buildroot}%{_bindir}/systemctl
install -m0755 dist/fedora/compat/systemd-tmpfiles %{buildroot}%{_bindir}/systemd-tmpfiles
install -m0755 dist/fedora/compat/systemd-sysusers %{buildroot}%{_bindir}/systemd-sysusers
install -m0755 dist/fedora/compat/udevadm %{buildroot}%{_bindir}/udevadm
install -m0755 dist/fedora/compat/systemd-update-helper %{buildroot}%{_prefix}/lib/systemd/systemd-update-helper
install -m0755 dist/fedora/compat/systemd-sysctl %{buildroot}%{_prefix}/lib/systemd/systemd-sysctl
install -m0755 dist/fedora/compat/systemd-binfmt %{buildroot}%{_prefix}/lib/systemd/systemd-binfmt
ln -s ../rustd/rustd-udevd %{buildroot}%{_prefix}/lib/systemd/systemd-udevd
ln -s ../lib/rustd/rustd %{buildroot}%{_sbindir}/init
install -m0755 rustd-shutdown %{buildroot}%{_prefix}/lib/rustd/rustd-shutdown
for name in halt poweroff reboot shutdown telinit runlevel; do
    ln -s ../lib/rustd/rustd-shutdown %{buildroot}%{_sbindir}/$name
done
install -m0644 dist/fedora/90-rustd-dracut.conf \
    %{buildroot}%{_prefix}/lib/dracut/dracut.conf.d/90-rustd.conf

%pretrans -p /bin/bash
set -eu
fail() {
    echo "rustd-fedora-compat: $*" >&2
    exit 1
}
command -v authselect >/dev/null 2>&1 \
    || fail 'authselect is unavailable; install and run rustd-cutover-tools first'
authselect check >/dev/null \
    || fail 'authselect configuration is invalid; refusing the exclusive swap'
[[ -e %{_libdir}/security/pam_rustd.so ]] \
    || fail 'pam_rustd.so is not staged'
[[ -e %{_libdir}/libnss_rustd_dns.so.2 ]] \
    || fail 'libnss_rustd_dns.so.2 is not staged'
grep -Eq '^hosts:.*[[:space:]]rustd_dns([[:space:]]|$)' /etc/nsswitch.conf \
    || fail 'hosts NSS is not migrated to rustd_dns'
! grep -Eq '^[[:alpha:]_][[:alnum:]_-]*:.*[[:space:]](myhostname|resolve|systemd)([[:space:]]|$)' /etc/nsswitch.conf \
    || fail 'NSS still references a systemd-owned backend'
grep -R -Fq 'pam_rustd.so' /etc/pam.d \
    || fail 'PAM is not migrated to pam_rustd.so'
! grep -R -E -q 'pam_systemd(_home|_loadkey)?\.so' /etc/pam.d \
    || fail 'PAM still references a systemd module'

%files
%license LICENSE*
%{_sbindir}/init
%{_sbindir}/halt
%{_sbindir}/poweroff
%{_sbindir}/reboot
%{_sbindir}/runlevel
%{_sbindir}/shutdown
%{_sbindir}/telinit
%{_prefix}/lib/rustd/rustd-shutdown
%{_bindir}/systemctl
%{_bindir}/systemd-tmpfiles
%{_bindir}/systemd-sysusers
%{_bindir}/udevadm
%{_prefix}/lib/systemd/systemd-update-helper
%{_prefix}/lib/systemd/systemd-sysctl
%{_prefix}/lib/systemd/systemd-binfmt
%{_prefix}/lib/systemd/systemd-udevd
%{_prefix}/lib/dracut/dracut.conf.d/90-rustd.conf

%changelog
* Tue Aug 18 2026 Kenny Glowner <SisyphusAeolides@pm.me> - 0.1.2-1
- Require a validated staged PAM and NSS migration before the exclusive swap
- Own the final /usr/sbin/init path in the conflicting compatibility package
- Provide exact Fedora manager and udev compatibility capabilities
- Route dracut's legacy udev daemon path to RustD
