%{!?systemd_compat_evr:%global systemd_compat_evr 0:0-0}
# This subpackage contains only shell frontends and symlinks.  Disable RPM's
# automatic debuginfo split so platforms whose macros emit an empty
# debugsource file list (Rocky/RHEL) do not reject the otherwise valid RPM.
%global debug_package %{nil}
# EL/RHEL's shebang mangler rewrites /bin/bash to /usr/bin/bash even though
# the bash RPM provides only /bin/bash. Preserve the dependency that the
# distribution can actually satisfy.
%global __brp_mangle_shebangs %{nil}

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
Requires:       policycoreutils
Requires:       libselinux-utils
Provides:       systemd = %{systemd_compat_evr}
Provides:       systemd%{?_isa} = %{systemd_compat_evr}
Provides:       systemd-udev = %{systemd_compat_evr}
Provides:       systemd-udev%{?_isa} = %{systemd_compat_evr}
Provides:       systemd-pam = %{systemd_compat_evr}
Provides:       systemd-pam%{?_isa} = %{systemd_compat_evr}
Provides:       systemd-units = %{systemd_compat_evr}
Provides:       systemd-sysv = 206
Provides:       systemd-sysusers = %{systemd_compat_evr}
Provides:       systemd-sysusers%{?_isa} = %{systemd_compat_evr}
Provides:       systemd-standalone-sysusers = %{systemd_compat_evr}
Provides:       systemd-standalone-sysusers%{?_isa} = %{systemd_compat_evr}
Provides:       systemd-tmpfiles = %{systemd_compat_evr}
Provides:       systemd-standalone-tmpfiles = %{systemd_compat_evr}
Provides:       systemd-standalone-tmpfiles%{?_isa} = %{systemd_compat_evr}
Provides:       udev = %{systemd_compat_evr}
Provides:       udev%{?_isa} = %{systemd_compat_evr}
Provides:       u2f-hidraw-policy
Obsoletes:      systemd <= %{systemd_compat_evr}
Obsoletes:      systemd-udev <= %{systemd_compat_evr}
Obsoletes:      systemd-pam <= %{systemd_compat_evr}
Obsoletes:      systemd-sysusers <= %{systemd_compat_evr}
Obsoletes:      systemd-standalone-sysusers <= %{systemd_compat_evr}
Obsoletes:      systemd-standalone-tmpfiles <= %{systemd_compat_evr}

%description
Fedora transaction compatibility entry points and package capabilities backed
by RustD. The exact dependency on rustd-compat-libs makes the package-level
systemd/systemd-udev capability replacement fail closed until RustD's measured
Fedora ABI compatibility package can be built and installed. Legacy executable
paths required by Fedora package scripts and dracut resolve to RustD code.
The image kickstart validates the RustD PAM/NSS migration after installation;
this avoids requiring a shell interpreter before a fresh target transaction.

%prep
%autosetup -n rustd-%{version}

%build
# Shell frontends are architecture-independent source, but this RPM is kept on
# the native architecture because it has exact-version RustD dependencies.
for file in dist/fedora/compat/*; do
    case $file in
        *.c|*.rules) ;;
        *) bash -n "$file" ;;
    esac
done
%{__cc} %{build_cflags} %{build_ldflags} \
    dist/fedora/compat/rustd-shutdown.c -o rustd-shutdown

%check
bash tests/fedora-transaction-compat.sh
grep -Fq 'omit_dracutmodules+=' dist/fedora/90-rustd-dracut.conf
grep -Fq 'force_add_dracutmodules+=' dist/fedora/90-rustd-dracut.conf
grep -Eq 'force_add_dracutmodules\+=".*[[:space:]]selinux([[:space:]]|$)' \
    dist/fedora/90-rustd-dracut.conf
grep -Eq 'force_add_dracutmodules\+=".*[[:space:]]rustd-selinux-initramfs([[:space:]]|$)' \
    dist/fedora/90-rustd-dracut.conf
test -x dist/fedora/dracut/76rustd-selinux-initramfs/module-setup.sh
test -x dist/fedora/dracut/76rustd-selinux-initramfs/rustd-initramfs-permissive.sh
test -x dist/fedora/dracut/76rustd-selinux-initramfs/rustd-initramfs-relabel.sh
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
           %{buildroot}%{_prefix}/sbin \
           %{buildroot}%{_prefix}/lib/rustd \
           %{buildroot}%{_prefix}/lib/systemd \
           %{buildroot}%{_prefix}/lib/udev/rules.d \
           %{buildroot}%{_prefix}/lib/dracut/dracut.conf.d \
           %{buildroot}%{_prefix}/lib/dracut/modules.d/76rustd-selinux-initramfs
install -m0755 dist/fedora/compat/systemctl %{buildroot}%{_bindir}/systemctl
install -m0755 dist/fedora/compat/systemd-tmpfiles %{buildroot}%{_bindir}/systemd-tmpfiles
install -m0755 dist/fedora/compat/systemd-sysusers %{buildroot}%{_bindir}/systemd-sysusers
install -m0755 dist/fedora/compat/udevadm %{buildroot}%{_bindir}/udevadm
install -m0755 dist/fedora/compat/kernel-install %{buildroot}%{_bindir}/kernel-install
install -m0755 dist/fedora/compat/systemd-update-helper %{buildroot}%{_prefix}/lib/systemd/systemd-update-helper
install -m0755 dist/fedora/compat/systemd-sysctl %{buildroot}%{_prefix}/lib/systemd/systemd-sysctl
install -m0755 dist/fedora/compat/systemd-binfmt %{buildroot}%{_prefix}/lib/systemd/systemd-binfmt
install -m0644 dist/fedora/compat/50-rustd-default.rules \
    %{buildroot}%{_prefix}/lib/udev/rules.d/50-rustd-default.rules
install -m0644 dist/fedora/compat/80-drivers.rules \
    %{buildroot}%{_prefix}/lib/udev/rules.d/80-drivers.rules
ln -s ../rustd/rustd-udevd %{buildroot}%{_prefix}/lib/systemd/systemd-udevd
ln -s ../lib/rustd/rustd %{buildroot}%{_prefix}/sbin/init
install -m0755 rustd-shutdown %{buildroot}%{_prefix}/lib/rustd/rustd-shutdown
for name in halt poweroff reboot shutdown telinit runlevel; do
    ln -s ../lib/rustd/rustd-shutdown %{buildroot}%{_prefix}/sbin/$name
done
install -m0644 dist/fedora/90-rustd-dracut.conf \
    %{buildroot}%{_prefix}/lib/dracut/dracut.conf.d/90-rustd.conf
install -m0755 dist/fedora/dracut/76rustd-selinux-initramfs/module-setup.sh \
    %{buildroot}%{_prefix}/lib/dracut/modules.d/76rustd-selinux-initramfs/module-setup.sh
install -m0755 dist/fedora/dracut/76rustd-selinux-initramfs/rustd-initramfs-permissive.sh \
    %{buildroot}%{_prefix}/lib/dracut/modules.d/76rustd-selinux-initramfs/rustd-initramfs-permissive.sh
install -m0755 dist/fedora/dracut/76rustd-selinux-initramfs/rustd-initramfs-relabel.sh \
    %{buildroot}%{_prefix}/lib/dracut/modules.d/76rustd-selinux-initramfs/rustd-initramfs-relabel.sh

%files
%license LICENSE*
%{_prefix}/sbin/init
%{_prefix}/sbin/halt
%{_prefix}/sbin/poweroff
%{_prefix}/sbin/reboot
%{_prefix}/sbin/runlevel
%{_prefix}/sbin/shutdown
%{_prefix}/sbin/telinit
%{_prefix}/lib/rustd/rustd-shutdown
%{_bindir}/systemctl
%{_bindir}/systemd-tmpfiles
%{_bindir}/systemd-sysusers
%{_bindir}/udevadm
%{_bindir}/kernel-install
%{_prefix}/lib/systemd/systemd-update-helper
%{_prefix}/lib/systemd/systemd-sysctl
%{_prefix}/lib/systemd/systemd-binfmt
%{_prefix}/lib/systemd/systemd-udevd
%{_prefix}/lib/udev/rules.d/50-rustd-default.rules
%{_prefix}/lib/udev/rules.d/80-drivers.rules
%{_prefix}/lib/dracut/dracut.conf.d/90-rustd.conf
%{_prefix}/lib/dracut/modules.d/76rustd-selinux-initramfs/module-setup.sh
%{_prefix}/lib/dracut/modules.d/76rustd-selinux-initramfs/rustd-initramfs-permissive.sh
%{_prefix}/lib/dracut/modules.d/76rustd-selinux-initramfs/rustd-initramfs-relabel.sh

%changelog
* Tue Aug 18 2026 Kenny Glowner <SisyphusAeolides@pm.me> - 0.1.2-1
- Require a validated staged PAM and NSS migration before the exclusive swap
- Own the final /usr/sbin/init path in the conflicting compatibility package
- Provide exact Fedora manager and udev compatibility capabilities
- Route dracut's legacy udev daemon path to RustD
