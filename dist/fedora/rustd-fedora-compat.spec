# Resolve the platform systemd EVR in the buildroot when this SRPM is rebuilt
# by Koji. A zero fallback keeps source-package inspection possible, while a
# real RLC buildroot always supplies the exact capability being replaced.
%{!?systemd_compat_evr:%global systemd_compat_evr %(rpm -q --qf '%{EPOCHNUM}:%{VERSION}-%{RELEASE}' systemd 2>/dev/null || printf '0:0-0')}
# This subpackage contains shell frontends and compatibility pathnames. Disable RPM's
# automatic debuginfo split so platforms whose macros emit an empty
# debugsource file list (Rocky/RHEL) do not reject the otherwise valid RPM.
%global debug_package %{nil}
# EL/RHEL's shebang mangler rewrites /bin/bash to /usr/bin/bash even though
# the bash RPM provides only /bin/bash. Preserve the dependency that the
# distribution can actually satisfy.
%global __brp_mangle_shebangs %{nil}

Name:           rustd-fedora-compat
Version:        0.1.2
Release:        16%{?dist}
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
Requires:       lvm2
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
%{__cc} %{build_cflags} -Wno-error=cpp %{build_ldflags} \
    dist/fedora/compat/rustd-shutdown.c -o rustd-shutdown

%check
bash tests/fedora-transaction-compat.sh
grep -Fq 'omit_dracutmodules+=' dist/fedora/90-rustd-dracut.conf
grep -Fq 'force_add_dracutmodules+=' dist/fedora/90-rustd-dracut.conf
grep -Eq 'force_add_dracutmodules\+=".*[[:space:]]rustd-selinux-initramfs([[:space:]]|$)' \
    dist/fedora/90-rustd-dracut.conf
grep -Eq 'omit_dracutmodules\+=".*[[:space:]]selinux([[:space:]]|$)' \
    dist/fedora/90-rustd-dracut.conf
test -x dist/fedora/dracut/76rustd-selinux-initramfs/module-setup.sh
test -x dist/fedora/dracut/76rustd-selinux-initramfs/rustd-initramfs-relabel.sh
test -f dist/fedora/dropins/avahi-daemon.service.d/10-rustd-dbus.conf
test -f dist/fedora/dropins/rtkit-daemon.service.d/10-rustd-dbus.conf
test -f dist/fedora/dropins/chronyd.service.d/10-rustd-tmpfiles.conf
test -f dist/fedora/dropins/auditd.service.d/10-rustd-tmpfiles.conf
test -f dist/fedora/tmpfiles/rustd-fedora.conf
grep -Fq 'After=dbus.service' dist/fedora/dropins/avahi-daemon.service.d/10-rustd-dbus.conf
grep -Fq 'After=dbus.service' dist/fedora/dropins/rtkit-daemon.service.d/10-rustd-dbus.conf
grep -Fq 'Wants=dbus.service' dist/fedora/dropins/avahi-daemon.service.d/10-rustd-dbus.conf
grep -Fq 'Wants=dbus.service' dist/fedora/dropins/rtkit-daemon.service.d/10-rustd-dbus.conf
grep -Fq 'After=rustd-tmpfiles-setup.service' dist/fedora/dropins/chronyd.service.d/10-rustd-tmpfiles.conf
grep -Fq 'Requires=rustd-tmpfiles-setup.service' dist/fedora/dropins/chronyd.service.d/10-rustd-tmpfiles.conf
grep -Fq 'After=rustd-tmpfiles-setup.service' dist/fedora/dropins/auditd.service.d/10-rustd-tmpfiles.conf
grep -Fq 'Requires=rustd-tmpfiles-setup.service' dist/fedora/dropins/auditd.service.d/10-rustd-tmpfiles.conf
grep -Fq '/var/lib/chrony' dist/fedora/tmpfiles/rustd-fedora.conf
grep -Fq '/var/log/chrony' dist/fedora/tmpfiles/rustd-fedora.conf
! grep -Fq 'inst_hook pre-pivot' dist/fedora/dracut/76rustd-selinux-initramfs/module-setup.sh
grep -Fq 'init_exec_t' dist/fedora/selinux/rustd_fedora.fc
grep -Fq 'install_items+=" /usr/bin/rustudevadm /usr/lib/rustd/rustd-udevd /usr/lib/systemd/systemd-udevd "' \
    dist/fedora/90-rustd-dracut.conf
grep -Fq '/usr/lib/rustd/rustd-udevd' dist/fedora/90-rustd-dracut.conf
test -f dist/fedora/compat/systemd-udevd
grep -Fq 'exec /usr/lib/rustd/rustd-udevd' dist/fedora/compat/systemd-udevd
grep -Eq 'omit_dracutmodules\+=".*[[:space:]]rngd([[:space:]]|$)' \
    dist/fedora/90-rustd-dracut.conf
grep -Eq 'omit_dracutmodules\+=".*[[:space:]]memstrack([[:space:]]|$)' \
    dist/fedora/90-rustd-dracut.conf
! grep -Eq 'omit_dracutmodules\+=".*[[:space:]]systemd-initrd([[:space:]]|$)' \
    dist/fedora/90-rustd-dracut.conf
test -x dist/fedora/dracut/00systemd-initrd/module-setup.sh
bash -n dist/fedora/dracut/00systemd-initrd/module-setup.sh
grep -Fq 'echo base' dist/fedora/dracut/00systemd-initrd/module-setup.sh
grep -Fq '/usr/lib/systemd/systemd-udevd' dist/fedora/dracut/00systemd-initrd/module-setup.sh
grep -Fq '/usr/lib/rustd/rustd-udevd' dist/fedora/dracut/00systemd-initrd/module-setup.sh
test -x dist/fedora/dracut/91rustd-lvm/module-setup.sh
test -x dist/fedora/dracut/91rustd-lvm/lvm_scan.sh
test -x dist/fedora/dracut/91rustd-lvm/lvm_scan_initqueue.sh
bash -n dist/fedora/dracut/91rustd-lvm/module-setup.sh
bash -n dist/fedora/dracut/91rustd-lvm/lvm_scan.sh
sh -n dist/fedora/dracut/91rustd-lvm/lvm_scan_initqueue.sh
grep -Fq 'force_add_dracutmodules+=" base udev-rules rustd-selinux-initramfs rustd-lvm "' \
    dist/fedora/90-rustd-dracut.conf
grep -Fq 'lvm_scan.stock' dist/fedora/dracut/91rustd-lvm/module-setup.sh
grep -Fq 'modules.d/90lvm/lvm_scan.sh' dist/fedora/dracut/91rustd-lvm/module-setup.sh
grep -Fq 'modules.d/70lvm/lvm_scan.sh' dist/fedora/dracut/91rustd-lvm/module-setup.sh
grep -Fq 'rm -f "$initdir/usr/bin/lvm_scan"' dist/fedora/dracut/91rustd-lvm/module-setup.sh
grep -Fq 'inst_script "$moddir/lvm_scan.sh" /usr/bin/lvm_scan' \
    dist/fedora/dracut/91rustd-lvm/module-setup.sh
grep -Fq 'inst_hook initqueue/settled 90 "$moddir/lvm_scan_initqueue.sh"' \
    dist/fedora/dracut/91rustd-lvm/module-setup.sh
grep -Fq 'rustd_lvm=/usr/bin/lvm' dist/fedora/dracut/91rustd-lvm/lvm_scan.sh
grep -Fq -- '--noudevsync' dist/fedora/dracut/91rustd-lvm/lvm_scan.sh
grep -Fq 'LVM2_member' dist/fedora/dracut/91rustd-lvm/lvm_scan.sh
grep -Fq '/sbin/lvm_scan' dist/fedora/dracut/91rustd-lvm/lvm_scan_initqueue.sh
for file in \
    dist/fedora/dracut/00dmsquash-live/*.sh \
    dist/fedora/dracut/00livenet/*.sh \
    dist/fedora/dracut/99img-lib/*.sh; do
    test -x "$file"
    bash -n "$file"
done
grep -Fq 'echo dm rootfs-block img-lib overlayfs bash' \
    dist/fedora/dracut/00dmsquash-live/module-setup.sh
grep -Fq 'root=live:' dist/fedora/dracut/00dmsquash-live/parse-dmsquash-live.sh
grep -Fq 'echo network url-lib dmsquash-live img-lib bash' \
    dist/fedora/dracut/00livenet/module-setup.sh
! grep -Fq 'eval "$decompr"' dist/fedora/dracut/99img-lib/img-lib.sh
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
           %{buildroot}%{_sysconfdir}/rustd/system/avahi-daemon.service.d \
           %{buildroot}%{_sysconfdir}/rustd/system/auditd.service.d \
           %{buildroot}%{_sysconfdir}/rustd/system/chronyd.service.d \
           %{buildroot}%{_sysconfdir}/rustd/system/rtkit-daemon.service.d \
           %{buildroot}%{_prefix}/lib/tmpfiles.d \
           %{buildroot}%{_prefix}/lib/udev/rules.d \
           %{buildroot}%{_prefix}/lib/dracut/dracut.conf.d \
           %{buildroot}%{_prefix}/lib/dracut/modules.d/00systemd-initrd \
           %{buildroot}%{_prefix}/lib/dracut/modules.d/00dmsquash-live \
           %{buildroot}%{_prefix}/lib/dracut/modules.d/00livenet \
           %{buildroot}%{_prefix}/lib/dracut/modules.d/76rustd-selinux-initramfs \
           %{buildroot}%{_prefix}/lib/dracut/modules.d/91rustd-lvm \
           %{buildroot}%{_prefix}/lib/dracut/modules.d/99img-lib
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
install -m0644 dist/fedora/dropins/avahi-daemon.service.d/10-rustd-dbus.conf \
    %{buildroot}%{_sysconfdir}/rustd/system/avahi-daemon.service.d/10-rustd-dbus.conf
install -m0644 dist/fedora/dropins/auditd.service.d/10-rustd-tmpfiles.conf \
    %{buildroot}%{_sysconfdir}/rustd/system/auditd.service.d/10-rustd-tmpfiles.conf
install -m0644 dist/fedora/dropins/chronyd.service.d/10-rustd-tmpfiles.conf \
    %{buildroot}%{_sysconfdir}/rustd/system/chronyd.service.d/10-rustd-tmpfiles.conf
install -m0644 dist/fedora/dropins/rtkit-daemon.service.d/10-rustd-dbus.conf \
    %{buildroot}%{_sysconfdir}/rustd/system/rtkit-daemon.service.d/10-rustd-dbus.conf
install -m0644 dist/fedora/tmpfiles/rustd-fedora.conf \
    %{buildroot}%{_prefix}/lib/tmpfiles.d/rustd-fedora.conf
install -m0755 dist/fedora/compat/systemd-udevd \
    %{buildroot}%{_prefix}/lib/systemd/systemd-udevd
ln -s ../lib/rustd/rustd %{buildroot}%{_prefix}/sbin/init
install -m0755 rustd-shutdown %{buildroot}%{_prefix}/lib/rustd/rustd-shutdown
for name in halt poweroff reboot shutdown telinit runlevel; do
    ln -s ../lib/rustd/rustd-shutdown %{buildroot}%{_prefix}/sbin/$name
done
install -m0644 dist/fedora/90-rustd-dracut.conf \
    %{buildroot}%{_prefix}/lib/dracut/dracut.conf.d/90-rustd.conf
install -m0755 dist/fedora/dracut/76rustd-selinux-initramfs/module-setup.sh \
    %{buildroot}%{_prefix}/lib/dracut/modules.d/76rustd-selinux-initramfs/module-setup.sh
install -m0755 dist/fedora/dracut/00systemd-initrd/module-setup.sh \
    %{buildroot}%{_prefix}/lib/dracut/modules.d/00systemd-initrd/module-setup.sh
install -m0755 dist/fedora/dracut/91rustd-lvm/module-setup.sh \
    %{buildroot}%{_prefix}/lib/dracut/modules.d/91rustd-lvm/module-setup.sh
install -m0755 dist/fedora/dracut/91rustd-lvm/lvm_scan.sh \
    %{buildroot}%{_prefix}/lib/dracut/modules.d/91rustd-lvm/lvm_scan.sh
install -m0755 dist/fedora/dracut/91rustd-lvm/lvm_scan_initqueue.sh \
    %{buildroot}%{_prefix}/lib/dracut/modules.d/91rustd-lvm/lvm_scan_initqueue.sh
for file in dist/fedora/dracut/00dmsquash-live/*.sh; do
    install -m0755 "$file" \
        %{buildroot}%{_prefix}/lib/dracut/modules.d/00dmsquash-live/"$(basename "$file")"
done
for file in dist/fedora/dracut/00livenet/*.sh; do
    install -m0755 "$file" \
        %{buildroot}%{_prefix}/lib/dracut/modules.d/00livenet/"$(basename "$file")"
done
for file in dist/fedora/dracut/99img-lib/*.sh; do
    install -m0755 "$file" \
        %{buildroot}%{_prefix}/lib/dracut/modules.d/99img-lib/"$(basename "$file")"
done

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
%{_sysconfdir}/rustd/system/avahi-daemon.service.d/10-rustd-dbus.conf
%{_sysconfdir}/rustd/system/auditd.service.d/10-rustd-tmpfiles.conf
%{_sysconfdir}/rustd/system/chronyd.service.d/10-rustd-tmpfiles.conf
%{_sysconfdir}/rustd/system/rtkit-daemon.service.d/10-rustd-dbus.conf
%{_prefix}/lib/tmpfiles.d/rustd-fedora.conf
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
%{_prefix}/lib/dracut/modules.d/00systemd-initrd/module-setup.sh
%{_prefix}/lib/dracut/modules.d/00dmsquash-live/*
%{_prefix}/lib/dracut/modules.d/00livenet/*
%{_prefix}/lib/dracut/modules.d/76rustd-selinux-initramfs/module-setup.sh
%{_prefix}/lib/dracut/modules.d/91rustd-lvm/module-setup.sh
%{_prefix}/lib/dracut/modules.d/91rustd-lvm/lvm_scan.sh
%{_prefix}/lib/dracut/modules.d/91rustd-lvm/lvm_scan_initqueue.sh
%{_prefix}/lib/dracut/modules.d/99img-lib/*

%changelog
* Tue Sep 01 2026 Sisyphus Aeolides <SisyphusAeolides@pm.me> - 0.1.2-16
- Coordinate Fedora transaction compatibility with RustD journal sockets

* Tue Sep 01 2026 Sisyphus Aeolides <SisyphusAeolides@pm.me> - 0.1.2-15
- Require LVM userspace for the RustD initramfs compatibility module

* Tue Sep 01 2026 Sisyphus Aeolides <SisyphusAeolides@pm.me> - 0.1.2-14
- Align the kernel installer compatibility wrapper with RustD's plugin controls

* Tue Sep 01 2026 Sisyphus Aeolides <SisyphusAeolides@pm.me> - 0.1.2-13
- Route kernel package boot installation through RustD's native kernel installer

* Tue Sep 01 2026 Sisyphus Aeolides <SisyphusAeolides@pm.me> - 0.1.2-12
- Preserve LVM multiplexer argv[0] while applying RustD initramfs activation flags

* Tue Sep 01 2026 Sisyphus Aeolides <SisyphusAeolides@pm.me> - 0.1.2-11
- Run the RustD LVM scanner from settled initqueue coldplug
- Seed LVM2 PV markers when reduced udev rules omit the stock RUN action

* Mon Aug 31 2026 Sisyphus Aeolides <SisyphusAeolides@pm.me> - 0.1.2-10
- Make RustD-owned initramfs LVM activation independent of systemd-udev cookies

* Mon Aug 31 2026 Sisyphus Aeolides <SisyphusAeolides@pm.me> - 0.1.2-9
- Coordinate the standard systemd D-Bus compatibility namespace
- Keep graphical live-session startup and udev coldplug on RustD

* Mon Aug 31 2026 Sisyphus Aeolides <SisyphusAeolides@pm.me> - 0.1.2-8
- Coordinate the live-media udev condition fix

* Mon Aug 31 2026 Sisyphus Aeolides <SisyphusAeolides@pm.me> - 0.1.2-7
- Coordinate the enforcing-mode logind runtime and D-Bus activation policy

* Mon Aug 31 2026 Sisyphus Aeolides <SisyphusAeolides@pm.me> - 0.1.2-6
- Coordinate the SELinux logind activation transition

* Mon Aug 31 2026 Sisyphus Aeolides <SisyphusAeolides@pm.me> - 0.1.2-5
- Coordinate the standard D-Bus logind activation fix

* Mon Aug 31 2026 Sisyphus Aeolides <SisyphusAeolides@pm.me> - 0.1.2-4
- Provide RustD-owned dmsquash-live and network-live dracut contracts
- Keep standard Anaconda live boot compatible without systemd generators

* Sun Aug 30 2026 Sisyphus Aeolides <SisyphusAeolides@pm.me> - 0.1.2-3
- Provide RustD's systemd-initrd dracut compatibility contract
- Keep RLC live-image squash support free of systemd implementation modules

* Sun Aug 30 2026 Kenny Glowner <SisyphusAeolides@pm.me> - 0.1.2-2
- Install a regular initramfs-safe udev compatibility wrapper
- Explicitly include RustD's udev daemon in dracut images

* Tue Aug 18 2026 Kenny Glowner <SisyphusAeolides@pm.me> - 0.1.2-1
- Require a validated staged PAM and NSS migration before the exclusive swap
- Own the final /usr/sbin/init path in the conflicting compatibility package
- Provide exact Fedora manager and udev compatibility capabilities
- Route dracut's legacy udev daemon path to RustD
