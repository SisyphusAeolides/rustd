#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Destructive Fedora guest transaction used by the full-VM certification job.
set -Eeuo pipefail

RPM_REPO=${RUSTD_RPM_REPO:-/var/tmp/rustd-rpms}
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo 'guest cutover must run as root' >&2; exit 1; }
[[ -d $RPM_REPO ]] || { echo "RPM repository missing: $RPM_REPO" >&2; exit 1; }

cat /etc/fedora-release
test "$(cat /proc/1/comm)" = systemd
test "$(getenforce)" = Enforcing

dnf -y install createrepo_c dracut authselect
createrepo_c "$RPM_REPO"
rpm -qa --qf '%{NAME}-%{EVR}.%{ARCH}\n' | sort > /var/tmp/packages-before.txt
rpm -q --whatrequires systemd 2>/dev/null | sort -u > /var/tmp/systemd-consumers-before.txt || true

systemd_evr_before="$(rpm -q --qf '%{EVR}\n' systemd)"
systemd_libs_evr_before="$(rpm -q --qf '%{EVR}\n' systemd-libs)"
systemd_udev_evr_before="$(rpm -q --qf '%{EVR}\n' systemd-udev)"
test "$(rpm -qf --qf '%{NAME}\n' /usr/sbin/init)" = systemd

# Phase one is deliberately nonconflicting. Install only the PAM migration
# helper and NSS module, then prove that no pre-existing package or PID 1 path
# was removed before touching authentication configuration.
dnf -y \
    --repofrompath=rustd,"file://$RPM_REPO" \
    --setopt=rustd.gpgcheck=0 \
    --setopt=install_weak_deps=False \
    install rustd-cutover-tools rustd-resolved-nss

rpm -qa --qf '%{NAME}-%{EVR}.%{ARCH}\n' | sort > /var/tmp/packages-staged.txt
comm -23 /var/tmp/packages-before.txt /var/tmp/packages-staged.txt \
    > /var/tmp/packages-removed-during-stage.txt
if [[ -s /var/tmp/packages-removed-during-stage.txt ]]; then
    echo 'the nonconflicting stage removed or replaced existing packages:' >&2
    cat /var/tmp/packages-removed-during-stage.txt >&2
    exit 1
fi

test "$(rpm -q --qf '%{EVR}\n' systemd)" = "$systemd_evr_before"
test "$(rpm -q --qf '%{EVR}\n' systemd-libs)" = "$systemd_libs_evr_before"
test "$(rpm -q --qf '%{EVR}\n' systemd-udev)" = "$systemd_udev_evr_before"
test "$(rpm -qf --qf '%{NAME}\n' /usr/sbin/init)" = systemd
test "$(cat /proc/1/comm)" = systemd
rpm -q rustd-cutover-tools rustd-resolved-nss
for package in rustd rustd-resolved rustd-compat-libs rustd-fedora-compat rustd-selinux; do
    if rpm -q "$package" >/dev/null 2>&1; then
        echo "exclusive package was installed during nonconflicting stage: $package" >&2
        exit 1
    fi
done
test "$(rpm -qf --qf '%{NAME}\n' /usr/sbin/rustd-fedora-cutover)" = rustd-cutover-tools
test "$(rpm -qf --qf '%{NAME}\n' /usr/lib64/security/pam_rustd.so)" = rustd-cutover-tools
test "$(rpm -qf --qf '%{NAME}\n' /usr/lib64/libnss_rustd_dns.so.2)" = rustd-resolved-nss

# Migrate and validate authentication while every original Fedora package and
# the old PID 1 are still present. The final compatibility RPM has an RPM-level
# pre-transaction guard that independently enforces this state.
/usr/sbin/rustd-fedora-cutover

authselect check
grep -Eq '^hosts:.*[[:space:]]rustd_dns([[:space:]]|$)' /etc/nsswitch.conf
! grep -Eq '^(hosts|passwd|group|shadow):.*[[:space:]](myhostname|resolve|systemd)([[:space:]]|$)' /etc/nsswitch.conf
! grep -R -E -q 'pam_systemd(_home|_loadkey)?\.so' /etc/pam.d
grep -R -Fq 'pam_rustd.so' /etc/pam.d
getent passwd root >/dev/null

# Phase two owns the overlapping Fedora paths and replacement capabilities.
# --allowerasing is permitted only after the staged migration has passed.
dnf -y \
    --repofrompath=rustd,"file://$RPM_REPO" \
    --setopt=rustd.gpgcheck=0 \
    --setopt=install_weak_deps=False \
    --setopt=protected_packages= \
    install rustd rustd-resolved rustd-compat-libs rustd-fedora-compat rustd-selinux \
    --allowerasing

# The package-level compatibility capabilities are now supplied by RustD. Erase
# any residual systemd subpackages explicitly instead of allowing weak-dep
# autoremove to prune unrelated Fedora packages.
mapfile -t residual < <(rpm -qa --qf '%{NAME}\n' | grep -E '^systemd($|-)' | sort -u || true)
if ((${#residual[@]})); then
    dnf -y --setopt=protected_packages= remove --no-autoremove "${residual[@]}"
fi

dnf -q check
if rpm -qa --qf '%{NAME}\n' | grep -Eq '^systemd($|-)'; then
    echo 'systemd RPM remains after RustD cutover:' >&2
    rpm -qa --qf '%{NAME}-%{EVR}.%{ARCH}\n' | grep '^systemd' >&2 || true
    exit 1
fi

rpm -q rustd rustd-cutover-tools rustd-resolved rustd-resolved-nss \
    rustd-compat-libs rustd-fedora-compat rustd-selinux \
    kernel-core NetworkManager openssh-server dbus-daemon selinux-policy-targeted authselect

test "$(rpm -qf --qf '%{NAME}\n' /usr/sbin/init)" = rustd-fedora-compat
test "$(readlink -f /usr/sbin/init)" = /usr/lib/rustd/rustd
test "$(rpm -qf --qf '%{NAME}\n' /usr/lib64/security/pam_rustd.so)" = rustd-cutover-tools
test "$(rpm -qf --qf '%{NAME}\n' /usr/lib64/libnss_rustd_dns.so.2)" = rustd-resolved-nss
test "$(rpm -qf --qf '%{NAME}\n' /usr/lib64/libsystemd.so.0)" = rustd-compat-libs
test "$(rpm -qf --qf '%{NAME}\n' /usr/lib64/libudev.so.1)" = rustd-compat-libs
test "$(rpm -qf --qf '%{NAME}\n' /usr/lib/systemd/systemd-udevd)" = rustd-fedora-compat
test "$(readlink -f /usr/lib/systemd/systemd-udevd)" = /usr/lib/rustd/rustd-udevd

authselect check
grep -Eq '^hosts:.*[[:space:]]rustd_dns([[:space:]]|$)' /etc/nsswitch.conf
! grep -Eq '^(hosts|passwd|group|shadow):.*[[:space:]](myhostname|resolve|systemd)([[:space:]]|$)' /etc/nsswitch.conf
! grep -R -E -q 'pam_systemd(_home|_loadkey)?\.so' /etc/pam.d
[[ -e /usr/lib64/security/pam_rustd.so ]]
[[ -e /usr/lib64/libnss_rustd_dns.so.2 ]]

# Rebuild the boot image after the package swap and prove that dracut selected
# no systemd implementation module. A legacy udevd pathname is allowed only as
# the package-owned symlink to RustD required by dracut's shell init path.
kernel="$(ls -1 /usr/lib/modules | sort -V | tail -1)"
image="/boot/initramfs-${kernel}.img"
dracut --force "$image" "$kernel"
lsinitrd -m "$image" > /var/tmp/rustd-initrd-modules.txt
lsinitrd "$image" > /var/tmp/rustd-lsinitrd.txt

if grep -Eq '^[[:space:]]*(systemd|dracut-systemd|systemd-[^[:space:]]+)([[:space:]]|$)' /var/tmp/rustd-initrd-modules.txt; then
    echo 'systemd dracut module remains in converted initramfs:' >&2
    grep -E '^[[:space:]]*(systemd|dracut-systemd|systemd-[^[:space:]]+)([[:space:]]|$)' /var/tmp/rustd-initrd-modules.txt >&2 || true
    exit 1
fi

grep -Fq 'usr/lib/rustd/rustd-udevd' /var/tmp/rustd-lsinitrd.txt
grep -Eq 'usr/lib/systemd/systemd-udevd -> \.\./rustd/rustd-udevd$' /var/tmp/rustd-lsinitrd.txt
for old in usr/lib/systemd/systemd usr/lib/systemd/systemd-journald usr/lib/systemd/systemd-resolved; do
    if grep -Eq "[[:space:]]${old}$" /var/tmp/rustd-lsinitrd.txt; then
        echo "removed implementation executable remains in initramfs: $old" >&2
        exit 1
    fi
done

sync
