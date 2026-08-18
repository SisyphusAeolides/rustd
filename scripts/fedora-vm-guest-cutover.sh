#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Destructive Fedora guest transaction used by the full-VM certification job.
set -Eeuo pipefail

RPM_REPO=${RUSTD_RPM_REPO:-/var/tmp/rustd-rpms}
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo 'guest cutover must run as root' >&2; exit 1; }
[[ -d $RPM_REPO ]] || { echo "RPM repository missing: $RPM_REPO" >&2; exit 1; }

cat /etc/fedora-release
test "$(cat /proc/1/comm)" = systemd
test "$(rpm -qf --qf '%{NAME}\n' /usr/sbin/init)" = systemd
getenforce

dnf -y install createrepo_c dracut authselect
createrepo_c "$RPM_REPO"
rpm -qa --qf '%{NAME}\n' | sort > /var/tmp/packages-before.txt
rpm -q --whatrequires systemd 2>/dev/null | sort -u > /var/tmp/systemd-consumers-before.txt || true

repo_args=(
    --repofrompath=rustd,"file://$RPM_REPO"
    --setopt=rustd.gpgcheck=0
)

# Stage only packages that do not conflict with the running Fedora manager.
# This makes pam_rustd and libnss_rustd_dns available while the original PAM,
# NSS, resolver and PID 1 packages are still installed and recoverable.
dnf -y "${repo_args[@]}" install rustd rustd-resolved-nss
rpm -q systemd systemd-pam systemd-resolved rustd rustd-resolved-nss
test "$(cat /proc/1/comm)" = systemd
test "$(rpm -qf --qf '%{NAME}\n' /usr/sbin/init)" = systemd
[[ -e /usr/lib64/security/pam_systemd.so ]]
[[ -e /usr/lib64/security/pam_rustd.so ]]
[[ -e /usr/lib64/libnss_rustd_dns.so.2 ]]

# Convert PAM and NSS before any package supplying the old session/NSS modules
# is removed. The helper validates the generated authselect profile and creates
# a rollback backup before activation.
/usr/sbin/rustd-fedora-cutover
authselect check
grep -Eq '^hosts:.*[[:space:]]rustd_dns([[:space:]]|$)' /etc/nsswitch.conf
! grep -Eq '^(hosts|passwd|group|shadow):.*[[:space:]](myhostname|resolve|systemd)([[:space:]]|$)' /etc/nsswitch.conf
! grep -R -E -q 'pam_systemd(_home|_loadkey)?\.so' /etc/pam.d

# Fedora protects the running manager from ordinary DNF removals. The explicit
# exclusive cutover disables only that package-protection list for this
# disposable certification transaction; the running kernel remains protected.
dnf -y \
    "${repo_args[@]}" \
    --setopt=protected_packages= \
    install rustd-resolved rustd-compat-libs rustd-fedora-compat rustd-selinux \
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

rpm -q rustd rustd-resolved rustd-resolved-nss rustd-compat-libs rustd-fedora-compat rustd-selinux \
    kernel-core NetworkManager openssh-server dbus-daemon selinux-policy-targeted authselect

test "$(rpm -qf --qf '%{NAME}\n' /usr/sbin/init)" = rustd-fedora-compat
test "$(readlink -f /usr/sbin/init)" = /usr/lib/rustd/rustd
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
