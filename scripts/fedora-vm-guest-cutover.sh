#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Destructive Fedora/RHEL-family guest transaction used by full-VM certification.
set -Eeuo pipefail

RPM_REPO=${RUSTD_RPM_REPO:-/var/tmp/rustd-rpms}
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo 'guest cutover must run as root' >&2; exit 1; }
[[ -d $RPM_REPO ]] || { echo "RPM repository missing: $RPM_REPO" >&2; exit 1; }

. /etc/os-release
case ${ID:-} in
    fedora|rocky) ;;
    *) echo "unsupported guest distribution: ${ID:-unknown}" >&2; exit 1 ;;
esac
printf '%s\n' "${PRETTY_NAME:-${ID} ${VERSION_ID:-}}"
test "$(cat /proc/1/comm)" = systemd
test "$(getenforce)" = Enforcing

# Align every installed consumer with the repository's current systemd EVR
# before building the exact-EVR replacement RPMs. Mixing an older cloud image
# with newer compatibility Provides can otherwise make DNF erase consumers
# whose dependencies are locked to the older systemd build.
dnf -y upgrade --refresh
dnf -y install createrepo_c dracut authselect binutils
createrepo_c "$RPM_REPO"
/var/tmp/scripts/audit-systemd-elf-consumers.py \
    --output /var/tmp/rustd-precutover-elf-audit.json
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
! grep -Eq '^[[:alpha:]_][[:alnum:]_-]*:.*[[:space:]](myhostname|resolve|systemd)([[:space:]]|$)' /etc/nsswitch.conf
! grep -R -E -q 'pam_systemd(_home|_loadkey)?\.so' /etc/pam.d
grep -R -Fq 'pam_rustd.so' /etc/pam.d
getent passwd root >/dev/null

# Phase two owns the overlapping Fedora paths and replacement capabilities.
# --allowerasing is permitted only after the staged migration has passed.
solver_log=/var/tmp/rustd-exclusive-solver.txt
set +e
LC_ALL=C dnf \
    --repofrompath=rustd,"file://$RPM_REPO" \
    --setopt=rustd.gpgcheck=0 \
    --setopt=install_weak_deps=False \
    --setopt=protected_packages= \
    install rustd rustd-resolved rustd-compat-libs rustd-fedora-compat rustd-selinux \
    --allowerasing --assumeno >"$solver_log" 2>&1
solver_status=$?
set -e
cat "$solver_log"
[[ $solver_status -ne 0 ]] || {
    echo 'exclusive solver preflight unexpectedly completed a transaction' >&2
    exit 1
}
grep -Fq 'Transaction Summary' "$solver_log"
if grep -Fq 'Removing dependent packages:' "$solver_log"; then
    echo 'exclusive solver preflight would remove dependent packages' >&2
    exit 1
fi

dnf -y \
    --repofrompath=rustd,"file://$RPM_REPO" \
    --setopt=rustd.gpgcheck=0 \
    --setopt=install_weak_deps=False \
    --setopt=protected_packages= \
    install rustd rustd-resolved rustd-compat-libs rustd-fedora-compat rustd-selinux \
    --allowerasing

# An exclusive replacement may erase systemd packages, but never unrelated
# packages. Fail the disposable certification guest if the solver pruned any
# pre-cutover workload or boot component.
rpm -qa --qf '%{NAME}-%{EVR}.%{ARCH}\n' | sort > /var/tmp/packages-after-exclusive.txt
awk -F- '$1 != "systemd"' /var/tmp/packages-before.txt > /var/tmp/non-systemd-before.txt
awk -F- '$1 != "systemd"' /var/tmp/packages-after-exclusive.txt > /var/tmp/non-systemd-after.txt
comm -23 /var/tmp/non-systemd-before.txt /var/tmp/non-systemd-after.txt \
    > /var/tmp/non-systemd-removed-during-exclusive.txt
if [[ -s /var/tmp/non-systemd-removed-during-exclusive.txt ]]; then
    echo 'exclusive transaction removed or replaced non-systemd packages:' >&2
    cat /var/tmp/non-systemd-removed-during-exclusive.txt >&2
    exit 1
fi

# The package-level compatibility capabilities are now supplied by RustD. Erase
# any residual systemd subpackages explicitly instead of allowing weak-dep
# autoremove to prune unrelated Fedora packages.
mapfile -t residual < <(rpm -qa --qf '%{NAME}\n' | grep -E '^systemd($|-)' | sort -u || true)
if ((${#residual[@]})); then
    dnf -y --setopt=protected_packages= \
        --setopt=clean_requirements_on_remove=False remove "${residual[@]}"
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
compat_systemd=$(rpm -ql rustd-compat-libs | grep '/libsystemd\.so\.0$')
compat_udev=$(rpm -ql rustd-compat-libs | grep '/libudev\.so\.1$')
test "$(rpm -qf --qf '%{NAME}\n' "$compat_systemd")" = rustd-compat-libs
test "$(rpm -qf --qf '%{NAME}\n' "$compat_udev")" = rustd-compat-libs
/var/tmp/scripts/check-compat-closure.py \
    --report /var/tmp/rustd-precutover-elf-audit.json \
    --repository-root /var/tmp/rustd-source \
    --libsystemd "$compat_systemd" \
    --libudev "$compat_udev"
test "$(rpm -qf --qf '%{NAME}\n' /usr/lib/systemd/systemd-udevd)" = rustd-fedora-compat
test "$(readlink -f /usr/lib/systemd/systemd-udevd)" = /usr/lib/rustd/rustd-udevd

authselect check
grep -Eq '^hosts:.*[[:space:]]rustd_dns([[:space:]]|$)' /etc/nsswitch.conf
! grep -Eq '^[[:alpha:]_][[:alnum:]_-]*:.*[[:space:]](myhostname|resolve|systemd)([[:space:]]|$)' /etc/nsswitch.conf
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
