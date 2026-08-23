#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Static Fedora package ownership and two-phase cutover contract.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REFERENCE_EVR=${1:-1:999-1}
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

need() {
    command -v "$1" >/dev/null 2>&1 || {
        printf 'Fedora package contract: missing command: %s\n' "$1" >&2
        exit 1
    }
}
for command in bash grep make python3 rpmspec semodule_package; do
    need "$command"
done

cd "$ROOT"
for spec in dist/fedora/*.spec; do
    printf '==> %s\n' "$spec"
    expanded="$WORK/$(basename "$spec").expanded"
    rpmspec -P --define "systemd_compat_evr $REFERENCE_EVR" "$spec" > "$expanded"
    test -s "$expanded"
done

for frontend in dist/fedora/compat/*; do
    case "$frontend" in
        *.c|*.rules) continue ;;
    esac
    test "$(head -n1 "$frontend")" = '#!/bin/bash'
done
! grep -R -n -F '#!/usr/bin/bash' dist/fedora/compat
grep -Fq '%global __brp_mangle_shebangs %{nil}' dist/fedora/rustd.spec
grep -Fq '%global __brp_mangle_shebangs %{nil}' dist/fedora/rustd-fedora-compat.spec

mkdir -p "$WORK/selinux"
cp dist/fedora/selinux/rustd_fedora.te "$WORK/selinux/"
cp dist/fedora/selinux/rustd_fedora.fc "$WORK/selinux/"
make -C "$WORK/selinux" \
    -f /usr/share/selinux/devel/Makefile rustd_fedora.pp
test -s "$WORK/selinux/rustd_fedora.pp"

grep -Fq 'Obsoletes:      systemd-libs <= %{systemd_compat_evr}' \
    dist/fedora/rustd-compat-libs.spec
grep -Fq 'Provides:       systemd-libs = %{systemd_compat_evr}' \
    dist/fedora/rustd-compat-libs.spec
grep -Fq 'Provides:       systemd = %{systemd_compat_evr}' \
    dist/fedora/rustd-fedora-compat.spec
grep -Fq 'Provides:       systemd-udev = %{systemd_compat_evr}' \
    dist/fedora/rustd-fedora-compat.spec
for capability in \
    'systemd%{?_isa} = %{systemd_compat_evr}' \
    'systemd-udev%{?_isa} = %{systemd_compat_evr}' \
    'systemd-pam = %{systemd_compat_evr}' \
    'systemd-pam%{?_isa} = %{systemd_compat_evr}' \
    'systemd-units = %{systemd_compat_evr}' \
    'systemd-sysv = 206' \
    'systemd-sysusers = %{systemd_compat_evr}' \
    'systemd-sysusers%{?_isa} = %{systemd_compat_evr}' \
    'systemd-standalone-sysusers = %{systemd_compat_evr}' \
    'systemd-standalone-sysusers%{?_isa} = %{systemd_compat_evr}' \
    'systemd-tmpfiles = %{systemd_compat_evr}' \
    'systemd-standalone-tmpfiles = %{systemd_compat_evr}' \
    'systemd-standalone-tmpfiles%{?_isa} = %{systemd_compat_evr}' \
    'udev = %{systemd_compat_evr}' \
    'udev%{?_isa} = %{systemd_compat_evr}'; do
    grep -Fq "Provides:       $capability" dist/fedora/rustd-fedora-compat.spec
done
grep -Fq 'Obsoletes:      systemd <= %{systemd_compat_evr}' \
    dist/fedora/rustd-fedora-compat.spec
grep -Fq 'Obsoletes:      systemd-udev <= %{systemd_compat_evr}' \
    dist/fedora/rustd-fedora-compat.spec
grep -Fq 'Obsoletes:      systemd-pam <= %{systemd_compat_evr}' \
    dist/fedora/rustd-fedora-compat.spec
grep -Fq 'Obsoletes:      systemd-sysusers <= %{systemd_compat_evr}' \
    dist/fedora/rustd-fedora-compat.spec
grep -Fq 'Obsoletes:      systemd-standalone-sysusers <= %{systemd_compat_evr}' \
    dist/fedora/rustd-fedora-compat.spec
grep -Fq 'Obsoletes:      systemd-standalone-tmpfiles <= %{systemd_compat_evr}' \
    dist/fedora/rustd-fedora-compat.spec
grep -Fq 'Requires:       rustd-compat-libs%{?_isa} = %{version}-%{release}' \
    dist/fedora/rustd-fedora-compat.spec
grep -Fq 'Requires:       rustd-cutover-tools%{?_isa} = %{version}-%{release}' \
    dist/fedora/rustd-fedora-compat.spec

mapfile -t manager_providers < <(
    grep -l -E '^Provides:[[:space:]]+systemd([[:space:]=]|$)' dist/fedora/*.spec
)
[[ ${#manager_providers[@]} -eq 1 ]]
[[ ${manager_providers[0]} == dist/fedora/rustd-fedora-compat.spec ]]
grep -Eq "^Provides:[[:space:]]+systemd = ${REFERENCE_EVR//./\\.}$" \
    "$WORK/rustd-fedora-compat.spec.expanded"
grep -Eq "^Provides:[[:space:]]+systemd-udev = ${REFERENCE_EVR//./\\.}$" \
    "$WORK/rustd-fedora-compat.spec.expanded"
grep -Eq "^Provides:[[:space:]]+systemd-units = ${REFERENCE_EVR//./\\.}$" \
    "$WORK/rustd-fedora-compat.spec.expanded"
grep -Eq '^Provides:[[:space:]]+systemd-sysv = 206$' \
    "$WORK/rustd-fedora-compat.spec.expanded"
grep -Eq "^Provides:[[:space:]]+systemd-libs = ${REFERENCE_EVR//./\\.}$" \
    "$WORK/rustd-compat-libs.spec.expanded"

python3 - "$ROOT" <<'PY'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
base = (root / "dist/fedora/rustd.spec").read_text()
compat = (root / "dist/fedora/rustd-fedora-compat.spec").read_text()
guest = (root / "scripts/fedora-vm-guest-cutover.sh").read_text()

def between(text: str, start: str, end: str | None = None) -> str:
    try:
        body = text.split(start, 1)[1]
    except IndexError as exc:
        raise SystemExit(f"missing section marker: {start!r}") from exc
    if end is not None:
        try:
            body = body.split(end, 1)[0]
        except IndexError as exc:
            raise SystemExit(f"missing section end marker: {end!r}") from exc
    return body

main_files = between(base, "\n%files\n", "\n%files cutover-tools\n")
cutover_files = between(base, "\n%files cutover-tools\n", "\n%files devel\n")
compat_files = between(compat, "\n%files\n", "\n%changelog\n")

assert "%package cutover-tools" in base
assert "Requires:       rustd-resolved-nss%{?_isa} >= 0.2.3" in base
assert "%{_prefix}/sbin/init" not in main_files
assert "pam_rustd.so" not in main_files
assert "%{_prefix}/sbin/rustd-fedora-cutover" in cutover_files
assert "%{_libdir}/security/pam_rustd.so" in cutover_files

assert "%pretrans -p /bin/bash" in compat
assert "authselect check" in compat
assert "pam_systemd(_home|_loadkey)?" in compat
assert "%{_prefix}/sbin/init" in compat_files
assert "%{_prefix}/lib/udev/rules.d/80-drivers.rules" in compat_files
assert "%{_prefix}/sbin/rustd-fedora-cutover" not in compat_files
assert "Requires:       authselect" not in compat
assert "Requires:       python3" not in compat

stage = guest.index("install rustd-cutover-tools rustd-resolved-nss")
migrate = guest.index("/usr/sbin/rustd-fedora-cutover", stage)
exclusive = guest.index(
    "install rustd rustd-resolved rustd-compat-libs rustd-fedora-compat rustd-selinux",
    migrate,
)
assert stage < migrate < exclusive
assert "--allowerasing" not in guest[stage:migrate]
assert "comm -23" in guest[stage:migrate]
assert "packages-removed-during-stage.txt" in guest[stage:migrate]
assert "--setopt=protected_packages=" in guest[migrate:exclusive + 500]
assert re.search(
    r"/usr/sbin/init\)\" = rustd-fedora-compat",
    guest,
)
PY

grep -Fq 'systemd_evr="$(rpm -q --qf' scripts/build-fedora-rpms.sh
grep -Fq 'systemd_libs_evr="$(rpm -q --qf' scripts/build-fedora-rpms.sh
grep -Fq 'systemd_udev_evr="$(rpm -q --qf' scripts/build-fedora-rpms.sh
grep -Fq "rpm -q --qf '%{EVR}' systemd " scripts/build-fedora-rpms.sh
grep -Fq "rpm -q --qf '%{EVR}' systemd-libs " scripts/build-fedora-rpms.sh
grep -Fq "rpm -q --qf '%{EVR}' systemd-udev " scripts/build-fedora-rpms.sh
grep -Fq '"$systemd_evr" == "$systemd_libs_evr"' scripts/build-fedora-rpms.sh
grep -Fq '"$systemd_evr" == "$systemd_udev_evr"' scripts/build-fedora-rpms.sh
test "$(grep -Fc -- '--define "systemd_compat_evr $systemd_evr"' \
    scripts/build-fedora-rpms.sh)" -eq 3

pinned="$(tr -d '[:space:]' < scripts/rustd-resolved-revision.txt)"
[[ $pinned =~ ^[0-9a-f]{40}$ ]]
grep -Fq 'authselect create-profile rustd' \
    dist/fedora/compat/rustd-fedora-cutover
grep -Fq 'pam_systemd_loadkey' \
    dist/fedora/compat/rustd-fedora-cutover
grep -Fq 'pam_rustd.so' \
    dist/fedora/compat/rustd-fedora-cutover
grep -Fq 'rustd_dns' \
    dist/fedora/compat/rustd-fedora-cutover
grep -Fxq 'ExecStart=/usr/bin/rustd-sysusers' \
    packaging/rustd/rustd-sysusers.service
grep -Fxq 'ExecStart=/usr/bin/rustd-tmpfiles' \
    packaging/rustd/rustd-tmpfiles-setup.service
grep -Fxq 'ExecStart=/usr/bin/rustd-tmpfiles --prefix=/dev --create --boot' \
    packaging/rustd/rustd-tmpfiles-setup-dev.service
grep -Fxq 'ENV{MODALIAS}=="?*", RUN{builtin}+="kmod load"' \
    dist/fedora/compat/80-drivers.rules
grep -Fxq 'ACTION=="remove", GOTO="rustd_drivers_end"' \
    dist/fedora/compat/80-drivers.rules
grep -Fq "grep -Fq 'usr/lib/udev/rules.d/80-drivers.rules'" \
    scripts/fedora-vm-guest-cutover.sh
grep -Fq "owner_matches /usr/sbin/rustd-fedora-cutover '^rustd-cutover-tools$'" \
    scripts/fedora-cutover-gate.sh
grep -Fq "owner_matches /usr/lib64/security/pam_rustd.so '^rustd-cutover-tools$'" \
    scripts/fedora-cutover-gate.sh
grep -Fq "owner_matches /usr/lib64/libnss_rustd_dns.so.2 '^rustd-resolved-nss$'" \
    scripts/fedora-cutover-gate.sh

bash -n \
    scripts/build-fedora-rpms.sh \
    scripts/check-fedora-package-contract.sh \
    scripts/fedora-cutover-gate.sh \
    scripts/fedora-vm-guest-cutover.sh \
    dist/fedora/compat/rustd-fedora-cutover

printf 'Fedora package ownership and two-phase cutover contract: PASS\n'
