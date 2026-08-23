#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Final Fedora-only wrapper around RustD's detailed cutover gate.
set -Eeuo pipefail

SOURCE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATE="$SOURCE_ROOT/scripts/fedora-cutover-gate.sh"

fail() { printf 'Fedora RustD release cutover: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "required command missing: $1"; }

[[ -r /etc/os-release ]] || fail '/etc/os-release is unavailable'
# shellcheck disable=SC1091
. /etc/os-release
[[ ${ID:-} == fedora ]] || fail "host is not Fedora (ID=${ID:-unknown})"

for command in rpm dnf getenforce; do need "$command"; done
[[ $(getenforce 2>/dev/null || true) == Enforcing ]] \
    || fail 'SELinux must be Enforcing for production cutover'

# An ELF compatibility library can satisfy libsystemd/libudev requirements, but
# it must never pretend to satisfy packages that require the `systemd` package
# itself for executables, macros, or scriptlet semantics. Resolve those packages
# explicitly before the destructive swap.
mapfile -t package_consumers < <(
    rpm -q --whatrequires systemd 2>/dev/null \
        | sed '/^no package requires/d' \
        | awk '!/^systemd($|-)/' \
        | sort -u
)
if ((${#package_consumers[@]})); then
    fail "installed RPMs still require package-level systemd: ${package_consumers[*]}"
fi

# Ensure the Fedora transaction compatibility surface itself is certified.
transaction_voucher="$SOURCE_ROOT/certification/fedora-transaction-latest.txt"
[[ -r $transaction_voucher ]] || fail 'Fedora transaction voucher is missing'
"$SOURCE_ROOT/scripts/check-voucher-source-equivalence.sh" "$transaction_voucher" \
    || fail 'Fedora transaction voucher is stale for this source revision'
grep -Fxq 'status=pass' "$transaction_voucher" \
    || fail 'Fedora transaction compatibility is not green'
for key in systemctl update_helper tmpfiles sysusers sysctl binfmt udevadm; do
    grep -Fxq "$key=rustd-backed" "$transaction_voucher" \
        || fail "Fedora transaction voucher is missing $key=rustd-backed"
done

# 335/335 is non-negotiable before systemd-libs can leave the RPM transaction.
abi="$SOURCE_ROOT/certification/final-abi-closure-latest.txt"
[[ -r $abi ]] || fail 'final RustD ABI closure voucher is missing'
"$SOURCE_ROOT/scripts/check-voucher-source-equivalence.sh" "$abi" \
    || fail 'final RustD ABI closure voucher is stale for this source revision'
grep -Fxq 'status=pass' "$abi" || fail 'final RustD ABI closure is not green'
grep -Fxq 'required=335' "$abi" || fail 'ABI voucher does not require 335 symbols'
grep -Fxq 'supported=335' "$abi" || fail 'ABI voucher does not certify 335 symbols'
grep -Fxq 'unsupported=0' "$abi" || fail 'ABI voucher still has unsupported symbols'
grep -Fxq 'missing=0' "$abi" || fail 'ABI voucher still has missing symbols'
grep -Fxq 'systemd_headers=none' "$abi" || fail 'systemd development headers remain in the compatibility implementation'
grep -Fxq 'systemd_runtime_link=none' "$abi" || fail 'RustD compatibility library links back to libsystemd'

# Fedora package/SELinux source contracts must have been compiled on Fedora.
package_voucher="$SOURCE_ROOT/certification/fedora-package-contract-latest.txt"
[[ -r $package_voucher ]] || fail 'Fedora package/SELinux contract voucher is missing'
"$SOURCE_ROOT/scripts/check-voucher-source-equivalence.sh" "$package_voucher" \
    || fail 'Fedora package/SELinux contract voucher is stale for this source revision'
grep -Eq '^status=(success|pass)$' "$package_voucher" \
    || fail 'Fedora package/SELinux contract is not green'
grep -Fxq 'selinux_reference_policy=compiled' "$package_voucher" \
    || fail 'RustD SELinux policy has not compiled against Fedora reference policy'
grep -Fxq 'rpm_specs=parsed' "$package_voucher" \
    || fail 'Fedora RPM specs have not passed parsing'

exec "$GATE" "$@"
