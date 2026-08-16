#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Exclusive RustD cutover gate for CachyOS.
#
# Run this against a snapshot-backed CachyOS VM before replacing systemd on a
# live desktop. Do NOT uninstall systemd on production hardware until every
# checklist item prints PASS.

set -Eeuo pipefail

ROOT="${RUSTD_CUTOVER_ROOT:-/}"
RUSTCTL="${RUSTCTL:-${ROOT}/usr/bin/rustctl}"
PASS=0
FAIL=0

pass() {
    echo "PASS: $*"
    PASS=$((PASS + 1))
}

fail() {
    echo "FAIL: $*" >&2
    FAIL=$((FAIL + 1))
}

require_cmd() {
    if command -v "$1" >/dev/null 2>&1; then
        pass "command $1 available"
    else
        fail "command $1 missing"
    fi
}

package_installed_exactly() {
    pacman -Qq | awk -v wanted="$1" '$0 == wanted { found = 1 } END { exit !found }'
}

echo "==> RustD exclusive cutover gate"
echo "    root=$ROOT"

if [[ ! -e "${ROOT}/usr/lib/rustd/.exclusive-replacement" ]]; then
    fail "rustd exclusive replacement marker missing"
else
    pass "rustd exclusive replacement marker present"
fi

if [[ -e "${ROOT}/usr/lib/rustd/.side-by-side-certification" ]]; then
    fail "side-by-side certification marker still present"
else
    pass "no side-by-side certification marker"
fi

if [[ -e "${ROOT}/usr/lib/rustd/resolved/.exclusive-replacement" ]]; then
    pass "rustd-resolved exclusive marker present"
else
    fail "rustd-resolved exclusive marker missing"
fi

if package_installed_exactly systemd; then
    fail "systemd package still installed"
else
    pass "systemd package absent"
fi

if pacman -Q systemd-libs >/dev/null 2>&1; then
    pass "systemd-libs retained"
else
    fail "systemd-libs missing (sd-bus ABI required)"
fi

if pacman -Q rustd rustd-resolved >/dev/null 2>&1; then
    pass "rustd and rustd-resolved installed"
else
    fail "rustd and/or rustd-resolved not installed"
fi

require_cmd rustctl
require_cmd rustd-resolved
require_cmd udevadm

if [[ -x "$RUSTCTL" ]]; then
    for unit in default.target multi-user.target graphical.target dbus.service rustd-journald.service rustd-udevd.service rustd-logind.service; do
        if "$RUSTCTL" --quiet is-active "$unit" >/dev/null 2>&1; then
            pass "unit active: $unit"
        else
            fail "unit inactive: $unit"
        fi
    done
else
    fail "rustctl not executable at $RUSTCTL"
fi

if [[ -S /run/dbus/system_bus_socket ]]; then
    pass "system bus socket present"
else
    fail "system bus socket missing"
fi

if [[ -S /run/rustd/ctl.sock ]]; then
    pass "rustd control socket present"
else
    fail "rustd control socket missing"
fi

if [[ -e /etc/resolv.conf ]]; then
    pass "/etc/resolv.conf present"
else
    fail "/etc/resolv.conf missing"
fi

if [[ -e /usr/lib/libnss_resolve.so.2 ]] || [[ -e /usr/lib/libnss_resolve.so ]]; then
    pass "libnss_resolve installed"
else
    fail "libnss_resolve missing"
fi

if [[ -e /usr/lib/security/pam_systemd.so ]] || [[ -e /lib/security/pam_systemd.so ]]; then
    pass "pam_systemd.so present (pam_rustd alias)"
else
    fail "pam_systemd.so missing"
fi

echo
echo "==> Manual graphical checklist (operator)"
cat <<'EOF'
[ ] Three cold boots reach SDDM/GDM graphical login
[ ] NetworkManager online with DNS via rustd-resolved
[ ] PipeWire / WirePlumber user units active under rustd --user
[ ] Reboot, shutdown, tty login, and linger sessions work
[ ] pacman -Qkk rustd rustd-resolved systemd-libs is clean
[ ] CachyOS rescue USB verified bootable
EOF

echo
echo "Summary: $PASS passed, $FAIL failed"
if (( FAIL > 0 )); then
    echo "Cutover BLOCKED — do not replace systemd on the live host." >&2
    exit 1
fi
echo "Automated gate green. Complete the manual graphical checklist, then cut over."
exit 0
