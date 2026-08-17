#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Exclusive RustD cutover gate for CachyOS.
#
# Run this against a snapshot-backed CachyOS VM before enabling RustD on a
# live desktop. Do not proceed until every checklist item prints PASS.

set -Eeuo pipefail

ROOT="${RUSTD_CUTOVER_ROOT:-/}"
RUSTCTL="${RUSTCTL:-${ROOT%/}/usr/bin/rustctl}"
MODE=audit
ATTESTATION="${RUSTD_GRAPHICAL_ATTESTATION:-}"
CERT_REPORT="${RUSTD_CERT_REPORT:-}"
PASS=0
FAIL=0
PENDING=0

usage() {
    cat <<'EOF'
Usage: exclusive-cutover-gate.sh [--audit] [--release]
       [--attestation FILE] [--certification-report FILE]

Audit mode runs diagnostics but can never certify a production cutover.
Release mode requires completed machine certification and root-owned graphical
attestation files in addition to all automated checks.
EOF
}

while (($#)); do
    case "$1" in
        --audit) MODE=audit ;;
        --release) MODE=release ;;
        --attestation)
            (($# >= 2)) || { usage >&2; exit 64; }
            ATTESTATION="$2"
            shift
            ;;
        --certification-report)
            (($# >= 2)) || { usage >&2; exit 64; }
            CERT_REPORT="$2"
            shift
            ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage >&2; exit 64 ;;
    esac
    shift
done

pass() {
    echo "PASS: $*"
    PASS=$((PASS + 1))
}

fail() {
    echo "FAIL: $*" >&2
    FAIL=$((FAIL + 1))
}

pending() {
    echo "PENDING: $*" >&2
    PENDING=$((PENDING + 1))
}

require_cmd() {
    if command -v "$1" >/dev/null 2>&1; then
        pass "command $1 available"
    else
        fail "command $1 missing"
    fi
}

pacman_query() {
    if [[ "$ROOT" == "/" ]]; then
        pacman "$@"
    else
        pacman --root "$ROOT" "$@"
    fi
}

package_installed_exactly() {
    pacman_query -Qq | awk -v wanted="$1" '$0 == wanted { found = 1 } END { exit !found }'
}

scan_live_processes() {
    local exe resolved comm unsafe=0
    if [[ "$ROOT" != "/" ]]; then
        pending "live-process scan requires RUSTD_CUTOVER_ROOT=/"
        return
    fi
    for exe in /proc/[0-9]*/exe; do
        [[ -e "$exe" ]] || continue
        resolved="$(readlink -f -- "$exe" 2>/dev/null || true)"
        [[ -n "$resolved" ]] || continue
        comm=
        if [[ -r "${exe%/exe}/comm" ]]; then
            IFS= read -r comm <"${exe%/exe}/comm" || true
        fi
        case "$comm:$resolved" in
            systemd*:*|systemctl:*|journalctl:*|udevadm:*|*:/usr/lib/systemd/*|*:/usr/bin/systemd*)
                fail "forbidden compatibility process is live: pid=${exe#/proc/} comm=$comm exe=$resolved"
                unsafe=1
                ;;
        esac
    done
    (( unsafe == 0 )) && pass "no compatibility-named processes are live"
}

check_certification_report() {
    if [[ -z "$CERT_REPORT" || ! -r "$CERT_REPORT" ]]; then
        pending "completed installed-certification report not supplied"
        return
    fi
    if grep -Eq '"status":"(fail|pending|skip)"' "$CERT_REPORT"; then
        fail "certification report contains fail, pending, or skipped gates"
    elif grep -q '"status":"pass"' "$CERT_REPORT"; then
        pass "installed certification report contains only completed passing gates"
    else
        fail "certification report has no passing gates"
    fi
}

check_attestation() {
    local key owner mode
    if [[ -z "$ATTESTATION" || ! -r "$ATTESTATION" ]]; then
        pending "graphical cutover attestation not supplied"
        return
    fi
    owner="$(stat -c %u "$ATTESTATION")"
    mode="$(stat -c %a "$ATTESTATION")"
    if [[ "$owner" != 0 || $((8#$mode & 022)) -ne 0 ]]; then
        fail "graphical attestation must be root-owned and not group/other writable"
        return
    fi
    for key in three-cold-boots graphical-login network-dns user-audio \
               lifecycle package-integrity rescue-media; do
        if grep -Fxq "$key=pass" "$ATTESTATION"; then
            pass "manual attestation: $key"
        else
            fail "manual attestation missing: $key=pass"
        fi
    done
}

echo "==> RustD exclusive cutover gate"
echo "    root=$ROOT"
echo "    mode=$MODE"

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

if package_installed_exactly systemd-libs; then
    pass "systemd-libs retained for certified third-party client ABI"
else
    fail "systemd-libs missing before rustd-compat full ABI promotion"
fi

if pacman_query -Q rustd rustd-resolved >/dev/null 2>&1; then
    pass "rustd and rustd-resolved installed"
else
    fail "rustd and/or rustd-resolved not installed"
fi

require_cmd rustctl
require_cmd rustd-resolved
require_cmd rustudevadm

for forbidden_package in systemd systemd-sysvcompat systemd-tools udev; do
    if package_installed_exactly "$forbidden_package"; then
        fail "compatibility package must be supplied by RustD, not installed separately: $forbidden_package"
    else
        pass "no separately installed $forbidden_package package"
    fi
done

# Until the preview shims cover the complete host ABI, the compatibility
# SONAMEs must remain owned by systemd-libs.
for shim in /usr/lib/libsystemd.so.0 /usr/lib/libudev.so.1; do
    if [[ ! -e "${ROOT%/}$shim" ]]; then
        fail "missing compatibility shim: $shim"
    elif pacman_query -Qo "${ROOT%/}$shim" 2>/dev/null | grep -Fq systemd-libs; then
        pass "$shim owned by retained systemd-libs"
    else
        fail "$shim must be owned by retained systemd-libs"
    fi
done

for forbidden_path in \
    /usr/bin/systemctl /usr/bin/journalctl /usr/bin/udevadm \
    /usr/bin/systemd-tmpfiles /usr/lib/systemd; do
    if [[ -e "${ROOT%/}${forbidden_path}" ]]; then
        fail "forbidden compatibility path exists: $forbidden_path"
    else
        pass "forbidden compatibility path absent: $forbidden_path"
    fi
done

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

if [[ -S "${ROOT%/}/run/dbus/system_bus_socket" ]]; then
    pass "system bus socket present"
else
    fail "system bus socket missing"
fi

if [[ -S "${ROOT%/}/run/rustd/ctl.sock" ]]; then
    pass "rustd control socket present"
else
    fail "rustd control socket missing"
fi

if [[ -e "${ROOT%/}/etc/resolv.conf" ]]; then
    pass "/etc/resolv.conf present"
else
    fail "/etc/resolv.conf missing"
fi

if [[ -e "${ROOT%/}/usr/lib/libnss_rustd_dns.so.2" ]] || [[ -e "${ROOT%/}/lib/libnss_rustd_dns.so.2" ]]; then
    pass "libnss_rustd_dns installed"
else
    fail "libnss_rustd_dns missing"
fi
if [[ -e "${ROOT%/}/usr/lib/libnss_resolve.so.2" ]] || [[ -e "${ROOT%/}/usr/lib/libnss_resolve.so" ]]; then
    fail "compatibility libnss_resolve must not be installed"
fi

if [[ -e "${ROOT%/}/usr/lib/security/pam_rustd.so" ]] || [[ -e "${ROOT%/}/lib/security/pam_rustd.so" ]]; then
    pass "pam_rustd.so present"
else
    fail "pam_rustd.so missing"
fi

scan_live_processes
check_certification_report
check_attestation

echo
echo "Summary: $PASS passed, $FAIL failed, $PENDING pending"
if (( FAIL > 0 || PENDING > 0 )); then
    echo "Cutover BLOCKED — do not enable RustD on the live host." >&2
    exit 1
fi
if [[ "$MODE" != release ]]; then
    echo "Audit complete, but production green requires an explicit --release run." >&2
    exit 2
fi
echo "PRODUCTION GREEN: automated, installed-image, and graphical release gates passed."
exit 0
