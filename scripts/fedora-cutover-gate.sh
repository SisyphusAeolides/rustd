#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Fedora-exclusive RustD cutover gate. Fails closed on any remaining systemd
# package/runtime dependency or un-replaced host capability.
set -Eeuo pipefail

SOURCE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE=audit
CERT_REPORT=${RUSTD_CERT_REPORT:-}
GRAPHICAL_ATTESTATION=${RUSTD_GRAPHICAL_ATTESTATION:-}
PASS=0
FAIL=0
PENDING=0

usage() {
    cat <<'EOF'
Usage: fedora-cutover-gate.sh [--audit|--release]
       [--certification-report FILE] [--attestation FILE]

Audit mode reports blockers. Release mode succeeds only when the Fedora host is
fully RustD-owned and exact-stack machine/performance evidence is supplied.
EOF
}

while (($#)); do
    case "$1" in
        --audit) MODE=audit ;;
        --release) MODE=release ;;
        --certification-report) shift; CERT_REPORT=${1:?missing report} ;;
        --attestation) shift; GRAPHICAL_ATTESTATION=${1:?missing attestation} ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage >&2; exit 64 ;;
    esac
    shift
done

pass() { printf 'PASS: %s\n' "$*"; PASS=$((PASS+1)); }
fail() { printf 'FAIL: %s\n' "$*" >&2; FAIL=$((FAIL+1)); }
pending() { printf 'PENDING: %s\n' "$*" >&2; PENDING=$((PENDING+1)); }

require_cmd() {
    command -v "$1" >/dev/null 2>&1 && pass "command $1 available" || fail "command $1 missing"
}

if [[ ! -r /etc/os-release ]]; then
    fail '/etc/os-release is unavailable'
else
    # shellcheck disable=SC1091
    . /etc/os-release
    [[ ${ID:-} == fedora ]] && pass "Fedora host detected (${VERSION_ID:-unknown})" || fail "host is not Fedora"
fi

for cmd in rpm dnf readelf nm rustctl rustd-resolvectl getenforce semodule; do require_cmd "$cmd"; done

# Fedora production cutover must preserve SELinux enforcement and load the
# RustD policy extension. A permissive/unloaded policy is never release-green.
selinux_mode="$(getenforce 2>/dev/null || true)"
if [[ $selinux_mode == Enforcing ]]; then
    pass 'SELinux is enforcing'
else
    fail "SELinux is not enforcing (mode=${selinux_mode:-unknown})"
fi
if rpm -q rustd-selinux >/dev/null 2>&1; then
    pass 'rustd-selinux RPM installed'
else
    fail 'rustd-selinux RPM is not installed'
fi
if semodule -l 2>/dev/null | awk '{print $1}' | grep -Fxq rustd_fedora; then
    pass 'rustd_fedora SELinux module loaded'
else
    fail 'rustd_fedora SELinux module is not loaded'
fi

# Full release means zero installed systemd RPMs, not merely a different PID 1.
mapfile -t systemd_pkgs < <(rpm -qa --qf '%{NAME}\n' | awk '/^systemd($|-)/' | sort -u)
if ((${#systemd_pkgs[@]})); then
    if [[ $MODE == release ]]; then
        fail "systemd RPMs remain installed: ${systemd_pkgs[*]}"
    else
        pending "systemd RPMs still installed before cutover: ${systemd_pkgs[*]}"
    fi
else
    pass 'no systemd RPMs installed'
fi

# DNF/RPM dependency graph must remain internally consistent after the swap.
if dnf -q check >/tmp/rustd-fedora-dnf-check.out 2>&1; then
    pass 'dnf dependency check clean'
else
    fail "dnf dependency check failed: $(tail -n 20 /tmp/rustd-fedora-dnf-check.out | tr '\n' ' ')"
fi

owner_matches() {
    local path=$1 pattern=$2 owner
    if [[ ! -e $path && ! -L $path ]]; then
        fail "required cutover path missing: $path"
        return
    fi
    owner=$(rpm -qf --qf '%{NAME}\n' "$path" 2>/dev/null || true)
    if [[ $owner =~ $pattern ]]; then
        pass "$path owned by $owner"
    else
        fail "$path is not RustD package-owned (owner=${owner:-none})"
    fi
}

symlink_target_matches() {
    local path=$1 expected=$2 target
    if [[ ! -L $path ]]; then
        fail "$path is not a compatibility symlink"
        return
    fi
    target=$(readlink -f "$path" 2>/dev/null || true)
    if [[ $target == "$expected" ]]; then
        pass "$path resolves to $expected"
    else
        fail "$path resolves to ${target:-unknown}, expected $expected"
    fi
}

owner_matches /usr/sbin/init '^rustd-fedora-compat$'
owner_matches /usr/sbin/rustd-fedora-cutover '^rustd-cutover-tools$'
owner_matches /usr/lib64/security/pam_rustd.so '^rustd-cutover-tools$'
owner_matches /usr/lib64/libnss_rustd_dns.so.2 '^rustd-resolved-nss$'
owner_matches /usr/lib64/libsystemd.so.0 '^rustd-compat-libs$'
owner_matches /usr/lib64/libudev.so.1 '^rustd-compat-libs$'
for path in /usr/bin/systemctl /usr/lib/systemd/systemd-update-helper \
            /usr/bin/systemd-tmpfiles /usr/bin/systemd-sysusers \
            /usr/lib/systemd/systemd-sysctl /usr/lib/systemd/systemd-binfmt \
            /usr/lib/systemd/systemd-udevd /usr/bin/udevadm; do
    owner_matches "$path" '^rustd-fedora-compat$'
done
symlink_target_matches /usr/sbin/init /usr/lib/rustd/rustd
if [[ -f /usr/lib/systemd/systemd-udevd && ! -L /usr/lib/systemd/systemd-udevd && \
      -x /usr/lib/systemd/systemd-udevd ]] &&
   grep -Fq 'exec /usr/lib/rustd/rustd-udevd' /usr/lib/systemd/systemd-udevd; then
    pass '/usr/lib/systemd/systemd-udevd is a RustD wrapper'
else
    fail '/usr/lib/systemd/systemd-udevd is not an executable RustD wrapper'
fi

# PID 1 must be RustD itself.
pid1=$(readlink -f /proc/1/exe 2>/dev/null || true)
if [[ $pid1 == /usr/lib/rustd/rustd ]]; then
    pass 'PID 1 is RustD'
else
    fail "PID 1 is not RustD (exe=${pid1:-unknown})"
fi

# No live process may execute binaries from a removed systemd package tree.
unsafe=0
for exe in /proc/[0-9]*/exe; do
    [[ -e $exe ]] || continue
    target=$(readlink -f "$exe" 2>/dev/null || true)
    case "$target" in
        /usr/lib/systemd/*|/usr/bin/systemd*|/usr/lib64/systemd/*)
            # RustD-owned Fedora transaction frontends are shell scripts and
            # therefore do not appear as process executables here.
            fail "systemd-named executable is live: ${exe#/proc/} -> $target"
            unsafe=1
            ;;
    esac
done
((unsafe == 0)) && pass 'no systemd runtime processes are live'

# Fedora's systemd-libs normally supplies myhostname/resolve/systemd NSS
# modules. A zero-systemd host must not reference those modules.
if grep -Eq '^hosts:.*\b(myhostname|resolve|systemd)\b' /etc/nsswitch.conf; then
    fail 'hosts NSS line still references a systemd NSS module'
elif grep -Eq '^hosts:.*\brustd_dns\b' /etc/nsswitch.conf; then
    pass 'hosts NSS line is RustD-backed'
else
    fail 'hosts NSS line does not include rustd_dns'
fi
if grep -Eq '^[[:alpha:]_][[:alnum:]_-]*:.*\bsystemd\b' /etc/nsswitch.conf; then
    fail 'NSS configuration still references libnss_systemd'
else
    pass 'NSS configuration does not require libnss_systemd'
fi

# PAM cannot keep loading modules owned by the removed systemd-pam RPM.
pam_hits=$(grep -R -nE 'pam_systemd(_home|_loadkey)?\.so' /etc/pam.d 2>/dev/null || true)
if [[ -n $pam_hits ]]; then
    fail "PAM still references systemd modules: $(printf '%s' "$pam_hits" | head -n 10 | tr '\n' ' ')"
else
    pass 'PAM configuration contains no systemd PAM modules'
fi
if find /usr/lib64/security -maxdepth 1 -name 'pam_systemd*.so' -print -quit 2>/dev/null | grep -q .; then
    fail 'systemd PAM module files remain installed'
else
    pass 'systemd PAM module files absent'
fi
[[ -e /usr/lib64/security/pam_rustd.so ]] && pass 'pam_rustd.so installed' || fail 'pam_rustd.so missing'

# Refuse removal when an existing LUKS2 volume uses token types whose Fedora
# implementation currently comes from systemd-udev. This is an operational
# dependency that RPM cannot discover.
if command -v cryptsetup >/dev/null 2>&1 && command -v lsblk >/dev/null 2>&1; then
    token_block=0
    while read -r device fstype; do
        [[ $fstype == crypto_LUKS && -b $device ]] || continue
        dump=$(cryptsetup luksDump --dump-json-metadata "$device" 2>/dev/null || true)
        if grep -Eq '"type"[[:space:]]*:[[:space:]]*"systemd-(fido2|tpm2|pkcs11)"' <<<"$dump"; then
            fail "$device uses a systemd cryptsetup token without a certified RustD token plugin"
            token_block=1
        fi
    done < <(lsblk -rno PATH,FSTYPE 2>/dev/null || true)
    ((token_block == 0)) && pass 'no LUKS2 systemd token dependency detected'
else
    pending 'cryptsetup/lsblk unavailable; LUKS token audit not run'
fi

# Compatibility ELF version namespaces required by Fedora 43/44. Symbol-level
# coverage is separately checked against RustD's measured ABI list.
if [[ -e /usr/lib64/libsystemd.so.0 ]]; then
    version_text=$(readelf --version-info /usr/lib64/libsystemd.so.0 2>/dev/null || true)
    max_systemd=258
    [[ ${VERSION_ID:-0} =~ ^[0-9]+$ && ${VERSION_ID:-0} -ge 44 ]] && max_systemd=259
    missing_versions=0
    for version in 209 211 213 214 216 217 219 220 221 222 226 227 229 230 231 232 233 234 235 236 237 238 239 240 241 242 243 244 245 246 247 248 249 250 251 252 253 254 255 256 257 258; do
        (( version <= max_systemd )) || continue
        if ! grep -Fq "LIBSYSTEMD_$version" <<<"$version_text"; then
            fail "libsystemd.so.0 lacks Fedora version node LIBSYSTEMD_$version"
            missing_versions=1
        fi
    done
    if (( max_systemd >= 259 )) && ! grep -Fq 'LIBSYSTEMD_259' <<<"$version_text"; then
        fail 'libsystemd.so.0 lacks Fedora version node LIBSYSTEMD_259'
        missing_versions=1
    fi
    ((missing_versions == 0)) && pass 'libsystemd Fedora symbol-version namespaces present'
fi
if [[ -e /usr/lib64/libudev.so.1 ]]; then
    version_text=$(readelf --version-info /usr/lib64/libudev.so.1 2>/dev/null || true)
    missing_versions=0
    for version in 183 189 196 199 215 247; do
        if ! grep -Fq "LIBUDEV_$version" <<<"$version_text"; then
            fail "libudev.so.1 lacks Fedora version node LIBUDEV_$version"
            missing_versions=1
        fi
    done
    ((missing_versions == 0)) && pass 'libudev Fedora symbol-version namespaces present'
fi

if [[ -x $SOURCE_ROOT/scripts/check-compat-libs.sh ]]; then
    if "$SOURCE_ROOT/scripts/check-compat-libs.sh" /usr; then
        pass 'installed RustD compatibility libraries pass symbol audit'
    else
        fail 'installed RustD compatibility library audit failed'
    fi
fi

# Resolver/NSS runtime checks.
if rustctl --quiet is-active rustd-resolved.service >/dev/null 2>&1; then
    pass 'rustd-resolved service active'
else
    fail 'rustd-resolved service inactive'
fi
if getent hosts localhost >/dev/null 2>&1 && getent hosts "$(hostname)" >/dev/null 2>&1; then
    pass 'localhost and machine hostname resolve through NSS'
else
    fail 'NSS localhost/machine-hostname resolution failed'
fi

# Exact-stack installed certification remains mandatory.
if [[ -z $CERT_REPORT || ! -r $CERT_REPORT ]]; then
    pending 'exact-stack installed certification report not supplied'
else
    rustd_sha=$(git -C "$SOURCE_ROOT" rev-parse HEAD 2>/dev/null || true)
    resolved_sha=$(tr -d '[:space:]' < "$SOURCE_ROOT/scripts/rustd-resolved-revision.txt" 2>/dev/null || true)
    if python3 "$SOURCE_ROOT/scripts/validate-installed-certification-report.py" \
        "$CERT_REPORT" --expected-rustd-sha "$rustd_sha" --expected-resolved-sha "$resolved_sha" >/dev/null; then
        pass 'installed certification matches the exact RustD/Resolved pair'
    else
        fail 'installed certification is missing, stale, insecure, or for another stack'
    fi
fi

if [[ -z $GRAPHICAL_ATTESTATION || ! -r $GRAPHICAL_ATTESTATION ]]; then
    pending 'Fedora graphical/audio/update attestation not supplied'
else
    for key in three-cold-boots graphical-login network-dns user-audio dnf-update suspend-resume rescue-media; do
        grep -Fxq "$key=pass" "$GRAPHICAL_ATTESTATION" \
            && pass "manual attestation: $key" \
            || fail "manual attestation missing: $key=pass"
    done
fi

echo "Summary: $PASS passed, $FAIL failed, $PENDING pending"
if ((FAIL > 0 || PENDING > 0)); then
    echo 'FEDORA CUTOVER BLOCKED — retain a known-good boot/recovery path.' >&2
    exit 1
fi
if [[ $MODE != release ]]; then
    echo 'Audit passed, but production cutover requires --release.' >&2
    exit 2
fi
echo 'FEDORA PRODUCTION GREEN: exact-stack, RPM, NSS, PAM, ABI, boot and graphical gates passed.'
