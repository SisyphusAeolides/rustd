#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Validate RustD-owned libsystemd/libudev compatibility SONAMEs for a full cutover.
set -euo pipefail

SOURCE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="${1:-}"
if [[ -z "$ROOT" ]]; then
    echo "usage: $0 <prefix-or-destdir-prefix>" >&2
    exit 64
fi

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }

lib_path() {
    local name="$1"
    if [[ -e "$ROOT/lib/$name" ]]; then
        printf '%s\n' "$ROOT/lib/$name"
    elif [[ -e "$ROOT/lib64/$name" ]]; then
        printf '%s\n' "$ROOT/lib64/$name"
    else
        return 1
    fi
}

systemd_lib="$(lib_path libsystemd.so.0)" || fail "missing RustD compatibility libsystemd.so.0"
udev_lib="$(lib_path libudev.so.1)" || fail "missing RustD compatibility libudev.so.1"

readelf -d "$systemd_lib" | grep -Fq 'Library soname: [libsystemd.so.0]' \
    || fail "libsystemd.so.0 has the wrong SONAME"
readelf -d "$udev_lib" | grep -Fq 'Library soname: [libudev.so.1]' \
    || fail "libudev.so.1 has the wrong SONAME"
pass "compatibility SONAMEs are correct"

# A RustD compatibility library must never resolve through the systemd/udev
# libraries it is replacing. RustD native libraries, libc, libdbus and json-c
# are legitimate dependencies of the compatibility implementation.
if readelf -d "$systemd_lib" "$udev_lib" | grep -Eq \
    'Shared library: \[(libsystemd\.so|libudev\.so)'; then
    fail "compatibility library depends on the systemd/udev library being replaced"
fi
pass "compatibility libraries have no systemd/udev runtime dependency"

systemd_symbols="$(nm -D --defined-only "$systemd_lib")"
udev_symbols="$(nm -D --defined-only "$udev_lib")"
missing=0
while IFS= read -r symbol; do
    [[ -n "$symbol" && "${symbol:0:1}" != '#' ]] || continue
    case "$symbol" in
        udev_*) symbols="$udev_symbols" ;;
        sd_*) symbols="$systemd_symbols" ;;
        *) continue ;;
    esac
    if ! grep -Eq "[[:space:]][TDRB] ${symbol}(@@|$)" <<<"$symbols"; then
        echo "missing installed compatibility symbol: $symbol" >&2
        missing=1
    fi
done < "$SOURCE_ROOT/libs/compat/needed_syms.txt"
(( missing == 0 )) || fail "installed compatibility symbol set is incomplete"
pass "installed compatibility symbol set is complete"

if [[ -L "$ROOT/lib/libsystemd.so" || -L "$ROOT/lib64/libsystemd.so" || \
      -L "$ROOT/lib/libudev.so" || -L "$ROOT/lib64/libudev.so" ]]; then
    pass "optional unversioned compatibility development links present"
fi

pass "RustD compatibility libraries are ready to replace systemd-libs runtime SONAMEs"
