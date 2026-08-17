#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail

if [[ -z "${DESTDIR:-}" || "${DESTDIR}" == "/" || "${DESTDIR}" != /* ]]; then
    printf '%s\n' 'DESTDIR must name an absolute, non-root staging directory' >&2
    exit 64
fi

prefix="${PREFIX:-/usr}"
builddir="${BUILDDIR:-target/release}"
native_libexec="${RUSTLIBEXECDIR:-${prefix}/lib/rustd}"
apparmor_dir="${APPARMORDIR:-/etc/apparmor.d}"

if [[ "${prefix}" != /* || "${native_libexec}" != /* || "${apparmor_dir}" != /* ]]; then
    printf '%s\n' 'PREFIX, RUSTLIBEXECDIR, and APPARMORDIR must be absolute paths' >&2
    exit 64
fi

python3 scripts/install-executable-surfaces.py \
    --build-directory "${builddir}" \
    --destdir "${DESTDIR}" \
    --prefix "${prefix}" \
    --native-libexec-directory "${native_libexec}"

profile_source="packaging/apparmor/usr.bin.rustd-nspawn"
profile_target="${DESTDIR}${apparmor_dir}/usr.bin.rustd-nspawn"
[[ -f "${profile_source}" ]] || {
    printf 'missing RustD nspawn AppArmor profile: %s\n' "${profile_source}" >&2
    exit 1
}
install -d -m0755 "$(dirname "${profile_target}")"
python3 - "${profile_source}" "${profile_target}" "${prefix}/bin/rustd-nspawn" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1])
target = Path(sys.argv[2])
executable = sys.argv[3]
text = source.read_text(encoding="utf-8")
needle = "/usr/bin/rustd-nspawn flags=(unconfined) {"
replacement = f"{executable} flags=(unconfined) {{"
if text.count(needle) != 1:
    raise SystemExit("RustD nspawn AppArmor template attachment is not unique")
target.write_text(text.replace(needle, replacement, 1), encoding="utf-8")
target.chmod(0o644)
PY
