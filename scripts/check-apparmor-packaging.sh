#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail

work=$(mktemp -d)
cleanup() {
    rm -rf "${work}"
}
trap cleanup EXIT HUP INT TERM

builddir="${work}/build"
stage="${work}/stage"
mkdir -p "${builddir}" "${stage}"

python3 - "${builddir}" <<'PY'
from pathlib import Path
import sys

from scripts.executable_contract import NATIVE_BUILD_ALIASES, NATIVE_EXECUTABLES

build = Path(sys.argv[1])
for native in NATIVE_EXECUTABLES:
    name = NATIVE_BUILD_ALIASES.get(native, native)
    path = build / name
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
PY

DESTDIR="${stage}" \
PREFIX=/opt/rustd \
RUSTLIBEXECDIR=/opt/rustd/lib/rustd \
BUILDDIR="${builddir}" \
bash scripts/install-rustd-names.sh >/dev/null

profile="${stage}/etc/apparmor.d/usr.bin.rustd-nspawn"
[[ -f "${profile}" ]]
[[ "$(stat -c %a "${profile}")" == 644 ]]
grep -Fq '/opt/rustd/bin/rustd-nspawn flags=(unconfined) {' "${profile}"
grep -Fq '  userns,' "${profile}"
[[ -x "${stage}/opt/rustd/bin/rustd-nspawn" ]]

echo 'RustD nspawn AppArmor packaging contract passed'
