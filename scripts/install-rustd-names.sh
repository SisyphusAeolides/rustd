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

exec python3 scripts/install-executable-surfaces.py \
    --build-directory "${builddir}" \
    --destdir "${DESTDIR}" \
    --prefix "${prefix}" \
    --native-libexec-directory "${native_libexec}"
