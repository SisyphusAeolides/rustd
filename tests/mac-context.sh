#!/usr/bin/env sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/rustd-mac-context.XXXXXX")
cleanup() { rm -rf "$build"; }
trap cleanup EXIT HUP INT TERM

compiler=${CC:-cc}
"$compiler" -std=c17 -O2 -Wall -Wextra -Werror -Wpedantic \
    -I"$root/ffi" \
    "$root/tests/test-mac-context.c" \
    "$root/ffi/spawn.c" \
    "$root/ffi/sandbox.c" \
    "$root/ffi/socket_activation.c" \
    "$root/ffi/seccomp.c" \
    "$root/ffi/capability.c" \
    -ldl -o "$build/test-mac-context"
"$build/test-mac-context"
