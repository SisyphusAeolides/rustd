#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Validate installed RustD native shared libraries and devel surface.
set -euo pipefail

ROOT="${1:-}"
if [[ -z "$ROOT" ]]; then
  echo "usage: $0 <prefix-or-destdir-prefix>" >&2
  exit 64
fi

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }

for lib in librustd_service librustd_journal librustd_device librustd_login librustd_manager; do
  [[ -e "$ROOT/lib/$lib.so.1" || -e "$ROOT/lib64/$lib.so.1" ]] \
    || fail "missing $lib.so.1"
  path="$ROOT/lib/$lib.so.1"
  [[ -e "$path" ]] || path="$ROOT/lib64/$lib.so.1"
  readelf -d "$path" | grep -Fq "Library soname: [$lib.so.1]" \
    || fail "$lib has wrong SONAME"
  if nm -D --defined-only "$path" | awk '{print $3}' | grep -E '^(sd_|udev_)'; then
    fail "$lib exports forbidden sd_/udev_ symbols"
  fi
  pass "$lib SONAME and symbol policy"
done

for hdr in service.h journal.h device.h login.h manager.h; do
  [[ -f "$ROOT/include/rustd/$hdr" ]] || fail "missing include/rustd/$hdr"
done
pass "public headers installed"

for pc in rustd-service rustd-journal rustd-device rustd-login rustd-manager; do
  [[ -f "$ROOT/lib/pkgconfig/$pc.pc" || -f "$ROOT/lib64/pkgconfig/$pc.pc" ]] \
    || fail "missing $pc.pc"
done
pass "pkg-config files installed"

if find "$ROOT" \( -name 'libsystemd.so*' -o -name 'libudev.so*' \) | grep -q .; then
  fail "forbidden systemd/udev library names present under $ROOT"
fi
pass "no libsystemd/libudev artifacts"
