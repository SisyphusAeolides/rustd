#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -Eeuo pipefail

ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT
git -C "$ROOT" init -q
git -C "$ROOT" config user.name tester
git -C "$ROOT" config user.email tester@example.invalid
mkdir -p "$ROOT/certification"
printf 'source\n' > "$ROOT/source.txt"
git -C "$ROOT" add .
git -C "$ROOT" commit -qm source
SOURCE_SHA=$(git -C "$ROOT" rev-parse HEAD)
printf 'status=pass\ntested_sha=%s\n' "$SOURCE_SHA" > "$ROOT/certification/voucher.txt"
git -C "$ROOT" add .
git -C "$ROOT" commit -qm evidence
EVIDENCE_SHA=$(git -C "$ROOT" rev-parse HEAD)

RUSTD_SOURCE_ROOT="$ROOT" scripts/check-voucher-source-equivalence.sh \
    "$ROOT/certification/voucher.txt" "$EVIDENCE_SHA" >/dev/null

printf 'changed\n' >> "$ROOT/source.txt"
git -C "$ROOT" add .
git -C "$ROOT" commit -qm changed
CHANGED_SHA=$(git -C "$ROOT" rev-parse HEAD)
if RUSTD_SOURCE_ROOT="$ROOT" scripts/check-voucher-source-equivalence.sh \
    "$ROOT/certification/voucher.txt" "$CHANGED_SHA" >/dev/null 2>&1; then
    echo 'stale voucher was accepted after a source change' >&2
    exit 1
fi

printf 'status=pass\ntested_sha=invalid\n' > "$ROOT/certification/malformed.txt"
if RUSTD_SOURCE_ROOT="$ROOT" scripts/check-voucher-source-equivalence.sh \
    "$ROOT/certification/malformed.txt" "$CHANGED_SHA" >/dev/null 2>&1; then
    echo 'malformed voucher was accepted' >&2
    exit 1
fi

echo 'voucher source equivalence tests: PASS'
