#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Reject certification vouchers issued for a different source revision.
set -Eeuo pipefail

SOURCE_ROOT="${RUSTD_SOURCE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
VOUCHER=${1:?usage: check-voucher-source-equivalence.sh VOUCHER [EXPECTED_SHA]}
EXPECTED_SHA=${2:-$(git -C "$SOURCE_ROOT" rev-parse HEAD)}

fail() {
    printf 'voucher source equivalence: %s\n' "$*" >&2
    exit 1
}

[[ -r $VOUCHER ]] || fail "voucher is unreadable: $VOUCHER"
[[ $EXPECTED_SHA =~ ^[0-9a-f]{40}$ ]] || fail 'expected revision is not a full commit ID'
git -C "$SOURCE_ROOT" cat-file -e "$EXPECTED_SHA^{commit}" 2>/dev/null \
    || fail 'expected revision is not available in the source repository'

mapfile -t tested_lines < <(sed -n 's/^tested_sha=//p' "$VOUCHER")
(( ${#tested_lines[@]} == 1 )) || fail 'voucher must contain exactly one tested_sha field'
TESTED_SHA=${tested_lines[0]}
[[ $TESTED_SHA =~ ^[0-9a-f]{40}$ ]] || fail 'tested_sha is not a full commit ID'
git -C "$SOURCE_ROOT" cat-file -e "$TESTED_SHA^{commit}" 2>/dev/null \
    || fail 'tested_sha is not available in the source repository'
git -C "$SOURCE_ROOT" merge-base --is-ancestor "$TESTED_SHA" "$EXPECTED_SHA" \
    || fail 'tested_sha is not an ancestor of the expected revision'

# Evidence publishers intentionally add commits after the revision they tested.
# Such descendants remain equivalent only when every intervening path is
# certification evidence; source, packaging, workflow, and test changes make
# the voucher stale.
if ! git -C "$SOURCE_ROOT" diff --quiet "$TESTED_SHA" "$EXPECTED_SHA" -- \
    . ':(exclude)certification/**'; then
    fail 'non-certification files changed after tested_sha'
fi

printf 'voucher source equivalence: PASS (%s)\n' "$TESTED_SHA"
