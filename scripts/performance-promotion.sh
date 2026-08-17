#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Comparative release-performance promotion for the exact RustD stack revision.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${RUSTD_BENCH_DIR:-$ROOT/target/benchmarks}"
MODE=audit
EVIDENCE="${RUSTD_PERF_EVIDENCE:-}"
REFERENCE="${RUSTD_SYSTEMD_REF:-systemd 261}"

usage() {
  cat >&2 <<'EOF'
usage: performance-promotion.sh [--audit|--release] [--evidence FILE]
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --audit)
      MODE=audit
      shift
      ;;
    --release)
      MODE=release
      shift
      ;;
    --evidence)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      EVIDENCE="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'performance promotion: unknown argument %q\n' "$1" >&2
      usage
      exit 2
      ;;
  esac
done

RUSTD_SHA="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || true)"
RESOLVED_SHA="$(tr -d '[:space:]' <"$ROOT/scripts/rustd-resolved-revision.txt")"
if [[ ! "$RUSTD_SHA" =~ ^[0-9a-f]{40}$ || ! "$RESOLVED_SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo "performance promotion: exact RustD/resolver revisions are unavailable" >&2
  exit 2
fi

mkdir -p "$OUT"

if [[ "$MODE" == audit ]]; then
  cat <<EOF
Performance audit wiring is available.
RustD SHA:     $RUSTD_SHA
Resolver SHA:  $RESOLVED_SHA
Reference:     $REFERENCE
Release promotion requires --release plus a real paired lab evidence file.
No synthetic baseline or promotion voucher is produced in audit mode.
EOF
  exit 0
fi

if [[ -z "$EVIDENCE" ]]; then
  echo "performance promotion: release requires RUSTD_PERF_EVIDENCE or --evidence FILE" >&2
  exit 2
fi

voucher="$OUT/PROMOTE-${RUSTD_SHA:0:12}-${RESOLVED_SHA:0:12}.json"
temporary="$(mktemp "$OUT/.promotion.XXXXXX")"
trap 'rm -f "$temporary"' EXIT

python3 "$ROOT/scripts/validate-performance-evidence.py" \
  "$EVIDENCE" \
  --expected-rustd-sha "$RUSTD_SHA" \
  --expected-resolved-sha "$RESOLVED_SHA" \
  --reference "$REFERENCE" >"$temporary"

chmod 0600 "$temporary"
mv -f "$temporary" "$voucher"
trap - EXIT

echo "Performance contract met for exact RustD stack revisions."
echo "Promotion voucher: $voucher"
