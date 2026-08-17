#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Installed-image certification harness for RustD.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPORT_DIR="${RUSTD_CERT_REPORT_DIR:-$ROOT/target/certification}"
MODE=release
EVIDENCE="${RUSTD_MACHINE_EVIDENCE:-}"
PERFORMANCE_VOUCHER="${RUSTD_PERFORMANCE_VOUCHER:-}"

usage() {
  cat >&2 <<'EOF'
usage: installed-certification.sh [--audit|--release] [--evidence FILE] [--performance-voucher FILE]
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
      [[ $# -ge 2 ]] || { usage; exit 64; }
      EVIDENCE="$2"
      shift 2
      ;;
    --performance-voucher)
      [[ $# -ge 2 ]] || { usage; exit 64; }
      PERFORMANCE_VOUCHER="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'installed certification: unknown argument %q\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

RUSTD_SHA="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || true)"
RESOLVED_SHA="$(tr -d '[:space:]' <"$ROOT/scripts/rustd-resolved-revision.txt")"
if [[ ! "$RUSTD_SHA" =~ ^[0-9a-f]{40}$ || ! "$RESOLVED_SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo "installed certification: exact RustD/resolver revisions are unavailable" >&2
  exit 2
fi

mkdir -p "$REPORT_DIR"
REPORT="$REPORT_DIR/installed-certification.jsonl"
: >"$REPORT"

log() {
  python3 - "$1" "$2" "$3" "$RUSTD_SHA" "$RESOLVED_SHA" <<'PY' | tee -a "$REPORT"
import json
import sys
import time

gate, status, detail, rustd_sha, resolved_sha = sys.argv[1:]
print(json.dumps({
    "gate": gate,
    "status": status,
    "detail": detail,
    "ts": int(time.time()),
    "rustd_sha": rustd_sha,
    "resolved_sha": resolved_sha,
}, sort_keys=True, separators=(",", ":")))
PY
}

require_bin() {
  command -v "$1" >/dev/null 2>&1
}

if [[ -x "$ROOT/target/release/rustd" ]] || [[ -x /usr/lib/rustd/rustd ]]; then
  log paths pass "rustd binary present for certification"
elif [[ "$MODE" == release ]]; then
  log paths fail "rustd binary is not installed or built for certification"
else
  log paths pending "rustd binary is not installed or built in this audit environment"
fi

if require_bin unshare && unshare --user --map-root-user true 2>/dev/null; then
  log container.user_ns pass "user namespace available for rootless profile"
elif [[ "$MODE" == release ]]; then
  log container.user_ns fail "user namespaces unavailable on release target"
else
  log container.user_ns pending "user namespaces unavailable in audit environment"
fi

if [[ -f /sys/fs/cgroup/cgroup.controllers ]] || [[ -f /sys/fs/cgroup/cgroup.subtree_control ]]; then
  log container.cgroup_v2 pass "cgroup v2 detected"
else
  log container.cgroup_v2 fail "cgroup v2 required for delegated isolation"
fi

required_machine_gates=(
  fault.disk_full_sim
  fault.oom_policy
  fault.signal_storm
  soak.72h
  boot.cold
  boot.reboot
  boot.poweroff
  boot.rescue
  boot.emergency
  boot.reexec
  boot.rollback
  container.rootful
  container.rootless
)

if [[ -n "$EVIDENCE" ]]; then
  normalized="$(mktemp)"
  trap 'rm -f "$normalized"' EXIT
  python3 "$ROOT/scripts/validate-certification-evidence.py" \
    "$EVIDENCE" \
    --expected-rustd-sha "$RUSTD_SHA" \
    --expected-resolved-sha "$RESOLVED_SHA" >"$normalized"
  cat "$normalized" | tee -a "$REPORT"
  rm -f "$normalized"
  trap - EXIT
else
  for gate in "${required_machine_gates[@]}"; do
    log "$gate" pending "requires SHA-bound installed-image campaign evidence"
  done
fi

if [[ -n "$PERFORMANCE_VOUCHER" ]]; then
  normalized="$(mktemp)"
  trap 'rm -f "$normalized"' EXIT
  python3 "$ROOT/scripts/validate-performance-evidence.py" \
    "$PERFORMANCE_VOUCHER" \
    --expected-rustd-sha "$RUSTD_SHA" \
    --expected-resolved-sha "$RESOLVED_SHA" \
    --reference "${RUSTD_SYSTEMD_REF:-systemd 261}" \
    --require-promote >"$normalized"
  log performance.stack pass "comparative performance voucher matches exact RustD stack revisions"
  rm -f "$normalized"
  trap - EXIT
else
  log performance.stack pending "requires exact-SHA comparative performance promotion voucher"
fi

echo "Certification report: $REPORT"

if [[ "$MODE" == audit ]]; then
  echo "Audit complete; release promotion requires all installed-image and performance evidence."
  exit 0
fi

python3 - "$REPORT" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
failures = []
for raw in path.read_text(encoding="utf-8").splitlines():
    if not raw.strip():
        continue
    record = json.loads(raw)
    if record.get("status") != "pass":
        failures.append(f"{record.get('gate', '<unknown>')}={record.get('status', '<missing>')}")
if failures:
    raise SystemExit("release certification incomplete: " + ", ".join(failures))
PY

echo "PRODUCTION GREEN: every installed-image and performance certification gate passed."
