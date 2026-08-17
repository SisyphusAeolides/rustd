#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Installed-image certification harness for RustD.
#
# Exercises what can be validated on the current host and records a machine-
# readable report for VM/bare-metal/container gates. Full 72-hour soak is
# opt-in via RUSTD_SOAK_SECONDS (default 60s local smoke).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPORT_DIR="${RUSTD_CERT_REPORT_DIR:-$ROOT/target/certification}"
SOAK_SECONDS="${RUSTD_SOAK_SECONDS:-60}"
MODE=audit

case "${1:-}" in
  "") ;;
  --audit) MODE=audit ;;
  --release) MODE=release ;;
  -h|--help)
    echo "Usage: $0 [--audit|--release]"
    exit 0
    ;;
  *)
    echo "Usage: $0 [--audit|--release]" >&2
    exit 64
    ;;
esac

mkdir -p "$REPORT_DIR"
REPORT="$REPORT_DIR/installed-certification.jsonl"
: >"$REPORT"

log() {
  local gate="$1" status="$2" detail="$3"
  printf '{"gate":"%s","status":"%s","detail":%s,"ts":%s}\n' \
    "$gate" "$status" "$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$detail")" \
    "$(date +%s)" | tee -a "$REPORT"
}

require_bin() {
  command -v "$1" >/dev/null 2>&1
}

# --- Package / path identity -------------------------------------------------
if [[ -x "$ROOT/target/release/rustd" ]] || [[ -x /usr/lib/rustd/rustd ]]; then
  log paths pass "rustd binary present for certification"
else
  log paths skip "rustd binary not installed in this environment"
fi

# --- Container profile matrix ------------------------------------------------
if require_bin unshare && unshare --user --map-root-user true 2>/dev/null; then
  log container.user_ns pass "user namespace available for rootless profile"
else
  log container.user_ns skip "user namespaces unavailable"
fi

if [[ -f /sys/fs/cgroup/cgroup.controllers ]] || [[ -f /sys/fs/cgroup/cgroup.subtree_control ]]; then
  log container.cgroup_v2 pass "cgroup v2 detected"
else
  log container.cgroup_v2 fail "cgroup v2 required for delegated isolation"
fi

# --- Fault injection smokes --------------------------------------------------
python3 - "$REPORT" <<'PY'
import json, sys, time, pathlib
report = pathlib.Path(sys.argv[1])
cases = [
    ("fault.disk_full_sim", "skip", "requires destructive installed-image fault injection"),
    ("fault.oom_policy", "skip", "requires installed-image OOM pressure injection"),
    ("fault.signal_storm", "skip", "requires installed-image concurrent child stress"),
]
with report.open("a", encoding="utf-8") as fh:
    for gate, status, detail in cases:
        fh.write(json.dumps({"gate": gate, "status": status, "detail": detail, "ts": int(time.time())}) + "\n")
        print(f"{status.upper()}: {gate}: {detail}")
PY

# --- Soak --------------------------------------------------------------------
if [[ "$MODE" == release && "$SOAK_SECONDS" -lt 259200 ]]; then
  log soak.duration fail "release certification requires at least 259200 seconds (72 hours)"
else
  log soak.duration pass "configured soak duration is ${SOAK_SECONDS}s"
fi
log soak.start pass "running ${SOAK_SECONDS}s soak"
start=$(date +%s)
deadline=$((start + SOAK_SECONDS))
samples=0
while (( $(date +%s) < deadline )); do
  # Lightweight control-plane liveness probe: spawn helper stress binary when present.
  if [[ -x "$ROOT/build/test_spawn" ]]; then
    "$ROOT/build/test_spawn" >/dev/null
  else
    sleep 1
  fi
  samples=$((samples + 1))
done
log soak.complete pass "completed ${samples} soak iterations over ${SOAK_SECONDS}s"

# --- Boot/reboot matrix placeholders for VM/bare-metal runners ---------------
for gate in boot.cold boot.reboot boot.poweroff boot.rescue boot.emergency boot.reexec \
            boot.rollback container.rootful container.rootless; do
  log "$gate" pending "requires snapshot-backed CachyOS VM or bare-metal runner"
done

echo "Certification report: $REPORT"
if grep -q '"status":"fail"' "$REPORT"; then
  echo "One or more certification gates failed" >&2
  exit 1
fi
if grep -Eq '"status":"(pending|skip)"' "$REPORT"; then
  echo "Certification is incomplete; pending or skipped gates cannot be promoted." >&2
  exit 2
fi
if [[ "$MODE" != release ]]; then
  echo "Audit complete; production certification requires an explicit --release run." >&2
  exit 2
fi
echo "PRODUCTION GREEN: every installed-image certification gate passed."
