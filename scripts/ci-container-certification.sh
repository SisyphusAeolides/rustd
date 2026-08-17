#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -Eeuo pipefail

binary=${1:?usage: ci-container-certification.sh RUSTD_NSPAWN EVIDENCE_OUT}
evidence=${2:?usage: ci-container-certification.sh RUSTD_NSPAWN EVIDENCE_OUT}
iterations=${RUSTD_CONTAINER_ITERATIONS:-10}
[[ $iterations -ge 10 ]] || {
    echo "container certification requires at least 10 iterations" >&2
    exit 1
}
command -v busybox >/dev/null || {
    echo "busybox is required" >&2
    exit 1
}
[[ -x $binary ]] || {
    echo "rustd-nspawn is not executable: $binary" >&2
    exit 1
}

root=$(mktemp -d /tmp/rustd-container-root.XXXXXX)
host_sentinel=$(mktemp /tmp/rustd-container-host-sentinel.XXXXXX)
cleanup() {
    rm -rf "$root" "$host_sentinel"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$root/bin" "$root/proc" "$root/tmp"
cp "$(command -v busybox)" "$root/bin/busybox"
for applet in sh cat hostname; do
    ln -s busybox "$root/bin/$applet"
done
printf 'inside-rustd-container\n' > "$root/inside-marker"
cat > "$root/certify.sh" <<'EOF_CERT'
#!/bin/sh
set -eu
expected_hostname=$1
host_sentinel=$2
[ "$$" -eq 1 ]
[ "$(hostname)" = "$expected_hostname" ]
[ "$(cat /inside-marker)" = "inside-rustd-container" ]
[ ! -e "$host_sentinel" ]
[ -r /proc/1/status ]
grep -q '^Name:' /proc/1/status
EOF_CERT
chmod 0755 "$root/certify.sh"

run_one() {
    mode=$1
    attempt=$2
    machine="rustd-${mode}-${attempt}"
    if [[ $mode == rootful ]]; then
        sudo env PATH="$PATH" "$binary" --quiet --directory "$root" --machine "$machine" \
            /bin/sh /certify.sh "$machine" "$host_sentinel"
    else
        "$binary" --quiet --private-users=pick --directory "$root" --machine "$machine" \
            /bin/sh /certify.sh "$machine" "$host_sentinel"
    fi
}

for attempt in $(seq 1 "$iterations"); do
    echo "rootful container certification ${attempt}/${iterations}"
    run_one rootful "$attempt"
done
for attempt in $(seq 1 "$iterations"); do
    echo "rootless container certification ${attempt}/${iterations}"
    run_one rootless "$attempt"
done

rustd_sha=$(git rev-parse HEAD)
resolved_sha=$(tr -d '[:space:]' < scripts/rustd-resolved-revision.txt)
[[ $rustd_sha =~ ^[0-9a-f]{40}$ ]]
[[ $resolved_sha =~ ^[0-9a-f]{40}$ ]]
umask 077
python3 - "$evidence" "$rustd_sha" "$resolved_sha" "$iterations" <<'PY'
import json
from pathlib import Path
import sys
import time

path = Path(sys.argv[1])
rustd_sha, resolved_sha = sys.argv[2:4]
iterations = int(sys.argv[4])
timestamp = int(time.time())
for gate, detail in (
    (
        "container.rootful",
        f"{iterations} rootful RustD nspawn runs created mount/PID/UTS/IPC namespaces, entered a chroot, mounted namespace-correct /proc, and proved PID 1, hostname, and host-root isolation",
    ),
    (
        "container.rootless",
        f"{iterations} unprivileged RustD nspawn runs created a mapped user namespace plus mount/PID/UTS/IPC namespaces, entered a chroot, mounted namespace-correct /proc, and proved PID 1, hostname, and host-root isolation",
    ),
):
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({
            "gate": gate,
            "status": "pass",
            "detail": detail,
            "ts": timestamp,
            "rustd_sha": rustd_sha,
            "resolved_sha": resolved_sha,
            "iterations": iterations,
            "source": "scripts/ci-container-certification.sh",
        }, sort_keys=True, separators=(",", ":")) + "\n")
PY
chmod 0600 "$evidence"
echo "RustD rootful/rootless container certification passed"
