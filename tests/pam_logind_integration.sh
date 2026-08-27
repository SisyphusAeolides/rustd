#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
rustd_logind=${RUSTD_LOGIND_BIN:-"$repo_root/target/release/rustd-logind"}
pam_module=${PAM_RUSTD_MODULE:-"$repo_root/build/pam_rustd.so"}

test -x "$rustd_logind"
test -f "$pam_module"
test -x "$(command -v dbus-run-session)"
test -x "$(command -v cc)"

work=$(mktemp -d)
cleanup() {
    rm -rf "$work"
}
trap cleanup EXIT HUP INT TERM

cc -std=c17 -Wall -Wextra -Werror tests/pam_logind_probe.c \
    -o "$work/pam-logind-probe" -lpam
mkdir -p "$work/pam-config"
printf 'session required %s\n' "$pam_module" >"$work/pam-config/probe"

dbus-run-session -- bash -s -- \
    "$work" "$rustd_logind" "$work/pam-config" \
    "$(id -un)" "$work/user-runtime" <<'EOF'
set -euo pipefail

work=$1
rustd_logind=$2
pam_config=$3
user=$4
user_runtime=$5

# RustD's logind service intentionally uses the system-bus API.  Point the
# test connection at dbus-run-session's isolated bus rather than the host bus.
export DBUS_SYSTEM_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS"
export RUSTD_LOGIND_RUNTIME="$work/logind-runtime"
export RUSTD_USER_RUNTIME_ROOT="$user_runtime"

"$rustd_logind" >"$work/rustd-logind.log" 2>&1 &
daemon_pid=$!
cleanup_daemon() {
    kill "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
}
trap cleanup_daemon EXIT HUP INT TERM

for attempt in $(seq 1 100); do
    if gdbus introspect --session \
        --dest io.rustd.Login1 \
        --object-path /io/rustd/Login1 >/dev/null 2>&1; then
        break
    fi
    if ! kill -0 "$daemon_pid" 2>/dev/null; then
        cat "$work/rustd-logind.log" >&2
        exit 1
    fi
    sleep 0.1
done

test -d "$RUSTD_LOGIND_RUNTIME"
"$work/pam-logind-probe" "$user" "$pam_config"
EOF
