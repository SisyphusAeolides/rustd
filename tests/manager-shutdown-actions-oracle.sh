#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Isolated v261 user-manager oracle for the system shutdown action methods.

set -eu
runtime_dir=$(mktemp -d)
dbus_pid=
manager_pid=
cleanup() {
    if [ -n "$manager_pid" ]; then
        kill "$manager_pid" 2>/dev/null || :
        sleep 0.1
        kill -KILL "$manager_pid" 2>/dev/null || :
        wait "$manager_pid" 2>/dev/null || :
    fi
    if [ -n "$dbus_pid" ]; then kill "$dbus_pid" 2>/dev/null || :; fi
    chmod u+rwx "$runtime_dir/systemd/inaccessible" 2>/dev/null || :
    rm -rf "$runtime_dir"
}
trap cleanup EXIT HUP INT TERM

dbus-daemon --session --fork --address="unix:path=$runtime_dir/bus" --print-pid=1 \
    >"$runtime_dir/dbus-pid"
dbus_pid=$(sed -n '1p' "$runtime_dir/dbus-pid")
export XDG_RUNTIME_DIR="$runtime_dir"
export DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime_dir/bus"
export SYSTEMD_UNIT_PATH=/usr/lib/systemd/user

/usr/lib/systemd/systemd --user >"$runtime_dir/systemd.out" 2>"$runtime_dir/systemd.err" &
manager_pid=$!
ready=0
attempt=0
while [ "$attempt" -lt 100 ]; do
    if busctl --user --no-pager status org.freedesktop.systemd1 >/dev/null 2>&1; then
        ready=1
        break
    fi
    attempt=$((attempt + 1))
    sleep 0.05
done
[ "$ready" -eq 1 ] || { cat "$runtime_dir/systemd.err" >&2; exit 1; }

xml=$(busctl --user --no-pager --xml-interface introspect \
    org.freedesktop.systemd1 /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager)
for method in Reboot PowerOff Halt KExec; do
    printf '%s\n' "$xml" | grep -F "<method name=\"$method\">" >/dev/null
done

assert_not_supported() {
    method=$1
    message=$2
    set +e
    output=$(busctl --user --no-pager call org.freedesktop.systemd1 \
        /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager "$method" 2>&1)
    status=$?
    set -e
    [ "$status" -ne 0 ] || exit 1
    printf '%s\n' "$output" | grep -F "Call failed: $message" >/dev/null
}

assert_not_supported Reboot 'Reboot is only supported by system manager.'
assert_not_supported PowerOff 'Powering off is only supported by system manager.'
assert_not_supported Halt 'Halt is only supported by system manager.'
assert_not_supported KExec 'KExec is only supported by system manager.'

printf '%s\n' 'manager shutdown-actions oracle: PASS'
