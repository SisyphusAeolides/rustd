#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
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
    if [ -n "$dbus_pid" ]; then
        kill "$dbus_pid" 2>/dev/null || :
    fi
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

/usr/lib/systemd/systemd --user >"$runtime_dir/manager.out" 2>"$runtime_dir/manager.err" &
manager_pid=$!

get_owner() {
    busctl --user call org.freedesktop.DBus /org/freedesktop/DBus \
        org.freedesktop.DBus GetNameOwner s org.freedesktop.systemd1 2>/dev/null \
        | awk -F'"' 'NF >= 2 { print $2 }'
}

ready=0
attempt=0
while [ "$attempt" -lt 100 ]; do
    if owner=$(get_owner) && [ -n "$owner" ]; then
        ready=1
        break
    fi
    attempt=$((attempt + 1))
    sleep 0.05
done
[ "$ready" -eq 1 ] || {
    sed -n '1,120p' "$runtime_dir/manager.err" >&2
    exit 1
}
owner_before=$owner

xml=$(busctl --user --no-pager --xml-interface introspect \
    org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager)
method=$(printf '%s\n' "$xml" | sed -n '/<method name="Reexecute">/,/<\/method>/p')
[ -n "$method" ] || { echo 'missing v261 Reexecute method' >&2; exit 1; }
if printf '%s\n' "$method" | grep -q '<arg '; then
    echo 'Reexecute unexpectedly has D-Bus arguments' >&2
    exit 1
fi

dbus-send --session --type=method_call --dest=org.freedesktop.systemd1 \
    /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager.Reexecute

changed=0
attempt=0
while [ "$attempt" -lt 200 ]; do
    if ! kill -0 "$manager_pid" 2>/dev/null; then
        echo 'manager PID died during Reexecute' >&2
        exit 1
    fi
    if owner_after=$(get_owner) && [ -n "$owner_after" ] \
        && busctl --user get-property org.freedesktop.systemd1 \
            /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager Version \
            >/dev/null 2>&1; then
        changed=1
        break
    fi
    attempt=$((attempt + 1))
    sleep 0.05
done
[ "$changed" -eq 1 ] || {
    echo 'manager did not return a live D-Bus interface after Reexecute' >&2
    sed -n '1,160p' "$runtime_dir/manager.err" >&2
    exit 1
}

busctl --user get-property org.freedesktop.systemd1 /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager Version | grep -F '261' >/dev/null

dbus-send --session --type=method_call --dest=org.freedesktop.systemd1 \
    /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager.Exit
attempt=0
while kill -0 "$manager_pid" 2>/dev/null && [ "$attempt" -lt 100 ]; do
    attempt=$((attempt + 1))
    sleep 0.05
done
if kill -0 "$manager_pid" 2>/dev/null; then
    echo 'manager remained alive after Exit' >&2
    exit 1
fi
wait "$manager_pid"
manager_pid=

printf '%s\n' 'manager reexecute oracle: PASS'
