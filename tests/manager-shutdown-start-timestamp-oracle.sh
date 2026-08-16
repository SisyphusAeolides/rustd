#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Host/candidate v261 Manager oracle for shutdown-start timestamps.
#
# The live check is intentionally non-destructive: shutdown methods are not
# invoked.  v261 leaves this pair at zero until a shutdown objective begins.

set -eu

runtime_dir=$(mktemp -d)
dbus_pid=
manager_pid=
candidate_mode=${RUSTD_CANDIDATE_ORACLE:-0}
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

export HOME="$runtime_dir/home"
export XDG_CONFIG_HOME="$runtime_dir/config"
export XDG_RUNTIME_DIR="$runtime_dir"
export DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime_dir/bus"
export SYSTEMD_UNIT_PATH=/usr/lib/systemd/user
mkdir -p "$HOME" "$XDG_CONFIG_HOME"

/usr/lib/systemd/systemd --user >"$runtime_dir/manager.out" 2>"$runtime_dir/manager.err" &
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
[ "$ready" -eq 1 ] || {
    sed -n '1,120p' "$runtime_dir/manager.err" >&2
    exit 1
}

xml=$(busctl --user --no-pager --xml-interface introspect \
    org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager)
for property in ShutdownStartTimestamp ShutdownStartTimestampMonotonic; do
    printf '%s\n' "$xml" | grep -F \
        "<property name=\"$property\" type=\"t\" access=\"read\">" >/dev/null || {
        if [ "$candidate_mode" -eq 1 ]; then
            echo "candidate Manager lacks $property" >&2
            exit 1
        fi
        printf '%s\n' "manager shutdown-start timestamp oracle: SKIP (host manager lacks $property)"
        exit 0
    }
    property_xml=$(printf '%s\n' "$xml" | sed -n "/<property name=\"$property\"/,/<\/property>/p")
    printf '%s\n' "$property_xml" | grep -F \
        '<annotation name="org.freedesktop.DBus.Property.EmitsChangedSignal" value="const"/>' \
        >/dev/null
done

get_property() {
    busctl --user --no-pager get-property org.freedesktop.systemd1 \
        /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager "$1" | awk '{print $2}'
}

[ "$(get_property ShutdownStartTimestamp)" -eq 0 ]
[ "$(get_property ShutdownStartTimestampMonotonic)" -eq 0 ]

printf '%s\n' 'manager shutdown-start timestamp oracle: PASS'
