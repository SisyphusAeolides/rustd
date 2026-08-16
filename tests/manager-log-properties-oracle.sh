#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Isolated v261 user-manager oracle for writable LogLevel/LogTarget.

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

dbus-daemon --session --fork --address="unix:path=$runtime_dir/bus" --print-pid=1 >"$runtime_dir/dbus-pid"
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

xml=$(busctl --user --no-pager --xml-interface introspect org.freedesktop.systemd1 \
    /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager)
for property in LogLevel LogTarget; do
    printf '%s\n' "$xml" | grep -F "<property name=\"$property\" type=\"s\" access=\"readwrite\">" >/dev/null
done

level=$(busctl --user get-property org.freedesktop.systemd1 /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager LogLevel)
target=$(busctl --user get-property org.freedesktop.systemd1 /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager LogTarget)
[ "$level" = 's "info"' ] || { echo "unexpected LogLevel: $level" >&2; exit 1; }
[ "$target" = 's "console"' ] || { echo "unexpected LogTarget: $target" >&2; exit 1; }

set_property() {
    dbus-send --session --print-reply --dest=org.freedesktop.systemd1 \
        /org/freedesktop/systemd1 org.freedesktop.DBus.Properties.Set \
        string:org.freedesktop.systemd1.Manager "string:$1" "variant:string:$2"
}
set_property LogLevel debug >/dev/null
set_property LogTarget console >/dev/null
[ "$(busctl --user get-property org.freedesktop.systemd1 /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager LogLevel)" = 's "debug"' ]
[ "$(busctl --user get-property org.freedesktop.systemd1 /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager LogTarget)" = 's "console"' ]

if set_property LogLevel invalid >"$runtime_dir/invalid.out" 2>&1; then
    echo 'invalid LogLevel unexpectedly succeeded' >&2
    exit 1
fi
grep -F "Error org.freedesktop.DBus.Error.InvalidArgs: Invalid log level 'invalid'" \
    "$runtime_dir/invalid.out" >/dev/null

printf '%s\n' 'manager LogLevel/LogTarget oracle: PASS'
