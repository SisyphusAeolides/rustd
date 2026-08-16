#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Non-mutating v261 user-manager oracle for SetShowStatus/ShowStatus.

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
[ "$ready" -eq 1 ] || {
    sed -n '1,120p' "$runtime_dir/systemd.err" >&2
    exit 1
}

xml=$(busctl --user --no-pager --xml-interface introspect \
    org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager)
method=$(printf '%s\n' "$xml" | sed -n '/<method name="SetShowStatus"/,/<\/method>/p')
case "$method" in
    *'<arg type="s" name="mode" direction="in"/>'*) ;;
    *) echo 'missing v261 SetShowStatus signature' >&2; exit 1 ;;
esac
case "$xml" in
    *'<property name="ShowStatus" type="b" access="read"/>'*) ;;
    *) echo 'missing v261 ShowStatus property' >&2; exit 1 ;;
esac

for mode in yes temporary no auto ''; do
    dbus-send --session --print-reply --dest=org.freedesktop.systemd1 \
        /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager.SetShowStatus \
        "string:$mode" >/dev/null
    value=$(busctl --user get-property org.freedesktop.systemd1 \
        /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager ShowStatus)
    case "$value" in
        'b false') ;;
        *) echo "unexpected user-manager ShowStatus after mode '$mode': $value" >&2; exit 1 ;;
    esac
done

if dbus-send --session --print-reply --dest=org.freedesktop.systemd1 \
    /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager.SetShowStatus \
    string:invalid >"$runtime_dir/request.out" 2>"$runtime_dir/request.err"; then
    echo 'invalid SetShowStatus unexpectedly succeeded' >&2
    exit 1
fi
grep -F "Error org.freedesktop.DBus.Error.InvalidArgs: Invalid show status 'invalid'" \
    "$runtime_dir/request.err" >/dev/null

printf '%s\n' 'manager SetShowStatus/ShowStatus oracle: PASS'
