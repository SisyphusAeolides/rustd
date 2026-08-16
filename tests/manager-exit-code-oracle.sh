#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Non-mutating v261 host oracle for Manager.ExitCode and SetExitCode.

set -eu

runtime_dir=$(mktemp -d)
dbus_pid=
manager_pid=

cleanup() {
    if [ -n "$manager_pid" ]; then
        kill "$manager_pid" 2>/dev/null || :
        wait "$manager_pid" 2>/dev/null || :
    fi
    if [ -n "$dbus_pid" ]; then
        kill "$dbus_pid" 2>/dev/null || :
    fi
    chmod u+rwx "$runtime_dir/systemd/inaccessible" 2>/dev/null || :
    rm -rf "$runtime_dir"
}
trap cleanup EXIT HUP INT TERM

dbus_pid=$(dbus-daemon --session --fork --address="unix:path=$runtime_dir/bus" --print-pid=1)
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

manager_xml=$(busctl --user --no-pager --xml-interface introspect \
    org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager)
property=$(printf '%s\n' "$manager_xml" | sed -n \
    '/<property name="ExitCode"/,/<\/property>/p')
case "$property" in
    *'<property name="ExitCode" type="y" access="read">'*'EmitsChangedSignal" value="false"'*)
        ;;
    *)
        echo 'missing v261 ExitCode property contract' >&2
        exit 1
        ;;
esac

method=$(printf '%s\n' "$manager_xml" | sed -n \
    '/<method name="SetExitCode"/,/<\/method>/p')
printf '%s\n' "$method" | grep -F \
    '<arg type="y" name="number" direction="in"/>' >/dev/null

exit_code=$(busctl --user --no-pager get-property \
    org.freedesktop.systemd1 /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager ExitCode)
[ "$exit_code" = 'y 0' ]

busctl --user --no-pager call org.freedesktop.systemd1 \
    /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager SetExitCode y 73
[ "$(busctl --user --no-pager get-property org.freedesktop.systemd1 \
    /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager ExitCode)" = 'y 73' ]

busctl --user --no-pager call org.freedesktop.systemd1 \
    /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager Exit
if wait "$manager_pid"; then
    manager_status=0
else
    manager_status=$?
fi
manager_pid=
[ "$manager_status" -eq 73 ]

printf '%s\n' 'manager ExitCode oracle: PASS'
