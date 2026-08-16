#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Isolated v261 user-manager oracle for StartupFinished's wire and timing
# contract.  The signal is captured before the manager is started so the
# one-shot startup emission cannot race the observer.

set -eu
runtime_dir=$(mktemp -d)
dbus_pid=
manager_pid=
watcher_pid=
cleanup() {
    if [ -n "$manager_pid" ]; then
        kill "$manager_pid" 2>/dev/null || :
        sleep 0.1
        kill -KILL "$manager_pid" 2>/dev/null || :
        wait "$manager_pid" 2>/dev/null || :
    fi
    if [ -n "$watcher_pid" ]; then
        kill "$watcher_pid" 2>/dev/null || :
        wait "$watcher_pid" 2>/dev/null || :
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

dbus-monitor --address "$DBUS_SESSION_BUS_ADDRESS" \
    "type='signal',path='/org/freedesktop/systemd1',interface='org.freedesktop.systemd1.Manager',member='StartupFinished'" \
    >"$runtime_dir/monitor" 2>"$runtime_dir/watcher.err" &
watcher_pid=$!
sleep 0.2
/usr/lib/systemd/systemd --user >"$runtime_dir/systemd.out" 2>"$runtime_dir/systemd.err" &
manager_pid=$!

attempt=0
while ! grep -F 'member=StartupFinished' "$runtime_dir/monitor" >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 200 ]; then
        cat "$runtime_dir/watcher.err" >&2
        cat "$runtime_dir/systemd.err" >&2
        exit 1
    fi
    sleep 0.05
done
values=$(awk '
    /member=StartupFinished/ { remaining=6; next }
    remaining && /uint64/ { print $2; remaining-- }
' "$runtime_dir/monitor" | head -n 6 | tr '\n' ' ')
set -- $values
[ "$#" -eq 6 ]
[ "$1" -eq 0 ]
[ "$2" -eq 0 ]
[ "$3" -eq 0 ]
[ "$4" -eq 0 ]
[ "$5" -ge 0 ]
[ "$6" -ge "$5" ]

xml=$(busctl --user --no-pager --xml-interface introspect \
    org.freedesktop.systemd1 /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager)
printf '%s\n' "$xml" | grep -F '<signal name="StartupFinished">' >/dev/null
for arg in firmware loader kernel initrd userspace total; do
    printf '%s\n' "$xml" | grep -F "<arg name=\"$arg\" type=\"t\"/>" >/dev/null
done

printf '%s\n' 'manager StartupFinished oracle: PASS'
