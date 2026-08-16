#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Host oracle for Manager.ReloadCount. It uses an isolated stock v261 user
# manager and performs reload only in that private process.

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
property=$(printf '%s\n' "$xml" | sed -n '/<property name="ReloadCount"/,/<\/property>/p')
case "$property" in
    *'<property name="ReloadCount" type="t" access="read">'*'EmitsChangedSignal" value="false"'*)
        ;;
    *)
        echo 'missing v261 ReloadCount property contract' >&2
        exit 1
        ;;
esac

get_count() {
    busctl --user --no-pager get-property org.freedesktop.systemd1 \
        /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager ReloadCount \
        | sed -n 's/^t \([0-9][0-9]*\)$/\1/p'
}

before=$(get_count)
[ "$before" = 0 ] || {
    echo "unexpected initial ReloadCount: $before" >&2
    exit 1
}

busctl --user --no-pager call org.freedesktop.systemd1 /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager Reload >/dev/null

after=$(get_count)
[ "$after" = 1 ] || {
    echo "expected ReloadCount 1 after isolated reload, got: $after" >&2
    exit 1
}

printf '%s\n' 'manager reload-count oracle: PASS'
