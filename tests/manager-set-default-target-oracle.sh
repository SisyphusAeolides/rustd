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
    if [ -n "$dbus_pid" ]; then kill "$dbus_pid" 2>/dev/null || :; fi
    chmod u+rwx "$runtime_dir/systemd/inaccessible" 2>/dev/null || :
    rm -rf "$runtime_dir"
}
trap cleanup EXIT HUP INT TERM
mkdir -p "$runtime_dir/config/systemd/user" "$runtime_dir/state"
printf '%s\n' '[Unit]' 'Description=Parity target' >"$runtime_dir/config/systemd/user/parity.target"
printf '%s\n' '[Unit]' 'Description=Other target' >"$runtime_dir/config/systemd/user/other.target"
dbus-daemon --session --fork --address="unix:path=$runtime_dir/bus" --print-pid=1 >"$runtime_dir/dbus-pid"
dbus_pid=$(sed -n '1p' "$runtime_dir/dbus-pid")
export XDG_RUNTIME_DIR="$runtime_dir"
export DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime_dir/bus"
export XDG_CONFIG_HOME="$runtime_dir/config"
export XDG_STATE_HOME="$runtime_dir/state"
export SYSTEMD_UNIT_PATH="$runtime_dir/config/systemd/user:/usr/lib/systemd/user"
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
xml=$(busctl --user --no-pager --xml-interface introspect org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager)
method=$(printf '%s\n' "$xml" | sed -n '/<method name="SetDefaultTarget"/,/<\/method>/p')
printf '%s\n' "$method" | grep -F 'SetDefaultTarget' >/dev/null
printf '%s\n' "$method" | grep -F 'a(sss)' >/dev/null
result=$(busctl --user --no-pager call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager SetDefaultTarget sb parity.target false)
printf '%s\n' "$result" | grep -F 'a(sss) 1' >/dev/null
[ -L "$runtime_dir/config/systemd/user/default.target" ]
if gdbus call --session --dest org.freedesktop.systemd1 \
    --object-path /org/freedesktop/systemd1 \
    --method org.freedesktop.systemd1.Manager.SetDefaultTarget \
    other.target false >"$runtime_dir/existing" 2>&1; then
    echo 'non-force replacement unexpectedly succeeded' >&2
    exit 1
fi
grep -F 'GDBus.Error:org.freedesktop.systemd1.UnitExists:' "$runtime_dir/existing" >/dev/null
grep -F "File '$runtime_dir/config/systemd/user/default.target' already exists and is a symlink to $runtime_dir/config/systemd/user/parity.target" "$runtime_dir/existing" >/dev/null
if gdbus call --session --dest org.freedesktop.systemd1 \
    --object-path /org/freedesktop/systemd1 \
    --method org.freedesktop.systemd1.Manager.SetDefaultTarget \
    missing.target false >"$runtime_dir/missing" 2>&1; then
    echo 'missing target unexpectedly succeeded' >&2
    exit 1
fi
grep -F 'GDBus.Error:org.freedesktop.systemd1.NoSuchUnit: Unit missing.target does not exist' "$runtime_dir/missing" >/dev/null
if gdbus call --session --dest org.freedesktop.systemd1 \
    --object-path /org/freedesktop/systemd1 \
    --method org.freedesktop.systemd1.Manager.SetDefaultTarget \
    default.target false >"$runtime_dir/invalid" 2>&1; then
    echo 'default.target unexpectedly accepted' >&2
    exit 1
fi
grep -F 'GDBus.Error:org.freedesktop.DBus.Error.InvalidArgs: Invalid argument' "$runtime_dir/invalid" >/dev/null
printf '%s\n' 'manager SetDefaultTarget oracle: PASS'
