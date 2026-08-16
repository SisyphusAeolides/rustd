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
printf '%s\n' \
    '[Unit]' \
    'Description=Preset oracle' \
    '[Install]' \
    'WantedBy=default.target' \
    >"$runtime_dir/config/systemd/user/preset.service"

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

xml=$(busctl --user --no-pager --xml-interface introspect \
    org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager)
for method in PresetUnitFiles PresetUnitFilesWithMode PresetAllUnitFiles; do
    printf '%s\n' "$xml" | sed -n "/<method name=\"$method\"/,/<\/method>/p" | grep -F '<arg'
done
method=$(printf '%s\n' "$xml" | sed -n '/<method name="PresetUnitFiles"/,/<\/method>/p')
printf '%s\n' "$method" | grep -F '<arg type="as" name="files" direction="in"/>' >/dev/null
printf '%s\n' "$method" | grep -F '<arg type="b" name="runtime" direction="in"/>' >/dev/null
printf '%s\n' "$method" | grep -F '<arg type="b" name="force" direction="in"/>' >/dev/null
printf '%s\n' "$method" | grep -F '<arg type="b" name="carries_install_info" direction="out"/>' >/dev/null
printf '%s\n' "$method" | grep -F '<arg type="a(sss)" name="changes" direction="out"/>' >/dev/null

all_result=$(gdbus call --session --dest org.freedesktop.systemd1 \
    --object-path /org/freedesktop/systemd1 \
    --method org.freedesktop.systemd1.Manager.PresetAllUnitFiles \
    disable-only true false)
[ "$all_result" = '(@a(sss) [],)' ]

result=$(gdbus call --session --dest org.freedesktop.systemd1 \
    --object-path /org/freedesktop/systemd1 \
    --method org.freedesktop.systemd1.Manager.PresetUnitFiles \
    '["preset.service"]' false false)
expected="(true, [('symlink', '$runtime_dir/config/systemd/user/default.target.wants/preset.service', '$runtime_dir/config/systemd/user/preset.service')])"
[ "$result" = "$expected" ]
[ -L "$runtime_dir/config/systemd/user/default.target.wants/preset.service" ]

result=$(gdbus call --session --dest org.freedesktop.systemd1 \
    --object-path /org/freedesktop/systemd1 \
    --method org.freedesktop.systemd1.Manager.PresetUnitFilesWithMode \
    '["preset.service"]' enable-only false false)
[ "$result" = '(true, @a(sss) [])' ]

result=$(gdbus call --session --dest org.freedesktop.systemd1 \
    --object-path /org/freedesktop/systemd1 \
    --method org.freedesktop.systemd1.Manager.PresetUnitFilesWithMode \
    '["preset.service"]' disable-only false false)
[ "$result" = '(false, @a(sss) [])' ]

if gdbus call --session --dest org.freedesktop.systemd1 \
    --object-path /org/freedesktop/systemd1 \
    --method org.freedesktop.systemd1.Manager.PresetUnitFilesWithMode \
    '["preset.service"]' invalid false false >"$runtime_dir/invalid-mode" 2>&1; then
    echo 'invalid preset mode unexpectedly succeeded' >&2
    exit 1
fi
grep -F 'GDBus.Error:org.freedesktop.DBus.Error.InvalidArgs: Invalid argument' \
    "$runtime_dir/invalid-mode" >/dev/null

printf '%s\n' 'manager preset-unit-files oracle: PASS'
