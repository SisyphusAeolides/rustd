#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Host oracle for the v261 caller-relative Manager unit lookups. It uses an
# isolated stock user manager and only performs queries that cannot queue or
# modify a unit.

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
assert_method() {
    name=$1
    first=$2
    second=$3
    method=$(printf '%s\n' "$xml" | sed -n "/<method name=\"$name\"/,/<\/method>/p")
    case "$method" in *"$first"*) ;; *) echo "missing v261 $name input" >&2; exit 1;; esac
    case "$method" in *"$second"*) ;; *) echo "missing v261 $name output" >&2; exit 1;; esac
}

assert_method GetUnit '<arg type="s" name="name" direction="in"/>' \
    '<arg type="o" name="unit" direction="out"/>'
assert_method GetUnitByPID '<arg type="u" name="pid" direction="in"/>' \
    '<arg type="o" name="unit" direction="out"/>'

call() {
    dbus-send --session --print-reply --dest=org.freedesktop.systemd1 \
        /org/freedesktop/systemd1 "$@"
}

if call org.freedesktop.systemd1.Manager.GetUnit \
    string:rustd-missing-unit.service >"$runtime_dir/missing.out" 2>"$runtime_dir/missing.err"; then
    echo 'GetUnit unexpectedly accepted a missing unit' >&2
    exit 1
fi
grep -F 'Error org.freedesktop.systemd1.NoSuchUnit: Unit rustd-missing-unit.service not loaded.' \
    "$runtime_dir/missing.err" >/dev/null

if call org.freedesktop.systemd1.Manager.GetUnitByPID uint32:4294967295 \
    >"$runtime_dir/invalid-pid.out" 2>"$runtime_dir/invalid-pid.err"; then
    echo 'GetUnitByPID unexpectedly accepted an out-of-range PID' >&2
    exit 1
fi
grep -F 'Error org.freedesktop.DBus.Error.InvalidArgs: Invalid PID -1' \
    "$runtime_dir/invalid-pid.err" >/dev/null

assert_caller_lookup() {
    method=$1
    argument=$2
    error_name=$3
    error_prefix=$4
    output="$runtime_dir/$method.out"
    error="$runtime_dir/$method.err"
    if call "org.freedesktop.systemd1.Manager.$method" "$argument" >"$output" 2>"$error"; then
        grep -E 'object path "/org/freedesktop/systemd1/unit/' "$output" >/dev/null || {
            cat "$output" >&2
            exit 1
        }
    else
        grep -E "Error $error_name: $error_prefix [1-9][0-9]* .*" "$error" >/dev/null || {
            cat "$error" >&2
            exit 1
        }
    fi
}

assert_caller_lookup GetUnit string: org.freedesktop.systemd1.NoSuchUnit Client
assert_caller_lookup GetUnitByPID uint32:0 org.freedesktop.systemd1.NoUnitForPID PID

printf '%s\n' 'manager caller-unit-lookup oracle: PASS'
