#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Host oracle for the v261 StartUnitWithFlags contract. It uses an isolated
# stock user manager and sends only invalid requests, so it never queues or
# executes a unit job on the host manager.

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
method=$(printf '%s\n' "$xml" | sed -n '/<method name="StartUnitWithFlags"/,/<\/method>/p')
for argument in \
    '<arg type="s" name="name" direction="in"/>' \
    '<arg type="s" name="mode" direction="in"/>' \
    '<arg type="t" name="flags" direction="in"/>' \
    '<arg type="o" name="job" direction="out"/>'; do
    case "$method" in
        *"$argument"*) ;;
        *)
            echo 'missing v261 StartUnitWithFlags signature' >&2
            exit 1
            ;;
    esac
done

assert_invalid_args() {
    mode=$1
    flags=$2
    expected=$3
    if dbus-send --session --print-reply --dest=org.freedesktop.systemd1 \
        /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager.StartUnitWithFlags \
        string:basic.target "string:$mode" "uint64:$flags" \
        >"$runtime_dir/request.out" 2>"$runtime_dir/request.err"; then
        echo 'StartUnitWithFlags unexpectedly queued a job' >&2
        exit 1
    fi
    if ! grep -F "Error org.freedesktop.DBus.Error.InvalidArgs: $expected" \
        "$runtime_dir/request.err" >/dev/null; then
        cat "$runtime_dir/request.err" >&2
        exit 1
    fi
}

assert_invalid_args not-a-mode 0 'Job mode not-a-mode invalid'
assert_invalid_args replace 18446744073709551615 \
    "Invalid 'flags' parameter '18446744073709551615'"

printf '%s\n' 'manager StartUnitWithFlags oracle: PASS'
