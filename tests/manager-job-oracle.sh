#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Host oracle for the Manager conditional-job methods. It starts the stock
# v261 user manager on an isolated user bus and issues only malformed calls,
# so no host unit is started, stopped, or reloaded.

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
for method in ReloadUnit TryRestartUnit ReloadOrRestartUnit ReloadOrTryRestartUnit; do
    case "$xml" in
        *"<method name=\"$method\">"*"<arg type=\"s\" name=\"name\" direction=\"in\"/>"*"<arg type=\"s\" name=\"mode\" direction=\"in\"/>"*"<arg type=\"o\" name=\"job\" direction=\"out\"/>"*)
            ;;
        *)
            echo "missing v261 signature for $method" >&2
            exit 1
            ;;
    esac
done

case "$xml" in
    *'<method name="EnqueueUnitJob">'*'<arg type="s" name="name" direction="in"/>'*'<arg type="s" name="job_type" direction="in"/>'*'<arg type="s" name="job_mode" direction="in"/>'*'<arg type="u" name="job_id" direction="out"/>'*'<arg type="o" name="job_path" direction="out"/>'*'<arg type="s" name="unit_id" direction="out"/>'*'<arg type="o" name="unit_path" direction="out"/>'*'<arg type="a(uosos)" name="affected_jobs" direction="out"/>'*)
        ;;
    *)
        echo 'missing v261 signature for EnqueueUnitJob' >&2
        exit 1
        ;;
esac

assert_invalid_args() {
    method=$1
    name=$2
    mode=$3
    expected=$4
    if dbus-send --session --print-reply --dest=org.freedesktop.systemd1 \
        /org/freedesktop/systemd1 "org.freedesktop.systemd1.Manager.$method" \
        "string:$name" "string:$mode" >"$runtime_dir/$method.out" 2>"$runtime_dir/$method.err"; then
        echo "$method unexpectedly succeeded" >&2
        exit 1
    fi
    if ! grep -F "Error org.freedesktop.DBus.Error.InvalidArgs: $expected" \
        "$runtime_dir/$method.err" >/dev/null; then
        cat "$runtime_dir/$method.err" >&2
        exit 1
    fi
}

for method in ReloadUnit TryRestartUnit ReloadOrRestartUnit ReloadOrTryRestartUnit; do
    assert_invalid_args "$method" bad replace "Unit name bad is not valid."
    assert_invalid_args "$method" default.target not-a-mode "Job mode not-a-mode invalid"
done

printf '%s\n' 'manager conditional-job oracle: PASS'
