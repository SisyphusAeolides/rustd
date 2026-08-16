#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Host/candidate v261 oracle for Manager RefUnit and UnrefUnit.  A persistent
# D-Bus connection is required because systemd tracks references by sender
# unique name; each call from a new one-shot client would correctly produce
# NotReferenced after the first client disconnects.

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
for method in RefUnit UnrefUnit; do
    method_xml=$(printf '%s\n' "$xml" | sed -n "/<method name=\"$method\"/,/<\/method>/p")
    case "$method_xml" in
        *'<arg type="s" name="name" direction="in"/>'*) ;;
        *)
            echo "missing v261 signature for $method" >&2
            exit 1
            ;;
    esac
done

python3 - <<'PY'
import os
import gi
gi.require_version("Gio", "2.0")
from gi.repository import Gio, GLib

address = os.environ["DBUS_SESSION_BUS_ADDRESS"]
flags = Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION
connection = Gio.DBusConnection.new_for_address_sync(address, flags, None, None)
proxy = Gio.DBusProxy.new_sync(
    connection,
    Gio.DBusProxyFlags.NONE,
    None,
    "org.freedesktop.systemd1",
    "/org/freedesktop/systemd1",
    "org.freedesktop.systemd1.Manager",
    None,
)

def call(method, name):
    return proxy.call_sync(
        method,
        GLib.Variant("(s)", (name,)),
        Gio.DBusCallFlags.NONE,
        5000,
        None,
    )

def assert_error(method, name, expected):
    try:
        call(method, name)
    except GLib.Error as error:
        if expected not in error.message:
            raise AssertionError(f"{method} error {error.message!r} lacks {expected!r}")
    else:
        raise AssertionError(f"{method} {name} unexpectedly succeeded")

call("RefUnit", "default.target")
call("RefUnit", "default.target")
call("UnrefUnit", "default.target")
call("UnrefUnit", "default.target")
assert_error(
    "UnrefUnit",
    "default.target",
    "org.freedesktop.systemd1.NotReferenced: Unit has not been referenced yet.",
)
assert_error(
    "RefUnit",
    "bad",
    "org.freedesktop.DBus.Error.InvalidArgs: Unit name bad is not valid.",
)
assert_error(
    "RefUnit",
    "rustd-missing-unit.service",
    "org.freedesktop.systemd1.NoSuchUnit: Unit rustd-missing-unit.service not found.",
)
assert_error(
    "UnrefUnit",
    "rustd-missing-unit.service",
    "org.freedesktop.systemd1.NoSuchUnit: Unit rustd-missing-unit.service not loaded.",
)

# A second persistent sender exercises recursive sender ownership.  The
# manager's NameOwnerChanged monitor must discard this reference after the
# connection closes; a later process must not inherit it.
owner = Gio.DBusConnection.new_for_address_sync(address, flags, None, None)
owner_proxy = Gio.DBusProxy.new_sync(
    owner,
    Gio.DBusProxyFlags.NONE,
    None,
    "org.freedesktop.systemd1",
    "/org/freedesktop/systemd1",
    "org.freedesktop.systemd1.Manager",
    None,
)
owner_proxy.call_sync(
    "RefUnit", GLib.Variant("(s)", ("default.target",)), Gio.DBusCallFlags.NONE, 5000, None
)
owner.close_sync(None)

print("manager unit-reference oracle: PASS")
PY
