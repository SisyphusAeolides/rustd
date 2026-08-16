#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Non-mutating v261 host oracle for Manager.KillUnit.

set -eu

manager_xml=$(busctl --system --no-pager --xml-interface introspect \
    org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager)
method=$(printf '%s\n' "$manager_xml" | sed -n \
    '/<method name="KillUnit"/,/<\/method>/p')
for argument in \
    '<arg type="s" name="name" direction="in"/>' \
    '<arg type="s" name="whom" direction="in"/>' \
    '<arg type="i" name="signal" direction="in"/>'
do
    printf '%s\n' "$method" | grep -F "$argument" >/dev/null
done

if missing=$(dbus-send --system --print-reply \
    --dest=org.freedesktop.systemd1 /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager.KillUnit \
    string:no-such-unit-for-parity.service string:all int32:15 2>&1); then
    echo 'missing KillUnit target unexpectedly succeeded' >&2
    exit 1
fi
case "$missing" in
    *'Error org.freedesktop.systemd1.NoSuchUnit: Unit no-such-unit-for-parity.service not loaded.'*)
        ;;
    *)
        echo "unexpected missing KillUnit error: $missing" >&2
        exit 1
        ;;
esac

if invalid_whom=$(dbus-send --system --print-reply \
    --dest=org.freedesktop.systemd1 /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager.KillUnit \
    string:systemd-journald.service string:invalid int32:15 2>&1); then
    echo 'invalid KillUnit whom unexpectedly succeeded' >&2
    exit 1
fi
case "$invalid_whom" in
    *'Error org.freedesktop.DBus.Error.InvalidArgs: Invalid whom argument: invalid'*)
        ;;
    *)
        echo "unexpected KillUnit whom error: $invalid_whom" >&2
        exit 1
        ;;
esac

if invalid_signal=$(dbus-send --system --print-reply \
    --dest=org.freedesktop.systemd1 /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager.KillUnit \
    string:systemd-journald.service string:all int32:0 2>&1); then
    echo 'invalid KillUnit signal unexpectedly succeeded' >&2
    exit 1
fi
case "$invalid_signal" in
    *'Error org.freedesktop.DBus.Error.InvalidArgs: Signal number out of range.'*)
        ;;
    *)
        echo "unexpected KillUnit signal error: $invalid_signal" >&2
        exit 1
        ;;
esac

printf '%s\n' 'manager KillUnit oracle: PASS'
