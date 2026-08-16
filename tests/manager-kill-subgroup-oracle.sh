#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Non-mutating v261 host oracle for Manager.KillUnitSubgroup and
# Manager.QueueSignalUnit.  Every call below fails before delivery/auth and
# therefore leaves the host manager unchanged.

set -eu

manager_xml=$(busctl --system --no-pager --xml-interface introspect \
    org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager \
    | sed -E 's/[[:space:]]+\/>/\/>/g')

subgroup_method=$(printf '%s\n' "$manager_xml" | sed -n \
    '/<method name="KillUnitSubgroup"/,/<\/method>/p')
# Ubuntu's systemd package used by the compatibility workflow predates the
# v261 method.  Keep this host-only oracle non-failing there; v261 hosts still
# run the complete wire/error assertions below.  The candidate manager's own
# user-bus surface is covered by the other replacement oracles.
if [ -z "$subgroup_method" ]; then
    printf '%s\n' 'manager KillUnitSubgroup/QueueSignalUnit oracle: SKIP (host manager lacks v261 methods)'
    exit 0
fi
for argument in \
    '<arg type="s" name="name" direction="in"/>' \
    '<arg type="s" name="whom" direction="in"/>' \
    '<arg type="s" name="subgroup" direction="in"/>' \
    '<arg type="i" name="signal" direction="in"/>'
do
    if ! printf '%s\n' "$subgroup_method" | grep -F "$argument" >/dev/null; then
        echo "missing KillUnitSubgroup XML argument: $argument" >&2
        printf '%s\n' "$subgroup_method" >&2
        exit 1
    fi
done

queue_method=$(printf '%s\n' "$manager_xml" | sed -n \
    '/<method name="QueueSignalUnit"/,/<\/method>/p')
for argument in \
    '<arg type="s" name="name" direction="in"/>' \
    '<arg type="s" name="whom" direction="in"/>' \
    '<arg type="i" name="signal" direction="in"/>' \
    '<arg type="i" name="value" direction="in"/>'
do
    if ! printf '%s\n' "$queue_method" | grep -F "$argument" >/dev/null; then
        echo "missing QueueSignalUnit XML argument: $argument" >&2
        printf '%s\n' "$queue_method" >&2
        exit 1
    fi
done

if missing=$(dbus-send --system --print-reply \
    --dest=org.freedesktop.systemd1 /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager.KillUnitSubgroup \
    string:no-such-subgroup-unit-for-parity.service string:cgroup string: int32:15 2>&1); then
    echo 'missing KillUnitSubgroup target unexpectedly succeeded' >&2
    exit 1
fi
case "$missing" in
    *'Error org.freedesktop.systemd1.NoSuchUnit: Unit no-such-subgroup-unit-for-parity.service not loaded.'*)
        ;;
    *)
        echo "unexpected missing KillUnitSubgroup error: $missing" >&2
        exit 1
        ;;
esac

if invalid_subgroup=$(dbus-send --system --print-reply \
    --dest=org.freedesktop.systemd1 /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager.KillUnitSubgroup \
    string:systemd-journald.service string:cgroup string:../escape int32:15 2>&1); then
    echo 'invalid KillUnitSubgroup path unexpectedly succeeded' >&2
    exit 1
fi
case "$invalid_subgroup" in
    *'Error org.freedesktop.DBus.Error.InvalidArgs: Specified cgroup sub-path is not valid.'*)
        ;;
    *)
        echo "unexpected subgroup path error: $invalid_subgroup" >&2
        exit 1
        ;;
esac

if invalid_whom=$(dbus-send --system --print-reply \
    --dest=org.freedesktop.systemd1 /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager.KillUnitSubgroup \
    string:systemd-journald.service string:invalid string: int32:15 2>&1); then
    echo 'invalid KillUnitSubgroup whom unexpectedly succeeded' >&2
    exit 1
fi
case "$invalid_whom" in
    *'Error org.freedesktop.DBus.Error.InvalidArgs: Invalid whom argument: invalid'*)
        ;;
    *)
        echo "unexpected subgroup whom error: $invalid_whom" >&2
        exit 1
        ;;
esac

if invalid_signal=$(dbus-send --system --print-reply \
    --dest=org.freedesktop.systemd1 /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager.KillUnitSubgroup \
    string:systemd-journald.service string:cgroup string: int32:0 2>&1); then
    echo 'invalid KillUnitSubgroup signal unexpectedly succeeded' >&2
    exit 1
fi
case "$invalid_signal" in
    *'Error org.freedesktop.DBus.Error.InvalidArgs: Signal number out of range.'*)
        ;;
    *)
        echo "unexpected subgroup signal error: $invalid_signal" >&2
        exit 1
        ;;
esac

if invalid_value=$(dbus-send --system --print-reply \
    --dest=org.freedesktop.systemd1 /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager.QueueSignalUnit \
    string:systemd-journald.service string:main int32:15 int32:42 2>&1); then
    echo 'invalid QueueSignalUnit value unexpectedly succeeded' >&2
    exit 1
fi
printf '%s\n' "$invalid_value" | grep -F \
    'Error org.freedesktop.DBus.Error.InvalidArgs: Value parameter only accepted for realtime signals' \
    >/dev/null
printf '%s\n' "$invalid_value" | grep -F 'refusing for signal SIGTERM.' >/dev/null

printf '%s\n' 'manager KillUnitSubgroup/QueueSignalUnit oracle: PASS'
