#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Read-only v261 host oracle for the Manager watchdog observability properties.
# This host has no configured hardware watchdog, the same supported state the
# candidate exposes without a watchdog backend.

set -eu

xml=$(busctl --system --no-pager --xml-interface introspect \
    org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager)

assert_property() {
    name=$1
    signature=$2
    annotation=$3
    property=$(printf '%s\n' "$xml" | sed -n "/<property name=\"$name\"/,/<\/property>/p")
    case "$property" in
        *"<property name=\"$name\" type=\"$signature\" access=\"read\">"*"EmitsChangedSignal\" value=\"$annotation\""*)
            ;;
        *)
            echo "missing v261 property contract for $name" >&2
            exit 1
            ;;
    esac
}

assert_property WatchdogDevice s const
assert_property WatchdogLastPingTimestamp t false
assert_property WatchdogLastPingTimestampMonotonic t false

[ "$(busctl --system --no-pager get-property org.freedesktop.systemd1 \
    /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager WatchdogDevice)" = 's ""' ]
[ "$(busctl --system --no-pager get-property org.freedesktop.systemd1 \
    /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager WatchdogLastPingTimestamp)" = 't 18446744073709551615' ]
[ "$(busctl --system --no-pager get-property org.freedesktop.systemd1 \
    /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager WatchdogLastPingTimestampMonotonic)" = 't 18446744073709551615' ]

printf '%s\n' 'manager watchdog oracle: PASS'
