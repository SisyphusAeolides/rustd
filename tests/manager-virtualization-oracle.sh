#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Non-mutating v261 host oracle for Manager.Virtualization.

set -eu

manager_xml=$(busctl --system --no-pager --xml-interface introspect \
    org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager)
property=$(printf '%s\n' "$manager_xml" | sed -n \
    '/<property name="Virtualization"/,/<\/property>/p')
printf '%s\n' "$property" | grep -F \
    '<property name="Virtualization" type="s" access="read">' >/dev/null
printf '%s\n' "$property" | grep -F \
    '<annotation name="org.freedesktop.DBus.Property.EmitsChangedSignal" value="const"/>' >/dev/null

# `detect_virtualization()` returns `none` on bare metal, but the D-Bus API
# intentionally exposes that case as the empty string.
detected=$(systemd-detect-virt 2>/dev/null || true)
if [ "$detected" = none ]; then
    expected='s ""'
else
    expected="s \"$detected\""
fi
actual=$(busctl --system --no-pager get-property \
    org.freedesktop.systemd1 /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager Virtualization)
[ "$actual" = "$expected" ]

printf '%s\n' 'manager virtualization oracle: PASS'
