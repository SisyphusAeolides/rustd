#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Non-mutating v261 host oracle for the Manager invocation-ID lookup contract.

set -eu

manager_xml=$(busctl --system --no-pager --xml-interface introspect \
    org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager)
manager_method=$(printf '%s\n' "$manager_xml" | sed -n \
    '/<method name="GetUnitByInvocationID"/,/<\/method>/p')
case "$manager_method" in
    *'<arg type="ay" name="invocation_id" direction="in"/>'*'<arg type="o" name="unit" direction="out"/>'*)
        ;;
    *)
        echo 'missing v261 GetUnitByInvocationID contract' >&2
        exit 1
        ;;
esac

unit=$(busctl --system --no-pager call \
    org.freedesktop.systemd1 /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager GetUnit s systemd-journald.service)
unit_path=$(printf '%s\n' "$unit" | sed -n 's/^o "\(.*\)"$/\1/p')
[ -n "$unit_path" ]

unit_xml=$(busctl --system --no-pager --xml-interface introspect \
    org.freedesktop.systemd1 "$unit_path" org.freedesktop.systemd1.Unit)
printf '%s\n' "$unit_xml" | grep -F \
    '<property name="InvocationID" type="ay" access="read">' >/dev/null

# A loaded but not started service has the id128 null value, represented as an
# empty byte array rather than an omitted property.
inactive=$(busctl --system --no-pager call \
    org.freedesktop.systemd1 /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager GetUnit s getty@tty1.service)
inactive_path=$(printf '%s\n' "$inactive" | sed -n 's/^o "\(.*\)"$/\1/p')
[ -n "$inactive_path" ]
[ "$(busctl --system --no-pager get-property \
    org.freedesktop.systemd1 "$inactive_path" org.freedesktop.systemd1.Unit InvocationID)" \
    = 'ay 0' ]

invocation=$(busctl --system --no-pager get-property \
    org.freedesktop.systemd1 "$unit_path" org.freedesktop.systemd1.Unit InvocationID)
set -- $invocation
[ "$1" = ay ]
[ "$2" = 16 ]
shift 2
[ "$#" = 16 ]
case "$7" in 64|65|66|67|68|69|70|71|72|73|74|75|76|77|78|79) ;; *)
    echo "host InvocationID is not UUIDv4-shaped: $invocation" >&2
    exit 1
    ;;
esac
[ "$9" -ge 128 ]
[ "$9" -le 191 ]

resolved=$(busctl --system --no-pager call \
    org.freedesktop.systemd1 /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager GetUnitByInvocationID ay 16 "$@")
resolved_path=$(printf '%s\n' "$resolved" | sed -n 's/^o "\(.*\)"$/\1/p')
[ -n "$resolved_path" ]
[ "$resolved_path" != "$unit_path" ]
[ "$(busctl --system --no-pager get-property \
    org.freedesktop.systemd1 "$resolved_path" org.freedesktop.systemd1.Unit Id)" \
    = 's "systemd-journald.service"' ]
[ "$(busctl --system --no-pager get-property \
    org.freedesktop.systemd1 "$resolved_path" org.freedesktop.systemd1.Unit InvocationID)" \
    = "$invocation" ]

zero=$(busctl --system --no-pager call \
    org.freedesktop.systemd1 /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager GetUnitByInvocationID \
    ay 16 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0)
zero_path=$(printf '%s\n' "$zero" | sed -n 's/^o "\(.*\)"$/\1/p')
[ -n "$zero_path" ]
printf '%s\n' "$zero_path" | grep -E \
    '^/org/freedesktop/systemd1/unit/_[0-9a-f]{32}$' >/dev/null

if invalid=$(dbus-send --system --print-reply \
    --dest=org.freedesktop.systemd1 /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager.GetUnitByInvocationID array:byte:0 2>&1); then
    echo 'short InvocationID unexpectedly succeeded' >&2
    exit 1
fi
case "$invalid" in
    *'Error org.freedesktop.DBus.Error.InvalidArgs: Invalid invocation ID'*) ;;
    *)
        echo "unexpected short InvocationID error: $invalid" >&2
        exit 1
        ;;
esac

if unknown=$(dbus-send --system --print-reply \
    --dest=org.freedesktop.systemd1 /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager.GetUnitByInvocationID \
    array:byte:1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1 2>&1); then
    echo 'unknown InvocationID unexpectedly succeeded' >&2
    exit 1
fi
case "$unknown" in
    *'Error org.freedesktop.systemd1.NoUnitForInvocationID: No unit with the specified invocation ID 01010101010101010101010101010101 known.'*)
        ;;
    *)
        echo "unexpected unknown InvocationID error: $unknown" >&2
        exit 1
        ;;
esac

printf '%s\n' 'manager invocation-ID oracle: PASS'
