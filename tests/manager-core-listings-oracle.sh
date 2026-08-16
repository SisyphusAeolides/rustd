#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Read-only host oracle for v261's core Manager listing method contracts.
# It only introspects the live system manager.

set -eu

xml=$(busctl --system --no-pager --xml-interface introspect \
    org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager)

assert_method_argument() {
    method_name=$1
    argument=$2
    method=$(printf '%s\n' "$xml" | sed -n "/<method name=\"$method_name\"/,/<\/method>/p")
    case "$method" in
        *"$argument"*) ;;
        *)
            echo "missing v261 $method_name argument: $argument" >&2
            exit 1
            ;;
    esac
}

units='a(ssssssouso)'
jobs='a(usssoo)'
assert_method_argument ListUnits "<arg type=\"$units\" name=\"units\" direction=\"out\"/>"
assert_method_argument ListUnitsFiltered '<arg type="as" name="states" direction="in"/>'
assert_method_argument ListUnitsFiltered "<arg type=\"$units\" name=\"units\" direction=\"out\"/>"
assert_method_argument ListUnitsByPatterns '<arg type="as" name="states" direction="in"/>'
assert_method_argument ListUnitsByPatterns '<arg type="as" name="patterns" direction="in"/>'
assert_method_argument ListUnitsByPatterns "<arg type=\"$units\" name=\"units\" direction=\"out\"/>"
assert_method_argument ListJobs "<arg type=\"$jobs\" name=\"jobs\" direction=\"out\"/>"

printf '%s\n' 'manager core-listings oracle: PASS'
