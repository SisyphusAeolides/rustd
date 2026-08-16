#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Read-only v261 Manager oracle for method argument names.  These names are
# part of the introspection contract even though D-Bus dispatch uses only the
# argument positions and signatures.

set -eu

xml=$(busctl --system --no-pager --xml-interface introspect \
    org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager)

assert_method_argument() {
    method_name=$1
    argument=$2
    selected_method=$(printf '%s\n' "$xml" | sed -n "/<method name=\"$method_name\"/,/<\/method>/p")
    case "$selected_method" in
        *"$argument"*) ;;
        *)
            echo "missing v261 $method_name argument: $argument" >&2
            exit 1
            ;;
    esac
}

for name in StartUnit StopUnit RestartUnit; do
    assert_method_argument "$name" '<arg type="s" name="name" direction="in"/>'
    assert_method_argument "$name" '<arg type="s" name="mode" direction="in"/>'
    assert_method_argument "$name" '<arg type="o" name="job" direction="out"/>'
done

assert_method_argument GetUnitFileState '<arg type="s" name="file" direction="in"/>'
assert_method_argument GetUnitFileState '<arg type="s" name="state" direction="out"/>'
assert_method_argument GetDefaultTarget '<arg type="s" name="name" direction="out"/>'
assert_method_argument GetJob '<arg type="u" name="id" direction="in"/>'
assert_method_argument GetJob '<arg type="o" name="job" direction="out"/>'

for name in GetJobAfter GetJobBefore; do
    assert_method_argument "$name" '<arg type="u" name="id" direction="in"/>'
    assert_method_argument "$name" '<arg type="a(usssoo)" name="jobs" direction="out"/>'
done

assert_method_argument ListUnitFiles '<arg type="a(ss)" name="unit_files" direction="out"/>'
assert_method_argument ListUnitFilesByPatterns '<arg type="as" name="states" direction="in"/>'
assert_method_argument ListUnitFilesByPatterns '<arg type="as" name="patterns" direction="in"/>'
assert_method_argument ListUnitFilesByPatterns '<arg type="a(ss)" name="unit_files" direction="out"/>'

printf '%s\n' 'manager output-argument-names oracle: PASS'
