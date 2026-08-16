#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Non-mutating v261 host oracle for Manager.DefaultOOMScoreAdjust.

set -eu

xml=$(busctl --system --no-pager --xml-interface introspect \
    org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager)
property=$(printf '%s\n' "$xml" | sed -n \
    '/<property name="DefaultOOMScoreAdjust"/,/<\/property>/p')
case "$property" in
    *'<property name="DefaultOOMScoreAdjust" type="i" access="read">'*'EmitsChangedSignal" value="const"'*)
        ;;
    *)
        echo 'missing v261 DefaultOOMScoreAdjust property contract' >&2
        exit 1
        ;;
esac

# With no DefaultOOMScoreAdjust= override, v261's property getter reads the
# live manager process adjustment. This host's configured value is the same
# process-visible default, so compare it directly without changing PID 1.
expected=$(tr -d '\n' </proc/1/oom_score_adj)
actual=$(busctl --system --no-pager get-property \
    org.freedesktop.systemd1 /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager DefaultOOMScoreAdjust)
[ "$actual" = "i $expected" ]

printf '%s\n' 'manager DefaultOOMScoreAdjust oracle: PASS'
