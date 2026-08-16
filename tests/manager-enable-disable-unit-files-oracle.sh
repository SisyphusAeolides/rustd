#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
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
    if [ -n "$dbus_pid" ]; then kill "$dbus_pid" 2>/dev/null || :; fi
    chmod u+rwx "$runtime_dir/systemd/inaccessible" 2>/dev/null || :
    rm -rf "$runtime_dir"
}
trap cleanup EXIT HUP INT TERM
mkdir -p "$runtime_dir/config/systemd/user" "$runtime_dir/state"
printf '%s\n' '[Unit]' 'Description=Enabled unit' '[Install]' \
    'WantedBy=default.target' 'Alias=alias.service' \
    >"$runtime_dir/config/systemd/user/foo.service"
printf '%s\n' '[Unit]' 'Description=Static unit' >"$runtime_dir/config/systemd/user/static.service"
ln -s /dev/null "$runtime_dir/config/systemd/user/masked.service"
mkdir -p "$runtime_dir/external"
printf '%s\n' '[Unit]' '[Install]' 'WantedBy=default.target' \
    'Alias=external-alias.service' >"$runtime_dir/external/external.service"
printf '%s\n' '[Unit]' >"$runtime_dir/external/link-only.service"
dbus-daemon --session --fork --address="unix:path=$runtime_dir/bus" --print-pid=1 >"$runtime_dir/dbus-pid"
dbus_pid=$(sed -n '1p' "$runtime_dir/dbus-pid")
export XDG_RUNTIME_DIR="$runtime_dir"
export DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime_dir/bus"
export XDG_CONFIG_HOME="$runtime_dir/config"
export XDG_STATE_HOME="$runtime_dir/state"
export SYSTEMD_UNIT_PATH="$runtime_dir/config/systemd/user:/usr/lib/systemd/user"
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
[ "$ready" -eq 1 ] || { cat "$runtime_dir/systemd.err" >&2; exit 1; }

xml=$(busctl --user --no-pager --xml-interface introspect \
    org.freedesktop.systemd1 /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager)
enable_method=$(printf '%s\n' "$xml" | sed -n '/<method name="EnableUnitFiles"/,/<\/method>/p')
disable_method=$(printf '%s\n' "$xml" | sed -n '/<method name="DisableUnitFiles"/,/<\/method>/p')
reenable_method=$(printf '%s\n' "$xml" | sed -n '/<method name="ReenableUnitFiles"/,/<\/method>/p')
link_method=$(printf '%s\n' "$xml" | sed -n '/<method name="LinkUnitFiles"/,/<\/method>/p')
links_method=$(printf '%s\n' "$xml" | sed -n '/<method name="GetUnitFileLinks"/,/<\/method>/p')
enable_flags_method=$(printf '%s\n' "$xml" | sed -n '/<method name="EnableUnitFilesWithFlags"/,/<\/method>/p')
disable_flags_method=$(printf '%s\n' "$xml" | sed -n '/<method name="DisableUnitFilesWithFlags"/,/<\/method>/p')
disable_flags_info_method=$(printf '%s\n' "$xml" | sed -n '/<method name="DisableUnitFilesWithFlagsAndInstallInfo"/,/<\/method>/p')
printf '%s\n' "$enable_method" | grep -F '<arg type="as" name="files" direction="in"/>' >/dev/null
printf '%s\n' "$enable_method" | grep -F '<arg type="b" name="runtime" direction="in"/>' >/dev/null
printf '%s\n' "$enable_method" | grep -F '<arg type="b" name="force" direction="in"/>' >/dev/null
printf '%s\n' "$enable_method" | grep -F '<arg type="b" name="carries_install_info" direction="out"/>' >/dev/null
printf '%s\n' "$enable_method" | grep -F '<arg type="a(sss)" name="changes" direction="out"/>' >/dev/null
printf '%s\n' "$disable_method" | grep -F '<arg type="as" name="files" direction="in"/>' >/dev/null
printf '%s\n' "$disable_method" | grep -F '<arg type="b" name="runtime" direction="in"/>' >/dev/null
printf '%s\n' "$disable_method" | grep -F '<arg type="a(sss)" name="changes" direction="out"/>' >/dev/null
printf '%s\n' "$reenable_method" | grep -F '<arg type="as" name="files" direction="in"/>' >/dev/null
printf '%s\n' "$reenable_method" | grep -F '<arg type="b" name="runtime" direction="in"/>' >/dev/null
printf '%s\n' "$reenable_method" | grep -F '<arg type="b" name="force" direction="in"/>' >/dev/null
printf '%s\n' "$reenable_method" | grep -F '<arg type="b" name="carries_install_info" direction="out"/>' >/dev/null
printf '%s\n' "$reenable_method" | grep -F '<arg type="a(sss)" name="changes" direction="out"/>' >/dev/null
printf '%s\n' "$link_method" | grep -F '<arg type="as" name="files" direction="in"/>' >/dev/null
printf '%s\n' "$link_method" | grep -F '<arg type="b" name="runtime" direction="in"/>' >/dev/null
printf '%s\n' "$link_method" | grep -F '<arg type="b" name="force" direction="in"/>' >/dev/null
printf '%s\n' "$link_method" | grep -F '<arg type="a(sss)" name="changes" direction="out"/>' >/dev/null
printf '%s\n' "$links_method" | grep -F '<arg type="s" name="name" direction="in"/>' >/dev/null
printf '%s\n' "$links_method" | grep -F '<arg type="b" name="runtime" direction="in"/>' >/dev/null
printf '%s\n' "$links_method" | grep -F '<arg type="as" name="links" direction="out"/>' >/dev/null
printf '%s\n' "$enable_flags_method" | grep -F '<arg type="as" name="files" direction="in"/>' >/dev/null
printf '%s\n' "$enable_flags_method" | grep -F '<arg type="t" name="flags" direction="in"/>' >/dev/null
printf '%s\n' "$enable_flags_method" | grep -F '<arg type="b" name="carries_install_info" direction="out"/>' >/dev/null
printf '%s\n' "$enable_flags_method" | grep -F '<arg type="a(sss)" name="changes" direction="out"/>' >/dev/null
printf '%s\n' "$disable_flags_method" | grep -F '<arg type="as" name="files" direction="in"/>' >/dev/null
printf '%s\n' "$disable_flags_method" | grep -F '<arg type="t" name="flags" direction="in"/>' >/dev/null
printf '%s\n' "$disable_flags_method" | grep -F '<arg type="a(sss)" name="changes" direction="out"/>' >/dev/null
printf '%s\n' "$disable_flags_info_method" | grep -F '<arg type="t" name="flags" direction="in"/>' >/dev/null
printf '%s\n' "$disable_flags_info_method" | grep -F '<arg type="b" name="carries_install_info" direction="out"/>' >/dev/null
printf '%s\n' "$disable_flags_info_method" | grep -F '<arg type="a(sss)" name="changes" direction="out"/>' >/dev/null

result=$(gdbus call --session --dest org.freedesktop.systemd1 \
    --object-path /org/freedesktop/systemd1 \
    --method org.freedesktop.systemd1.Manager.EnableUnitFiles \
    '["foo.service"]' false false)
expected="(true, [('symlink', '$runtime_dir/config/systemd/user/alias.service', '$runtime_dir/config/systemd/user/foo.service'), ('symlink', '$runtime_dir/config/systemd/user/default.target.wants/foo.service', '$runtime_dir/config/systemd/user/foo.service')])"
[ "$result" = "$expected" ]
[ -L "$runtime_dir/config/systemd/user/alias.service" ]
[ -L "$runtime_dir/config/systemd/user/default.target.wants/foo.service" ]

result=$(gdbus call --session --dest org.freedesktop.systemd1 \
    --object-path /org/freedesktop/systemd1 \
    --method org.freedesktop.systemd1.Manager.ReenableUnitFiles \
    '["foo.service"]' false false)
expected="(true, [('unlink', '$runtime_dir/config/systemd/user/default.target.wants/foo.service', ''), ('unlink', '$runtime_dir/config/systemd/user/alias.service', ''), ('symlink', '$runtime_dir/config/systemd/user/alias.service', '$runtime_dir/config/systemd/user/foo.service'), ('symlink', '$runtime_dir/config/systemd/user/default.target.wants/foo.service', '$runtime_dir/config/systemd/user/foo.service')])"
[ "$result" = "$expected" ]

result=$(gdbus call --session --dest org.freedesktop.systemd1 \
    --object-path /org/freedesktop/systemd1 \
    --method org.freedesktop.systemd1.Manager.GetUnitFileLinks \
    'foo.service' false)
printf '%s\n' "$result" | grep -F "$runtime_dir/config/systemd/user/default.target.wants/foo.service" >/dev/null
printf '%s\n' "$result" | grep -F "$runtime_dir/config/systemd/user/alias.service" >/dev/null

result=$(gdbus call --session --dest org.freedesktop.systemd1 \
    --object-path /org/freedesktop/systemd1 \
    --method org.freedesktop.systemd1.Manager.EnableUnitFiles \
    '["foo.service"]' false false)
printf '%s\n' "$result" | grep -F '(true, @a(sss) [])' >/dev/null
result=$(gdbus call --session --dest org.freedesktop.systemd1 \
    --object-path /org/freedesktop/systemd1 \
    --method org.freedesktop.systemd1.Manager.EnableUnitFiles \
    '["static.service"]' false false)
printf '%s\n' "$result" | grep -F '(false, @a(sss) [])' >/dev/null

if gdbus call --session --dest org.freedesktop.systemd1 \
    --object-path /org/freedesktop/systemd1 \
    --method org.freedesktop.systemd1.Manager.EnableUnitFiles \
    '["missing.service"]' false false >"$runtime_dir/missing" 2>&1; then
    echo 'missing enable target unexpectedly succeeded' >&2
    exit 1
fi
grep -F 'GDBus.Error:org.freedesktop.systemd1.NoSuchUnit: Unit missing.service does not exist' "$runtime_dir/missing" >/dev/null

result=$(gdbus call --session --dest org.freedesktop.systemd1 \
    --object-path /org/freedesktop/systemd1 \
    --method org.freedesktop.systemd1.Manager.DisableUnitFiles \
    '["foo.service"]' false)
expected="([('unlink', '$runtime_dir/config/systemd/user/default.target.wants/foo.service', ''), ('unlink', '$runtime_dir/config/systemd/user/alias.service', '')],)"
[ "$result" = "$expected" ]
[ ! -e "$runtime_dir/config/systemd/user/alias.service" ]
[ ! -e "$runtime_dir/config/systemd/user/default.target.wants/foo.service" ]

result=$(gdbus call --session --dest org.freedesktop.systemd1 \
    --object-path /org/freedesktop/systemd1 \
    --method org.freedesktop.systemd1.Manager.EnableUnitFiles \
    "['$runtime_dir/external/external.service']" false false)
expected="(true, [('symlink', '$runtime_dir/config/systemd/user/external.service', '$runtime_dir/external/external.service'), ('symlink', '$runtime_dir/config/systemd/user/external-alias.service', '$runtime_dir/config/systemd/user/external.service'), ('symlink', '$runtime_dir/config/systemd/user/default.target.wants/external.service', '$runtime_dir/external/external.service')])"
[ "$result" = "$expected" ]

result=$(gdbus call --session --dest org.freedesktop.systemd1 \
    --object-path /org/freedesktop/systemd1 \
    --method org.freedesktop.systemd1.Manager.LinkUnitFiles \
    "['$runtime_dir/external/link-only.service']" false false)
expected="([('symlink', '$runtime_dir/config/systemd/user/link-only.service', '$runtime_dir/external/link-only.service')],)"
[ "$result" = "$expected" ]

result=$(gdbus call --session --dest org.freedesktop.systemd1 \
    --object-path /org/freedesktop/systemd1 \
    --method org.freedesktop.systemd1.Manager.LinkUnitFiles \
    "['$runtime_dir/external/link-only.service']" false false)
[ "$result" = '(@a(sss) [],)' ]

if gdbus call --session --dest org.freedesktop.systemd1 \
    --object-path /org/freedesktop/systemd1 \
    --method org.freedesktop.systemd1.Manager.EnableUnitFiles \
    '["masked.service"]' false false >"$runtime_dir/masked" 2>&1; then
    echo 'masked enable target unexpectedly succeeded' >&2
    exit 1
fi
grep -F "GDBus.Error:org.freedesktop.systemd1.UnitMasked: Unit $runtime_dir/config/systemd/user/masked.service is masked" "$runtime_dir/masked" >/dev/null

result=$(gdbus call --session --dest org.freedesktop.systemd1 \
    --object-path /org/freedesktop/systemd1 \
    --method org.freedesktop.systemd1.Manager.DisableUnitFiles \
    '["masked.service"]' false)
expected="([('masked', '$runtime_dir/config/systemd/user/masked.service', '')],)"
[ "$result" = "$expected" ]

if gdbus call --session --dest org.freedesktop.systemd1 \
    --object-path /org/freedesktop/systemd1 \
    --method org.freedesktop.systemd1.Manager.EnableUnitFiles \
    '["../bad.service"]' false false >"$runtime_dir/invalid" 2>&1; then
    echo 'invalid enable name unexpectedly succeeded' >&2
    exit 1
fi
grep -F 'GDBus.Error:org.freedesktop.DBus.Error.InvalidArgs: File ../bad.service: Invalid argument' "$runtime_dir/invalid" >/dev/null
printf '%s\n' 'manager EnableUnitFiles/DisableUnitFiles oracle: PASS'
