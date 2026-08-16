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
printf '%s\n' '[Unit]' 'Description=Dependency target' >"$runtime_dir/config/systemd/user/parity.target"
printf '%s\n' '[Unit]' 'Description=Dependency source' >"$runtime_dir/config/systemd/user/dependency.service"
ln -s /dev/null "$runtime_dir/config/systemd/user/masked.target"
ln -s /dev/null "$runtime_dir/config/systemd/user/masked.service"
ln -s missing.service "$runtime_dir/config/systemd/user/dangling.service"

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

xml=$(busctl --user --no-pager --xml-interface introspect org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager)
method=$(printf '%s\n' "$xml" | sed -n '/<method name="AddDependencyUnitFiles"/,/<\/method>/p')
printf '%s\n' "$method" | grep -F '<arg type="as" name="files" direction="in"/>' >/dev/null
printf '%s\n' "$method" | grep -F '<arg type="s" name="target" direction="in"/>' >/dev/null
printf '%s\n' "$method" | grep -F '<arg type="s" name="type" direction="in"/>' >/dev/null
printf '%s\n' "$method" | grep -F '<arg type="b" name="runtime" direction="in"/>' >/dev/null
printf '%s\n' "$method" | grep -F '<arg type="b" name="force" direction="in"/>' >/dev/null
printf '%s\n' "$method" | grep -F '<arg type="a(sss)" name="changes" direction="out"/>' >/dev/null

result=$(gdbus call --session --dest org.freedesktop.systemd1 --object-path /org/freedesktop/systemd1 --method org.freedesktop.systemd1.Manager.AddDependencyUnitFiles '["dependency.service"]' parity.target Wants false false)
expected="([('symlink', '$runtime_dir/config/systemd/user/parity.target.wants/dependency.service', '$runtime_dir/config/systemd/user/dependency.service')],)"
[ "$result" = "$expected" ]
[ -L "$runtime_dir/config/systemd/user/parity.target.wants/dependency.service" ]

printf '%s\n' '[Unit]' 'Description=Linked dependency source' >"$runtime_dir/linked.service"
result=$(gdbus call --session --dest org.freedesktop.systemd1 --object-path /org/freedesktop/systemd1 --method org.freedesktop.systemd1.Manager.AddDependencyUnitFiles "['$runtime_dir/linked.service']" parity.target Wants false false)
expected="([('symlink', '$runtime_dir/config/systemd/user/linked.service', '$runtime_dir/linked.service'), ('symlink', '$runtime_dir/config/systemd/user/parity.target.wants/linked.service', '$runtime_dir/linked.service')],)"
[ "$result" = "$expected" ]
[ -L "$runtime_dir/config/systemd/user/linked.service" ]
[ -L "$runtime_dir/config/systemd/user/parity.target.wants/linked.service" ]

result=$(gdbus call --session --dest org.freedesktop.systemd1 --object-path /org/freedesktop/systemd1 --method org.freedesktop.systemd1.Manager.AddDependencyUnitFiles '["dependency.service"]' parity.target Wants false false)
[ "$result" = '(@a(sss) [],)' ]

result=$(gdbus call --session --dest org.freedesktop.systemd1 --object-path /org/freedesktop/systemd1 --method org.freedesktop.systemd1.Manager.AddDependencyUnitFiles '["dependency.service"]' parity.target Requires true false)
expected="([('symlink', '$runtime_dir/systemd/user/parity.target.requires/dependency.service', '$runtime_dir/config/systemd/user/dependency.service')],)"
[ "$result" = "$expected" ]
[ -L "$runtime_dir/systemd/user/parity.target.requires/dependency.service" ]

if gdbus call --session --dest org.freedesktop.systemd1 --object-path /org/freedesktop/systemd1 --method org.freedesktop.systemd1.Manager.AddDependencyUnitFiles '["dependency.service"]' parity.target Other false false >"$runtime_dir/type-error" 2>&1; then
    echo 'invalid dependency type unexpectedly succeeded' >&2
    exit 1
fi
grep -F 'GDBus.Error:org.freedesktop.DBus.Error.InvalidArgs: Invalid argument' "$runtime_dir/type-error" >/dev/null

if gdbus call --session --dest org.freedesktop.systemd1 --object-path /org/freedesktop/systemd1 --method org.freedesktop.systemd1.Manager.AddDependencyUnitFiles '["dependency.service"]' bad Wants false false >"$runtime_dir/bad-target" 2>&1; then
    echo 'invalid dependency target unexpectedly succeeded' >&2
    exit 1
fi
grep -F 'GDBus.Error:org.freedesktop.systemd1.BadUnitSetting: Invalid unit name bad' "$runtime_dir/bad-target" >/dev/null

if gdbus call --session --dest org.freedesktop.systemd1 --object-path /org/freedesktop/systemd1 --method org.freedesktop.systemd1.Manager.AddDependencyUnitFiles '["dependency.service"]' masked.target Wants false false >"$runtime_dir/masked-target" 2>&1; then
    echo 'masked dependency target unexpectedly succeeded' >&2
    exit 1
fi
grep -F "GDBus.Error:org.freedesktop.systemd1.UnitMasked: Unit $runtime_dir/config/systemd/user/masked.target is masked" "$runtime_dir/masked-target" >/dev/null

if gdbus call --session --dest org.freedesktop.systemd1 --object-path /org/freedesktop/systemd1 --method org.freedesktop.systemd1.Manager.AddDependencyUnitFiles '["masked.service"]' parity.target Wants false false >"$runtime_dir/masked-source" 2>&1; then
    echo 'masked dependency source unexpectedly succeeded' >&2
    exit 1
fi
grep -F "GDBus.Error:org.freedesktop.systemd1.UnitMasked: Unit $runtime_dir/config/systemd/user/masked.service is masked" "$runtime_dir/masked-source" >/dev/null

if gdbus call --session --dest org.freedesktop.systemd1 --object-path /org/freedesktop/systemd1 --method org.freedesktop.systemd1.Manager.AddDependencyUnitFiles '["dependency.service"]' missing.target Wants false false >"$runtime_dir/missing" 2>&1; then
    echo 'missing dependency target unexpectedly succeeded' >&2
    exit 1
fi
grep -F 'GDBus.Error:org.freedesktop.systemd1.NoSuchUnit: Unit missing.target does not exist' "$runtime_dir/missing" >/dev/null

if gdbus call --session --dest org.freedesktop.systemd1 --object-path /org/freedesktop/systemd1 --method org.freedesktop.systemd1.Manager.AddDependencyUnitFiles '["missing.service"]' parity.target Wants false false >"$runtime_dir/missing-source" 2>&1; then
    echo 'missing dependency source unexpectedly succeeded' >&2
    exit 1
fi
grep -F 'GDBus.Error:org.freedesktop.systemd1.NoSuchUnit: Unit missing.service does not exist' "$runtime_dir/missing-source" >/dev/null

if gdbus call --session --dest org.freedesktop.systemd1 --object-path /org/freedesktop/systemd1 --method org.freedesktop.systemd1.Manager.AddDependencyUnitFiles '["dangling.service"]' parity.target Wants false false >"$runtime_dir/dangling-source" 2>&1; then
    echo 'dangling dependency source unexpectedly succeeded' >&2
    exit 1
fi
grep -F 'GDBus.Error:org.freedesktop.systemd1.NoSuchUnit: Unit dangling.service is an unresolvable alias' "$runtime_dir/dangling-source" >/dev/null

if gdbus call --session --dest org.freedesktop.systemd1 --object-path /org/freedesktop/systemd1 --method org.freedesktop.systemd1.Manager.AddDependencyUnitFiles '["../bad.service"]' parity.target Wants false false >"$runtime_dir/invalid" 2>&1; then
    echo 'invalid dependency file unexpectedly succeeded' >&2
    exit 1
fi
grep -F 'GDBus.Error:org.freedesktop.DBus.Error.InvalidArgs: File ../bad.service: Invalid argument' "$runtime_dir/invalid" >/dev/null

printf '%s\n' 'manager AddDependencyUnitFiles oracle: PASS'
