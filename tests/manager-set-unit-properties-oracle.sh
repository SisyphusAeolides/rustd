#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Host/candidate v261 oracle for Manager SetUnitProperties.

set -eu

runtime_dir=$(mktemp -d)
dbus_pid=
manager_pid=
candidate_mode=${RUSTD_CANDIDATE_ORACLE:-0}
cleanup() {
    if [ -n "$manager_pid" ]; then
        kill "$manager_pid" 2>/dev/null || :
        sleep 0.1
        kill -KILL "$manager_pid" 2>/dev/null || :
        wait "$manager_pid" 2>/dev/null || :
    fi
    if [ -n "$dbus_pid" ]; then
        kill "$dbus_pid" 2>/dev/null || :
    fi
    chmod u+rwx "$runtime_dir/systemd/inaccessible" 2>/dev/null || :
    rm -rf "$runtime_dir"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$runtime_dir/units" "$runtime_dir/home" "$runtime_dir/config"
cat >"$runtime_dir/units/set-property-oracle.service" <<'EOF'
[Unit]
Description=SetUnitProperties oracle service

[Service]
Type=simple
ExecStart=/bin/sleep 60
EOF

dbus-daemon --session --fork --address="unix:path=$runtime_dir/bus" --print-pid=1 \
    >"$runtime_dir/dbus-pid"
dbus_pid=$(sed -n '1p' "$runtime_dir/dbus-pid")
export HOME="$runtime_dir/home"
export XDG_CONFIG_HOME="$runtime_dir/config"
export XDG_RUNTIME_DIR="$runtime_dir"
export DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime_dir/bus"
export SYSTEMD_UNIT_PATH="$runtime_dir/units:/usr/lib/systemd/user"
export RUSTD_CGROUP_ROOT="$runtime_dir/cgroup"

# A pre-created fake cgroup makes a candidate's actual live write observable,
# while the host manager (which does not honor RUSTD_CGROUP_ROOT) leaves
# the sentinel untouched and is still a valid D-Bus oracle.
uid=$(id -u)
cgroup="$runtime_dir/cgroup/user.slice/user-$uid.slice/user@$uid.service/app.slice/set-property-oracle.service"
mkdir -p "$cgroup"
printf '100\n' >"$cgroup/cpu.weight"

/usr/lib/systemd/systemd --user >"$runtime_dir/manager.out" 2>"$runtime_dir/manager.err" &
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
[ "$ready" -eq 1 ] || { cat "$runtime_dir/manager.err" >&2; exit 1; }

xml=$(busctl --user --no-pager --xml-interface introspect \
    org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager)
case "$xml" in
    *'name="SetUnitProperties"'*) ;;
    *) printf '%s\n' 'manager SetUnitProperties oracle: SKIP (host manager lacks v261 method)'; exit 0 ;;
esac
method=$(printf '%s\n' "$xml" | sed -n '/<method name="SetUnitProperties"/,/<\/method>/p')
for argument in \
    '<arg type="s" name="name" direction="in"/>' \
    '<arg type="b" name="runtime" direction="in"/>' \
    '<arg type="a(sv)" name="properties" direction="in"/>'
do
    printf '%s\n' "$method" | grep -F "$argument" >/dev/null
done

if [ "$candidate_mode" -ne 1 ]; then
    printf '%s\n' 'manager SetUnitProperties oracle: PASS (host signature; live-value semantics skipped)'
    exit 0
fi

gdbus_call() {
    gdbus call --session --dest org.freedesktop.systemd1 \
        --object-path /org/freedesktop/systemd1 \
        --method org.freedesktop.systemd1.Manager.SetUnitProperties "$@"
}
unit_path=/org/freedesktop/systemd1/unit/set_2dproperty_2doracle_2eservice
expect_property() {
    interface=$1
    property=$2
    expected=$3
    actual=$(busctl --user --no-pager get-property org.freedesktop.systemd1 "$unit_path" \
        "$interface" "$property" 2>&1) || {
        echo "failed to read $interface.$property: $actual" >&2
        exit 1
    }
    [ "$actual" = "$expected" ] || {
        echo "unexpected $interface.$property: got '$actual', expected '$expected'" >&2
        exit 1
    }
}

# Persistent properties use the configured user control root and are visible
# through the live unit object before a separate daemon-reload.
gdbus_call set-property-oracle.service false \
    "[(\"CPUWeight\", <uint64 300>), (\"Description\", <'Persistent property'>)]" >/dev/null
expect_property org.freedesktop.systemd1.Service CPUWeight 't 300'
expect_property org.freedesktop.systemd1.Unit Description 's "Persistent property"'

# Runtime settings override the persistent value and are written to the
# volatile control hierarchy.
gdbus_call set-property-oracle.service true \
    "[(\"CPUWeight\", <uint64 250>)]" >/dev/null
expect_property org.freedesktop.systemd1.Service CPUWeight 't 250'

# CPUWeight=0 is v261's explicit idle sentinel, distinct from UINT64_MAX
# (unset).  Restore the ordinary weight for the transaction/cgroup checks.
gdbus_call set-property-oracle.service true \
    "[(\"CPUWeight\", <uint64 0>)]" >/dev/null
expect_property org.freedesktop.systemd1.Service CPUWeight 't 0'
gdbus_call set-property-oracle.service true \
    "[(\"CPUWeight\", <uint64 250>)]" >/dev/null
expect_property org.freedesktop.systemd1.Service CPUWeight 't 250'

# A transaction containing a valid property followed by an unknown one must
# fail without applying the valid prefix.
if gdbus_call set-property-oracle.service true \
    "[(\"CPUWeight\", <uint64 500>), (\"UnknownProperty\", <uint64 1>)]" \
    >"$runtime_dir/invalid.out" 2>&1; then
    echo 'invalid SetUnitProperties transaction unexpectedly succeeded' >&2
    exit 1
fi
grep -E 'PropertyReadOnly|InvalidArgs' "$runtime_dir/invalid.out" >/dev/null
expect_property org.freedesktop.systemd1.Service CPUWeight 't 250'

# Wrong variant types are rejected at the method boundary.
if gdbus_call set-property-oracle.service true \
    "[(\"CPUWeight\", <'wrong type'>)]" >"$runtime_dir/type.out" 2>&1; then
    echo 'wrong SetUnitProperties variant unexpectedly succeeded' >&2
    exit 1
fi
grep -E 'InvalidArgs|Invalid argument|Invalid value' "$runtime_dir/type.out" >/dev/null

# Candidate-only fake-cgroup assertion: the host intentionally skips this
# because its systemd manager does not use the candidate's test root.
if [ "$(cat "$cgroup/cpu.weight")" != '100' ]; then
    [ "$(cat "$cgroup/cpu.weight")" = '250' ] || {
        echo 'candidate SetUnitProperties wrote an unexpected CPU weight' >&2
        exit 1
    }
    printf '%s\n' 'manager SetUnitProperties oracle: PASS (including live cgroup write)'
else
    printf '%s\n' 'manager SetUnitProperties oracle: PASS (host D-Bus parity; cgroup skipped)'
fi
