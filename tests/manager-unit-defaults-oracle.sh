#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Isolated v261 Manager UnitDefaults oracle.  It checks configuration
# precedence, the Manager D-Bus values, inherited service limits, explicit
# service overrides, and percentage TasksMax resolution.  Candidate mode is
# selected by run-candidate-manager-oracles.sh; host mode skips only when the
# host does not expose the v261 properties.

set -eu

runtime_dir=$(mktemp -d)
dbus_pid=
manager_pid=
manager_unit=
candidate_mode=${RUSTD_CANDIDATE_ORACLE:-0}
host_runtime_dir=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}
host_bus_address=${DBUS_SESSION_BUS_ADDRESS:-unix:path=$host_runtime_dir/bus}
cleanup() {
    for unit in unit-default-inherited.service unit-default-explicit.service; do
        busctl --user --no-pager call org.freedesktop.systemd1 \
            /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager \
            StopUnit ss "$unit" replace >/dev/null 2>&1 || :
    done
    if [ -n "$manager_unit" ]; then
        XDG_RUNTIME_DIR="$host_runtime_dir" DBUS_SESSION_BUS_ADDRESS="$host_bus_address" \
            systemctl --user --no-block stop "$manager_unit" >/dev/null 2>&1 || :
    fi
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

# Keep the fixtures exclusively in the XDG user-unit hierarchy.  In
# particular, do not set SYSTEMD_UNIT_PATH: the post-reload inheritance
# checks below must fail if a user manager accidentally rebuilds a system
# loader during daemon-reload.
mkdir -p "$runtime_dir/home" "$runtime_dir/config/systemd/user.conf.d" \
    "$runtime_dir/config/systemd/user"
cat >"$runtime_dir/config/systemd/user.conf" <<'EOF'
[Manager]
DefaultLimitNOFILE=101:202
DefaultTasksMax=20%
EOF
# The later lexical assignment wins, while the duplicate-name rule is tested
# by the optional directory fixture below when the parser is run in isolation.
cat >"$runtime_dir/config/systemd/user.conf.d/10-unit-defaults.conf" <<'EOF'
[Manager]
DefaultLimitNOFILE=123:456
DefaultLimitCPU=1500ms
DefaultTasksMax=15%
EOF
cat >"$runtime_dir/config/systemd/user.conf.d/20-unit-defaults.conf" <<'EOF'
[Manager]
DefaultLimitNOFILE=321:654
DefaultTasksMax=2
EOF
cat >"$runtime_dir/config/systemd/user/unit-default-inherited.service" <<EOF
[Unit]
Description=UnitDefaults inherited limit oracle

[Service]
Type=oneshot
TasksMax=9
TasksMax=
ExecStart=/bin/sh -c 'ulimit -Sn > $runtime_dir/inherited.soft; ulimit -Hn > $runtime_dir/inherited.hard'
EOF
cat >"$runtime_dir/config/systemd/user/unit-default-explicit.service" <<EOF
[Unit]
Description=UnitDefaults explicit limit oracle

[Service]
Type=oneshot
LimitNOFILE=77:88
TasksMax=7
ExecStart=/bin/sh -c 'ulimit -Sn > $runtime_dir/explicit.soft; ulimit -Hn > $runtime_dir/explicit.hard'
EOF
if [ "$candidate_mode" -eq 0 ]; then
    cat >"$runtime_dir/config/systemd/user/default.target" <<'EOF'
[Unit]
Description=Isolated UnitDefaults Oracle Target
DefaultDependencies=no
Requires=dbus.socket dbus.service
After=dbus.socket
EOF
else
    cat >"$runtime_dir/config/systemd/user/default.target" <<'EOF'
[Unit]
Description=Isolated UnitDefaults Oracle Target
EOF
fi

if [ "$candidate_mode" -eq 1 ]; then
    dbus-daemon --session --fork --address="unix:path=$runtime_dir/bus" --print-pid=1 \
        >"$runtime_dir/dbus-pid"
    dbus_pid=$(sed -n '1p' "$runtime_dir/dbus-pid")
fi
private_bus_address="unix:path=$runtime_dir/bus"
manager_unit="manager-unit-defaults-oracle-$$.scope"
XDG_RUNTIME_DIR="$host_runtime_dir" DBUS_SESSION_BUS_ADDRESS="$host_bus_address" \
    systemd-run --user --scope --quiet --collect \
    --unit="$manager_unit" \
    --property=Delegate=yes \
    --property=TasksMax=infinity \
    --setenv="HOME=$runtime_dir/home" \
    --setenv="XDG_CONFIG_HOME=$runtime_dir/config" \
    --setenv="XDG_RUNTIME_DIR=$runtime_dir" \
    --setenv="DBUS_SESSION_BUS_ADDRESS=$private_bus_address" \
    /usr/bin/env -u MANAGERPID -u MANAGERPIDFDID -u INVOCATION_ID -u JOURNAL_STREAM \
    -u SYSTEMD_EXEC_PID -u RUSTD_NOTIFY_SOCKET -u SYSTEMD_UNIT_PATH \
    /usr/lib/systemd/systemd --user >"$runtime_dir/manager.out" \
    2>"$runtime_dir/manager.err" &
manager_pid=$!
export HOME="$runtime_dir/home"
export XDG_CONFIG_HOME="$runtime_dir/config"
export XDG_RUNTIME_DIR="$runtime_dir"
export DBUS_SESSION_BUS_ADDRESS="$private_bus_address"
unset SYSTEMD_UNIT_PATH
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
[ "$ready" -eq 1 ] || {
    cat "$runtime_dir/manager.out" >&2
    cat "$runtime_dir/manager.err" >&2
    XDG_RUNTIME_DIR="$host_runtime_dir" DBUS_SESSION_BUS_ADDRESS="$host_bus_address" \
        systemctl --user --no-pager status "$manager_unit" >&2 || :
    exit 1
}

xml=$(busctl --user --no-pager --xml-interface introspect \
    org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager)
for property in DefaultLimitNOFILE DefaultLimitNOFILESoft DefaultTasksMax; do
    if ! printf '%s\n' "$xml" | grep -F \
        "<property name=\"$property\" type=\"t\" access=\"read\">" >/dev/null; then
        if [ "$candidate_mode" -eq 1 ]; then
            echo "candidate Manager lacks $property" >&2
            exit 1
        fi
        echo "manager UnitDefaults oracle: SKIP (host manager lacks $property)"
        exit 0
    fi
done

get_property() {
    busctl --user --no-pager get-property org.freedesktop.systemd1 \
        /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager "$1" | awk '{print $2}'
}
get_unit_property() {
    busctl --user --no-pager get-property org.freedesktop.systemd1 "$1" "$2" "$3" | awk '{print $2}'
}

# The lexical 20-unit-defaults.conf assignment must win.
[ "$(get_property DefaultLimitNOFILE)" = 654 ]
[ "$(get_property DefaultLimitNOFILESoft)" = 321 ]
[ "$(get_property DefaultTasksMax)" = 2 ]

manager_call() {
    busctl --user --no-pager call org.freedesktop.systemd1 \
        /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager "$@"
}
manager_call StartUnit ss unit-default-inherited.service replace >/dev/null
manager_call StartUnit ss unit-default-explicit.service replace >/dev/null

attempt=0
while [ "$attempt" -lt 100 ] && [ ! -f "$runtime_dir/inherited.hard" ]; do
    attempt=$((attempt + 1))
    sleep 0.05
done
[ -f "$runtime_dir/inherited.hard" ]
[ "$(cat "$runtime_dir/inherited.soft")" = 321 ]
[ "$(cat "$runtime_dir/inherited.hard")" = 654 ]
[ "$(cat "$runtime_dir/explicit.soft")" = 77 ]
[ "$(cat "$runtime_dir/explicit.hard")" = 88 ]

inherited_path=/org/freedesktop/systemd1/unit/unit_2ddefault_2dinherited_2eservice
explicit_path=/org/freedesktop/systemd1/unit/unit_2ddefault_2dexplicit_2eservice
[ "$(get_unit_property "$inherited_path" org.freedesktop.systemd1.Service LimitNOFILE)" = 654 ]
[ "$(get_unit_property "$inherited_path" org.freedesktop.systemd1.Service LimitNOFILESoft)" = 321 ]
[ "$(get_unit_property "$inherited_path" org.freedesktop.systemd1.Service TasksMax)" = 2 ]
[ "$(get_unit_property "$explicit_path" org.freedesktop.systemd1.Service LimitNOFILE)" = 88 ]
[ "$(get_unit_property "$explicit_path" org.freedesktop.systemd1.Service LimitNOFILESoft)" = 77 ]
[ "$(get_unit_property "$explicit_path" org.freedesktop.systemd1.Service TasksMax)" = 7 ]

# Reload a winning permyriad assignment and compare the resolved Manager and
# inherited unit properties with system_tasks_max_scale().
cat >"$runtime_dir/config/systemd/user.conf.d/20-unit-defaults.conf" <<'EOF'
[Manager]
DefaultLimitNOFILE=321:654
DefaultTasksMax=12.5%
EOF
manager_call Reload >/dev/null
capacity=$(cat /proc/sys/kernel/threads-max)
pid_capacity=$(cat /proc/sys/kernel/pid_max)
pid_capacity=$((pid_capacity - 1))
[ "$pid_capacity" -ge "$capacity" ] || capacity=$pid_capacity
if [ -r /sys/fs/cgroup/pids.max ]; then
    root_capacity=$(cat /sys/fs/cgroup/pids.max)
    case "$root_capacity" in
        ''|*[!0-9]*) ;;
        *) [ "$root_capacity" -ge "$capacity" ] || capacity=$root_capacity ;;
    esac
fi
percentage_expected=$((capacity * 1250 / 10000))
attempt=0
while [ "$attempt" -lt 100 ] &&
    [ "$(get_property DefaultTasksMax)" != "$percentage_expected" ]; do
    attempt=$((attempt + 1))
    sleep 0.05
done
[ "$(get_property DefaultTasksMax)" = "$percentage_expected" ]
[ "$(get_unit_property "$inherited_path" org.freedesktop.systemd1.Service TasksMax)" = "$percentage_expected" ]
[ "$(get_unit_property "$explicit_path" org.freedesktop.systemd1.Service TasksMax)" = 7 ]

# An empty manager assignment selects the unlimited sentinel, while the empty
# unit assignment continues to restore that freshly reloaded manager default.
cat >"$runtime_dir/config/systemd/user.conf.d/20-unit-defaults.conf" <<'EOF'
[Manager]
DefaultLimitNOFILE=321:654
DefaultTasksMax=
EOF
manager_call Reload >/dev/null
attempt=0
while [ "$attempt" -lt 100 ] &&
    [ "$(get_property DefaultTasksMax)" != 18446744073709551615 ]; do
    attempt=$((attempt + 1))
    sleep 0.05
done
[ "$(get_property DefaultTasksMax)" = 18446744073709551615 ]
[ "$(get_unit_property "$inherited_path" org.freedesktop.systemd1.Service TasksMax)" = 18446744073709551615 ]
[ "$(get_unit_property "$explicit_path" org.freedesktop.systemd1.Service TasksMax)" = 7 ]

echo 'manager UnitDefaults oracle: PASS'
