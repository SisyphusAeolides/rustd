#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# v261 host/candidate oracle for delegated Manager cgroup methods.
set -eu

host_xml=
host_methods=0
if host_xml=$(busctl --system --no-pager --xml-interface introspect \
    org.freedesktop.systemd1 /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager 2>/dev/null); then
    if printf '%s\n' "$host_xml" | grep -F '<method name="AttachProcessesToUnit">' >/dev/null &&
            printf '%s\n' "$host_xml" | grep -F '<method name="RemoveSubgroupFromUnit">' >/dev/null; then
        host_methods=1
    fi
fi

if [ "$host_methods" -eq 1 ]; then
    printf '%s\n' "$host_xml" | grep -F '<arg type="au" name="pids" direction="in"/>' >/dev/null
    printf '%s\n' "$host_xml" | grep -F '<arg type="t" name="flags" direction="in"/>' >/dev/null

    if host_relative=$(busctl --system --no-pager call \
        org.freedesktop.systemd1 /org/freedesktop/systemd1 \
        org.freedesktop.systemd1.Manager AttachProcessesToUnit \
        ssau system.slice relative 0 2>&1); then
        echo 'host accepted a relative cgroup path' >&2
        exit 1
    fi
    printf '%s\n' "$host_relative" | grep -F 'Control group path is not absolute: relative' >/dev/null

    if host_flags=$(busctl --system --no-pager call \
        org.freedesktop.systemd1 /org/freedesktop/systemd1 \
        org.freedesktop.systemd1.Manager RemoveSubgroupFromUnit \
        sst system.slice / 1 2>&1); then
        echo 'host accepted non-zero subgroup flags' >&2
        exit 1
    fi
    printf '%s\n' "$host_flags" | grep -F "Invalid 'flags' parameter '1'" >/dev/null
else
    printf '%s\n' 'manager cgroup delegation host probes: SKIP (host manager lacks v261 methods)'
fi

runtime_dir=$(mktemp -d)
dbus_pid=
manager_pid=
helper_pid=
cleanup() {
    [ -z "$helper_pid" ] || kill "$helper_pid" 2>/dev/null || :
    if [ -n "$manager_pid" ]; then
        kill "$manager_pid" 2>/dev/null || :
        sleep 0.1
        kill -KILL "$manager_pid" 2>/dev/null || :
        wait "$manager_pid" 2>/dev/null || :
    fi
    [ -z "$dbus_pid" ] || kill "$dbus_pid" 2>/dev/null || :
    rm -rf "$runtime_dir"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$runtime_dir/units" "$runtime_dir/cgroup"
cat >"$runtime_dir/units/rustd-cgroup-oracle.service" <<'EOF'
[Unit]
Description=rustd delegated cgroup oracle

[Service]
Type=simple
Delegate=yes
ExecStart=/bin/sleep 60
EOF

dbus-daemon --session --fork --address="unix:path=$runtime_dir/bus" --print-pid=1 \
    >"$runtime_dir/dbus-pid"
dbus_pid=$(sed -n '1p' "$runtime_dir/dbus-pid")
export XDG_RUNTIME_DIR="$runtime_dir"
export DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime_dir/bus"
export SYSTEMD_UNIT_PATH="$runtime_dir/units:/usr/lib/systemd/user"
export RUSTD_CGROUP_ROOT="$runtime_dir/cgroup"

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
[ "$ready" -eq 1 ] || { sed -n '1,160p' "$runtime_dir/manager.err" >&2; exit 1; }

manager_call() {
    busctl --user --no-pager call org.freedesktop.systemd1 \
        /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager "$@"
}

candidate_xml=$(busctl --user --no-pager --xml-interface introspect \
    org.freedesktop.systemd1 /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager)
printf '%s\n' "$candidate_xml" | grep -F '<method name="AttachProcessesToUnit">' >/dev/null
printf '%s\n' "$candidate_xml" | grep -F '<method name="RemoveSubgroupFromUnit">' >/dev/null
printf '%s\n' "$candidate_xml" | grep -F '<arg type="au" name="pids" direction="in"/>' >/dev/null
printf '%s\n' "$candidate_xml" | grep -F '<arg type="t" name="flags" direction="in"/>' >/dev/null

manager_call StartUnit ss rustd-cgroup-oracle.service replace >/dev/null
unit_path=/org/freedesktop/systemd1/unit/rustd_2dcgroup_2doracle_2eservice
active=0
attempt=0
while [ "$attempt" -lt 100 ]; do
    state=$(busctl --user --no-pager get-property org.freedesktop.systemd1 \
        "$unit_path" org.freedesktop.systemd1.Unit ActiveState 2>/dev/null || :)
    case "$state" in *'"active"'*) active=1; break ;; esac
    attempt=$((attempt + 1))
    sleep 0.05
done
[ "$active" -eq 1 ] || { sed -n '1,160p' "$runtime_dir/manager.err" >&2; exit 1; }

uid=$(id -u)
unit_cgroup="$runtime_dir/cgroup/user.slice/user-$uid.slice/user@$uid.service/app.slice/rustd-cgroup-oracle.service"
[ -d "$unit_cgroup" ] || { echo 'missing candidate delegated cgroup' >&2; exit 1; }
mkdir -p "$unit_cgroup/workers"
: >"$unit_cgroup/workers/cgroup.procs"
/bin/sleep 60 &
helper_pid=$!
manager_call AttachProcessesToUnit ssau \
    rustd-cgroup-oracle.service /workers 1 "$helper_pid" >/dev/null
grep -Fx "$helper_pid" "$unit_cgroup/workers/cgroup.procs" >/dev/null

if busy=$(manager_call RemoveSubgroupFromUnit sst rustd-cgroup-oracle.service /workers 0 2>&1); then
    echo 'candidate removed populated delegated subgroup' >&2
    exit 1
fi
printf '%s\n' "$busy" | grep -F 'Device or resource busy' >/dev/null
: >"$unit_cgroup/workers/cgroup.procs"
manager_call RemoveSubgroupFromUnit sst rustd-cgroup-oracle.service /workers 0 >/dev/null
[ ! -e "$unit_cgroup/workers" ] || { echo 'candidate left empty subgroup' >&2; exit 1; }

if invalid=$(manager_call AttachProcessesToUnit ssau rustd-cgroup-oracle.service relative 0 2>&1); then
    echo 'candidate accepted relative cgroup path' >&2
    exit 1
fi
printf '%s\n' "$invalid" | grep -F 'Control group path is not absolute: relative' >/dev/null
if flags=$(manager_call RemoveSubgroupFromUnit sst rustd-cgroup-oracle.service / 1 2>&1); then
    echo 'candidate accepted non-zero flags' >&2
    exit 1
fi
printf '%s\n' "$flags" | grep -F "Invalid 'flags' parameter '1'" >/dev/null
printf '%s\n' 'manager cgroup delegation oracle: PASS'
