#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu

runtime_dir=$(mktemp -d)
dbus_pid=
manager_pid=
emulator_pid=

cleanup() {
    [ -z "$emulator_pid" ] || kill "$emulator_pid" 2>/dev/null || :
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
cat >"$runtime_dir/units/freezer-oracle.service" <<'EOF'
[Unit]
Description=Freezer oracle service

[Service]
Type=simple
ExecStart=/bin/sleep 60
EOF

dbus-daemon --session --fork --address="unix:path=$runtime_dir/bus" --print-pid=1 \
    >"$runtime_dir/dbus-pid"
dbus_pid=$(sed -n '1p' "$runtime_dir/dbus-pid")
export XDG_RUNTIME_DIR="$runtime_dir"
export DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime_dir/bus"
export SYSTEMD_UNIT_PATH="$runtime_dir/units:/usr/lib/systemd/user"
export RUSTD_CGROUP_ROOT="$runtime_dir/cgroup"

uid=$(id -u)
cg="$runtime_dir/cgroup/user.slice/user-$uid.slice/user@$uid.service/app.slice/freezer-oracle.service"
parent="$runtime_dir/cgroup/user.slice/user-$uid.slice/user@$uid.service/app.slice"
mkdir -p "$cg"
printf '0\n' >"$cg/cgroup.procs"
printf '0\n' >"$cg/cgroup.freeze"
write_events() {
    directory=$1
    frozen=$2
    temporary="$directory/.cgroup.events.$$"
    printf 'populated 1\nfrozen %s\n' "$frozen" >"$temporary"
    mv -f "$temporary" "$directory/cgroup.events"
}
write_events "$cg" 0
write_events "$parent" 0

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

xml=$(busctl --user --no-pager --xml-interface introspect \
    org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager)
for name in FreezeUnit ThawUnit; do
    method=$(printf '%s\n' "$xml" | sed -n "/<method name=\"$name\"/,/<\/method>/p")
    case "$method" in
        *'<arg type="s" name="name" direction="in"/>'*) ;;
        *) echo "missing v261 $name signature" >&2; exit 1 ;;
    esac
    count=$(printf '%s\n' "$method" | grep -c '<arg ' || :)
    [ "$count" -eq 1 ] || { echo "$name has unexpected arguments" >&2; exit 1; }
done

manager_call() {
    busctl --user --no-pager call org.freedesktop.systemd1 /org/freedesktop/systemd1 \
        org.freedesktop.systemd1.Manager "$@"
}
manager_call StartUnit ss freezer-oracle.service replace >/dev/null
unit_path=/org/freedesktop/systemd1/unit/freezer_2doracle_2eservice
active=0
attempt=0
while [ "$attempt" -lt 100 ]; do
    state=$(busctl --user --no-pager get-property org.freedesktop.systemd1 "$unit_path" \
        org.freedesktop.systemd1.Unit ActiveState 2>/dev/null || :)
    case "$state" in *'"active"'*) active=1; break ;; esac
    attempt=$((attempt + 1))
    sleep 0.05
done
[ "$active" -eq 1 ] || { echo 'freezer oracle service did not become active' >&2; exit 1; }
[ -d "$cg" ] || { echo 'candidate did not retain freezer oracle cgroup' >&2; exit 1; }

(
    last=
    while kill -0 "$manager_pid" 2>/dev/null; do
        value=$(cat "$cg/cgroup.freeze" 2>/dev/null || :)
        if [ "$value" != "$last" ]; then
            case "$value" in
                1) write_events "$cg" 1 ;;
                0) write_events "$cg" 0 ;;
            esac
            last=$value
        fi
        sleep 0.01
    done
) &
emulator_pid=$!

manager_call FreezeUnit s freezer-oracle.service >/dev/null
[ "$(cat "$cg/cgroup.freeze")" = 1 ] || {
    echo 'FreezeUnit did not request cgroup.freeze=1' >&2
    exit 1
}

write_events "$parent" 1
if blocked=$(manager_call ThawUnit s freezer-oracle.service 2>&1); then
    echo 'ThawUnit unexpectedly succeeded while parent slice was frozen' >&2
    exit 1
fi
case "$blocked" in
    *'org.freedesktop.systemd1.FrozenByParent'*|*'FrozenByParent'*|*'frozen by a parent slice'*) ;;
    *) echo "unexpected parent-freeze error: $blocked" >&2; exit 1 ;;
esac
[ "$(cat "$cg/cgroup.freeze")" = 1 ] || {
    echo 'blocked thaw changed cgroup.freeze' >&2
    exit 1
}

write_events "$parent" 0
manager_call ThawUnit s freezer-oracle.service >/dev/null
[ "$(cat "$cg/cgroup.freeze")" = 0 ] || {
    echo 'ThawUnit did not request cgroup.freeze=0' >&2
    exit 1
}

manager_call StopUnit ss freezer-oracle.service replace >/dev/null
inactive=0
attempt=0
while [ "$attempt" -lt 100 ]; do
    state=$(busctl --user --no-pager get-property org.freedesktop.systemd1 "$unit_path" \
        org.freedesktop.systemd1.Unit ActiveState 2>/dev/null || :)
    case "$state" in *'"inactive"'*|*'"failed"'*) inactive=1; break ;; esac
    attempt=$((attempt + 1))
    sleep 0.05
done
[ "$inactive" -eq 1 ] || { echo 'freezer oracle service did not stop' >&2; exit 1; }

if inactive_error=$(manager_call FreezeUnit s freezer-oracle.service 2>&1); then
    echo 'FreezeUnit unexpectedly accepted inactive unit' >&2
    exit 1
fi
case "$inactive_error" in
    *'org.freedesktop.systemd1.UnitInactive'*|*'UnitInactive'*|*'not active'*) ;;
    *) echo "unexpected inactive freeze error: $inactive_error" >&2; exit 1 ;;
esac

printf '%s\n' 'manager freezer oracle: PASS'
