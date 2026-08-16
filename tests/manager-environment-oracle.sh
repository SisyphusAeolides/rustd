#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Host oracle for the v261 Manager environment lifecycle API. The private
# stock user manager avoids changing the host manager's client environment.

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
    if [ -n "$dbus_pid" ]; then
        kill "$dbus_pid" 2>/dev/null || :
    fi
    chmod u+rwx "$runtime_dir/systemd/inaccessible" 2>/dev/null || :
    rm -rf "$runtime_dir"
}
trap cleanup EXIT HUP INT TERM

dbus-daemon --session --fork --address="unix:path=$runtime_dir/bus" --print-pid=1 \
    >"$runtime_dir/dbus-pid"
dbus_pid=$(sed -n '1p' "$runtime_dir/dbus-pid")

export XDG_RUNTIME_DIR="$runtime_dir"
export DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime_dir/bus"
export SYSTEMD_UNIT_PATH=/usr/lib/systemd/user

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
[ "$ready" -eq 1 ] || {
    sed -n '1,120p' "$runtime_dir/systemd.err" >&2
    exit 1
}

xml=$(busctl --user --no-pager --xml-interface introspect \
    org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager)

assert_method() {
    name=$1
    contract=$2
    method=$(printf '%s\n' "$xml" | sed -n "/<method name=\"$name\"/,/<\/method>/p")
    case "$method" in
        *"$contract"*) ;;
        *)
            echo "missing v261 method contract for $name" >&2
            exit 1
            ;;
    esac
}

assert_method SetEnvironment '<arg type="as" name="assignments" direction="in"/>'
assert_method UnsetEnvironment '<arg type="as" name="names" direction="in"/>'
assert_method UnsetAndSetEnvironment '<arg type="as" name="names" direction="in"/>'
unset_and_set=$(printf '%s\n' "$xml" | sed -n '/<method name="UnsetAndSetEnvironment"/,/<\/method>/p')
case "$unset_and_set" in
    *'<arg type="as" name="assignments" direction="in"/>'*) ;;
    *)
        echo 'missing v261 UnsetAndSetEnvironment assignments argument' >&2
        exit 1
        ;;
esac
property=$(printf '%s\n' "$xml" | sed -n '/<property name="Environment"/,/<\/property>/p')
case "$property" in
    *'<property name="Environment" type="as" access="read">'*'EmitsChangedSignal" value="false"'*) ;;
    *)
        echo 'missing v261 Environment property contract' >&2
        exit 1
        ;;
esac

manager_call() {
    busctl --user --no-pager call org.freedesktop.systemd1 /org/freedesktop/systemd1 \
        org.freedesktop.systemd1.Manager "$@"
}

manager_call SetEnvironment as 2 \
    RUSTD_ENVIRONMENT_ORACLE_ALPHA=one \
    RUSTD_ENVIRONMENT_ORACLE_BETA=two >/dev/null
environment=$(busctl --user --no-pager get-property org.freedesktop.systemd1 \
    /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager Environment)
case "$environment" in
    *'"RUSTD_ENVIRONMENT_ORACLE_ALPHA=one"'*'"RUSTD_ENVIRONMENT_ORACLE_BETA=two"'*) ;;
    *)
        echo 'v261 SetEnvironment did not update Environment' >&2
        exit 1
        ;;
esac

manager_call UnsetAndSetEnvironment asas 1 RUSTD_ENVIRONMENT_ORACLE_ALPHA 1 \
    RUSTD_ENVIRONMENT_ORACLE_BETA=updated >/dev/null
environment=$(busctl --user --no-pager get-property org.freedesktop.systemd1 \
    /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager Environment)
case "$environment" in
    *'"RUSTD_ENVIRONMENT_ORACLE_ALPHA='*)
        echo 'v261 UnsetAndSetEnvironment retained deleted assignment' >&2
        exit 1
        ;;
    *'"RUSTD_ENVIRONMENT_ORACLE_BETA=updated"'*) ;;
    *)
        echo 'v261 UnsetAndSetEnvironment did not merge replacement' >&2
        exit 1
        ;;
esac

manager_call UnsetEnvironment as 1 RUSTD_ENVIRONMENT_ORACLE_BETA >/dev/null
environment=$(busctl --user --no-pager get-property org.freedesktop.systemd1 \
    /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager Environment)
case "$environment" in
    *'"RUSTD_ENVIRONMENT_ORACLE_BETA='*)
        echo 'v261 UnsetEnvironment retained deleted assignment' >&2
        exit 1
        ;;
    *) ;;
esac

if invalid_assignment=$(manager_call SetEnvironment as 1 bad-name=value 2>&1); then
    echo 'v261 accepted invalid environment assignment' >&2
    exit 1
fi
case "$invalid_assignment" in
    *'Invalid environment assignments'*) ;;
    *)
        echo "unexpected v261 invalid-assignment error: $invalid_assignment" >&2
        exit 1
        ;;
esac

if invalid_name=$(manager_call UnsetEnvironment as 1 bad-name 2>&1); then
    echo 'v261 accepted invalid environment name' >&2
    exit 1
fi
case "$invalid_name" in
    *'Invalid environment variable names or assignments'*) ;;
    *)
        echo "unexpected v261 invalid-name error: $invalid_name" >&2
        exit 1
        ;;
esac

printf '%s\n' 'manager environment oracle: PASS'
