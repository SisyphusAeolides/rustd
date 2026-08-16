#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu

candidate=${1:-target/release/systemd}
oracle_timeout=${RUSTD_ORACLE_TIMEOUT:-45s}
case "$candidate" in
    /*) ;;
    *) candidate="$(pwd)/$candidate" ;;
esac

[ -x "$candidate" ] || {
    echo "candidate manager is not executable: $candidate" >&2
    exit 2
}

work=$(mktemp -d)
cleanup() {
    rm -rf "$work"
}
trap cleanup EXIT HUP INT TERM

cat >"$work/busctl" <<'EOF'
#!/bin/sh
set -eu
xml=false
introspect=false
for argument in "$@"; do
    [ "$argument" = --xml-interface ] && xml=true
    [ "$argument" = introspect ] && introspect=true
done
if [ "$xml" = true ] && [ "$introspect" = true ]; then
    /usr/bin/busctl "$@" | python3 -c '
import re
import sys
for line in sys.stdin:
    line = re.sub(
        r"<arg name=\"([^\"]*)\" type=\"([^\"]*)\" direction=\"([^\"]*)\"/>",
        "<arg type=\"\\2\" name=\"\\1\" direction=\"\\3\"/>",
        line,
    )
    sys.stdout.write(line)
'
else
    exec /usr/bin/busctl "$@"
fi
EOF
chmod 0755 "$work/busctl"
PATH="$work:$PATH"
export PATH

count=0
for source in \
    tests/manager-add-dependency-unit-files-oracle.sh \
    tests/manager-preset-unit-files-oracle.sh \
    tests/manager-caller-unit-lookup-oracle.sh \
    tests/manager-environment-oracle.sh \
    tests/manager-exit-code-oracle.sh \
    tests/manager-freezer-oracle.sh \
    tests/manager-job-oracle.sh \
    tests/manager-reload-count-oracle.sh \
    tests/manager-reexecute-oracle.sh \
    tests/manager-start-unit-with-flags-oracle.sh \
    tests/manager-show-status-oracle.sh \
    tests/manager-kill-subgroup-oracle.sh \
    tests/manager-log-properties-oracle.sh \
    tests/manager-shutdown-actions-oracle.sh \
    tests/manager-startup-finished-oracle.sh \
    tests/manager-set-default-target-oracle.sh \
    tests/manager-mask-unit-files-oracle.sh \
    tests/manager-enable-disable-unit-files-oracle.sh \
    tests/manager-revert-unit-files-oracle.sh \
    tests/manager-output-argument-names-oracle.sh \
    tests/manager-unit-reference-oracle.sh \
    tests/manager-set-unit-properties-oracle.sh \
    tests/manager-userspace-timestamp-oracle.sh \
    tests/manager-finish-timestamp-oracle.sh \
    tests/manager-units-load-timestamp-oracle.sh \
    tests/manager-units-load-timestamp-reload-oracle.sh \
    tests/manager-shutdown-start-timestamp-oracle.sh \
    tests/manager-cgroup-delegation-oracle.sh \
    tests/manager-unit-defaults-oracle.sh
do
    [ -f "$source" ] || {
        echo "missing manager oracle: $source" >&2
        exit 1
    }
    test_script="$work/$(basename "$source")"
    sed "s|/usr/lib/systemd/systemd|$candidate|g" "$source" >"$test_script"
    chmod 0755 "$test_script"
    RUSTD_CANDIDATE_ORACLE=1 timeout --kill-after=5s "$oracle_timeout" \
        "$test_script"
    count=$((count + 1))
done

[ "$count" -eq 29 ]
echo "candidate manager v261 oracles: $count passed"
