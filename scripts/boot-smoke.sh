#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Live RustD boot certificate.
#
# Run after installing RustD and booting the target machine or an isolated VM.
# The test verifies the native PID 1 identity, manager control plane, essential
# boot targets, journal service, and RustD-owned runtime sockets.

set -eu

RUSTCTL="${RUSTCTL:-/usr/bin/rustctl}"
PID1_EXE="${PID1_EXE:-/proc/1/exe}"
PASS=0
FAIL=0

pass() {
    echo "PASS: $*"
    PASS=$((PASS + 1))
}

fail() {
    echo "FAIL: $*"
    FAIL=$((FAIL + 1))
}

check_active() {
    unit="$1"
    if "${RUSTCTL}" --quiet is-active "${unit}" 2>/dev/null; then
        pass "${unit} is active"
    else
        fail "${unit} is not active"
    fi
}

check_inactive() {
    unit="$1"
    if "${RUSTCTL}" --quiet is-active "${unit}" >/dev/null 2>&1; then
        fail "${unit} is unexpectedly active"
        return
    fi
    state="$(${RUSTCTL} is-active "${unit}" 2>/dev/null || true)"
    pass "${unit} is not active (${state:-unknown})"
}

if [ ! -x "${RUSTCTL}" ]; then
    echo "FAIL: rustctl is not executable: ${RUSTCTL}"
    exit 1
fi

pid1_target="$(readlink "${PID1_EXE}" 2>/dev/null || true)"
pid1_name="$(basename "${pid1_target% (deleted)}")"
if [ "${pid1_name}" = "rustd" ]; then
    pass "PID 1 executable is rustd"
else
    fail "PID 1 executable is ${pid1_target:-unavailable}, expected rustd"
fi

if [ -S /run/rustd/ctl.sock ]; then
    pass "native manager control socket exists"
else
    fail "native manager control socket is missing"
fi

check_active basic.target
check_active default.target
check_active rustd-journald.service
check_inactive rescue.target
check_inactive emergency.target

if "${RUSTCTL}" --no-legend --no-pager --plain list-units 2>/dev/null | grep -q '[.]'; then
    pass "rustctl list-units returned unit data"
else
    fail "rustctl list-units returned no unit data"
fi

if ! "${RUSTCTL}" --quiet is-failed init.scope 2>/dev/null; then
    pass "init.scope is not failed"
else
    fail "init.scope is failed"
fi

for socket in /run/rustd/journal/socket /run/rustd/journal/dev-log /run/rustd/journal/stdout /dev/log; do
    if [ -S "${socket}" ]; then
        pass "${socket} exists"
    else
        fail "${socket} is missing"
    fi
done

printf '\nboot-smoke: %s passed, %s failed\n' "${PASS}" "${FAIL}"
[ "${FAIL}" -eq 0 ]
