#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Read-only host oracle for the Manager job-control method signatures and the
# missing-job cancellation error. It never queues, cancels, or clears a live
# host job.

set -eu

xml=$(busctl --system --no-pager --xml-interface introspect \
    org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager)

case "$xml" in
    *"<method name=\"CancelJob\">"*"<arg type=\"u\" name=\"id\" direction=\"in\"/>"*)
        ;;
    *)
        echo 'missing v261 signature for CancelJob' >&2
        exit 1
        ;;
esac

clear_jobs=$(printf '%s\n' "$xml" | sed -n '/<method name="ClearJobs">/,/<\/method>/p')
case "$clear_jobs" in
    *"<method name=\"ClearJobs\">"*)
        ;;
    *)
        echo 'missing v261 signature for ClearJobs' >&2
        exit 1
        ;;
esac
case "$clear_jobs" in
    *'<arg '*)
        echo 'ClearJobs unexpectedly has arguments' >&2
        exit 1
        ;;
esac

if output=$(dbus-send --system --print-reply --dest=org.freedesktop.systemd1 \
    /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager.CancelJob \
    uint32:4294967295 2>&1); then
    echo 'CancelJob unexpectedly accepted a missing ID' >&2
    exit 1
fi

case "$output" in
    *'Error org.freedesktop.systemd1.NoSuchJob: Job 4294967295 does not exist.'*)
        ;;
    *)
        printf '%s\n' "$output" >&2
        exit 1
        ;;
esac

printf '%s\n' 'manager job-control oracle: PASS'
