#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Enumerate installed Fedora RPM dependencies that currently resolve through
# the systemd package family. This does not mutate the host.
set -Eeuo pipefail

OUT=${1:-}
[[ -z $OUT || $OUT == /* ]] || {
    echo 'output path must be absolute when supplied' >&2
    exit 64
}
command -v rpm >/dev/null 2>&1 || { echo 'rpm is required' >&2; exit 1; }

if ! rpm -q systemd >/dev/null 2>&1; then
    echo 'systemd RPM is not installed; dependency audit must run before removal' >&2
    exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
providers="$work/providers"
paths="$work/paths"
records="$work/records"
: >"$records"

rpm -q --provides systemd | sed '/^[[:space:]]*$/d' | sort -u >"$providers"
rpm -ql systemd | awk '$0 ~ /^\// {print}' | sort -u >"$paths"

record_consumers() {
    local kind=$1 value=$2 consumer name
    while IFS= read -r consumer; do
        [[ -n $consumer ]] || continue
        name=${consumer%%-[0-9]*}
        [[ $name == systemd || $name == systemd-* ]] && continue
        printf '%s\t%s\t%s\n' "$kind" "$value" "$consumer" >>"$records"
    done < <(rpm -q --whatrequires "$value" 2>/dev/null | sed '/^no package requires/d' | sort -u || true)
}

while IFS= read -r capability; do
    record_consumers capability "$capability"
done <"$providers"

# Direct path requirements are separate from virtual Provides. Scan every
# systemd-owned path so packages requiring a helper executable cannot disappear
# silently when the systemd RPM is erased.
while IFS= read -r path; do
    record_consumers path "$path"
done <"$paths"

sort -u "$records" -o "$records"

emit() {
    printf 'schema=rustd-fedora-systemd-dependency-audit-v1\n'
    printf 'systemd_evr=%s\n' "$(rpm -q --qf '%{EVR}' systemd)"
    printf 'systemd_libraries_evr=%s\n' "$(rpm -q --qf '%{EVR}' systemd-libs 2>/dev/null || echo absent)"
    printf 'consumer_count=%s\n' "$(wc -l <"$records" | tr -d ' ')"
    while IFS=$'\t' read -r kind value consumer; do
        [[ -n ${consumer:-} ]] || continue
        printf 'consumer.%s=%s :: %s\n' "$kind" "$consumer" "$value"
    done <"$records"
}

if [[ -n $OUT ]]; then
    mkdir -p "$(dirname "$OUT")"
    emit >"$OUT"
    chmod 0644 "$OUT"
else
    emit
fi

# A non-zero exit is intentional when blockers exist so this can be used as a
# release gate. The report is still written first for diagnosis.
[[ ! -s $records ]]
