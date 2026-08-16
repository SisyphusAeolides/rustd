#!/usr/bin/env bash
set -euo pipefail

xml=$(busctl --system --no-pager --xml-interface introspect \
  org.freedesktop.systemd1 /org/freedesktop/systemd1)
method=$(awk '/<method name="StartUnitReplace">/{seen=1} seen{print} seen && /<\/method>/{exit}' <<<"$xml")
grep -q 'arg type="s" name="old_unit" direction="in"' <<<"$method"
grep -q 'arg type="s" name="new_unit" direction="in"' <<<"$method"
grep -q 'arg type="s" name="mode" direction="in"' <<<"$method"
grep -q 'arg type="o" name="job" direction="out"' <<<"$method"

set +e
output=$(busctl --system --no-pager call \
  org.freedesktop.systemd1 /org/freedesktop/systemd1 \
  org.freedesktop.systemd1.Manager StartUnitReplace sss bad replacement.service replace 2>&1)
status=$?
set -e
if [[ "$status" -eq 0 ]] || ! grep -q 'Unit bad not loaded' <<<"$output"; then
  echo "manager StartUnitReplace oracle: FAIL" >&2
  exit 1
fi
echo "manager StartUnitReplace oracle: PASS"
