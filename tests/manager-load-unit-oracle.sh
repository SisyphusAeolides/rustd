#!/usr/bin/env bash
set -euo pipefail

manager_xml=$(busctl --system --no-pager --xml-interface introspect \
  org.freedesktop.systemd1 /org/freedesktop/systemd1)
grep -q '<method name="LoadUnit">' <<<"$manager_xml"
grep -q 'arg type="s" name="name" direction="in"' <<<"$manager_xml"
grep -q 'arg type="o" name="unit" direction="out"' <<<"$manager_xml"

path=$(busctl --system --no-pager call \
  org.freedesktop.systemd1 /org/freedesktop/systemd1 \
  org.freedesktop.systemd1.Manager LoadUnit s no-such-rustd.service)
grep -q 'no_2dsuch_2dsystemd_2drs_2eservice' <<<"$path"

set +e
invalid_output=$(busctl --system --no-pager call \
  org.freedesktop.systemd1 /org/freedesktop/systemd1 \
  org.freedesktop.systemd1.Manager LoadUnit s bad 2>&1)
invalid_status=$?
set -e
if [[ "$invalid_status" -ne 0 ]] && grep -q 'Unit name bad is not valid' <<<"$invalid_output"; then
  echo "manager LoadUnit oracle: PASS"
else
  echo "manager LoadUnit oracle: FAIL" >&2
  exit 1
fi
