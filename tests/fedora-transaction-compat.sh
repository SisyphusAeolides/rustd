#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
mkdir -p "$WORK/bin" "$WORK/system" "$WORK/user" "$WORK/preset" "$WORK/user-preset" \
    "$WORK/native-system" "$WORK/native-user" "$WORK/global-user" "$WORK/markers" "$WORK/manager/system"
LOG=$WORK/rustctl.log

cat > "$WORK/bin/rustctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >> "$RUSTCTL_TEST_LOG"
printf '\n' >> "$RUSTCTL_TEST_LOG"
case " $* " in
  *" --no-legend list-units "*) printf '%s\n' 'user@1000.service loaded active running Test user manager' ;;
  *" --quiet is-active "*) exit 0 ;;
esac
EOF
chmod +x "$WORK/bin/rustctl"

for name in systemctl systemd-update-helper systemd-tmpfiles systemd-sysusers systemd-sysctl systemd-binfmt udevadm; do
    cp "$ROOT/dist/fedora/compat/$name" "$WORK/bin/$name"
    chmod +x "$WORK/bin/$name"
done

cat > "$WORK/system/demo.service" <<'EOF'
[Unit]
Description=Fedora transaction demo
[Service]
ExecStart=/usr/bin/true
[Install]
WantedBy=multi-user.target
EOF
mkdir -p "$WORK/system/demo.service.d"
printf '%s\n' '[Service]' 'Environment=FEDORA_COMPAT=1' > "$WORK/system/demo.service.d/10-test.conf"
printf '%s\n' 'enable demo.service' > "$WORK/preset/50-demo.preset"

cat > "$WORK/user/demo-user.service" <<'EOF'
[Unit]
Description=Fedora user transaction demo
[Service]
ExecStart=/usr/bin/true
[Install]
WantedBy=default.target
EOF
printf '%s\n' 'enable demo-user.service' > "$WORK/user-preset/50-demo-user.preset"

export RUSTCTL="$WORK/bin/rustctl"
export RUSTCTL_TEST_LOG="$LOG"
export RUSTD_FEDORA_SYSTEMCTL="$WORK/bin/systemctl"
export RUSTD_FEDORA_SYSTEM_UNIT_DIRS="$WORK/system"
export RUSTD_FEDORA_USER_UNIT_DIRS="$WORK/user"
export RUSTD_FEDORA_SYSTEM_PRESET_DIRS="$WORK/preset"
export RUSTD_FEDORA_USER_PRESET_DIRS="$WORK/user-preset"
export RUSTD_FEDORA_SYSTEM_UNIT_DEST="$WORK/native-system"
export RUSTD_FEDORA_USER_UNIT_DEST="$WORK/native-user"
export RUSTD_FEDORA_GLOBAL_USER_DEST="$WORK/global-user"
export RUSTD_FEDORA_MARK_ROOT="$WORK/markers"
export RUSTD_FEDORA_MANAGER_RUNTIME="$WORK/manager"

# Match Fedora's macro-generated call shapes, including options after verbs.
"$WORK/bin/systemctl" --no-reload preset demo.service
[[ -L "$WORK/native-system/demo.service" ]]
[[ -L "$WORK/native-system/demo.service.d/10-test.conf" ]]
grep -Fq 'enable demo.service' "$LOG"

"$WORK/bin/systemctl" preset --global demo-user.service
[[ -L "$WORK/native-user/demo-user.service" ]]
[[ -L "$WORK/global-user/default.target.wants/demo-user.service" ]]

"$WORK/bin/systemctl" disable --now --no-warn demo.service
grep -Eq -- '--now .*disable demo\.service|--now disable demo\.service' "$LOG"

# Fedora update-helper install and restart transaction.
"$WORK/bin/systemd-update-helper" install-system-units demo.service
"$WORK/bin/systemd-update-helper" mark-restart-system-units demo.service
[[ -f "$WORK/markers/restart/demo.service" ]]
"$WORK/bin/systemd-update-helper" system-reload-restart
[[ ! -e "$WORK/markers/restart/demo.service" ]]
grep -Fq 'daemon-reload' "$LOG"
grep -Fq 'restart demo.service' "$LOG"

# Fedora package macros feed tmpfiles/sysusers rules on stdin before the final
# package-owned file exists. Verify both translators preserve that input.
cat > "$WORK/bin/rustd-tmpfiles" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" > "$TMPFILES_ARGS"
for arg in "$@"; do
  [[ -f $arg ]] && cat "$arg" > "$TMPFILES_INPUT"
done
EOF
chmod +x "$WORK/bin/rustd-tmpfiles"
export RUSTD_TMPFILES="$WORK/bin/rustd-tmpfiles" TMPFILES_ARGS="$WORK/tmp.args" TMPFILES_INPUT="$WORK/tmp.input"
printf '%s\n' 'd /run/demo 0755 root root -' |
    "$WORK/bin/systemd-tmpfiles" --replace=/usr/lib/tmpfiles.d/demo.conf --create -
grep -Fq -- '--create' "$WORK/tmp.args"
grep -Fq 'd /run/demo 0755 root root -' "$WORK/tmp.input"

cat > "$WORK/bin/rustd-sysusers" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" > "$SYSUSERS_ARGS"
cat > "$SYSUSERS_INPUT"
EOF
chmod +x "$WORK/bin/rustd-sysusers"
export RUSTD_SYSUSERS="$WORK/bin/rustd-sysusers" SYSUSERS_ARGS="$WORK/sysusers.args" SYSUSERS_INPUT="$WORK/sysusers.input"
printf '%s\n' 'u demo - "Demo" / -' |
    "$WORK/bin/systemd-sysusers" --replace=/usr/lib/sysusers.d/demo.conf -
grep -Fq -- '--inline' "$WORK/sysusers.args"
grep -Fq 'u demo - "Demo" / -' "$WORK/sysusers.input"

for pair in 'systemd-sysctl rustd-sysctl RUSTD_SYSCTL' 'systemd-binfmt rustd-binfmt RUSTD_BINFMT' 'udevadm rustudevadm RUSTD_UDEVADM'; do
    read -r wrapper native variable <<< "$pair"
    cat > "$WORK/bin/$native" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$WORK/delegate.log"
EOF
    chmod +x "$WORK/bin/$native"
    export "$variable=$WORK/bin/$native"
    "$WORK/bin/$wrapper" --test-argument
 done
[[ $(wc -l < "$WORK/delegate.log") -eq 3 ]]

echo 'Fedora RPM transaction compatibility: PASS'
