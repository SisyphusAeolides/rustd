#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Certify RustD PID 1 behavior under a real cgroup-v2 OOM kill in QEMU.

set -Eeuo pipefail

ROOT="${RUSTD_PID1_OOM_ROOT:-$(mktemp -d)}"
KEEP_ROOT="${RUSTD_PID1_OOM_KEEP_ROOT:-0}"
RELEASE_DIR="${RUSTD_RELEASE_DIR:-target/release}"
SERIAL_LOG="${RUSTD_PID1_OOM_SERIAL_LOG:-pid1-oom-serial.log}"
KERNEL="${RUSTD_PID1_KERNEL:-}"
QEMU_TIMEOUT="${RUSTD_PID1_OOM_QEMU_TIMEOUT:-120s}"
QEMU="${RUSTD_QEMU_BINARY:-}"

cleanup() {
    status=$?
    if [[ "$KEEP_ROOT" != 1 ]]; then
        rm -rf "$ROOT"
    fi
    exit "$status"
}
trap cleanup EXIT

for binary in rustd rustctl; do
    [[ -x "$RELEASE_DIR/$binary" ]] || {
        echo "missing release binary: $RELEASE_DIR/$binary" >&2
        exit 1
    }
done
for command in busybox cc cpio gzip ldd timeout; do
    command -v "$command" >/dev/null || {
        echo "required command not found: $command" >&2
        exit 1
    }
done
if [[ -z "$QEMU" ]]; then
    QEMU="$(command -v qemu-system-x86_64 || true)"
    [[ -n "$QEMU" ]] || QEMU=/usr/libexec/qemu-kvm
fi
[[ -x "$QEMU" ]] || {
    echo "required QEMU x86_64 binary not found" >&2
    exit 1
}

if [[ -z "$KERNEL" ]]; then
    KERNEL="$(find /boot -maxdepth 1 -type f -name 'vmlinuz-*' ! -name '*+debug*' -print | sort -V | tail -1)"
fi
[[ -n "$KERNEL" && -r "$KERNEL" ]] || {
    echo "bootable kernel not found" >&2
    exit 1
}

INITROOT="$ROOT/initramfs"
mkdir -p \
    "$INITROOT/bin" \
    "$INITROOT/dev/pts" \
    "$INITROOT/dev/shm" \
    "$INITROOT/etc/rustd/system" \
    "$INITROOT/proc" \
    "$INITROOT/run" \
    "$INITROOT/sys/fs/cgroup" \
    "$INITROOT/tmp" \
    "$INITROOT/usr/bin" \
    "$INITROOT/usr/lib/rustd" \
    "$INITROOT/var"
ln -s ../run "$INITROOT/var/run"

cp "$(command -v busybox)" "$INITROOT/bin/busybox"
for applet in awk basename cat grep kill mkdir mount poweroff readlink sed sh sleep; do
    ln -s busybox "$INITROOT/bin/$applet"
done

install -m0755 "$RELEASE_DIR/rustd" "$INITROOT/usr/lib/rustd/rustd"
install -m0755 "$RELEASE_DIR/rustctl" "$INITROOT/usr/bin/rustctl"

cat >"$ROOT/oom-hog.c" <<'EOF'
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    const size_t chunk = 4u * 1024u * 1024u;
    for (;;) {
        unsigned char *p = malloc(chunk);
        if (!p)
            return errno ? errno : 1;
        memset(p, 0xa5, chunk);
        for (size_t i = 0; i < chunk; i += 4096)
            p[i] ^= (unsigned char)i;
        usleep(1000);
    }
}
EOF
cc -O2 -Wall -Wextra -Werror "$ROOT/oom-hog.c" -o "$ROOT/oom-hog"
install -m0755 "$ROOT/oom-hog" "$INITROOT/usr/lib/rustd/oom-hog"

copy_shared_libraries() {
    local executable="$1"
    local library
    while IFS= read -r library; do
        [[ -n "$library" && -r "$library" ]] || continue
        mkdir -p "$INITROOT$(dirname "$library")"
        cp -L "$library" "$INITROOT$library"
    done < <(
        ldd "$executable" \
            | awk '/=> \/[^ ]+/ {print $3} /^[[:space:]]*\/[^ ]+/ {print $1}' \
            | sort -u
    )
}
copy_shared_libraries "$RELEASE_DIR/rustd"
copy_shared_libraries "$RELEASE_DIR/rustctl"
copy_shared_libraries "$ROOT/oom-hog"
if [[ -x /usr/bin/dbus-daemon ]]; then
    install -m0755 /usr/bin/dbus-daemon "$INITROOT/usr/bin/dbus-daemon"
    copy_shared_libraries /usr/bin/dbus-daemon
else
    echo "required command not found: dbus-daemon" >&2
    exit 1
fi

mkdir -p "$INITROOT/etc/dbus-1" "$INITROOT/usr/share/dbus-1"
cat >"$INITROOT/usr/share/dbus-1/system.conf" <<'EOF'
<busconfig>
  <type>system</type>
  <user>root</user>
  <listen>unix:path=/run/dbus/system_bus_socket</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
EOF
cp "$INITROOT/usr/share/dbus-1/system.conf" "$INITROOT/etc/dbus-1/system.conf"

cat >"$INITROOT/etc/passwd" <<'EOF'
root:x:0:0:root:/root:/bin/sh
nobody:x:65534:65534:nobody:/:/bin/false
EOF
cat >"$INITROOT/etc/group" <<'EOF'
root:x:0:
nobody:x:65534:
EOF
printf 'rustd-oom-ci\n' >"$INITROOT/etc/hostname"
printf '0123456789abcdef0123456789abcdef\n' >"$INITROOT/etc/machine-id"

cat >"$INITROOT/etc/rustd/system/default.target" <<'EOF'
[Unit]
Description=RustD OOM Certification Target
DefaultDependencies=no
Wants=rustd-ci-keeper.service
EOF

cat >"$INITROOT/etc/rustd/system/rustd-ci-keeper.service" <<'EOF'
[Unit]
Description=RustD OOM Isolation Keeper
DefaultDependencies=no

[Service]
Type=simple
StandardOutput=console
StandardError=console
ExecStart=/bin/sh -c 'while :; do /bin/sleep 3600; done'
Restart=no
EOF

cat >"$INITROOT/etc/rustd/system/rustd-ci-oom.service" <<'EOF'
[Unit]
Description=RustD Kernel OOM Victim
DefaultDependencies=no

[Service]
Type=simple
StandardOutput=console
StandardError=console
ExecStart=/usr/lib/rustd/oom-hog
MemoryAccounting=yes
MemoryMax=24M
MemorySwapMax=0
OOMPolicy=stop
Restart=no
EOF

cat >"$INITROOT/usr/lib/rustd/oom-cert.sh" <<'EOF'
#!/bin/sh
set -eu

fail() {
    echo "RUSTD_PID1_OOM_CERT_FAIL: $*" >/dev/ttyS0
    /usr/bin/rustctl --no-pager --plain list-units >/dev/ttyS0 2>&1 || true
    /usr/bin/rustctl --no-pager --plain status rustd-ci-oom.service >/dev/ttyS0 2>&1 || true
    /usr/bin/rustctl --no-pager --plain status rustd-ci-keeper.service >/dev/ttyS0 2>&1 || true
    [ -r /sys/fs/cgroup/system.slice/rustd-ci-oom.service/memory.events ] \
        && cat /sys/fs/cgroup/system.slice/rustd-ci-oom.service/memory.events >/dev/ttyS0 2>&1 || true
    /bin/poweroff -f
    exit 1
}

main_pid() {
    /usr/bin/rustctl show rustd-ci-keeper.service 2>/dev/null \
        | /bin/awk -F= '$1 == "MainPID" { print $2; exit }'
}

attempt=0
while [ "$attempt" -lt 60 ]; do
    if /usr/bin/rustctl --quiet is-active rustd-ci-keeper.service >/dev/null 2>&1; then
        break
    fi
    attempt=$((attempt + 1))
    /bin/sleep 1
done
[ "$attempt" -lt 60 ] || fail 'keeper did not become active'

keeper_pid="$(main_pid)"
case "$keeper_pid" in
    ''|*[!0-9]*) fail "invalid keeper MainPID '$keeper_pid'" ;;
esac
[ "$keeper_pid" -gt 1 ] || fail "keeper MainPID is not a service process: $keeper_pid"
/bin/kill -0 "$keeper_pid" 2>/dev/null || fail 'keeper process is not alive before OOM'

# Start asynchronously so this probe can observe the kernel counter before an
# empty failed cgroup is eligible for manager cleanup.
/usr/bin/rustctl start rustd-ci-oom.service >/tmp/rustctl-oom-start.log 2>&1 &
start_ctl_pid=$!

events=/sys/fs/cgroup/system.slice/rustd-ci-oom.service/memory.events
oom_kill_seen=0
attempt=0
while [ "$attempt" -lt 600 ]; do
    if [ -r "$events" ]; then
        value="$(/bin/awk '$1 == "oom_kill" { print $2; exit }' "$events")"
        case "$value" in
            ''|*[!0-9]*) ;;
            *)
                if [ "$value" -gt 0 ]; then
                    oom_kill_seen="$value"
                    break
                fi
                ;;
        esac
    fi
    if ! /bin/kill -0 "$start_ctl_pid" 2>/dev/null && /usr/bin/rustctl --quiet is-failed rustd-ci-oom.service >/dev/null 2>&1; then
        # Give the cgroup event monitor one final chance before cleanup.
        if [ -r "$events" ]; then
            value="$(/bin/awk '$1 == "oom_kill" { print $2; exit }' "$events")"
            case "$value" in
                ''|*[!0-9]*) ;;
                *) [ "$value" -gt 0 ] && oom_kill_seen="$value" ;;
            esac
        fi
        break
    fi
    attempt=$((attempt + 1))
    /bin/sleep 0.05
done
wait "$start_ctl_pid" 2>/dev/null || true

[ "$oom_kill_seen" -gt 0 ] || fail 'kernel memory.events never reported oom_kill'
/usr/bin/rustctl --quiet is-failed rustd-ci-oom.service >/dev/null 2>&1 \
    || fail 'OOM victim did not settle in failed state'
[ "$(/bin/basename "$(/bin/readlink /proc/1/exe)")" = rustd ] \
    || fail 'PID 1 is no longer RustD after OOM'
/usr/bin/rustctl --quiet is-active rustd-ci-keeper.service >/dev/null 2>&1 \
    || fail 'unrelated keeper unit is no longer active after OOM'
current_pid="$(main_pid)"
[ "$current_pid" = "$keeper_pid" ] \
    || fail "keeper MainPID changed from $keeper_pid to $current_pid"
/bin/kill -0 "$keeper_pid" 2>/dev/null || fail 'keeper process died during OOM'
/usr/bin/rustctl --no-pager --plain list-units >/dev/null 2>&1 \
    || fail 'RustD control plane is unresponsive after OOM'

echo "RUSTD_PID1_OOM_CERT_PASS oom_kill=${oom_kill_seen} keeper_pid=${keeper_pid}" >/dev/ttyS0
/bin/sleep 1
/bin/poweroff -f
exit 0
EOF
chmod 0755 "$INITROOT/usr/lib/rustd/oom-cert.sh"

cat >"$INITROOT/init" <<'EOF'
#!/bin/sh
set -eu
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /dev/pts /dev/shm /run /run/dbus /tmp /sys/fs/cgroup
mount -t devpts devpts /dev/pts
mount -t tmpfs tmpfs /dev/shm
mount -t tmpfs tmpfs /run
mkdir -p /run/dbus
mount -t cgroup2 none /sys/fs/cgroup

/usr/bin/dbus-daemon --config-file=/usr/share/dbus-1/system.conf --fork --nopidfile

echo 'RUSTD_PID1_OOM_BOOT_BEGIN' >/dev/ttyS0
exec >/dev/ttyS0 2>&1
(
    attempt=0
    while [ "$attempt" -lt 60 ]; do
        [ -S /run/rustd/control ] && break
        attempt=$((attempt + 1))
        sleep 1
    done
    /bin/sh /usr/lib/rustd/oom-cert.sh
) &
exec /usr/lib/rustd/rustd
EOF
chmod 0755 "$INITROOT/init"

INITRAMFS="$ROOT/rustd-pid1-oom.cpio.gz"
(
    cd "$INITROOT"
    find . -print0 \
        | cpio --null --create --quiet --format=newc \
        | gzip -9 >"$INITRAMFS"
)

set +e
timeout --signal=TERM --kill-after=5s "$QEMU_TIMEOUT" \
    "$QEMU" \
        -machine accel=tcg \
        -cpu max \
        -m 256M \
        -smp 2 \
        -no-reboot \
        -kernel "$KERNEL" \
        -initrd "$INITRAMFS" \
        -append 'console=ttyS0 rdinit=/init panic=-1' \
        -serial "file:$SERIAL_LOG" \
        -monitor none \
        -display none
qemu_status=$?
set -e

cat "$SERIAL_LOG"
if ! grep -Fq 'RUSTD_PID1_OOM_CERT_PASS' "$SERIAL_LOG"; then
    echo "RustD PID1 OOM certification failed (qemu status $qemu_status)" >&2
    exit 1
fi
if grep -Fq 'RUSTD_PID1_OOM_CERT_FAIL:' "$SERIAL_LOG"; then
    echo "RustD PID1 OOM certification emitted a failure marker" >&2
    exit 1
fi

echo "RustD PID1 cgroup OOM certification passed"
