#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Certify RustD PID 1 survives a queued realtime-signal storm under QEMU.

set -Eeuo pipefail

ROOT="${RUSTD_PID1_ROOT:-$(mktemp -d)}"
KEEP_ROOT="${RUSTD_PID1_KEEP_ROOT:-0}"
RELEASE_DIR="${RUSTD_RELEASE_DIR:-target/release}"
SERIAL_LOG="${RUSTD_PID1_SERIAL_LOG:-pid1-signal-storm.log}"
KERNEL="${RUSTD_PID1_KERNEL:-}"
QEMU_TIMEOUT="${RUSTD_PID1_QEMU_TIMEOUT:-120s}"
SIGNAL_COUNT="${RUSTD_PID1_SIGNAL_COUNT:-1000}"
QEMU="${RUSTD_QEMU_BINARY:-}"

if [[ ! "$SIGNAL_COUNT" =~ ^[0-9]+$ ]] || (( SIGNAL_COUNT < 1000 )); then
    echo "RUSTD_PID1_SIGNAL_COUNT must be an integer >= 1000" >&2
    exit 64
fi

cleanup() {
    status=$?
    if [[ "$KEEP_ROOT" != 1 ]]; then
        rm -rf "$ROOT"
    fi
    exit "$status"
}
trap cleanup EXIT

for binary in rustd rustctl; do
    if [[ ! -x "$RELEASE_DIR/$binary" ]]; then
        echo "missing release binary: $RELEASE_DIR/$binary" >&2
        exit 1
    fi
done

for command in busybox cpio gzip ldd timeout; do
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
if [[ -z "$KERNEL" || ! -r "$KERNEL" ]]; then
    echo "bootable kernel not found" >&2
    exit 1
fi

INITROOT="$ROOT/initramfs"
mkdir -p \
    "$INITROOT/bin" \
    "$INITROOT/dev/pts" \
    "$INITROOT/dev/shm" \
    "$INITROOT/etc/dbus-1" \
    "$INITROOT/etc/rustd/system" \
    "$INITROOT/proc" \
    "$INITROOT/run" \
    "$INITROOT/sys/fs/cgroup" \
    "$INITROOT/tmp" \
    "$INITROOT/usr/bin" \
    "$INITROOT/usr/lib/rustd" \
    "$INITROOT/usr/share/dbus-1" \
    "$INITROOT/var"
ln -s ../run "$INITROOT/var/run"

cp "$(command -v busybox)" "$INITROOT/bin/busybox"
for applet in awk cat kill mkdir mount poweroff sh sleep; do
    ln -s busybox "$INITROOT/bin/$applet"
done

install -m0755 "$RELEASE_DIR/rustd" "$INITROOT/usr/lib/rustd/rustd"
install -m0755 "$RELEASE_DIR/rustctl" "$INITROOT/usr/bin/rustctl"

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
if [[ -x /usr/bin/dbus-daemon ]]; then
    install -m0755 /usr/bin/dbus-daemon "$INITROOT/usr/bin/dbus-daemon"
    copy_shared_libraries /usr/bin/dbus-daemon
else
    echo "required command not found: dbus-daemon" >&2
    exit 1
fi

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
printf 'rustd-signal-storm-ci\n' >"$INITROOT/etc/hostname"
printf '0123456789abcdef0123456789abcdef\n' >"$INITROOT/etc/machine-id"

cat >"$INITROOT/etc/rustd/system/basic.target" <<'EOF'
[Unit]
Description=RustD Signal Storm Basic Target
DefaultDependencies=no
EOF

cat >"$INITROOT/etc/rustd/system/default.target" <<'EOF'
[Unit]
Description=RustD Signal Storm Default Target
DefaultDependencies=no
Requires=basic.target
Wants=rustd-ci-signal-keeper.service rustd-ci-signal-trigger.service
After=basic.target
EOF

cat >"$INITROOT/etc/rustd/system/rustd-ci-signal-keeper.service" <<'EOF'
[Unit]
Description=RustD Signal Storm Keeper
DefaultDependencies=no
After=basic.target

[Service]
Type=exec
StandardOutput=console
StandardError=console
ExecStart=/bin/sh -c 'while :; do /bin/sleep 3600; done'
Restart=no
EOF

cat >"$INITROOT/etc/rustd/system/rustd-ci-signal-trigger.service" <<'EOF'
[Unit]
Description=RustD Signal Storm Trigger
DefaultDependencies=no
After=basic.target rustd-ci-signal-keeper.service
Requires=rustd-ci-signal-keeper.service

[Service]
Type=exec
StandardOutput=console
StandardError=console
ExecStart=/bin/sh /usr/lib/rustd/signal-storm-trigger.sh
Restart=no
EOF

cat >"$INITROOT/usr/lib/rustd/signal-storm-trigger.sh" <<EOF
#!/bin/sh
set -eu
count='$SIGNAL_COUNT'
main_pid() {
    /usr/bin/rustctl show rustd-ci-signal-keeper.service 2>/dev/null \
        | /bin/awk -F= '\$1 == "MainPID" { print \$2; exit }'
}
attempt=0
while [ "\$attempt" -lt 60 ]; do
    if /usr/bin/rustctl --quiet is-active default.target >/dev/null 2>&1 \
        && /usr/bin/rustctl --quiet is-active rustd-ci-signal-keeper.service >/dev/null 2>&1; then
        break
    fi
    attempt=\$((attempt + 1))
    /bin/sleep 1
done
if [ "\$attempt" -ge 60 ]; then
    echo 'RUSTD_PID1_SIGNAL_STORM_FAIL: unit graph did not become healthy' >/dev/ttyS0
    /bin/poweroff -f
    exit 1
fi

before="\$(main_pid)"
case "\$before" in
    ''|*[!0-9]*|0)
        echo "RUSTD_PID1_SIGNAL_STORM_FAIL: invalid keeper MainPID before storm: \$before" >/dev/ttyS0
        /bin/poweroff -f
        exit 1
        ;;
esac

# Linux x86_64 uses signal 34 as SIGRTMIN. RustD blocks SIGRTMIN+0 into
# signalfd and maps that offset to Ignore, so every realtime signal is queued
# and drained by the manager without triggering a lifecycle transition.
i=0
while [ "\$i" -lt "\$count" ]; do
    /bin/kill -34 1 || {
        echo "RUSTD_PID1_SIGNAL_STORM_FAIL: signal delivery failed at \$i" >/dev/ttyS0
        /bin/poweroff -f
        exit 1
    }
    i=\$((i + 1))
done

echo "RUSTD_PID1_SIGNAL_STORM_SENT \$count" >/dev/ttyS0

# A successful post-storm control-plane round trip means the event loop has
# returned from the signalfd drain path. Repeat the probe so one lucky poll
# cannot mask a wedged manager.
probe=0
while [ "\$probe" -lt 10 ]; do
    /usr/bin/rustctl --quiet is-active default.target >/dev/null 2>&1 || {
        echo "RUSTD_PID1_SIGNAL_STORM_FAIL: control plane unhealthy after storm at probe \$probe" >/dev/ttyS0
        /bin/poweroff -f
        exit 1
    }
    after="\$(main_pid)"
    if [ "\$after" != "\$before" ]; then
        echo "RUSTD_PID1_SIGNAL_STORM_FAIL: keeper MainPID changed from \$before to \$after" >/dev/ttyS0
        /bin/poweroff -f
        exit 1
    fi
    /bin/kill -0 "\$after" || {
        echo "RUSTD_PID1_SIGNAL_STORM_FAIL: keeper process \$after is not alive" >/dev/ttyS0
        /bin/poweroff -f
        exit 1
    }
    probe=\$((probe + 1))
    /bin/sleep 1
done

if [ ! -e /proc/1/exe ] || [ "\$(basename "\$(readlink /proc/1/exe)")" != rustd ]; then
    echo 'RUSTD_PID1_SIGNAL_STORM_FAIL: PID 1 is no longer rustd' >/dev/ttyS0
    /bin/poweroff -f
    exit 1
fi

echo "RUSTD_PID1_SIGNAL_STORM_OK \$count keeper=\$before" >/dev/ttyS0
/bin/poweroff -f
exit 0
EOF
chmod 0755 "$INITROOT/usr/lib/rustd/signal-storm-trigger.sh"

# readlink and basename are needed by the guest verification script.
ln -s busybox "$INITROOT/bin/readlink"
ln -s busybox "$INITROOT/bin/basename"

cat >"$INITROOT/init" <<'EOF'
#!/bin/sh
set -eu
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /dev/pts /dev/shm /run /run/rustd /tmp /sys/fs/cgroup
mount -t devpts devpts /dev/pts
mount -t tmpfs tmpfs /dev/shm
mount -t tmpfs tmpfs /run
mount -t cgroup2 none /sys/fs/cgroup
mkdir -p /run/dbus
/usr/bin/dbus-daemon --config-file=/usr/share/dbus-1/system.conf --fork --nopidfile
echo 'RUSTD_PID1_SIGNAL_STORM_BOOT_BEGIN' >/dev/ttyS0
exec >/dev/ttyS0 2>&1
exec /usr/lib/rustd/rustd
EOF
chmod 0755 "$INITROOT/init"

INITRAMFS="$ROOT/rustd-pid1-signal-storm.cpio.gz"
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
    -m 512M \
    -smp 2 \
    -kernel "$KERNEL" \
    -initrd "$INITRAMFS" \
    -append "console=ttyS0 panic=-1 random.trust_cpu=on rustd.unit=default.target rustd.log_target=console" \
    -display none \
    -serial stdio \
    -monitor none \
    -object rng-random,filename=/dev/urandom,id=rng0 \
    -device virtio-rng-pci,rng=rng0 \
    -no-reboot \
    >"$SERIAL_LOG" 2>&1
qemu_status=$?
set -e

if grep -Fq 'RUSTD_PID1_SIGNAL_STORM_FAIL:' "$SERIAL_LOG"; then
    cat "$SERIAL_LOG" >&2
    echo "RustD PID1 signal-storm certification reported a guest failure" >&2
    exit 1
fi
if ! grep -Fq "RUSTD_PID1_SIGNAL_STORM_SENT $SIGNAL_COUNT" "$SERIAL_LOG"; then
    cat "$SERIAL_LOG" >&2
    echo "RustD PID1 signal-storm certification did not deliver the requested signals" >&2
    exit 1
fi
if ! grep -Fq "RUSTD_PID1_SIGNAL_STORM_OK $SIGNAL_COUNT" "$SERIAL_LOG"; then
    cat "$SERIAL_LOG" >&2
    echo "RustD PID1 signal-storm certification did not reach the healthy post-storm state" >&2
    exit 1
fi
if [[ "$qemu_status" -ne 0 ]]; then
    cat "$SERIAL_LOG" >&2
    if [[ "$qemu_status" -eq 124 || "$qemu_status" -eq 137 ]]; then
        echo "RustD PID1 signal-storm certification timed out" >&2
    else
        echo "RustD PID1 signal-storm certification failed (qemu exit $qemu_status)" >&2
    fi
    exit 1
fi

echo "RustD PID1 signal-storm certification passed: $SIGNAL_COUNT queued realtime signals"
