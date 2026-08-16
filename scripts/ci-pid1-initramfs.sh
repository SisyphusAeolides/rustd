#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Build a minimal initramfs and cold-boot RustD as the real PID 1 under QEMU.

set -Eeuo pipefail

ROOT="${RUSTD_PID1_ROOT:-$(mktemp -d)}"
KEEP_ROOT="${RUSTD_PID1_KEEP_ROOT:-0}"
RELEASE_DIR="${RUSTD_RELEASE_DIR:-target/release}"
SERIAL_LOG="${RUSTD_PID1_SERIAL_LOG:-pid1-serial.log}"
KERNEL="${RUSTD_PID1_KERNEL:-}"

cleanup() {
    status=$?
    if [[ "$KEEP_ROOT" != 1 ]]; then
        rm -rf "$ROOT"
    fi
    exit "$status"
}
trap cleanup EXIT

for binary in rustd rustctl rustd-journald; do
    if [[ ! -x "$RELEASE_DIR/$binary" ]]; then
        echo "missing release binary: $RELEASE_DIR/$binary" >&2
        exit 1
    fi
done

for command in busybox cpio gzip ldd qemu-system-x86_64 timeout; do
    command -v "$command" >/dev/null || {
        echo "required command not found: $command" >&2
        exit 1
    }
done

if [[ -z "$KERNEL" ]]; then
    KERNEL="$(find /boot -maxdepth 1 -type f -name 'vmlinuz-*' -print | sort -V | tail -1)"
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
    "$INITROOT/etc/rustd/system" \
    "$INITROOT/proc" \
    "$INITROOT/run" \
    "$INITROOT/sys/fs/cgroup" \
    "$INITROOT/tmp" \
    "$INITROOT/usr/bin" \
    "$INITROOT/usr/lib/rustd"

cp "$(command -v busybox)" "$INITROOT/bin/busybox"
for applet in basename cat grep mkdir mount poweroff readlink sh sleep; do
    ln -s busybox "$INITROOT/bin/$applet"
done

install -m0755 "$RELEASE_DIR/rustd" "$INITROOT/usr/lib/rustd/rustd"
install -m0755 "$RELEASE_DIR/rustctl" "$INITROOT/usr/bin/rustctl"
install -m0755 "$RELEASE_DIR/rustd-journald" "$INITROOT/usr/lib/rustd/rustd-journald"
install -m0755 scripts/boot-smoke.sh "$INITROOT/usr/lib/rustd/boot-smoke.sh"

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
copy_shared_libraries "$RELEASE_DIR/rustd-journald"
if [[ -x /usr/bin/dbus-daemon ]]; then
    install -m0755 /usr/bin/dbus-daemon "$INITROOT/usr/bin/dbus-daemon"
    copy_shared_libraries /usr/bin/dbus-daemon
fi

cat >"$INITROOT/etc/passwd" <<'EOF'
root:x:0:0:root:/root:/bin/sh
dbus:x:81:81:System Message Bus:/:/usr/bin/nologin
nobody:x:65534:65534:nobody:/:/bin/false
EOF
cat >"$INITROOT/etc/group" <<'EOF'
root:x:0:
dbus:x:81:
nobody:x:65534:
EOF
printf 'rustd-ci\n' >"$INITROOT/etc/hostname"
printf '0123456789abcdef0123456789abcdef\n' >"$INITROOT/etc/machine-id"

# Minimal system bus config: run as root, no fork, no servicehelper (initramfs).
mkdir -p "$INITROOT/etc/dbus-1" "$INITROOT/usr/share/dbus-1" "$INITROOT/usr/lib/dbus-1"
cat >"$INITROOT/usr/share/dbus-1/system.conf" <<'EOF'
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>system</type>
  <user>root</user>
  <keep_umask/>
  <listen>unix:path=/run/dbus/system_bus_socket</listen>
  <auth>EXTERNAL</auth>
  <pidfile>/run/dbus/pid</pidfile>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
EOF
cp "$INITROOT/usr/share/dbus-1/system.conf" "$INITROOT/etc/dbus-1/system.conf"

cat >"$INITROOT/etc/rustd/system/basic.target" <<'EOF'
[Unit]
Description=RustD PID1 Certification Basic Target
DefaultDependencies=no
Wants=rustd-journald.service
After=rustd-journald.service
EOF

cat >"$INITROOT/etc/rustd/system/multi-user.target" <<'EOF'
[Unit]
Description=RustD PID1 Certification Multi-User Target
DefaultDependencies=no
Requires=basic.target
Wants=getty.target
After=basic.target
EOF

cat >"$INITROOT/etc/rustd/system/getty.target" <<'EOF'
[Unit]
Description=RustD PID1 Certification Login Prompts
DefaultDependencies=no
EOF

cat >"$INITROOT/etc/rustd/system/default.target" <<'EOF'
[Unit]
Description=RustD PID1 Certification Default Target
DefaultDependencies=no
Requires=basic.target
Wants=multi-user.target rustd-ci-cert.service
After=basic.target
EOF

cat >"$INITROOT/etc/rustd/system/dbus.service" <<'EOF'
[Unit]
Description=D-Bus System Message Bus
DefaultDependencies=no

[Service]
Type=simple
StandardOutput=null
StandardError=null
ExecStartPre=/bin/mkdir -p /run/dbus
ExecStart=/usr/bin/dbus-daemon --config-file=/usr/share/dbus-1/system.conf --nofork --nopidfile
Restart=no
EOF

cat >"$INITROOT/etc/rustd/system/rescue.target" <<'EOF'
[Unit]
Description=RustD PID1 Certification Rescue Target
DefaultDependencies=no
EOF

cat >"$INITROOT/etc/rustd/system/emergency.target" <<'EOF'
[Unit]
Description=RustD PID1 Certification Emergency Target
DefaultDependencies=no
EOF

cat >"$INITROOT/etc/rustd/system/rustd-journald.service" <<'EOF'
[Unit]
Description=RustD Journal Service
DefaultDependencies=no

[Service]
Type=simple
StandardOutput=null
StandardError=null
ExecStart=/usr/lib/rustd/rustd-journald --runtime-directory /run/rustd/journal
Restart=always
RestartSec=1
EOF

cat >"$INITROOT/usr/lib/rustd/ci-cert.sh" <<'EOF'
#!/bin/sh
set -eu

attempt=0
while [ "$attempt" -lt 30 ]; do
    if /usr/bin/rustctl --quiet is-active default.target >/dev/null 2>&1 \
        && /usr/bin/rustctl --quiet is-active basic.target >/dev/null 2>&1 \
        && /usr/bin/rustctl --quiet is-active multi-user.target >/dev/null 2>&1 \
        && /usr/bin/rustctl --quiet is-active getty.target >/dev/null 2>&1 \
        && /usr/bin/rustctl --quiet is-active rustd-journald.service >/dev/null 2>&1; then
        if RUSTCTL=/usr/bin/rustctl /usr/lib/rustd/boot-smoke.sh >/dev/ttyS0 2>&1; then
            echo 'RUSTD_PID1_CERT_PASS' >/dev/ttyS0
            sleep 1
            /bin/poweroff -f
            exit 0
        fi
    fi
    attempt=$((attempt + 1))
    sleep 1
done

echo 'RUSTD_PID1_CERT_FAIL: boot contract did not become healthy' >/dev/ttyS0
/usr/bin/rustctl --no-pager --plain list-units >/dev/ttyS0 2>&1 || true
/bin/poweroff -f
exit 1
EOF
chmod 0755 "$INITROOT/usr/lib/rustd/ci-cert.sh"

cat >"$INITROOT/etc/rustd/system/rustd-ci-cert.service" <<'EOF'
[Unit]
Description=RustD PID1 Certification Probe
DefaultDependencies=no
After=basic.target rustd-journald.service

[Service]
Type=simple
StandardOutput=null
StandardError=null
ExecStart=/usr/lib/rustd/ci-cert.sh
Restart=no
EOF

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
mkdir -p /run/rustd
mount -t cgroup2 none /sys/fs/cgroup

echo 'RUSTD_PID1_BOOT_BEGIN' >/dev/ttyS0
exec >/dev/ttyS0 2>&1
mkdir -p /run/dbus
if [ -x /usr/bin/dbus-daemon ]; then
    /usr/bin/dbus-daemon --config-file=/usr/share/dbus-1/system.conf --nofork --nopidfile &
fi
exec /usr/lib/rustd/rustd
EOF
chmod 0755 "$INITROOT/init"

INITRAMFS="$ROOT/rustd-pid1-initramfs.cpio.gz"
(
    cd "$INITROOT"
    find . -print0 \
        | cpio --null --create --quiet --format=newc \
        | gzip -9 >"$INITRAMFS"
)

set +e
timeout --signal=TERM --kill-after=5s 90s \
    qemu-system-x86_64 \
    -machine accel=tcg \
    -cpu max \
    -m 768M \
    -smp 2 \
    -kernel "$KERNEL" \
    -initrd "$INITRAMFS" \
    -append 'console=ttyS0 panic=-1 random.trust_cpu=on rustd.unit=default.target rustd.log_target=console' \
    -display none \
    -serial stdio \
    -monitor none \
    -object rng-random,filename=/dev/urandom,id=rng0 \
    -device virtio-rng-pci,rng=rng0 \
    -no-reboot \
    >"$SERIAL_LOG" 2>&1
qemu_status=$?
set -e

if grep -Fq 'RUSTD_PID1_CERT_PASS' "$SERIAL_LOG"; then
    echo "RustD PID1 certification passed"
    exit 0
fi

cat "$SERIAL_LOG" >&2
if [[ "$qemu_status" -eq 124 || "$qemu_status" -eq 137 ]]; then
    echo "RustD PID1 certification timed out" >&2
else
    echo "RustD PID1 certification failed (qemu exit $qemu_status)" >&2
fi
exit 1
