#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Boot RustD as PID 1 into rescue.target or emergency.target under QEMU.

set -Eeuo pipefail

MODE=${1:?usage: ci-pid1-special-target.sh rescue|emergency}
case "$MODE" in
    rescue|emergency) ;;
    *) echo "unsupported PID1 target mode: $MODE" >&2; exit 2 ;;
esac
TARGET="${MODE}.target"
ROOT="${RUSTD_PID1_ROOT:-$(mktemp -d)}"
KEEP_ROOT="${RUSTD_PID1_KEEP_ROOT:-0}"
RELEASE_DIR="${RUSTD_RELEASE_DIR:-target/release}"
SERIAL_LOG="${RUSTD_PID1_SERIAL_LOG:-pid1-${MODE}-serial.log}"
KERNEL="${RUSTD_PID1_KERNEL:-}"
QEMU_TIMEOUT="${RUSTD_PID1_QEMU_TIMEOUT:-90s}"
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
    KERNEL="$(find /boot -maxdepth 1 -type f -name 'vmlinuz-*' -print | sort -V | tail -1)"
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
    "$INITROOT/run/rustd" \
    "$INITROOT/sys/fs/cgroup" \
    "$INITROOT/tmp" \
    "$INITROOT/usr/bin" \
    "$INITROOT/usr/lib/rustd" \
    "$INITROOT/var"
ln -s ../run "$INITROOT/var/run"

cp "$(command -v busybox)" "$INITROOT/bin/busybox"
for applet in cat mkdir mount poweroff sh sleep; do
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

cat >"$INITROOT/etc/passwd" <<'PASSWD'
root:x:0:0:root:/root:/bin/sh
nobody:x:65534:65534:nobody:/:/bin/false
PASSWD
cat >"$INITROOT/etc/group" <<'GROUP'
root:x:0:
nobody:x:65534:
GROUP
printf 'rustd-ci-%s\n' "$MODE" >"$INITROOT/etc/hostname"
printf 'fedcba9876543210fedcba9876543210\n' >"$INITROOT/etc/machine-id"

cat >"$INITROOT/etc/rustd/system/$TARGET" <<EOF_TARGET
[Unit]
Description=RustD PID1 Certification ${MODE^} Target
DefaultDependencies=no
Requires=rustd-ci-special-cert.service
EOF_TARGET

cat >"$INITROOT/usr/lib/rustd/ci-special-cert.sh" <<EOF_CERT
#!/bin/sh
set -eu
attempt=0
while [ "\$attempt" -lt 30 ]; do
    if /usr/bin/rustctl --quiet is-active "$TARGET" >/dev/null 2>&1; then
        echo 'RUSTD_PID1_${MODE^^}_CERT_PASS' >/dev/ttyS0
        sleep 1
        /bin/poweroff -f
        exit 0
    fi
    attempt=\$((attempt + 1))
    /bin/sleep 1
done
echo 'RUSTD_PID1_${MODE^^}_CERT_FAIL' >/dev/ttyS0
/usr/bin/rustctl --no-pager --plain list-units >/dev/ttyS0 2>&1 || true
/bin/poweroff -f
exit 1
EOF_CERT
chmod 0755 "$INITROOT/usr/lib/rustd/ci-special-cert.sh"

cat >"$INITROOT/etc/rustd/system/rustd-ci-special-cert.service" <<'EOF_SERVICE'
[Unit]
Description=RustD PID1 Special Target Certification Probe
DefaultDependencies=no

[Service]
Type=exec
StandardOutput=console
StandardError=console
ExecStart=/bin/sh /usr/lib/rustd/ci-special-cert.sh
Restart=no
EOF_SERVICE

cat >"$INITROOT/init" <<'EOF_INIT'
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
echo 'RUSTD_PID1_SPECIAL_BOOT_BEGIN' >/dev/ttyS0
exec >/dev/ttyS0 2>&1
exec /usr/lib/rustd/rustd
EOF_INIT
chmod 0755 "$INITROOT/init"

INITRAMFS="$ROOT/rustd-pid1-${MODE}.cpio.gz"
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
    -append "console=ttyS0 panic=-1 random.trust_cpu=on rustd.unit=$TARGET rustd.log_target=console" \
    -display none \
    -serial stdio \
    -monitor none \
    -object rng-random,filename=/dev/urandom,id=rng0 \
    -device virtio-rng-pci,rng=rng0 \
    -no-reboot \
    >"$SERIAL_LOG" 2>&1
qemu_status=$?
set -e

marker="RUSTD_PID1_${MODE^^}_CERT_PASS"
if grep -Fq "$marker" "$SERIAL_LOG"; then
    echo "RustD PID1 $MODE target certification passed"
    exit 0
fi

cat "$SERIAL_LOG" >&2
if [[ "$qemu_status" -eq 124 || "$qemu_status" -eq 137 ]]; then
    echo "RustD PID1 $MODE target certification timed out" >&2
else
    echo "RustD PID1 $MODE target certification failed (qemu exit $qemu_status)" >&2
fi
exit 1
