#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Certify RustD's orderly reboot/poweroff path as real PID 1 under QEMU.

set -Eeuo pipefail

TRANSITION="${RUSTD_PID1_TRANSITION:-}"
ROOT="${RUSTD_PID1_ROOT:-$(mktemp -d)}"
KEEP_ROOT="${RUSTD_PID1_KEEP_ROOT:-0}"
RELEASE_DIR="${RUSTD_RELEASE_DIR:-target/release}"
SERIAL_LOG="${RUSTD_PID1_SERIAL_LOG:-pid1-machine-transition.log}"
KERNEL="${RUSTD_PID1_KERNEL:-}"
QEMU_TIMEOUT="${RUSTD_PID1_QEMU_TIMEOUT:-90s}"

case "$TRANSITION" in
    reboot|poweroff) ;;
    *)
        echo "RUSTD_PID1_TRANSITION must be reboot or poweroff" >&2
        exit 64
        ;;
esac

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
    "$INITROOT/usr/lib/rustd" \
    "$INITROOT/var"
ln -s ../run "$INITROOT/var/run"

cp "$(command -v busybox)" "$INITROOT/bin/busybox"
for applet in cat kill mkdir mount poweroff reboot sh sleep; do
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

cat >"$INITROOT/etc/passwd" <<'EOF'
root:x:0:0:root:/root:/bin/sh
nobody:x:65534:65534:nobody:/:/bin/false
EOF
cat >"$INITROOT/etc/group" <<'EOF'
root:x:0:
nobody:x:65534:
EOF
printf 'rustd-transition-ci\n' >"$INITROOT/etc/hostname"
printf 'fedcba9876543210fedcba9876543210\n' >"$INITROOT/etc/machine-id"

cat >"$INITROOT/etc/rustd/system/basic.target" <<'EOF'
[Unit]
Description=RustD Machine Transition Basic Target
DefaultDependencies=no
EOF

cat >"$INITROOT/etc/rustd/system/default.target" <<'EOF'
[Unit]
Description=RustD Machine Transition Default Target
DefaultDependencies=no
Requires=basic.target
Wants=rustd-ci-transition-keeper.service rustd-ci-transition-trigger.service
After=basic.target
EOF

cat >"$INITROOT/etc/rustd/system/rustd-ci-transition-keeper.service" <<'EOF'
[Unit]
Description=RustD Machine Transition Keeper
DefaultDependencies=no
After=basic.target

[Service]
Type=exec
StandardOutput=console
StandardError=console
ExecStart=/bin/sh -c 'while :; do /bin/sleep 3600; done'
ExecStop=/bin/sh /usr/lib/rustd/transition-stop.sh
Restart=no
EOF

cat >"$INITROOT/etc/rustd/system/rustd-ci-transition-trigger.service" <<'EOF'
[Unit]
Description=RustD Machine Transition Trigger
DefaultDependencies=no
After=basic.target rustd-ci-transition-keeper.service
Requires=rustd-ci-transition-keeper.service

[Service]
Type=exec
StandardOutput=console
StandardError=console
ExecStart=/bin/sh /usr/lib/rustd/transition-trigger.sh
Restart=no
EOF

cat >"$INITROOT/usr/lib/rustd/transition-stop.sh" <<'EOF'
#!/bin/sh
set -eu
echo 'RUSTD_PID1_MACHINE_STOP_OK' >/dev/ttyS0
exit 0
EOF
chmod 0755 "$INITROOT/usr/lib/rustd/transition-stop.sh"

cat >"$INITROOT/usr/lib/rustd/transition-trigger.sh" <<EOF
#!/bin/sh
set -eu
transition='$TRANSITION'
attempt=0
while [ "\$attempt" -lt 60 ]; do
    if /usr/bin/rustctl --quiet is-active default.target >/dev/null 2>&1 \
        && /usr/bin/rustctl --quiet is-active rustd-ci-transition-keeper.service >/dev/null 2>&1; then
        echo "RUSTD_PID1_MACHINE_REQUEST \$transition" >/dev/ttyS0
        /usr/bin/rustctl "\$transition" >/dev/ttyS0 2>&1 || {
            echo "RUSTD_PID1_MACHINE_CERT_FAIL: rustctl \$transition failed" >/dev/ttyS0
            /bin/poweroff -f
            exit 1
        }
        /bin/sleep 15
        echo "RUSTD_PID1_MACHINE_CERT_FAIL: manager returned without completing \$transition" >/dev/ttyS0
        /bin/poweroff -f
        exit 1
    fi
    attempt=\$((attempt + 1))
    /bin/sleep 1
done
echo 'RUSTD_PID1_MACHINE_CERT_FAIL: unit graph did not become healthy' >/dev/ttyS0
/bin/poweroff -f
exit 1
EOF
chmod 0755 "$INITROOT/usr/lib/rustd/transition-trigger.sh"

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
echo 'RUSTD_PID1_MACHINE_BOOT_BEGIN' >/dev/ttyS0
exec >/dev/ttyS0 2>&1
exec /usr/lib/rustd/rustd
EOF
chmod 0755 "$INITROOT/init"

INITRAMFS="$ROOT/rustd-pid1-machine-transition.cpio.gz"
(
    cd "$INITROOT"
    find . -print0 \
        | cpio --null --create --quiet --format=newc \
        | gzip -9 >"$INITRAMFS"
)

set +e
timeout --signal=TERM --kill-after=5s "$QEMU_TIMEOUT" \
    qemu-system-x86_64 \
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

if grep -Fq 'RUSTD_PID1_MACHINE_CERT_FAIL:' "$SERIAL_LOG"; then
    cat "$SERIAL_LOG" >&2
    echo "RustD PID1 $TRANSITION certification reported a guest failure" >&2
    exit 1
fi
if ! grep -Fq "RUSTD_PID1_MACHINE_REQUEST $TRANSITION" "$SERIAL_LOG"; then
    cat "$SERIAL_LOG" >&2
    echo "RustD PID1 $TRANSITION certification never issued the transition" >&2
    exit 1
fi
if ! grep -Fq 'RUSTD_PID1_MACHINE_STOP_OK' "$SERIAL_LOG"; then
    cat "$SERIAL_LOG" >&2
    echo "RustD PID1 $TRANSITION certification did not observe orderly ExecStop" >&2
    exit 1
fi
if [[ "$qemu_status" -ne 0 ]]; then
    cat "$SERIAL_LOG" >&2
    if [[ "$qemu_status" -eq 124 || "$qemu_status" -eq 137 ]]; then
        echo "RustD PID1 $TRANSITION certification timed out" >&2
    else
        echo "RustD PID1 $TRANSITION certification failed (qemu exit $qemu_status)" >&2
    fi
    exit 1
fi

echo "RustD PID1 $TRANSITION certification passed"
