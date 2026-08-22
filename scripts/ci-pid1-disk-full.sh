#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Certify RustD PID 1 remains healthy when persistent journal storage reaches ENOSPC.

set -Eeuo pipefail

ROOT="${RUSTD_PID1_ROOT:-$(mktemp -d)}"
KEEP_ROOT="${RUSTD_PID1_KEEP_ROOT:-0}"
RELEASE_DIR="${RUSTD_RELEASE_DIR:-target/release}"
SERIAL_LOG="${RUSTD_PID1_SERIAL_LOG:-pid1-disk-full.log}"
KERNEL="${RUSTD_PID1_KERNEL:-}"
QEMU_TIMEOUT="${RUSTD_PID1_QEMU_TIMEOUT:-120s}"

cleanup() {
    status=$?
    if [[ "$KEEP_ROOT" != 1 ]]; then
        rm -rf "$ROOT"
    fi
    exit "$status"
}
trap cleanup EXIT

for binary in rustd rustctl rustd-journald rustd-cat; do
    [[ -x "$RELEASE_DIR/$binary" ]] || {
        echo "missing release binary: $RELEASE_DIR/$binary" >&2
        exit 1
    }
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
[[ -n "$KERNEL" && -r "$KERNEL" ]] || {
    echo "bootable kernel not found" >&2
    exit 1
}

INITROOT="$ROOT/initramfs"
mkdir -p \
    "$INITROOT/bin" "$INITROOT/dev/pts" "$INITROOT/dev/shm" \
    "$INITROOT/etc/rustd/system" "$INITROOT/proc" "$INITROOT/run" \
    "$INITROOT/sys/fs/cgroup" "$INITROOT/tmp" "$INITROOT/usr/bin" \
    "$INITROOT/usr/lib/rustd" "$INITROOT/var/log/journal"
mkdir -p "$INITROOT/var/run"
rm -rf "$INITROOT/var/run"
ln -s ../run "$INITROOT/var/run"

cp "$(command -v busybox)" "$INITROOT/bin/busybox"
for applet in awk basename cat dd grep kill mkdir mount poweroff readlink sh sleep; do
    ln -s busybox "$INITROOT/bin/$applet"
done

install -m0755 "$RELEASE_DIR/rustd" "$INITROOT/usr/lib/rustd/rustd"
install -m0755 "$RELEASE_DIR/rustctl" "$INITROOT/usr/bin/rustctl"
install -m0755 "$RELEASE_DIR/rustd-journald" "$INITROOT/usr/lib/rustd/rustd-journald"
install -m0755 "$RELEASE_DIR/rustd-cat" "$INITROOT/usr/bin/rustd-cat"

copy_shared_libraries() {
    local executable="$1" library
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
for executable in rustd rustctl rustd-journald rustd-cat; do
    copy_shared_libraries "$RELEASE_DIR/$executable"
done

cat >"$INITROOT/etc/passwd" <<'EOF'
root:x:0:0:root:/root:/bin/sh
nobody:x:65534:65534:nobody:/:/bin/false
EOF
cat >"$INITROOT/etc/group" <<'EOF'
root:x:0:
nobody:x:65534:
EOF
printf 'rustd-disk-full-ci\n' >"$INITROOT/etc/hostname"
printf '0123456789abcdef0123456789abcdef\n' >"$INITROOT/etc/machine-id"

cat >"$INITROOT/etc/rustd/system/basic.target" <<'EOF'
[Unit]
Description=RustD Disk Full Basic Target
DefaultDependencies=no
Wants=rustd-journald.service
EOF
cat >"$INITROOT/etc/rustd/system/default.target" <<'EOF'
[Unit]
Description=RustD Disk Full Default Target
DefaultDependencies=no
Requires=basic.target
Wants=rustd-ci-disk-keeper.service rustd-ci-disk-trigger.service
After=basic.target
EOF
cat >"$INITROOT/etc/rustd/system/rustd-journald.service" <<'EOF'
[Unit]
Description=RustD Journal Service
DefaultDependencies=no

[Service]
Type=simple
StandardOutput=console
StandardError=console
ExecStart=/usr/lib/rustd/rustd-journald --runtime-directory /run/rustd/journal --journal-directory /var/log/journal
Restart=always
RestartSec=1
EOF
cat >"$INITROOT/etc/rustd/system/rustd-ci-disk-keeper.service" <<'EOF'
[Unit]
Description=RustD Disk Full Keeper
DefaultDependencies=no
After=basic.target

[Service]
Type=exec
StandardOutput=console
StandardError=console
ExecStart=/bin/sh -c 'while :; do /bin/sleep 3600; done'
Restart=no
EOF
cat >"$INITROOT/etc/rustd/system/rustd-ci-disk-trigger.service" <<'EOF'
[Unit]
Description=RustD Disk Full Trigger
DefaultDependencies=no
After=rustd-journald.service rustd-ci-disk-keeper.service
Requires=rustd-ci-disk-keeper.service

[Service]
Type=exec
StandardOutput=console
StandardError=console
ExecStart=/bin/sh /usr/lib/rustd/disk-full-trigger.sh
Restart=no
EOF

cat >"$INITROOT/usr/lib/rustd/disk-full-trigger.sh" <<'EOF'
#!/bin/sh
set -eu

fail() {
    echo "RUSTD_PID1_DISK_FULL_FAIL: $*" >/dev/ttyS0
    /usr/bin/rustctl --no-pager --plain list-units >/dev/ttyS0 2>&1 || true
    /usr/bin/rustctl --no-pager --plain status rustd-journald.service >/dev/ttyS0 2>&1 || true
    /bin/poweroff -f
    exit 1
}
main_pid() {
    /usr/bin/rustctl show rustd-ci-disk-keeper.service 2>/dev/null \
        | /bin/awk -F= '$1 == "MainPID" { print $2; exit }'
}

attempt=0
while [ "$attempt" -lt 120 ]; do
    if /usr/bin/rustctl --quiet is-active default.target >/dev/null 2>&1 \
        && /usr/bin/rustctl --quiet is-active rustd-ci-disk-keeper.service >/dev/null 2>&1 \
        && /usr/bin/rustctl --quiet is-active rustd-journald.service >/dev/null 2>&1 \
        && [ -S /run/rustd/journal/stdout ]; then
        break
    fi
    attempt=$((attempt + 1))
    /bin/sleep 0.1
done
[ "$attempt" -lt 120 ] || fail 'initial journal/control graph did not become healthy'

keeper_pid="$(main_pid)"
case "$keeper_pid" in
    ''|*[!0-9]*|0|1) fail "invalid keeper MainPID '$keeper_pid'" ;;
esac
/bin/kill -0 "$keeper_pid" 2>/dev/null || fail "keeper process $keeper_pid is not alive before ENOSPC"

set +e
/bin/dd if=/dev/zero of=/var/log/journal/fill.bin bs=4096 2>/tmp/disk-fill.err
fill_status=$?
set -e
[ "$fill_status" -ne 0 ] || fail 'journal filesystem filler unexpectedly completed without ENOSPC'
if echo x >>/var/log/journal/fill.bin 2>/tmp/disk-confirm.err; then
    fail 'journal filesystem still accepted a write after filler failure'
fi
echo 'RUSTD_PID1_DISK_FULL_CONFIRMED' >/dev/ttyS0

# Send real stdout-stream journal traffic after the persistent filesystem is full.
# The journal daemon is expected to surface persistence failure; PID 1 and
# unrelated service supervision must remain healthy.
set +e
/usr/bin/rustd-cat -t rustd-disk-full /bin/sh -c '
    i=0
    while [ "$i" -lt 64 ]; do
        echo "disk-full-journal-message-$i-abcdefghijklmnopqrstuvwxyz0123456789"
        i=$((i + 1))
    done
'
cat_status=$?
set -e
echo "RUSTD_PID1_DISK_FULL_JOURNAL_ATTEMPT status=$cat_status" >/dev/ttyS0
# The stdout worker records persistence errors asynchronously. A second
# connection wakes the daemon's control loop so it can report the failure.
/bin/sleep 0.1
/usr/bin/rustd-cat -t rustd-disk-full-probe /bin/echo probe >/dev/null 2>&1 || true
/bin/sleep 2

probe=0
while [ "$probe" -lt 10 ]; do
    /usr/bin/rustctl --quiet is-active default.target >/dev/null 2>&1 \
        || fail "control plane unhealthy after ENOSPC at probe $probe"
    /usr/bin/rustctl --quiet is-active rustd-ci-disk-keeper.service >/dev/null 2>&1 \
        || fail "keeper unit inactive after ENOSPC at probe $probe"
    current_pid="$(main_pid)"
    [ "$current_pid" = "$keeper_pid" ] \
        || fail "keeper MainPID changed from $keeper_pid to $current_pid after ENOSPC"
    /bin/kill -0 "$keeper_pid" 2>/dev/null \
        || fail "keeper process $keeper_pid died after ENOSPC"
    [ "$(/bin/basename "$(/bin/readlink /proc/1/exe)")" = rustd ] \
        || fail 'PID 1 is no longer rustd after ENOSPC'
    probe=$((probe + 1))
    /bin/sleep 0.2
done

echo "RUSTD_PID1_DISK_FULL_OK keeper=$keeper_pid" >/dev/ttyS0
/bin/poweroff -f
exit 0
EOF
chmod 0755 "$INITROOT/usr/lib/rustd/disk-full-trigger.sh"

cat >"$INITROOT/init" <<'EOF'
#!/bin/sh
set -eu
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /dev/pts /dev/shm /run /run/rustd /tmp /sys/fs/cgroup /var/log/journal
mount -t devpts devpts /dev/pts
mount -t tmpfs tmpfs /dev/shm
mount -t tmpfs tmpfs /run
mount -t cgroup2 none /sys/fs/cgroup
mount -t tmpfs -o size=128k,nr_inodes=128 tmpfs /var/log/journal
echo 'RUSTD_PID1_DISK_FULL_BOOT_BEGIN' >/dev/ttyS0
exec >/dev/ttyS0 2>&1
exec /usr/lib/rustd/rustd
EOF
chmod 0755 "$INITROOT/init"

INITRAMFS="$ROOT/rustd-pid1-disk-full.cpio.gz"
(
    cd "$INITROOT"
    find . -print0 | cpio --null --create --quiet --format=newc | gzip -9 >"$INITRAMFS"
)

set +e
timeout --signal=TERM --kill-after=5s "$QEMU_TIMEOUT" \
    qemu-system-x86_64 \
    -machine accel=tcg -cpu max -m 512M -smp 2 \
    -kernel "$KERNEL" -initrd "$INITRAMFS" \
    -append "console=ttyS0 panic=-1 random.trust_cpu=on rustd.unit=default.target rustd.log_target=console" \
    -display none -serial stdio -monitor none \
    -object rng-random,filename=/dev/urandom,id=rng0 \
    -device virtio-rng-pci,rng=rng0 -no-reboot \
    >"$SERIAL_LOG" 2>&1
qemu_status=$?
set -e

if grep -Fq 'RUSTD_PID1_DISK_FULL_FAIL:' "$SERIAL_LOG"; then
    cat "$SERIAL_LOG" >&2
    echo "RustD PID1 disk-full certification reported a guest failure" >&2
    exit 1
fi
if ! grep -Fq 'RUSTD_PID1_DISK_FULL_CONFIRMED' "$SERIAL_LOG"; then
    cat "$SERIAL_LOG" >&2
    echo "RustD PID1 disk-full certification never reached ENOSPC" >&2
    exit 1
fi
if ! grep -Fq 'RUSTD_PID1_DISK_FULL_JOURNAL_ATTEMPT' "$SERIAL_LOG"; then
    cat "$SERIAL_LOG" >&2
    echo "RustD PID1 disk-full certification did not inject journal traffic" >&2
    exit 1
fi
if ! grep -Fq 'journal persistence failed' "$SERIAL_LOG"; then
    cat "$SERIAL_LOG" >&2
    echo "RustD PID1 disk-full certification did not observe journal persistence failure" >&2
    exit 1
fi
if ! grep -Fq 'RUSTD_PID1_DISK_FULL_OK' "$SERIAL_LOG"; then
    cat "$SERIAL_LOG" >&2
    echo "RustD PID1 disk-full certification did not reach the healthy post-ENOSPC state" >&2
    exit 1
fi
if [[ "$qemu_status" -ne 0 ]]; then
    cat "$SERIAL_LOG" >&2
    if [[ "$qemu_status" -eq 124 || "$qemu_status" -eq 137 ]]; then
        echo "RustD PID1 disk-full certification timed out" >&2
    else
        echo "RustD PID1 disk-full certification failed (qemu exit $qemu_status)" >&2
    fi
    exit 1
fi

echo "RustD PID1 disk-full certification passed"
