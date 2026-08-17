#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Certify 100 in-place RustD PID1 re-execs while preserving a live service.

set -Eeuo pipefail

ROOT="${RUSTD_PID1_ROOT:-$(mktemp -d)}"
KEEP_ROOT="${RUSTD_PID1_KEEP_ROOT:-0}"
RELEASE_DIR="${RUSTD_RELEASE_DIR:-target/release}"
SERIAL_LOG="${RUSTD_PID1_SERIAL_LOG:-pid1-reexec.log}"
KERNEL="${RUSTD_PID1_KERNEL:-}"
QEMU_TIMEOUT="${RUSTD_PID1_QEMU_TIMEOUT:-180s}"
CYCLES="${RUSTD_PID1_REEXEC_CYCLES:-100}"

if [[ ! "$CYCLES" =~ ^[0-9]+$ ]] || (( CYCLES < 100 )); then
    echo "RUSTD_PID1_REEXEC_CYCLES must be an integer >= 100" >&2
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
    "$INITROOT/usr/lib/rustd" "$INITROOT/var"
ln -s ../run "$INITROOT/var/run"

cp "$(command -v busybox)" "$INITROOT/bin/busybox"
for applet in awk basename cat kill mkdir mount poweroff readlink sh sleep; do
    ln -s busybox "$INITROOT/bin/$applet"
done
install -m0755 "$RELEASE_DIR/rustd" "$INITROOT/usr/lib/rustd/rustd"
install -m0755 "$RELEASE_DIR/rustctl" "$INITROOT/usr/bin/rustctl"

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
printf 'rustd-reexec-ci\n' >"$INITROOT/etc/hostname"
printf '0123456789abcdef0123456789abcdef\n' >"$INITROOT/etc/machine-id"

cat >"$INITROOT/etc/rustd/system/basic.target" <<'EOF'
[Unit]
Description=RustD Reexec Basic Target
DefaultDependencies=no
EOF
cat >"$INITROOT/etc/rustd/system/default.target" <<'EOF'
[Unit]
Description=RustD Reexec Default Target
DefaultDependencies=no
Requires=basic.target
Wants=rustd-ci-keeper.service
After=basic.target
EOF
cat >"$INITROOT/etc/rustd/system/rustd-ci-keeper.service" <<'EOF'
[Unit]
Description=RustD Reexec State Keeper
DefaultDependencies=no
After=basic.target

[Service]
Type=exec
StandardOutput=console
StandardError=console
ExecStart=/bin/sh -c 'while :; do /bin/sleep 3600; done'
Restart=no
EOF

cat >"$INITROOT/usr/lib/rustd/reexec-cert.sh" <<'EOF'
#!/bin/sh
set -eu

cycles="${1:-100}"
fail() {
    echo "RUSTD_PID1_REEXEC_CERT_FAIL: $*" >/dev/ttyS0
    /usr/bin/rustctl --no-pager --plain list-units >/dev/ttyS0 2>&1 || true
    /usr/bin/rustctl --no-pager --plain status rustd-ci-keeper.service >/dev/ttyS0 2>&1 || true
    /bin/poweroff -f
    exit 1
}
main_pid() {
    /usr/bin/rustctl show rustd-ci-keeper.service 2>/dev/null \
        | /bin/awk -F= '$1 == "MainPID" { print $2; exit }'
}
ready_with_pid() {
    expected="$1"
    /usr/bin/rustctl --quiet is-active default.target >/dev/null 2>&1 || return 1
    /usr/bin/rustctl --quiet is-active basic.target >/dev/null 2>&1 || return 1
    /usr/bin/rustctl --quiet is-active rustd-ci-keeper.service >/dev/null 2>&1 || return 1
    current="$(main_pid)" || return 1
    [ "$current" = "$expected" ] || return 1
    /bin/kill -0 "$expected" 2>/dev/null || return 1
    return 0
}

attempt=0
while [ "$attempt" -lt 120 ]; do
    if /usr/bin/rustctl --quiet is-active default.target >/dev/null 2>&1 \
        && /usr/bin/rustctl --quiet is-active basic.target >/dev/null 2>&1 \
        && /usr/bin/rustctl --quiet is-active rustd-ci-keeper.service >/dev/null 2>&1; then
        break
    fi
    attempt=$((attempt + 1))
    /bin/sleep 0.1
done
[ "$attempt" -lt 120 ] || fail 'initial unit graph did not become healthy'

keeper_pid="$(main_pid)"
case "$keeper_pid" in
    ''|*[!0-9]*|0|1) fail "invalid keeper MainPID '$keeper_pid'" ;;
esac
/bin/kill -0 "$keeper_pid" 2>/dev/null || fail "keeper process $keeper_pid is not alive before reexec"

i=1
while [ "$i" -le "$cycles" ]; do
    echo "RUSTD_PID1_REEXEC_CYCLE ${i}/${cycles}" >/dev/ttyS0
    /usr/bin/rustctl daemon-reexec >/dev/ttyS0 2>&1 \
        || fail "rustctl daemon-reexec failed at cycle $i"
    [ "$(/bin/basename "$(/bin/readlink /proc/1/exe)")" = rustd ] \
        || fail "PID 1 is no longer rustd after cycle $i"

    # daemon-reexec returns when the manager has rebound its control socket.
    # Reexec-state restoration happens immediately after Manager::new(), so
    # wait for the restored graph itself to become query-ready before judging
    # preservation. This does not permit a replacement service PID.
    attempt=0
    while [ "$attempt" -lt 120 ]; do
        if ready_with_pid "$keeper_pid"; then
            break
        fi
        attempt=$((attempt + 1))
        /bin/sleep 0.05
    done
    [ "$attempt" -lt 120 ] || fail "restored graph was not ready with keeper MainPID $keeper_pid after cycle $i"
    i=$((i + 1))
done

echo "RUSTD_PID1_REEXEC_CERT_PASS cycles=${cycles} keeper_pid=${keeper_pid}" >/dev/ttyS0
/bin/sleep 1
/bin/poweroff -f
exit 0
EOF
chmod 0755 "$INITROOT/usr/lib/rustd/reexec-cert.sh"

cat >"$INITROOT/init" <<EOF
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
echo 'RUSTD_PID1_REEXEC_BOOT_BEGIN' >/dev/ttyS0
exec >/dev/ttyS0 2>&1
/bin/sh /usr/lib/rustd/reexec-cert.sh '$CYCLES' &
exec /usr/lib/rustd/rustd
EOF
chmod 0755 "$INITROOT/init"

INITRAMFS="$ROOT/rustd-pid1-reexec.cpio.gz"
(
    cd "$INITROOT"
    find . -print0 | cpio --null --create --quiet --format=newc | gzip -9 >"$INITRAMFS"
)

set +e
timeout --signal=TERM --kill-after=5s "$QEMU_TIMEOUT" \
    qemu-system-x86_64 \
    -machine accel=tcg -cpu max -m 768M -smp 2 \
    -kernel "$KERNEL" -initrd "$INITRAMFS" \
    -append "console=ttyS0 panic=-1 random.trust_cpu=on rustd.unit=default.target rustd.log_target=console" \
    -display none -serial stdio -monitor none \
    -object rng-random,filename=/dev/urandom,id=rng0 \
    -device virtio-rng-pci,rng=rng0 -no-reboot \
    >"$SERIAL_LOG" 2>&1
qemu_status=$?
set -e

if grep -Fq "RUSTD_PID1_REEXEC_CERT_PASS cycles=$CYCLES" "$SERIAL_LOG"; then
    echo "RustD PID1 reexec certification passed ($CYCLES cycles)"
    exit 0
fi
cat "$SERIAL_LOG" >&2
if [[ "$qemu_status" -eq 124 || "$qemu_status" -eq 137 ]]; then
    echo "RustD PID1 reexec certification timed out" >&2
else
    echo "RustD PID1 reexec certification failed (qemu exit $qemu_status)" >&2
fi
exit 1
