#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Build a minimal initramfs and cold-boot RustD as the real PID 1 under QEMU.

set -Eeuo pipefail

ROOT="${RUSTD_PID1_ROOT:-$(mktemp -d)}"
KEEP_ROOT="${RUSTD_PID1_KEEP_ROOT:-0}"
RELEASE_DIR="${RUSTD_RELEASE_DIR:-target/release}"
SERIAL_LOG="${RUSTD_PID1_SERIAL_LOG:-pid1-serial.log}"
KERNEL="${RUSTD_PID1_KERNEL:-}"
QEMU_TIMEOUT="${RUSTD_PID1_QEMU_TIMEOUT:-90s}"
REEXEC_CYCLES="${RUSTD_PID1_REEXEC_CYCLES:-0}"
QEMU="${RUSTD_QEMU_BINARY:-}"

if [[ ! "$REEXEC_CYCLES" =~ ^[0-9]+$ ]]; then
    echo "RUSTD_PID1_REEXEC_CYCLES must be a non-negative integer" >&2
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

for binary in rustd rustctl rustd-journald; do
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
for applet in awk basename cat grep kill mkdir mount poweroff readlink sh sleep; do
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
Wants=rustd-journald.service dbus.service
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

if (( REEXEC_CYCLES > 0 )); then
    cat >"$INITROOT/etc/rustd/system/default.target" <<'EOF'
[Unit]
Description=RustD PID1 Reexec Certification Default Target
DefaultDependencies=no
Requires=basic.target
Wants=multi-user.target rustd-ci-keeper.service
After=basic.target
EOF
else
    cat >"$INITROOT/etc/rustd/system/default.target" <<'EOF'
[Unit]
Description=RustD PID1 Certification Default Target
DefaultDependencies=no
Requires=basic.target
Wants=multi-user.target rustd-ci-cert.service
After=basic.target
EOF
fi

cat >"$INITROOT/etc/rustd/system/dbus.service" <<'EOF'
[Unit]
Description=D-Bus System Message Bus
DefaultDependencies=no

[Service]
Type=exec
StandardOutput=console
StandardError=console
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
StandardOutput=console
StandardError=console
ExecStart=/usr/lib/rustd/rustd-journald --runtime-directory /run/rustd/journal
Restart=always
RestartSec=1
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

cat >"$INITROOT/usr/lib/rustd/ci-cert.sh" <<'EOF'
#!/bin/sh
set -eu

attempt=0
while [ "$attempt" -lt 30 ]; do
    if /usr/bin/rustctl --quiet is-active default.target >/dev/null 2>&1 \
        && /usr/bin/rustctl --quiet is-active basic.target >/dev/null 2>&1 \
        && /usr/bin/rustctl --quiet is-active multi-user.target >/dev/null 2>&1 \
        && /usr/bin/rustctl --quiet is-active getty.target >/dev/null 2>&1 \
        && /usr/bin/rustctl --quiet is-active rustd-journald.service >/dev/null 2>&1 \
        && /usr/bin/rustctl --quiet is-active dbus.service >/dev/null 2>&1 \
        && [ -S /run/dbus/system_bus_socket ]; then
        if RUSTCTL=/usr/bin/rustctl /usr/lib/rustd/boot-smoke.sh >/dev/ttyS0 2>&1; then
            echo 'RUSTD_PID1_CERT_PASS' >/dev/ttyS0
            sleep 1
            /bin/poweroff -f
            exit 0
        fi
    fi
    attempt=$((attempt + 1))
    /bin/sleep 1
done

echo 'RUSTD_PID1_CERT_FAIL: boot contract did not become healthy' >/dev/ttyS0
/usr/bin/rustctl --no-pager --plain list-units >/dev/ttyS0 2>&1 || true
/bin/poweroff -f
exit 1
EOF
chmod 0755 "$INITROOT/usr/lib/rustd/ci-cert.sh"

cat >"$INITROOT/usr/lib/rustd/reexec-cert.sh" <<'EOF'
#!/bin/sh
set -eu

cycles="${1:-0}"
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

attempt=0
while [ "$attempt" -lt 60 ]; do
    if /usr/bin/rustctl --quiet is-active default.target >/dev/null 2>&1 \
        && /usr/bin/rustctl --quiet is-active basic.target >/dev/null 2>&1 \
        && /usr/bin/rustctl --quiet is-active multi-user.target >/dev/null 2>&1 \
        && /usr/bin/rustctl --quiet is-active rustd-ci-keeper.service >/dev/null 2>&1; then
        break
    fi
    attempt=$((attempt + 1))
    /bin/sleep 1
done
[ "$attempt" -lt 60 ] || fail 'initial unit graph did not become healthy'

keeper_pid="$(main_pid)"
case "$keeper_pid" in
    ''|*[!0-9]*) fail "invalid keeper MainPID '$keeper_pid'" ;;
esac
[ "$keeper_pid" -gt 1 ] || fail "keeper MainPID is not a service process: $keeper_pid"
/bin/kill -0 "$keeper_pid" 2>/dev/null || fail "keeper process $keeper_pid is not alive before reexec"

i=1
while [ "$i" -le "$cycles" ]; do
    echo "RUSTD_PID1_REEXEC_CYCLE ${i}/${cycles}" >/dev/ttyS0
    /usr/bin/rustctl daemon-reexec >/dev/ttyS0 2>&1 \
        || fail "rustctl daemon-reexec failed at cycle $i"
    [ "$(/bin/basename "$(/bin/readlink /proc/1/exe)")" = rustd ] \
        || fail "PID 1 is no longer rustd after cycle $i"
    /usr/bin/rustctl --quiet is-active rustd-ci-keeper.service >/dev/null 2>&1 \
        || fail "keeper unit is not active after cycle $i"
    current_pid="$(main_pid)"
    [ "$current_pid" = "$keeper_pid" ] \
        || fail "keeper MainPID changed from $keeper_pid to $current_pid at cycle $i"
    /bin/kill -0 "$keeper_pid" 2>/dev/null \
        || fail "keeper process $keeper_pid died at cycle $i"
    i=$((i + 1))
done

echo "RUSTD_PID1_REEXEC_CERT_PASS cycles=${cycles} keeper_pid=${keeper_pid}" >/dev/ttyS0
/bin/sleep 1
/bin/poweroff -f
exit 0
EOF
chmod 0755 "$INITROOT/usr/lib/rustd/reexec-cert.sh"

cat >"$INITROOT/etc/rustd/system/rustd-ci-cert.service" <<'EOF'
[Unit]
Description=RustD PID1 Certification Probe
DefaultDependencies=no
After=basic.target rustd-journald.service

[Service]
Type=exec
StandardOutput=console
StandardError=console
ExecStart=/bin/sh /usr/lib/rustd/ci-cert.sh
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
mkdir -p /run/dbus /run/rustd /usr/share/dbus-1/system.d /etc/dbus-1/system.d
mount -t cgroup2 none /sys/fs/cgroup

echo 'RUSTD_PID1_BOOT_BEGIN' >/dev/ttyS0
exec >/dev/ttyS0 2>&1
reexec_cycles=0
for argument in $(cat /proc/cmdline); do
    case "$argument" in
        rustd.reexec-cert=*) reexec_cycles="${argument#rustd.reexec-cert=}" ;;
    esac
done
if [ "$reexec_cycles" -gt 0 ] 2>/dev/null; then
    /bin/sh /usr/lib/rustd/reexec-cert.sh "$reexec_cycles" &
else
    (
        sleep 10
        echo 'RUSTD_PID1_DIAGNOSTIC_BEGIN'
        /usr/bin/rustctl --no-pager --plain list-jobs || true
        /usr/bin/rustctl --no-pager --plain list-units || true
        /usr/bin/rustctl --no-pager --plain status dbus.service || true
        /usr/bin/rustctl --no-pager --plain status rustd-ci-cert.service || true
        /usr/bin/rustctl --no-pager --plain show dbus.service || true
        /usr/bin/rustctl --no-pager --plain show rustd-ci-cert.service || true
        echo 'RUSTD_PID1_DIAGNOSTIC_END'
    ) &
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

extra_cmdline=""
expected_marker="RUSTD_PID1_CERT_PASS"
if (( REEXEC_CYCLES > 0 )); then
    extra_cmdline="rustd.reexec-cert=$REEXEC_CYCLES"
    expected_marker="RUSTD_PID1_REEXEC_CERT_PASS"
fi

set +e
timeout --signal=TERM --kill-after=5s "$QEMU_TIMEOUT" \
    "$QEMU" \
    -machine accel=tcg \
    -cpu max \
    -m 768M \
    -smp 2 \
    -kernel "$KERNEL" \
    -initrd "$INITRAMFS" \
    -append "console=ttyS0 panic=-1 random.trust_cpu=on rustd.unit=default.target rustd.log_target=console $extra_cmdline" \
    -display none \
    -serial stdio \
    -monitor none \
    -object rng-random,filename=/dev/urandom,id=rng0 \
    -device virtio-rng-pci,rng=rng0 \
    -no-reboot \
    >"$SERIAL_LOG" 2>&1
qemu_status=$?
set -e

if grep -Fq "$expected_marker" "$SERIAL_LOG"; then
    if (( REEXEC_CYCLES > 0 )); then
        echo "RustD PID1 reexec certification passed ($REEXEC_CYCLES cycles)"
    else
        echo "RustD PID1 certification passed"
    fi
    exit 0
fi

cat "$SERIAL_LOG" >&2
if [[ "$qemu_status" -eq 124 || "$qemu_status" -eq 137 ]]; then
    echo "RustD PID1 certification timed out" >&2
else
    echo "RustD PID1 certification failed (qemu exit $qemu_status)" >&2
fi
exit 1
