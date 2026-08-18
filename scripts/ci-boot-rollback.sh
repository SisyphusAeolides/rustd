#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Exercise RustD boot-counter rollback semantics under real OVMF UEFI/efivarfs.

set -Eeuo pipefail

ROOT="${RUSTD_ROLLBACK_ROOT:-$(mktemp -d)}"
KEEP_ROOT="${RUSTD_ROLLBACK_KEEP_ROOT:-0}"
RELEASE_DIR="${RUSTD_RELEASE_DIR:-target/release}"
SERIAL_LOG="${RUSTD_ROLLBACK_SERIAL_LOG:-rollback-serial.log}"
KERNEL="${RUSTD_PID1_KERNEL:-}"
OVMF_CODE="${RUSTD_OVMF_CODE:-}"
OVMF_VARS="${RUSTD_OVMF_VARS:-}"
QEMU_TIMEOUT="${RUSTD_ROLLBACK_QEMU_TIMEOUT:-120s}"
LOADER_GUID="4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"

cleanup() {
    status=$?
    if [[ "$KEEP_ROOT" != 1 ]]; then
        rm -rf "$ROOT"
    fi
    exit "$status"
}
trap cleanup EXIT

for binary in rustd rustctl rustd-bless-boot; do
    [[ -x "$RELEASE_DIR/$binary" ]] || {
        echo "missing release binary: $RELEASE_DIR/$binary" >&2
        exit 1
    }
done
for command in busybox cpio grub-mkstandalone gzip ldd python3 qemu-system-x86_64 timeout; do
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

if [[ -z "$OVMF_CODE" ]]; then
    OVMF_CODE="$(find /usr/share/OVMF /usr/share/edk2 -type f \( -name 'OVMF_CODE_4M.fd' -o -name 'OVMF_CODE.fd' \) 2>/dev/null | head -1)"
fi
if [[ -z "$OVMF_VARS" ]]; then
    OVMF_VARS="$(find /usr/share/OVMF /usr/share/edk2 -type f \( -name 'OVMF_VARS_4M.fd' -o -name 'OVMF_VARS.fd' \) 2>/dev/null | head -1)"
fi
[[ -n "$OVMF_CODE" && -r "$OVMF_CODE" ]] || {
    echo "OVMF code image not found" >&2
    exit 1
}
[[ -n "$OVMF_VARS" && -r "$OVMF_VARS" ]] || {
    echo "OVMF variable template not found" >&2
    exit 1
}

INITROOT="$ROOT/initramfs"
mkdir -p \
    "$INITROOT/bin" \
    "$INITROOT/boot-test/EFI/Linux" \
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
for applet in awk basename cat grep kill mkdir mount poweroff readlink sh sleep test; do
    ln -s busybox "$INITROOT/bin/$applet"
done
install -m0755 "$RELEASE_DIR/rustd" "$INITROOT/usr/lib/rustd/rustd"
install -m0755 "$RELEASE_DIR/rustctl" "$INITROOT/usr/bin/rustctl"
install -m0755 "$RELEASE_DIR/rustd-bless-boot" "$INITROOT/usr/bin/rustd-bless-boot"

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
copy_shared_libraries "$RELEASE_DIR/rustd-bless-boot"

cat >"$INITROOT/etc/passwd" <<'EOF'
root:x:0:0:root:/root:/bin/sh
nobody:x:65534:65534:nobody:/:/bin/false
EOF
cat >"$INITROOT/etc/group" <<'EOF'
root:x:0:
nobody:x:65534:
EOF
printf 'rustd-rollback-ci\n' >"$INITROOT/etc/hostname"
printf '0123456789abcdef0123456789abcdef\n' >"$INITROOT/etc/machine-id"

# The fallback entry is deliberately independent of the boot-counted candidate.
printf 'candidate image\n' >"$INITROOT/boot-test/EFI/Linux/rustd-candidate+3-1.efi"
printf 'fallback image\n' >"$INITROOT/boot-test/EFI/Linux/rustd-fallback.efi"

python3 - "$INITROOT/usr/lib/rustd/loader-boot-count.bin" <<'PY'
import struct
import sys
from pathlib import Path

path = "/EFI/Linux/rustd-candidate+3-1.efi"
# EFI_VARIABLE_NON_VOLATILE | BOOTSERVICE_ACCESS | RUNTIME_ACCESS.
payload = struct.pack("<I", 0x7) + path.encode("utf-16-le") + b"\0\0"
Path(sys.argv[1]).write_bytes(payload)
PY

cat >"$INITROOT/etc/rustd/system/default.target" <<'EOF'
[Unit]
Description=RustD UEFI Rollback Certification Target
DefaultDependencies=no
Wants=rustd-ci-rollback.service
EOF

cat >"$INITROOT/etc/rustd/system/rustd-ci-rollback.service" <<'EOF'
[Unit]
Description=RustD UEFI Boot Rollback Probe
DefaultDependencies=no

[Service]
Type=exec
StandardOutput=console
StandardError=console
ExecStart=/bin/sh /usr/lib/rustd/rollback-cert.sh
Restart=no
EOF

cat >"$INITROOT/usr/lib/rustd/rollback-cert.sh" <<EOF
#!/bin/sh
set -eu

fail() {
    echo "RUSTD_BOOT_ROLLBACK_CERT_FAIL: \$*" >/dev/ttyS0
    /usr/bin/rustctl --no-pager --plain list-units >/dev/ttyS0 2>&1 || true
    /bin/poweroff -f
    exit 1
}

[ -d /sys/firmware/efi ] || fail 'guest was not booted through UEFI'
mkdir -p /sys/firmware/efi/efivars
if ! mount -t efivarfs efivarfs /sys/firmware/efi/efivars 2>/dev/null; then
    [ -d /sys/firmware/efi/efivars ] || fail 'efivarfs is unavailable'
fi
variable=/sys/firmware/efi/efivars/LoaderBootCountPath-${LOADER_GUID}
cat /usr/lib/rustd/loader-boot-count.bin >"\$variable" \
    || fail 'could not publish LoaderBootCountPath in real efivarfs'
[ -r "\$variable" ] || fail 'LoaderBootCountPath is not readable'

status="\$(/usr/bin/rustd-bless-boot --path=/boot-test status)" \
    || fail 'initial boot-counter status failed'
[ "\$status" = indeterminate ] || fail "expected indeterminate, got \$status"

/usr/bin/rustd-bless-boot --path=/boot-test good \
    || fail 'mark-good transition failed'
[ -f /boot-test/EFI/Linux/rustd-candidate.efi ] \
    || fail 'mark-good did not remove the boot counter from the candidate name'
[ -f /boot-test/EFI/Linux/rustd-fallback.efi ] \
    || fail 'fallback entry disappeared during mark-good'
status="\$(/usr/bin/rustd-bless-boot --path=/boot-test status)" \
    || fail 'good status failed'
[ "\$status" = good ] || fail "expected good, got \$status"

/usr/bin/rustd-bless-boot --path=/boot-test indeterminate \
    || fail 'indeterminate transition failed'
[ -f /boot-test/EFI/Linux/rustd-candidate+3-1.efi ] \
    || fail 'indeterminate did not restore the counted candidate name'
status="\$(/usr/bin/rustd-bless-boot --path=/boot-test status)" \
    || fail 'indeterminate status failed'
[ "\$status" = indeterminate ] || fail "expected indeterminate after reset, got \$status"

/usr/bin/rustd-bless-boot --path=/boot-test bad \
    || fail 'mark-bad rollback transition failed'
[ -f /boot-test/EFI/Linux/rustd-candidate+0-1.efi ] \
    || fail 'mark-bad did not exhaust the candidate boot counter'
[ ! -e /boot-test/EFI/Linux/rustd-candidate+3-1.efi ] \
    || fail 'old counted candidate remains after mark-bad'
[ ! -e /boot-test/EFI/Linux/rustd-candidate.efi ] \
    || fail 'good candidate remains after mark-bad'
[ -f /boot-test/EFI/Linux/rustd-fallback.efi ] \
    || fail 'fallback entry disappeared during rollback'
status="\$(/usr/bin/rustd-bless-boot --path=/boot-test status)" \
    || fail 'bad status failed'
[ "\$status" = bad ] || fail "expected bad, got \$status"

[ "\$(/bin/basename "\$(/bin/readlink /proc/1/exe)")" = rustd ] \
    || fail 'PID 1 is no longer RustD during rollback campaign'
/usr/bin/rustctl --no-pager --plain list-units >/dev/null 2>&1 \
    || fail 'RustD control plane is not responsive after rollback transition'

echo 'RUSTD_BOOT_ROLLBACK_CERT_PASS uefi=1 efivarfs=1 transitions=good,indeterminate,bad fallback=preserved' >/dev/ttyS0
/bin/sleep 1
/bin/poweroff -f
exit 0
EOF
chmod 0755 "$INITROOT/usr/lib/rustd/rollback-cert.sh"

cat >"$INITROOT/init" <<'EOF'
#!/bin/sh
set -eu
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /dev/pts /dev/shm /run /tmp /sys/fs/cgroup
mount -t devpts devpts /dev/pts
mount -t tmpfs tmpfs /dev/shm
mount -t tmpfs tmpfs /run
mount -t cgroup2 none /sys/fs/cgroup

echo 'RUSTD_BOOT_ROLLBACK_BEGIN' >/dev/ttyS0
exec >/dev/ttyS0 2>&1
exec /usr/lib/rustd/rustd
EOF
chmod 0755 "$INITROOT/init"

INITRAMFS="$ROOT/rustd-rollback-initramfs.cpio.gz"
(
    cd "$INITROOT"
    find . -print0 \
        | cpio --null --create --quiet --format=newc \
        | gzip -9 >"$INITRAMFS"
)

ESP="$ROOT/esp"
mkdir -p "$ESP/EFI/BOOT"
cp "$KERNEL" "$ESP/vmlinuz"
cp "$INITRAMFS" "$ESP/initramfs.cpio.gz"
cat >"$ROOT/grub.cfg" <<'EOF'
set timeout=0
set default=0
terminal_output console
linux /vmlinuz console=ttyS0 rdinit=/init panic=-1
initrd /initramfs.cpio.gz
boot
EOF
grub-mkstandalone \
    -O x86_64-efi \
    -o "$ESP/EFI/BOOT/BOOTX64.EFI" \
    "boot/grub/grub.cfg=$ROOT/grub.cfg"

cp "$OVMF_VARS" "$ROOT/OVMF_VARS.fd"
set +e
timeout --signal=TERM --kill-after=5s "$QEMU_TIMEOUT" \
    qemu-system-x86_64 \
        -machine q35,accel=tcg \
        -m 256M \
        -smp 2 \
        -nodefaults \
        -no-reboot \
        -drive "if=pflash,format=raw,readonly=on,file=$OVMF_CODE" \
        -drive "if=pflash,format=raw,file=$ROOT/OVMF_VARS.fd" \
        -drive "format=raw,file=fat:rw:$ESP" \
        -serial "file:$SERIAL_LOG" \
        -display none
qemu_status=$?
set -e

cat "$SERIAL_LOG"
if ! grep -Fq 'RUSTD_BOOT_ROLLBACK_CERT_PASS' "$SERIAL_LOG"; then
    echo "RustD UEFI rollback certification failed (qemu status $qemu_status)" >&2
    exit 1
fi
if grep -Fq 'RUSTD_BOOT_ROLLBACK_CERT_FAIL:' "$SERIAL_LOG"; then
    echo "RustD UEFI rollback certification emitted a failure marker" >&2
    exit 1
fi

echo "RustD UEFI boot rollback certification passed"
