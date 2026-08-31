#!/usr/bin/sh

command -v getarg >/dev/null 2>&1 || . /lib/dracut-lib.sh

isofile=$1
[ -n "$isofile" ] || exit 1

for device in /dev/disk/by-label/* /dev/disk/by-uuid/*; do
    [ -e "$device" ] || continue
    mountpoint=/run/initramfs/iso-scan
    mkdir -p "$mountpoint"
    if mount -n -o ro "$device" "$mountpoint" 2>/dev/null \
        && [ -f "$mountpoint$isofile" ]; then
        root="live:$device"
        umount "$mountpoint"
        exec /sbin/dmsquash-live-root "$device"
    fi
    umount "$mountpoint" 2>/dev/null || :
done

exit 1
