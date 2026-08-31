#!/usr/bin/bash

# RustD-compatible implementation of the Fedora/RHEL live-media contract.
# This module deliberately uses dracut's shell initqueue path.  The logical
# systemd-initrd module supplied by RustD must not make a legacy live image
# select systemd generators or systemd mount units.

check() {
    [[ $hostonly ]] && return 1
    return 255
}

depends() {
    echo dm rootfs-block img-lib overlayfs bash
    return 0
}

installkernel() {
    instmods squashfs loop iso9660 erofs overlay
}

install() {
    inst_multiple umount dmsetup blkid dd losetup blockdev find rmdir grep
    inst_multiple -o checkisomd5
    inst_hook cmdline 30 "$moddir/parse-dmsquash-live.sh"
    inst_hook cmdline 31 "$moddir/parse-iso-scan.sh"
    inst_hook pre-udev 30 "$moddir/dmsquash-live-genrules.sh"
    inst_hook pre-udev 30 "$moddir/dmsquash-liveiso-genrules.sh"
    inst_script "$moddir/dmsquash-live-root.sh" /sbin/dmsquash-live-root
    inst_script "$moddir/iso-scan.sh" /sbin/iso-scan
    dracut_need_initqueue
}
