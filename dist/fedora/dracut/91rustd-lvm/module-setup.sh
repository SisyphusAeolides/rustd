#!/usr/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later

# RustD owns the initramfs udev daemon. Device-mapper's legacy cookie wait is
# not a required ordering primitive for that daemon; lvm_scan activates the
# mapping without the cookie wait and lets the following udevadm settle call
# process the resulting kernel event.

check() {
    return 255
}

depends() {
    echo lvm
    return 0
}

install() {
    # Keep the distribution's lvm_scan behavior in sync with dracut. The
    # wrapper below only changes the activation calls that need the legacy
    # device-mapper udev acknowledgement.
    inst_script "$dracutbasedir/modules.d/90lvm/lvm_scan.sh" \
        /usr/lib/rustd/initrd/lvm_scan.stock
    inst_simple /usr/bin/lvm /usr/lib/rustd/initrd/lvm.real
    inst_script "$moddir/lvm_scan.sh" /sbin/lvm_scan
}
