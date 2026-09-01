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
    local stock_scanner=

    # Keep the distribution's lvm_scan behavior in sync with dracut. The
    # wrapper below only changes the activation calls that need the legacy
    # device-mapper udev acknowledgement.
    for stock_scanner in \
        "$dracutbasedir/modules.d/90lvm/lvm_scan.sh" \
        "$dracutbasedir/modules.d/70lvm/lvm_scan.sh"; do
        test -f "$stock_scanner" && break
    done
    test -f "$stock_scanner"
    inst_script "$stock_scanner" \
        /usr/lib/rustd/initrd/lvm_scan.stock
    inst_simple /usr/bin/lvm /usr/lib/rustd/initrd/lvm.real
    # Fedora's merged-/usr initramfs resolves /sbin/lvm_scan to this path;
    # install over the stock scanner after preserving its implementation.
    inst_script "$moddir/lvm_scan.sh" /usr/bin/lvm_scan
}
