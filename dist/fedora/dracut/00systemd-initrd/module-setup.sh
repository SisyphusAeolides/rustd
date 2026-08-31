#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later

# RustD provides the logical systemd-initrd dracut module contract.  RLC and
# Fedora live-image modules depend on that name even when the systemd
# implementation is not present.  Keeping the contract here lets those
# modules remain unmodified while RustD continues to own PID 1 and udev.

check() {
    # A live-image build explicitly requests this dependency.  Returning 255
    # keeps the module available to dependency resolution without making it a
    # host-only auto-selection.
    return 255
}

depends() {
    echo base
    return 0
}

install() {
    # The shell dracut path starts udev through this compatibility pathname.
    # The executable is supplied by rustd-fedora-compat and delegates to
    # RustD's native udev daemon; no systemd implementation binary is copied.
    inst_multiple -o \
        /usr/lib/systemd/systemd-udevd \
        /usr/lib/rustd/rustd-udevd \
        /usr/bin/rustudevadm
}
