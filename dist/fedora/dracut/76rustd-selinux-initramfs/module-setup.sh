#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later

check() {
    return 0
}

depends() {
    echo base
    return 0
}

install() {
    # RustD loads the installed policy after switch_root.  The cpio initramfs
    # root is a ramfs and cannot carry security.selinux xattrs, so attempting
    # to relabel it before pivot is both ineffective and fatal under enforcing
    # mode.
    inst /etc/selinux/config
    inst /etc/selinux/targeted/contexts/files/file_contexts
}
