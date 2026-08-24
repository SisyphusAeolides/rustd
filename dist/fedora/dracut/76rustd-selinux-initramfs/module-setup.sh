#!/usr/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later

check() {
    require_binaries restorecon setenforce || return 1
    return 0
}

depends() {
    echo base
    return 0
}

install() {
    inst_multiple restorecon setenforce
    inst /etc/selinux/config
    inst /etc/selinux/targeted/contexts/files/file_contexts
    inst_hook pre-pivot 39 "$moddir/rustd-initramfs-permissive.sh"
    inst_hook pre-pivot 40 "$moddir/rustd-initramfs-relabel.sh"
}
