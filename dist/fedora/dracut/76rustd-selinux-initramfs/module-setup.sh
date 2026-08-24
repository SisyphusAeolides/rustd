#!/usr/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later

check() {
    require_binaries setfiles find || return 1
    return 0
}

depends() {
    echo base
    return 0
}

install() {
    inst_multiple setfiles find
    inst /etc/selinux/config
    inst /etc/selinux/targeted/contexts/files/file_contexts
    inst_hook pre-pivot 40 "$moddir/rustd-initramfs-relabel.sh"
}
