#!/usr/bin/bash

# RustD-compatible network-live module.  The shell initqueue path is used so
# network live media does not select dracut's systemd generators merely because
# the compatibility package provides the logical systemd-initrd dependency.
check() {
    return 255
}

depends() {
    echo network url-lib dmsquash-live img-lib bash
    return 0
}

install() {
    inst_hook cmdline 29 "$moddir/parse-livenet.sh"
    inst_hook initqueue/online 95 "$moddir/fetch-liveupdate.sh"
    inst_script "$moddir/livenetroot.sh" /sbin/livenetroot
    dracut_need_initqueue
}
