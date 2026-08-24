#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later

# Fedora's cpio initramfs path does not preserve security.selinux xattrs from
# the installed root. Relabel the early-userspace tree before dracut's SELinux
# module loads the target policy; otherwise enforcing mode sees mount, chroot,
# udevadm, and dracut helpers as root_t and cannot execute them.

if getarg "selinux=0" > /dev/null; then
    exit 0
fi

if [ ! -s /etc/selinux/targeted/contexts/files/file_contexts ]; then
    warn "RustD initramfs SELinux file_contexts is missing"
    exit 1
fi

for path in /bin /etc /init /lib /lib64 /sbin /shutdown /usr /var; do
    [ -e "$path" ] || continue
    /usr/sbin/restorecon -RF "$path" || exit 1
done
