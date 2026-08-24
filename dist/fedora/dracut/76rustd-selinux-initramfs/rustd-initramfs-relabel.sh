#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later

# Fedora's cpio initramfs path does not preserve security.selinux xattrs from
# the installed root. Relabel the early-userspace executables before dracut's
# SELinux module loads the target policy; otherwise enforcing mode sees the
# handoff helpers as root_t and cannot execute them. Keep this list bounded:
# recursively relabeling the live root's /usr and /var can stall the pivot.

if getarg "selinux=0" > /dev/null; then
    exit 0
fi

if [ ! -s /etc/selinux/targeted/contexts/files/file_contexts ]; then
    warn "RustD initramfs SELinux file_contexts is missing"
    exit 1
fi

for path in \
    /bin /etc /lib /lib64 /sbin /usr /usr/bin /usr/sbin /usr/lib \
    /usr/lib/dracut /usr/lib/rustd /var /init /shutdown \
    /bin/* /sbin/* /usr/bin/* /usr/sbin/* \
    /usr/lib/dracut/dracut-util /usr/lib/rustd/rustd \
    /usr/lib/rustd/rustd-udevd; do
    [ -e "$path" ] || continue
    /usr/sbin/restorecon -F "$path" || exit 1
done
