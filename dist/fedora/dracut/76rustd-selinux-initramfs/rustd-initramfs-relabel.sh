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

contexts=/etc/selinux/targeted/contexts/files/file_contexts
if [ ! -s "$contexts" ]; then
    warn "RustD initramfs SELinux file_contexts is missing"
    exit 1
fi

# restorecon defers when the kernel has not loaded a policy yet.  setfiles can
# apply the policy's labels directly to cpio-created inodes.  Restrict the
# input to files at the early-userspace directory level; passing a directory
# to setfiles would recursively relabel the live root and stall the pivot.
for directory in /bin /sbin /usr/bin /usr/sbin /lib /lib64 /usr/lib \
    /usr/lib/dracut /usr/lib/rustd; do
    [ -d "$directory" ] || continue
    find "$directory" -mindepth 1 -maxdepth 1 -type f \
        -exec /usr/bin/setfiles -F "$contexts" {} + || exit 1
done

for path in /init /shutdown; do
    [ -e "$path" ] || continue
    /usr/bin/setfiles -F "$contexts" "$path" || exit 1
done
