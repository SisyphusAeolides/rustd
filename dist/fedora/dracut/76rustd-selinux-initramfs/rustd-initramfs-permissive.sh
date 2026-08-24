#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later

# Fedora's cpio initramfs cannot carry security.selinux xattrs.  Keep the
# kernel permissive until dracut loads the installed policy at pre-pivot 50;
# RustD PID 1 applies the configured enforcing mode after switch-root.
if getarg "selinux=0" > /dev/null || getarg "enforcing=0" > /dev/null; then
    exit 0
fi

/usr/sbin/setenforce 0 || exit 1
