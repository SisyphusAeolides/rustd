#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later

# RustD loads SELinux after switch_root, when the installed root filesystem's
# labels are available. Fedora's cpio initramfs is a ramfs and cannot carry
# security.selinux xattrs, so there is no safe pre-pivot relabel operation.
# Keep this file as a compatibility placeholder for older package layouts; it
# is intentionally not installed as a dracut hook.

exit 0
