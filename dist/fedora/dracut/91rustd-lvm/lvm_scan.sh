#!/usr/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later

# Source dracut's stock scanner while providing the one early-userspace
# compatibility change RustD needs: lvchange/vgchange must not wait for a
# systemd-udev device-mapper cookie. The stock scanner still owns all LVM
# discovery, filtering, retry, and activation policy.

rustd_lvm=/usr/lib/rustd/initrd/lvm.real

lvm() {
    case "${1:-}" in
        lvchange|vgchange)
            subcommand=$1
            shift
            command "$rustd_lvm" "$subcommand" --noudevsync "$@"
            ;;
        *)
            command "$rustd_lvm" "$@"
            ;;
    esac
}

. /usr/lib/rustd/initrd/lvm_scan.stock
