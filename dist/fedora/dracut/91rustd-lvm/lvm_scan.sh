#!/usr/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later

# Source dracut's stock scanner while providing the one early-userspace
# compatibility change RustD needs: lvchange/vgchange must not wait for a
# systemd-udev device-mapper cookie. The stock scanner still owns all LVM
# discovery, filtering, retry, and activation policy.

# LVM is a command multiplexer and uses argv[0] to select its command-line
# personality.  Invoke the preserved /usr/bin/lvm path so version, config,
# lvs, vgscan, and activation dispatch normally; calling the identical ELF
# through its lvm.real storage path makes it reject every subcommand.
rustd_lvm=/usr/bin/lvm

# Fedora's stock scanner normally receives one marker from 64-lvm.rules for
# each LVM2 PV. Keep the wrapper self-sufficient when early coldplug was
# performed through RustD's reduced rule engine and that RUN action was not
# delivered.
for sysdev in /sys/class/block/*; do
    test -e "$sysdev/dev" || continue
    node=/dev/${sysdev##*/}
    lvm_type=$(blkid -p -o value -s TYPE "$node" 2>/dev/null) || lvm_type=
    test "$lvm_type" = LVM2_member || continue
    : > "/tmp/.lvm_scan-${sysdev##*/}"
done

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
