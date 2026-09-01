#!/usr/bin/env bash
set -Eeuo pipefail

bin=${RUSTD_KERNEL_INSTALL_BIN:-target/release/rustkernel-install}
test -x "$bin"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
root=$work/root
machine_id=0123456789abcdef0123456789abcdef
version=7.2.0-test
mkdir -p "$root/etc/default" "$root/boot"
printf '%s\n' "$machine_id" > "$root/etc/machine-id"
printf '%s\n' 'NAME="Test Linux"' 'ID=testlinux' > "$root/etc/os-release"
printf '%s\n' 'UUID=11111111-2222-3333-4444-555555555555 / ext4 defaults 1 1' \
    > "$root/etc/fstab"
printf '%s\n' 'GRUB_CMDLINE_LINUX="rd.lvm.lv=test/root console=ttyS0,115200n8"' \
    > "$root/etc/default/grub"
printf '%s\n' 'kernel image' > "$work/vmlinuz"
printf '%s\n' 'initramfs image' > "$work/initramfs.img"

"$bin" --root "$root" --boot-path "$root/boot" add \
    "$version" "$work/vmlinuz" "$work/initramfs.img"

entry="$root/boot/loader/entries/$machine_id-$version.conf"
entry_dir="$root/boot/$machine_id/$version"
test -s "$entry"
test -s "$entry_dir/linux"
test -s "$entry_dir/initrd"
grep -Fxq 'linux      /0123456789abcdef0123456789abcdef/7.2.0-test/linux' "$entry"
grep -Fxq 'initrd     /0123456789abcdef0123456789abcdef/7.2.0-test/initrd' "$entry"
grep -Fxq 'options    root=UUID=11111111-2222-3333-4444-555555555555 rd.lvm.lv=test/root console=ttyS0,115200n8 ro' "$entry"

"$bin" --root "$root" --boot-path "$root/boot" --no-legend list | grep -Fq "$version"
"$bin" --root "$root" --boot-path "$root/boot" remove "$version"
test ! -e "$entry"
test ! -e "$entry_dir"

plugin="$root/usr/lib/kernel/install.d/99-test-plugin"
plugin_marker="$root/plugin-marker"
mkdir -p "$(dirname "$plugin")"
{
    printf '%s\n' '#!/bin/sh'
    printf 'printf "%%s\\n" invoked > %q\n' "$plugin_marker"
} > "$plugin"
chmod 0755 "$plugin"

skip_version=7.2.0-skip-plugins-test
"$bin" --root "$root" --boot-path "$root/boot" --skip-plugins add \
    "$skip_version" "$work/vmlinuz" "$work/initramfs.img"
skip_entry="$root/boot/loader/entries/$machine_id-$skip_version.conf"
skip_entry_dir="$root/boot/$machine_id/$skip_version"
test -s "$skip_entry"
test -s "$skip_entry_dir/linux"
test -s "$skip_entry_dir/initrd"
test ! -e "$plugin_marker"
"$bin" --root "$root" --boot-path "$root/boot" --skip-plugins remove \
    "$skip_version"
test ! -e "$skip_entry"
test ! -e "$skip_entry_dir"

plugin_version=7.2.0-plugin-test
"$bin" --root "$root" --boot-path "$root/boot" add \
    "$plugin_version" "$work/vmlinuz" "$work/initramfs.img"
plugin_entry="$root/boot/loader/entries/$machine_id-$plugin_version.conf"
plugin_entry_dir="$root/boot/$machine_id/$plugin_version"
test -s "$plugin_entry"
test -s "$plugin_entry_dir/linux"
test -s "$plugin_entry_dir/initrd"
test -s "$plugin_marker"
"$bin" --root "$root" --boot-path "$root/boot" remove "$plugin_version"
test ! -e "$plugin_entry"
test ! -e "$plugin_entry_dir"

mkdir -p "$root/boot/efi/EFI"
esp_version=7.2.0-esp-test
"$bin" --root "$root" add \
    "$esp_version" "$work/vmlinuz" "$work/initramfs.img"
esp_entry="$root/boot/loader/entries/$machine_id-$esp_version.conf"
esp_entry_dir="$root/boot/$machine_id/$esp_version"
test -s "$esp_entry"
test -s "$esp_entry_dir/linux"
test -s "$esp_entry_dir/initrd"
test ! -e "$root/boot/efi/$machine_id/$esp_version/linux"
"$bin" --root "$root" remove "$esp_version"
test ! -e "$esp_entry"
test ! -e "$esp_entry_dir"

printf '%s\n' 'kernel-install compatibility test passed'
