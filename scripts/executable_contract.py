#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Native executable naming, build, and installation contract for RustD."""

from __future__ import annotations

NATIVE_EXECUTABLES = frozenset(
    {
        "rustd",
        "rustbootctl",
        "rustbusctl",
        "rustcoredumpctl",
        "rustctl",
        "rustd-ac-power",
        "rustd-analyze",
        "rustd-ask-password",
        "rustd-backlight",
        "rustd-battery-check",
        "rustd-bless-boot",
        "rustd-bless-boot-generator",
        "rustd-binfmt",
        "rustd-boot-check-no-failures",
        "rustd-cat",
        "rustd-cgls",
        "rustd-cgtop",
        "rustd-confext",
        "rustd-creds",
        "rustd-cryptenroll",
        "rustd-cryptsetup",
        "rustd-delta",
        "rustd-detect-virt",
        "rustd-debug-generator",
        "rustd-getty-generator",
        "rustd-dissect",
        "rustd-escape",
        "rustd-firstboot",
        "rustd-factory-reset-generator",
        "rustd-fstab-generator",
        "rustd-fsck",
        "rustd-home-fallback-shell",
        "rustd-hostnamed",
        "rustd-hwdb",
        "rustd-id128",
        "rustd-inhibit",
        "rustd-journald",
        "rustd-localed",
        "rustd-logind",
        "rustd-machine-id-setup",
        "rustd-modules-load",
        "rustd-mount",
        "rustd-mstack",
        "rustd-mute-console",
        "rustd-notify",
        "rustd-nspawn",
        "rustd-path",
        "rustd-pty-forward",
        "rustd-quotacheck",
        "rustd-random-seed",
        "rustd-repart",
        "rustd-repart.standalone",
        "rustd-remount-fs",
        "rustd-reply-password",
        "rustd-resolve",
        "rustd-rfkill",
        "rustd-run-generator",
        "rustd-run",
        "rustd-socket-activate",
        "rustd-socket-proxyd",
        "rustd-ssh-issue",
        "rustd-stdio-bridge",
        "rustd-sulogin-shell",
        "rustd-sysext",
        "rustd-sysctl",
        "rustd-sysinstall",
        "rustd-system-update-generator",
        "rustd-sysupdate",
        "rustd-sysusers",
        "rustd-sysusers.standalone",
        "rustd-time-wait-sync",
        "rustd-tmpfiles",
        "rustd-tmpfiles.standalone",
        "rustd-tty-ask-password-agent",
        "rustd-umount",
        "rustd-update-done",
        "rustd-update-utmp",
        "rustd-udevd",
        "rustd-user-sessions",
        "rustd-volatile-root",
        "rustd-vconsole-setup",
        "rustd-vmspawn",
        "rustd-vpick",
        "rustd-xdg-autostart-condition",
        "rusthomectl",
        "rusthostnamectl",
        "rustimportctl",
        "rustinstallkernel",
        "rustjournalctl",
        "rustkernel-install",
        "rustlocalectl",
        "rustloginctl",
        "rustmachinectl",
        "rustmount-ddi",
        "rustmount-mstack",
        "rustmount-storage",
        "rustmount_ddi",
        "rustmount_mstack",
        "rustmount_storage",
        "rustnetworkctl",
        "rustoomctl",
        "rustportablectl",
        "rustresolvectl",
        "rustrun0",
        "ruststoragectl",
        "rusttimedatectl",
        "rustudevadm",
        "rustupdatectl",
        "rustuserdbctl",
        "rustvarlinkctl",
    }
)

# Dotted standalone filenames are install surfaces, not valid Rust crate target
# names. They reuse the corresponding native RustD executable object code.
NATIVE_BUILD_ALIASES = {
    "rustd-repart.standalone": "rustd-repart",
    "rustd-sysusers.standalone": "rustd-sysusers",
    "rustd-tmpfiles.standalone": "rustd-tmpfiles",
}
NATIVE_BUILD_EXECUTABLES = frozenset(NATIVE_EXECUTABLES - NATIVE_BUILD_ALIASES.keys())

NATIVE_GENERATORS = frozenset(
    {
        "rustd-bless-boot-generator",
        "rustd-debug-generator",
        "rustd-factory-reset-generator",
        "rustd-fstab-generator",
        "rustd-getty-generator",
        "rustd-run-generator",
        "rustd-system-update-generator",
    }
)

NATIVE_LIBEXEC = frozenset(
    {
        "rustd",
        "rustd-backlight",
        "rustd-battery-check",
        "rustd-bless-boot",
        "rustd-bless-boot-generator",
        "rustd-binfmt",
        "rustd-debug-generator",
        "rustd-factory-reset-generator",
        "rustd-fstab-generator",
        "rustd-getty-generator",
        "rustd-boot-check-no-failures",
        "rustd-fsck",
        "rustd-hostnamed",
        "rustd-journald",
        "rustd-localed",
        "rustd-logind",
        "rustd-modules-load",
        "rustd-quotacheck",
        "rustd-random-seed",
        "rustd-remount-fs",
        "rustd-reply-password",
        "rustd-rfkill",
        "rustd-run-generator",
        "rustd-socket-proxyd",
        "rustd-ssh-issue",
        "rustd-sulogin-shell",
        "rustd-sysctl",
        "rustd-system-update-generator",
        "rustd-time-wait-sync",
        "rustd-update-done",
        "rustd-update-utmp",
        "rustd-udevd",
        "rustd-user-sessions",
        "rustd-volatile-root",
        "rustd-vconsole-setup",
        "rustd-xdg-autostart-condition",
    }
)

EXPECTED_EXECUTABLE_COUNT = len(NATIVE_EXECUTABLES)
EXPECTED_BUILD_EXECUTABLE_COUNT = len(NATIVE_BUILD_EXECUTABLES)
FORBIDDEN_COMPATIBILITY_EXECUTABLES = frozenset(
    {
        "systemctl",
        "journalctl",
        "udevadm",
        "loginctl",
        "hostnamectl",
        "localectl",
        "timedatectl",
        "networkctl",
        "busctl",
        "run0",
    }
)

assert len(NATIVE_EXECUTABLES) == 110
assert EXPECTED_EXECUTABLE_COUNT == 110
assert len(NATIVE_BUILD_EXECUTABLES) == 107
assert EXPECTED_BUILD_EXECUTABLE_COUNT == 107
assert NATIVE_LIBEXEC <= NATIVE_EXECUTABLES
assert NATIVE_GENERATORS <= NATIVE_LIBEXEC
assert NATIVE_EXECUTABLES.isdisjoint(FORBIDDEN_COMPATIBILITY_EXECUTABLES)
assert all("systemd" not in name for name in NATIVE_EXECUTABLES)
