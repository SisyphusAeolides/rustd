/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Wrappers around the Linux reboot(2) system call.
 *
 * Upstream reference: src/core/reboot-util.c (v261)
 */

/* syscall(2) requires _GNU_SOURCE or _XOPEN_SOURCE >= 500 */
#define _GNU_SOURCE

#include "kexec.h"

#include <errno.h>
#include <sys/syscall.h>
#include <sys/reboot.h>
#include <unistd.h>

/*
 * Linux reboot(2) magic values from <linux/reboot.h>.
 * We define them locally to avoid a kernel-headers dependency.
 */
#define RUSTD_LINUX_REBOOT_MAGIC1   0xfee1dead
#define RUSTD_LINUX_REBOOT_MAGIC2   672274793U
#define RUSTD_LINUX_REBOOT_CMD_RESTART   0x01234567U
#define RUSTD_LINUX_REBOOT_CMD_HALT      0xcdef0123U
#define RUSTD_LINUX_REBOOT_CMD_POWER_OFF 0x4321fedcU
#define RUSTD_LINUX_REBOOT_CMD_KEXEC     0x45584543U

int rustd_sys_reboot(unsigned int cmd) {
    int r = (int)syscall(SYS_reboot,
                         (int)RUSTD_LINUX_REBOOT_MAGIC1,
                         (int)RUSTD_LINUX_REBOOT_MAGIC2,
                         cmd,
                         (void *)0);
    if (r < 0)
        return -errno;
    return 0;
}

int rustd_reboot(void) {
    return rustd_sys_reboot(RUSTD_LINUX_REBOOT_CMD_RESTART);
}

int rustd_poweroff(void) {
    return rustd_sys_reboot(RUSTD_LINUX_REBOOT_CMD_POWER_OFF);
}

int rustd_halt(void) {
    return rustd_sys_reboot(RUSTD_LINUX_REBOOT_CMD_HALT);
}

int rustd_kexec(void) {
    return rustd_sys_reboot(RUSTD_LINUX_REBOOT_CMD_KEXEC);
}
