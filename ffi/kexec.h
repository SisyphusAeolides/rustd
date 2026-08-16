/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/*
 * Wrappers around Linux reboot(2) and kexec_load(2).
 *
 * Upstream reference: src/core/reboot-util.c,
 *                     src/shared/reboot-util.h  (v261)
 */

/*
 * rustd_sys_reboot - invoke reboot(2) with the given magic constant.
 *
 * Suitable magic values (from <linux/reboot.h>):
 *   LINUX_REBOOT_CMD_RESTART   0x01234567
 *   LINUX_REBOOT_CMD_HALT      0xcdef0123
 *   LINUX_REBOOT_CMD_POWER_OFF 0x4321fedc
 *   LINUX_REBOOT_CMD_KEXEC     0x45584543
 *
 * Returns 0 on success, -errno on failure.
 */
int rustd_sys_reboot(unsigned int cmd);

/*
 * rustd_reboot  - trigger a clean system reboot.
 * rustd_poweroff - trigger a clean system poweroff.
 * rustd_halt    - trigger a clean system halt.
 * rustd_kexec   - jump into a pre-loaded kexec kernel.
 *
 * All return 0 on success, -errno on failure.
 * On success the call does not return.
 */
int rustd_reboot(void);
int rustd_poweroff(void);
int rustd_halt(void);
int rustd_kexec(void);
