/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/*
 * sandbox.h — in-child security sandbox helpers.
 *
 * All functions are intended to be called after fork() and before execve(),
 * in the single-threaded child context.  They mirror the sandboxing logic in
 * upstream src/core/execute.c exec_child() and
 * src/core/execute-security.c (v261).
 */

/* ── NoNewPrivileges ─────────────────────────────────────────────────────── */

/*
 * rustd_sandbox_no_new_privs: set PR_SET_NO_NEW_PRIVS so the child (and all its
 * descendants) can never gain new privileges through setuid/setcap binaries.
 *
 * Returns 0 on success, -errno on failure.
 */
int rustd_sandbox_no_new_privs(void);

/* ── Mount-namespace sandboxing ──────────────────────────────────────────── */

/*
 * rustd_sandbox_mount_namespaces: isolate the mount tree.
 *
 *   private_tmp      — mount private tmpfs over /tmp and /var/tmp
 *   private_devices  — mount a minimal read-only /dev in the new namespace
 *   private_network  — unshare the network namespace (empty loopback only)
 *   protect_system   — 0=no, 1=yes (/usr ro), 2=full (+/boot ro), 3=strict
 *   protect_home     — 0=no, 1=yes (inaccessible), 2=read-only, 3=tmpfs
 *
 * Requires CAP_SYS_ADMIN or unprivileged user namespaces
 * (kernel.unprivileged_userns_clone=1).  Failures are non-fatal at the
 * caller's discretion (match upstream tolerance).
 *
 * Returns 0 on success, -errno on failure.
 */
int rustd_sandbox_mount_namespaces(int private_tmp,
                                int private_devices,
                                int private_network,
                                int protect_system,
                                int protect_home,
                                int force_mount_namespace);

/* ── Read-only path protection ───────────────────────────────────────────── */

/*
 * rustd_sandbox_protect_paths: bind-mount sensitive paths read-only.
 *
 *   protect_kernel_tunables — /proc/sys, /sys read-only
 *   protect_kernel_modules  — /lib/modules, /usr/lib/modules read-only,
 *                             /proc/modules read-only
 *   protect_kernel_logs     — mask /dev/kmsg
 *   protect_clock           — mask common RTC devices
 *   restrict_suid_sgid      — remount /dev with nosuid, /tmp with nosuid
 *
 * Must be called after rustd_sandbox_mount_namespaces when a mount namespace
 * has been established.  Safe to call without a namespace (effect is
 * process-wide bind-mount, requires CAP_SYS_ADMIN).
 *
 * Returns 0 on success, -errno on failure.
 */
int rustd_sandbox_protect_paths(int protect_kernel_tunables,
                             int protect_kernel_modules,
                             int protect_kernel_logs,
                             int protect_clock,
                             int protect_control_groups,
                             int restrict_suid_sgid);

/* ── Real-time scheduling restriction ───────────────────────────────────── */

/*
 * rustd_sandbox_restrict_realtime: prevent the process from using real-time
 * scheduling policies (SCHED_FIFO, SCHED_RR).
 *
 * Uses seccomp(2) to block sched_setscheduler(2) calls that would set a
 * real-time policy, matching upstream RestrictRealtime= behaviour.
 * Falls back gracefully if seccomp is unavailable.
 *
 * Returns 0 on success, -errno on failure.
 */
int rustd_sandbox_restrict_realtime(void);
