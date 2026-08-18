/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>

/*
 * sandbox.h — in-child security sandbox helpers.
 *
 * All functions are intended to be called in a fresh single-threaded helper
 * before execve(). They mirror the sandboxing logic in upstream
 * src/core/execute.c exec_child() and src/core/execute-security.c (v261).
 */

/* ── NoNewPrivileges ─────────────────────────────────────────────────────── */

int rustd_sandbox_no_new_privs(void);

/* ── Mount-namespace sandboxing ──────────────────────────────────────────── */

/*
 * Isolate the mount tree and apply ProtectSystem=/ProtectHome=.
 * Returns 0 on success, -errno on failure.
 */
int rustd_sandbox_mount_namespaces(int private_tmp,
                                int private_devices,
                                int private_network,
                                int protect_system,
                                int protect_home,
                                int force_mount_namespace);

/*
 * Re-open explicitly declared ReadWritePaths= inside the private mount tree.
 * Each entry must be absolute. A leading '-' means a missing path is ignored.
 * The helper calls this only after ProtectSystem= has made the base tree
 * read-only, so these bind mounts are narrow writable exceptions rather than
 * changes to the host mount namespace.
 *
 * Returns 0 on success, -errno on failure.
 */
int rustd_sandbox_make_writable_paths(const char *const *paths, size_t n_paths);

/* ── Read-only path protection ───────────────────────────────────────────── */

int rustd_sandbox_protect_paths(int protect_kernel_tunables,
                             int protect_kernel_modules,
                             int protect_kernel_logs,
                             int protect_clock,
                             int protect_control_groups,
                             int restrict_suid_sgid);

/* ── Real-time scheduling restriction ───────────────────────────────────── */

int rustd_sandbox_restrict_realtime(void);
