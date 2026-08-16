/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>
#include <stdint.h>

/*
 * seccomp.h — hand-coded BPF seccomp filter helpers.
 *
 * All functions install seccomp(2) BPF filters into the calling process.
 * They are designed to be called in the child process after fork(), before
 * execve(), in the same position as upstream's seccomp_restrict_*() family
 * from src/shared/seccomp-util.c (v261).
 *
 * Return values: 0 on success, -errno on failure.
 * Non-fatal kernels that do not support seccomp return 0.
 */

/*
 * rustd_seccomp_memory_deny_write_execute:
 *   Block mmap(2) when PROT_WRITE|PROT_EXEC are both requested, and
 *   block mprotect(2) when PROT_EXEC is requested.
 *   Implements MemoryDenyWriteExecute=yes.
 */
int rustd_seccomp_memory_deny_write_execute(void);

/*
 * rustd_seccomp_restrict_namespaces:
 *   Block unshare(2) and clone(2) calls that would create any namespace
 *   type whose bit is NOT set in allowed_mask.  allowed_mask=0 blocks all
 *   namespace creation.  Implements RestrictNamespaces=.
 */
int rustd_seccomp_restrict_namespaces(uint64_t allowed_mask);

/* Block kernel log access through syslog(2). Implements ProtectKernelLogs=. */
int rustd_seccomp_protect_kernel_logs(void);

/* Block syscalls that modify wall/realtime clocks. Implements ProtectClock=. */
int rustd_seccomp_protect_clock(void);

typedef struct {
    int nr;
    uint32_t action;
} rustd_seccomp_rule;

/* Resolve a syscall name for the native architecture through libseccomp. */
int rustd_seccomp_syscall_resolve_name(const char *name, int *ret_nr);

/* Return 1 if a native syscall number is known to libseccomp, 0 if not. */
int rustd_seccomp_syscall_is_known(int nr);

/* Allow only the native syscall architecture. */
int rustd_seccomp_restrict_native_architecture(void);

/* Install per-syscall actions with a default action. */
int rustd_seccomp_syscall_rules(const rustd_seccomp_rule *rules,
                             size_t n_rules,
                             uint32_t default_action);

/*
 * rustd_seccomp_syscall_filter:
 *   Install a syscall allow-list or deny-list BPF filter.
 *   Exactly one of allow_list or deny_list must be non-NULL.
 *   Syscall names are matched against a built-in table.
 *   error_number is the errno to return for blocked calls (e.g. EPERM).
 */
int rustd_seccomp_syscall_filter(const char *const *allow_list,
                               const char *const *deny_list,
                               int error_number);
