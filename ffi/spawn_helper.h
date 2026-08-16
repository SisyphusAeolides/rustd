/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/*
 * spawn_helper.h — child side of rustd_spawn().
 *
 * rustd_spawn_helper_main() runs in a fresh image created by posix_spawn(),
 * never in a forked copy of the manager, so it may use the full C library
 * while it applies the pending request.  It reads the sealed request from
 * RUSTD_SPAWN_REQUEST_FD, performs cgroup, namespace, MAC, rlimit, credential,
 * capability, seccomp and environment setup, and execs the service.  It never
 * returns: failures are reported on RUSTD_SPAWN_ERROR_FD and through the exit
 * status.
 */
_Noreturn void rustd_spawn_helper_main(void);
