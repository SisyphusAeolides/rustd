/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Public RustD service lifecycle helpers. Uses RUSTD_NOTIFY_SOCKET and
 * RUSTD_LISTEN_* only. Never provides libsystemd SONAMEs or sd_* symbols. */

unsigned rustd_service_abi_version(void);

int rustd_notify_ready(void);
int rustd_notify_stopping(void);
int rustd_notify_watchdog(void);
int rustd_notify_status(const char *status);
int rustd_watchdog_enabled(int unset_environment, uint64_t *usec);

int rustd_listen_fds(int unset_environment);
int rustd_is_socket(int fd, int family, int type, int listening);

uid_t rustd_current_uid(void);
int rustd_peer_uid(int fd, uid_t *uid_out);
int rustd_peer_pid(int fd, pid_t *pid_out);

int rustd_notify_send(pid_t pid, const char *state, const int *fds, size_t n_fds);
int rustd_notify_barrier(pid_t pid, uint64_t timeout_usec);

#ifdef __cplusplus
}
#endif
