/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdint.h>
#include <sys/types.h>

/* Signal handling */
int rustd_install_signal_handlers(void);

/* systemd-notify / sd-daemon ABI */
int rustd_notify_ready(void);
int rustd_notify_stopping(void);
int rustd_notify_watchdog(void);
int rustd_watchdog_enabled(int unset_environment, uint64_t *usec);

/* Process and peer credentials */
uid_t rustd_current_uid(void);
int rustd_peer_uid(int fd, uid_t *uid_out);
int rustd_peer_pid(int fd, pid_t *pid_out);

/* Inherited descriptor helpers */
int rustd_listen_fds(int unset_environment);
int rustd_is_socket(int fd, int family, int type, int listening);

/* Filesystem operations that require Linux-specific atomic semantics. */
int rustd_rename_noreplace(const char *from, const char *to);
