/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

int rustd_notify_send(pid_t pid, const char *state, const int *fds, size_t n_fds);
int rustd_notify_barrier(pid_t pid, uint64_t timeout_usec);
int rustd_notify_enable_passcred(int fd);
int rustd_notify_autobind(char *address, size_t capacity);
int rustd_notify_recv(
        int fd,
        char *buffer,
        size_t capacity,
        pid_t *pid,
        uid_t *uid,
        gid_t *gid,
        int *fds,
        size_t fd_capacity,
        size_t *n_fds);
int rustd_pidfd_inode_id(pid_t pid, uint64_t *inode_id);
int rustd_set_notify_gid(gid_t gid);
int rustd_set_notify_uid(uid_t uid);
int rustd_dup_cloexec(int fd);
uint64_t rustd_monotonic_usec(void);
int rustd_notify_install_forward_signals(void);
int rustd_notify_forward_pending(pid_t child);
