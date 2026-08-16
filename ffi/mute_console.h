/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

int rustd_mute_console_install_signals(void);
int rustd_mute_console_termination_requested(void);
int rustd_mute_console_peer_uid(int fd, uid_t *ret_uid);
int rustd_mute_console_socket_accepts(int fd);
uid_t rustd_mute_console_uid(void);
