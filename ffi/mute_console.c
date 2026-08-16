/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE

#include "mute_console.h"

#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>

static volatile sig_atomic_t terminate_requested = 0;

static void request_termination(int signal_number) {
    (void)signal_number;
    terminate_requested = 1;
}

int rustd_mute_console_install_signals(void) {
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_handler = request_termination;
    sigemptyset(&action.sa_mask);
    terminate_requested = 0;
    if (sigaction(SIGINT, &action, NULL) < 0)
        return -errno;
    if (sigaction(SIGTERM, &action, NULL) < 0)
        return -errno;
    return 0;
}

int rustd_mute_console_termination_requested(void) {
    return terminate_requested != 0;
}

int rustd_mute_console_peer_uid(int fd, uid_t *ret_uid) {
    struct ucred credential;
    socklen_t length = sizeof(credential);

    if (!ret_uid)
        return -EINVAL;
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credential, &length) < 0)
        return -errno;
    if (length != sizeof(credential))
        return -EPROTO;
    *ret_uid = credential.uid;
    return 0;
}

int rustd_mute_console_socket_accepts(int fd) {
    int value;
    socklen_t length = sizeof(value);

    if (getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &value, &length) < 0)
        return -errno;
    if (length != sizeof(value))
        return -EPROTO;
    return value != 0;
}

uid_t rustd_mute_console_uid(void) {
    return getuid();
}
