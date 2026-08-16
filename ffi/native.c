/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
#include "native.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1U << 0)
#endif

#define RUSTD_LISTEN_FDS_START 3

static int parse_u64_decimal(const char *text, uint64_t *value_out) {
    if (!text || !*text || !value_out)
        return -EINVAL;

    uint64_t value = 0;
    for (const unsigned char *cursor = (const unsigned char *)text; *cursor; cursor++) {
        if (*cursor < '0' || *cursor > '9')
            return -EINVAL;
        const uint64_t digit = (uint64_t)(*cursor - '0');
        if (value > (UINT64_MAX - digit) / 10U)
            return -ERANGE;
        value = value * 10U + digit;
    }

    *value_out = value;
    return 0;
}

static int parse_pid_decimal(const char *text, pid_t *pid_out) {
    uint64_t value = 0;
    int result = parse_u64_decimal(text, &value);
    if (result < 0)
        return result;
    if (value == 0 || value > (uint64_t)INT_MAX)
        return -EINVAL;

    *pid_out = (pid_t)value;
    return 0;
}

static int own_pidfd_inode_id(uint64_t *inode_out) {
    if (!inode_out)
        return -EINVAL;

#if defined(SYS_pidfd_open)
    const int pidfd = (int)syscall(SYS_pidfd_open, getpid(), 0U);
    if (pidfd < 0)
        return -errno;

    struct stat stat_buffer;
    if (fstat(pidfd, &stat_buffer) < 0) {
        const int saved_errno = errno;
        (void)close(pidfd);
        return -saved_errno;
    }
    (void)close(pidfd);
    *inode_out = (uint64_t)stat_buffer.st_ino;
    return 0;
#else
    return -ENOSYS;
#endif
}

static void unset_listen_environment(int unset_environment) {
    if (!unset_environment)
        return;

    (void)unsetenv("LISTEN_PID");
    (void)unsetenv("LISTEN_PIDFDID");
    (void)unsetenv("LISTEN_FDS");
    (void)unsetenv("LISTEN_FDNAMES");
}

static void unset_watchdog_environment(int unset_environment) {
    if (!unset_environment)
        return;

    (void)unsetenv("WATCHDOG_USEC");
    (void)unsetenv("WATCHDOG_PID");
}

static int notify_address(
        const char *socket_path,
        struct sockaddr_un *address,
        socklen_t *address_length) {
    if (!socket_path || !*socket_path || !address || !address_length)
        return -EINVAL;

    const size_t path_length = strlen(socket_path);
    memset(address, 0, sizeof(*address));
    address->sun_family = AF_UNIX;

    if (socket_path[0] == '@') {
        if (path_length > sizeof(address->sun_path))
            return -ENAMETOOLONG;

        address->sun_path[0] = '\0';
        memcpy(address->sun_path + 1, socket_path + 1, path_length - 1);
        *address_length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + path_length);
        return 0;
    }

    if (socket_path[0] != '/')
        return -EINVAL;
    if (path_length >= sizeof(address->sun_path))
        return -ENAMETOOLONG;

    memcpy(address->sun_path, socket_path, path_length + 1);
    *address_length =
        (socklen_t)(offsetof(struct sockaddr_un, sun_path) + path_length + 1);
    return 0;
}

static int notify_message(const char *message) {
    if (!message)
        return -EINVAL;

    const char *socket_path = getenv("NOTIFY_SOCKET");
    if (!socket_path)
        return 0;

    struct sockaddr_un address;
    socklen_t address_length = 0;
    int result = notify_address(socket_path, &address, &address_length);
    if (result < 0)
        return result;

    const int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -errno;

    const size_t message_length = strlen(message);
    const ssize_t sent = sendto(
        fd,
        message,
        message_length,
        MSG_NOSIGNAL,
        (const struct sockaddr *)&address,
        address_length);
    const int saved_errno = errno;
    (void)close(fd);

    if (sent < 0)
        return -saved_errno;
    if ((size_t)sent != message_length)
        return -EIO;
    return 1;
}

int rustd_install_signal_handlers(void) {
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    sigemptyset(&action.sa_mask);

    static const int signals[] = {
        SIGTERM, SIGINT, SIGHUP, SIGCHLD, SIGUSR1, SIGUSR2, SIGPIPE
    };
    for (size_t index = 0; index < sizeof(signals) / sizeof(signals[0]); index++) {
        if (sigaction(signals[index], &action, NULL) < 0)
            return -errno;
    }
    return 0;
}

int rustd_notify_ready(void) {
    return notify_message("READY=1\n");
}

int rustd_notify_stopping(void) {
    return notify_message("STOPPING=1\n");
}

int rustd_notify_watchdog(void) {
    return notify_message("WATCHDOG=1\n");
}

int rustd_watchdog_enabled(int unset_environment, uint64_t *usec) {
    const char *watchdog_usec = getenv("WATCHDOG_USEC");
    int result = 0;

    if (!watchdog_usec)
        goto finish;

    uint64_t parsed_usec = 0;
    result = parse_u64_decimal(watchdog_usec, &parsed_usec);
    if (result < 0)
        goto finish;
    if (parsed_usec == 0) {
        result = -EINVAL;
        goto finish;
    }

    const char *watchdog_pid = getenv("WATCHDOG_PID");
    if (watchdog_pid) {
        pid_t parsed_pid = 0;
        result = parse_pid_decimal(watchdog_pid, &parsed_pid);
        if (result < 0)
            goto finish;
        if (parsed_pid != getpid()) {
            result = 0;
            goto finish;
        }
    }

    if (usec)
        *usec = parsed_usec;
    result = 1;

finish:
    unset_watchdog_environment(unset_environment);
    return result;
}

uid_t rustd_current_uid(void) {
    return getuid();
}

int rustd_peer_uid(int fd, uid_t *uid_out) {
    if (fd < 0)
        return -EBADF;
    if (!uid_out)
        return -EINVAL;

    struct ucred credentials;
    socklen_t length = sizeof(credentials);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &length) < 0)
        return -errno;
    if (length != sizeof(credentials))
        return -EIO;

    *uid_out = credentials.uid;
    return 0;
}

int rustd_peer_pid(int fd, pid_t *pid_out) {
    if (fd < 0)
        return -EBADF;
    if (!pid_out)
        return -EINVAL;

    struct ucred credentials;
    socklen_t length = sizeof(credentials);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &length) < 0)
        return -errno;
    if (length != sizeof(credentials))
        return -EIO;

    *pid_out = credentials.pid;
    return 0;
}

int rustd_listen_fds(int unset_environment) {
    const char *listen_pid = getenv("LISTEN_PID");
    int result = 0;

    if (!listen_pid)
        goto finish;

    pid_t parsed_pid = 0;
    result = parse_pid_decimal(listen_pid, &parsed_pid);
    if (result < 0)
        goto finish;
    if (parsed_pid != getpid()) {
        result = 0;
        goto finish;
    }

    const char *listen_pidfd_id = getenv("LISTEN_PIDFDID");
    if (listen_pidfd_id) {
        uint64_t expected_inode = 0;
        result = parse_u64_decimal(listen_pidfd_id, &expected_inode);
        if (result < 0)
            goto finish;

        uint64_t own_inode = 0;
        if (own_pidfd_inode_id(&own_inode) >= 0 && own_inode != expected_inode) {
            result = 0;
            goto finish;
        }
    }

    const char *listen_fds = getenv("LISTEN_FDS");
    if (!listen_fds) {
        result = 0;
        goto finish;
    }

    uint64_t parsed_fds = 0;
    result = parse_u64_decimal(listen_fds, &parsed_fds);
    if (result < 0)
        goto finish;
    if (parsed_fds == 0 || parsed_fds > (uint64_t)(INT_MAX - RUSTD_LISTEN_FDS_START)) {
        result = -EINVAL;
        goto finish;
    }

    const int descriptor_count = (int)parsed_fds;
    for (int fd = RUSTD_LISTEN_FDS_START;
         fd < RUSTD_LISTEN_FDS_START + descriptor_count;
         fd++) {
        const int flags = fcntl(fd, F_GETFD);
        if (flags < 0) {
            result = -errno;
            goto finish;
        }
        if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0) {
            result = -errno;
            goto finish;
        }
    }

    result = descriptor_count;

finish:
    unset_listen_environment(unset_environment);
    return result;
}

int rustd_is_socket(int fd, int family, int type, int listening) {
    if (fd < 0)
        return -EBADF;
    if (family < 0 || type < 0)
        return -EINVAL;

    struct stat descriptor_stat;
    if (fstat(fd, &descriptor_stat) < 0)
        return -errno;
    if (!S_ISSOCK(descriptor_stat.st_mode))
        return 0;

    if (type != 0) {
        int actual_type = 0;
        socklen_t actual_type_length = sizeof(actual_type);
        if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &actual_type, &actual_type_length) < 0)
            return -errno;
        if (actual_type_length != sizeof(actual_type))
            return -EIO;
        if (actual_type != type)
            return 0;
    }

    if (listening >= 0) {
        int accepting = 0;
        socklen_t accepting_length = sizeof(accepting);
        if (getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &accepting, &accepting_length) < 0)
            return -errno;
        if (accepting_length != sizeof(accepting))
            return -EIO;
        if ((accepting != 0) != (listening != 0))
            return 0;
    }

    if (family > 0) {
        struct sockaddr_storage address;
        socklen_t address_length = sizeof(address);
        memset(&address, 0, sizeof(address));
        if (getsockname(fd, (struct sockaddr *)&address, &address_length) < 0)
            return -errno;
        if (address_length < sizeof(sa_family_t))
            return -EINVAL;
        if (((const struct sockaddr *)&address)->sa_family != family)
            return 0;
    }

    return 1;
}

static int rename_noreplace_fallback(const char *from, const char *to) {
    if (link(from, to) < 0)
        return -errno;

    if (unlink(from) < 0) {
        const int saved_errno = errno;
        (void)unlink(to);
        return -saved_errno;
    }

    return 0;
}

int rustd_rename_noreplace(const char *from, const char *to) {
    if (!from || !*from || !to || !*to)
        return -EINVAL;

#if defined(SYS_renameat2)
    if (syscall(SYS_renameat2, AT_FDCWD, from, AT_FDCWD, to, RENAME_NOREPLACE) == 0)
        return 0;
    if (errno != ENOSYS && errno != EINVAL)
        return -errno;
#endif

    return rename_noreplace_fallback(from, to);
}
