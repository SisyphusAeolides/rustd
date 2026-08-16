/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
#include "notify.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define NOTIFY_MAX_FDS 253U

static volatile sig_atomic_t pending_forward_signal = 0;

static void remember_forward_signal(int signal_number) {
    pending_forward_signal = signal_number;
}

static int notify_address(const char *path, struct sockaddr_un *address, socklen_t *length) {
    size_t n;

    if (!path || !address || !length)
        return -EINVAL;
    n = strlen(path);
    if (path[0] == '@') {
        if (n > sizeof(address->sun_path))
            return -ENAMETOOLONG;
        memset(address, 0, sizeof(*address));
        address->sun_family = AF_UNIX;
        memcpy(address->sun_path + 1, path + 1, n - 1U);
        *length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + n);
        return 0;
    }
    if (path[0] != '/')
        return -EPROTO;
    if (n <= 1U)
        return -EINVAL;
    if (n >= sizeof(address->sun_path))
        return -ENAMETOOLONG;
    memset(address, 0, sizeof(*address));
    address->sun_family = AF_UNIX;
    memcpy(address->sun_path, path, n + 1U);
    *length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + n + 1U);
    return 0;
}

int rustd_notify_send(pid_t pid, const char *state, const int *fds, size_t n_fds) {
    const char *path;
    struct sockaddr_un address;
    struct iovec iov;
    struct msghdr message;
    struct cmsghdr *cmsg;
    struct ucred credentials;
    char control[CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(sizeof(int) * NOTIFY_MAX_FDS)];
    socklen_t address_length;
    bool send_credentials;
    int fd, result;
    ssize_t sent;

    if (!state || (n_fds > 0U && !fds))
        return -EINVAL;
    if (n_fds > NOTIFY_MAX_FDS)
        return -E2BIG;
    path = getenv("NOTIFY_SOCKET");
    if (!path)
        return 0;
    result = notify_address(path, &address, &address_length);
    if (result < 0)
        return result;
    fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -errno;

    if (pid <= 0)
        pid = getpid();
    send_credentials = pid != getpid() || getuid() != geteuid() || getgid() != getegid();
    credentials.pid = pid;
    credentials.uid = getuid();
    credentials.gid = getgid();

    memset(&iov, 0, sizeof(iov));
    iov.iov_base = (void *)state;
    iov.iov_len = strlen(state);
    memset(&message, 0, sizeof(message));
    message.msg_name = &address;
    message.msg_namelen = address_length;
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen =
            (n_fds > 0U ? CMSG_SPACE(sizeof(int) * n_fds) : 0U) +
            (send_credentials ? CMSG_SPACE(sizeof(credentials)) : 0U);
    memset(control, 0, sizeof(control));

    cmsg = CMSG_FIRSTHDR(&message);
    if (n_fds > 0U) {
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int) * n_fds);
        memcpy(CMSG_DATA(cmsg), fds, sizeof(int) * n_fds);
        if (send_credentials)
            cmsg = CMSG_NXTHDR(&message, cmsg);
    }
    if (send_credentials) {
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_CREDENTIALS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(credentials));
        memcpy(CMSG_DATA(cmsg), &credentials, sizeof(credentials));
    }
    if (message.msg_controllen == 0U)
        message.msg_control = NULL;

    sent = sendmsg(fd, &message, MSG_NOSIGNAL);
    if (sent < 0 && send_credentials) {
        message.msg_controllen -= CMSG_SPACE(sizeof(credentials));
        if (message.msg_controllen == 0U)
            message.msg_control = NULL;
        sent = sendmsg(fd, &message, MSG_NOSIGNAL);
    }
    if (sent < 0)
        result = -errno;
    else if ((size_t)sent != iov.iov_len)
        result = -EIO;
    else
        result = 1;
    (void)close(fd);
    return result;
}

int rustd_notify_barrier(pid_t pid, uint64_t timeout_usec) {
    struct pollfd poll_fd;
    struct timespec timeout;
    int pipes[2] = {-1, -1};
    int result;

    if (pipe2(pipes, O_CLOEXEC) < 0)
        return -errno;
    result = rustd_notify_send(pid, "BARRIER=1", &pipes[1], 1U);
    if (result <= 0)
        goto finish;
    (void)close(pipes[1]);
    pipes[1] = -1;
    memset(&poll_fd, 0, sizeof(poll_fd));
    poll_fd.fd = pipes[0];
    timeout.tv_sec = (time_t)(timeout_usec / UINT64_C(1000000));
    timeout.tv_nsec = (long)((timeout_usec % UINT64_C(1000000)) * UINT64_C(1000));
    result = ppoll(&poll_fd, 1, &timeout, NULL);
    if (result < 0)
        result = -errno;
    else if (result == 0)
        result = -ETIMEDOUT;
    else
        result = 1;
finish:
    if (pipes[0] >= 0)
        (void)close(pipes[0]);
    if (pipes[1] >= 0)
        (void)close(pipes[1]);
    return result;
}

int rustd_notify_enable_passcred(int fd) {
    int enabled = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled)) < 0)
        return -errno;
    return 0;
}

int rustd_notify_autobind(char *address, size_t capacity) {
    struct sockaddr_un socket_address;
    socklen_t length;
    size_t name_length;
    int fd, result;

    if (!address || capacity < 2U)
        return -EINVAL;
    fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -errno;
    memset(&socket_address, 0, sizeof(socket_address));
    socket_address.sun_family = AF_UNIX;
    if (bind(fd, (const struct sockaddr *)&socket_address, offsetof(struct sockaddr_un, sun_path)) < 0) {
        result = -errno;
        (void)close(fd);
        return result;
    }
    length = sizeof(socket_address);
    if (getsockname(fd, (struct sockaddr *)&socket_address, &length) < 0) {
        result = -errno;
        (void)close(fd);
        return result;
    }
    if (length <= offsetof(struct sockaddr_un, sun_path) + 1U || socket_address.sun_path[0] != '\0') {
        (void)close(fd);
        return -EPROTO;
    }
    name_length = (size_t)length - offsetof(struct sockaddr_un, sun_path) - 1U;
    if (name_length + 2U > capacity) {
        (void)close(fd);
        return -ENOBUFS;
    }
    address[0] = '@';
    memcpy(address + 1, socket_address.sun_path + 1, name_length);
    address[name_length + 1U] = '\0';
    return fd;
}

int rustd_notify_recv(
        int fd,
        char *buffer,
        size_t capacity,
        pid_t *pid,
        uid_t *uid,
        gid_t *gid,
        int *fds,
        size_t fd_capacity,
        size_t *n_fds) {
    struct iovec iov;
    struct msghdr message;
    struct cmsghdr *cmsg;
    char control[CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(sizeof(int) * NOTIFY_MAX_FDS)];
    ssize_t received;

    if (fd < 0 || !buffer || capacity == 0U || !n_fds || (fd_capacity > 0U && !fds))
        return -EINVAL;
    memset(&iov, 0, sizeof(iov));
    iov.iov_base = buffer;
    iov.iov_len = capacity;
    memset(&message, 0, sizeof(message));
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof(control);
    memset(control, 0, sizeof(control));
    received = recvmsg(fd, &message, MSG_CMSG_CLOEXEC);
    if (received < 0)
        return -errno;
    if ((message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0)
        return -E2BIG;

    *n_fds = 0U;
    if (pid)
        *pid = 0;
    if (uid)
        *uid = (uid_t)-1;
    if (gid)
        *gid = (gid_t)-1;
    for (cmsg = CMSG_FIRSTHDR(&message); cmsg; cmsg = CMSG_NXTHDR(&message, cmsg)) {
        if (cmsg->cmsg_level != SOL_SOCKET)
            continue;
        if (cmsg->cmsg_type == SCM_CREDENTIALS && cmsg->cmsg_len >= CMSG_LEN(sizeof(struct ucred))) {
            const struct ucred *credentials = (const struct ucred *)CMSG_DATA(cmsg);
            if (pid)
                *pid = credentials->pid;
            if (uid)
                *uid = credentials->uid;
            if (gid)
                *gid = credentials->gid;
        } else if (cmsg->cmsg_type == SCM_RIGHTS) {
            size_t count = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
            const int *received_fds = (const int *)CMSG_DATA(cmsg);
            size_t index;
            if (count > fd_capacity) {
                for (index = 0; index < count; index++)
                    (void)close(received_fds[index]);
                return -E2BIG;
            }
            memcpy(fds, received_fds, count * sizeof(int));
            *n_fds = count;
        }
    }
    return received > INT_MAX ? -E2BIG : (int)received;
}

int rustd_pidfd_inode_id(pid_t pid, uint64_t *inode_id) {
#if defined(SYS_pidfd_open)
    struct stat metadata;
    int pidfd;
    if (pid <= 0 || !inode_id)
        return -EINVAL;
    pidfd = (int)syscall(SYS_pidfd_open, pid, 0U);
    if (pidfd < 0)
        return -errno;
    if (fstat(pidfd, &metadata) < 0) {
        int result = -errno;
        (void)close(pidfd);
        return result;
    }
    (void)close(pidfd);
    *inode_id = (uint64_t)metadata.st_ino;
    return 0;
#else
    (void)pid;
    (void)inode_id;
    return -ENOSYS;
#endif
}

int rustd_set_notify_gid(gid_t gid) {
    if (setregid(gid, (gid_t)-1) < 0)
        return -errno;
    return 0;
}

int rustd_set_notify_uid(uid_t uid) {
    if (setreuid(uid, (uid_t)-1) < 0)
        return -errno;
    return 0;
}

int rustd_dup_cloexec(int fd) {
    int copy = fcntl(fd, F_DUPFD_CLOEXEC, 3);
    return copy < 0 ? -errno : copy;
}

uint64_t rustd_monotonic_usec(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
        return 0U;
    return (uint64_t)now.tv_sec * UINT64_C(1000000) + (uint64_t)now.tv_nsec / UINT64_C(1000);
}

int rustd_notify_install_forward_signals(void) {
    static const int signals[] = {
        SIGHUP, SIGTERM, SIGINT, SIGQUIT, SIGTSTP, SIGCONT, SIGUSR1, SIGUSR2
    };
    struct sigaction action;
    size_t index;

    memset(&action, 0, sizeof(action));
    action.sa_handler = remember_forward_signal;
    sigemptyset(&action.sa_mask);
    for (index = 0U; index < sizeof(signals) / sizeof(signals[0]); index++)
        if (sigaction(signals[index], &action, NULL) < 0)
            return -errno;
    return 0;
}

int rustd_notify_forward_pending(pid_t child) {
    int signal_number = pending_forward_signal;
    if (signal_number == 0)
        return 0;
    pending_forward_signal = 0;
    if (kill(child, signal_number) < 0)
        return -errno;
    return signal_number;
}
