/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
/*
 * socket_activation.c — listener socket creation helpers.
 *
 * Upstream reference: src/core/socket.c socket_open_fds() (v261)
 */

#include "socket_activation.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

/* ── helpers ─────────────────────────────────────────────────────────────── */

/*
 * clear_cloexec: remove O_CLOEXEC from fd so it survives exec.
 * Listener fds must not be close-on-exec so the activated service inherits
 * them via RUSTD_LISTEN_FDS.
 */
static int clear_cloexec(int fd) {
    int flags = fcntl(fd, F_GETFD);
    if (flags < 0)
        return -errno;
    if (!(flags & FD_CLOEXEC))
        return 0;
    if (fcntl(fd, F_SETFD, flags & ~FD_CLOEXEC) < 0)
        return -errno;
    return 0;
}

/*
 * set_reuseaddr: set SO_REUSEADDR on fd.
 */
static int set_reuseaddr(int fd) {
    int v = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v)) < 0)
        return -errno;
    return 0;
}

/*
 * remove_stale_socket: if a unix socket path already exists and is not
 * connected, remove it so we can re-bind.  Best effort.
 */
static void remove_stale_socket(const char *path) {
    struct stat st;
    if (stat(path, &st) < 0)
        return;
    if (S_ISSOCK(st.st_mode))
        (void)unlink(path);
}

/* ── AF_UNIX helpers ─────────────────────────────────────────────────────── */

static int unix_bind(int type, const char *path) {
    remove_stale_socket(path);

    int fd = socket(AF_UNIX, type | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -errno;

    (void)set_reuseaddr(fd);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(addr.sun_path)) {
        close(fd);
        return -ENAMETOOLONG;
    }
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        int e = errno;
        close(fd);
        return -e;
    }

    /* Remove O_CLOEXEC so the fd survives exec into the service. */
    if (clear_cloexec(fd) < 0) {
        int e = errno;
        close(fd);
        return -e;
    }

    return fd;
}

/* ── rustd_socket_listen_stream ─────────────────────────────────────────────── */

int rustd_socket_listen_stream(const char *path, int backlog) {
    int fd = unix_bind(SOCK_STREAM, path);
    if (fd < 0)
        return fd;

    if (listen(fd, backlog > 0 ? backlog : 128) < 0) {
        int e = errno;
        close(fd);
        return -e;
    }
    return fd;
}

/* ── rustd_socket_listen_datagram ───────────────────────────────────────────── */

int rustd_socket_listen_datagram(const char *path) {
    return unix_bind(SOCK_DGRAM, path);
}

/* ── rustd_socket_listen_seqpacket ──────────────────────────────────────────── */

int rustd_socket_listen_seqpacket(const char *path, int backlog) {
    int fd = unix_bind(SOCK_SEQPACKET, path);
    if (fd < 0)
        return fd;

    if (listen(fd, backlog > 0 ? backlog : 128) < 0) {
        int e = errno;
        close(fd);
        return -e;
    }
    return fd;
}

/* ── rustd_socket_listen_inet_stream ────────────────────────────────────────── */

int rustd_socket_listen_inet_stream(const char *port, int backlog) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_PASSIVE | AI_NUMERICSERV;

    struct addrinfo *res = NULL;
    int rc = getaddrinfo(NULL, port, &hints, &res);
    if (rc != 0) {
        /* Fall back to IPv4 only. */
        hints.ai_family = AF_INET;
        rc = getaddrinfo(NULL, port, &hints, &res);
        if (rc != 0)
            return -EINVAL;
    }

    int fd = socket(res->ai_family, res->ai_socktype | SOCK_CLOEXEC, res->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(res);
        return -errno;
    }

    (void)set_reuseaddr(fd);

    /* Enable dual-stack for IPv6 sockets. */
    if (res->ai_family == AF_INET6) {
        int v = 0;
        (void)setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v, sizeof(v));
    }

    if (bind(fd, res->ai_addr, res->ai_addrlen) < 0) {
        int e = errno;
        freeaddrinfo(res);
        close(fd);
        return -e;
    }
    freeaddrinfo(res);

    if (listen(fd, backlog > 0 ? backlog : 128) < 0) {
        int e = errno;
        close(fd);
        return -e;
    }

    if (clear_cloexec(fd) < 0) {
        int e = errno;
        close(fd);
        return -e;
    }

    return fd;
}

/* ── rustd_socket_listen_inet_datagram ──────────────────────────────────────── */

int rustd_socket_listen_inet_datagram(const char *port) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET6;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags    = AI_PASSIVE | AI_NUMERICSERV;

    struct addrinfo *res = NULL;
    int rc = getaddrinfo(NULL, port, &hints, &res);
    if (rc != 0) {
        hints.ai_family = AF_INET;
        rc = getaddrinfo(NULL, port, &hints, &res);
        if (rc != 0)
            return -EINVAL;
    }

    int fd = socket(res->ai_family, res->ai_socktype | SOCK_CLOEXEC, res->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(res);
        return -errno;
    }

    (void)set_reuseaddr(fd);

    if (bind(fd, res->ai_addr, res->ai_addrlen) < 0) {
        int e = errno;
        freeaddrinfo(res);
        close(fd);
        return -e;
    }
    freeaddrinfo(res);

    if (clear_cloexec(fd) < 0) {
        int e = errno;
        close(fd);
        return -e;
    }

    return fd;
}

/* ── socket option helpers ───────────────────────────────────────────────── */

int rustd_socket_set_passcred(int fd, int enable) {
    if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &enable, sizeof(enable)) < 0)
        return -errno;
    return 0;
}

int rustd_socket_set_rcvbuf(int fd, int sz) {
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz)) < 0)
        return -errno;
    return 0;
}

int rustd_socket_set_sndbuf(int fd, int sz) {
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz)) < 0)
        return -errno;
    return 0;
}
