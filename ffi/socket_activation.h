/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/*
 * socket_activation.h — listener socket creation helpers.
 *
 * Each function creates, binds, and starts listening on one socket.
 * All returned file descriptors are blocking, have SO_REUSEADDR set, and
 * have the close-on-exec flag cleared so they can be inherited across exec.
 *
 * Upstream reference: src/core/socket.c socket_open_fds() (v261)
 */

/*
 * rustd_socket_listen_stream: create an AF_UNIX SOCK_STREAM socket bound to
 * path and call listen(2).
 *
 * Returns the fd on success, -errno on failure.
 */
int rustd_socket_listen_stream(const char *path, int backlog);

/*
 * rustd_socket_listen_datagram: create an AF_UNIX SOCK_DGRAM socket bound to
 * path.  No listen(2) call is made (connectionless).
 *
 * Returns the fd on success, -errno on failure.
 */
int rustd_socket_listen_datagram(const char *path);

/*
 * rustd_socket_listen_seqpacket: create an AF_UNIX SOCK_SEQPACKET socket bound
 * to path and call listen(2).
 *
 * Returns the fd on success, -errno on failure.
 */
int rustd_socket_listen_seqpacket(const char *path, int backlog);

/*
 * rustd_socket_listen_inet_stream: create an AF_INET6 (dual-stack) SOCK_STREAM
 * socket bound to port and call listen(2).  Falls back to AF_INET if IPv6 is
 * unavailable.
 *
 * port — decimal port number string, e.g. "80".
 * Returns the fd on success, -errno on failure.
 */
int rustd_socket_listen_inet_stream(const char *port, int backlog);

/*
 * rustd_socket_listen_inet_datagram: create an AF_INET6 (dual-stack) SOCK_DGRAM
 * socket bound to port.
 *
 * Returns the fd on success, -errno on failure.
 */
int rustd_socket_listen_inet_datagram(const char *port);

/*
 * rustd_socket_set_passcred: set SO_PASSCRED on fd (pass credentials with
 * each recvmsg(2)).  Returns 0 on success, -errno on failure.
 */
int rustd_socket_set_passcred(int fd, int enable);

/*
 * rustd_socket_set_rcvbuf: set SO_RCVBUF to sz bytes.
 * Returns 0 on success, -errno on failure.
 */
int rustd_socket_set_rcvbuf(int fd, int sz);

/*
 * rustd_socket_set_sndbuf: set SO_SNDBUF to sz bytes.
 * Returns 0 on success, -errno on failure.
 */
int rustd_socket_set_sndbuf(int fd, int sz);
