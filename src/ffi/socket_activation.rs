// SPDX-License-Identifier: LGPL-2.1-or-later
//! FFI bindings for `ffi/socket_activation.c`.
//!
//! Upstream reference: `src/core/socket.c socket_open_fds()` (v261)

use libc::c_int;

extern "C" {
    /// Create, bind, and listen on an `AF_UNIX SOCK_STREAM` socket at `path`.
    /// Returns the fd on success, -errno on failure.
    pub fn rustd_socket_listen_stream(path: *const libc::c_char, backlog: c_int) -> c_int;

    /// Create and bind an `AF_UNIX SOCK_DGRAM` socket at `path`.
    /// Returns the fd on success, -errno on failure.
    pub fn rustd_socket_listen_datagram(path: *const libc::c_char) -> c_int;

    /// Create, bind, and listen on an `AF_UNIX SOCK_SEQPACKET` socket at `path`.
    /// Returns the fd on success, -errno on failure.
    pub fn rustd_socket_listen_seqpacket(path: *const libc::c_char, backlog: c_int) -> c_int;

    /// Create, bind, and listen on a dual-stack `SOCK_STREAM` socket on `port`.
    /// Returns the fd on success, -errno on failure.
    pub fn rustd_socket_listen_inet_stream(port: *const libc::c_char, backlog: c_int) -> c_int;

    /// Create and bind a dual-stack `SOCK_DGRAM` socket on `port`.
    /// Returns the fd on success, -errno on failure.
    pub fn rustd_socket_listen_inet_datagram(port: *const libc::c_char) -> c_int;

    /// Set `SO_PASSCRED` on `fd`.
    /// Returns 0 on success, -errno on failure.
    pub fn rustd_socket_set_passcred(fd: c_int, enable: c_int) -> c_int;

    /// Set `SO_RCVBUF` on `fd`.
    /// Returns 0 on success, -errno on failure.
    pub fn rustd_socket_set_rcvbuf(fd: c_int, sz: c_int) -> c_int;

    /// Set `SO_SNDBUF` on `fd`.
    /// Returns 0 on success, -errno on failure.
    pub fn rustd_socket_set_sndbuf(fd: c_int, sz: c_int) -> c_int;
}
