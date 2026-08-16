// SPDX-License-Identifier: LGPL-2.1-or-later
//! Raw bindings for RustD's private native helper ABI.
//!
//! Upstream reference: `src/libsystemd/sd-daemon/sd-daemon.c` (v261)

#[allow(missing_docs)]
#[link(name = "rustd_native", kind = "static")]
extern "C" {
    /// Restore the default dispositions for signals managed by the service manager.
    pub fn rustd_install_signal_handlers() -> libc::c_int;

    /// Send `READY=1` to `NOTIFY_SOCKET`.
    pub fn rustd_notify_ready() -> libc::c_int;
    /// Send `STOPPING=1` to `NOTIFY_SOCKET`.
    pub fn rustd_notify_stopping() -> libc::c_int;
    /// Send `WATCHDOG=1` to `NOTIFY_SOCKET`.
    pub fn rustd_notify_watchdog() -> libc::c_int;
    /// Parse `WATCHDOG_USEC` and `WATCHDOG_PID`.
    pub fn rustd_watchdog_enabled(unset_environment: libc::c_int, usec: *mut u64) -> libc::c_int;

    /// Return the real UID of the manager process.
    pub fn rustd_current_uid() -> libc::uid_t;
    /// Read the peer UID from an `AF_UNIX` socket.
    pub fn rustd_peer_uid(fd: libc::c_int, uid_out: *mut libc::uid_t) -> libc::c_int;
    /// Read the peer PID from an `AF_UNIX` socket.
    pub fn rustd_peer_pid(fd: libc::c_int, pid_out: *mut libc::pid_t) -> libc::c_int;

    /// Return the number of socket-activation descriptors inherited at fd 3.
    pub fn rustd_listen_fds(unset_environment: libc::c_int) -> libc::c_int;
    /// Test whether a descriptor is a socket with the requested properties.
    pub fn rustd_is_socket(
        fd: libc::c_int,
        family: libc::c_int,
        socket_type: libc::c_int,
        listening: libc::c_int,
    ) -> libc::c_int;

    /// Atomically rename a filesystem object without replacing an existing destination.
    pub fn rustd_rename_noreplace(
        from: *const libc::c_char,
        to: *const libc::c_char,
    ) -> libc::c_int;
}
