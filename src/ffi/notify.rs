// SPDX-License-Identifier: LGPL-2.1-or-later
//! Narrow native boundary for Linux notification ancillary data.

#[allow(missing_docs)]
#[link(name = "rustd_native", kind = "static")]
extern "C" {
    pub fn rustd_notify_send(
        pid: libc::pid_t,
        state: *const libc::c_char,
        fds: *const libc::c_int,
        n_fds: usize,
    ) -> libc::c_int;
    pub fn rustd_notify_barrier(pid: libc::pid_t, timeout_usec: u64) -> libc::c_int;
    pub fn rustd_notify_enable_passcred(fd: libc::c_int) -> libc::c_int;
    pub fn rustd_notify_autobind(address: *mut libc::c_char, capacity: usize) -> libc::c_int;
    pub fn rustd_notify_recv(
        fd: libc::c_int,
        buffer: *mut libc::c_char,
        capacity: usize,
        pid: *mut libc::pid_t,
        uid: *mut libc::uid_t,
        gid: *mut libc::gid_t,
        fds: *mut libc::c_int,
        fd_capacity: usize,
        n_fds: *mut usize,
    ) -> libc::c_int;
    pub fn rustd_pidfd_inode_id(pid: libc::pid_t, inode_id: *mut u64) -> libc::c_int;
    pub fn rustd_set_notify_gid(gid: libc::gid_t) -> libc::c_int;
    pub fn rustd_set_notify_uid(uid: libc::uid_t) -> libc::c_int;
    pub fn rustd_dup_cloexec(fd: libc::c_int) -> libc::c_int;
    pub fn rustd_monotonic_usec() -> u64;
    pub fn rustd_notify_install_forward_signals() -> libc::c_int;
    pub fn rustd_notify_forward_pending(child: libc::pid_t) -> libc::c_int;
}
