// SPDX-License-Identifier: LGPL-2.1-or-later
//! Native signal and socket credential helpers for `systemd-mute-console`.

extern "C" {
    pub fn rustd_mute_console_install_signals() -> libc::c_int;
    pub fn rustd_mute_console_termination_requested() -> libc::c_int;
    pub fn rustd_mute_console_peer_uid(fd: libc::c_int, ret_uid: *mut libc::uid_t) -> libc::c_int;
    pub fn rustd_mute_console_socket_accepts(fd: libc::c_int) -> libc::c_int;
    pub fn rustd_mute_console_uid() -> libc::uid_t;
}
