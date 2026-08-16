// SPDX-License-Identifier: LGPL-2.1-or-later
//! Raw FFI declarations for ffi/event.c.
//!
//! All `extern "C"` items here correspond 1-for-1 to declarations in
//! `ffi/event.h`.  No logic lives here — only types and `extern` blocks.
//! All calls are `unsafe`; safe wrappers live in `src/event/`.

/// Corresponds to `rustd_epoll_event` in ffi/event.h.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SdEpollEvent {
    pub events: u32,
    pub token: u64,
}

/// Corresponds to `rustd_child_info` in ffi/event.h.
#[repr(C)]
pub struct SdChildInfo {
    pub pid: libc::pid_t,
    pub code: libc::c_int,
    pub status: libc::c_int,
}

#[link(name = "rustd_native", kind = "static")]
extern "C" {
    // epoll
    pub fn rustd_epoll_create1() -> libc::c_int;
    pub fn rustd_epoll_add_fd(
        epfd: libc::c_int,
        fd: libc::c_int,
        events: u32,
        token: u64,
    ) -> libc::c_int;
    pub fn rustd_epoll_mod_fd(
        epfd: libc::c_int,
        fd: libc::c_int,
        events: u32,
        token: u64,
    ) -> libc::c_int;
    pub fn rustd_epoll_del_fd(epfd: libc::c_int, fd: libc::c_int) -> libc::c_int;
    pub fn rustd_epoll_wait(
        epfd: libc::c_int,
        events_out: *mut SdEpollEvent,
        max_events: libc::c_int,
        timeout_ms: libc::c_int,
    ) -> libc::c_int;

    // signalfd
    pub fn rustd_signalfd_create() -> libc::c_int;
    pub fn rustd_signalfd_read(sfd: libc::c_int, signo: *mut libc::c_int) -> libc::c_int;

    // timerfd
    pub fn rustd_timerfd_create(clockid: libc::c_int) -> libc::c_int;
    pub fn rustd_timerfd_settime(
        tfd: libc::c_int,
        flags: libc::c_int,
        value_sec: i64,
        value_nsec: i64,
        interval_sec: i64,
        interval_nsec: i64,
    ) -> libc::c_int;
    pub fn rustd_timerfd_disarm(tfd: libc::c_int) -> libc::c_int;
    pub fn rustd_timerfd_read(tfd: libc::c_int) -> i64;

    // inotify
    pub fn rustd_inotify_create1() -> libc::c_int;
    pub fn rustd_inotify_add_watch(
        ifd: libc::c_int,
        path: *const libc::c_char,
        mask: u32,
    ) -> libc::c_int;
    pub fn rustd_inotify_rm_watch(ifd: libc::c_int, wd: libc::c_int) -> libc::c_int;

    // eventfd
    pub fn rustd_eventfd_create() -> libc::c_int;
    pub fn rustd_eventfd_write(efd: libc::c_int, val: u64) -> libc::c_int;
    pub fn rustd_eventfd_read(efd: libc::c_int) -> i64;

    // child / waitid
    pub fn rustd_child_reap(info: *mut SdChildInfo) -> libc::c_int;

    // clock
    pub fn rustd_clock_now_nsec(clockid: libc::c_int) -> i64;
}
