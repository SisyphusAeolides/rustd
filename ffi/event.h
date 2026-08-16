/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/*
 * event.h — event loop ABI declarations.
 *
 * All epoll/signalfd/timerfd/inotify/waitid syscalls are confined to
 * ffi/event.c.  Rust calls these through src/event/loop_.rs via the
 * safe wrappers declared here.  RustD keeps these Linux kernel interfaces behind its private native event ABI.
 *
 * Upstream reference: src/libsystemd/sd-event/sd-event.c (v261)
 */

#include <signal.h>
#include <stdint.h>
#include <sys/types.h>

/* ── epoll ─────────────────────────────────────────────────────────────── */

/*
 * rustd_epoll_create1: create a cloexec epoll fd.
 * Returns fd on success, -errno on failure.
 */
int rustd_epoll_create1(void);

/*
 * rustd_epoll_add_fd: add fd to the epoll set with given events (EPOLLIN etc.)
 * and a u64 token used to identify the source in dispatch.
 * Returns 0 on success, -errno on failure.
 */
int rustd_epoll_add_fd(int epfd, int fd, uint32_t events, uint64_t token);

/*
 * rustd_epoll_mod_fd: modify the event mask for an already-registered fd.
 * Returns 0 on success, -errno on failure.
 */
int rustd_epoll_mod_fd(int epfd, int fd, uint32_t events, uint64_t token);

/*
 * rustd_epoll_del_fd: remove fd from the epoll set.
 * Returns 0 on success, -errno on failure.
 */
int rustd_epoll_del_fd(int epfd, int fd);

/*
 * rustd_epoll_wait: wait for events.
 * events_out must point to a buffer of at least max_events rustd_epoll_event structs.
 * Returns number of ready events (≥0) or -errno.
 */
typedef struct {
    uint32_t events;
    uint64_t token;
} rustd_epoll_event;

int rustd_epoll_wait(int epfd, rustd_epoll_event *events_out, int max_events,
                  int timeout_ms);

/* ── signalfd ───────────────────────────────────────────────────────────── */

/*
 * rustd_signalfd_create: block all signals in the calling thread and create a
 * cloexec signalfd for the full set.  This is the PID 1 signal setup:
 * signals are not delivered asynchronously but are read from the fd in the
 * epoll loop.
 * Returns fd on success, -errno on failure.
 *
 * Upstream reference: src/core/main.c: install_signal_handlers()
 */
int rustd_signalfd_create(void);

/*
 * rustd_signalfd_read: read one pending signal from a signalfd.
 * Fills *signo on success.
 * Returns 0 on success, -errno on failure, -EAGAIN if no signal pending.
 */
int rustd_signalfd_read(int sfd, int *signo);

/* ── timerfd ────────────────────────────────────────────────────────────── */

/*
 * Clock IDs matching CLOCK_REALTIME / CLOCK_MONOTONIC / CLOCK_BOOTTIME.
 * These values are the Linux kernel constants.
 */
#define RUSTD_CLOCK_REALTIME  0
#define RUSTD_CLOCK_MONOTONIC 1
#define RUSTD_CLOCK_BOOTTIME  7

/*
 * rustd_timerfd_create: create a cloexec, non-blocking timerfd for the given
 * clock.
 * Returns fd on success, -errno on failure.
 */
int rustd_timerfd_create(int clockid);

/*
 * rustd_timerfd_settime: arm the timerfd.
 * value_sec / value_nsec: first expiry (absolute if RUSTD_TIMER_ABSTIME, else
 *   relative).
 * interval_sec / interval_nsec: repeat interval (0 = one-shot).
 * Returns 0 on success, -errno on failure.
 */
#define RUSTD_TIMER_ABSTIME 1
int rustd_timerfd_settime(int tfd, int flags,
                       int64_t value_sec, int64_t value_nsec,
                       int64_t interval_sec, int64_t interval_nsec);

/*
 * rustd_timerfd_disarm: cancel a timerfd (set both value and interval to zero).
 * Returns 0 on success, -errno on failure.
 */
int rustd_timerfd_disarm(int tfd);

/*
 * rustd_timerfd_read: drain a timerfd after it fires.
 * Returns number of expirations, or -errno.
 */
int64_t rustd_timerfd_read(int tfd);

/* ── inotify ────────────────────────────────────────────────────────────── */

/*
 * rustd_inotify_create1: create a cloexec, non-blocking inotify fd.
 * Returns fd on success, -errno on failure.
 */
int rustd_inotify_create1(void);

/*
 * rustd_inotify_add_watch: add a path watch.
 * mask: combination of IN_* constants (IN_CREATE, IN_DELETE, IN_MODIFY, …).
 * Returns watch descriptor (≥0) on success, -errno on failure.
 */
int rustd_inotify_add_watch(int ifd, const char *path, uint32_t mask);

/*
 * rustd_inotify_rm_watch: remove a watch by descriptor.
 * Returns 0 on success, -errno on failure.
 */
int rustd_inotify_rm_watch(int ifd, int wd);

/* ── eventfd ────────────────────────────────────────────────────────────── */

/*
 * rustd_eventfd_create: create a cloexec, non-blocking eventfd (semaphore mode).
 * Returns fd on success, -errno on failure.
 */
int rustd_eventfd_create(void);

/*
 * rustd_eventfd_write: increment the counter by val.
 * Returns 0 on success, -errno on failure.
 */
int rustd_eventfd_write(int efd, uint64_t val);

/*
 * rustd_eventfd_read: read (and clear) the counter.
 * Returns counter value on success, -errno on failure.
 */
int64_t rustd_eventfd_read(int efd);

/* ── child / waitid ─────────────────────────────────────────────────────── */

/*
 * Child exit status record filled by rustd_child_reap.
 */
typedef struct {
    pid_t  pid;
    int    code;     /* CLD_EXITED, CLD_KILLED, CLD_DUMPED */
    int    status;   /* exit code or signal number */
} rustd_child_info;

/*
 * rustd_child_reap: reap one child non-blockingly using waitid(WNOHANG).
 * Fills *info and returns 0 on success, -ECHILD if no children,
 * -EAGAIN if no child has exited yet, -errno on error.
 */
int rustd_child_reap(rustd_child_info *info);

/*
 * rustd_clock_now_nsec: return current time in nanoseconds for the given clockid.
 * Returns nanoseconds on success, -errno on failure.
 */
int64_t rustd_clock_now_nsec(int clockid);
