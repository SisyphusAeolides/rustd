/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
/*
 * event.c — event loop syscall wrappers.
 *
 * All epoll/signalfd/timerfd/inotify/waitid calls live here.
 * Rust touches these only through the typed declarations in event.h.
 *
 * Upstream reference: src/libsystemd/sd-event/sd-event.c (v261)
 *                     src/core/main.c install_signal_handlers()
 */

#include "event.h"

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* ── epoll ─────────────────────────────────────────────────────────────── */

int rustd_epoll_create1(void) {
    int fd = epoll_create1(EPOLL_CLOEXEC);
    return fd < 0 ? -errno : fd;
}

int rustd_epoll_add_fd(int epfd, int fd, uint32_t events, uint64_t token) {
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events   = events;
    ev.data.u64 = token;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0)
        return -errno;
    return 0;
}

int rustd_epoll_mod_fd(int epfd, int fd, uint32_t events, uint64_t token) {
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events   = events;
    ev.data.u64 = token;
    if (epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev) < 0)
        return -errno;
    return 0;
}

int rustd_epoll_del_fd(int epfd, int fd) {
    if (epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL) < 0)
        return -errno;
    return 0;
}

int rustd_epoll_wait(int epfd, rustd_epoll_event *events_out, int max_events,
                  int timeout_ms) {
    /* Translate our thin rustd_epoll_event into struct epoll_event inline. */
    struct epoll_event evs[256];
    if (max_events > 256)
        max_events = 256;

    int n;
    do {
        n = epoll_wait(epfd, evs, max_events, timeout_ms);
    } while (n < 0 && errno == EINTR);

    if (n < 0)
        return -errno;

    for (int i = 0; i < n; i++) {
        events_out[i].events = evs[i].events;
        events_out[i].token  = evs[i].data.u64;
    }
    return n;
}

/* ── signalfd ───────────────────────────────────────────────────────────── */

int rustd_signalfd_create(void) {
    sigset_t mask;
    sigfillset(&mask);

    /* Block all signals so they are delivered only via the signalfd. */
    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0)
        return -errno;

    int fd = signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK);
    return fd < 0 ? -errno : fd;
}

int rustd_signalfd_read(int sfd, int *signo) {
    struct signalfd_siginfo ssi;
    ssize_t n = read(sfd, &ssi, sizeof(ssi));
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return -EAGAIN;
        return -errno;
    }
    *signo = (int)ssi.ssi_signo;
    return 0;
}

/* ── timerfd ────────────────────────────────────────────────────────────── */

int rustd_timerfd_create(int clockid) {
    int fd = timerfd_create(clockid, TFD_CLOEXEC | TFD_NONBLOCK);
    return fd < 0 ? -errno : fd;
}

int rustd_timerfd_settime(int tfd, int flags,
                       int64_t value_sec, int64_t value_nsec,
                       int64_t interval_sec, int64_t interval_nsec) {
    struct itimerspec its;
    its.it_value.tv_sec     = (time_t)value_sec;
    its.it_value.tv_nsec    = (long)value_nsec;
    its.it_interval.tv_sec  = (time_t)interval_sec;
    its.it_interval.tv_nsec = (long)interval_nsec;

    int tfd_flags = (flags & RUSTD_TIMER_ABSTIME) ? TFD_TIMER_ABSTIME : 0;
    if (timerfd_settime(tfd, tfd_flags, &its, NULL) < 0)
        return -errno;
    return 0;
}

int rustd_timerfd_disarm(int tfd) {
    return rustd_timerfd_settime(tfd, 0, 0, 0, 0, 0);
}

int64_t rustd_timerfd_read(int tfd) {
    uint64_t expirations;
    ssize_t n = read(tfd, &expirations, sizeof(expirations));
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;
        return -errno;
    }
    return (int64_t)expirations;
}

/* ── inotify ────────────────────────────────────────────────────────────── */

int rustd_inotify_create1(void) {
    int fd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
    return fd < 0 ? -errno : fd;
}

int rustd_inotify_add_watch(int ifd, const char *path, uint32_t mask) {
    int wd = inotify_add_watch(ifd, path, mask);
    return wd < 0 ? -errno : wd;
}

int rustd_inotify_rm_watch(int ifd, int wd) {
    if (inotify_rm_watch(ifd, wd) < 0)
        return -errno;
    return 0;
}

/* ── eventfd ────────────────────────────────────────────────────────────── */

int rustd_eventfd_create(void) {
    int fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK | EFD_SEMAPHORE);
    return fd < 0 ? -errno : fd;
}

int rustd_eventfd_write(int efd, uint64_t val) {
    if (write(efd, &val, sizeof(val)) < 0)
        return -errno;
    return 0;
}

int64_t rustd_eventfd_read(int efd) {
    uint64_t val;
    ssize_t n = read(efd, &val, sizeof(val));
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;
        return -errno;
    }
    return (int64_t)val;
}

/* ── child / waitid ─────────────────────────────────────────────────────── */

int rustd_child_reap(rustd_child_info *info) {
    siginfo_t si;
    memset(&si, 0, sizeof(si));

    if (waitid(P_ALL, 0, &si, WNOHANG | WEXITED | WNOWAIT) < 0) {
        if (errno == ECHILD)
            return -ECHILD;
        return -errno;
    }
    if (si.si_pid == 0)
        return -EAGAIN; /* no child has exited yet */

    /* Consume the child so it doesn't become a zombie. */
    waitid(P_PID, (id_t)si.si_pid, NULL, WNOHANG | WEXITED);

    info->pid    = si.si_pid;
    info->code   = si.si_code;
    info->status = si.si_status;
    return 0;
}

/* ── clock ──────────────────────────────────────────────────────────────── */

int64_t rustd_clock_now_nsec(int clockid) {
    struct timespec ts;
    if (clock_gettime(clockid, &ts) < 0)
        return -errno;
    return (int64_t)ts.tv_sec * INT64_C(1000000000) + (int64_t)ts.tv_nsec;
}
