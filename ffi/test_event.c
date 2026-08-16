/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
/*
 * test_event.c — smoke tests for ffi/event.c.
 * Compiled and run by `make check-native`.
 *
 * Tests:
 *   1. epoll create, add fd, wait (no-op with timeout 0).
 *   2. timerfd create, arm, read expiry.
 *   3. inotify create, add /tmp watch, remove watch.
 *   4. eventfd create, write, read.
 *   5. signalfd create (non-PID-1 context: blocks signals).
 *   6. rustd_clock_now_nsec returns a plausible value.
 */

#include "event.h"

#include <assert.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
    /* ── epoll ─────────────────────────────────────────────────────────── */
    int epfd = rustd_epoll_create1();
    assert(epfd >= 0);

    /* Add a read end of a pipe to epoll. */
    int pipefd[2];
    assert(pipe(pipefd) == 0);
    assert(rustd_epoll_add_fd(epfd, pipefd[0], 0x001 /* EPOLLIN */, 42ULL) == 0);

    /* epoll_wait with timeout 0: nothing ready → returns 0 */
    rustd_epoll_event evs[4];
    int n = rustd_epoll_wait(epfd, evs, 4, 0);
    assert(n == 0);

    assert(rustd_epoll_del_fd(epfd, pipefd[0]) == 0);
    close(pipefd[0]);
    close(pipefd[1]);
    close(epfd);

    /* ── timerfd ────────────────────────────────────────────────────────── */
    int tfd = rustd_timerfd_create(RUSTD_CLOCK_MONOTONIC);
    assert(tfd >= 0);

    /* Arm for 1 ms relative */
    assert(rustd_timerfd_settime(tfd, 0, 0, 1000000LL, 0, 0) == 0);

    /* Busy-wait up to 50 ms for expiry */
    int64_t exp = 0;
    for (int i = 0; i < 500 && exp == 0; i++) {
        usleep(100);
        exp = rustd_timerfd_read(tfd);
    }
    assert(exp >= 1);

    assert(rustd_timerfd_disarm(tfd) == 0);
    close(tfd);

    /* ── inotify ────────────────────────────────────────────────────────── */
    int ifd = rustd_inotify_create1();
    assert(ifd >= 0);

    int wd = rustd_inotify_add_watch(ifd, "/tmp", 0x100 /* IN_CREATE */);
    assert(wd >= 0);

    assert(rustd_inotify_rm_watch(ifd, wd) == 0);
    close(ifd);

    /* ── eventfd ────────────────────────────────────────────────────────── */
    int efd = rustd_eventfd_create();
    assert(efd >= 0);

    assert(rustd_eventfd_write(efd, 3ULL) == 0);
    int64_t val = rustd_eventfd_read(efd);
    /* EFD_SEMAPHORE: each read decrements by 1, so first read returns 1 */
    assert(val == 1);
    close(efd);

    /* ── clock ──────────────────────────────────────────────────────────── */
    int64_t now = rustd_clock_now_nsec(RUSTD_CLOCK_MONOTONIC);
    assert(now > 0);

    /* ── signalfd ───────────────────────────────────────────────────────── */
    int sfd = rustd_signalfd_create();
    assert(sfd >= 0);
    /* No signal pending → EAGAIN */
    int signo = 0;
    int r = rustd_signalfd_read(sfd, &signo);
    assert(r == -11 /* EAGAIN */);
    close(sfd);

    puts("test_event: all assertions passed");
    return 0;
}
