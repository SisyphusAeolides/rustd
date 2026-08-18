/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
/*
 * signal.c — signal handler installation for PID 1.
 *
 * RustD PID 1 uses signalfd rather than async signal handlers; this
 * module sets all managed signals to SIG_DFL, then the Rust event loop
 * opens a signalfd and blocks delivery via the process signal mask.
 * These helpers are the native reset/blocking implementation used by PID 1.
 */

#include <errno.h>
#include <signal.h>
#include <string.h>

static const int managed_signals[] = {
    SIGTERM, SIGINT, SIGHUP, SIGCHLD,
    SIGUSR1, SIGUSR2, SIGWINCH, SIGPIPE,
    SIGPWR,
#ifdef SIGRTMIN
    /* SIGRTMIN+0 through SIGRTMIN+29 are reserved for realtime control. */
#endif
};

/* Reset all managed signals to SIG_DFL so signalfd can receive them. */
int rustd_reset_all_signal_handlers(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_DFL;
    sigemptyset(&sa.sa_mask);

    for (size_t i = 0;
         i < sizeof(managed_signals) / sizeof(managed_signals[0]); i++) {
        if (sigaction(managed_signals[i], &sa, NULL) < 0)
            return -errno;
    }
    return 0;
}

/* Block all signals so that signalfd is the sole delivery mechanism. */
int rustd_block_all_signals(void) {
    sigset_t mask;
    sigfillset(&mask);
    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0)
        return -errno;
    return 0;
}
