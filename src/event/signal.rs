// SPDX-License-Identifier: LGPL-2.1-or-later
//! Signal source — signalfd setup and the PID 1 signal disposition table.
//!
//! Upstream reference:
//!   src/core/main.c `install_signal_handlers()` (v261)
//!   src/core/manager.c `manager_dispatch_signal_fd()` (v261)

use std::os::unix::io::{FromRawFd, OwnedFd};

/// Block every signal in the calling thread so process-directed signals remain
/// pending for the manager's signalfd. Internal worker threads call this at
/// entry as a defense against runtimes or libraries changing their mask while
/// creating the thread.
pub(crate) fn block_all_signals_for_current_thread() -> anyhow::Result<()> {
    let mut mask = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
    // Safety: `sigfillset` initializes the provided sigset_t and
    // `pthread_sigmask` only reads it for the duration of the call.
    let fill_result = unsafe { libc::sigfillset(mask.as_mut_ptr()) };
    if fill_result != 0 {
        return Err(anyhow::anyhow!("sigfillset failed: errno {}", errno()));
    }
    // Safety: the successful call above initialized `mask`.
    let mask = unsafe { mask.assume_init() };
    // pthread_sigmask returns an errno value directly rather than setting
    // errno.
    let result = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut()) };
    if result != 0 {
        return Err(anyhow::anyhow!("pthread_sigmask failed: errno {result}"));
    }
    Ok(())
}

fn errno() -> libc::c_int {
    // Safety: libc exposes a valid thread-local errno pointer on Linux.
    unsafe { *libc::__errno_location() }
}

/// Fixed (non-RT) signals that PID 1 manages via signalfd.
///
/// `libc::SIGRTMIN` is a function on Linux (the value is not a compile-time
/// constant), so the RT signal list is built at runtime via
/// `managed_signals()` below.
pub const MANAGED_SIGNALS_FIXED: &[libc::c_int] = &[
    libc::SIGCHLD,
    libc::SIGTERM,
    libc::SIGINT,
    libc::SIGHUP,
    libc::SIGUSR1,
    libc::SIGUSR2,
    libc::SIGWINCH,
    libc::SIGPIPE,
    libc::SIGPWR,
];

/// RT signal offsets from `SIGRTMIN` that systemd manages.
/// Upstream reference: src/core/main.c `install_signal_handlers()` (v261).
const RT_OFFSETS: &[libc::c_int] = &[0, 1, 2, 3, 4, 13, 14, 15, 20, 21, 22, 26, 29];

/// Return the full set of signals that PID 1 manages.
#[must_use]
pub fn managed_signals() -> Vec<libc::c_int> {
    // Safety: SIGRTMIN() is a libc wrapper around a kernel-provided constant.
    let min = libc::SIGRTMIN();
    let mut sigs: Vec<libc::c_int> = MANAGED_SIGNALS_FIXED.to_vec();
    for &off in RT_OFFSETS {
        sigs.push(min + off);
    }
    sigs
}

/// What the event loop should do in response to a received signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalAction {
    /// Reload unit configuration (SIGHUP).
    Reload,
    /// Terminate the manager cleanly (SIGTERM when running as user manager).
    Terminate,
    /// Reap one or more children (SIGCHLD).
    ReapChildren,
    /// Initiate a clean system shutdown (SIGINT / Ctrl-Alt-Delete).
    CtrlAltDelete,
    /// Dump manager status to the journal (SIGUSR1).
    DumpStatus,
    /// Re-execute the manager binary in place (SIGUSR2).
    Reexecute,
    /// Propagate a window-resize event (SIGWINCH, user manager only).
    WindowResize,
    /// Power failure notification from UPS (SIGPWR).
    PowerFailure,
    /// systemd-specific RT signal.
    Realtime(libc::c_int),
    /// Ignore this signal.
    Ignore,
}

/// Map a received signal number to the action the manager should take.
///
/// Mirrors `manager_dispatch_signal_fd()` in upstream `src/core/manager.c`.
#[must_use]
pub fn signal_to_action(signo: libc::c_int) -> SignalAction {
    match signo {
        libc::SIGCHLD => SignalAction::ReapChildren,
        libc::SIGHUP => SignalAction::Reload,
        libc::SIGTERM => SignalAction::Terminate,
        libc::SIGINT => SignalAction::CtrlAltDelete,
        libc::SIGUSR1 => SignalAction::DumpStatus,
        libc::SIGUSR2 => SignalAction::Reexecute,
        libc::SIGWINCH => SignalAction::WindowResize,
        libc::SIGPIPE => SignalAction::Ignore,
        libc::SIGPWR => SignalAction::PowerFailure,
        other => SignalAction::Realtime(other),
    }
}

/// An owned signalfd file descriptor.
#[derive(Debug)]
pub(crate) struct SignalFd(pub(crate) OwnedFd);

impl SignalFd {
    /// Create the PID 1 signalfd: block the full signal set and return the fd.
    pub(crate) fn create() -> anyhow::Result<Self> {
        // Safety: rustd_signalfd_create is a pure C wrapper around signalfd(2)
        // and sigprocmask(2).  It returns a valid fd or -errno.
        let fd = unsafe { crate::ffi::event::rustd_signalfd_create() };
        if fd < 0 {
            return Err(anyhow::anyhow!("signalfd_create failed: errno {}", -fd));
        }
        // Safety: fd is valid and owned.
        Ok(Self(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    /// Read one pending signal from the fd.
    ///
    /// Returns `Ok(Some(signo))` on success, `Ok(None)` if no signal is
    /// pending yet (EAGAIN), or `Err` on a real error.
    pub(crate) fn read_one(&self) -> anyhow::Result<Option<libc::c_int>> {
        use std::os::unix::io::AsRawFd;
        let mut signo: libc::c_int = 0;
        let r = unsafe { crate::ffi::event::rustd_signalfd_read(self.0.as_raw_fd(), &mut signo) };
        if r == 0 {
            Ok(Some(signo))
        } else if r == -libc::EAGAIN {
            Ok(None)
        } else {
            Err(anyhow::anyhow!("signalfd_read failed: errno {}", -r))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::block_all_signals_for_current_thread;

    #[test]
    fn worker_signal_mask_blocks_realtime_manager_signals() {
        std::thread::spawn(|| {
            let mut empty = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
            // Safety: these libc calls initialize and then install the local
            // signal set for this test thread only.
            assert_eq!(unsafe { libc::sigemptyset(empty.as_mut_ptr()) }, 0);
            let empty = unsafe { empty.assume_init() };
            assert_eq!(
                unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut()) },
                0
            );

            block_all_signals_for_current_thread().unwrap();

            let mut current = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
            assert_eq!(
                unsafe {
                    libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), current.as_mut_ptr())
                },
                0
            );
            let current = unsafe { current.assume_init() };
            assert_eq!(unsafe { libc::sigismember(&current, libc::SIGRTMIN()) }, 1);
            assert_eq!(unsafe { libc::sigismember(&current, libc::SIGTERM) }, 1);
        })
        .join()
        .unwrap();
    }
}
