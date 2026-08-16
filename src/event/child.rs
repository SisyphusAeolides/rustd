// SPDX-License-Identifier: LGPL-2.1-or-later
//! Child process reaping.
//!
//! When SIGCHLD is received via the signalfd, the manager calls
//! `reap_children` to collect all exited children.
//!
//! Upstream reference: src/core/manager.c `manager_dispatch_sigchld()` (v261)

/// Exit status of a child process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChildExit {
    /// PID of the exited child.
    pub pid: libc::pid_t,
    /// `CLD_EXITED`, `CLD_KILLED`, or `CLD_DUMPED`.
    pub code: i32,
    /// Exit code (if `CLD_EXITED`) or signal number (if killed/dumped).
    pub status: i32,
}

impl ChildExit {
    /// True if the child exited with code 0.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.code == libc::CLD_EXITED && self.status == 0
    }
}

/// Reap all currently-exited children.
///
/// Calls `waitid(WNOHANG)` in a loop until no more children have exited.
/// Returns a `Vec` of every child that was collected during this call.
///
/// Upstream reference: `manager_dispatch_sigchld()` — reaps all pending
/// children after a SIGCHLD, not just one.
#[must_use]
pub fn reap_children() -> Vec<ChildExit> {
    let mut result = Vec::new();
    loop {
        let mut info = crate::ffi::event::SdChildInfo {
            pid: 0,
            code: 0,
            status: 0,
        };
        // Safety: rustd_child_reap fills info and returns 0, -EAGAIN, or -errno.
        let r = unsafe { crate::ffi::event::rustd_child_reap(&mut info) };
        if r == 0 {
            result.push(ChildExit {
                pid: info.pid,
                code: info.code,
                status: info.status,
            });
        } else {
            // -EAGAIN: no more exited children.  -ECHILD: no children at all.
            break;
        }
    }
    result
}
