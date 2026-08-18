// SPDX-License-Identifier: LGPL-2.1-or-later
//! FFI bindings for `ffi/sandbox.c`.
//!
//! All functions here are designed to be called after `fork()` and before
//! `execve()`, in the single-threaded child process.
//!
//! Upstream reference: `src/core/execute.c exec_child()`,
//!   `src/core/execute-security.c` (v261)

use libc::c_int;

extern "C" {
    /// Set `PR_SET_NO_NEW_PRIVS` on the calling process.
    /// Returns 0 on success, -errno on failure.
    pub fn rustd_sandbox_no_new_privs() -> c_int;

    /// Unshare mount (and optionally network) namespace and apply
    /// `PrivateTmp` / `PrivateDevices` / `ProtectSystem` / `ProtectHome` isolation.
    ///
    /// # Safety
    /// Must be called in the single-threaded child context after `fork()`.
    pub fn rustd_sandbox_mount_namespaces(
        private_tmp: c_int,
        private_devices: c_int,
        private_network: c_int,
        protect_system: c_int,
        protect_home: c_int,
        force_mount_namespace: c_int,
    ) -> c_int;

    /// Re-open declared writable paths inside the private mount namespace.
    ///
    /// # Safety
    /// `paths` must reference `n_paths` valid NUL-terminated strings for the
    /// duration of the call. The caller must already be in its private mount
    /// namespace when path exceptions are requested.
    pub fn rustd_sandbox_make_writable_paths(
        paths: *const *const libc::c_char,
        n_paths: usize,
    ) -> c_int;

    /// Bind-mount sensitive kernel paths read-only.
    ///
    /// # Safety
    /// Must be called in the single-threaded child context after `fork()`.
    pub fn rustd_sandbox_protect_paths(
        protect_kernel_tunables: c_int,
        protect_kernel_modules: c_int,
        protect_kernel_logs: c_int,
        protect_clock: c_int,
        protect_control_groups: c_int,
        restrict_suid_sgid: c_int,
    ) -> c_int;

    /// Install a seccomp filter that returns `EPERM` for scheduling policies
    /// other than `SCHED_OTHER`, `SCHED_BATCH`, and `SCHED_IDLE`.
    ///
    /// # Safety
    /// Must be called in the single-threaded child context after `fork()`.
    pub fn rustd_sandbox_restrict_realtime() -> c_int;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn realtime_filter_matches_upstream_policy_set() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            let param = libc::sched_param { sched_priority: 0 };

            // Policy value 4 is not a Linux scheduling policy accepted by
            // sched_setscheduler(). Before seccomp, the kernel rejects it as
            // EINVAL; after our filter, upstream-compatible behavior is EPERM.
            let before = unsafe { libc::sched_setscheduler(0, 4, &param) };
            let before_errno = std::io::Error::last_os_error().raw_os_error();
            if before != -1 || before_errno != Some(libc::EINVAL) {
                unsafe { libc::_exit(100) };
            }

            if unsafe { rustd_sandbox_no_new_privs() } < 0 {
                unsafe { libc::_exit(101) };
            }
            if unsafe { rustd_sandbox_restrict_realtime() } < 0 {
                unsafe { libc::_exit(102) };
            }

            let after = unsafe { libc::sched_setscheduler(0, 4, &param) };
            if after != -1 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
                unsafe { libc::_exit(103) };
            }

            if unsafe { libc::sched_setscheduler(0, libc::SCHED_OTHER, &param) } != 0 {
                unsafe { libc::_exit(104) };
            }
            unsafe { libc::_exit(0) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }
}
