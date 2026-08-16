// SPDX-License-Identifier: LGPL-2.1-or-later
//! FFI bindings for `ffi/seccomp.c` — BPF seccomp filter helpers.
//!
//! Upstream reference: `src/shared/seccomp-util.c` (v261)

/// Kill the complete process when a syscall is denied.
pub const SECCOMP_ACTION_KILL_PROCESS: u32 = 0x8000_0000;
/// Return an errno encoded in the low 16 bits.
pub const SECCOMP_ACTION_ERRNO: u32 = 0x0005_0000;
/// Allow the syscall.
pub const SECCOMP_ACTION_ALLOW: u32 = 0x7fff_0000;

/// One native-architecture syscall action for the C seccomp backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct SdSeccompRule {
    pub nr: libc::c_int,
    pub action: u32,
}

extern "C" {
    /// Block `mmap(2)` with `PROT_WRITE|PROT_EXEC` and `mprotect(2)` with
    /// `PROT_EXEC`.  Implements `MemoryDenyWriteExecute=yes`.
    ///
    /// Returns 0 on success; negative errno on failure.
    ///
    /// # Safety
    /// Must be called from a single-threaded child process after `fork()`.
    pub fn rustd_seccomp_memory_deny_write_execute() -> libc::c_int;

    /// Block namespace-changing `unshare(2)`, `clone(2)`, `clone3(2)`, and
    /// `setns(2)` calls for any
    /// namespace type whose bit is NOT set in `allowed_mask`.
    /// `allowed_mask = 0` blocks all namespace creation.
    ///
    /// Returns 0 on success; negative errno on failure.
    ///
    /// # Safety
    /// Must be called from a single-threaded child process after `fork()`.
    pub fn rustd_seccomp_restrict_namespaces(allowed_mask: u64) -> libc::c_int;

    /// Block kernel log access through `syslog(2)`.
    pub fn rustd_seccomp_protect_kernel_logs() -> libc::c_int;

    /// Block syscalls that change the realtime clock.
    pub fn rustd_seccomp_protect_clock() -> libc::c_int;

    /// Resolve a syscall name through the native libseccomp runtime.
    pub fn rustd_seccomp_syscall_resolve_name(
        name: *const libc::c_char,
        ret_nr: *mut libc::c_int,
    ) -> libc::c_int;

    /// Return 1 when the native syscall number is known, 0 when unknown.
    pub fn rustd_seccomp_syscall_is_known(nr: libc::c_int) -> libc::c_int;

    /// Reject non-native syscall architectures.
    pub fn rustd_seccomp_restrict_native_architecture() -> libc::c_int;

    /// Install per-syscall actions with a default action.
    pub fn rustd_seccomp_syscall_rules(
        rules: *const SdSeccompRule,
        n_rules: usize,
        default_action: u32,
    ) -> libc::c_int;

    /// Install a syscall allow-list or deny-list BPF filter.
    ///
    /// Exactly one of `allow_list` or `deny_list` must be non-NULL.
    /// Unrecognised syscall names are silently skipped.
    /// `error_number` is the errno returned for blocked calls (e.g. `EPERM`).
    ///
    /// Returns 0 on success; negative errno on failure.
    ///
    /// # Safety
    /// `allow_list` / `deny_list` must be NULL-terminated arrays of valid
    /// NUL-terminated C strings, or NULL.  Must be called after `fork()`.
    pub fn rustd_seccomp_syscall_filter(
        allow_list: *const *const libc::c_char,
        deny_list: *const *const libc::c_char,
        error_number: libc::c_int,
    ) -> libc::c_int;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn c_list(names: &[&str]) -> (Vec<CString>, Vec<*const libc::c_char>) {
        let strings: Vec<CString> = names
            .iter()
            .map(|name| CString::new(*name).expect("syscall name"))
            .collect();
        let mut pointers: Vec<*const libc::c_char> =
            strings.iter().map(|name| name.as_ptr()).collect();
        pointers.push(std::ptr::null());
        (strings, pointers)
    }

    fn wait_child(pid: libc::pid_t) {
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn namespace_filter_blocks_setns_and_hides_clone3() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            if unsafe { rustd_seccomp_restrict_namespaces(0) } < 0 {
                unsafe { libc::_exit(100) };
            }
            let rc = unsafe { libc::syscall(libc::SYS_setns, -1, 0) };
            if rc != -1 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
                unsafe { libc::_exit(101) };
            }
            #[cfg(any(target_os = "linux", target_os = "android"))]
            {
                let rc =
                    unsafe { libc::syscall(libc::SYS_clone3, std::ptr::null::<libc::c_void>(), 0) };
                if rc != -1 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOSYS)
                {
                    unsafe { libc::_exit(102) };
                }
            }
            unsafe { libc::_exit(0) };
        }
        wait_child(pid);
    }

    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn numeric_rules_support_per_syscall_errno() {
        let name = CString::new("getpid").unwrap();
        let mut nr = -1;
        assert_eq!(
            unsafe { rustd_seccomp_syscall_resolve_name(name.as_ptr(), &mut nr) },
            0
        );
        assert!(nr >= 0);

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let rule = SdSeccompRule {
                nr,
                action: SECCOMP_ACTION_ERRNO | u32::try_from(libc::EACCES).unwrap(),
            };
            if unsafe { rustd_seccomp_syscall_rules(&rule, 1, SECCOMP_ACTION_ALLOW) } < 0 {
                unsafe { libc::_exit(130) };
            }
            let rc = unsafe { libc::syscall(libc::SYS_getpid) };
            if rc != -1 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EACCES) {
                unsafe { libc::_exit(131) };
            }
            if unsafe { libc::syscall(libc::SYS_getppid) } <= 0 {
                unsafe { libc::_exit(132) };
            }
            unsafe { libc::_exit(0) };
        }
        wait_child(pid);
    }

    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn deny_list_blocks_only_matching_syscall() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let (_strings, list) = c_list(&["getpid"]);
            if unsafe {
                rustd_seccomp_syscall_filter(std::ptr::null(), list.as_ptr(), libc::EACCES)
            } < 0
            {
                unsafe { libc::_exit(110) };
            }
            let rc = unsafe { libc::syscall(libc::SYS_getpid) };
            if rc != -1 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EACCES) {
                unsafe { libc::_exit(111) };
            }
            if unsafe { libc::syscall(libc::SYS_getppid) } <= 0 {
                unsafe { libc::_exit(112) };
            }
            unsafe { libc::_exit(0) };
        }
        wait_child(pid);
    }

    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn allow_list_denies_nonmatching_syscall() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let (_strings, list) = c_list(&["getpid", "exit", "exit_group", "rt_sigreturn"]);
            if unsafe {
                rustd_seccomp_syscall_filter(list.as_ptr(), std::ptr::null(), libc::EACCES)
            } < 0
            {
                unsafe { libc::_exit(120) };
            }
            if unsafe { libc::syscall(libc::SYS_getpid) } <= 0 {
                unsafe { libc::_exit(121) };
            }
            let rc = unsafe { libc::syscall(libc::SYS_getppid) };
            if rc != -1 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EACCES) {
                unsafe { libc::_exit(122) };
            }
            unsafe { libc::_exit(0) };
        }
        wait_child(pid);
    }
}
