// SPDX-License-Identifier: LGPL-2.1-or-later
//! FFI binding for `ffi/spawn.c` — async-signal-safe process spawning.
//!
//! The manager never forks after threads exist.  It `posix_spawn`s a fresh
//! RustD image in helper mode, and that helper applies the spawn parameters
//! before `execve`.  Call [`configure_spawn_helper`] with an absolute path to
//! the RustD executable before creating any manager threads.
//!
//! Upstream reference: `src/core/execute.c exec_child()` (v261)

use libc::{gid_t, pid_t, uid_t};
use std::ffi::CString;
use std::path::Path;

use crate::ffi::seccomp::{SdSeccompRule, SECCOMP_ACTION_ALLOW};

/// Security sandbox parameters mirroring `rustd_spawn_sandbox` from `ffi/spawn.h`.
///
/// Set `sandbox` pointer in [`SdSpawnParams`] to `NULL` for no sandboxing, or
/// to a pointer to one of these structs to enable it.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SdSpawnSandbox {
    /// Boolean: set `PR_SET_NO_NEW_PRIVS`.
    pub no_new_privs: libc::c_int,
    /// Boolean: private tmpfs on `/tmp` and `/var/tmp`.
    pub private_tmp: libc::c_int,
    /// Boolean: minimal `/dev` in new mount namespace.
    pub private_devices: libc::c_int,
    /// Boolean: new empty network namespace.
    pub private_network: libc::c_int,
    /// Boolean: force a private mount namespace.
    pub private_mounts: libc::c_int,
    /// `ProtectSystem=`: 0=no, 1=yes, 2=full, 3=strict.
    pub protect_system: libc::c_int,
    /// `ProtectHome=`: 0=no, 1=yes, 2=read-only, 3=tmpfs.
    pub protect_home: libc::c_int,
    /// Boolean: `/proc/sys`, `/sys` read-only.
    pub protect_kernel_tunables: libc::c_int,
    /// Boolean: `/lib/modules` read-only.
    pub protect_kernel_modules: libc::c_int,
    /// Boolean: block kernel log access (`syslog(2)`, `/dev/kmsg`).
    pub protect_kernel_logs: libc::c_int,
    /// Boolean: block realtime clock modification and RTC device access.
    pub protect_clock: libc::c_int,
    /// Boolean: `/sys/fs/cgroup` read-only.
    pub protect_control_groups: libc::c_int,
    /// Boolean: `nosuid` on `/dev` and `/tmp`.
    pub restrict_suid_sgid: libc::c_int,
    /// Boolean: seccomp-block real-time scheduling.
    pub restrict_realtime: libc::c_int,
    /// Boolean: block namespace-changing syscalls.
    pub restrict_namespaces: libc::c_int,
    /// Boolean: block writable executable mappings.
    pub memory_deny_write_execute: libc::c_int,
    /// Compiled `SystemCallFilter=` rules.
    pub syscall_filter_rules: *const SdSeccompRule,
    /// Number of compiled syscall rules.
    pub n_syscall_filter_rules: usize,
    /// Action applied to syscalls without an explicit rule.
    pub syscall_filter_default_action: u32,
    /// Boolean: install the compiled syscall filter.
    pub syscall_filter_enabled: libc::c_int,
    /// Boolean: reject non-native syscall architectures.
    pub restrict_native_syscalls: libc::c_int,
}

impl Default for SdSpawnSandbox {
    fn default() -> Self {
        Self {
            no_new_privs: 0,
            private_tmp: 0,
            private_devices: 0,
            private_network: 0,
            private_mounts: 0,
            protect_system: 0,
            protect_home: 0,
            protect_kernel_tunables: 0,
            protect_kernel_modules: 0,
            protect_kernel_logs: 0,
            protect_clock: 0,
            protect_control_groups: 0,
            restrict_suid_sgid: 0,
            restrict_realtime: 0,
            restrict_namespaces: 0,
            memory_deny_write_execute: 0,
            syscall_filter_rules: std::ptr::null(),
            n_syscall_filter_rules: 0,
            syscall_filter_default_action: SECCOMP_ACTION_ALLOW,
            syscall_filter_enabled: 0,
            restrict_native_syscalls: 0,
        }
    }
}

/// One native process resource limit. `u64::MAX` means `RLIM_INFINITY`.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SdSpawnRlimit {
    pub resource: libc::c_int,
    pub soft: u64,
    pub hard: u64,
}

/// Parameters for `rustd_spawn`.
///
/// Mirrors `rustd_spawn_params` from `ffi/spawn.h`.
#[repr(C)]
pub struct SdSpawnParams {
    /// Executable path, independent of `argv[0]`.
    pub path: *const libc::c_char,
    /// NULL-terminated argument vector.
    pub argv: *const *const libc::c_char,
    /// NULL-terminated environment vector; NULL inherits the parent env.
    pub envp: *const *const libc::c_char,
    /// Working directory; NULL inherits the parent's cwd.
    pub cwd: *const libc::c_char,
    /// Path to the prepared unit `cgroup.procs`, or NULL.
    pub cgroup_procs_path: *const libc::c_char,
    /// Requested process resource limits.
    pub rlimits: *const SdSpawnRlimit,
    /// Number of entries in `rlimits`.
    pub n_rlimits: usize,
    /// User ID to switch to; `(uid_t)-1` = do not switch.
    pub uid: uid_t,
    /// Group ID to switch to; `(gid_t)-1` = do not switch.
    pub gid: gid_t,
    /// `SELinux` execution context; NULL disables the transition.
    pub selinux_context: *const libc::c_char,
    /// Boolean: ignore `SELinux` transition failure.
    pub selinux_context_ignore: libc::c_int,
    /// `AppArmor` execution profile; NULL disables the transition.
    pub apparmor_profile: *const libc::c_char,
    /// Boolean: ignore `AppArmor` profile transition failure.
    pub apparmor_profile_ignore: libc::c_int,
    /// stdin fd; -1 = redirect to /dev/null.
    pub stdin_fd: libc::c_int,
    /// stdout fd; -1 = inherit.
    pub stdout_fd: libc::c_int,
    /// stderr fd; -1 = inherit.
    pub stderr_fd: libc::c_int,
    /// Notification socket enable flag; -1 disables notifications.
    pub notify_fd: libc::c_int,
    /// Service watchdog interval in microseconds; 0 disables it.
    pub watchdog_usec: u64,
    /// Security sandbox parameters; NULL = no sandbox.
    pub sandbox: *const SdSpawnSandbox,
    /// Listener fds to pass as `RUSTD_LISTEN_FDS`.  NULL or empty = none.
    pub listen_fds: *const libc::c_int,
    /// Number of entries in `listen_fds`; 0 = none.
    pub n_listen_fds: libc::c_int,
    /// Capability bounding set bitmask — bits set = capabilities to KEEP.
    /// `u64::MAX` means no change; `0` drops all capabilities.
    pub cap_bounding_set: u64,
    /// Ambient capability bitmask — bits set = capabilities to raise.
    /// `0` means no ambient caps.
    pub ambient_caps: u64,
    /// Wait until the child successfully crosses `execve(2)`.
    pub wait_for_exec: libc::c_int,
    /// Read side of the `Type=idle` execution gate, or -1.
    pub idle_read_fd: libc::c_int,
    /// Write side of the `Type=idle` execution gate, or -1.
    pub idle_write_fd: libc::c_int,
}

extern "C" {
    /// Install the absolute path of the helper image used by [`rustd_spawn`].
    ///
    /// # Safety
    /// `executable_path` must be a valid NUL-terminated C string for the
    /// duration of the call.
    pub fn rustd_spawn_helper_configure(executable_path: *const libc::c_char) -> libc::c_int;

    /// Non-zero once [`rustd_spawn_helper_configure`] has succeeded.
    pub fn rustd_spawn_helper_configured() -> libc::c_int;

    /// Spawn with the given parameters without forking the manager.
    ///
    /// Returns the child PID on success, or a negative errno on failure.
    ///
    /// # Safety
    /// `p` must be a valid pointer to an initialised `SdSpawnParams`.
    /// All pointer fields within `p` must be valid for the duration of
    /// the call (they are not accessed after `rustd_spawn` returns).
    pub fn rustd_spawn(p: *const SdSpawnParams) -> pid_t;
}

/// Install the helper image that [`rustd_spawn`] launches for child setup.
///
/// Must be called before the manager creates any thread.  Production entry
/// points pass `/proc/self/exe` (or an equivalent absolute path to the RustD
/// binary).  Returns `Ok(())` on success.
///
/// # Errors
/// Returns an error when the path is not absolute, cannot be reached, or the
/// native configuration call fails.
pub fn configure_spawn_helper(executable: &Path) -> anyhow::Result<()> {
    let path = executable
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("spawn helper path is not valid UTF-8"))?;
    if !path.starts_with('/') {
        anyhow::bail!("spawn helper path must be absolute");
    }
    let c_path =
        CString::new(path).map_err(|_| anyhow::anyhow!("spawn helper path contains a NUL byte"))?;
    // Safety: `c_path` is a valid NUL-terminated C string for this call.
    let result = unsafe { rustd_spawn_helper_configure(c_path.as_ptr()) };
    if result < 0 {
        anyhow::bail!(
            "failed to configure spawn helper '{}': errno {}",
            path,
            -result
        );
    }
    Ok(())
}

/// Resolve `/proc/self/exe` and install it as the spawn helper.
///
/// # Errors
/// Returns an error when `/proc/self/exe` cannot be read or configured.
pub fn configure_spawn_helper_from_self() -> anyhow::Result<()> {
    let exe = std::fs::read_link("/proc/self/exe")
        .map_err(|error| anyhow::anyhow!("cannot read /proc/self/exe: {error}"))?;
    configure_spawn_helper(&exe)
}

/// Test-only auto-configuration so unit tests that spawn services do not need
/// to call the production entry path.  Production builds never include this.
#[cfg(test)]
pub(crate) fn ensure_spawn_helper_for_tests() {
    use std::sync::Once;

    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        if unsafe { rustd_spawn_helper_configured() } != 0 {
            return;
        }
        if let Err(error) = configure_spawn_helper_from_self() {
            panic!("test spawn helper configuration failed: {error}");
        }
    });
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn production_spawn_sources_never_call_fork() {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        for relative in ["ffi/spawn.c", "ffi/spawn_helper.c"] {
            let source = fs::read_to_string(manifest.join(relative)).unwrap();
            assert!(
                !ForkCallPattern::is_match(&source),
                "{relative} must not call fork()"
            );
        }

        let spawn_c = fs::read_to_string(manifest.join("ffi/spawn.c")).unwrap();
        let start = spawn_c
            .find("pid_t rustd_spawn(")
            .expect("rustd_spawn definition");
        let body = &spawn_c[start..];
        let end = body.find("\n}\n").expect("rustd_spawn closing brace") + 3;
        let function = &body[..end];
        assert!(
            !ForkCallPattern::is_match(function),
            "production rustd_spawn must not call fork"
        );
        assert!(
            function.contains("spawn_helper_image"),
            "production rustd_spawn must launch through spawn_helper_image"
        );
        assert!(
            call_free_contains_posix_spawn(&spawn_c),
            "ffi/spawn.c must use posix_spawn"
        );
    }

    fn call_free_contains_posix_spawn(source: &str) -> bool {
        source
            .lines()
            .map(|line| line.split("//").next().unwrap_or(line))
            .any(|line| line.contains("posix_spawn"))
    }

    struct ForkCallPattern;

    impl ForkCallPattern {
        fn is_match(source: &str) -> bool {
            let without_blocks = strip_block_comments(source);
            for line in without_blocks.lines() {
                let code = line.split("//").next().unwrap_or(line);
                let bytes = code.as_bytes();
                let needle = b"fork";
                let mut index = 0;
                while let Some(relative) = bytes[index..]
                    .windows(needle.len())
                    .position(|window| window == needle)
                {
                    let at = index + relative;
                    let before = if at == 0 { b' ' } else { bytes[at - 1] };
                    if before.is_ascii_alphanumeric() || before == b'_' {
                        index = at + needle.len();
                        continue;
                    }
                    let after = &code[at + needle.len()..];
                    let trimmed = after.trim_start();
                    if trimmed.starts_with('(') {
                        return true;
                    }
                    index = at + needle.len();
                }
            }
            false
        }
    }

    fn strip_block_comments(source: &str) -> String {
        let mut output = String::with_capacity(source.len());
        let bytes = source.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            if index + 1 < bytes.len() && bytes[index] == b'/' && bytes[index + 1] == b'*' {
                index += 2;
                while index + 1 < bytes.len() && !(bytes[index] == b'*' && bytes[index + 1] == b'/')
                {
                    index += 1;
                }
                index = (index + 2).min(bytes.len());
                output.push(' ');
                continue;
            }
            output.push(bytes[index] as char);
            index += 1;
        }
        output
    }
}
