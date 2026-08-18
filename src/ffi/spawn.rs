// SPDX-License-Identifier: LGPL-2.1-or-later
//! FFI binding for `ffi/spawn.c` — async-signal-safe process spawning.
//!
//! The public Rust sandbox layout remains stable for the service execution
//! code. Immediately before the native call, this module expands that layout
//! to the v2 C ABI and attaches the validated `ReadWritePaths=` vector staged
//! by `SecurityContext::from_service`.
//!
//! Upstream reference: `src/core/execute.c exec_child()` (v261)

use libc::{gid_t, pid_t, uid_t};
use std::ffi::CString;
use std::path::Path;

use crate::ffi::seccomp::{SdSeccompRule, SECCOMP_ACTION_ALLOW};

const MAX_READ_WRITE_PATHS: usize = 256;

/// Stable Rust-side security sandbox parameters consumed by `service.rs`.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SdSpawnSandbox {
    pub no_new_privs: libc::c_int,
    pub private_tmp: libc::c_int,
    pub private_devices: libc::c_int,
    pub private_network: libc::c_int,
    pub private_mounts: libc::c_int,
    pub protect_system: libc::c_int,
    pub protect_home: libc::c_int,
    pub protect_kernel_tunables: libc::c_int,
    pub protect_kernel_modules: libc::c_int,
    pub protect_kernel_logs: libc::c_int,
    pub protect_clock: libc::c_int,
    pub protect_control_groups: libc::c_int,
    pub restrict_suid_sgid: libc::c_int,
    pub restrict_realtime: libc::c_int,
    pub restrict_namespaces: libc::c_int,
    pub memory_deny_write_execute: libc::c_int,
    pub syscall_filter_rules: *const SdSeccompRule,
    pub n_syscall_filter_rules: usize,
    pub syscall_filter_default_action: u32,
    pub syscall_filter_enabled: libc::c_int,
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

#[derive(Debug, Clone, Copy)]
#[repr(C)]
struct NativeSpawnSandbox {
    no_new_privs: libc::c_int,
    private_tmp: libc::c_int,
    private_devices: libc::c_int,
    private_network: libc::c_int,
    private_mounts: libc::c_int,
    protect_system: libc::c_int,
    protect_home: libc::c_int,
    protect_kernel_tunables: libc::c_int,
    protect_kernel_modules: libc::c_int,
    protect_kernel_logs: libc::c_int,
    protect_clock: libc::c_int,
    protect_control_groups: libc::c_int,
    restrict_suid_sgid: libc::c_int,
    restrict_realtime: libc::c_int,
    restrict_namespaces: libc::c_int,
    memory_deny_write_execute: libc::c_int,
    syscall_filter_rules: *const SdSeccompRule,
    n_syscall_filter_rules: usize,
    syscall_filter_default_action: u32,
    syscall_filter_enabled: libc::c_int,
    restrict_native_syscalls: libc::c_int,
    read_write_paths: *const *const libc::c_char,
    n_read_write_paths: usize,
}

impl NativeSpawnSandbox {
    fn from_legacy(value: Option<&SdSpawnSandbox>) -> Self {
        value.map_or(
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
                read_write_paths: std::ptr::null(),
                n_read_write_paths: 0,
            },
            |legacy| Self {
                no_new_privs: legacy.no_new_privs,
                private_tmp: legacy.private_tmp,
                private_devices: legacy.private_devices,
                private_network: legacy.private_network,
                private_mounts: legacy.private_mounts,
                protect_system: legacy.protect_system,
                protect_home: legacy.protect_home,
                protect_kernel_tunables: legacy.protect_kernel_tunables,
                protect_kernel_modules: legacy.protect_kernel_modules,
                protect_kernel_logs: legacy.protect_kernel_logs,
                protect_clock: legacy.protect_clock,
                protect_control_groups: legacy.protect_control_groups,
                restrict_suid_sgid: legacy.restrict_suid_sgid,
                restrict_realtime: legacy.restrict_realtime,
                restrict_namespaces: legacy.restrict_namespaces,
                memory_deny_write_execute: legacy.memory_deny_write_execute,
                syscall_filter_rules: legacy.syscall_filter_rules,
                n_syscall_filter_rules: legacy.n_syscall_filter_rules,
                syscall_filter_default_action: legacy.syscall_filter_default_action,
                syscall_filter_enabled: legacy.syscall_filter_enabled,
                restrict_native_syscalls: legacy.restrict_native_syscalls,
                read_write_paths: std::ptr::null(),
                n_read_write_paths: 0,
            },
        )
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

/// Parameters supplied by the service execution layer.
#[repr(C)]
pub struct SdSpawnParams {
    pub path: *const libc::c_char,
    pub argv: *const *const libc::c_char,
    pub envp: *const *const libc::c_char,
    pub cwd: *const libc::c_char,
    pub cgroup_procs_path: *const libc::c_char,
    pub rlimits: *const SdSpawnRlimit,
    pub n_rlimits: usize,
    pub uid: uid_t,
    pub gid: gid_t,
    pub selinux_context: *const libc::c_char,
    pub selinux_context_ignore: libc::c_int,
    pub apparmor_profile: *const libc::c_char,
    pub apparmor_profile_ignore: libc::c_int,
    pub stdin_fd: libc::c_int,
    pub stdout_fd: libc::c_int,
    pub stderr_fd: libc::c_int,
    pub notify_fd: libc::c_int,
    pub watchdog_usec: u64,
    pub sandbox: *const SdSpawnSandbox,
    pub listen_fds: *const libc::c_int,
    pub n_listen_fds: libc::c_int,
    pub cap_bounding_set: u64,
    pub ambient_caps: u64,
    pub wait_for_exec: libc::c_int,
    pub idle_read_fd: libc::c_int,
    pub idle_write_fd: libc::c_int,
}

#[repr(C)]
struct NativeSpawnParams {
    path: *const libc::c_char,
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
    cwd: *const libc::c_char,
    cgroup_procs_path: *const libc::c_char,
    rlimits: *const SdSpawnRlimit,
    n_rlimits: usize,
    uid: uid_t,
    gid: gid_t,
    selinux_context: *const libc::c_char,
    selinux_context_ignore: libc::c_int,
    apparmor_profile: *const libc::c_char,
    apparmor_profile_ignore: libc::c_int,
    stdin_fd: libc::c_int,
    stdout_fd: libc::c_int,
    stderr_fd: libc::c_int,
    notify_fd: libc::c_int,
    watchdog_usec: u64,
    sandbox: *const NativeSpawnSandbox,
    listen_fds: *const libc::c_int,
    n_listen_fds: libc::c_int,
    cap_bounding_set: u64,
    ambient_caps: u64,
    wait_for_exec: libc::c_int,
    idle_read_fd: libc::c_int,
    idle_write_fd: libc::c_int,
}

extern "C" {
    pub fn rustd_spawn_helper_configure(executable_path: *const libc::c_char) -> libc::c_int;
    pub fn rustd_spawn_helper_configured() -> libc::c_int;

    #[link_name = "rustd_spawn"]
    fn rustd_spawn_native(p: *const NativeSpawnParams) -> pid_t;
}

/// Spawn through the v2 native ABI while attaching the validated writable path
/// vector staged for this service launch.
///
/// # Safety
/// `p` must point to a fully initialized [`SdSpawnParams`] whose pointer fields
/// remain valid for the duration of this call.
pub unsafe fn rustd_spawn(p: *const SdSpawnParams) -> pid_t {
    if p.is_null() {
        return -libc::EINVAL;
    }
    let params = unsafe { &*p };
    let legacy_sandbox = if params.sandbox.is_null() {
        None
    } else {
        Some(unsafe { &*params.sandbox })
    };

    let paths = crate::sandbox::take_spawn_read_write_paths();
    if paths.len() > MAX_READ_WRITE_PATHS {
        return -libc::E2BIG;
    }
    let mut path_strings = Vec::with_capacity(paths.len());
    for raw in &paths {
        let path = raw.strip_prefix('-').unwrap_or(raw.as_str());
        if path.is_empty() || !path.starts_with('/') {
            return -libc::EINVAL;
        }
        let Ok(value) = CString::new(raw.as_str()) else {
            return -libc::EINVAL;
        };
        path_strings.push(value);
    }
    let path_pointers = path_strings
        .iter()
        .map(|value| value.as_ptr())
        .collect::<Vec<_>>();

    let mut sandbox = NativeSpawnSandbox::from_legacy(legacy_sandbox);
    sandbox.read_write_paths = if path_pointers.is_empty() {
        std::ptr::null()
    } else {
        path_pointers.as_ptr()
    };
    sandbox.n_read_write_paths = path_pointers.len();
    let sandbox_enabled = legacy_sandbox.is_some() || !path_pointers.is_empty();

    let native = NativeSpawnParams {
        path: params.path,
        argv: params.argv,
        envp: params.envp,
        cwd: params.cwd,
        cgroup_procs_path: params.cgroup_procs_path,
        rlimits: params.rlimits,
        n_rlimits: params.n_rlimits,
        uid: params.uid,
        gid: params.gid,
        selinux_context: params.selinux_context,
        selinux_context_ignore: params.selinux_context_ignore,
        apparmor_profile: params.apparmor_profile,
        apparmor_profile_ignore: params.apparmor_profile_ignore,
        stdin_fd: params.stdin_fd,
        stdout_fd: params.stdout_fd,
        stderr_fd: params.stderr_fd,
        notify_fd: params.notify_fd,
        watchdog_usec: params.watchdog_usec,
        sandbox: if sandbox_enabled {
            std::ptr::addr_of!(sandbox)
        } else {
            std::ptr::null()
        },
        listen_fds: params.listen_fds,
        n_listen_fds: params.n_listen_fds,
        cap_bounding_set: params.cap_bounding_set,
        ambient_caps: params.ambient_caps,
        wait_for_exec: params.wait_for_exec,
        idle_read_fd: params.idle_read_fd,
        idle_write_fd: params.idle_write_fd,
    };

    unsafe { rustd_spawn_native(std::ptr::addr_of!(native)) }
}

/// Install the helper image that [`rustd_spawn`] launches for child setup.
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
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn public_sandbox_layout_stays_service_compatible() {
        let sandbox = SdSpawnSandbox::default();
        assert_eq!(sandbox.protect_system, 0);
        assert_eq!(sandbox.n_syscall_filter_rules, 0);
    }

    #[test]
    fn native_sandbox_appends_writable_path_vector() {
        let legacy = SdSpawnSandbox::default();
        let native = NativeSpawnSandbox::from_legacy(Some(&legacy));
        assert!(native.read_write_paths.is_null());
        assert_eq!(native.n_read_write_paths, 0);
    }

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
