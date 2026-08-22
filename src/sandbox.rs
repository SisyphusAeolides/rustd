// SPDX-License-Identifier: LGPL-2.1-or-later
//! Service execution security context.
//!
//! Derives a `SecurityContext` from a `ServiceSection` and passes it to
//! `rustd_spawn` as extended parameters, or applies it in the child via the
//! native sandbox helpers.
//!
//! Upstream reference: `src/core/execute.c exec_child()`,
//!   `src/core/execute-security.c` (v261)

use std::cell::RefCell;
use std::ffi::CString;

use anyhow::anyhow;

use crate::unit::section_service::{ProtectHome, ProtectSystem, ServiceSection};

const MAX_READ_WRITE_PATHS: usize = 256;

thread_local! {
    static SPAWN_READ_WRITE_PATHS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

pub(crate) fn take_spawn_read_write_paths() -> Vec<String> {
    SPAWN_READ_WRITE_PATHS.with(|paths| std::mem::take(&mut *paths.borrow_mut()))
}

fn validate_read_write_paths(paths: &[String]) -> anyhow::Result<Vec<String>> {
    if paths.len() > MAX_READ_WRITE_PATHS {
        return Err(anyhow!(
            "ReadWritePaths= contains {} entries; maximum is {MAX_READ_WRITE_PATHS}",
            paths.len()
        ));
    }
    paths
        .iter()
        .map(|raw| {
            let path = raw.strip_prefix('-').unwrap_or(raw.as_str());
            if path.is_empty() || !path.starts_with('/') {
                return Err(anyhow!("ReadWritePaths= entry '{raw}' is not an absolute path"));
            }
            if raw.as_bytes().contains(&0) {
                return Err(anyhow!("ReadWritePaths= entry contains a NUL byte"));
            }
            Ok(raw.clone())
        })
        .collect()
}

// ── SecurityContext ───────────────────────────────────────────────────────

/// All sandbox settings resolved from `[Service]` section fields.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Default, Clone)]
pub struct SecurityContext {
    pub uid: libc::uid_t,
    pub gid: libc::gid_t,
    pub no_new_privileges: bool,
    pub private_tmp: bool,
    pub private_devices: bool,
    pub private_network: bool,
    pub private_mounts: bool,
    pub protect_system: u8,
    pub protect_home: u8,
    pub protect_kernel_tunables: bool,
    pub protect_kernel_modules: bool,
    pub protect_kernel_logs: bool,
    pub protect_clock: bool,
    pub protect_control_groups: bool,
    pub restrict_realtime: bool,
    pub restrict_suid_sgid: bool,
    pub restrict_namespaces: bool,
    pub memory_deny_write_execute: bool,
    pub cap_bounding_set: u64,
    pub ambient_caps: u64,
    pub read_write_paths: Vec<String>,
}

const PROTECT_SYSTEM_NO: u8 = 0;
const PROTECT_SYSTEM_YES: u8 = 1;
const PROTECT_SYSTEM_FULL: u8 = 2;
const PROTECT_SYSTEM_STRICT: u8 = 3;

const PROTECT_HOME_NO: u8 = 0;
const PROTECT_HOME_YES: u8 = 1;
const PROTECT_HOME_READ_ONLY: u8 = 2;
const PROTECT_HOME_TMPFS: u8 = 3;

impl SecurityContext {
    fn parse_cap_list(names: &[String]) -> u64 {
        if names.is_empty() {
            return u64::MAX;
        }
        let mut mask: u64 = 0;
        for name in names {
            let Ok(cname) = CString::new(name.as_str()) else {
                continue;
            };
            let number =
                unsafe { crate::ffi::capability::rustd_capability_name_to_num(cname.as_ptr()) };
            let Ok(number) = u32::try_from(number) else {
                continue;
            };
            if number < u64::BITS {
                mask |= 1u64 << number;
            }
        }
        mask
    }

    /// Resolve a security context from a parsed `[Service]` section.
    ///
    /// # Errors
    /// Returns an error if a named user/group cannot be resolved or a writable
    /// path exception is malformed or exceeds the transport bound.
    pub fn from_service(svc: &ServiceSection) -> anyhow::Result<Self> {
        let read_write_paths = validate_read_write_paths(&svc.read_write_paths)?;
        let context = Self {
            uid: resolve_user(&svc.user)?,
            gid: resolve_group(&svc.group)?,
            no_new_privileges: svc.no_new_privileges,
            private_tmp: svc.private_tmp,
            private_devices: svc.private_devices,
            private_network: svc.private_network,
            private_mounts: svc.private_mounts,
            protect_system: match svc.protect_system {
                ProtectSystem::No => PROTECT_SYSTEM_NO,
                ProtectSystem::Yes => PROTECT_SYSTEM_YES,
                ProtectSystem::Full => PROTECT_SYSTEM_FULL,
                ProtectSystem::Strict => PROTECT_SYSTEM_STRICT,
            },
            protect_home: match svc.protect_home {
                ProtectHome::No => PROTECT_HOME_NO,
                ProtectHome::Yes => PROTECT_HOME_YES,
                ProtectHome::ReadOnly => PROTECT_HOME_READ_ONLY,
                ProtectHome::Tmpfs => PROTECT_HOME_TMPFS,
            },
            protect_kernel_tunables: svc.protect_kernel_tunables,
            protect_kernel_modules: svc.protect_kernel_modules,
            protect_kernel_logs: svc.protect_kernel_logs,
            protect_clock: svc.protect_clock,
            protect_control_groups: svc.protect_control_groups,
            restrict_realtime: svc.restrict_realtime,
            restrict_suid_sgid: svc.restrict_suid_sgid,
            restrict_namespaces: svc.restrict_namespaces,
            memory_deny_write_execute: svc.memory_deny_write_execute,
            cap_bounding_set: Self::parse_cap_list(&svc.capability_bounding_set),
            ambient_caps: if svc.ambient_capabilities.is_empty() {
                0
            } else {
                Self::parse_cap_list(&svc.ambient_capabilities)
            },
            read_write_paths,
        };
        SPAWN_READ_WRITE_PATHS.with(|paths| {
            paths.borrow_mut().clone_from(&context.read_write_paths);
        });
        Ok(context)
    }

    /// Apply the security context in the child process (legacy direct path).
    ///
    /// # Errors
    /// Returns an error if a required writable exception cannot be realized.
    pub fn apply_in_child(&self) -> anyhow::Result<()> {
        use crate::ffi::sandbox::{
            rustd_sandbox_make_writable_paths, rustd_sandbox_mount_namespaces,
            rustd_sandbox_no_new_privs, rustd_sandbox_protect_paths,
            rustd_sandbox_restrict_realtime,
        };
        use crate::ffi::seccomp::{
            rustd_seccomp_memory_deny_write_execute, rustd_seccomp_protect_clock,
            rustd_seccomp_protect_kernel_logs, rustd_seccomp_restrict_namespaces,
        };

        if self.no_new_privileges {
            let rc = unsafe { rustd_sandbox_no_new_privs() };
            if rc < 0 {
                return Err(anyhow!("PR_SET_NO_NEW_PRIVS failed: errno {}", -rc));
            }
        }

        let needs_ns = self.private_tmp
            || self.private_devices
            || self.private_mounts
            || self.protect_system != PROTECT_SYSTEM_NO
            || self.protect_home != PROTECT_HOME_NO
            || self.protect_kernel_tunables
            || self.protect_kernel_modules
            || self.protect_kernel_logs
            || self.protect_clock
            || self.protect_control_groups
            || self.restrict_suid_sgid
            || !self.read_write_paths.is_empty();

        if needs_ns || self.private_network {
            let rc = unsafe {
                rustd_sandbox_mount_namespaces(
                    libc::c_int::from(self.private_tmp),
                    libc::c_int::from(self.private_devices),
                    libc::c_int::from(self.private_network),
                    libc::c_int::from(self.protect_system),
                    libc::c_int::from(self.protect_home),
                    libc::c_int::from(needs_ns),
                )
            };
            if rc < 0 {
                return Err(anyhow!("mount namespace setup failed: errno {}", -rc));
            }
        }

        if !self.read_write_paths.is_empty() {
            let strings = self
                .read_write_paths
                .iter()
                .map(|path| CString::new(path.as_str()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| anyhow!("ReadWritePaths= entry contains a NUL byte"))?;
            let pointers = strings.iter().map(|path| path.as_ptr()).collect::<Vec<_>>();
            let rc = unsafe { rustd_sandbox_make_writable_paths(pointers.as_ptr(), pointers.len()) };
            if rc < 0 {
                return Err(anyhow!("ReadWritePaths= setup failed: errno {}", -rc));
            }
        }

        if self.protect_kernel_tunables
            || self.protect_kernel_modules
            || self.protect_kernel_logs
            || self.protect_clock
            || self.protect_control_groups
            || self.restrict_suid_sgid
        {
            let rc = unsafe {
                rustd_sandbox_protect_paths(
                    libc::c_int::from(self.protect_kernel_tunables),
                    libc::c_int::from(self.protect_kernel_modules),
                    libc::c_int::from(self.protect_kernel_logs),
                    libc::c_int::from(self.protect_clock),
                    libc::c_int::from(self.protect_control_groups),
                    libc::c_int::from(self.restrict_suid_sgid),
                )
            };
            if rc < 0 {
                return Err(anyhow!("sandbox path protection failed: errno {}", -rc));
            }
        }

        if self.restrict_realtime {
            let rc = unsafe { rustd_sandbox_restrict_realtime() };
            if rc < 0 {
                eprintln!("sandbox: restrict realtime failed (errno {})", -rc);
            }
        }

        if self.memory_deny_write_execute {
            let rc = unsafe { rustd_seccomp_memory_deny_write_execute() };
            if rc < 0 {
                eprintln!(
                    "sandbox: MemoryDenyWriteExecute filter failed (errno {})",
                    -rc
                );
            }
        }

        if self.restrict_namespaces {
            let rc = unsafe { rustd_seccomp_restrict_namespaces(0) };
            if rc < 0 {
                eprintln!("sandbox: RestrictNamespaces filter failed (errno {})", -rc);
            }
        }

        if self.protect_kernel_logs {
            let rc = unsafe { rustd_seccomp_protect_kernel_logs() };
            if rc < 0 {
                eprintln!("sandbox: ProtectKernelLogs filter failed (errno {})", -rc);
            }
        }

        if self.protect_clock {
            let rc = unsafe { rustd_seccomp_protect_clock() };
            if rc < 0 {
                eprintln!("sandbox: ProtectClock filter failed (errno {})", -rc);
            }
        }

        Ok(())
    }
}

/// Resolve a user name or decimal UID.
///
/// # Errors
/// Returns an error when `user` contains an interior NUL byte or does not name
/// an existing account.
pub fn resolve_user(user: &str) -> anyhow::Result<libc::uid_t> {
    if user.is_empty() {
        #[allow(clippy::cast_sign_loss)]
        return Ok(u32::MAX as libc::uid_t);
    }
    if let Ok(n) = user.parse::<u32>() {
        return Ok(n as libc::uid_t);
    }
    let name = CString::new(user).map_err(|e| anyhow!("user name NUL: {e}"))?;
    let pw = unsafe { libc::getpwnam(name.as_ptr()) };
    if pw.is_null() {
        return Err(anyhow!("user '{user}' not found"));
    }
    Ok(unsafe { (*pw).pw_uid })
}

/// Resolve a group name or decimal GID.
///
/// # Errors
/// Returns an error when `group` contains an interior NUL byte or does not name
/// an existing group.
pub fn resolve_group(group: &str) -> anyhow::Result<libc::gid_t> {
    if group.is_empty() {
        #[allow(clippy::cast_sign_loss)]
        return Ok(u32::MAX as libc::gid_t);
    }
    if let Ok(n) = group.parse::<u32>() {
        return Ok(n as libc::gid_t);
    }
    let name = CString::new(group).map_err(|e| anyhow!("group name NUL: {e}"))?;
    let gr = unsafe { libc::getgrnam(name.as_ptr()) };
    if gr.is_null() {
        return Err(anyhow!("group '{group}' not found"));
    }
    Ok(unsafe { (*gr).gr_gid })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_root_user() {
        assert_eq!(resolve_user("root").unwrap(), 0);
        assert_eq!(resolve_user("0").unwrap(), 0);
    }

    #[test]
    fn resolve_empty_user_returns_minus1() {
        assert_eq!(resolve_user("").unwrap(), u32::MAX as libc::uid_t);
    }

    #[test]
    fn resolve_nonexistent_user_errors() {
        assert!(resolve_user("__no_such_user_xyz__").is_err());
    }

    #[test]
    fn resolve_root_group() {
        assert_eq!(resolve_group("root").unwrap(), 0);
    }

    #[test]
    fn mount_isolation_controls_are_resolved() {
        let service = ServiceSection {
            private_mounts: true,
            protect_control_groups: true,
            ..Default::default()
        };
        let context = SecurityContext::from_service(&service).unwrap();
        assert!(context.private_mounts);
        assert!(context.protect_control_groups);
    }

    #[test]
    fn read_write_paths_are_validated_and_staged() {
        let service = ServiceSection {
            read_write_paths: vec!["/var/lib/rustd".into(), "-/run/optional".into(), "/".into()],
            ..Default::default()
        };
        let context = SecurityContext::from_service(&service).unwrap();
        assert_eq!(context.read_write_paths, service.read_write_paths);
        assert_eq!(take_spawn_read_write_paths(), service.read_write_paths);

        let invalid = ServiceSection {
            read_write_paths: vec!["relative/path".into()],
            ..Default::default()
        };
        assert!(SecurityContext::from_service(&invalid).is_err());
    }

    #[test]
    fn security_context_defaults() {
        let ctx = SecurityContext::default();
        assert!(!ctx.no_new_privileges);
        assert!(!ctx.private_tmp);
        assert_eq!(ctx.protect_system, PROTECT_SYSTEM_NO);
        assert!(ctx.read_write_paths.is_empty());
    }
}
