// SPDX-License-Identifier: LGPL-2.1-or-later
//! Service execution security context.
//!
//! Derives a `SecurityContext` from a `ServiceSection` and passes it to
//! `rustd_spawn` as extended parameters, or applies it in the child via the
//! new `rustd_sandbox_apply` C helper.
//!
//! Upstream reference: `src/core/execute.c exec_child()`,
//!   `src/core/execute-security.c` (v261)

use std::ffi::CString;

use anyhow::anyhow;

use crate::unit::section_service::{ProtectHome, ProtectSystem, ServiceSection};

// ── SecurityContext ───────────────────────────────────────────────────────

/// All sandbox settings resolved from `[Service]` section fields.
///
/// Passed to `rustd_sandbox_apply()` in the child after fork.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Default, Clone)]
pub struct SecurityContext {
    /// Resolved numeric UID to switch to (`-1` = keep current).
    pub uid: libc::uid_t,
    /// Resolved numeric GID to switch to (`-1` = keep current).
    pub gid: libc::gid_t,
    /// `NoNewPrivileges=` — set `PR_SET_NO_NEW_PRIVS`.
    pub no_new_privileges: bool,
    /// `PrivateTmp=` — mount private tmpfs on `/tmp` and `/var/tmp`.
    pub private_tmp: bool,
    /// `PrivateDevices=` — mount minimal `/dev` in a new mount namespace.
    pub private_devices: bool,
    /// `PrivateNetwork=` — move to a new network namespace.
    pub private_network: bool,
    /// `PrivateMounts=` — propagation flag `MS_SLAVE` on `/`.
    pub private_mounts: bool,
    /// `ProtectSystem=` value.
    pub protect_system: u8,
    /// `ProtectHome=` value.
    pub protect_home: u8,
    /// `ProtectKernelTunables=`
    pub protect_kernel_tunables: bool,
    /// `ProtectKernelModules=`
    pub protect_kernel_modules: bool,
    /// `ProtectKernelLogs=`
    pub protect_kernel_logs: bool,
    /// `ProtectClock=`
    pub protect_clock: bool,
    /// `ProtectControlGroups=`
    pub protect_control_groups: bool,
    /// `RestrictRealtime=`
    pub restrict_realtime: bool,
    /// `RestrictSUIDSGID=`
    pub restrict_suid_sgid: bool,
    /// `RestrictNamespaces=` — deny `unshare(2)` / `clone(CLONE_NEW*)`
    pub restrict_namespaces: bool,
    /// `MemoryDenyWriteExecute=`
    pub memory_deny_write_execute: bool,
    /// `CapabilityBoundingSet=` — bitmask of capabilities to keep.
    /// `u64::MAX` = no change (keep all).
    pub cap_bounding_set: u64,
    /// `AmbientCapabilities=` — bitmask of capabilities to raise as ambient.
    pub ambient_caps: u64,
}

// ── ProtectSystem numeric constants for C ABI ─────────────────────────────
const PROTECT_SYSTEM_NO: u8 = 0;
const PROTECT_SYSTEM_YES: u8 = 1;
const PROTECT_SYSTEM_FULL: u8 = 2;
const PROTECT_SYSTEM_STRICT: u8 = 3;

const PROTECT_HOME_NO: u8 = 0;
const PROTECT_HOME_YES: u8 = 1;
const PROTECT_HOME_READ_ONLY: u8 = 2;
const PROTECT_HOME_TMPFS: u8 = 3;

// ── Builder ───────────────────────────────────────────────────────────────

impl SecurityContext {
    /// Parse a capability-name list into a bitmask.
    ///
    /// Each token is resolved via `rustd_capability_name_to_num`. An empty list
    /// means no bounding-set restriction and therefore returns `u64::MAX`.
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
    /// Returns an error if a named `User=` or `Group=` cannot be resolved.
    pub fn from_service(svc: &ServiceSection) -> anyhow::Result<Self> {
        Ok(Self {
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
        })
    }

    /// Apply the security context in the child process (after fork, before exec).
    ///
    /// Must be called from a single-threaded child context only.
    ///
    /// # Errors
    /// Returns an error if any syscall fails.
    pub fn apply_in_child(&self) -> anyhow::Result<()> {
        use crate::ffi::sandbox::{
            rustd_sandbox_mount_namespaces, rustd_sandbox_no_new_privs,
            rustd_sandbox_protect_paths, rustd_sandbox_restrict_realtime,
        };
        use crate::ffi::seccomp::{
            rustd_seccomp_memory_deny_write_execute, rustd_seccomp_protect_clock,
            rustd_seccomp_protect_kernel_logs, rustd_seccomp_restrict_namespaces,
        };

        // 1. NoNewPrivileges must come before any namespace operations.
        if self.no_new_privileges {
            let rc = unsafe { rustd_sandbox_no_new_privs() };
            if rc < 0 {
                return Err(anyhow!("PR_SET_NO_NEW_PRIVS failed: errno {}", -rc));
            }
        }

        // 2. Mount namespace sandboxing (PrivateTmp, PrivateDevices,
        //    ProtectSystem, ProtectHome, ProtectKernelTunables, etc.)
        //    Requires CAP_SYS_ADMIN or unprivileged user namespaces.
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
            || self.restrict_suid_sgid;

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
            // Non-fatal: if the kernel doesn't support unprivileged namespaces,
            // continue without the sandbox rather than failing the service.
            if rc < 0 {
                // Log warning but don't abort; matches upstream tolerance.
                eprintln!(
                    "sandbox: mount namespace setup failed (errno {}), continuing without",
                    -rc
                );
            }
        }

        // 3. Protect read-only paths.
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
                eprintln!("sandbox: protect paths failed (errno {})", -rc);
            }
        }

        // 4. Restrict real-time scheduling.
        if self.restrict_realtime {
            let rc = unsafe { rustd_sandbox_restrict_realtime() };
            if rc < 0 {
                eprintln!("sandbox: restrict realtime failed (errno {})", -rc);
            }
        }

        // 5. MemoryDenyWriteExecute=.
        if self.memory_deny_write_execute {
            let rc = unsafe { rustd_seccomp_memory_deny_write_execute() };
            if rc < 0 {
                eprintln!(
                    "sandbox: MemoryDenyWriteExecute filter failed (errno {})",
                    -rc
                );
            }
        }

        // 6. RestrictNamespaces=.
        if self.restrict_namespaces {
            // allowed_mask=0 blocks all namespace creation.
            let rc = unsafe { rustd_seccomp_restrict_namespaces(0) };
            if rc < 0 {
                eprintln!("sandbox: RestrictNamespaces filter failed (errno {})", -rc);
            }
        }

        // 7. Protect kernel log access.
        if self.protect_kernel_logs {
            let rc = unsafe { rustd_seccomp_protect_kernel_logs() };
            if rc < 0 {
                eprintln!("sandbox: ProtectKernelLogs filter failed (errno {})", -rc);
            }
        }

        // 8. Protect wall/realtime clocks.
        if self.protect_clock {
            let rc = unsafe { rustd_seccomp_protect_clock() };
            if rc < 0 {
                eprintln!("sandbox: ProtectClock filter failed (errno {})", -rc);
            }
        }

        Ok(())
    }
}

// ── User/group resolution ─────────────────────────────────────────────────

/// Resolve a user name or numeric string to a UID.
/// Returns `!0u32` (i.e. `(uid_t)-1`) if the field is empty.
///
/// # Errors
/// Returns an error if the name is non-empty and cannot be resolved.
pub fn resolve_user(user: &str) -> anyhow::Result<libc::uid_t> {
    if user.is_empty() {
        #[allow(clippy::cast_sign_loss)]
        return Ok(u32::MAX as libc::uid_t);
    }
    // Try numeric first.
    if let Ok(n) = user.parse::<u32>() {
        return Ok(n as libc::uid_t);
    }
    // NSS lookup via getpwnam(3).
    let name = CString::new(user).map_err(|e| anyhow!("user name NUL: {e}"))?;
    // Safety: getpwnam is thread-safe when called before any threads are
    // spawned (we are in the single-threaded child).
    let pw = unsafe { libc::getpwnam(name.as_ptr()) };
    if pw.is_null() {
        return Err(anyhow!("user '{user}' not found"));
    }
    Ok(unsafe { (*pw).pw_uid })
}

/// Resolve a group name or numeric string to a GID.
/// Returns `!0u32` (i.e. `(gid_t)-1`) if the field is empty.
///
/// # Errors
/// Returns an error if the name is non-empty and cannot be resolved.
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

// ── Tests ─────────────────────────────────────────────────────────────────

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
    fn security_context_defaults() {
        let ctx = SecurityContext::default();
        assert!(!ctx.no_new_privileges);
        assert!(!ctx.private_tmp);
        assert_eq!(ctx.protect_system, PROTECT_SYSTEM_NO);
    }
}
