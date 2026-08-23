// SPDX-License-Identifier: LGPL-2.1-or-later
//! Compile `SystemCallFilter=` assignments into native seccomp rules.

use std::collections::BTreeMap;
use std::ffi::CString;

use anyhow::{anyhow, bail};

use crate::ffi::seccomp::{
    rustd_seccomp_syscall_is_known, rustd_seccomp_syscall_resolve_name, SdSeccompRule,
    SECCOMP_ACTION_ALLOW, SECCOMP_ACTION_ERRNO, SECCOMP_ACTION_KILL_PROCESS,
};
use crate::seccomp_groups::group;
use crate::unit::section_service::{ServiceSection, ServiceType, SystemCallFilterAssignment};

const MAX_KNOWN_SYSCALL_NR: i32 = 8191;

#[derive(Debug, Clone)]
pub(crate) struct CompiledSyscallFilter {
    pub(crate) rules: Vec<SdSeccompRule>,
    pub(crate) default_action: u32,
}

#[must_use]
pub(crate) fn valid_error_number(value: &str) -> bool {
    value.is_empty() || value == "kill" || errno_number(value).is_some()
}

fn errno_action(error: i32) -> u32 {
    SECCOMP_ACTION_ERRNO | u32::try_from(error).expect("positive Linux errno")
}

fn negative_action(value: &str) -> anyhow::Result<u32> {
    if value.is_empty() || value == "kill" {
        return Ok(SECCOMP_ACTION_KILL_PROCESS);
    }
    errno_number(value)
        .map(errno_action)
        .ok_or_else(|| anyhow!("invalid SystemCallErrorNumber={value}"))
}

#[allow(clippy::too_many_lines)]
pub(crate) fn errno_number(value: &str) -> Option<i32> {
    if let Ok(number) = value.parse::<i32>() {
        return (number > 0 && number <= 4095).then_some(number);
    }
    Some(match value {
        "EPERM" => libc::EPERM,
        "ENOENT" => libc::ENOENT,
        "ESRCH" => libc::ESRCH,
        "EINTR" => libc::EINTR,
        "EIO" => libc::EIO,
        "ENXIO" => libc::ENXIO,
        "E2BIG" => libc::E2BIG,
        "ENOEXEC" => libc::ENOEXEC,
        "EBADF" => libc::EBADF,
        "ECHILD" => libc::ECHILD,
        "EAGAIN" | "EWOULDBLOCK" => libc::EAGAIN,
        "ENOMEM" => libc::ENOMEM,
        "EACCES" => libc::EACCES,
        "EFAULT" => libc::EFAULT,
        "EBUSY" => libc::EBUSY,
        "EEXIST" => libc::EEXIST,
        "EXDEV" => libc::EXDEV,
        "ENODEV" => libc::ENODEV,
        "ENOTDIR" => libc::ENOTDIR,
        "EISDIR" => libc::EISDIR,
        "EINVAL" => libc::EINVAL,
        "ENFILE" => libc::ENFILE,
        "EMFILE" => libc::EMFILE,
        "ENOTTY" => libc::ENOTTY,
        "EFBIG" => libc::EFBIG,
        "ENOSPC" => libc::ENOSPC,
        "ESPIPE" => libc::ESPIPE,
        "EROFS" => libc::EROFS,
        "EMLINK" => libc::EMLINK,
        "EPIPE" => libc::EPIPE,
        "EDOM" => libc::EDOM,
        "ERANGE" => libc::ERANGE,
        "EDEADLK" => libc::EDEADLK,
        "ENAMETOOLONG" => libc::ENAMETOOLONG,
        "ENOLCK" => libc::ENOLCK,
        "ENOSYS" => libc::ENOSYS,
        "ENOTEMPTY" => libc::ENOTEMPTY,
        "ELOOP" => libc::ELOOP,
        "ENOMSG" => libc::ENOMSG,
        "EIDRM" => libc::EIDRM,
        "ENOSTR" => libc::ENOSTR,
        "ENODATA" => libc::ENODATA,
        "ETIME" => libc::ETIME,
        "ENOSR" => libc::ENOSR,
        "ENONET" => libc::ENONET,
        "EREMOTE" => libc::EREMOTE,
        "ENOLINK" => libc::ENOLINK,
        "EPROTO" => libc::EPROTO,
        "EMULTIHOP" => libc::EMULTIHOP,
        "EBADMSG" => libc::EBADMSG,
        "EOVERFLOW" => libc::EOVERFLOW,
        "EILSEQ" => libc::EILSEQ,
        "EUSERS" => libc::EUSERS,
        "ENOTSOCK" => libc::ENOTSOCK,
        "EDESTADDRREQ" => libc::EDESTADDRREQ,
        "EMSGSIZE" => libc::EMSGSIZE,
        "EPROTOTYPE" => libc::EPROTOTYPE,
        "ENOPROTOOPT" => libc::ENOPROTOOPT,
        "EPROTONOSUPPORT" => libc::EPROTONOSUPPORT,
        "EOPNOTSUPP" | "ENOTSUP" => libc::EOPNOTSUPP,
        "EAFNOSUPPORT" => libc::EAFNOSUPPORT,
        "EADDRINUSE" => libc::EADDRINUSE,
        "EADDRNOTAVAIL" => libc::EADDRNOTAVAIL,
        "ENETDOWN" => libc::ENETDOWN,
        "ENETUNREACH" => libc::ENETUNREACH,
        "ENETRESET" => libc::ENETRESET,
        "ECONNABORTED" => libc::ECONNABORTED,
        "ECONNRESET" => libc::ECONNRESET,
        "ENOBUFS" => libc::ENOBUFS,
        "EISCONN" => libc::EISCONN,
        "ENOTCONN" => libc::ENOTCONN,
        "ETIMEDOUT" => libc::ETIMEDOUT,
        "ECONNREFUSED" => libc::ECONNREFUSED,
        "EHOSTUNREACH" => libc::EHOSTUNREACH,
        "EALREADY" => libc::EALREADY,
        "EINPROGRESS" => libc::EINPROGRESS,
        "ESTALE" => libc::ESTALE,
        "EDQUOT" => libc::EDQUOT,
        "ECANCELED" => libc::ECANCELED,
        "ENOKEY" => libc::ENOKEY,
        "EKEYEXPIRED" => libc::EKEYEXPIRED,
        "EKEYREVOKED" => libc::EKEYREVOKED,
        "EKEYREJECTED" => libc::EKEYREJECTED,
        "EOWNERDEAD" => libc::EOWNERDEAD,
        "ENOTRECOVERABLE" => libc::ENOTRECOVERABLE,
        "ERFKILL" => libc::ERFKILL,
        "EHWPOISON" => libc::EHWPOISON,
        _ => return None,
    })
}

fn resolve_name(name: &str) -> anyhow::Result<Option<i32>> {
    let name = CString::new(name).map_err(|_| anyhow!("syscall name contains NUL"))?;
    let mut nr = -1;
    // Safety: both pointers are valid for this call.
    let rc = unsafe { rustd_seccomp_syscall_resolve_name(name.as_ptr(), &mut nr) };
    if rc == 0 {
        return Ok(Some(nr));
    }
    if rc == -libc::ENOENT {
        return Ok(None);
    }
    Err(anyhow!(
        "native libseccomp syscall resolver unavailable: errno {}",
        -rc
    ))
}

fn visit_filter_name(
    name: &str,
    depth: usize,
    callback: &mut impl FnMut(i32),
) -> anyhow::Result<()> {
    if depth > 32 {
        bail!("SystemCallFilter group recursion is too deep");
    }
    if name == "@__known_native__" {
        for nr in 0..=MAX_KNOWN_SYSCALL_NR {
            // Safety: numeric query has no pointer arguments.
            let rc = unsafe { rustd_seccomp_syscall_is_known(nr) };
            match rc.cmp(&0) {
                std::cmp::Ordering::Greater => callback(nr),
                std::cmp::Ordering::Less => {
                    return Err(anyhow!(
                        "native libseccomp syscall enumeration unavailable: errno {}",
                        -rc
                    ));
                }
                std::cmp::Ordering::Equal => {}
            }
        }
        return Ok(());
    }
    if name.starts_with('@') {
        if let Some(items) = group(name) {
            for item in items {
                visit_filter_name(item, depth + 1, callback)?;
            }
        }
        return Ok(());
    }
    if let Some(nr) = resolve_name(name)? {
        callback(nr);
    }
    Ok(())
}

fn split_item(item: &str) -> (&str, Option<u32>) {
    let Some((name, error)) = item.rsplit_once(':') else {
        return (item, None);
    };
    let action = if error == "kill" {
        Some(SECCOMP_ACTION_KILL_PROCESS)
    } else {
        errno_number(error).map(errno_action)
    };
    (name, action)
}

fn apply_assignment(
    rules: &mut BTreeMap<i32, u32>,
    assignment: &SystemCallFilterAssignment,
    allow_list: bool,
    negative: u32,
) -> anyhow::Result<()> {
    for item in &assignment.items {
        let (name, explicit_action) = split_item(item);
        if item.contains(':') && explicit_action.is_none() {
            continue;
        }
        if !assignment.invert && explicit_action.is_some() {
            continue;
        }

        let insert = (assignment.invert != allow_list)
            || (assignment.invert && allow_list && explicit_action.is_some());
        let action = if allow_list {
            explicit_action.unwrap_or(SECCOMP_ACTION_ALLOW)
        } else {
            explicit_action.unwrap_or(negative)
        };

        visit_filter_name(name, 0, &mut |nr| {
            if insert {
                rules.insert(nr, action);
            } else {
                rules.remove(&nr);
            }
        })?;
    }
    Ok(())
}

pub(crate) fn restrict_native_architectures(section: &ServiceSection) -> anyhow::Result<bool> {
    if section.system_call_architectures.is_empty() {
        return Ok(false);
    }
    if section
        .system_call_architectures
        .iter()
        .any(|architecture| architecture != "native")
    {
        bail!("only SystemCallArchitectures=native is currently supported");
    }
    Ok(true)
}

pub(crate) fn compile_syscall_filter(
    section: &ServiceSection,
) -> anyhow::Result<Option<CompiledSyscallFilter>> {
    let Some(first) = section.system_call_filter.first() else {
        return Ok(None);
    };

    let _ = restrict_native_architectures(section)?;

    let allow_list = !first.invert;
    let negative = negative_action(&section.system_call_error_number)?;
    let mut rules = BTreeMap::new();

    if allow_list {
        let defaults = SystemCallFilterAssignment {
            invert: false,
            items: vec!["@default".to_owned()],
        };
        apply_assignment(&mut rules, &defaults, true, negative)?;
    }

    for assignment in &section.system_call_filter {
        apply_assignment(&mut rules, assignment, allow_list, negative)?;
    }

    if allow_list && section.service_type == ServiceType::Exec {
        if let Some(write_nr) = resolve_name("write")? {
            rules.insert(write_nr, SECCOMP_ACTION_ALLOW);
        }
    }

    Ok(Some(CompiledSyscallFilter {
        rules: rules
            .into_iter()
            .map(|(nr, action)| SdSeccompRule { nr, action })
            .collect(),
        default_action: if allow_list {
            negative
        } else {
            SECCOMP_ACTION_ALLOW
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule_action(filter: &CompiledSyscallFilter, name: &str) -> Option<u32> {
        let nr = resolve_name(name).unwrap().unwrap();
        filter
            .rules
            .iter()
            .find(|rule| rule.nr == nr)
            .map(|rule| rule.action)
    }

    #[test]
    fn deny_list_uses_global_and_per_syscall_errno() {
        let mut section = ServiceSection::default();
        section.apply("SystemCallErrorNumber", "EPERM");
        section.apply("SystemCallFilter", "~getpid getppid:EACCES");
        let filter = compile_syscall_filter(&section).unwrap().unwrap();
        assert!(filter.rules.iter().all(|rule| rule.nr >= 0));
        assert_eq!(filter.default_action, SECCOMP_ACTION_ALLOW);
        assert_eq!(
            rule_action(&filter, "getpid"),
            Some(errno_action(libc::EPERM))
        );
        assert_eq!(
            rule_action(&filter, "getppid"),
            Some(errno_action(libc::EACCES))
        );
    }

    #[test]
    fn allow_list_is_seeded_with_default_and_can_remove_or_errno() {
        let mut section = ServiceSection::default();
        section.apply("SystemCallFilter", "getppid");
        section.apply("SystemCallFilter", "~getppid:EACCES");
        let filter = compile_syscall_filter(&section).unwrap().unwrap();
        assert_eq!(filter.default_action, SECCOMP_ACTION_KILL_PROCESS);
        assert_eq!(rule_action(&filter, "getpid"), Some(SECCOMP_ACTION_ALLOW));
        assert_eq!(
            rule_action(&filter, "getppid"),
            Some(errno_action(libc::EACCES))
        );
    }

    #[test]
    fn system_service_group_expands_to_a_large_native_policy() {
        let mut section = ServiceSection::default();
        section.apply("SystemCallErrorNumber", "EPERM");
        section.apply("SystemCallFilter", "@system-service");
        section.apply("SystemCallArchitectures", "native");
        let filter = compile_syscall_filter(&section).unwrap().unwrap();
        assert!(filter.rules.len() > 100);
        assert_eq!(rule_action(&filter, "read"), Some(SECCOMP_ACTION_ALLOW));
        assert_eq!(rule_action(&filter, "write"), Some(SECCOMP_ACTION_ALLOW));
    }

    #[test]
    fn chronyd_deny_groups_install_as_a_native_filter() {
        let mut section = ServiceSection::default();
        section.apply(
            "SystemCallFilter",
            "~@cpu-emulation @debug @module @mount @obsolete @raw-io @reboot @swap",
        );
        section.apply(
            "CapabilityBoundingSet",
            "~CAP_AUDIT_CONTROL CAP_AUDIT_READ CAP_AUDIT_WRITE CAP_BLOCK_SUSPEND CAP_KILL CAP_LEASE CAP_LINUX_IMMUTABLE CAP_MAC_ADMIN CAP_MAC_OVERRIDE CAP_MKNOD CAP_SYS_ADMIN CAP_SYS_BOOT CAP_SYS_CHROOT CAP_SYS_MODULE CAP_SYS_PACCT CAP_SYS_PTRACE CAP_SYS_RAWIO CAP_SYS_TTY_CONFIG CAP_WAKE_ALARM",
        );
        let bounding_set = crate::sandbox::SecurityContext::from_service(&section)
            .unwrap()
            .cap_bounding_set;
        let filter = compile_syscall_filter(&section).unwrap().unwrap();
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let setup = [
                unsafe { crate::ffi::seccomp::rustd_seccomp_memory_deny_write_execute() },
                unsafe { crate::ffi::seccomp::rustd_seccomp_restrict_namespaces(0) },
                unsafe { crate::ffi::seccomp::rustd_seccomp_protect_kernel_logs() },
                unsafe { crate::ffi::seccomp::rustd_seccomp_restrict_native_architecture() },
            ];
            if let Some(index) = setup.iter().position(|result| *result < 0) {
                unsafe { libc::_exit(100 + index as i32) };
            }
            let result = unsafe {
                crate::ffi::seccomp::rustd_seccomp_syscall_rules(
                    filter.rules.as_ptr(),
                    filter.rules.len(),
                    filter.default_action,
                )
            };
            unsafe { libc::_exit(if result == 0 { 0 } else { -result }) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);

        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        crate::ffi::spawn::configure_spawn_helper_from_self().unwrap();
        let executable = CString::new("/bin/true").unwrap();
        let argument = CString::new("true").unwrap();
        let argv = [argument.as_ptr(), std::ptr::null()];
        let sandbox = crate::ffi::spawn::SdSpawnSandbox {
            no_new_privs: 1,
            private_tmp: 1,
            protect_system: 3,
            protect_home: 1,
            protect_kernel_tunables: 1,
            protect_kernel_modules: 1,
            memory_deny_write_execute: 1,
            restrict_namespaces: 1,
            protect_kernel_logs: 1,
            protect_control_groups: 1,
            restrict_suid_sgid: 1,
            restrict_native_syscalls: 1,
            syscall_filter_rules: filter.rules.as_ptr(),
            n_syscall_filter_rules: filter.rules.len(),
            syscall_filter_default_action: filter.default_action,
            syscall_filter_enabled: 1,
            ..Default::default()
        };
        let params = crate::ffi::spawn::SdSpawnParams {
            path: executable.as_ptr(),
            argv: argv.as_ptr(),
            envp: std::ptr::null(),
            cwd: std::ptr::null(),
            cgroup_procs_path: std::ptr::null(),
            rlimits: std::ptr::null(),
            n_rlimits: 0,
            uid: libc::uid_t::MAX,
            gid: libc::gid_t::MAX,
            selinux_context: std::ptr::null(),
            selinux_context_ignore: 0,
            apparmor_profile: std::ptr::null(),
            apparmor_profile_ignore: 0,
            stdin_fd: -1,
            stdout_fd: -1,
            stderr_fd: -1,
            notify_fd: -1,
            watchdog_usec: 0,
            sandbox: std::ptr::addr_of!(sandbox),
            listen_fds: std::ptr::null(),
            n_listen_fds: 0,
            cap_bounding_set: bounding_set,
            ambient_caps: 0,
            wait_for_exec: 1,
            idle_read_fd: -1,
            idle_write_fd: -1,
        };
        let spawned = unsafe { crate::ffi::spawn::rustd_spawn(std::ptr::addr_of!(params)) };
        assert!(
            spawned > 0,
            "chronyd-like spawn transport failed: {spawned}"
        );
        assert_eq!(unsafe { libc::waitpid(spawned, &mut status, 0) }, spawned);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }
}
