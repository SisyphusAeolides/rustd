// SPDX-License-Identifier: LGPL-2.1-or-later
//! Initial SELinux policy loading for RustD PID 1.
//!
//! A kernel with SELinux compiled in starts without an active policy.  The
//! initramfs normally loads it before switch-root, but PID 1 must retain the
//! same fail-closed responsibility when it is invoked directly or an initramfs
//! omits that handoff.

use std::ffi::{CStr, CString};
use std::fs;
use std::io;
use std::path::Path;

use anyhow::{anyhow, Context};

const SELINUX_CONFIG: &str = "/etc/selinux/config";

/// Load the configured SELinux policy when SELinux is enabled for this host.
///
/// The policy loader is resolved at runtime so non-SELinux distributions can
/// use the same RustD binary.  An enabled Fedora/RHEL installation is
/// fail-closed: proceeding as an unlabeled PID 1 would silently downgrade the
/// host's mandatory access-control policy.
///
/// # Errors
/// Returns an error when configured SELinux policy loading cannot be completed.
pub fn load_initial_policy() -> anyhow::Result<()> {
    let config = match fs::read_to_string(SELINUX_CONFIG) {
        Ok(config) => config,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("read /etc/selinux/config"),
    };
    if selinux_disabled_in_config(&config) || selinux_disabled_on_kernel_command_line()? {
        return Ok(());
    }
    if !Path::new("/sys/fs/selinux").exists()
        // Dracut's SELinux module completed the handoff before switch-root.
        || Path::new("/sys/fs/selinux/enforce").exists()
    {
        return Ok(());
    }

    let library = CString::new("libselinux.so.1")?;
    let symbol = CString::new("selinux_init_load_policy")?;
    // Safety: `library` is NUL-terminated and the returned handle is used only
    // with `dlsym`/`dlclose` below.
    let handle = unsafe { libc::dlopen(library.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    if handle.is_null() {
        return Err(anyhow!(dl_error("open libselinux")));
    }

    // Safety: the symbol name is NUL-terminated and libselinux documents this
    // exact C ABI.  The library stays open until after the call returns.
    let raw = unsafe { libc::dlsym(handle, symbol.as_ptr()) };
    if raw.is_null() {
        // Safety: `handle` was returned by `dlopen` above.
        unsafe { libc::dlclose(handle) };
        return Err(anyhow!(dl_error("resolve selinux_init_load_policy")));
    }
    type InitLoadPolicy = unsafe extern "C" fn(*mut libc::c_int) -> libc::c_int;
    // Safety: `raw` is the documented `selinux_init_load_policy` symbol.
    let init_load_policy: InitLoadPolicy = unsafe { std::mem::transmute(raw) };
    let mut enforcing = 0;
    // Safety: `enforcing` is a valid writable `int` for the duration of call.
    let result = unsafe { init_load_policy(&mut enforcing) };
    if result < 0 {
        let error = io::Error::last_os_error();
        // Safety: `handle` was returned by `dlopen` above.
        unsafe { libc::dlclose(handle) };
        return Err(error).context("load initial SELinux policy");
    }
    // Safety: `handle` was returned by `dlopen` above and no function pointer
    // from it is retained after this point.
    unsafe { libc::dlclose(handle) };
    eprintln!(
        "rustd: loaded initial SELinux policy ({})",
        if enforcing != 0 {
            "enforcing"
        } else {
            "permissive"
        }
    );
    Ok(())
}

fn selinux_disabled_on_kernel_command_line() -> anyhow::Result<bool> {
    let command_line = fs::read_to_string("/proc/cmdline").context("read /proc/cmdline")?;
    Ok(command_line_disables_selinux(&command_line))
}

fn command_line_disables_selinux(command_line: &str) -> bool {
    command_line
        .split_ascii_whitespace()
        .any(|word| word == "selinux=0")
}

fn selinux_disabled_in_config(config: &str) -> bool {
    config.lines().any(|line| {
        let line = line.trim();
        !line.starts_with('#')
            && line
                .split_once('=')
                .is_some_and(|(key, value)| key.trim() == "SELINUX" && value.trim() == "disabled")
    })
}

fn dl_error(operation: &str) -> String {
    // Safety: `dlerror` returns either NULL or a NUL-terminated diagnostic
    // valid until the next dynamic-loader call on this thread.
    let error = unsafe { libc::dlerror() };
    if error.is_null() {
        format!("{operation}: dynamic loader returned no diagnostic")
    } else {
        // Safety: `dlerror` guarantees a NUL-terminated diagnostic string.
        let detail = unsafe { CStr::from_ptr(error) }.to_string_lossy();
        format!("{operation}: {detail}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_config_is_honored() {
        assert!(selinux_disabled_in_config("SELINUX=disabled\n"));
        assert!(selinux_disabled_in_config(
            " # comment\n SELINUX = disabled\n"
        ));
    }

    #[test]
    fn enforcing_and_permissive_configs_require_policy_loading() {
        assert!(!selinux_disabled_in_config("SELINUX=enforcing\n"));
        assert!(!selinux_disabled_in_config("SELINUX=permissive\n"));
        assert!(!selinux_disabled_in_config("# SELINUX=disabled\n"));
    }

    #[test]
    fn kernel_command_line_disables_selinux_only_with_zero_value() {
        assert!(command_line_disables_selinux("quiet selinux=0 audit=0"));
        assert!(!command_line_disables_selinux(
            "quiet selinux=1 enforcing=0"
        ));
    }
}
