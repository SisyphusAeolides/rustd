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
use std::os::unix::ffi::OsStrExt;
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
    let desired_enforcing = selinux_mode(&config).map_or(true, |mode| mode == "enforcing");
    if !Path::new("/sys/fs/selinux").exists()
        // Dracut's SELinux module completed the handoff before switch-root.
        || Path::new("/sys/fs/selinux/enforce").exists()
    {
        if Path::new("/sys/fs/selinux/enforce").exists() {
            set_enforcing(desired_enforcing)?;
        }
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
    set_enforcing(desired_enforcing)?;
    eprintln!(
        "rustd: loaded initial SELinux policy ({})",
        if desired_enforcing && enforcing != 0 {
            "enforcing"
        } else {
            "permissive"
        }
    );
    Ok(())
}

/// Restore SELinux labels for one path using libselinux's policy-aware API.
///
/// RustD cannot rely on systemd-udevd's label restoration because RustD owns
/// the udev daemon on a system-free Fedora installation. Resolve the symbol at
/// runtime so the binary remains usable on non-SELinux systems.
///
/// # Errors
/// Returns an error if the path contains a NUL byte, libselinux cannot be
/// loaded, the restorecon symbol cannot be resolved, or relabeling fails.
pub fn restorecon_path(path: &Path) -> anyhow::Result<()> {
    if !Path::new("/sys/fs/selinux/enforce").exists() {
        return Ok(());
    }
    let c_path = CString::new(path.as_os_str().as_bytes())
        .with_context(|| format!("SELinux path contains NUL: {}", path.display()))?;
    let library = CString::new("libselinux.so.1")?;
    let symbol = CString::new("selinux_restorecon")?;
    // Safety: the C strings are NUL-terminated and the returned handle is
    // closed after the function pointer call completes.
    let handle = unsafe { libc::dlopen(library.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    if handle.is_null() {
        return Err(anyhow!(dl_error("open libselinux for restorecon")));
    }
    // Safety: `handle` remains open while the resolved function is called.
    let raw = unsafe { libc::dlsym(handle, symbol.as_ptr()) };
    if raw.is_null() {
        unsafe { libc::dlclose(handle) };
        return Err(anyhow!(dl_error("resolve selinux_restorecon")));
    }
    type Restorecon = unsafe extern "C" fn(*const libc::c_char, libc::c_uint) -> libc::c_int;
    // Safety: `raw` is the documented libselinux `selinux_restorecon` ABI;
    // `c_path` remains alive for the duration of the call.
    let restorecon: Restorecon = unsafe { std::mem::transmute(raw) };
    let result = unsafe { restorecon(c_path.as_ptr(), 0) };
    let error = if result < 0 {
        Some(io::Error::last_os_error())
    } else {
        None
    };
    unsafe { libc::dlclose(handle) };
    if let Some(error) = error {
        return Err(error).with_context(|| format!("restore SELinux label on {}", path.display()));
    }
    Ok(())
}

/// Restore labels for a path and its descendants without following symlinks.
///
/// The recursive walk intentionally lives here instead of depending on the
/// external `restorecon` command: RustD's PID 1 and udev daemon must be able to
/// perform this operation during early boot with only libselinux available.
///
/// # Errors
/// Returns an error if a path cannot be labeled or its directory entries
/// cannot be read.
pub fn restorecon_tree(path: &Path) -> anyhow::Result<()> {
    restorecon_path(path)?;
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).with_context(|| format!("stat {}", path.display())),
    };
    if !metadata.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(path).with_context(|| format!("read {}", path.display()))? {
        let entry = entry?;
        // Live-media userspace exposes the immutable lower root under
        // `/run/rootfsbase`.  Do not descend into nested mounts: relabeling
        // their contents is both incorrect for the owning filesystem and can
        // turn early boot into a multi-minute read-only tree walk.
        if crate::mount_setup::is_mount_point(&entry.path()) {
            continue;
        }
        restorecon_tree(&entry.path())?;
    }
    Ok(())
}

fn set_enforcing(enforcing: bool) -> anyhow::Result<()> {
    let library = CString::new("libselinux.so.1")?;
    let symbol = CString::new("security_setenforce")?;
    // Safety: `library` is NUL-terminated and the returned handle is used only
    // with `dlsym`/`dlclose` below.
    let handle = unsafe { libc::dlopen(library.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    if handle.is_null() {
        return Err(anyhow!(dl_error("open libselinux for enforcement")));
    }
    // Safety: the symbol name is NUL-terminated and libselinux documents this
    // exact C ABI.  The library stays open until after the call returns.
    let raw = unsafe { libc::dlsym(handle, symbol.as_ptr()) };
    if raw.is_null() {
        unsafe { libc::dlclose(handle) };
        return Err(anyhow!(dl_error("resolve security_setenforce")));
    }
    type SetEnforce = unsafe extern "C" fn(libc::c_int) -> libc::c_int;
    // Safety: `raw` is the documented `security_setenforce` symbol.
    let security_setenforce: SetEnforce = unsafe { std::mem::transmute(raw) };
    let result = unsafe { security_setenforce(i32::from(enforcing)) };
    let error = if result < 0 {
        Some(io::Error::last_os_error())
    } else {
        None
    };
    // Safety: `handle` was returned by `dlopen` above and no function pointer
    // from it is retained after this point.
    unsafe { libc::dlclose(handle) };
    if let Some(error) = error {
        return Err(error).context("set SELinux enforcement mode");
    }
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

fn selinux_mode(config: &str) -> Option<&str> {
    config.lines().find_map(|line| {
        let line = line.trim();
        if line.starts_with('#') {
            return None;
        }
        let (key, value) = line.split_once('=')?;
        (key.trim() == "SELINUX").then_some(value.trim())
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

    #[test]
    fn selinux_mode_ignores_comments_and_whitespace() {
        assert_eq!(
            selinux_mode("# SELINUX=permissive\n SELINUX = enforcing\n"),
            Some("enforcing")
        );
        assert_eq!(selinux_mode("SELINUX=disabled\n"), Some("disabled"));
    }
}
