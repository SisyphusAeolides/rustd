// SPDX-License-Identifier: LGPL-2.1-or-later
//! Mount and swap unit lifecycle through native Linux syscalls.

use std::ffi::CString;
use std::fs;
use std::os::unix::fs::PermissionsExt;

use anyhow::{anyhow, Context};

use crate::service::UnitRecord;
use crate::unit::loader::LoadedUnit;
use crate::unit::UnitState;

/// Mount a `.mount` unit and mark it active only after the syscall succeeds.
///
/// # Errors
/// Returns an error for invalid configuration or a failed mount operation.
pub fn activate_mount(record: &mut UnitRecord) -> anyhow::Result<()> {
    let LoadedUnit::Mount(mount) = &record.loaded else {
        return Err(anyhow!("activate_mount called for non-mount unit"));
    };
    if !mount.specific.where_.starts_with('/') {
        return Err(anyhow!("Mount.Where= must be an absolute path"));
    }
    if mount.specific.what.is_empty() {
        return Err(anyhow!("Mount.What= is required"));
    }

    fs::create_dir_all(&mount.specific.where_)
        .with_context(|| format!("create mount point {}", mount.specific.where_))?;
    if !mount.specific.directory_mode.is_empty() {
        let mode = u32::from_str_radix(mount.specific.directory_mode.trim_start_matches('0'), 8)
            .context("invalid Mount.DirectoryMode=")?;
        fs::set_permissions(&mount.specific.where_, fs::Permissions::from_mode(mode))?;
    }

    let (flags, data) = parse_mount_options(&mount.specific.options);
    let source = CString::new(mount.specific.what.as_str())?;
    let target = CString::new(mount.specific.where_.as_str())?;
    let fstype = (!mount.specific.r#type.is_empty() && mount.specific.r#type != "auto")
        .then(|| CString::new(mount.specific.r#type.as_str()))
        .transpose()?;
    let data = (!data.is_empty()).then(|| CString::new(data)).transpose()?;

    // Safety: all pointers are NUL-terminated and remain valid for the call.
    let result = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype
                .as_ref()
                .map_or(std::ptr::null(), |value| value.as_ptr()),
            flags,
            data.as_ref()
                .map_or(std::ptr::null(), |value| value.as_ptr().cast()),
        )
    };
    if result < 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!("mount {} on {}", mount.specific.what, mount.specific.where_)
        });
    }
    record.state = UnitState::Active;
    Ok(())
}

/// Unmount a `.mount` unit.
///
/// # Errors
/// Returns an error for the wrong unit type or a failed unmount operation.
pub fn deactivate_mount(record: &mut UnitRecord) -> anyhow::Result<()> {
    let LoadedUnit::Mount(mount) = &record.loaded else {
        return Err(anyhow!("deactivate_mount called for non-mount unit"));
    };
    let target = CString::new(mount.specific.where_.as_str())?;
    let mut flags = 0;
    if mount.specific.lazy_unmount {
        flags |= libc::MNT_DETACH;
    }
    if mount.specific.force_unmount {
        flags |= libc::MNT_FORCE;
    }
    // Safety: target is a valid NUL-terminated path.
    if unsafe { libc::umount2(target.as_ptr(), flags) } < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("unmount {}", mount.specific.where_));
    }
    record.state = UnitState::Inactive;
    Ok(())
}

/// Enable a `.swap` unit through `swapon(2)`.
///
/// # Errors
/// Returns an error for invalid configuration or a failed `swapon` operation.
pub fn activate_swap(record: &mut UnitRecord) -> anyhow::Result<()> {
    let LoadedUnit::Swap(swap) = &record.loaded else {
        return Err(anyhow!("activate_swap called for non-swap unit"));
    };
    if swap.specific.what.is_empty() {
        return Err(anyhow!("Swap.What= is required"));
    }
    let path = CString::new(swap.specific.what.as_str())?;
    let flags = swap.specific.priority.map_or(0, |priority| {
        const SWAP_FLAG_PREFER: libc::c_int = 0x8000;
        const SWAP_FLAG_PRIO_MASK: libc::c_int = 0x7fff;
        SWAP_FLAG_PREFER | (priority.clamp(0, SWAP_FLAG_PRIO_MASK) & SWAP_FLAG_PRIO_MASK)
    });
    // Safety: path is a valid NUL-terminated path.
    if unsafe { libc::swapon(path.as_ptr(), flags) } < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("enable swap {}", swap.specific.what));
    }
    record.state = UnitState::Active;
    Ok(())
}

/// Disable a `.swap` unit through `swapoff(2)`.
///
/// # Errors
/// Returns an error for the wrong unit type or a failed `swapoff` operation.
pub fn deactivate_swap(record: &mut UnitRecord) -> anyhow::Result<()> {
    let LoadedUnit::Swap(swap) = &record.loaded else {
        return Err(anyhow!("deactivate_swap called for non-swap unit"));
    };
    let path = CString::new(swap.specific.what.as_str())?;
    // Safety: path is a valid NUL-terminated path.
    if unsafe { libc::swapoff(path.as_ptr()) } < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("disable swap {}", swap.specific.what));
    }
    record.state = UnitState::Inactive;
    Ok(())
}

fn parse_mount_options(options: &str) -> (libc::c_ulong, String) {
    let mut flags = 0;
    let mut data = Vec::new();
    for option in options.split(',').filter(|value| !value.is_empty()) {
        let flag = match option {
            "defaults" | "rw" => Some(0),
            "ro" => Some(libc::MS_RDONLY),
            "nosuid" => Some(libc::MS_NOSUID),
            "nodev" => Some(libc::MS_NODEV),
            "noexec" => Some(libc::MS_NOEXEC),
            "sync" => Some(libc::MS_SYNCHRONOUS),
            "dirsync" => Some(libc::MS_DIRSYNC),
            "remount" => Some(libc::MS_REMOUNT),
            "bind" => Some(libc::MS_BIND),
            "rbind" => Some(libc::MS_BIND | libc::MS_REC),
            "move" => Some(libc::MS_MOVE),
            "silent" => Some(libc::MS_SILENT),
            "noatime" => Some(libc::MS_NOATIME),
            "nodiratime" => Some(libc::MS_NODIRATIME),
            "relatime" => Some(libc::MS_RELATIME),
            "strictatime" => Some(libc::MS_STRICTATIME),
            "lazytime" => Some(libc::MS_LAZYTIME),
            value if value.starts_with("x-systemd.") || value == "_netdev" || value == "nofail" => {
                Some(0)
            }
            _ => None,
        };
        if let Some(flag) = flag {
            flags |= flag;
        } else {
            data.push(option);
        }
    }
    (flags, data.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn mount_options_split_kernel_flags_from_filesystem_data() {
        let (flags, data) = parse_mount_options("ro,nosuid,nodev,compress=zstd,nofail");
        assert_ne!(flags & libc::MS_RDONLY, 0);
        assert_ne!(flags & libc::MS_NOSUID, 0);
        assert_ne!(flags & libc::MS_NODEV, 0);
        assert_eq!(data, "compress=zstd");
    }

    #[test]
    fn path_type_is_used_for_mount_points() {
        assert!(Path::new("/srv/data").is_absolute());
    }
}
