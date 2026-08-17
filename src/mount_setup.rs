// SPDX-License-Identifier: LGPL-2.1-or-later
//! Early API filesystem setup performed by PID 1.
//!
//! On a bare-metal boot the initramfs hands over a root filesystem where the
//! kernel API mounts are either absent or only partially present. PID 1 owns
//! them, so `/proc`, `/sys`, `/dev`, and the cgroup v2 hierarchy have to exist
//! before the manager validates cgroup delegation or starts any unit.
//!
//! Upstream reference: `src/core/mount-setup.c` (v261)

use std::ffi::CString;
use std::fs;
use std::io;
use std::path::Path;

struct ApiMount {
    source: &'static str,
    target: &'static str,
    fstype: &'static str,
    flags: libc::c_ulong,
    options: &'static str,
    /// A boot cannot continue without this mount.
    required: bool,
}

const NOSUID_NOEXEC_NODEV: libc::c_ulong =
    (libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV) as libc::c_ulong;
const NOSUID_NODEV: libc::c_ulong = (libc::MS_NOSUID | libc::MS_NODEV) as libc::c_ulong;
const NOSUID_NOEXEC: libc::c_ulong = (libc::MS_NOSUID | libc::MS_NOEXEC) as libc::c_ulong;

const API_MOUNTS: &[ApiMount] = &[
    ApiMount {
        source: "proc",
        target: "/proc",
        fstype: "proc",
        flags: NOSUID_NOEXEC_NODEV,
        options: "",
        required: true,
    },
    ApiMount {
        source: "sysfs",
        target: "/sys",
        fstype: "sysfs",
        flags: NOSUID_NOEXEC_NODEV,
        options: "",
        required: true,
    },
    ApiMount {
        source: "devtmpfs",
        target: "/dev",
        fstype: "devtmpfs",
        flags: (libc::MS_NOSUID | libc::MS_STRICTATIME) as libc::c_ulong,
        options: "mode=0755,size=4m,nr_inodes=1m",
        required: true,
    },
    ApiMount {
        source: "devpts",
        target: "/dev/pts",
        fstype: "devpts",
        flags: NOSUID_NOEXEC,
        options: "mode=0620,gid=5,ptmxmode=0666",
        required: false,
    },
    ApiMount {
        source: "tmpfs",
        target: "/dev/shm",
        fstype: "tmpfs",
        flags: (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_STRICTATIME) as libc::c_ulong,
        options: "mode=01777",
        required: false,
    },
    ApiMount {
        source: "tmpfs",
        target: "/run",
        fstype: "tmpfs",
        flags: (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_STRICTATIME) as libc::c_ulong,
        options: "mode=0755,size=20%,nr_inodes=800k",
        required: false,
    },
    ApiMount {
        source: "cgroup2",
        target: "/sys/fs/cgroup",
        fstype: "cgroup2",
        flags: NOSUID_NOEXEC_NODEV,
        options: "nsdelegate,memory_recursiveprot",
        required: true,
    },
    ApiMount {
        source: "securityfs",
        target: "/sys/kernel/security",
        fstype: "securityfs",
        flags: NOSUID_NOEXEC_NODEV,
        options: "",
        required: false,
    },
    ApiMount {
        source: "tmpfs",
        target: "/run/lock",
        fstype: "tmpfs",
        flags: NOSUID_NODEV,
        options: "mode=01777,size=5m",
        required: false,
    },
];

/// Mount the kernel API filesystems PID 1 depends on.
///
/// Mounts that the initramfs already established are left untouched, and
/// optional mounts that the running kernel does not support are skipped.
///
/// # Errors
/// Returns an error when a mount the manager cannot operate without —
/// `/proc`, `/sys`, `/dev`, or the cgroup v2 hierarchy — is missing and
/// cannot be established.
pub fn mount_api_filesystems() -> anyhow::Result<()> {
    for entry in API_MOUNTS {
        if let Err(error) = mount_one(entry) {
            if entry.required {
                return Err(anyhow::anyhow!(
                    "rustd: cannot mount {} on {}: {error}",
                    entry.fstype,
                    entry.target
                ));
            }
            eprintln!(
                "rustd: skipping optional {} mount on {}: {error}",
                entry.fstype, entry.target
            );
        }
    }

    Ok(())
}

fn mount_one(entry: &ApiMount) -> io::Result<()> {
    let target = Path::new(entry.target);
    if is_mount_point(target) {
        return Ok(());
    }

    // The parent may itself be an API mount that was just established, so the
    // mount point can legitimately not exist yet.
    if !target.exists() {
        fs::create_dir_all(target)?;
    }

    let source = CString::new(entry.source)?;
    let target_c = CString::new(entry.target)?;
    let fstype = CString::new(entry.fstype)?;
    let options = CString::new(entry.options)?;
    let data = if entry.options.is_empty() {
        std::ptr::null()
    } else {
        options.as_ptr().cast::<libc::c_void>()
    };

    let ret = unsafe {
        libc::mount(
            source.as_ptr(),
            target_c.as_ptr(),
            fstype.as_ptr(),
            entry.flags,
            data,
        )
    };

    if ret == 0 {
        return Ok(());
    }

    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        // Another mount raced us onto the same target.
        Some(libc::EBUSY) => Ok(()),
        _ => Err(error),
    }
}

/// Report whether `path` is the root of a mount.
///
/// `/proc` is not guaranteed to exist this early, so this compares the device
/// ID of `path` with the device ID of its parent instead of parsing
/// `/proc/self/mountinfo`.
fn is_mount_point(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;

    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    // The filesystem root has no distinct parent path to compare against, but
    // is necessarily the root of the process's root mount.
    if path == Path::new("/") {
        return true;
    }
    let Some(parent) = path.parent() else {
        return false;
    };
    let Ok(parent_metadata) = fs::metadata(parent) else {
        return false;
    };

    metadata.dev() != parent_metadata.dev()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_is_a_mount_point() {
        assert!(is_mount_point(Path::new("/")));
    }

    #[test]
    fn missing_path_is_not_a_mount_point() {
        assert!(!is_mount_point(Path::new("/nonexistent-rustd-mount-check")));
    }

    #[test]
    fn required_mounts_cover_the_manager_prerequisites() {
        for target in ["/proc", "/sys", "/dev", "/sys/fs/cgroup"] {
            assert!(
                API_MOUNTS
                    .iter()
                    .any(|entry| entry.target == target && entry.required),
                "{target} must be a required API mount"
            );
        }
    }
}
