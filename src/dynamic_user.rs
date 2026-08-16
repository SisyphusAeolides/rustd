// SPDX-License-Identifier: LGPL-2.1-or-later
//! Ephemeral UID/GID allocation for `DynamicUser=yes`.
//!
//! Compatibility reference: systemd v261 `src/core/dynamic-user.c`.
//!
//! Allocates UIDs in the range **61184–65519** (0xEF00–0xFFEF), preserving
//! the established dynamic-user allocation range. Allocations are tracked as
//! lock-files under `/run/rustd/dynamic-uid/` named `<uid>-<service_name>`.
//! The lock-file is created with `O_CREAT | O_EXCL` so concurrent managers
//! cannot race each other.

use std::fs;
use std::io;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Inclusive lower bound of the dynamic-user UID range.
pub const DYNAMIC_UID_MIN: libc::uid_t = 61184;
/// Inclusive upper bound of the dynamic-user UID range.
pub const DYNAMIC_UID_MAX: libc::uid_t = 65519;

/// Base directory for dynamic-user lock-files.
///
/// `RUSTD_DYNAMIC_UID_DIR` is authoritative. `SYSTEMD_DYNAMIC_UID_DIR` remains
/// accepted as a compatibility input when the native override is absent.
fn dynamic_uid_dir() -> String {
    std::env::var("RUSTD_DYNAMIC_UID_DIR")
        .or_else(|_| std::env::var("SYSTEMD_DYNAMIC_UID_DIR"))
        .unwrap_or_else(|_| "/run/rustd/dynamic-uid".to_owned())
}

#[derive(Debug)]
pub struct DynamicUser {
    pub uid: libc::uid_t,
    pub name: String,
    lock_path: PathBuf,
}

impl DynamicUser {
    /// Allocate a dynamic UID/GID pair for `service_name`.
    ///
    /// # Errors
    ///
    /// Returns an error if the allocation directory cannot be created, a lock
    /// file cannot be created, or the dynamic UID range is exhausted.
    pub fn allocate(service_name: &str) -> anyhow::Result<Self> {
        let dir = dynamic_uid_dir();
        Self::allocate_in(service_name, Path::new(&dir))
    }

    /// Allocate a dynamic UID/GID pair using `dir` for allocation lock files.
    ///
    /// # Errors
    ///
    /// Returns an error if `dir` cannot be created or secured, a lock file
    /// cannot be created, or the dynamic UID range is exhausted.
    pub fn allocate_in(service_name: &str, dir: &Path) -> anyhow::Result<Self> {
        fs::create_dir_all(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;

        for uid in DYNAMIC_UID_MIN..=DYNAMIC_UID_MAX {
            let name = format!("{uid}-{service_name}");
            let path = dir.join(&name);
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(_file) => {
                    return Ok(Self {
                        uid,
                        name: service_name.to_owned(),
                        lock_path: path,
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }

        anyhow::bail!(
            "dynamic-user range {DYNAMIC_UID_MIN}–{DYNAMIC_UID_MAX} exhausted \
             for service '{service_name}'"
        );
    }

    #[must_use]
    pub fn gid(&self) -> libc::gid_t {
        self.uid as libc::gid_t
    }
}

impl Drop for DynamicUser {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uid_range_sanity() {
        assert_eq!(DYNAMIC_UID_MIN, 61184);
        assert_eq!(DYNAMIC_UID_MAX, 65519);
    }

    #[test]
    fn native_directory_is_authoritative() {
        let native =
            std::env::temp_dir().join(format!("rustd-test-dynuid-native-{}", std::process::id()));
        let legacy =
            std::env::temp_dir().join(format!("rustd-test-dynuid-legacy-{}", std::process::id()));
        std::env::set_var("RUSTD_DYNAMIC_UID_DIR", &native);
        std::env::set_var("SYSTEMD_DYNAMIC_UID_DIR", &legacy);
        assert_eq!(dynamic_uid_dir(), native.to_string_lossy().into_owned());
        std::env::remove_var("RUSTD_DYNAMIC_UID_DIR");
        assert_eq!(dynamic_uid_dir(), legacy.to_string_lossy().into_owned());
        std::env::remove_var("SYSTEMD_DYNAMIC_UID_DIR");
        assert_eq!(dynamic_uid_dir(), "/run/rustd/dynamic-uid");
    }

    #[test]
    fn allocation_state_is_owner_only() {
        let tmp = std::env::temp_dir().join(format!(
            "rustd-test-dynuid-permissions-{}",
            std::process::id()
        ));
        let allocation = DynamicUser::allocate_in("secure.service", &tmp).unwrap();
        let dir_mode = fs::metadata(&tmp).unwrap().permissions().mode() & 0o777;
        let lock_mode = fs::metadata(&allocation.lock_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
        assert_eq!(lock_mode, 0o600);
        drop(allocation);
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn two_allocations_get_distinct_uids() {
        let tmp =
            std::env::temp_dir().join(format!("rustd-test-dynuid-distinct-{}", std::process::id()));
        let a = DynamicUser::allocate_in("same-svc", &tmp).unwrap();
        let b = DynamicUser::allocate_in("same-svc", &tmp).unwrap();
        assert_ne!(a.uid, b.uid);
        assert_eq!(a.name, "same-svc");
        assert_eq!(b.name, "same-svc");
        assert!(a.uid >= DYNAMIC_UID_MIN && a.uid <= DYNAMIC_UID_MAX);
        assert!(b.uid >= DYNAMIC_UID_MIN && b.uid <= DYNAMIC_UID_MAX);
        let path_a = a.lock_path.clone();
        let path_b = b.lock_path.clone();
        drop(a);
        drop(b);
        assert!(!path_a.exists(), "lock-file for a was not removed");
        assert!(!path_b.exists(), "lock-file for b was not removed");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn drop_removes_lock_file() {
        let tmp =
            std::env::temp_dir().join(format!("rustd-test-dynuid-drop-{}", std::process::id()));
        let du = DynamicUser::allocate_in("test-svc-drop-check", &tmp).unwrap();
        let path = du.lock_path.clone();
        assert!(path.exists());
        drop(du);
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
