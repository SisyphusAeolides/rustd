// SPDX-License-Identifier: LGPL-2.1-or-later
//! Inotify source — directory and file watch management.
//!
//! Used by path units and the unit file monitor to detect changes in
//! `/etc/systemd/system/` and `/lib/systemd/system/`.
//!
//! Upstream reference: src/core/path.c `path_spec_watch()` (v261)

use std::collections::HashMap;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};

/// A single inotify watch entry.
#[derive(Debug)]
pub struct Watch {
    /// The watch descriptor returned by `inotify_add_watch(2)`.
    pub wd: i32,
    /// The path that was registered.
    pub path: String,
    /// The mask that was registered (combination of `IN_*` constants).
    pub mask: u32,
}

/// An inotify fd and the set of active watches.
#[derive(Debug)]
pub struct InotifyFd {
    fd: OwnedFd,
    watches: HashMap<i32, Watch>,
}

impl InotifyFd {
    /// Create a new inotify instance.
    ///
    /// # Errors
    /// Returns an error if `inotify_init1(2)` fails.
    pub fn create() -> anyhow::Result<Self> {
        // Safety: rustd_inotify_create1 returns a valid fd or -errno.
        let fd = unsafe { crate::ffi::event::rustd_inotify_create1() };
        if fd < 0 {
            return Err(anyhow::anyhow!("inotify_init1 failed: errno {}", -fd));
        }
        Ok(Self {
            // Safety: fd is valid and owned.
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
            watches: HashMap::new(),
        })
    }

    /// Add a watch for `path` with the given `mask`.
    ///
    /// If the path is already watched the kernel updates the mask and returns
    /// the same watch descriptor.
    ///
    /// # Errors
    /// Returns an error if the path contains a NUL byte or `inotify_add_watch(2)` fails.
    pub fn add_watch(&mut self, path: &str, mask: u32) -> anyhow::Result<i32> {
        let c_path = std::ffi::CString::new(path)
            .map_err(|_| anyhow::anyhow!("path contains NUL byte: {path}"))?;
        // Safety: rustd_inotify_add_watch takes a valid fd and NUL-terminated path.
        let wd = unsafe {
            crate::ffi::event::rustd_inotify_add_watch(self.fd.as_raw_fd(), c_path.as_ptr(), mask)
        };
        if wd < 0 {
            return Err(anyhow::anyhow!(
                "inotify_add_watch({path}) failed: errno {}",
                -wd
            ));
        }
        self.watches.insert(
            wd,
            Watch {
                wd,
                path: path.to_owned(),
                mask,
            },
        );
        Ok(wd)
    }

    /// Remove a watch by its watch descriptor.
    ///
    /// # Errors
    /// Returns an error if `inotify_rm_watch(2)` fails.
    pub fn remove_watch(&mut self, wd: i32) -> anyhow::Result<()> {
        // Safety: rustd_inotify_rm_watch takes a valid fd and a valid wd.
        let r = unsafe { crate::ffi::event::rustd_inotify_rm_watch(self.fd.as_raw_fd(), wd) };
        if r < 0 {
            return Err(anyhow::anyhow!(
                "inotify_rm_watch({wd}) failed: errno {}",
                -r
            ));
        }
        self.watches.remove(&wd);
        Ok(())
    }

    /// The raw fd, for registering with epoll.
    #[must_use]
    pub fn as_raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }

    /// Look up the path for a watch descriptor (for dispatch).
    #[must_use]
    pub fn path_for(&self, wd: i32) -> Option<&str> {
        self.watches.get(&wd).map(|w| w.path.as_str())
    }
}
