// SPDX-License-Identifier: LGPL-2.1-or-later
//! Ownership tracking for journal UNIX socket paths.
//!
//! A UNIX socket's filesystem entry survives after its file descriptor closes.
//! This guard records the device and inode of a path immediately after bind,
//! then removes that same socket entry during teardown.  It deliberately does
//! not remove a replacement entry owned by another process.

use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};

/// A socket path created by this daemon instance.
pub(crate) struct SocketPathGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl SocketPathGuard {
    /// Record the identity of a socket path just created by `bind(2)`.
    ///
    /// # Errors
    /// Returns an error if `path` is not a filesystem socket.
    pub(crate) fn capture(path: &Path) -> anyhow::Result<Self> {
        let metadata = std::fs::symlink_metadata(path).map_err(|error| {
            anyhow::anyhow!("inspect journal socket {}: {error}", path.display())
        })?;
        if !metadata.file_type().is_socket() {
            return Err(anyhow::anyhow!(
                "journal socket path is not a socket: {}",
                path.display()
            ));
        }
        Ok(Self {
            path: path.to_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    fn remove_if_owned(&self) {
        let Ok(metadata) = std::fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

impl Drop for SocketPathGuard {
    fn drop(&mut self) {
        self.remove_if_owned();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixDatagram;

    #[test]
    fn removes_the_socket_it_captured() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("socket");
        let socket = UnixDatagram::bind(&path).unwrap();
        let guard = SocketPathGuard::capture(&path).unwrap();
        drop(guard);

        assert!(!path.exists());
        drop(socket);
    }
}
