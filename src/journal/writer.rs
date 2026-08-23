// SPDX-License-Identifier: LGPL-2.1-or-later
//! Journal file writer.
//!
//! Wraps `rustd_journal_file_open` / `rustd_journal_file_append` /
//! `rustd_journal_file_close` to provide a safe Rust interface for appending
//! entries to an on-disk journal file.
//!
//! Upstream reference: `src/journal/journal-file.c` (v261).

use std::ffi::CString;
use std::io;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::ffi::journal::{
    rustd_journal_file_append, rustd_journal_file_close, rustd_journal_file_open, SdJournalField,
};
use crate::journal::entry::JournalEntry;

// ── JournalWriter ─────────────────────────────────────────────────────────

/// Appends [`JournalEntry`] values to an open journal file.
///
/// The file is closed (and fsynced by the C layer) when the writer is
/// dropped or when [`JournalWriter::close`] is called explicitly.
pub struct JournalWriter {
    /// Raw fd returned by `rustd_journal_file_open`; `-1` after `close`.
    fd: RawFd,
    /// Absolute path of the journal file.
    pub path: PathBuf,
    /// Running estimate of bytes written to this file.
    ///
    /// Each [`append`](JournalWriter::append) call adds
    /// `64 + fields.len() * 16` as a coarse accounting value matching the
    /// upstream rotation heuristic.
    pub bytes_written: u64,
}

impl JournalWriter {
    /// Open (or create) the journal file at `path`.
    ///
    /// # Errors
    /// Returns an error if `path` cannot be converted to a C string or if
    /// [`rustd_journal_file_open`] returns a negative errno.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let fd = open_fd(path)?;
        Ok(Self {
            fd,
            path: path.to_owned(),
            bytes_written: 0,
        })
    }

    /// Open a journal, quarantining a structurally damaged active file once.
    ///
    /// Permission, capacity, and other operational errors remain fatal. Only
    /// errors that identify invalid journal contents cause the active file to
    /// be moved aside and replaced.
    ///
    /// # Errors
    /// Returns an error if the initial failure is not corruption-related, the
    /// damaged file cannot be quarantined, or the replacement cannot be opened.
    pub fn open_resilient(path: &Path) -> anyhow::Result<Self> {
        match Self::open(path) {
            Ok(writer) => Ok(writer),
            Err(error) => {
                let Some(errno) = journal_errno(&error) else {
                    return Err(error);
                };
                if !is_corruption_errno(errno) || !path.exists() {
                    return Err(error);
                }
                let quarantined = quarantine_path(path)?;
                Self::open(path).map_err(|replacement| {
                    anyhow::anyhow!(
                        "quarantined damaged journal {} as {} after errno {errno}, but replacement open failed: {replacement}",
                        path.display(),
                        quarantined.display()
                    )
                })
            }
        }
    }

    fn reopen_after_corruption(&mut self, errno: i32) -> anyhow::Result<PathBuf> {
        let _ = self.close_fd();
        let quarantined = quarantine_path(&self.path).map_err(|error| {
            anyhow::anyhow!(
                "journal append failed with errno {errno}, and {} could not be quarantined: {error}",
                self.path.display()
            )
        })?;
        self.fd = open_fd(&self.path).map_err(|error| {
            anyhow::anyhow!(
                "quarantined damaged journal {} as {}, but replacement open failed: {error}",
                self.path.display(),
                quarantined.display()
            )
        })?;
        self.bytes_written = 0;
        Ok(quarantined)
    }

    fn append_fields(&self, fields: &[SdJournalField], entry: &JournalEntry) -> libc::c_int {
        // Safety: field pointers are owned by the caller for this call and the
        // writer fd remains open for the duration of the append.
        unsafe {
            rustd_journal_file_append(
                self.fd,
                fields.as_ptr(),
                fields.len(),
                entry.realtime_usec,
                entry.seqnum,
            )
        }
    }

    fn append_error(errno: i32) -> anyhow::Error {
        anyhow::anyhow!("rustd_journal_file_append failed: errno {errno}")
    }

    fn open_error(path: &Path, errno: i32) -> anyhow::Error {
        anyhow::Error::new(io::Error::from_raw_os_error(errno)).context(format!(
            "rustd_journal_file_open({}) failed",
            path.display()
        ))
    }

    fn checked_open(path: &Path) -> anyhow::Result<RawFd> {
        let c_path = CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|e| anyhow::anyhow!("journal path contains NUL: {e}"))?;
        // Safety: c_path is valid for the duration of the call.
        let fd = unsafe { rustd_journal_file_open(c_path.as_ptr()) };
        if fd < 0 {
            return Err(Self::open_error(path, -fd));
        }
        Ok(fd)
    }

    /// Append a single entry to the journal file.
    ///
    /// Builds the [`SdJournalField`] array from `entry.fields`, calls
    /// [`rustd_journal_file_append`], and bumps [`bytes_written`](Self::bytes_written).
    ///
    /// # Errors
    /// Returns an error if [`rustd_journal_file_append`] returns a negative errno.
    pub fn append(&mut self, entry: &JournalEntry) -> anyhow::Result<()> {
        // Build parallel C-string key storage and field descriptors.
        // The two Vecs must stay alive for the duration of the FFI call.
        let mut ckeys: Vec<CString> = Vec::with_capacity(entry.fields.len());
        let mut c_fields: Vec<SdJournalField> = Vec::with_capacity(entry.fields.len());

        for (key, value) in &entry.fields {
            let ckey = CString::new(key.as_bytes())
                .map_err(|e| anyhow::anyhow!("field key contains NUL: {e}"))?;
            c_fields.push(SdJournalField {
                key: ckey.as_ptr(),
                value: value.as_ptr(),
                value_len: value.len(),
            });
            ckeys.push(ckey);
        }

        let mut rc = self.append_fields(&c_fields, entry);
        if rc < 0 {
            let errno = -rc;
            if !is_corruption_errno(errno) {
                return Err(Self::append_error(errno));
            }
            let quarantined = self.reopen_after_corruption(errno)?;
            rc = self.append_fields(&c_fields, entry);
            if rc < 0 {
                return Err(anyhow::anyhow!(
                    "journal append retry failed with errno {} after quarantining {}",
                    -rc,
                    quarantined.display()
                ));
            }
        }

        // Coarse byte estimate matching the upstream rotation heuristic.
        #[allow(clippy::cast_possible_truncation)]
        let estimate = 64u64 + (entry.fields.len() as u64) * 16;
        self.bytes_written += estimate;
        Ok(())
    }

    /// Explicitly flush and close the journal file, consuming `self`.
    ///
    /// The `Drop` impl also closes the file, so this is only needed when
    /// callers want to check for errors on close.
    ///
    /// # Errors
    /// Returns an error if [`rustd_journal_file_close`] returns a negative errno.
    pub fn close(mut self) -> anyhow::Result<()> {
        let rc = self.close_fd();
        if rc < 0 {
            return Err(anyhow::anyhow!(
                "rustd_journal_file_close failed: errno {}",
                -rc
            ));
        }
        Ok(())
    }

    /// Issue `fsync` on the underlying fd via the C layer's close path.
    ///
    /// This is a best-effort flush; errors are silently ignored.
    pub fn flush(&self) {
        // Safety: self.fd is a valid open fd (close() sets it to -1 before
        // drop, so this path is only reachable while the fd is live).
        unsafe {
            libc::fsync(self.fd);
        }
    }

    /// Internal: close the fd and mark it invalid.  Returns the raw C return value.
    fn close_fd(&mut self) -> libc::c_int {
        if self.fd < 0 {
            return 0;
        }
        // Safety: self.fd was opened by rustd_journal_file_open and is valid.
        let rc = unsafe { rustd_journal_file_close(self.fd) };
        self.fd = -1;
        rc
    }
}

fn open_fd(path: &Path) -> anyhow::Result<RawFd> {
    JournalWriter::checked_open(path)
}

fn is_corruption_errno(errno: i32) -> bool {
    matches!(
        errno,
        libc::EIO
            | libc::EBADMSG
            | libc::ENODATA
            | libc::EPROTONOSUPPORT
            | libc::EHOSTDOWN
            | libc::ESTALE
            | libc::EINVAL
    )
}

fn journal_errno(error: &anyhow::Error) -> Option<i32> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<io::Error>())
        .and_then(io::Error::raw_os_error)
}

fn quarantine_path(path: &Path) -> anyhow::Result<PathBuf> {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let parent = path.parent().ok_or_else(|| {
        anyhow::anyhow!("journal path {} has no parent directory", path.display())
    })?;
    let name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("journal path {} has no file name", path.display()))?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    for _ in 0..1024 {
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(
            "{}.corrupt-{timestamp}-{}-{sequence}",
            name.to_string_lossy(),
            std::process::id()
        ));
        if candidate.exists() {
            continue;
        }
        std::fs::rename(path, &candidate).map_err(|error| {
            anyhow::anyhow!(
                "move damaged journal {} to {}: {error}",
                path.display(),
                candidate.display()
            )
        })?;
        return Ok(candidate);
    }
    anyhow::bail!(
        "could not allocate a quarantine name for damaged journal {}",
        path.display()
    )
}

impl Drop for JournalWriter {
    fn drop(&mut self) {
        if self.fd >= 0 {
            // Safety: self.fd is a valid open fd.
            unsafe { rustd_journal_file_close(self.fd) };
            self.fd = -1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_is_limited_to_structural_failures() {
        for errno in [
            libc::EIO,
            libc::EBADMSG,
            libc::ENODATA,
            libc::EPROTONOSUPPORT,
            libc::EHOSTDOWN,
            libc::ESTALE,
            libc::EINVAL,
        ] {
            assert!(is_corruption_errno(errno), "errno {errno}");
        }
        for errno in [
            libc::EACCES,
            libc::EPERM,
            libc::ENOSPC,
            libc::EDQUOT,
            libc::EROFS,
            libc::EMFILE,
        ] {
            assert!(!is_corruption_errno(errno), "errno {errno}");
        }
    }

    #[test]
    fn resilient_open_quarantines_invalid_active_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("system.journal");
        std::fs::write(&path, b"not a journal").unwrap();

        let mut writer = JournalWriter::open_resilient(&path).unwrap();
        writer
            .append(&JournalEntry::message("probe.service", 6, "recovered"))
            .unwrap();
        writer.close().unwrap();

        assert!(path.is_file());
        let quarantined: Vec<_> = std::fs::read_dir(directory.path())
            .unwrap()
            .flatten()
            .map(|entry| entry.path())
            .filter(|candidate| {
                candidate.file_name().is_some_and(|name| {
                    name.to_string_lossy()
                        .starts_with("system.journal.corrupt-")
                })
            })
            .collect();
        assert_eq!(quarantined.len(), 1);
        assert_eq!(std::fs::read(&quarantined[0]).unwrap(), b"not a journal");
    }
}
