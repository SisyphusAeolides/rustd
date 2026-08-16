// SPDX-License-Identifier: LGPL-2.1-or-later
//! Journal file writer.
//!
//! Wraps `rustd_journal_file_open` / `rustd_journal_file_append` /
//! `rustd_journal_file_close` to provide a safe Rust interface for appending
//! entries to an on-disk journal file.
//!
//! Upstream reference: `src/journal/journal-file.c` (v261).

use std::ffi::CString;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};

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
        let c_path = CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|e| anyhow::anyhow!("journal path contains NUL: {e}"))?;
        // Safety: c_path is valid for the duration of the call.
        let fd = unsafe { rustd_journal_file_open(c_path.as_ptr()) };
        if fd < 0 {
            return Err(anyhow::anyhow!(
                "rustd_journal_file_open({}) failed: errno {}",
                path.display(),
                -fd,
            ));
        }
        Ok(Self {
            fd,
            path: path.to_owned(),
            bytes_written: 0,
        })
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

        // Safety: c_fields[i].key points into ckeys[i], which is alive here.
        //         c_fields[i].value points into entry.fields values, alive here.
        let rc = unsafe {
            rustd_journal_file_append(
                self.fd,
                c_fields.as_ptr(),
                c_fields.len(),
                entry.realtime_usec,
                entry.seqnum,
            )
        };
        if rc < 0 {
            return Err(anyhow::anyhow!(
                "rustd_journal_file_append failed: errno {}",
                -rc
            ));
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

impl Drop for JournalWriter {
    fn drop(&mut self) {
        if self.fd >= 0 {
            // Safety: self.fd is a valid open fd.
            unsafe { rustd_journal_file_close(self.fd) };
            self.fd = -1;
        }
    }
}
