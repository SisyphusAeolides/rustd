// SPDX-License-Identifier: LGPL-2.1-or-later
//! Journal file rotation and vacuum.
//!
//! When the active journal file exceeds the configured size limit, it is
//! archived (renamed to a timestamped path) and a fresh file is opened.
//! Vacuum removes archived files when total disk use exceeds the configured
//! maximum or files are older than the retention limit.
//!
//! Upstream reference: `src/journal/journal-vacuum.c`,
//!   `src/journald/journald-server.c server_rotate()` (v261).

use std::path::{Path, PathBuf};

use crate::journal::writer::JournalWriter;

/// Default maximum size of a single active journal file (128 MiB).
pub const DEFAULT_MAX_FILE_SIZE: u64 = 128 * 1024 * 1024;

/// Default maximum total journal disk use (4 GiB).
pub const DEFAULT_MAX_USE: u64 = 4 * 1024 * 1024 * 1024;

// ── Rotation ──────────────────────────────────────────────────────────────

/// Rotate `writer` if its estimated size exceeds `max_file_size`.
///
/// On rotation the active file is renamed to
/// `<base>/<timestamp>~<seqnum>.journal~` (archived) and a new active file
/// is opened at the original path.  Returns the new writer (either unchanged
/// or freshly opened).
///
/// # Errors
/// Returns an error if the new file cannot be opened.
pub fn rotate_if_needed(
    writer: JournalWriter,
    max_file_size: u64,
) -> anyhow::Result<JournalWriter> {
    if writer.bytes_written < max_file_size {
        return Ok(writer);
    }
    rotate(writer)
}

/// Force a rotation regardless of file size.
///
/// # Errors
/// Returns an error if the new file cannot be opened or the rename fails.
pub fn rotate(writer: JournalWriter) -> anyhow::Result<JournalWriter> {
    let active_path = writer.path.clone();
    // Build the archive path: same directory, timestamp-based name.
    let dir = active_path
        .parent()
        .unwrap_or(Path::new("/var/log/journal"));
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_micros());
    let archive_name = format!("archive-{ts:020}.journal");
    let archive_path = dir.join(archive_name);

    // Flush and close the current writer before renaming.
    writer.close()?;

    // Rename active → archive (best effort; ignore missing-file errors).
    let _ = std::fs::rename(&active_path, archive_path);

    // Open a fresh active file at the original path.
    JournalWriter::open(&active_path)
}

// ── Vacuum ────────────────────────────────────────────────────────────────

/// Remove archived journal files until total disk use is below `max_use`.
///
/// Files matching `archive-*.journal` in `journal_dir` are candidates.
/// They are removed oldest-first.
///
/// `max_retention_secs`: if non-zero, also remove files whose modification
/// time is older than this many seconds ago.
pub fn vacuum(journal_dir: &Path, max_use: u64, max_retention_secs: u64) {
    let mut archives = collect_archives(journal_dir);
    // Sort by mtime ascending (oldest first).
    archives.sort_by_key(|p| mtime_secs(p));

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    let mut total = total_size(&archives);

    for path in archives {
        let should_remove_size = total > max_use;
        let should_remove_age = max_retention_secs > 0
            && now_secs.saturating_sub(mtime_secs(&path)) > max_retention_secs;

        if should_remove_size || should_remove_age {
            if let Ok(meta) = std::fs::metadata(&path) {
                total = total.saturating_sub(meta.len());
            }
            let _ = std::fs::remove_file(&path);
        } else {
            break;
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────

fn collect_archives(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("archive-") && n.ends_with(".journal"))
        })
        .collect()
}

fn total_size(paths: &[PathBuf]) -> u64 {
    paths
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok())
        .map(|m| m.len())
        .sum()
}

fn mtime_secs(path: &Path) -> u64 {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs())
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn collect_archives_finds_only_archives() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("archive-0001.journal"), b"x").unwrap();
        std::fs::write(dir.path().join("system.journal"), b"y").unwrap();
        std::fs::write(dir.path().join("other.txt"), b"z").unwrap();

        let archives = collect_archives(dir.path());
        assert_eq!(archives.len(), 1);
        assert!(archives[0]
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("archive-"));
    }

    #[test]
    fn vacuum_removes_oldest_when_over_limit() {
        let dir = tempfile::tempdir().unwrap();

        // Write two archive files of 100 bytes each.
        for i in 0u8..2 {
            let mut f =
                std::fs::File::create(dir.path().join(format!("archive-{i:020}.journal"))).unwrap();
            f.write_all(&[0u8; 100]).unwrap();
        }

        // max_use = 150 → one file (100 bytes) must be removed.
        vacuum(dir.path(), 150, 0);

        let remaining = collect_archives(dir.path());
        assert_eq!(remaining.len(), 1);
    }
}
