// SPDX-License-Identifier: LGPL-2.1-or-later
//! In-memory journal entry types and cursor-based ring buffer.
//!
//! Upstream reference: `src/journal/journal-def.h`,
//!   `src/journald/journald-server.c` (v261)

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

// ── Timestamps ────────────────────────────────────────────────────────────

/// Return the current realtime as microseconds since the Unix epoch.
fn realtime_usec() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        // Truncation is intentional: timestamps beyond year 584,554 are not
        // a concern for a journal implementation.
        .map_or(0, |d| {
            #[allow(clippy::cast_possible_truncation)]
            let usec = d.as_micros() as u64;
            usec
        })
}

/// Monotonically increasing sequence counter (per-process, not per-boot).
static SEQ: AtomicU64 = AtomicU64::new(1);

fn next_seqnum() -> u64 {
    SEQ.fetch_add(1, Ordering::Relaxed)
}

fn normalize_id128(value: &str) -> Option<String> {
    let mut compact = String::with_capacity(32);
    for ch in value.chars() {
        if ch == '-' || ch.is_ascii_whitespace() {
            continue;
        }
        if !ch.is_ascii_hexdigit() || compact.len() >= 32 {
            return None;
        }
        compact.push(ch.to_ascii_lowercase());
    }
    (compact.len() == 32).then_some(compact)
}

/// Return the current Linux boot ID in systemd's compact lowercase ID128
/// representation. The value is cached because a boot ID is immutable for the
/// lifetime of the running kernel.
#[must_use]
pub fn current_boot_id() -> Option<&'static str> {
    static BOOT_ID: OnceLock<Option<String>> = OnceLock::new();
    BOOT_ID
        .get_or_init(|| {
            let raw = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
            normalize_id128(&raw)
        })
        .as_deref()
}

// ── JournalEntry ──────────────────────────────────────────────────────────

/// A single journal entry: a set of `KEY=VALUE` fields plus metadata.
///
/// Upstream reference: entry object layout in `journal-def.h`.
#[derive(Debug, Clone)]
pub struct JournalEntry {
    /// Realtime timestamp in microseconds since the Unix epoch.
    pub realtime_usec: u64,
    /// Monotonic sequence number (increments per entry, not per-boot clock).
    pub seqnum: u64,
    /// Human-readable fields: `MESSAGE`, `PRIORITY`, `_PID`, etc.
    pub fields: HashMap<String, Vec<u8>>,
}

impl JournalEntry {
    /// Create a new entry, stamping current boot identity when the caller has
    /// not already supplied historical `_BOOT_ID` metadata.
    ///
    /// `fields` is a map from field name (without `=`) to raw bytes.
    #[must_use]
    pub fn new(mut fields: HashMap<String, Vec<u8>>) -> Self {
        if !fields.contains_key("_BOOT_ID") {
            if let Some(boot_id) = current_boot_id() {
                fields.insert("_BOOT_ID".into(), boot_id.as_bytes().to_vec());
            }
        }
        Self {
            realtime_usec: realtime_usec(),
            seqnum: next_seqnum(),
            fields,
        }
    }

    /// Convenience: build a simple text message entry.
    #[must_use]
    pub fn message(unit: &str, priority: u8, msg: &str) -> Self {
        let mut fields = HashMap::new();
        fields.insert("MESSAGE".into(), msg.as_bytes().to_vec());
        fields.insert("PRIORITY".into(), priority.to_string().into_bytes());
        if !unit.is_empty() {
            fields.insert("_SYSTEMD_UNIT".into(), unit.as_bytes().to_vec());
        }
        Self::new(fields)
    }

    /// Return the `MESSAGE` field as a UTF-8 string, or `""`.
    #[must_use]
    pub fn message_str(&self) -> &str {
        self.fields
            .get("MESSAGE")
            .and_then(|v| std::str::from_utf8(v).ok())
            .unwrap_or("")
    }

    /// Return the `PRIORITY` field as a u8 (syslog level), or 6 (INFO).
    #[must_use]
    pub fn priority(&self) -> u8 {
        self.fields
            .get("PRIORITY")
            .and_then(|v| std::str::from_utf8(v).ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(6)
    }

    /// Return the `_SYSTEMD_UNIT` field, or `""`.
    #[must_use]
    pub fn unit(&self) -> &str {
        self.fields
            .get("_SYSTEMD_UNIT")
            .and_then(|v| std::str::from_utf8(v).ok())
            .unwrap_or("")
    }

    /// Return the `_PID` field as a string, or `""`.
    #[must_use]
    pub fn pid_str(&self) -> &str {
        self.fields
            .get("_PID")
            .and_then(|v| std::str::from_utf8(v).ok())
            .unwrap_or("")
    }
}

// ── EntryRing ─────────────────────────────────────────────────────────────

/// A bounded ring buffer of journal entries with cursor-based reads.
///
/// The ring holds up to `capacity` entries.  When full, the oldest entry
/// is overwritten.  Readers track their position via the sequence number
/// of the last entry they consumed.
pub struct EntryRing {
    /// Maximum number of entries retained in memory.
    capacity: usize,
    entries: Vec<JournalEntry>,
    /// Write head (next slot to overwrite), wraps modulo capacity.
    head: usize,
    /// Total entries ever inserted.
    total: usize,
}

impl EntryRing {
    /// Create a ring with the given capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            capacity,
            entries: Vec::with_capacity(capacity),
            head: 0,
            total: 0,
        }
    }

    /// Push a new entry into the ring.
    pub fn push(&mut self, entry: JournalEntry) {
        if self.entries.len() < self.capacity {
            self.entries.push(entry);
        } else {
            self.entries[self.head] = entry;
        }
        self.head = (self.head + 1) % self.capacity;
        self.total += 1;
    }

    /// Return all entries with `seqnum > after_seqnum`, in insertion order.
    /// Pass `0` to get all retained entries.
    #[must_use]
    pub fn drain_since(&self, after_seqnum: u64) -> Vec<&JournalEntry> {
        // Reconstruct insertion order from ring state.
        let len = self.entries.len();
        if len == 0 {
            return Vec::new();
        }
        // If ring is not yet full, entries are in [0..len) order.
        // If full, oldest entry starts at self.head.
        let ordered: Vec<&JournalEntry> = if self.total <= self.capacity {
            self.entries.iter().collect()
        } else {
            let mut v = Vec::with_capacity(len);
            for i in 0..len {
                v.push(&self.entries[(self.head + i) % self.capacity]);
            }
            v
        };
        ordered
            .into_iter()
            .filter(|e| e.seqnum > after_seqnum)
            .collect()
    }

    /// Total entries ever pushed (not just currently retained).
    #[must_use]
    pub fn total_pushed(&self) -> usize {
        self.total
    }

    /// Number of entries currently retained.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if the ring contains no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ── Priority constants ────────────────────────────────────────────────────

/// Syslog priority levels (`LOG_EMERG` … `LOG_DEBUG`).
pub mod priority {
    pub const EMERG: u8 = 0;
    pub const ALERT: u8 = 1;
    pub const CRIT: u8 = 2;
    pub const ERR: u8 = 3;
    pub const WARNING: u8 = 4;
    pub const NOTICE: u8 = 5;
    pub const INFO: u8 = 6;
    pub const DEBUG: u8 = 7;

    /// Return the short name for a priority level.
    #[must_use]
    pub fn name(p: u8) -> &'static str {
        match p {
            0 => "emerg",
            1 => "alert",
            2 => "crit",
            3 => "err",
            4 => "warning",
            5 => "notice",
            6 => "info",
            7 => "debug",
            _ => "unknown",
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_compact_and_hyphenated_id128() {
        let compact = "0123456789abcdef0123456789abcdef";
        let hyphenated = "01234567-89ab-cdef-0123-456789abcdef\n";
        assert_eq!(normalize_id128(compact).as_deref(), Some(compact));
        assert_eq!(normalize_id128(hyphenated).as_deref(), Some(compact));
        assert!(normalize_id128("0123-not-an-id").is_none());
    }

    #[test]
    fn new_entry_has_current_boot_id_when_available() {
        let entry = JournalEntry::message("test.service", 6, "hello");
        if let Some(boot_id) = current_boot_id() {
            assert_eq!(
                entry.fields.get("_BOOT_ID").map(Vec::as_slice),
                Some(boot_id.as_bytes())
            );
        }
    }

    #[test]
    fn historical_boot_id_is_preserved() {
        let historical = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_vec();
        let mut fields = HashMap::new();
        fields.insert("_BOOT_ID".into(), historical.clone());
        let entry = JournalEntry::new(fields);
        assert_eq!(entry.fields.get("_BOOT_ID"), Some(&historical));
    }

    #[test]
    fn push_and_drain_all() {
        let mut ring = EntryRing::new(16);
        for i in 0..3u8 {
            ring.push(JournalEntry::message(
                "test.service",
                6,
                &format!("msg {i}"),
            ));
        }
        assert_eq!(ring.len(), 3);
        let all = ring.drain_since(0);
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].message_str(), "msg 0");
        assert_eq!(all[2].message_str(), "msg 2");
    }

    #[test]
    fn drain_since_cursor() {
        let mut ring = EntryRing::new(16);
        ring.push(JournalEntry::message("a.service", 6, "first"));
        ring.push(JournalEntry::message("a.service", 6, "second"));
        ring.push(JournalEntry::message("a.service", 6, "third"));
        let all = ring.drain_since(0);
        let cursor = all[1].seqnum;
        let tail = ring.drain_since(cursor);
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0].message_str(), "third");
    }

    #[test]
    fn ring_wraps_correctly() {
        let mut ring = EntryRing::new(4);
        for i in 0..6u8 {
            ring.push(JournalEntry::message("x.service", 6, &format!("{i}")));
        }
        assert_eq!(ring.len(), 4);
        assert_eq!(ring.total_pushed(), 6);
        // Should retain entries 2..=5.
        let all = ring.drain_since(0);
        assert_eq!(all.len(), 4);
        assert_eq!(all[0].message_str(), "2");
        assert_eq!(all[3].message_str(), "5");
    }

    #[test]
    fn priority_name() {
        assert_eq!(priority::name(6), "info");
        assert_eq!(priority::name(3), "err");
        assert_eq!(priority::name(0), "emerg");
    }

    #[test]
    fn entry_fields() {
        let e = JournalEntry::message("foo.service", 4, "hello");
        assert_eq!(e.message_str(), "hello");
        assert_eq!(e.priority(), 4);
        assert_eq!(e.unit(), "foo.service");
    }
}
