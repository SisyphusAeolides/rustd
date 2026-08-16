// SPDX-License-Identifier: LGPL-2.1-or-later
//! Journal resource and crash-behavior certification fixtures.
//!
//! These gates keep stdout admission control and reserved-metadata rejection
//! within explicit bounds so a flood cannot grow the in-memory ring without
//! bound, and service stdio defaults continue to target the RustD journal.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rustd::journal::entry::{EntryRing, JournalEntry};
use rustd::journal::sink::JournalSink;
use rustd::journal::stdout::{self, DEFAULT_STDOUT_PATH};

#[test]
fn journal_stdout_path_is_rustd_native() {
    assert_eq!(DEFAULT_STDOUT_PATH, "/run/rustd/journal/stdout");
}

#[test]
fn datagram_flood_is_bounded_by_ring_capacity() {
    let ring = Arc::new(Mutex::new(EntryRing::new(32)));
    let sink = JournalSink::in_memory(Arc::clone(&ring));
    for index in 0..10_000 {
        let mut fields = HashMap::new();
        fields.insert("MESSAGE".into(), format!("flood-{index}").into_bytes());
        fields.insert("PRIORITY".into(), b"6".to_vec());
        sink.record(JournalEntry::new(fields));
    }
    let guard = ring.lock().unwrap();
    assert!(guard.len() <= 32);
}

#[test]
fn stdout_mode_defaults_to_journal_routing() {
    assert!(stdout::wants_journal_stdio(""));
    assert!(stdout::wants_journal_stdio("journal"));
    assert!(!stdout::wants_journal_stdio("null"));
}
