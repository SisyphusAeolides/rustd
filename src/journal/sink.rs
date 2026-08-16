// SPDX-License-Identifier: LGPL-2.1-or-later
//! Shared destination for entries accepted by `systemd-journald`.
//!
//! The socket handlers keep their event-loop responsibilities small: parse an
//! entry and hand it to this sink.  The sink writes the entry to the durable
//! journal before making it visible in the in-memory ring, so a daemon caller
//! can report storage failures instead of silently claiming an entry arrived.

use std::sync::{Arc, Mutex};

use crate::journal::entry::{EntryRing, JournalEntry};
use crate::journal::writer::JournalWriter;

/// Thread-safe destination shared by the datagram and stdout socket servers.
pub struct JournalSink {
    ring: Arc<Mutex<EntryRing>>,
    writer: Option<Mutex<Option<JournalWriter>>>,
    failure: Mutex<Option<String>>,
}

impl JournalSink {
    /// Construct an in-memory destination for consumers that do not persist.
    #[must_use]
    pub fn in_memory(ring: Arc<Mutex<EntryRing>>) -> Arc<Self> {
        Arc::new(Self {
            ring,
            writer: None,
            failure: Mutex::new(None),
        })
    }

    /// Construct a destination that persists entries before retaining them.
    #[must_use]
    pub fn with_writer(ring: Arc<Mutex<EntryRing>>, writer: JournalWriter) -> Arc<Self> {
        Arc::new(Self {
            ring,
            writer: Some(Mutex::new(Some(writer))),
            failure: Mutex::new(None),
        })
    }

    /// Persist and retain one entry.
    ///
    /// A failed append is recorded for the daemon's control loop.  Subsequent
    /// entries are not accepted after that failure, preserving the ordering
    /// contract between durable and in-memory state.
    pub fn record(&self, entry: JournalEntry) {
        if self.failure().is_some() {
            return;
        }

        if let Some(writer) = &self.writer {
            let Ok(mut guard) = writer.lock() else {
                self.record_failure("journal writer lock poisoned".into());
                return;
            };
            let Some(writer) = guard.as_mut() else {
                self.record_failure("journal writer is already closed".into());
                return;
            };
            if let Err(error) = writer.append(&entry) {
                self.record_failure(error.to_string());
                return;
            }
        }

        match self.ring.lock() {
            Ok(mut ring) => ring.push(entry),
            Err(_) => self.record_failure("journal ring lock poisoned".into()),
        }
    }

    /// Return the first persistence failure observed by a socket handler.
    #[must_use]
    pub fn failure(&self) -> Option<String> {
        self.failure.lock().ok().and_then(|failure| failure.clone())
    }

    /// Flush and close the persisted journal, if this sink owns one.
    ///
    /// # Errors
    /// Returns an error if the journal writer cannot be locked or closed.
    pub fn shutdown(&self) -> anyhow::Result<()> {
        let Some(writer) = &self.writer else {
            return Ok(());
        };
        let mut guard = writer
            .lock()
            .map_err(|_| anyhow::anyhow!("journal writer lock poisoned during shutdown"))?;
        if let Some(writer) = guard.take() {
            writer.close()?;
        }
        Ok(())
    }

    fn record_failure(&self, failure: String) {
        if let Ok(mut stored) = self.failure.lock() {
            if stored.is_none() {
                *stored = Some(failure);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::entry::EntryRing;

    #[test]
    fn in_memory_sink_retains_entries() {
        let ring = Arc::new(Mutex::new(EntryRing::new(2)));
        let sink = JournalSink::in_memory(Arc::clone(&ring));
        sink.record(JournalEntry::message("test.service", 6, "stored"));

        let guard = ring.lock().unwrap();
        assert_eq!(guard.len(), 1);
        assert_eq!(guard.drain_since(0)[0].message_str(), "stored");
        assert!(sink.failure().is_none());
    }
}
