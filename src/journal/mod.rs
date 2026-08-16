// SPDX-License-Identifier: LGPL-2.1-or-later
//! Journal subsystem: in-memory ring buffer, datagram receiver, file writer,
//! and stdout stream server.
//!
//! Upstream reference: `src/journald/` and `src/journal/` (v261).

pub mod catalog;
pub mod compression;
pub mod daemon;
pub mod entry;
pub mod receiver;
pub mod rotation;
pub mod sink;
mod socket;
pub mod stdout;
pub mod writer;
