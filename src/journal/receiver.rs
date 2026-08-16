// SPDX-License-Identifier: LGPL-2.1-or-later
//! Journal datagram receiver.
//!
//! Wraps the journal datagram socket fd, implements [`IoHandler`], and parses
//! incoming `rustd_journal_sendv`-style datagrams into [`JournalEntry`] values
//! pushed into an `Arc<Mutex<EntryRing>>`.
//!
//! Compatibility reference: systemd v261 `src/journald/journald-server.c`.
//!
//! # Wire protocol
//!
//! Each datagram is a sequence of newline-separated fields. Each field is
//! either:
//!
//! - `KEY=value\n` — printable text value, or
//! - `KEY\n` followed by a little-endian `uint64_t` length, followed by
//!   `length` raw bytes, followed by `\n` — binary / large value.
//!
//! Fields that start with `_` are trusted metadata; others are user-supplied.

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::event::loop_::IoHandler;
use crate::ffi::journal::{rustd_journal_socket_recv, JOURNAL_RECV_BUF};
use crate::journal::entry::{EntryRing, JournalEntry};
use crate::journal::sink::JournalSink;
use crate::journal::socket::SocketPathGuard;

/// The native `RustD` journal datagram path used by installed execution.
pub const DEFAULT_SOCKET_PATH: &str = "/run/rustd/journal/socket";

pub struct JournalReceiver {
    pub fd: RawFd,
    _socket: OwnedFd,
    _path_guard: SocketPathGuard,
    sink: Arc<JournalSink>,
}

impl JournalReceiver {
    /// Bind the installed `RustD` journal datagram socket.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket cannot be bound or configured.
    pub fn new(ring: Arc<Mutex<EntryRing>>) -> anyhow::Result<Self> {
        Self::bind_at(Path::new(DEFAULT_SOCKET_PATH), JournalSink::in_memory(ring))
    }

    /// Bind a nonblocking journal datagram socket at `path`.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket path already exists, the socket cannot
    /// be bound, or its nonblocking mode or permissions cannot be configured.
    pub fn bind_at(path: &Path, sink: Arc<JournalSink>) -> anyhow::Result<Self> {
        let socket = UnixDatagram::bind(path)
            .map_err(|error| anyhow::anyhow!("bind journal socket {}: {error}", path.display()))?;
        let path_guard = SocketPathGuard::capture(path)?;
        socket.set_nonblocking(true)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;

        let raw = socket.into_raw_fd();
        let socket = unsafe { OwnedFd::from_raw_fd(raw) };
        let fd = socket.as_raw_fd();
        Ok(Self {
            fd,
            _socket: socket,
            _path_guard: path_guard,
            sink,
        })
    }

    #[must_use]
    pub fn raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl IoHandler for JournalReceiver {
    fn on_io(&mut self, _fd: i32, _events: u32) {
        let mut buf = vec![0u8; JOURNAL_RECV_BUF];
        loop {
            let n =
                unsafe { rustd_journal_socket_recv(self.fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                break;
            }
            #[allow(clippy::cast_sign_loss)]
            let data = &buf[..n as usize];
            if let Some(entry) = parse_datagram(data) {
                self.sink.record(entry);
            }
        }
    }
}

fn parse_datagram(data: &[u8]) -> Option<JournalEntry> {
    let mut fields: HashMap<String, Vec<u8>> = HashMap::new();
    let mut pos = 0usize;

    while pos < data.len() {
        let nl_offset = data[pos..].iter().position(|&b| b == b'\n');
        let line_end = nl_offset.map_or(data.len(), |n| pos + n);
        let line = &data[pos..line_end];
        pos = line_end + 1;

        if line.is_empty() {
            continue;
        }

        if let Some(eq) = line.iter().position(|&b| b == b'=') {
            let key = std::str::from_utf8(&line[..eq]).ok()?.to_ascii_uppercase();
            let val = line[eq + 1..].to_vec();
            fields.insert(key, val);
        } else {
            let key = std::str::from_utf8(line).ok()?.to_ascii_uppercase();
            if pos + 8 > data.len() {
                break;
            }
            #[allow(clippy::cast_possible_truncation)]
            let len = u64::from_le_bytes(data[pos..pos + 8].try_into().ok()?) as usize;
            pos += 8;
            if pos + len > data.len() {
                break;
            }
            let val = data[pos..pos + len].to_vec();
            pos += len + 1;
            fields.insert(key, val);
        }
    }

    fields.remove("_BOOT_ID");
    if fields.is_empty() {
        return None;
    }
    Some(JournalEntry::new(fields))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::entry::current_boot_id;

    fn make_text_datagram(fields: &[(&str, &str)]) -> Vec<u8> {
        let mut buf = Vec::new();
        for (k, v) in fields {
            buf.extend_from_slice(k.as_bytes());
            buf.push(b'=');
            buf.extend_from_slice(v.as_bytes());
            buf.push(b'\n');
        }
        buf
    }

    fn make_binary_datagram(key: &str, value: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(key.as_bytes());
        buf.push(b'\n');
        let len = value.len() as u64;
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(value);
        buf.push(b'\n');
        buf
    }

    #[test]
    fn default_socket_path_is_native_rustd() {
        assert_eq!(DEFAULT_SOCKET_PATH, "/run/rustd/journal/socket");
    }

    #[test]
    fn parse_text_fields() {
        let data = make_text_datagram(&[("MESSAGE", "hello"), ("PRIORITY", "6")]);
        let entry = parse_datagram(&data).expect("should parse");
        assert_eq!(entry.message_str(), "hello");
        assert_eq!(entry.priority(), 6);
    }

    #[test]
    fn parse_binary_field() {
        let value = b"\x00\x01\x02binary";
        let mut data = make_binary_datagram("MESSAGE", value);
        data.extend_from_slice(b"PRIORITY=3\n");
        let entry = parse_datagram(&data).expect("should parse binary");
        assert_eq!(
            entry.fields.get("MESSAGE").map(Vec::as_slice),
            Some(value.as_slice())
        );
        assert_eq!(entry.priority(), 3);
    }

    #[test]
    fn parse_empty_returns_none() {
        assert!(parse_datagram(b"").is_none());
        assert!(parse_datagram(b"\n\n\n").is_none());
    }

    #[test]
    fn key_is_uppercased() {
        let data = make_text_datagram(&[("message", "hi")]);
        let entry = parse_datagram(&data).expect("should parse");
        assert!(entry.fields.contains_key("MESSAGE"));
    }

    #[test]
    fn sender_cannot_spoof_boot_id() {
        let data = make_text_datagram(&[
            ("MESSAGE", "hello"),
            ("_BOOT_ID", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ]);
        let entry = parse_datagram(&data).expect("should parse");
        if let Some(boot_id) = current_boot_id() {
            assert_eq!(
                entry.fields.get("_BOOT_ID").map(Vec::as_slice),
                Some(boot_id.as_bytes())
            );
        } else {
            assert!(!entry.fields.contains_key("_BOOT_ID"));
        }
    }
}
