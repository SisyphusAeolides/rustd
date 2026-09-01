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
//! Fields that start with `_` are trusted metadata and are never accepted from
//! the sender. Peer `_PID`/`_UID`/`_GID` come from `SCM_CREDENTIALS`.

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
    _path_guard: Option<SocketPathGuard>,
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
        if path.exists() {
            return Err(anyhow::anyhow!(
                "journal datagram socket already exists: {}",
                path.display()
            ));
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let socket = UnixDatagram::bind(path)
            .map_err(|error| anyhow::anyhow!("bind journal socket {}: {error}", path.display()))?;
        let path_guard = SocketPathGuard::capture(path)?;
        socket.set_nonblocking(true)?;
        // World-writable for unprivileged local clients; identity is recovered
        // from SCM_CREDENTIALS, never from the payload.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
        enable_passcred(socket.as_raw_fd())?;

        let raw = socket.into_raw_fd();
        let socket = unsafe { OwnedFd::from_raw_fd(raw) };
        let fd = socket.as_raw_fd();
        Ok(Self {
            fd,
            _socket: socket,
            _path_guard: Some(path_guard),
            sink,
        })
    }

    /// Adopt an already-bound datagram socket supplied by a RustD socket
    /// unit. The socket unit owns the filesystem path and will remove it
    /// when deactivated; the journal daemon owns only this descriptor.
    pub fn from_inherited_fd(fd: RawFd, sink: Arc<JournalSink>) -> anyhow::Result<Self> {
        // SAFETY: the caller transfers ownership of this activation fd to the
        // receiver and does not use or close it afterwards.
        let socket = unsafe { UnixDatagram::from_raw_fd(fd) };
        socket.set_nonblocking(true)?;
        enable_passcred(socket.as_raw_fd())?;
        let raw = socket.into_raw_fd();
        // SAFETY: `raw` is the owned descriptor returned by `into_raw_fd`.
        let socket = unsafe { OwnedFd::from_raw_fd(raw) };
        let fd = socket.as_raw_fd();
        Ok(Self {
            fd,
            _socket: socket,
            _path_guard: None,
            sink,
        })
    }

    #[must_use]
    pub fn raw_fd(&self) -> RawFd {
        self.fd
    }
}

fn enable_passcred(fd: RawFd) -> anyhow::Result<()> {
    let enable: libc::c_int = 1;
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PASSCRED,
            std::ptr::addr_of!(enable).cast(),
            std::mem::size_of_val(&enable) as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "setsockopt(SO_PASSCRED) failed: {}",
            std::io::Error::last_os_error()
        ))
    }
}

impl IoHandler for JournalReceiver {
    fn on_io(&mut self, _fd: i32, _events: u32) {
        let mut buf = vec![0u8; JOURNAL_RECV_BUF];
        loop {
            let mut pid: libc::pid_t = 0;
            let mut uid: libc::uid_t = libc::uid_t::MAX;
            let mut gid: libc::gid_t = libc::gid_t::MAX;
            let n = unsafe {
                rustd_journal_socket_recv(
                    self.fd,
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    std::ptr::addr_of_mut!(pid),
                    std::ptr::addr_of_mut!(uid),
                    std::ptr::addr_of_mut!(gid),
                )
            };
            if n <= 0 {
                break;
            }
            #[allow(clippy::cast_sign_loss)]
            let data = &buf[..n as usize];
            let peer = if pid > 0 && uid != libc::uid_t::MAX {
                Some((pid, uid, gid))
            } else {
                None
            };
            if let Some(entry) = parse_datagram_with_peer(data, peer) {
                self.sink.record(entry);
            }
        }
    }
}

#[cfg(test)]
fn parse_datagram(data: &[u8]) -> Option<JournalEntry> {
    parse_datagram_with_peer(data, None)
}

fn parse_datagram_with_peer(
    data: &[u8],
    peer: Option<(libc::pid_t, libc::uid_t, libc::gid_t)>,
) -> Option<JournalEntry> {
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
            if !valid_field_name(&key) {
                continue;
            }
            // Reserved journal metadata always starts with `_` and is only
            // attached from trusted kernel/manager state below.
            if key.starts_with('_') {
                continue;
            }
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
            if !valid_field_name(&key) {
                continue;
            }
            if key.starts_with('_') {
                continue;
            }
            fields.insert(key, val);
        }
    }

    if fields.is_empty() {
        return None;
    }
    if let Some((pid, uid, gid)) = peer {
        fields.insert("_PID".into(), pid.to_string().into_bytes());
        fields.insert("_UID".into(), uid.to_string().into_bytes());
        fields.insert("_GID".into(), gid.to_string().into_bytes());
    }
    fields.insert("_TRANSPORT".into(), b"journal".to_vec());
    Some(JournalEntry::new(fields))
}

/// Return whether `key` satisfies the field-name grammar accepted by the
/// native journal writer.  `sd_journal_sendv` callers are allowed to provide
/// arbitrary extra fields, while the on-disk format accepts only ASCII
/// uppercase letters, digits, and underscores (with a non-digit first byte).
/// Normalize to uppercase before this check so callers using the historical
/// Python logging names (`name`, `pathname`, ...) remain compatible.
fn valid_field_name(key: &str) -> bool {
    let bytes = key.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 || bytes[0].is_ascii_digit() {
        return false;
    }
    bytes
        .iter()
        .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_')
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
    fn invalid_field_names_are_ignored_without_rejecting_the_entry() {
        let long_key = "A".repeat(65);
        let data = make_text_datagram(&[
            ("MESSAGE", "hello"),
            ("bad-key", "discarded"),
            ("1NOT_A_FIELD", "discarded"),
        ])
        .into_iter()
        .chain(format!("{long_key}=discarded\n").into_bytes())
        .collect::<Vec<_>>();
        let entry = parse_datagram(&data).expect("valid fields should remain");
        assert_eq!(entry.message_str(), "hello");
        assert!(!entry.fields.contains_key("BAD-KEY"));
        assert!(!entry.fields.contains_key("1NOT_A_FIELD"));
        assert!(!entry.fields.contains_key(&long_key));
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

    #[test]
    fn sender_cannot_spoof_any_reserved_metadata() {
        let data = make_text_datagram(&[
            ("MESSAGE", "hello"),
            ("_PID", "1"),
            ("_UID", "0"),
            ("_SYSTEMD_UNIT", "spoofed.service"),
            ("_RUSTD_UNIT", "spoofed.service"),
            ("_TRANSPORT", "driver"),
        ]);
        let entry = parse_datagram_with_peer(&data, Some((4242, 1000, 1000))).expect("parse");
        assert_eq!(entry.pid_str(), "4242");
        assert_eq!(
            entry.fields.get("_UID").map(Vec::as_slice),
            Some(b"1000".as_slice())
        );
        assert!(!entry.fields.contains_key("_SYSTEMD_UNIT"));
        assert_eq!(
            entry.fields.get("_TRANSPORT").map(Vec::as_slice),
            Some(b"journal".as_slice())
        );
    }

    #[test]
    fn bind_rejects_preexisting_socket_path() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("socket");
        let _holder = UnixDatagram::bind(&path).unwrap();
        let ring = Arc::new(Mutex::new(EntryRing::new(8)));
        let err = JournalReceiver::bind_at(&path, JournalSink::in_memory(ring))
            .err()
            .expect("preexisting path must fail");
        assert!(err.to_string().contains("already exists"));
    }
}
