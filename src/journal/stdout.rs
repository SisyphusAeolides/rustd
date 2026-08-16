// SPDX-License-Identifier: LGPL-2.1-or-later
//! Journal stdout stream server.
//!
//! Listens on `/run/rustd/journal/stdout` (a `SOCK_STREAM` Unix socket),
//! accepts connections, and turns each line into a [`JournalEntry`] pushed
//! into the shared ring buffer.
//!
//! # Connection protocol
//!
//! Each accepted connection sends a three-line header followed by log lines:
//!
//! ```text
//! IDENTIFIER\n
//! UNIT_NAME\n
//! PRIORITY\n
//! log line 1\n
//! log line 2\n
//! …
//! ```
//!
//! Compatibility reference: systemd v261 `src/journald/journald-stream.c`.

use std::collections::HashMap;
use std::io::BufRead as _;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::event::loop_::IoHandler;
use crate::journal::entry::{priority, EntryRing, JournalEntry};
use crate::journal::sink::JournalSink;
use crate::journal::socket::SocketPathGuard;

/// The native RustD journal stdout path used by installed execution.
pub const DEFAULT_STDOUT_PATH: &str = "/run/rustd/journal/stdout";

pub struct StdoutServer {
    pub listen_fd: RawFd,
    _listener: OwnedFd,
    _path_guard: SocketPathGuard,
    sink: Arc<JournalSink>,
}

impl StdoutServer {
    /// Bind the installed RustD journal stdout socket.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket cannot be bound or configured.
    pub fn new(ring: Arc<Mutex<EntryRing>>) -> anyhow::Result<Self> {
        Self::bind_at(Path::new(DEFAULT_STDOUT_PATH), JournalSink::in_memory(ring))
    }

    /// Bind a nonblocking journal stdout socket at `path`.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket path already exists, the socket cannot
    /// be bound, or its nonblocking mode or permissions cannot be configured.
    pub fn bind_at(path: &Path, sink: Arc<JournalSink>) -> anyhow::Result<Self> {
        let listener = UnixListener::bind(path)
            .map_err(|error| anyhow::anyhow!("bind journal stdout {}: {error}", path.display()))?;
        let path_guard = SocketPathGuard::capture(path)?;
        listener.set_nonblocking(true)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;

        let raw = listener.into_raw_fd();
        let listener = unsafe { OwnedFd::from_raw_fd(raw) };
        let listen_fd = listener.as_raw_fd();
        Ok(Self {
            listen_fd,
            _listener: listener,
            _path_guard: path_guard,
            sink,
        })
    }

    #[must_use]
    pub fn raw_fd(&self) -> RawFd {
        self.listen_fd
    }
}

impl IoHandler for StdoutServer {
    fn on_io(&mut self, _fd: i32, _events: u32) {
        let conn_fd = unsafe {
            libc::accept4(
                self.listen_fd,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        };
        if conn_fd < 0 {
            return;
        }
        let sink = Arc::clone(&self.sink);
        std::thread::spawn(move || {
            serve_connection(conn_fd, &sink);
        });
    }
}

fn serve_connection(conn_fd: RawFd, sink: &Arc<JournalSink>) {
    let stream = unsafe { <UnixStream as std::os::unix::io::FromRawFd>::from_raw_fd(conn_fd) };
    let mut reader = std::io::BufReader::new(stream);

    let mut identifier = String::new();
    let mut unit_name = String::new();
    let mut priority_line = String::new();

    if reader.read_line(&mut identifier).is_err() {
        return;
    }
    if reader.read_line(&mut unit_name).is_err() {
        return;
    }
    if reader.read_line(&mut priority_line).is_err() {
        return;
    }

    let identifier = identifier.trim_end_matches('\n').to_owned();
    let unit_name = unit_name.trim_end_matches('\n').to_owned();
    let prio: u8 = priority_line
        .trim_end_matches('\n')
        .parse()
        .unwrap_or(priority::INFO);

    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let msg = line.trim_end_matches('\n');
        if msg.is_empty() {
            continue;
        }

        let mut fields: HashMap<String, Vec<u8>> = HashMap::new();
        fields.insert("MESSAGE".into(), msg.as_bytes().to_vec());
        fields.insert("PRIORITY".into(), prio.to_string().into_bytes());
        if !identifier.is_empty() {
            fields.insert("SYSLOG_IDENTIFIER".into(), identifier.as_bytes().to_vec());
        }
        if !unit_name.is_empty() {
            fields.insert("_SYSTEMD_UNIT".into(), unit_name.as_bytes().to_vec());
        }

        let entry = JournalEntry::new(fields);
        sink.record(entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_stdout_path_is_native_rustd() {
        assert_eq!(DEFAULT_STDOUT_PATH, "/run/rustd/journal/stdout");
    }

    #[test]
    fn serve_connection_pushes_entries() {
        use std::io::Write as _;

        let ring = Arc::new(Mutex::new(EntryRing::new(64)));
        let sink = JournalSink::in_memory(Arc::clone(&ring));
        let mut fds = [0i32; 2];
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        assert_eq!(rc, 0);

        let writer_fd = fds[1];
        let server_fd = fds[0];
        let mut w = unsafe { <UnixStream as std::os::unix::io::FromRawFd>::from_raw_fd(writer_fd) };
        write!(w, "myapp\ntest.service\n6\nfirst line\nsecond line\n").unwrap();
        drop(w);

        serve_connection(server_fd, &sink);

        let guard = ring.lock().unwrap();
        let entries = guard.drain_since(0);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].message_str(), "first line");
        assert_eq!(entries[1].message_str(), "second line");
        assert_eq!(entries[0].priority(), 6);
        assert_eq!(entries[0].unit(), "test.service");
    }

    #[test]
    fn serve_connection_empty_unit() {
        use std::io::Write as _;

        let ring = Arc::new(Mutex::new(EntryRing::new(64)));
        let sink = JournalSink::in_memory(Arc::clone(&ring));
        let mut fds = [0i32; 2];
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        assert_eq!(rc, 0);

        let mut w = unsafe { <UnixStream as std::os::unix::io::FromRawFd>::from_raw_fd(fds[1]) };
        write!(w, "sshd\n\n3\nerror occurred\n").unwrap();
        drop(w);

        serve_connection(fds[0], &sink);

        let guard = ring.lock().unwrap();
        let entries = guard.drain_since(0);
        assert_eq!(entries.len(), 1);
        assert!(!entries[0].fields.contains_key("_SYSTEMD_UNIT"));
        assert_eq!(entries[0].priority(), 3);
    }
}
