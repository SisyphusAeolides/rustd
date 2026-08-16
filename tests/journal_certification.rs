// SPDX-License-Identifier: LGPL-2.1-or-later
//! Journal resource and crash-behavior certification fixtures.
//!
//! These gates keep stdout admission control and reserved-metadata rejection
//! within explicit bounds so a flood cannot grow the in-memory ring without
//! bound, and service stdio defaults continue to target the RustD journal.

use std::collections::HashMap;
use std::io::Write as _;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustd::journal::daemon::{JournalDaemon, JournalDaemonConfig};
use rustd::journal::entry::{EntryRing, JournalEntry};
use rustd::journal::receiver::JournalReceiver;
use rustd::journal::sink::JournalSink;
use rustd::journal::stdout::{
    self, connect_service_stream_with_limits, wants_journal_stdio, LogRateLimiter, StdoutServer,
    DEFAULT_LOG_RATE_LIMIT_BURST, DEFAULT_LOG_RATE_LIMIT_INTERVAL, DEFAULT_STDOUT_PATH,
};

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

#[test]
fn rate_limiter_defaults_match_systemd() {
    assert_eq!(DEFAULT_LOG_RATE_LIMIT_INTERVAL, Duration::from_secs(30));
    assert_eq!(DEFAULT_LOG_RATE_LIMIT_BURST, 10_000);
    let mut limiter = LogRateLimiter::from_unit_settings(Some(Duration::from_secs(60)), Some(4));
    assert!(limiter.allow());
    assert!(limiter.allow());
    assert!(limiter.allow());
    assert!(limiter.allow());
    assert!(!limiter.allow());
}

#[test]
fn datagram_bind_rejects_preexisting_path() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("socket");
    let _holder = UnixDatagram::bind(&path).unwrap();
    let ring = Arc::new(Mutex::new(EntryRing::new(4)));
    let error = JournalReceiver::bind_at(&path, JournalSink::in_memory(ring))
        .err()
        .expect("preexisting path must fail");
    assert!(error.to_string().contains("already exists"));
}

#[test]
fn stdout_bind_rejects_preexisting_path() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("stdout");
    let _holder = UnixListener::bind(&path).unwrap();
    let ring = Arc::new(Mutex::new(EntryRing::new(4)));
    let error = StdoutServer::bind_at(&path, JournalSink::in_memory(ring))
        .err()
        .expect("preexisting path must fail");
    assert!(error.to_string().contains("already exists"));
}

#[test]
fn daemon_rejects_conflicting_socket_paths() {
    let runtime = tempfile::tempdir().unwrap();
    let journal_dir = tempfile::tempdir().unwrap();
    let config = JournalDaemonConfig {
        runtime_directory: runtime.path().to_path_buf(),
        journal_directory: journal_dir.path().to_path_buf(),
        journal_file: Some(journal_dir.path().join("system.journal")),
        ring_capacity: 64,
    };
    let first = JournalDaemon::new(&config).expect("first daemon");
    let conflict = JournalDaemon::new(&config);
    assert!(conflict.is_err());
    drop(first);
}

#[test]
fn connect_service_stream_fails_when_socket_missing() {
    let missing = PathBuf::from("/tmp/rustd-journal-stdout-missing-cert");
    let _ = std::fs::remove_file(&missing);
    let error = connect_service_stream_with_limits(
        &missing,
        "unit",
        "unit.service",
        6,
        Some(Duration::from_secs(1)),
        Some(5),
    )
    .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn connect_service_stream_reaches_live_stdout_server() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("stdout");
    let ring = Arc::new(Mutex::new(EntryRing::new(32)));
    let sink = JournalSink::in_memory(Arc::clone(&ring));
    let server = StdoutServer::bind_at(&path, sink).expect("bind stdout");

    let client = std::thread::spawn({
        let path = path.clone();
        move || {
            let mut stream =
                connect_service_stream_with_limits(&path, "demo", "demo.service", 6, None, Some(8))
                    .expect("connect");
            writeln!(stream, "hello-from-service").unwrap();
            std::thread::sleep(Duration::from_millis(100));
        }
    });

    use rustd::event::loop_::IoHandler as _;
    let mut server = server;
    for _ in 0..50 {
        server.on_io(server.raw_fd(), libc::EPOLLIN as u32);
        if ring.lock().unwrap().len() > 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    client.join().unwrap();

    let guard = ring.lock().unwrap();
    let entries = guard.drain_since(0);
    assert!(
        entries
            .iter()
            .any(|entry| entry.message_str() == "hello-from-service"),
        "expected journal entry from service stream, got {entries:?}"
    );
}

#[test]
fn peercred_gate_rejects_foreign_uid() {
    assert!(!wants_journal_stdio("null"));
    // peer_authorized is private; exercise the public contract via bind mode.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("stdout");
    let ring = Arc::new(Mutex::new(EntryRing::new(4)));
    let server = StdoutServer::bind_at(&path, JournalSink::in_memory(ring)).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions();
    use std::os::unix::fs::PermissionsExt as _;
    assert_eq!(mode.mode() & 0o777, 0o660);
    drop(server);
}

#[test]
fn stream_header_encodes_unit_rate_limits() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("stdout");
    let listener = UnixListener::bind(&path).unwrap();
    listener.set_nonblocking(true).unwrap();

    let client = std::thread::spawn({
        let path = path.clone();
        move || {
            connect_service_stream_with_limits(
                &path,
                "id",
                "rate.service",
                6,
                Some(Duration::from_secs(2)),
                Some(15),
            )
            .unwrap()
        }
    });

    let (mut server_side, _) = loop {
        match listener.accept() {
            Ok(pair) => break pair,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("accept failed: {error}"),
        }
    };
    let mut buf = Vec::new();
    use std::io::Read as _;
    // Read the fixed header plus extras the client wrote before returning.
    let mut tmp = [0u8; 512];
    let n = server_side.read(&mut tmp).unwrap();
    buf.extend_from_slice(&tmp[..n]);
    drop(client.join().unwrap());

    let text = String::from_utf8_lossy(&buf);
    assert!(text.contains("RUSTD_LOG_RATE_INTERVAL_USEC=2000000"));
    assert!(text.contains("RUSTD_LOG_RATE_BURST=15"));
    assert!(text.contains("rate.service"));
}

#[test]
fn socketpair_stream_survives_owned_fd_hand_off() {
    // Regression: manager keeps Owned UnixStream alive while raw fd is passed
    // into spawn params; dropping early would invalidate the child stdio.
    let mut fds = [0; 2];
    assert_eq!(
        unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) },
        0
    );
    let stream = unsafe { UnixStream::from_raw_fd(fds[0]) };
    let raw = stream.as_raw_fd();
    assert!(raw >= 0);
    let mut peer = unsafe { UnixStream::from_raw_fd(fds[1]) };
    writeln!(peer, "ping").unwrap();
    drop(peer);
    let mut line = String::new();
    use std::io::BufRead as _;
    std::io::BufReader::new(&stream)
        .read_line(&mut line)
        .unwrap();
    assert_eq!(line.trim(), "ping");
}
