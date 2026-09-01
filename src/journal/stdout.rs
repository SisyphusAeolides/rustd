// SPDX-License-Identifier: LGPL-2.1-or-later
//! Journal stdout stream server.
//!
//! Listens on `/run/rustd/journal/stdout` (a `SOCK_STREAM` Unix socket),
//! accepts connections onto a bounded worker pool, and turns each line into a
//! [`JournalEntry`] pushed into the shared sink.
//!
//! # Connection protocol
//!
//! Compatible with systemd v261 `src/journald/journald-stream.c` / `rustd-cat`:
//!
//! ```text
//! IDENTIFIER\n
//! UNIT_NAME\n
//! PRIORITY\n
//! LEVEL_PREFIX\n
//! FORWARD_SECURE_SEALING\n
//! NAMESPACE\n
//! EXTRA_FIELDS_COUNT\n
//! log line 1\n
//! …
//! ```
//!
//! Trusted identity (`_PID`, `_UID`, `_GID`, and unit when the peer is not
//! privileged) is derived from `SO_PEERCRED`, never from sender-controlled
//! reserved `_` fields in the payload.

use std::collections::HashMap;
use std::io::{BufRead, Read as _};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use crate::event::loop_::IoHandler;
use crate::journal::entry::{priority, EntryRing, JournalEntry};
use crate::journal::sink::JournalSink;
use crate::journal::socket::SocketPathGuard;

/// The native `RustD` journal stdout path used by installed execution.
pub const DEFAULT_STDOUT_PATH: &str = "/run/rustd/journal/stdout";

const MAX_ACTIVE_CONNECTIONS: usize = 128;
const MAX_HEADER_LINE_BYTES: usize = 4 * 1024;
const MAX_MESSAGE_LINE_BYTES: usize = 64 * 1024;
const MAX_MESSAGES_PER_CONNECTION: usize = 100_000;
const WORKER_COUNT: usize = 4;
const ACCEPT_QUEUE_CAPACITY: usize = 64;
/// systemd v261 default `LogRateLimitIntervalSec`.
pub const DEFAULT_LOG_RATE_LIMIT_INTERVAL: Duration = Duration::from_secs(30);
/// systemd v261 default `LogRateLimitBurst`.
pub const DEFAULT_LOG_RATE_LIMIT_BURST: u32 = 10_000;

#[derive(Clone, Copy, Debug)]
struct PeerCred {
    pid: libc::pid_t,
    uid: libc::uid_t,
    gid: libc::gid_t,
}

struct AcceptedConnection {
    fd: RawFd,
    peer: PeerCred,
}

struct WorkerPool {
    sender: SyncSender<AcceptedConnection>,
    active: Arc<AtomicUsize>,
}

type WorkerPoolSlot = Option<(usize, Arc<WorkerPool>)>;

impl WorkerPool {
    fn global(sink: Arc<JournalSink>) -> Arc<Self> {
        static POOL: OnceLock<Mutex<WorkerPoolSlot>> = OnceLock::new();
        let sink_addr = Arc::as_ptr(&sink) as usize;
        let slot = POOL.get_or_init(|| Mutex::new(None));
        let mut guard = slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((addr, pool)) = guard.as_ref() {
            if *addr == sink_addr {
                return Arc::clone(pool);
            }
        }
        let pool = Self::spawn(sink);
        *guard = Some((sink_addr, Arc::clone(&pool)));
        pool
    }

    fn spawn(sink: Arc<JournalSink>) -> Arc<Self> {
        let (sender, receiver) = mpsc::sync_channel::<AcceptedConnection>(ACCEPT_QUEUE_CAPACITY);
        let active = Arc::new(AtomicUsize::new(0));
        let receiver = Arc::new(Mutex::new(receiver));
        for _ in 0..WORKER_COUNT {
            let sink = Arc::clone(&sink);
            let receiver = Arc::clone(&receiver);
            let active = Arc::clone(&active);
            thread::Builder::new()
                .name("rustd-journal-stdout".into())
                .spawn(move || loop {
                    let job = {
                        let Ok(guard) = receiver.lock() else {
                            break;
                        };
                        guard.recv()
                    };
                    let Ok(job) = job else {
                        break;
                    };
                    active.fetch_add(1, Ordering::Relaxed);
                    serve_connection(job.fd, &sink, job.peer);
                    active.fetch_sub(1, Ordering::Relaxed);
                })
                .expect("spawn journal stdout worker");
        }
        Arc::new(Self { sender, active })
    }

    fn try_submit(&self, job: AcceptedConnection) -> Result<(), AcceptedConnection> {
        if self.active.load(Ordering::Relaxed) >= MAX_ACTIVE_CONNECTIONS {
            return Err(job);
        }
        self.sender.try_send(job).map_err(|error| match error {
            mpsc::TrySendError::Full(job) | mpsc::TrySendError::Disconnected(job) => job,
        })
    }
}

pub struct StdoutServer {
    pub listen_fd: RawFd,
    _listener: OwnedFd,
    _path_guard: Option<SocketPathGuard>,
    pool: Arc<WorkerPool>,
}

impl StdoutServer {
    /// Bind the installed `RustD` journal stdout socket.
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
        if path.exists() {
            return Err(anyhow::anyhow!(
                "journal stdout socket already exists: {}",
                path.display()
            ));
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let listener = UnixListener::bind(path)
            .map_err(|error| anyhow::anyhow!("bind journal stdout {}: {error}", path.display()))?;
        let path_guard = SocketPathGuard::capture(path)?;
        listener.set_nonblocking(true)?;
        // Root-owned clients (manager, helpers) and the journal group; world
        // write is intentionally omitted so untrusted peers cannot flood PID1.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;

        let pool = WorkerPool::global(Arc::clone(&sink));
        let raw = listener.into_raw_fd();
        let listener = unsafe { OwnedFd::from_raw_fd(raw) };
        let listen_fd = listener.as_raw_fd();
        Ok(Self {
            listen_fd,
            _listener: listener,
            _path_guard: Some(path_guard),
            pool,
        })
    }

    /// Adopt an already-bound stream listener supplied by a RustD socket
    /// unit. The socket unit owns the filesystem path and lifecycle.
    pub fn from_inherited_fd(fd: RawFd, sink: Arc<JournalSink>) -> anyhow::Result<Self> {
        // SAFETY: the caller transfers ownership of this activation fd to the
        // server and does not use or close it afterwards.
        let listener = unsafe { UnixListener::from_raw_fd(fd) };
        listener.set_nonblocking(true)?;
        let pool = WorkerPool::global(Arc::clone(&sink));
        let raw = listener.into_raw_fd();
        // SAFETY: `raw` is the owned descriptor returned by `into_raw_fd`.
        let listener = unsafe { OwnedFd::from_raw_fd(raw) };
        let listen_fd = listener.as_raw_fd();
        Ok(Self {
            listen_fd,
            _listener: listener,
            _path_guard: None,
            pool,
        })
    }

    #[must_use]
    pub fn raw_fd(&self) -> RawFd {
        self.listen_fd
    }
}

impl IoHandler for StdoutServer {
    fn on_io(&mut self, _fd: i32, _events: u32) {
        loop {
            let conn_fd = unsafe {
                libc::accept4(
                    self.listen_fd,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    libc::SOCK_CLOEXEC,
                )
            };
            if conn_fd < 0 {
                break;
            }
            let peer = match peer_credentials(conn_fd) {
                Some(peer) => peer,
                None => {
                    unsafe { libc::close(conn_fd) };
                    continue;
                }
            };
            if !peer_authorized(peer) {
                unsafe { libc::close(conn_fd) };
                continue;
            }
            if self
                .pool
                .try_submit(AcceptedConnection { fd: conn_fd, peer })
                .is_err()
            {
                unsafe { libc::close(conn_fd) };
            }
        }
    }
}

fn peer_authorized(peer: PeerCred) -> bool {
    peer.uid == 0 || peer.uid == unsafe { libc::geteuid() }
}

/// Token-bucket rate limiter matching systemd journald's per-unit log limits.
#[derive(Debug)]
pub struct LogRateLimiter {
    interval: Duration,
    burst: u32,
    tokens: u32,
    window_start: Instant,
}

impl LogRateLimiter {
    /// Build a limiter from unit settings, falling back to systemd defaults.
    #[must_use]
    pub fn from_unit_settings(interval: Option<Duration>, burst: Option<u32>) -> Self {
        let interval = interval
            .filter(|value| !value.is_zero())
            .unwrap_or(DEFAULT_LOG_RATE_LIMIT_INTERVAL);
        let burst = burst
            .filter(|value| *value > 0)
            .unwrap_or(DEFAULT_LOG_RATE_LIMIT_BURST);
        Self {
            interval,
            burst,
            tokens: burst,
            window_start: Instant::now(),
        }
    }

    /// Return whether one more log line may be recorded.
    pub fn allow(&mut self) -> bool {
        let now = Instant::now();
        if now.duration_since(self.window_start) >= self.interval {
            self.window_start = now;
            self.tokens = self.burst;
        }
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }
}

fn peer_credentials(fd: RawFd) -> Option<PeerCred> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of_val(&cred) as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::addr_of_mut!(cred).cast(),
            &mut length,
        )
    };
    if result == 0 {
        Some(PeerCred {
            pid: cred.pid,
            uid: cred.uid,
            gid: cred.gid,
        })
    } else {
        None
    }
}

fn read_bounded_line(reader: &mut impl BufRead, limit: usize) -> Result<String, ()> {
    let mut buf = Vec::new();
    let mut take = reader.take(limit as u64 + 1);
    let read = take.read_until(b'\n', &mut buf).map_err(|_| ())?;
    if read == 0 {
        return Err(());
    }
    if buf.len() > limit {
        return Err(());
    }
    if buf.last() == Some(&b'\n') {
        buf.pop();
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
    }
    String::from_utf8(buf).map_err(|_| ())
}

fn serve_connection(conn_fd: RawFd, sink: &Arc<JournalSink>, peer: PeerCred) {
    serve_connection_with_limiter(conn_fd, sink, peer, None);
}

fn serve_connection_with_limiter(
    conn_fd: RawFd,
    sink: &Arc<JournalSink>,
    peer: PeerCred,
    limiter_override: Option<LogRateLimiter>,
) {
    let stream = unsafe { UnixStream::from_raw_fd(conn_fd) };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let mut reader = std::io::BufReader::new(stream);

    let Ok(identifier) = read_bounded_line(&mut reader, MAX_HEADER_LINE_BYTES) else {
        return;
    };
    let Ok(unit_name) = read_bounded_line(&mut reader, MAX_HEADER_LINE_BYTES) else {
        return;
    };
    let Ok(priority_line) = read_bounded_line(&mut reader, MAX_HEADER_LINE_BYTES) else {
        return;
    };
    // LEVEL_PREFIX, FORWARD_SECURE_SEALING, NAMESPACE
    for _ in 0..3 {
        if read_bounded_line(&mut reader, MAX_HEADER_LINE_BYTES).is_err() {
            return;
        }
    }
    let Ok(extra_count_line) = read_bounded_line(&mut reader, MAX_HEADER_LINE_BYTES) else {
        return;
    };
    let extra_count: usize = extra_count_line.parse().unwrap_or(0).min(32);

    let mut interval = None;
    let mut burst = None;
    for _ in 0..extra_count {
        let Ok(extra) = read_bounded_line(&mut reader, MAX_HEADER_LINE_BYTES) else {
            return;
        };
        if let Some((key, value)) = extra.split_once('=') {
            match key {
                "RUSTD_LOG_RATE_INTERVAL_USEC" => {
                    if let Ok(usec) = value.parse::<u64>() {
                        interval = Some(Duration::from_micros(usec));
                    }
                }
                "RUSTD_LOG_RATE_BURST" => {
                    if let Ok(value) = value.parse::<u32>() {
                        burst = Some(value);
                    }
                }
                _ => {}
            }
        }
    }

    let mut limiter =
        limiter_override.unwrap_or_else(|| LogRateLimiter::from_unit_settings(interval, burst));

    let prio: u8 = priority_line.parse().unwrap_or(priority::INFO);
    // Privileged peers (manager / helper) may declare the unit; everyone else
    // keeps only peer-credential identity.
    let trusted_unit = if peer.uid == 0 || peer.uid == unsafe { libc::geteuid() } {
        unit_name
    } else {
        String::new()
    };

    for _ in 0..MAX_MESSAGES_PER_CONNECTION {
        let Ok(line) = read_bounded_line(&mut reader, MAX_MESSAGE_LINE_BYTES) else {
            break;
        };
        if line.is_empty() {
            continue;
        }
        if !limiter.allow() {
            continue;
        }

        let mut fields: HashMap<String, Vec<u8>> = HashMap::new();
        fields.insert("MESSAGE".into(), line.into_bytes());
        fields.insert("PRIORITY".into(), prio.to_string().into_bytes());
        if !identifier.is_empty() {
            fields.insert("SYSLOG_IDENTIFIER".into(), identifier.as_bytes().to_vec());
        }
        if !trusted_unit.is_empty() {
            fields.insert("_SYSTEMD_UNIT".into(), trusted_unit.as_bytes().to_vec());
            fields.insert("_RUSTD_UNIT".into(), trusted_unit.as_bytes().to_vec());
        }
        fields.insert("_PID".into(), peer.pid.to_string().into_bytes());
        fields.insert("_UID".into(), peer.uid.to_string().into_bytes());
        fields.insert("_GID".into(), peer.gid.to_string().into_bytes());
        fields.insert("_TRANSPORT".into(), b"stdout".to_vec());

        sink.record(JournalEntry::new(fields));
    }
}

/// Connect to the journal stdout socket and write the systemd-compatible
/// stream header. Used by the manager when routing service stdio.
///
/// # Errors
///
/// Returns an I/O error when the socket cannot be reached or the header
/// cannot be written.
pub fn connect_service_stream(
    path: &Path,
    identifier: &str,
    unit_name: &str,
    priority: u8,
) -> std::io::Result<UnixStream> {
    connect_service_stream_with_limits(path, identifier, unit_name, priority, None, None)
}

/// Connect with explicit `LogRateLimit*` settings encoded as stream extras.
///
/// # Errors
///
/// Returns an I/O error when the socket cannot be reached or the header
/// cannot be written.
pub fn connect_service_stream_with_limits(
    path: &Path,
    identifier: &str,
    unit_name: &str,
    priority: u8,
    rate_interval: Option<Duration>,
    rate_burst: Option<u32>,
) -> std::io::Result<UnixStream> {
    let mut stream = UnixStream::connect(path)?;
    stream.shutdown(std::net::Shutdown::Read)?;
    use std::io::Write as _;
    let interval = rate_interval
        .filter(|value| !value.is_zero())
        .unwrap_or(DEFAULT_LOG_RATE_LIMIT_INTERVAL);
    let burst = rate_burst
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_LOG_RATE_LIMIT_BURST);
    write!(
        stream,
        "{identifier}\n{unit_name}\n{priority}\n0\n0\n\n2\nRUSTD_LOG_RATE_INTERVAL_USEC={}\nRUSTD_LOG_RATE_BURST={burst}\n",
        u64::try_from(interval.as_micros()).unwrap_or(u64::MAX),
    )?;
    Ok(stream)
}

/// Whether a `StandardOutput=` / `StandardError=` value should be connected
/// to the `RustD` journal stream.
#[must_use]
pub fn wants_journal_stdio(value: &str) -> bool {
    let normalized = value.trim();
    normalized.is_empty()
        || normalized.eq_ignore_ascii_case("journal")
        || normalized.eq_ignore_ascii_case("journal+console")
        || normalized.eq_ignore_ascii_case("inherit")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn default_stdout_path_is_native_rustd() {
        assert_eq!(DEFAULT_STDOUT_PATH, "/run/rustd/journal/stdout");
    }

    #[test]
    fn wants_journal_for_default_and_journal_modes() {
        assert!(wants_journal_stdio(""));
        assert!(wants_journal_stdio("journal"));
        assert!(wants_journal_stdio("journal+console"));
        assert!(!wants_journal_stdio("null"));
        assert!(!wants_journal_stdio("tty"));
    }

    #[test]
    fn serve_connection_pushes_entries_with_peer_metadata() {
        let ring = Arc::new(Mutex::new(EntryRing::new(64)));
        let sink = JournalSink::in_memory(Arc::clone(&ring));
        let mut fds = [0i32; 2];
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        assert_eq!(rc, 0);

        let writer_fd = fds[1];
        let server_fd = fds[0];
        let mut w = unsafe { UnixStream::from_raw_fd(writer_fd) };
        write!(
            w,
            "myapp\ntest.service\n6\n0\n0\n\n0\nfirst line\nsecond line\n"
        )
        .unwrap();
        drop(w);

        let peer = PeerCred {
            pid: 4242,
            uid: 0,
            gid: 0,
        };
        serve_connection(server_fd, &sink, peer);

        let guard = ring.lock().unwrap();
        let entries = guard.drain_since(0);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].message_str(), "first line");
        assert_eq!(entries[1].message_str(), "second line");
        assert_eq!(entries[0].priority(), 6);
        assert_eq!(entries[0].unit(), "test.service");
        assert_eq!(entries[0].pid_str(), "4242");
    }

    #[test]
    fn serve_connection_rejects_oversized_line() {
        let ring = Arc::new(Mutex::new(EntryRing::new(64)));
        let sink = JournalSink::in_memory(Arc::clone(&ring));
        let mut fds = [0i32; 2];
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) },
            0
        );
        let mut w = unsafe { UnixStream::from_raw_fd(fds[1]) };
        write!(w, "id\nunit\n6\n0\n0\n\n0\n").unwrap();
        let huge = "x".repeat(MAX_MESSAGE_LINE_BYTES + 8);
        writeln!(w, "{huge}").unwrap();
        drop(w);
        serve_connection(
            fds[0],
            &sink,
            PeerCred {
                pid: 1,
                uid: 0,
                gid: 0,
            },
        );
        assert!(ring.lock().unwrap().drain_since(0).is_empty());
    }

    #[test]
    fn unprivileged_peer_cannot_set_unit_from_header() {
        let ring = Arc::new(Mutex::new(EntryRing::new(64)));
        let sink = JournalSink::in_memory(Arc::clone(&ring));
        let mut fds = [0i32; 2];
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) },
            0
        );
        let mut w = unsafe { UnixStream::from_raw_fd(fds[1]) };
        write!(w, "sshd\nspoofed.service\n3\n0\n0\n\n0\nerror\n").unwrap();
        drop(w);
        // Pick a uid that is neither 0 nor the current euid.
        let foreign_uid = unsafe { libc::geteuid() }.wrapping_add(1000).max(1);
        serve_connection(
            fds[0],
            &sink,
            PeerCred {
                pid: 9,
                uid: foreign_uid,
                gid: foreign_uid,
            },
        );
        let guard = ring.lock().unwrap();
        let entries = guard.drain_since(0);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].unit().is_empty());
        assert_eq!(entries[0].pid_str(), "9");
    }

    #[test]
    fn rate_limiter_drops_after_burst() {
        let mut limiter =
            LogRateLimiter::from_unit_settings(Some(Duration::from_secs(60)), Some(3));
        assert!(limiter.allow());
        assert!(limiter.allow());
        assert!(limiter.allow());
        assert!(!limiter.allow());
    }

    #[test]
    fn serve_connection_honors_rate_limit_extras() {
        let ring = Arc::new(Mutex::new(EntryRing::new(64)));
        let sink = JournalSink::in_memory(Arc::clone(&ring));
        let mut fds = [0i32; 2];
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) },
            0
        );
        let mut w = unsafe { UnixStream::from_raw_fd(fds[1]) };
        write!(
            w,
            "id\nunit\n6\n0\n0\n\n2\nRUSTD_LOG_RATE_INTERVAL_USEC=60000000\nRUSTD_LOG_RATE_BURST=2\none\ntwo\nthree\n"
        )
        .unwrap();
        drop(w);
        serve_connection(
            fds[0],
            &sink,
            PeerCred {
                pid: 1,
                uid: 0,
                gid: 0,
            },
        );
        assert_eq!(ring.lock().unwrap().len(), 2);
    }

    #[test]
    fn bind_rejects_preexisting_stdout_path() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("stdout");
        let _holder = UnixListener::bind(&path).unwrap();
        let ring = Arc::new(Mutex::new(EntryRing::new(8)));
        let err = StdoutServer::bind_at(&path, JournalSink::in_memory(ring))
            .err()
            .expect("preexisting path must fail");
        assert!(err.to_string().contains("already exists"));
    }
}
