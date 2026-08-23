// SPDX-License-Identifier: LGPL-2.1-or-later
//! Socket unit lifecycle — open listener fds for socket activation.
//!
//! A `.socket` unit listens on one or more addresses. Matching upstream
//! `Accept=no` behaviour, activating the socket only binds the listeners; the
//! companion `.service` is started when explicitly pulled in (or later by
//! connection-based activation), receiving open fds via `RUSTD_LISTEN_FDS`.
//!
//! Lifecycle:
//!   `Inactive → Activating → Active`  (fds open)
//!   `Active → Deactivating → Inactive`  (fds closed, paths unlinked)
//!
//! Upstream reference: `src/core/socket.c` (v261)

use std::ffi::CString;
use std::os::unix::io::RawFd;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::anyhow;

use crate::event::loop_::{EventLoop, IoHandler};
use crate::event::source::SourceId;
use crate::ffi::socket_activation::{
    rustd_socket_listen_datagram, rustd_socket_listen_inet_datagram,
    rustd_socket_listen_inet_stream, rustd_socket_listen_seqpacket, rustd_socket_listen_stream,
    rustd_socket_set_passcred, rustd_socket_set_rcvbuf, rustd_socket_set_sndbuf,
};
use crate::job::{JobKind, JobQueue};
use crate::service::UnitRecord;
use crate::unit::loader::LoadedUnit;
use crate::unit::section_socket::ListenSpec;
use crate::unit::UnitState;

/// Default listen backlog used when `MaxConnections=` is not set.
const DEFAULT_BACKLOG: libc::c_int = 128;

/// Open all listener fds described by a `ListenSpec` slice.
///
/// Returns a `Vec` of raw fds on success.  All returned fds have
/// `O_CLOEXEC` **cleared** so they survive exec into the triggered service.
///
/// # Errors
/// Returns an error if any `Listen*=` directive cannot be bound.
pub fn open_listen_fds(specs: &[ListenSpec], pass_cred: bool) -> anyhow::Result<Vec<RawFd>> {
    let mut fds = Vec::with_capacity(specs.len());

    for spec in specs {
        let fd = open_one(spec)?;
        if fd < 0 {
            return Err(anyhow!(
                "listen {} {}: errno {}",
                spec.kind,
                spec.address,
                -fd
            ));
        }

        // Apply PassCredentials= if requested.
        if pass_cred
            && matches!(
                spec.kind.as_str(),
                "Stream" | "Datagram" | "SequentialPacket"
            )
        {
            unsafe { rustd_socket_set_passcred(fd, 1) };
        }

        fds.push(fd);
    }

    Ok(fds)
}

/// Open a single listener fd for one `ListenSpec`.
fn open_one(spec: &ListenSpec) -> anyhow::Result<RawFd> {
    // Absolute UNIX paths need their parent directories, which early boot often
    // has not created yet (for example `/run/dbus` before dbus.socket binds).
    if spec.address.starts_with('/') {
        if let Some(parent) = Path::new(&spec.address).parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|error| {
                    anyhow!(
                        "failed to create listen directory {}: {error}",
                        parent.display()
                    )
                })?;
            }
        }
    }

    let addr = CString::new(spec.address.as_str()).map_err(|e| anyhow!("address NUL: {e}"))?;

    let fd = unsafe {
        match spec.kind.as_str() {
            "Stream" => rustd_socket_listen_stream(addr.as_ptr(), DEFAULT_BACKLOG),
            "Datagram" => rustd_socket_listen_datagram(addr.as_ptr()),
            "SequentialPacket" => rustd_socket_listen_seqpacket(addr.as_ptr(), DEFAULT_BACKLOG),
            // Numeric port strings → inet sockets.
            k if k.starts_with("Stream") || spec.address.chars().all(|c| c.is_ascii_digit()) => {
                // TCP inet port.
                rustd_socket_listen_inet_stream(addr.as_ptr(), DEFAULT_BACKLOG)
            }
            _ => {
                // Try to guess from address: numeric = inet, otherwise unix.
                if spec.address.chars().all(|c| c.is_ascii_digit()) {
                    if spec.kind.contains("Datagram") {
                        rustd_socket_listen_inet_datagram(addr.as_ptr())
                    } else {
                        rustd_socket_listen_inet_stream(addr.as_ptr(), DEFAULT_BACKLOG)
                    }
                } else {
                    // Fall back: unix stream.
                    rustd_socket_listen_stream(addr.as_ptr(), DEFAULT_BACKLOG)
                }
            }
        }
    };

    if fd < 0 {
        Err(anyhow!(
            "failed to open listen {} {}: errno {}",
            spec.kind,
            spec.address,
            -fd
        ))
    } else {
        Ok(fd)
    }
}

/// Close all fds in `fds` and remove any `AF_UNIX` socket paths.
pub fn close_listen_fds(fds: &[RawFd], specs: &[ListenSpec]) {
    for &fd in fds {
        unsafe { libc::close(fd) };
    }
    // Remove unix socket paths so the address can be reused.
    for spec in specs {
        if !spec.address.starts_with('/') {
            continue;
        }
        if let Ok(path) = CString::new(spec.address.as_str()) {
            unsafe { libc::unlink(path.as_ptr()) };
        }
    }
}

/// Apply optional buffer-size options from `SocketSection` to each open fd.
pub fn apply_socket_opts(fds: &[RawFd], recv_buf: Option<u64>, send_buf: Option<u64>) {
    for &fd in fds {
        if let Some(sz) = recv_buf {
            #[allow(clippy::cast_possible_truncation)]
            unsafe {
                rustd_socket_set_rcvbuf(fd, sz.min(i32::MAX as u64) as libc::c_int)
            };
        }
        if let Some(sz) = send_buf {
            #[allow(clippy::cast_possible_truncation)]
            unsafe {
                rustd_socket_set_sndbuf(fd, sz.min(i32::MAX as u64) as libc::c_int)
            };
        }
    }
}

// ── SocketRecord ──────────────────────────────────────────────────────────

/// Runtime state for an active socket unit.
#[derive(Debug, Default)]
pub struct SocketRecord {
    /// The open listener file descriptors (empty when `Inactive`).
    pub listen_fds: Vec<RawFd>,
    /// Event-loop registrations which trigger the companion service.
    pub source_ids: Vec<SourceId>,
}

impl Drop for SocketRecord {
    fn drop(&mut self) {
        for &fd in &self.listen_fds {
            unsafe { libc::close(fd) };
        }
    }
}

// ── activate_socket ───────────────────────────────────────────────────────

/// Activate a socket unit: open listener fds and transition to `Active`.
///
/// Matching upstream socket units with `Accept=no`, this only binds the
/// listeners. The associated service is started when it is pulled in by a
/// target/`Wants=` edge or later by connection-based activation — not as a
/// side effect of opening the socket. Prematurely starting every derived
/// `*.service` breaks sockets whose companion unit is missing or differently
/// named (for example `polkit-agent-helper.socket`).
///
/// # Errors
/// Returns an error if the unit is not a `Socket` or if any fd cannot be
/// opened.
pub fn activate_socket(
    record: &mut UnitRecord,
    sock_rec: &mut SocketRecord,
    event_loop: &mut EventLoop,
    queue: &Arc<Mutex<JobQueue>>,
) -> anyhow::Result<()> {
    let LoadedUnit::Socket(ref sock) = record.loaded else {
        return Err(anyhow!(
            "activate_socket called on non-socket unit '{}'",
            record.loaded.name()
        ));
    };

    let fds = open_listen_fds(&sock.specific.listen, sock.specific.pass_credentials)?;
    apply_socket_opts(
        &fds,
        sock.specific.receive_buffer,
        sock.specific.send_buffer,
    );

    let service_name = triggered_service_name(record.loaded.name(), &sock.specific.service);
    let trigger_limit = Arc::new(Mutex::new(TriggerLimit::new(
        sock.specific
            .trigger_limit_interval_sec
            .unwrap_or(Duration::from_secs(2)),
        sock.specific.trigger_limit_burst.unwrap_or(20),
    )));
    let mut source_ids = Vec::with_capacity(fds.len());
    for &fd in &fds {
        match event_loop.add_io(
            fd,
            libc::EPOLLIN as u32,
            Box::new(SocketReadableHandler {
                socket_name: record.loaded.name().to_owned(),
                service_name: service_name.clone(),
                queue: Arc::clone(queue),
                trigger_limit: Arc::clone(&trigger_limit),
            }),
        ) {
            Ok(source_id) => source_ids.push(source_id),
            Err(error) => {
                for source_id in source_ids {
                    let _ = event_loop.remove_io(source_id);
                }
                close_listen_fds(&fds, &sock.specific.listen);
                return Err(error);
            }
        }
    }

    sock_rec.listen_fds = fds;
    sock_rec.source_ids = source_ids;
    record.state = UnitState::Active;

    Ok(())
}

/// Deactivate a socket unit: close listener fds and transition to `Inactive`.
pub fn deactivate_socket(
    record: &mut UnitRecord,
    sock_rec: &mut SocketRecord,
    event_loop: &mut EventLoop,
) {
    let LoadedUnit::Socket(ref sock) = record.loaded else {
        return;
    };
    for source_id in sock_rec.source_ids.drain(..) {
        let _ = event_loop.remove_io(source_id);
    }
    close_listen_fds(&sock_rec.listen_fds, &sock.specific.listen);
    sock_rec.listen_fds.clear();
    record.state = UnitState::Inactive;
}

struct SocketReadableHandler {
    socket_name: String,
    service_name: String,
    queue: Arc<Mutex<JobQueue>>,
    trigger_limit: Arc<Mutex<TriggerLimit>>,
}

struct TriggerLimit {
    interval: Duration,
    burst: u32,
    window_started: Instant,
    count: u32,
    tripped: bool,
}

impl TriggerLimit {
    fn new(interval: Duration, burst: u32) -> Self {
        Self {
            interval,
            burst,
            window_started: Instant::now(),
            count: 0,
            tripped: false,
        }
    }

    fn admit(&mut self, now: Instant) -> TriggerDecision {
        if self.burst == 0 || self.interval.is_zero() {
            return TriggerDecision::Start;
        }
        if now.duration_since(self.window_started) >= self.interval {
            self.window_started = now;
            self.count = 0;
        }
        if self.count < self.burst {
            self.count += 1;
            return TriggerDecision::Start;
        }
        if self.tripped {
            TriggerDecision::Ignore
        } else {
            self.tripped = true;
            TriggerDecision::StopSocket
        }
    }
}

enum TriggerDecision {
    Start,
    StopSocket,
    Ignore,
}

impl IoHandler for SocketReadableHandler {
    fn on_io(&mut self, _fd: i32, events: u32) {
        if events & libc::EPOLLIN as u32 == 0 {
            return;
        }
        let decision = self
            .trigger_limit
            .lock()
            .map_or(TriggerDecision::Ignore, |mut limit| {
                limit.admit(Instant::now())
            });
        if let Ok(mut queue) = self.queue.lock() {
            match decision {
                TriggerDecision::Start => {
                    queue.enqueue(JobKind::Start, self.service_name.clone());
                }
                TriggerDecision::StopSocket => {
                    eprintln!(
                        "rustd: trigger limit hit for '{}'; stopping socket",
                        self.socket_name
                    );
                    queue.enqueue_internal(JobKind::Stop, self.socket_name.clone());
                }
                TriggerDecision::Ignore => {}
            }
        }
    }
}

// ── helpers ───────────────────────────────────────────────────────────────

/// Derive the service name triggered by a socket unit.
///
/// Rules (matching upstream):
/// 1. If `Service=` is set explicitly, use that.
/// 2. Otherwise replace `.socket` suffix with `.service`.
#[must_use]
pub fn triggered_service_name(socket_name: &str, explicit_service: &str) -> String {
    if !explicit_service.is_empty() {
        return explicit_service.to_owned();
    }
    if let Some(stem) = socket_name.strip_suffix(".socket") {
        format!("{stem}.service")
    } else {
        format!("{socket_name}.service")
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unit::loader::{LoadedUnit, ParsedUnit};
    use crate::unit::section_install::InstallSection;
    use crate::unit::section_socket::{ListenSpec, SocketSection};
    use crate::unit::section_unit::UnitSection;
    use std::path::PathBuf;

    #[test]
    fn triggered_service_name_strips_suffix() {
        assert_eq!(triggered_service_name("foo.socket", ""), "foo.service");
    }

    #[test]
    fn triggered_service_name_explicit_wins() {
        assert_eq!(
            triggered_service_name("foo.socket", "bar.service"),
            "bar.service"
        );
    }

    #[test]
    fn triggered_service_name_no_suffix() {
        assert_eq!(triggered_service_name("foo", ""), "foo.service");
    }

    #[test]
    fn socket_record_default_empty() {
        let r = SocketRecord::default();
        assert_eq!(r.listen_fds.len(), 0);
    }

    #[test]
    fn listener_starts_companion_only_after_traffic() {
        let root = tempfile::tempdir().unwrap();
        let socket_path = root.path().join("trigger.sock");
        let loaded = LoadedUnit::Socket(Box::new(ParsedUnit {
            name: "trigger.socket".to_owned(),
            source_path: PathBuf::from("/fake/trigger.socket"),
            unit: UnitSection::default(),
            install: InstallSection::default(),
            specific: SocketSection {
                listen: vec![ListenSpec {
                    kind: "Stream".to_owned(),
                    address: socket_path.display().to_string(),
                }],
                ..Default::default()
            },
        }));
        let mut record = UnitRecord::new(loaded);
        let mut socket_record = SocketRecord::default();
        let mut event_loop = EventLoop::new().unwrap();
        let queue = Arc::new(Mutex::new(JobQueue::default()));

        activate_socket(&mut record, &mut socket_record, &mut event_loop, &queue).unwrap();
        assert!(queue.lock().unwrap().is_empty());

        let _connection = std::os::unix::net::UnixStream::connect(&socket_path).unwrap();
        event_loop.run_once_timeout(100).unwrap();
        let job = queue.lock().unwrap().pop_front().unwrap();
        assert_eq!(job.unit_name, "trigger.service");

        deactivate_socket(&mut record, &mut socket_record, &mut event_loop);
    }

    #[test]
    fn trigger_limit_stops_a_persistently_readable_socket() {
        let root = tempfile::tempdir().unwrap();
        let socket_path = root.path().join("limited.sock");
        let loaded = LoadedUnit::Socket(Box::new(ParsedUnit {
            name: "limited.socket".to_owned(),
            source_path: PathBuf::from("/fake/limited.socket"),
            unit: UnitSection::default(),
            install: InstallSection::default(),
            specific: SocketSection {
                listen: vec![ListenSpec {
                    kind: "Stream".to_owned(),
                    address: socket_path.display().to_string(),
                }],
                trigger_limit_interval_sec: Some(Duration::from_secs(60)),
                trigger_limit_burst: Some(1),
                ..Default::default()
            },
        }));
        let mut record = UnitRecord::new(loaded);
        let mut socket_record = SocketRecord::default();
        let mut event_loop = EventLoop::new().unwrap();
        let queue = Arc::new(Mutex::new(JobQueue::default()));

        activate_socket(&mut record, &mut socket_record, &mut event_loop, &queue).unwrap();
        let _connection = std::os::unix::net::UnixStream::connect(&socket_path).unwrap();
        event_loop.run_once_timeout(100).unwrap();
        assert_eq!(
            queue.lock().unwrap().pop_front().unwrap().unit_name,
            "limited.service"
        );
        event_loop.run_once_timeout(100).unwrap();
        let stop = queue.lock().unwrap().pop_front().unwrap();
        assert_eq!(stop.kind, JobKind::Stop);
        assert_eq!(stop.unit_name, "limited.socket");

        deactivate_socket(&mut record, &mut socket_record, &mut event_loop);
    }
}
