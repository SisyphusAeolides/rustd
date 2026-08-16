// SPDX-License-Identifier: LGPL-2.1-or-later
//! Socket unit lifecycle — open listener fds, activate triggered service.
//!
//! A `.socket` unit listens on one or more addresses and, when a connection
//! arrives (or immediately for `Accept=no`), triggers its associated
//! `.service` unit, passing the open listener fds via the `RUSTD_LISTEN_FDS`
//! protocol.
//!
//! Lifecycle:
//!   `Inactive → Activating → Active`  (fds open, service triggered)
//!   `Active → Deactivating → Inactive`  (fds closed, paths unlinked)
//!
//! Upstream reference: `src/core/socket.c` (v261)

use std::ffi::CString;
use std::os::unix::io::RawFd;

use anyhow::anyhow;

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
/// Enqueues a `Start` job for the triggered service so the manager picks it
/// up on the next loop iteration and passes the fds via `RUSTD_LISTEN_FDS`.
///
/// # Errors
/// Returns an error if the unit is not a `Socket` or if any fd cannot be
/// opened.
pub fn activate_socket(
    record: &mut UnitRecord,
    sock_rec: &mut SocketRecord,
    queue: &mut JobQueue,
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

    sock_rec.listen_fds = fds;
    record.state = UnitState::Active;

    // Derive the triggered service name.
    let svc_name = triggered_service_name(record.loaded.name(), &sock.specific.service);
    queue.enqueue(JobKind::Start, svc_name);

    Ok(())
}

/// Deactivate a socket unit: close listener fds and transition to `Inactive`.
pub fn deactivate_socket(record: &mut UnitRecord, sock_rec: &mut SocketRecord) {
    let LoadedUnit::Socket(ref sock) = record.loaded else {
        return;
    };
    close_listen_fds(&sock_rec.listen_fds, &sock.specific.listen);
    sock_rec.listen_fds.clear();
    record.state = UnitState::Inactive;
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
}
