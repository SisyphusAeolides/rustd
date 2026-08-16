// SPDX-License-Identifier: LGPL-2.1-or-later
//! IPC server — binds the control socket, serves `rustctl` requests.
//!
//! The server runs in a dedicated thread; the main event loop thread publishes
//! a snapshot of unit state via `Arc<RwLock<Vec<UnitInfo>>>` which the server
//! reads without blocking the event loop.  Jobs are injected into the
//! pre-existing `Arc<Mutex<JobQueue>>` (shared with the timer sub-system).
//!
//! Upstream reference: `src/core/dbus-manager.c` (v261)

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex, RwLock,
};
use std::time::Duration;

use crate::config::ManagerScope;
use crate::event::EventLoopWake;
use crate::ipc::{
    control_socket_path, decode_request, encode_response, user_control_socket_path, IpcData,
    IpcJobInfo, IpcRequest, IpcResponse, UnitInfo, FRAME_MAX,
};
use crate::job::{JobKind, JobQueue};

const IPC_IO_TIMEOUT: Duration = Duration::from_secs(2);
const IPC_READ_CHUNK: usize = 4096;
const IPC_ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

/// Requests from client control paths to clear unit failure state.
pub type ResetFailedRequests = Arc<Mutex<Vec<Vec<String>>>>;

// ── IpcServer ─────────────────────────────────────────────────────────────

/// Owns the control socket and the spawned server thread.
pub struct IpcServer {
    // Keep the listener fd alive so the socket is not closed while running.
    _listener: Arc<UnixListener>,
    socket_path: PathBuf,
}

impl IpcServer {
    /// Bind the control socket and spawn the server thread.
    ///
    /// # Errors
    /// Returns an error if the socket cannot be created or bound.
    pub fn start(
        scope: ManagerScope,
        snapshot: &Arc<RwLock<Vec<UnitInfo>>>,
        jobs: &Arc<Mutex<JobQueue>>,
        wake: EventLoopWake,
        reload_flag: &Arc<AtomicBool>,
        reset_failed_requests: &ResetFailedRequests,
    ) -> anyhow::Result<Self> {
        let socket_path = match scope {
            ManagerScope::System => control_socket_path(),
            ManagerScope::User => user_control_socket_path(),
        };
        let dir = socket_path.parent().unwrap_or(std::path::Path::new("/run"));
        fs::create_dir_all(dir)
            .map_err(|error| anyhow::anyhow!("IPC runtime directory {}: {error}", dir.display()))?;

        // Remove stale socket file.
        let _ = fs::remove_file(&socket_path);

        let listener = UnixListener::bind(&socket_path)
            .map_err(|error| anyhow::anyhow!("IPC bind {}: {error}", socket_path.display()))?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600)).map_err(|error| {
            anyhow::anyhow!("IPC permissions {}: {error}", socket_path.display())
        })?;
        let listener = Arc::new(listener);
        // Spawn server thread.
        let thr_listener = Arc::clone(&listener);
        let thr_snapshot = Arc::clone(snapshot);
        let thr_jobs = Arc::clone(jobs);
        let thr_reload = Arc::clone(reload_flag);
        let thr_reset_failed = Arc::clone(reset_failed_requests);

        std::thread::Builder::new()
            .name("ipc-server".into())
            .spawn(move || {
                server_loop(
                    &thr_listener,
                    &thr_snapshot,
                    &thr_jobs,
                    &thr_reload,
                    &thr_reset_failed,
                    &wake,
                );
            })
            .map_err(|e| anyhow::anyhow!("IPC thread spawn: {e}"))?;

        Ok(Self {
            _listener: listener,
            socket_path,
        })
    }
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.socket_path);
    }
}

// ── Server loop ───────────────────────────────────────────────────────────

fn server_loop(
    listener: &UnixListener,
    snapshot: &Arc<RwLock<Vec<UnitInfo>>>,
    jobs: &Arc<Mutex<JobQueue>>,
    reload: &Arc<AtomicBool>,
    reset_failed_requests: &ResetFailedRequests,
    wake: &EventLoopWake,
) {
    for stream in listener.incoming() {
        match stream {
            Ok(mut conn) => {
                if let Err(error) = conn.set_read_timeout(Some(IPC_IO_TIMEOUT)) {
                    eprintln!("rustd: native IPC read-timeout setup failed: {error}");
                    continue;
                }
                if let Err(error) = conn.set_write_timeout(Some(IPC_IO_TIMEOUT)) {
                    eprintln!("rustd: native IPC write-timeout setup failed: {error}");
                    continue;
                }
                let resp = match read_request_frame(&mut conn) {
                    Err(error) => IpcResponse::err(error),
                    Ok(req) => dispatch(req, snapshot, jobs, reload, reset_failed_requests, wake),
                };
                if let Ok(bytes) = encode_response(&resp) {
                    let _ = conn.write_all(&bytes);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => {
                eprintln!("rustd: native IPC accept failed: {error}");
                std::thread::sleep(IPC_ACCEPT_ERROR_BACKOFF);
            }
        }
    }
}

/// Read one JSON request from a stream transport.
///
/// Unix streams may split a single client write across multiple `read(2)`
/// calls, so a request is complete only once the JSON decoder no longer
/// reports an EOF condition. Invalid JSON fails immediately and the hard frame
/// limit prevents an incomplete client from growing memory without bound.
fn read_request_frame(reader: &mut impl Read) -> Result<IpcRequest, String> {
    let mut frame = Vec::with_capacity(512);
    let mut chunk = [0u8; IPC_READ_CHUNK];

    loop {
        if frame.len() == FRAME_MAX {
            return Err(format!("request exceeds {FRAME_MAX}-byte frame limit"));
        }
        let remaining = FRAME_MAX - frame.len();
        let limit = remaining.min(chunk.len());
        let length = match reader.read(&mut chunk[..limit]) {
            Ok(0) => return Err("connection closed before a complete request".to_owned()),
            Ok(length) => length,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(format!("request read failed: {error}")),
        };
        frame.extend_from_slice(&chunk[..length]);

        match decode_request(&frame) {
            Ok(request) => return Ok(request),
            Err(error)
                if error
                    .downcast_ref::<serde_json::Error>()
                    .is_some_and(serde_json::Error::is_eof) =>
            {
                continue;
            }
            Err(error) => return Err(format!("bad request: {error}")),
        }
    }
}

// ── Dispatcher ────────────────────────────────────────────────────────────

fn dispatch(
    req: IpcRequest,
    snapshot: &Arc<RwLock<Vec<UnitInfo>>>,
    jobs: &Arc<Mutex<JobQueue>>,
    reload: &Arc<AtomicBool>,
    reset_failed_requests: &ResetFailedRequests,
    wake: &EventLoopWake,
) -> IpcResponse {
    match req {
        IpcRequest::ListUnits => {
            let guard = snapshot
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            IpcResponse::with_data(IpcData::Units(guard.clone()))
        }

        IpcRequest::ListJobs => {
            let Ok(queue) = jobs.lock() else {
                return IpcResponse::err("internal: job queue lock poisoned");
            };
            let jobs = queue
                .registry()
                .list()
                .into_iter()
                .map(|job| IpcJobInfo {
                    id: job.id,
                    unit_name: job.unit_name,
                    job_type: job.kind.as_str().to_owned(),
                    state: job.state.as_str().to_owned(),
                })
                .collect();
            IpcResponse::with_data(IpcData::Jobs(jobs))
        }

        IpcRequest::Status { unit } => {
            let guard = snapshot
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match guard.iter().find(|u| u.name == unit) {
                Some(info) => IpcResponse::with_data(IpcData::Unit(info.clone())),
                None => IpcResponse::err(format!("unit '{unit}' not loaded")),
            }
        }

        IpcRequest::Start { unit } => enqueue_job(jobs, wake, JobKind::Start, unit),

        IpcRequest::Stop { unit } => enqueue_job(jobs, wake, JobKind::Stop, unit),

        IpcRequest::Restart { unit } => enqueue_job(jobs, wake, JobKind::Restart, unit),

        IpcRequest::Reload { unit } => enqueue_job(jobs, wake, JobKind::Reload, unit),

        IpcRequest::Isolate { unit } => enqueue_job(jobs, wake, JobKind::Isolate, unit),

        IpcRequest::IsActive { unit } | IpcRequest::IsFailed { unit } => {
            let guard = snapshot
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match guard.iter().find(|u| u.name == unit) {
                Some(info) => IpcResponse::with_data(IpcData::Text(info.active_state.clone())),
                None => IpcResponse::err(format!("unit '{unit}' not loaded")),
            }
        }

        IpcRequest::ResetFailed { units } => match reset_failed_requests.lock() {
            Ok(mut requests) => {
                requests.push(units);
                wake_response(wake)
            }
            Err(_) => IpcResponse::err("internal: reset-failed queue lock poisoned"),
        },

        IpcRequest::DaemonReload => {
            reload.store(true, Ordering::Release);
            wake_response(wake)
        }

        IpcRequest::Cancel { job_id } => {
            let canceled = match jobs.lock() {
                Ok(mut queue) => match job_id {
                    Some(id) => queue.cancel(id),
                    None => queue.cancel_all() > 0,
                },
                Err(_) => return IpcResponse::err("internal: job queue lock poisoned"),
            };
            if canceled {
                wake_response(wake)
            } else {
                match job_id {
                    Some(id) => IpcResponse::err(format!("job {id} does not exist")),
                    None => IpcResponse::ok(),
                }
            }
        }

        // Enable/disable/is-enabled are handled entirely in rustctl (file ops).
        IpcRequest::Enable { .. } | IpcRequest::Disable { .. } | IpcRequest::IsEnabled { .. } => {
            IpcResponse::err("enable/disable are client-side file operations")
        }
    }
}

fn enqueue_job(
    jobs: &Arc<Mutex<JobQueue>>,
    wake: &EventLoopWake,
    kind: JobKind,
    unit: String,
) -> IpcResponse {
    match jobs.lock() {
        Ok(mut queue) => {
            queue.enqueue(kind, unit);
        }
        Err(_) => return IpcResponse::err("internal: job queue lock poisoned"),
    }
    wake_response(wake)
}

fn wake_response(wake: &EventLoopWake) -> IpcResponse {
    wake.wake().map_or_else(
        |error| IpcResponse::err(format!("internal: event loop wake failed: {error}")),
        |()| IpcResponse::ok(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::encode_request;
    use std::io::Cursor;
    use std::os::unix::net::UnixStream;

    #[test]
    fn fragmented_stream_request_is_reassembled() {
        let request = IpcRequest::Start {
            unit: "fragmented.service".to_owned(),
        };
        let encoded = encode_request(&request).expect("encode request");
        let split = encoded.len() / 2;
        let (mut writer, mut reader) = UnixStream::pair().expect("stream pair");
        let first = encoded[..split].to_vec();
        let second = encoded[split..].to_vec();
        let sender = std::thread::spawn(move || {
            writer.write_all(&first).expect("first fragment");
            std::thread::sleep(Duration::from_millis(10));
            writer.write_all(&second).expect("second fragment");
        });

        let decoded = read_request_frame(&mut reader).expect("fragmented request");
        sender.join().expect("sender thread");
        assert_eq!(decoded, request);
    }

    #[test]
    fn invalid_stream_request_fails_without_waiting_for_eof() {
        let mut input = Cursor::new(b"{invalid-json".to_vec());
        let error = read_request_frame(&mut input).expect_err("invalid request");
        assert!(error.starts_with("bad request:"));
    }

    #[test]
    fn incomplete_frame_is_bounded() {
        let mut input = Cursor::new(vec![b' '; FRAME_MAX]);
        let error = read_request_frame(&mut input).expect_err("oversized incomplete request");
        assert!(error.contains("frame limit"));
    }
}
