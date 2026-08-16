// SPDX-License-Identifier: LGPL-2.1-or-later
//! IPC wire protocol between the manager and `rustctl`.
//!
//! The manager binds a `SOCK_SEQPACKET` socket at [`SOCKET_PATH`].
//! Each transaction is one request frame followed by one response frame,
//! both JSON-encoded and newline-terminated, capped at [`FRAME_MAX`] bytes.
//!
//! Upstream reference: `src/rustctl/rustctl.c`,
//!   `src/core/dbus-manager.c` (v261)

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Path of the manager's control socket.
pub const SOCKET_PATH: &str = "/run/rustd/ctl.sock";

/// Resolve the manager control socket path.
///
/// `RUSTD_CONTROL_SOCKET` is primarily used by user managers, test
/// environments, and containers that cannot write below `/run`.
#[must_use]
pub fn control_socket_path() -> PathBuf {
    std::env::var_os("RUSTD_CONTROL_SOCKET")
        .map_or_else(|| PathBuf::from(SOCKET_PATH), PathBuf::from)
}

/// Resolve the per-user manager control socket path.
///
/// This follows the user manager's runtime directory rather than the global
/// `/run/rustd` namespace. Tests and containers may still override the
/// result with `RUSTD_CONTROL_SOCKET`.
#[must_use]
pub fn user_control_socket_path() -> PathBuf {
    if let Some(path) = std::env::var_os("RUSTD_CONTROL_SOCKET") {
        return PathBuf::from(path);
    }
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").map_or_else(
        || PathBuf::from(format!("/run/user/{}", unsafe { libc::getuid() })),
        PathBuf::from,
    );
    runtime.join("rustd/ctl.sock")
}

/// Maximum frame size (64 KiB).
pub const FRAME_MAX: usize = 65536;

// ── Request ───────────────────────────────────────────────────────────────

/// A command sent from `rustctl` to the manager.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cmd", content = "args", rename_all = "kebab-case")]
pub enum IpcRequest {
    /// Return a list of all loaded units.
    ListUnits,
    /// Return all jobs that are waiting or running.
    ListJobs,
    /// Return detailed information about one unit.
    Status { unit: String },
    /// Enqueue a `Start` job for the named unit.
    Start { unit: String },
    /// Enqueue a `Stop` job for the named unit.
    Stop { unit: String },
    /// Enqueue `Stop` then `Start` for the named unit.
    Restart { unit: String },
    /// Run the named unit's reload transaction.
    Reload { unit: String },
    /// Replace the active unit graph with the named isolatable target.
    Isolate { unit: String },
    /// Create `[Install]` symlinks for the named unit.
    Enable { unit: String },
    /// Remove `[Install]` symlinks for the named unit.
    Disable { unit: String },
    /// Report whether the unit is enabled.
    IsEnabled { unit: String },
    /// Report whether the unit is active.
    IsActive { unit: String },
    /// Report whether the unit is failed.
    IsFailed { unit: String },
    /// Clear failure state for named units, or every loaded unit when empty.
    ResetFailed { units: Vec<String> },
    /// Re-scan unit directories and reload changed units.
    DaemonReload,
    /// Cancel one job, or all pending jobs when no identifier is supplied.
    Cancel { job_id: Option<u32> },
}

// ── Response ──────────────────────────────────────────────────────────────

/// The manager's reply to a single request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcResponse {
    /// `true` on success, `false` on error.
    pub ok: bool,
    /// Human-readable error message when `ok == false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Response payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<IpcData>,
}

impl IpcResponse {
    /// Construct a success response with no payload.
    #[must_use]
    pub fn ok() -> Self {
        Self {
            ok: true,
            error: None,
            data: None,
        }
    }

    /// Construct a success response with a payload.
    #[must_use]
    pub fn with_data(data: IpcData) -> Self {
        Self {
            ok: true,
            error: None,
            data: Some(data),
        }
    }

    /// Construct an error response.
    #[must_use]
    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(msg.into()),
            data: None,
        }
    }
}

// ── Payload types ─────────────────────────────────────────────────────────

/// Discriminated union of all possible response payloads.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "type", content = "value")]
pub enum IpcData {
    /// A list of unit summaries (list-units).
    Units(Vec<UnitInfo>),
    /// A single unit's detailed info (status).
    Unit(UnitInfo),
    /// A list of currently live jobs (list-jobs).
    Jobs(Vec<IpcJobInfo>),
    /// A simple string result (is-enabled, is-active, is-failed).
    Text(String),
}

/// Job information returned by `list-jobs`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IpcJobInfo {
    /// Stable numeric job identifier.
    pub id: u32,
    /// Unit to which the job applies.
    pub unit_name: String,
    /// Canonical systemd job type, for example `start`.
    pub job_type: String,
    /// Canonical systemd job state, either `waiting` or `running`.
    pub state: String,
}

/// Service-specific runtime state exposed to D-Bus.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServiceRuntimeInfo {
    /// Per-start invocation identifier assigned by the manager.
    ///
    /// This is absent until the candidate has launched the service, matching
    /// the empty `Unit.InvocationID` value exposed for inactive units.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invocation_id: Option<[u8; 16]>,
    /// Number of automatic restart attempts.
    pub restart_count: u32,
    /// Configured `BusName=` for `Type=dbus` readiness monitoring.
    pub bus_name: Option<String>,
    /// PID of the current service control process.
    pub control_pid: Option<i32>,
    /// Latest `STATUS=` notification.
    pub status_text: Option<String>,
    /// Latest `ERRNO=` notification.
    pub status_errno: Option<i32>,
    /// Monotonic timestamp (ns) of the latest readiness/watchdog notification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub watchdog_timestamp_ns: Option<i64>,
    /// Realtime timestamp (ns) of the latest readiness/watchdog notification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub watchdog_timestamp_realtime_ns: Option<i64>,
    /// Realtime timestamp (ns) of the most recent main-process start.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec_main_start_realtime_ns: Option<i64>,
    /// Monotonic timestamp (ns) of the most recent main-process start.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec_main_start_monotonic_ns: Option<i64>,
    /// Realtime timestamp (ns) of the most recent main-process exit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec_main_exit_realtime_ns: Option<i64>,
    /// Monotonic timestamp (ns) of the most recent main-process exit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec_main_exit_monotonic_ns: Option<i64>,
    /// Upstream-compatible service result string.
    pub result: String,
    /// `siginfo.si_code` for the most recent main-process exit.
    pub exec_main_code: i32,
    /// Exit status or signal for the most recent main-process exit.
    pub exec_main_status: i32,
    /// Active `DynamicUser` allocation, if this service currently holds one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dynamic_user: Option<DynamicUserInfo>,
    /// Configured upper bound for the service descriptor store.
    ///
    /// The store itself is manager-owned runtime state; zero means that
    /// `FileDescriptorStoreMax=` is not enabled for this service.
    #[serde(default)]
    pub file_descriptor_store_max: u32,
}

/// One realized dynamic user allocation owned by a running service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DynamicUserInfo {
    /// Allocated UID, which is also used as the service GID.
    pub uid: u32,
    /// Dynamic account name.
    pub name: String,
}

/// Per-unit information returned by list-units and status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnitInfo {
    /// Unit file name, e.g. `"systemd-journald.service"`.
    pub name: String,
    /// Load state: `"loaded"`, `"not-found"`, `"masked"`.
    pub load_state: String,
    /// Active state: `"active"`, `"inactive"`, `"activating"`,
    /// `"deactivating"`, `"failed"`, `"maintenance"`.
    pub active_state: String,
    /// Sub-state (mirrors `active_state` for now; refined in Phase E).
    pub sub_state: String,
    /// Human-readable description from `[Unit] Description=`.
    pub description: String,
    /// Main PID, if the unit has an active process.
    pub main_pid: Option<i32>,
    /// Unit type: `"service"`, `"target"`, `"timer"`, etc.
    pub unit_type: String,
    /// `Type=` value for service units (`"simple"`, `"forking"`, …).
    /// `None` for non-service units.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_type: Option<String>,
    /// `Restart=` value for service units (`"no"`, `"on-failure"`, …).
    /// `None` for non-service units.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restart_policy: Option<String>,
    /// Runtime service state. Neutral for non-service units and older frames.
    #[serde(default)]
    pub service_runtime: Box<ServiceRuntimeInfo>,
}

// ── Frame I/O ─────────────────────────────────────────────────────────────

/// Serialise a request to JSON bytes (no trailing newline).
///
/// # Errors
/// Returns an error if JSON serialisation fails (should never happen for
/// well-formed `IpcRequest` values).
pub fn encode_request(req: &IpcRequest) -> anyhow::Result<Vec<u8>> {
    Ok(serde_json::to_vec(req)?)
}

/// Deserialise a response from a JSON byte slice.
///
/// # Errors
/// Returns an error if the bytes are not valid UTF-8 or valid JSON for
/// `IpcResponse`.
pub fn decode_response(buf: &[u8]) -> anyhow::Result<IpcResponse> {
    Ok(serde_json::from_slice(buf)?)
}

/// Deserialise a request from a JSON byte slice.
///
/// # Errors
/// Returns an error if the bytes are not valid UTF-8 or valid JSON for
/// `IpcRequest`.
pub fn decode_request(buf: &[u8]) -> anyhow::Result<IpcRequest> {
    Ok(serde_json::from_slice(buf)?)
}

/// Serialise a response to JSON bytes.
///
/// # Errors
/// Returns an error if JSON serialisation fails.
pub fn encode_response(resp: &IpcResponse) -> anyhow::Result<Vec<u8>> {
    Ok(serde_json::to_vec(resp)?)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_units_round_trip() {
        let req = IpcRequest::ListUnits;
        let bytes = encode_request(&req).unwrap();
        let back: IpcRequest = serde_json::from_slice(&bytes).unwrap();
        assert!(matches!(back, IpcRequest::ListUnits));
    }

    #[test]
    fn list_jobs_and_cancel_round_trip() {
        let requests = [
            IpcRequest::ListJobs,
            IpcRequest::Cancel { job_id: Some(42) },
            IpcRequest::Cancel { job_id: None },
            IpcRequest::ResetFailed {
                units: vec!["foo.service".to_owned()],
            },
        ];
        for request in requests {
            let bytes = encode_request(&request).unwrap();
            let back: IpcRequest = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(back, request);
        }
    }

    #[test]
    fn start_round_trip() {
        let req = IpcRequest::Start {
            unit: "foo.service".into(),
        };
        let bytes = encode_request(&req).unwrap();
        let back: IpcRequest = serde_json::from_slice(&bytes).unwrap();
        assert!(matches!(back, IpcRequest::Start { unit } if unit == "foo.service"));
    }

    #[test]
    fn reload_round_trip() {
        let req = IpcRequest::Reload {
            unit: "foo.service".into(),
        };
        let bytes = encode_request(&req).unwrap();
        let back: IpcRequest = serde_json::from_slice(&bytes).unwrap();
        assert!(matches!(back, IpcRequest::Reload { unit } if unit == "foo.service"));
    }

    #[test]
    fn response_ok_no_data() {
        let resp = IpcResponse::ok();
        let bytes = encode_response(&resp).unwrap();
        let back = decode_response(&bytes).unwrap();
        assert!(back.ok);
        assert!(back.data.is_none());
        assert!(back.error.is_none());
    }

    #[test]
    fn response_err() {
        let resp = IpcResponse::err("unit not found");
        let bytes = encode_response(&resp).unwrap();
        let back = decode_response(&bytes).unwrap();
        assert!(!back.ok);
        assert_eq!(back.error.as_deref(), Some("unit not found"));
    }

    #[test]
    fn unit_info_serializes() {
        let info = UnitInfo {
            name: "test.service".into(),
            load_state: "loaded".into(),
            active_state: "active".into(),
            sub_state: "running".into(),
            description: "Test".into(),
            main_pid: Some(1234),
            unit_type: "service".into(),
            service_type: Some("simple".into()),
            restart_policy: Some("no".into()),
            service_runtime: Box::default(),
        };
        let resp = IpcResponse::with_data(IpcData::Unit(info));
        let bytes = encode_response(&resp).unwrap();
        let back = decode_response(&bytes).unwrap();
        assert!(back.ok);
        assert!(matches!(back.data, Some(IpcData::Unit(_))));
    }

    #[test]
    fn job_info_serializes() {
        let response = IpcResponse::with_data(IpcData::Jobs(vec![IpcJobInfo {
            id: 7,
            unit_name: "demo.service".into(),
            job_type: "start".into(),
            state: "waiting".into(),
        }]));
        let bytes = encode_response(&response).unwrap();
        let back = decode_response(&bytes).unwrap();
        assert!(matches!(back.data, Some(IpcData::Jobs(jobs)) if jobs.len() == 1));
    }
}
