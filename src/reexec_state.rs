// SPDX-License-Identifier: LGPL-2.1-or-later
//! Persistent state handoff for in-place manager re-execution.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::ManagerScope;
use crate::unit::UnitState;

pub const REEXEC_STATE_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
pub struct ReexecState {
    pub version: u32,
    pub scope: String,
    pub units: Vec<ReexecUnitState>,
    pub sockets: Vec<ReexecSocketState>,
    pub reload_count: u64,
    pub startup_finished_emitted: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReexecUnitState {
    pub name: String,
    pub state: UnitState,
    pub active_pid: Option<libc::pid_t>,
    pub control_pid: Option<libc::pid_t>,
    pub stop_requested: bool,
    pub restart_count: u32,
    pub last_start_ns: i64,
    pub start_limit_window_ns: i64,
    pub start_limit_count: u32,
    pub dynamic_uid: Option<libc::uid_t>,
    pub status_text: Option<String>,
    pub status_errno: Option<i32>,
    pub watchdog_timestamp_ns: Option<i64>,
    pub watchdog_timestamp_realtime_ns: Option<i64>,
    pub exec_main_start_realtime_ns: Option<i64>,
    pub exec_main_start_monotonic_ns: Option<i64>,
    pub exec_main_exit_realtime_ns: Option<i64>,
    pub exec_main_exit_monotonic_ns: Option<i64>,
    pub watchdog_triggered: bool,
    pub service_result: String,
    pub exec_main_code: i32,
    pub exec_main_status: i32,
    pub invocation_id: Option<[u8; 16]>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReexecSocketState {
    pub name: String,
    pub listen_fds: Vec<libc::c_int>,
}

#[must_use]
pub fn state_path(scope: ManagerScope) -> PathBuf {
    match scope {
        ManagerScope::System => PathBuf::from("/run/rustd/reexec-state.json"),
        ManagerScope::User => {
            let root = std::env::var_os("XDG_RUNTIME_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(format!("/run/user/{}", unsafe { libc::getuid() })));
            root.join("rustd/reexec-state.json")
        }
    }
}

pub fn write_state(path: &Path, state: &ReexecState) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("reexec state path has no parent"))?;
    fs::create_dir_all(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    let temporary = parent.join(format!(".reexec-state-{}.tmp", std::process::id()));
    let payload = serde_json::to_vec(state)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temporary)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(&payload)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    if let Ok(directory) = fs::File::open(parent) {
        let _ = directory.sync_all();
    }
    Ok(())
}

pub fn read_state(path: &Path) -> anyhow::Result<ReexecState> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        anyhow::bail!("reexec state is not a regular file: {}", path.display());
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        anyhow::bail!("reexec state has unexpected owner: {}", path.display());
    }
    if metadata.mode() & 0o077 != 0 {
        anyhow::bail!("reexec state is group/world accessible: {}", path.display());
    }
    let state: ReexecState = serde_json::from_slice(&fs::read(path)?)?;
    if state.version != REEXEC_STATE_VERSION {
        anyhow::bail!(
            "unsupported reexec state version {} (expected {})",
            state.version,
            REEXEC_STATE_VERSION
        );
    }
    Ok(state)
}

#[must_use]
pub fn scope_name(scope: ManagerScope) -> &'static str {
    match scope {
        ManagerScope::System => "system",
        ManagerScope::User => "user",
    }
}
