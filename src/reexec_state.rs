// SPDX-License-Identifier: LGPL-2.1-or-later
//! Persistent state handoff for in-place manager re-execution.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::ManagerScope;
use crate::manager::Manager;
use crate::unit::loader::LoadedUnit;
use crate::unit::section_service::{NotifyAccess, ServiceSection, ServiceType};
use crate::unit::UnitState;

pub const REEXEC_STATE_VERSION: u32 = 2;

#[derive(Debug, Serialize, Deserialize)]
pub struct ReexecState {
    pub version: u32,
    pub scope: String,
    pub units: Vec<ReexecUnitState>,
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

#[must_use]
pub fn state_path(scope: ManagerScope) -> PathBuf {
    match scope {
        ManagerScope::System => PathBuf::from("/run/rustd/reexec-state.json"),
        ManagerScope::User => {
            let root = std::env::var_os("XDG_RUNTIME_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    PathBuf::from(format!("/run/user/{}", unsafe { libc::getuid() }))
                });
            root.join("rustd/reexec-state.json")
        }
    }
}

/// Serialize the manager state that can safely survive an in-place exec.
///
/// # Errors
///
/// Returns an error when the manager has live jobs, transitional units, event
/// sources or service modes that cannot yet be adopted after re-exec, or when
/// the owner-only state file cannot be serialized and durably written.
pub fn save_manager_state(manager: &Manager) -> anyhow::Result<PathBuf> {
    if !manager.job_registry.is_empty() || !manager.job_queue.is_empty() {
        anyhow::bail!("manager has live jobs; refusing reexec state handoff");
    }

    let mut units = Vec::with_capacity(manager.units.len());
    for (name, record) in &manager.units {
        if matches!(
            record.state,
            UnitState::Activating | UnitState::Deactivating
        ) {
            anyhow::bail!("unit '{name}' is transitional during reexec handoff");
        }
        if record.idle_gate_fd.is_some() {
            anyhow::bail!("unit '{name}' still owns an idle execution gate");
        }
        if matches!(record.state, UnitState::Active | UnitState::Failed) {
            match &record.loaded {
                LoadedUnit::Socket(_)
                | LoadedUnit::Path(_)
                | LoadedUnit::Timer(_)
                | LoadedUnit::Automount(_) => {
                    anyhow::bail!(
                        "active {} requires event-source adoption that is not yet supported by the reexec handoff: {name}",
                        unit_kind(&record.loaded)
                    );
                }
                LoadedUnit::Service(service) => {
                    if service.specific.service_type == ServiceType::Forking
                        || service.specific.exit_type == "cgroup"
                    {
                        anyhow::bail!(
                            "service '{name}' requires cgroup-source adoption that is not yet supported by the reexec handoff"
                        );
                    }
                }
                _ => {}
            }
        }
        if record.control_pid.is_some() {
            anyhow::bail!("unit '{name}' has a live control process during reexec handoff");
        }
        if record.state == UnitState::Inactive && record.restart_count > 0 {
            anyhow::bail!(
                "inactive unit '{name}' has restart history; refusing to lose a possible pending restart timer"
            );
        }
        units.push(ReexecUnitState {
            name: name.clone(),
            state: record.state,
            active_pid: record.active_pid,
            control_pid: record.control_pid,
            stop_requested: record.stop_requested,
            restart_count: record.restart_count,
            last_start_ns: record.last_start_ns,
            start_limit_window_ns: record.start_limit_window_ns,
            start_limit_count: record.start_limit_count,
            dynamic_uid: record.dynamic_user.as_ref().map(|identity| identity.uid),
            status_text: record.status_text.clone(),
            status_errno: record.status_errno,
            watchdog_timestamp_ns: record.watchdog_timestamp_ns,
            watchdog_timestamp_realtime_ns: record.watchdog_timestamp_realtime_ns,
            exec_main_start_realtime_ns: record.exec_main_start_realtime_ns,
            exec_main_start_monotonic_ns: record.exec_main_start_monotonic_ns,
            exec_main_exit_realtime_ns: record.exec_main_exit_realtime_ns,
            exec_main_exit_monotonic_ns: record.exec_main_exit_monotonic_ns,
            watchdog_triggered: record.watchdog_triggered,
            service_result: record.service_result.clone(),
            exec_main_code: record.exec_main_code,
            exec_main_status: record.exec_main_status,
            invocation_id: record.invocation_id,
        });
    }
    units.sort_by(|left, right| left.name.cmp(&right.name));

    let state = ReexecState {
        version: REEXEC_STATE_VERSION,
        scope: scope_name(manager.config.scope).to_owned(),
        units,
    };
    let path = state_path(manager.config.scope);
    write_state(&path, &state)?;
    Ok(path)
}

/// Restore a validated re-exec snapshot into a fresh manager registry.
///
/// # Errors
///
/// Returns an error when the snapshot cannot be read or validated, its scope
/// does not match the manager, the manager is not fresh, a referenced unit or
/// process cannot be restored safely, dynamic-user adoption fails, or the
/// consumed state file cannot be removed.
pub fn restore_manager_state(manager: &mut Manager, path: &Path) -> anyhow::Result<()> {
    let state = read_state(path)?;
    let expected_scope = scope_name(manager.config.scope);
    if state.scope != expected_scope {
        anyhow::bail!(
            "reexec state scope '{}' does not match manager scope '{expected_scope}'",
            state.scope
        );
    }
    if !manager.units.is_empty() || !manager.job_registry.is_empty() {
        anyhow::bail!("reexec restore requires a fresh manager registry");
    }

    for saved in &state.units {
        manager.load_unit(&saved.name)?;
        let record = manager
            .units
            .get_mut(&saved.name)
            .ok_or_else(|| anyhow::anyhow!("restored unit '{}' disappeared", saved.name))?;
        for pid in [saved.active_pid, saved.control_pid].into_iter().flatten() {
            if !pid_is_alive(pid) {
                anyhow::bail!(
                    "unit '{}' references dead pid {pid} in reexec state",
                    saved.name
                );
            }
        }
        if matches!(saved.state, UnitState::Active | UnitState::Failed) {
            match &record.loaded {
                LoadedUnit::Socket(_)
                | LoadedUnit::Path(_)
                | LoadedUnit::Timer(_)
                | LoadedUnit::Automount(_) => {
                    anyhow::bail!(
                        "reexec state contains unsupported active {}: {}",
                        unit_kind(&record.loaded),
                        saved.name
                    );
                }
                LoadedUnit::Service(service) => {
                    if service.specific.service_type == ServiceType::Forking
                        || service.specific.exit_type == "cgroup"
                    {
                        anyhow::bail!(
                            "reexec state contains service requiring unsupported cgroup adoption: {}",
                            saved.name
                        );
                    }
                }
                _ => {}
            }
        }
        record.state = saved.state;
        record.active_pid = saved.active_pid;
        record.control_pid = saved.control_pid;
        record.stop_requested = saved.stop_requested;
        record.restart_count = saved.restart_count;
        record.last_start_ns = saved.last_start_ns;
        record.start_limit_window_ns = saved.start_limit_window_ns;
        record.start_limit_count = saved.start_limit_count;
        record.dynamic_user = saved
            .dynamic_uid
            .map(|uid| crate::dynamic_user::DynamicUser::adopt(&saved.name, uid))
            .transpose()?;
        record.status_text.clone_from(&saved.status_text);
        record.status_errno = saved.status_errno;
        record.watchdog_timestamp_ns = saved.watchdog_timestamp_ns;
        record.watchdog_timestamp_realtime_ns = saved.watchdog_timestamp_realtime_ns;
        record.exec_main_start_realtime_ns = saved.exec_main_start_realtime_ns;
        record.exec_main_start_monotonic_ns = saved.exec_main_start_monotonic_ns;
        record.exec_main_exit_realtime_ns = saved.exec_main_exit_realtime_ns;
        record.exec_main_exit_monotonic_ns = saved.exec_main_exit_monotonic_ns;
        record.watchdog_triggered = saved.watchdog_triggered;
        record.service_result.clone_from(&saved.service_result);
        record.exec_main_code = saved.exec_main_code;
        record.exec_main_status = saved.exec_main_status;
        record.invocation_id = saved.invocation_id;
    }

    if let Some(notify) = manager.notify.as_ref() {
        for (name, record) in &manager.units {
            let (Some(pid), LoadedUnit::Service(service)) = (record.active_pid, &record.loaded)
            else {
                continue;
            };
            if let Some(access) = effective_notify_access(&service.specific) {
                notify.register_pid(pid, name.clone(), access);
            }
        }
    }

    fs::remove_file(path)?;
    Ok(())
}

/// Atomically persist a re-exec snapshot with owner-only permissions.
///
/// # Errors
///
/// Returns an error if the destination has no parent, serialization fails, or
/// the parent directory, temporary file, final rename, permission update, or
/// durability writes fail.
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

/// Read and validate an owner-only re-exec snapshot.
///
/// # Errors
///
/// Returns an error if metadata or file reads fail, the path is not a regular
/// file owned by the effective UID with owner-only permissions, JSON decoding
/// fails, or the serialized state version is unsupported.
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

fn pid_is_alive(pid: libc::pid_t) -> bool {
    if pid <= 0 {
        return false;
    }
    if unsafe { libc::kill(pid, 0) } == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn effective_notify_access(section: &ServiceSection) -> Option<NotifyAccess> {
    let notification_enabled = section.notify_access != NotifyAccess::None
        || section.watchdog_sec.is_some()
        || matches!(
            section.service_type,
            ServiceType::Notify | ServiceType::NotifyReload
        );
    if !notification_enabled {
        return None;
    }
    Some(if section.notify_access == NotifyAccess::None {
        NotifyAccess::Main
    } else {
        section.notify_access
    })
}

fn unit_kind(unit: &LoadedUnit) -> &'static str {
    match unit {
        LoadedUnit::Service(_) => "service",
        LoadedUnit::Socket(_) => "socket",
        LoadedUnit::Automount(_) => "automount",
        LoadedUnit::Timer(_) => "timer",
        LoadedUnit::Path(_) => "path",
        LoadedUnit::Mount(_) => "mount",
        LoadedUnit::Swap(_) => "swap",
        LoadedUnit::Target(_) => "target",
        LoadedUnit::Slice(_) => "slice",
        LoadedUnit::Scope(_) => "scope",
    }
}
