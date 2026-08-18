// SPDX-License-Identifier: LGPL-2.1-or-later
//! Service state machine — activate, deactivate, reload, and child exit handling.
//!
//! Implements the ordered service command pipeline around the main process:
//! `ExecCondition=`, `ExecStartPre=`, `ExecStart=`, `ExecStartPost=`,
//! `ExecReload=`, `ExecStop=`, and `ExecStopPost=`.
//!
//! Upstream reference: `src/core/service.c service_start()`,
//!   `service_enter_start()`, `service_enter_stop()`,
//!   `service_enter_reload()`, `service_sigchld_event()` (v261)

use std::ffi::{CStr, CString};
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use anyhow::anyhow;

use crate::dbus::manager_iface::{
    manager_environment_effective, merge_environment_entries, ManagerEnvironment,
};
use crate::dynamic_user::DynamicUser;
use crate::event::child::ChildExit;
use crate::ffi::spawn::{rustd_spawn, SdSpawnParams, SdSpawnRlimit, SdSpawnSandbox};
use crate::journal::stdout::{
    connect_service_stream_with_limits, wants_journal_stdio, DEFAULT_STDOUT_PATH,
};
use crate::kill_context::{signal_primary, KillOperation, KillPolicy};
use crate::restart::should_restart_result;
use crate::sandbox::SecurityContext;
use crate::seccomp_policy::{compile_syscall_filter, restrict_native_architectures};
use crate::unit::loader::{all_conditions_pass, LoadedUnit};
use crate::unit::section_service::{
    ExecCommand, ExecFlags, RlimitSpec, RlimitValue, ServiceSection, ServiceType,
};
use crate::unit::UnitState;

/// Runtime record for a managed unit.
#[derive(Debug)]
pub struct UnitRecord {
    pub loaded: LoadedUnit,
    pub state: UnitState,
    pub active_pid: Option<libc::pid_t>,
    pub control_pid: Option<libc::pid_t>,
    pub stop_requested: bool,
    pub idle_gate_fd: Option<libc::c_int>,
    pub restart_count: u32,
    pub last_start_ns: i64,
    pub start_limit_window_ns: i64,
    pub start_limit_count: u32,
    pub dynamic_user: Option<DynamicUser>,
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
    manager_environment: Option<ManagerEnvironment>,
}

impl UnitRecord {
    #[must_use]
    pub fn new(loaded: LoadedUnit) -> Self {
        Self {
            loaded,
            state: UnitState::Inactive,
            active_pid: None,
            control_pid: None,
            stop_requested: false,
            idle_gate_fd: None,
            restart_count: 0,
            last_start_ns: 0,
            start_limit_window_ns: 0,
            start_limit_count: 0,
            dynamic_user: None,
            status_text: None,
            status_errno: None,
            watchdog_timestamp_ns: None,
            watchdog_timestamp_realtime_ns: None,
            exec_main_start_realtime_ns: None,
            exec_main_start_monotonic_ns: None,
            exec_main_exit_realtime_ns: None,
            exec_main_exit_monotonic_ns: None,
            watchdog_triggered: false,
            service_result: "success".into(),
            exec_main_code: 0,
            exec_main_status: 0,
            invocation_id: None,
            manager_environment: None,
        }
    }

    pub(crate) fn assign_invocation_id(&mut self) -> std::io::Result<()> {
        let mut invocation_id = [0u8; 16];
        fill_invocation_id_bytes(&mut invocation_id)?;
        invocation_id[6] = (invocation_id[6] & 0x0f) | 0x40;
        invocation_id[8] = (invocation_id[8] & 0x3f) | 0x80;
        self.invocation_id = Some(invocation_id);
        Ok(())
    }
}

fn fill_invocation_id_bytes(buffer: &mut [u8]) -> std::io::Result<()> {
    let mut written = 0;
    while written < buffer.len() {
        let result = unsafe {
            libc::getrandom(
                buffer[written..].as_mut_ptr().cast(),
                buffer.len() - written,
                libc::GRND_NONBLOCK,
            )
        };
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            if error.raw_os_error() == Some(libc::EAGAIN) {
                return fill_from_urandom(&mut buffer[written..]);
            }
            return Err(error);
        }
        let read = usize::try_from(result).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "getrandom returned an invalid byte count",
            )
        })?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "getrandom returned no invocation ID bytes",
            ));
        }
        written += read;
    }
    Ok(())
}

fn fill_from_urandom(buffer: &mut [u8]) -> std::io::Result<()> {
    std::fs::File::open("/dev/urandom")?.read_exact(buffer)
}

pub(crate) fn attach_manager_environment(record: &mut UnitRecord, environment: ManagerEnvironment) {
    record.manager_environment = Some(environment);
}

fn launch_environment(record: &UnitRecord) -> Vec<String> {
    let mut environment = record.manager_environment.as_ref().map_or_else(
        || {
            let mut environment: Vec<String> = std::env::vars()
                .map(|(name, value)| format!("{name}={value}"))
                .collect();
            environment.sort_unstable();
            environment
        },
        manager_environment_effective,
    );
    if let Some(invocation_id) = record.invocation_id {
        environment = merge_environment_entries(
            &environment,
            &[format!("INVOCATION_ID={}", invocation_id_hex(&invocation_id))],
        );
    }
    environment
}

fn invocation_id_hex(invocation_id: &[u8; 16]) -> String {
    let mut output = String::with_capacity(32);
    for byte in invocation_id {
        use std::fmt::Write;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SpawnedProcess {
    pid: libc::pid_t,
    idle_gate_fd: Option<libc::c_int>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CommandOutcome {
    exit_code: Option<i32>,
    signal: Option<i32>,
    ignored: bool,
}

impl CommandOutcome {
    #[must_use]
    fn is_success(self) -> bool {
        self.ignored || self.exit_code == Some(0)
    }

    #[must_use]
    fn condition_skips(self) -> bool {
        !self.ignored && self.exit_code.is_some_and(|code| (1..=254).contains(&code))
    }
}

pub fn activate(record: &mut UnitRecord, listen_fds: &[libc::c_int]) -> anyhow::Result<()> {
    activate_with_notify(record, listen_fds, -1)
}

#[allow(clippy::too_many_lines)]
pub fn activate_with_notify(
    record: &mut UnitRecord,
    listen_fds: &[libc::c_int],
    notify_fd: libc::c_int,
) -> anyhow::Result<()> {
    activate_with_notify_in_cgroup(record, listen_fds, notify_fd, None)
}

#[allow(clippy::too_many_lines)]
pub(crate) fn activate_with_notify_in_cgroup(
    record: &mut UnitRecord,
    listen_fds: &[libc::c_int],
    notify_fd: libc::c_int,
    cgroup_procs_path: Option<&Path>,
) -> anyhow::Result<()> {
    release_idle_gate(record);

    let LoadedUnit::Service(ref service) = record.loaded else {
        return Err(anyhow!("activate called on non-service unit '{}'", record.loaded.name()));
    };

    if !all_conditions_pass(&service.unit) {
        record.state = UnitState::Inactive;
        return Ok(());
    }

    let unit_name = service.name.clone();
    let section = service.specific.clone();
    let environment = launch_environment(record);
    record.service_result = "success".into();
    record.stop_requested = false;
    record.exec_main_code = 0;
    record.exec_main_status = 0;
    record.active_pid = None;
    record.control_pid = None;
    if section.exec_start.is_empty() {
        record.state = UnitState::Failed;
        return Err(anyhow!("unit '{unit_name}' has no ExecStart="));
    }
    if section.service_type != ServiceType::Oneshot && section.exec_start.len() != 1 {
        record.state = UnitState::Failed;
        return Err(anyhow!("unit '{unit_name}' has multiple ExecStart= commands but is not Type=oneshot"));
    }
    if section.service_type == ServiceType::Dbus && section.bus_name.is_empty() {
        record.state = UnitState::Failed;
        return Err(anyhow!("unit '{unit_name}' has Type=dbus but no BusName="));
    }

    let dynamic_user = allocate_dynamic_user(&unit_name, &section).map_err(|error| {
        record.state = UnitState::Failed;
        error
    })?;

    for command in &section.exec_condition {
        let outcome = run_command(
            &unit_name, &section, command, &[], notify_fd, dynamic_user.as_ref(),
            cgroup_procs_path, &environment,
        ).map_err(|error| { record.state = UnitState::Failed; error })?;
        if outcome.condition_skips() {
            record.state = UnitState::Inactive;
            return Ok(());
        }
        if !outcome.is_success() {
            record.state = UnitState::Failed;
            return Err(command_failed("ExecCondition", command, outcome));
        }
    }

    run_command_list(
        "ExecStartPre", &unit_name, &section, &section.exec_start_pre, &[], notify_fd,
        dynamic_user.as_ref(), cgroup_procs_path, &environment,
    ).map_err(|error| { record.state = UnitState::Failed; error })?;

    record.dynamic_user = dynamic_user;
    record.state = UnitState::Activating;

    if section.service_type == ServiceType::Oneshot {
        for command in &section.exec_start {
            let outcome = run_command(
                &unit_name, &section, command, listen_fds, notify_fd,
                record.dynamic_user.as_ref(), cgroup_procs_path, &environment,
            ).map_err(|error| { record.state = UnitState::Failed; error })?;
            if !outcome.is_success() {
                record.state = UnitState::Failed;
                run_stop_post(record, &section, notify_fd, cgroup_procs_path);
                return Err(command_failed("ExecStart", command, outcome));
            }
        }
        run_command_list(
            "ExecStartPost", &unit_name, &section, &section.exec_start_post, listen_fds,
            notify_fd, record.dynamic_user.as_ref(), cgroup_procs_path, &environment,
        ).map_err(|error| { record.state = UnitState::Failed; error })?;
        record.state = if section.remain_after_exit {
            UnitState::Active
        } else {
            record.dynamic_user = None;
            UnitState::Inactive
        };
        return Ok(());
    }

    let command = &section.exec_start[0];
    let child = match spawn_command(
        &unit_name, &section, command, listen_fds, notify_fd, record.dynamic_user.as_ref(),
        section.service_type == ServiceType::Idle, cgroup_procs_path, &environment,
    ) {
        Ok(process) => process,
        Err(error) => {
            record.state = UnitState::Failed;
            run_stop_post(record, &section, notify_fd, cgroup_procs_path);
            record.dynamic_user = None;
            return Err(error);
        }
    };
    if section.service_type == ServiceType::Forking {
        record.control_pid = Some(child.pid);
        record.active_pid = None;
    } else {
        record.active_pid = Some(child.pid);
        record.control_pid = None;
    }
    record.idle_gate_fd = child.idle_gate_fd;
    record.state = match section.service_type {
        ServiceType::Simple | ServiceType::Exec | ServiceType::Idle => UnitState::Active,
        ServiceType::Forking | ServiceType::Notify | ServiceType::NotifyReload | ServiceType::Dbus => UnitState::Activating,
        ServiceType::Oneshot => unreachable!("oneshot handled above"),
    };

    if !matches!(section.service_type, ServiceType::Forking | ServiceType::Notify | ServiceType::NotifyReload | ServiceType::Dbus) {
        if let Err(error) = run_start_post(record, &section, listen_fds, notify_fd, cgroup_procs_path) {
            if let Some(pid) = record.active_pid {
                unsafe { libc::kill(pid, libc::SIGTERM) };
            }
            release_idle_gate(record);
            record.state = UnitState::Failed;
            return Err(error);
        }
    }
    Ok(())
}

pub fn deactivate(record: &mut UnitRecord) {
    deactivate_with_notify(record, -1);
}

pub fn deactivate_with_notify(record: &mut UnitRecord, notify_fd: libc::c_int) {
    deactivate_with_notify_in_cgroup(record, notify_fd, None, KillOperation::Terminate);
}

pub(crate) fn deactivate_with_notify_in_cgroup(
    record: &mut UnitRecord,
    notify_fd: libc::c_int,
    cgroup_procs_path: Option<&Path>,
    operation: KillOperation,
) {
    let LoadedUnit::Service(ref service) = record.loaded else {
        record.state = UnitState::Inactive;
        return;
    };
    let section = service.specific.clone();
    record.stop_requested = true;
    let environment = launch_environment(record);
    if let Err(error) = run_command_list(
        "ExecStop", record.loaded.name(), &section, &section.exec_stop, &[], notify_fd,
        record.dynamic_user.as_ref(), cgroup_procs_path, &environment,
    ) {
        eprintln!("service stop command failed: {error}");
    }
    if record.active_pid.is_some() || record.control_pid.is_some() {
        let policy = KillPolicy::from_service(&section);
        signal_primary(policy, record.active_pid, record.control_pid, operation);
        release_idle_gate(record);
        record.state = UnitState::Deactivating;
    } else {
        record.state = UnitState::Inactive;
        run_stop_post(record, &section, notify_fd, cgroup_procs_path);
        record.dynamic_user = None;
    }
}

pub fn reload(record: &mut UnitRecord) -> anyhow::Result<()> {
    reload_with_notify(record, -1)
}

pub fn reload_with_notify(record: &mut UnitRecord, notify_fd: libc::c_int) -> anyhow::Result<()> {
    reload_with_notify_in_cgroup(record, notify_fd, None)
}

pub(crate) fn reload_with_notify_in_cgroup(
    record: &mut UnitRecord,
    notify_fd: libc::c_int,
    cgroup_procs_path: Option<&Path>,
) -> anyhow::Result<()> {
    let LoadedUnit::Service(ref service) = record.loaded else {
        return Err(anyhow!("reload called on non-service unit '{}'", record.loaded.name()));
    };
    if record.state != UnitState::Active {
        return Err(anyhow!("unit '{}' is not active", service.name));
    }
    let section = service.specific.clone();
    let environment = launch_environment(record);
    if section.exec_reload.is_empty() {
        return Err(anyhow!("unit '{}' has no ExecReload=", service.name));
    }
    run_command_list(
        "ExecReload", record.loaded.name(), &section, &section.exec_reload, &[], notify_fd,
        record.dynamic_user.as_ref(), cgroup_procs_path, &environment,
    )
}

pub(crate) fn complete_notify_start_with_notify_in_cgroup(
    record: &mut UnitRecord,
    listen_fds: &[libc::c_int],
    notify_fd: libc::c_int,
    cgroup_procs_path: Option<&Path>,
) -> anyhow::Result<bool> {
    let LoadedUnit::Service(ref service) = record.loaded else { return Ok(false); };
    if !matches!(service.specific.service_type, ServiceType::Notify | ServiceType::NotifyReload)
        || record.state != UnitState::Activating { return Ok(false); }
    let section = service.specific.clone();
    if let Err(error) = run_start_post(record, &section, listen_fds, notify_fd, cgroup_procs_path) {
        if let Some(pid) = record.active_pid { unsafe { libc::kill(pid, libc::SIGTERM) }; }
        record.state = UnitState::Failed;
        record.service_result = "exit-code".into();
        return Err(error);
    }
    record.state = UnitState::Active;
    record.service_result = "success".into();
    Ok(true)
}

pub(crate) fn complete_dbus_start_with_notify_in_cgroup(
    record: &mut UnitRecord,
    listen_fds: &[libc::c_int],
    notify_fd: libc::c_int,
    cgroup_procs_path: Option<&Path>,
) -> anyhow::Result<bool> {
    let LoadedUnit::Service(ref service) = record.loaded else { return Ok(false); };
    if service.specific.service_type != ServiceType::Dbus || record.state != UnitState::Activating { return Ok(false); }
    let section = service.specific.clone();
    if let Err(error) = run_start_post(record, &section, listen_fds, notify_fd, cgroup_procs_path) {
        if let Some(pid) = record.active_pid { unsafe { libc::kill(pid, libc::SIGTERM) }; }
        record.state = UnitState::Failed;
        record.service_result = "exit-code".into();
        return Err(error);
    }
    record.state = UnitState::Active;
    record.service_result = "success".into();
    Ok(true)
}

pub(crate) fn on_forking_control_exit_with_notify_in_cgroup(
    record: &mut UnitRecord,
    exit: &ChildExit,
    notify_fd: libc::c_int,
    cgroup_procs_path: Option<&Path>,
) -> anyhow::Result<bool> {
    if record.control_pid != Some(exit.pid) { return Ok(false); }
    let LoadedUnit::Service(ref service) = record.loaded else { return Ok(false); };
    let section = service.specific.clone();
    if section.service_type != ServiceType::Forking { return Ok(false); }
    record.control_pid = None;
    let success = is_success(exit, section.exec_start.first().map(|command| command.flags), &section);
    if !success {
        record.state = UnitState::Failed;
        record.service_result = service_result_from_exit(exit).into();
        run_stop_post(record, &section, notify_fd, cgroup_procs_path);
        remove_pid_file(&section);
        record.dynamic_user = None;
        return Ok(true);
    }
    if section.pid_file.is_empty() {
        let main_pid = if section.guess_main_pid { guess_main_pid_from_cgroup(cgroup_procs_path) } else { None };
        finish_forking_start(record, &section, main_pid, notify_fd, cgroup_procs_path)?;
    } else {
        match read_pid_file(&section, cgroup_procs_path) {
            Ok(pid) => finish_forking_start(record, &section, Some(pid), notify_fd, cgroup_procs_path)?,
            Err(error) if pid_file_not_ready(&error) => return Ok(true),
            Err(error) => {
                fail_forking_start(record, &section, "protocol", notify_fd, cgroup_procs_path);
                return Err(error);
            }
        }
    }
    Ok(true)
}

#[must_use]
pub(crate) fn forking_pid_file_pending(record: &UnitRecord) -> bool {
    matches!(&record.loaded, LoadedUnit::Service(service)
        if service.specific.service_type == ServiceType::Forking
            && !service.specific.pid_file.is_empty()
            && record.state == UnitState::Activating
            && record.control_pid.is_none()
            && record.active_pid.is_none())
}

pub(crate) fn retry_forking_pid_file_with_notify_in_cgroup(
    record: &mut UnitRecord,
    notify_fd: libc::c_int,
    cgroup_procs_path: Option<&Path>,
) -> anyhow::Result<bool> {
    if !forking_pid_file_pending(record) { return Ok(false); }
    let LoadedUnit::Service(ref service) = record.loaded else { return Ok(false); };
    let section = service.specific.clone();
    match read_pid_file(&section, cgroup_procs_path) {
        Ok(pid) => {
            finish_forking_start(record, &section, Some(pid), notify_fd, cgroup_procs_path)?;
            Ok(true)
        }
        Err(error) if pid_file_not_ready(&error) => Ok(false),
        Err(error) => {
            fail_forking_start(record, &section, "protocol", notify_fd, cgroup_procs_path);
            Err(error)
        }
    }
}

fn finish_forking_start(
    record: &mut UnitRecord,
    section: &ServiceSection,
    main_pid: Option<libc::pid_t>,
    notify_fd: libc::c_int,
    cgroup_procs_path: Option<&Path>,
) -> anyhow::Result<()> {
    record.active_pid = main_pid;
    if let Err(error) = run_start_post(record, section, &[], notify_fd, cgroup_procs_path) {
        if let Some(pid) = record.active_pid { unsafe { libc::kill(pid, libc::SIGTERM) }; }
        fail_forking_start(record, section, "exit-code", notify_fd, cgroup_procs_path);
        return Err(error);
    }
    record.state = UnitState::Active;
    record.service_result = "success".into();
    Ok(())
}

fn fail_forking_start(
    record: &mut UnitRecord,
    section: &ServiceSection,
    result: &str,
    notify_fd: libc::c_int,
    cgroup_procs_path: Option<&Path>,
) {
    record.state = UnitState::Failed;
    record.service_result = result.into();
    run_stop_post(record, section, notify_fd, cgroup_procs_path);
    remove_pid_file(section);
    record.dynamic_user = None;
}

pub(crate) fn on_forking_cgroup_empty_with_notify_in_cgroup(
    record: &mut UnitRecord,
    notify_fd: libc::c_int,
    cgroup_procs_path: Option<&Path>,
) -> bool {
    let LoadedUnit::Service(ref service) = record.loaded else { return false; };
    if service.specific.service_type != ServiceType::Forking || record.state != UnitState::Active
        || record.active_pid.is_some() || record.control_pid.is_some() { return false; }
    let section = service.specific.clone();
    record.state = UnitState::Inactive;
    record.service_result = "success".into();
    run_stop_post(record, &section, notify_fd, cgroup_procs_path);
    remove_pid_file(&section);
    record.dynamic_user = None;
    true
}

fn run_start_post(
    record: &mut UnitRecord,
    section: &ServiceSection,
    listen_fds: &[libc::c_int],
    notify_fd: libc::c_int,
    cgroup_procs_path: Option<&Path>,
) -> anyhow::Result<()> {
    let environment = launch_environment(record);
    run_command_list(
        "ExecStartPost", record.loaded.name(), section, &section.exec_start_post, listen_fds,
        notify_fd, record.dynamic_user.as_ref(), cgroup_procs_path, &environment,
    )
}

fn pid_file_path(section: &ServiceSection) -> PathBuf {
    let path = PathBuf::from(&section.pid_file);
    if path.is_absolute() { path } else { Path::new("/run").join(path) }
}

fn read_pid_file(section: &ServiceSection, cgroup_procs_path: Option<&Path>) -> anyhow::Result<libc::pid_t> {
    let path = pid_file_path(section);
    let questionable_path = pid_file_has_symlink_component(&path);
    let metadata = std::fs::metadata(&path)?;
    let contents = std::fs::read_to_string(&path)?;
    let raw_pid = contents.split_whitespace().next().ok_or_else(|| std::io::Error::new(
        std::io::ErrorKind::WouldBlock, format!("PIDFile '{}' is empty", path.display())))?;
    let pid = raw_pid.parse::<libc::pid_t>().map_err(|_| anyhow!("PIDFile '{}' contains an invalid PID", path.display()))?;
    if pid <= 0 || !pid_is_alive(pid) { return Err(anyhow!("PIDFile '{}' refers to a process that is not running", path.display())); }
    if pid == 1 || pid == libc::pid_t::try_from(std::process::id()).unwrap_or(-1) {
        return Err(anyhow!("PIDFile '{}' refers to the service manager", path.display()));
    }
    let belongs_to_service = cgroup_procs_path.is_some_and(|procs| pid_in_cgroup_tree(pid, procs));
    if questionable_path && !belongs_to_service {
        return Err(anyhow!("PIDFile '{}' has an unsafe symlink chain and refers outside the service cgroup", path.display()));
    }
    let manager_uid = unsafe { libc::geteuid() };
    if !belongs_to_service && metadata.uid() != manager_uid {
        return Err(anyhow!("PIDFile '{}' refers outside the service cgroup and is owned by uid {} instead of manager uid {}",
            path.display(), metadata.uid(), manager_uid));
    }
    Ok(pid)
}

fn guess_main_pid_from_cgroup(cgroup_procs_path: Option<&Path>) -> Option<libc::pid_t> {
    let path = cgroup_procs_path?;
    let mut candidates = Vec::new();
    collect_cgroup_pids(path.parent()?, &mut candidates);
    candidates.retain(|pid| *pid > 0 && pid_is_alive(*pid));
    candidates.sort_unstable();
    candidates.dedup();
    if candidates.len() == 1 { candidates.first().copied() } else { None }
}

fn pid_in_cgroup_tree(pid: libc::pid_t, cgroup_procs_path: &Path) -> bool {
    let Some(root) = cgroup_procs_path.parent() else { return false; };
    let mut candidates = Vec::new();
    collect_cgroup_pids(root, &mut candidates);
    candidates.contains(&pid)
}

fn collect_cgroup_pids(directory: &Path, candidates: &mut Vec<libc::pid_t>) {
    if let Ok(contents) = std::fs::read_to_string(directory.join("cgroup.procs")) {
        candidates.extend(contents.split_whitespace().filter_map(|value| value.parse::<libc::pid_t>().ok()));
    }
    let Ok(entries) = std::fs::read_dir(directory) else { return; };
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else { continue; };
        if file_type.is_dir() { collect_cgroup_pids(&entry.path(), candidates); }
    }
}

fn cgroup_tree_populated(cgroup_procs_path: &Path) -> bool {
    let Some(root) = cgroup_procs_path.parent() else { return false; };
    let mut candidates = Vec::new();
    collect_cgroup_pids(root, &mut candidates);
    !candidates.is_empty()
}

fn pid_file_has_symlink_component(path: &Path) -> bool {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if std::fs::symlink_metadata(&current).is_ok_and(|metadata| metadata.file_type().is_symlink()) { return true; }
    }
    false
}

fn pid_file_not_ready(error: &anyhow::Error) -> bool {
    error.downcast_ref::<std::io::Error>().is_some_and(|error| matches!(error.kind(), std::io::ErrorKind::NotFound | std::io::ErrorKind::WouldBlock))
}

fn pid_is_alive(pid: libc::pid_t) -> bool {
    let result = unsafe { libc::kill(pid, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn service_result_from_exit(exit: &ChildExit) -> &'static str {
    if exit.code == libc::CLD_DUMPED { "core-dump" }
    else if exit.code == libc::CLD_KILLED { "signal" }
    else { "exit-code" }
}

fn remove_pid_file(section: &ServiceSection) {
    if section.pid_file.is_empty() { return; }
    let path = pid_file_path(section);
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => eprintln!("service: removing PIDFile '{}' failed: {error}", path.display()),
    }
}

pub fn on_child_exit(record: &mut UnitRecord, exit: &ChildExit) -> bool {
    on_child_exit_with_notify(record, exit, -1)
}

pub fn on_child_exit_with_notify(record: &mut UnitRecord, exit: &ChildExit, notify_fd: libc::c_int) -> bool {
    on_child_exit_with_notify_in_cgroup(record, exit, notify_fd, None)
}

pub(crate) fn on_child_exit_with_notify_in_cgroup(
    record: &mut UnitRecord,
    exit: &ChildExit,
    notify_fd: libc::c_int,
    cgroup_procs_path: Option<&Path>,
) -> bool {
    let Some(pid) = record.active_pid else { return false; };
    if exit.pid != pid { return false; }
    let LoadedUnit::Service(ref service) = record.loaded else { return false; };
    let section = service.specific.clone();
    release_idle_gate(record);
    let explicitly_stopping = record.stop_requested;
    let resource_failure = record.service_result == "resources";
    let timeout_failure = record.service_result == "timeout";
    record.active_pid = None;
    record.exec_main_code = exit.code;
    record.exec_main_status = exit.status;
    let success = is_success(exit, section.exec_start.first().map(|command| command.flags), &section);
    record.service_result = if resource_failure { "resources" }
        else if timeout_failure { "timeout" }
        else if record.watchdog_triggered { "watchdog" }
        else if explicitly_stopping || success { "success" }
        else if exit.code == libc::CLD_DUMPED { "core-dump" }
        else if exit.code == libc::CLD_KILLED { "signal" }
        else { "exit-code" }.into();
    let direct_restart = section.restart_mode == "direct" && !explicitly_stopping
        && restart_requested(&section, exit, &record.service_result);
    if section.exit_type == "cgroup" && !explicitly_stopping && cgroup_procs_path.is_some_and(cgroup_tree_populated) {
        record.state = UnitState::Active;
        return true;
    }
    record.state = if direct_restart { UnitState::Active } else { match record.state {
        UnitState::Activating => {
            if section.service_type == ServiceType::Oneshot && section.remain_after_exit && success { UnitState::Active }
            else if success { UnitState::Inactive } else { UnitState::Failed }
        }
        UnitState::Active => if success { UnitState::Inactive } else { UnitState::Failed },
        UnitState::Deactivating if explicitly_stopping => UnitState::Inactive,
        UnitState::Deactivating | UnitState::Failed => UnitState::Failed,
        _ => UnitState::Inactive,
    }};
    run_stop_post(record, &section, notify_fd, cgroup_procs_path);
    remove_pid_file(&section);
    record.dynamic_user = None;
    record.stop_requested = false;
    true
}

pub(crate) fn on_service_cgroup_empty_with_notify_in_cgroup(
    record: &mut UnitRecord,
    notify_fd: libc::c_int,
    cgroup_procs_path: Option<&Path>,
) -> bool {
    let LoadedUnit::Service(ref service) = record.loaded else { return false; };
    if service.specific.exit_type != "cgroup" || record.active_pid.is_some() || record.control_pid.is_some()
        || !matches!(record.state, UnitState::Active | UnitState::Activating)
        || cgroup_procs_path.is_some_and(cgroup_tree_populated) { return false; }
    let section = service.specific.clone();
    record.state = if record.stop_requested || record.service_result == "success" { UnitState::Inactive } else { UnitState::Failed };
    run_stop_post(record, &section, notify_fd, cgroup_procs_path);
    remove_pid_file(&section);
    record.dynamic_user = None;
    record.stop_requested = false;
    true
}

fn allocate_dynamic_user(unit_name: &str, section: &ServiceSection) -> anyhow::Result<Option<DynamicUser>> {
    if !section.dynamic_user { return Ok(None); }
    DynamicUser::allocate(unit_name).map(Some).map_err(|error| anyhow!("dynamic-user allocation failed for '{unit_name}': {error}"))
}

pub(crate) fn finish_timeout_failure_with_notify_in_cgroup(
    record: &mut UnitRecord, result: &str, notify_fd: libc::c_int, cgroup_procs_path: Option<&Path>,
) {
    let LoadedUnit::Service(ref service) = record.loaded else {
        record.state = UnitState::Failed; record.service_result = result.into(); record.stop_requested = false; return;
    };
    let section = service.specific.clone();
    release_idle_gate(record);
    record.active_pid = None;
    record.control_pid = None;
    record.state = UnitState::Failed;
    record.service_result = result.into();
    run_stop_post(record, &section, notify_fd, cgroup_procs_path);
    remove_pid_file(&section);
    record.dynamic_user = None;
    record.stop_requested = false;
}

pub(crate) fn on_timeout_cgroup_empty_with_notify_in_cgroup(
    record: &mut UnitRecord, notify_fd: libc::c_int, cgroup_procs_path: Option<&Path>,
) -> bool {
    if record.state != UnitState::Deactivating || record.active_pid.is_some() || record.control_pid.is_some()
        || !matches!(record.service_result.as_str(), "timeout" | "watchdog") { return false; }
    let result = record.service_result.clone();
    finish_timeout_failure_with_notify_in_cgroup(record, &result, notify_fd, cgroup_procs_path);
    true
}

fn run_stop_post(record: &mut UnitRecord, section: &ServiceSection, notify_fd: libc::c_int, cgroup_procs_path: Option<&Path>) {
    let environment = launch_environment(record);
    if run_command_list("ExecStopPost", record.loaded.name(), section, &section.exec_stop_post, &[], notify_fd,
        record.dynamic_user.as_ref(), cgroup_procs_path, &environment).is_err() { record.state = UnitState::Failed; }
}

#[allow(clippy::too_many_arguments)]
fn run_command_list(
    phase: &str, unit_name: &str, section: &ServiceSection, commands: &[ExecCommand], listen_fds: &[libc::c_int],
    notify_fd: libc::c_int, dynamic_user: Option<&DynamicUser>, cgroup_procs_path: Option<&Path>, environment: &[String],
) -> anyhow::Result<()> {
    for command in commands {
        let outcome = run_command(unit_name, section, command, listen_fds, notify_fd, dynamic_user, cgroup_procs_path, environment)?;
        if !outcome.is_success() { return Err(command_failed(phase, command, outcome)); }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_command(
    unit_name: &str, section: &ServiceSection, command: &ExecCommand, listen_fds: &[libc::c_int], notify_fd: libc::c_int,
    dynamic_user: Option<&DynamicUser>, cgroup_procs_path: Option<&Path>, environment: &[String],
) -> anyhow::Result<CommandOutcome> {
    let process = spawn_command(unit_name, section, command, listen_fds, notify_fd, dynamic_user, false, cgroup_procs_path, environment)?;
    wait_for_command(process.pid, command.flags)
}

fn rlimit_raw(value: RlimitValue) -> u64 { match value { RlimitValue::Value(value) => value, RlimitValue::Infinity => u64::MAX } }

fn compile_rlimits(section: &ServiceSection) -> Vec<SdSpawnRlimit> {
    let mut limits = Vec::new();
    let mut push = |resource: libc::c_int, value: Option<RlimitSpec>| {
        if let Some(value) = value { limits.push(SdSpawnRlimit { resource, soft: rlimit_raw(value.soft), hard: rlimit_raw(value.hard) }); }
    };
    #[allow(clippy::cast_possible_wrap)] {
        push(libc::RLIMIT_CPU as libc::c_int, section.limit_cpu); push(libc::RLIMIT_FSIZE as libc::c_int, section.limit_fsize);
        push(libc::RLIMIT_DATA as libc::c_int, section.limit_data); push(libc::RLIMIT_STACK as libc::c_int, section.limit_stack);
        push(libc::RLIMIT_CORE as libc::c_int, section.limit_core); push(libc::RLIMIT_RSS as libc::c_int, section.limit_rss);
        push(libc::RLIMIT_NOFILE as libc::c_int, section.limit_nofile); push(libc::RLIMIT_AS as libc::c_int, section.limit_as);
        push(libc::RLIMIT_NPROC as libc::c_int, section.limit_nproc); push(libc::RLIMIT_MEMLOCK as libc::c_int, section.limit_memlock);
        push(libc::RLIMIT_LOCKS as libc::c_int, section.limit_locks); push(libc::RLIMIT_SIGPENDING as libc::c_int, section.limit_sigpending);
        push(libc::RLIMIT_MSGQUEUE as libc::c_int, section.limit_msgqueue); push(libc::RLIMIT_NICE as libc::c_int, section.limit_nice);
        push(libc::RLIMIT_RTPRIO as libc::c_int, section.limit_rtprio); push(libc::RLIMIT_RTTIME as libc::c_int, section.limit_rttime);
    }
    limits
}

fn open_dev_null(flags: libc::c_int) -> anyhow::Result<libc::c_int> {
    let path = CString::new("/dev/null").expect("/dev/null is a valid CString");
    let fd = unsafe { libc::open(path.as_ptr(), flags | libc::O_CLOEXEC) };
    if fd < 0 { return Err(anyhow!("failed to open /dev/null: {}", std::io::Error::last_os_error())); }
    Ok(fd)
}

fn is_journal_daemon(unit_name: &str) -> bool { unit_name == "rustd-journald.service" || unit_name.ends_with("-journald.service") }

fn compile_read_write_paths(section: &ServiceSection) -> anyhow::Result<(Vec<CString>, Vec<*const libc::c_char>)> {
    if section.read_write_paths.len() > 256 {
        return Err(anyhow!("ReadWritePaths contains more than 256 entries"));
    }
    let strings: Vec<CString> = section.read_write_paths.iter().map(|raw| {
        let path = raw.strip_prefix('-').unwrap_or(raw.as_str());
        if !path.starts_with('/') || path.is_empty() {
            return Err(anyhow!("ReadWritePaths entry '{raw}' is not absolute"));
        }
        CString::new(raw.as_str()).map_err(|_| anyhow!("ReadWritePaths entry contains a NUL byte"))
    }).collect::<anyhow::Result<_>>()?;
    let pointers = strings.iter().map(|value| value.as_ptr()).collect();
    Ok((strings, pointers))
}

#[allow(clippy::too_many_lines)]
#[allow(clippy::too_many_arguments)]
fn spawn_command(
    unit_name: &str, section: &ServiceSection, command: &ExecCommand, listen_fds: &[libc::c_int], notify_fd: libc::c_int,
    dynamic_user: Option<&DynamicUser>, gate_idle_exec: bool, cgroup_procs_path: Option<&Path>, environment: &[String],
) -> anyhow::Result<SpawnedProcess> {
    #[cfg(test)] crate::ffi::spawn::ensure_spawn_helper_for_tests();
    if command.argv.is_empty() || command.path.is_empty() { return Err(anyhow!("empty service command")); }
    let security = SecurityContext::from_service(section)?;
    let fully_privileged = command.flags.contains(ExecFlags::FULL_PRIVILEGES);
    let no_setuid = command.flags.contains(ExecFlags::NO_SETUID);
    let merged_environment = merge_environment_entries(environment, &section.environment);
    let no_env_expand = command.flags.contains(ExecFlags::NO_ENV_EXPAND);
    let executable_path = if command.flags.contains(ExecFlags::VIA_SHELL) { selected_login_shell(section, dynamic_user) } else { command.path.clone() };
    let path_string = CString::new(executable_path.as_str()).map_err(|_| anyhow!("service executable path contains a NUL byte"))?;
    let effective_argv = if command.flags.contains(ExecFlags::VIA_SHELL) {
        let command_arguments = expand_exec_arguments(command.argv.get(1..).unwrap_or_default(), &merged_environment, no_env_expand);
        let mut argv = Vec::with_capacity(3);
        let login = command.argv.first().is_some_and(|value| value.starts_with('-'));
        argv.push(format!("{}{executable_path}", if login { "-" } else { "" }));
        if !command_arguments.is_empty() { argv.push("-c".to_owned()); argv.push(command_arguments.join(" ")); }
        argv
    } else { expand_exec_arguments(&command.argv, &merged_environment, no_env_expand) };
    if effective_argv.is_empty() { return Err(anyhow!("service command expanded to an empty argument vector")); }

    let restrict_native_syscalls = restrict_native_architectures(section)?;
    let syscall_filter = compile_syscall_filter(section)?;
    let (syscall_filter_rules, n_syscall_filter_rules, syscall_filter_default_action) = syscall_filter.as_ref().map_or(
        (std::ptr::null(), 0, crate::ffi::seccomp::SECCOMP_ACTION_ALLOW),
        |filter| (filter.rules.as_ptr(), filter.rules.len(), filter.default_action));
    let (_read_write_path_strings, read_write_paths) = compile_read_write_paths(section)?;

    let sandbox = SdSpawnSandbox {
        no_new_privs: libc::c_int::from(security.no_new_privileges),
        private_tmp: libc::c_int::from(security.private_tmp),
        private_devices: libc::c_int::from(security.private_devices),
        private_network: libc::c_int::from(security.private_network),
        private_mounts: libc::c_int::from(security.private_mounts),
        protect_system: libc::c_int::from(security.protect_system),
        protect_home: libc::c_int::from(security.protect_home),
        protect_kernel_tunables: libc::c_int::from(security.protect_kernel_tunables),
        protect_kernel_modules: libc::c_int::from(security.protect_kernel_modules),
        protect_kernel_logs: libc::c_int::from(security.protect_kernel_logs),
        protect_clock: libc::c_int::from(security.protect_clock),
        protect_control_groups: libc::c_int::from(security.protect_control_groups),
        restrict_suid_sgid: libc::c_int::from(security.restrict_suid_sgid),
        restrict_realtime: libc::c_int::from(security.restrict_realtime),
        restrict_namespaces: libc::c_int::from(security.restrict_namespaces),
        memory_deny_write_execute: libc::c_int::from(security.memory_deny_write_execute),
        syscall_filter_rules,
        n_syscall_filter_rules,
        syscall_filter_default_action,
        syscall_filter_enabled: libc::c_int::from(syscall_filter.is_some()),
        restrict_native_syscalls: libc::c_int::from(restrict_native_syscalls),
        read_write_paths: if read_write_paths.is_empty() { std::ptr::null() } else { read_write_paths.as_ptr() },
        n_read_write_paths: read_write_paths.len(),
    };
    let sandbox_enabled = !fully_privileged && (security.no_new_privileges || security.private_tmp || security.private_devices
        || security.private_network || security.private_mounts || security.protect_system != 0 || security.protect_home != 0
        || security.protect_kernel_tunables || security.protect_kernel_modules || security.protect_kernel_logs || security.protect_clock
        || security.protect_control_groups || security.restrict_suid_sgid || security.restrict_realtime || security.restrict_namespaces
        || security.memory_deny_write_execute || syscall_filter.is_some() || restrict_native_syscalls || !read_write_paths.is_empty());

    let argv_strings: Vec<CString> = effective_argv.iter().map(|argument| CString::new(argument.as_str())).collect::<Result<_, _>>()
        .map_err(|_| anyhow!("service command contains a NUL byte"))?;
    let mut argv: Vec<*const libc::c_char> = argv_strings.iter().map(|value| value.as_ptr()).collect(); argv.push(std::ptr::null());
    let env_strings: Vec<CString> = merged_environment.iter().filter_map(|entry| CString::new(entry.as_str()).ok()).collect();
    let mut env: Vec<*const libc::c_char> = env_strings.iter().map(|value| value.as_ptr()).collect(); env.push(std::ptr::null());
    let working_directory = CString::new(section.working_directory.as_str()).map_err(|_| anyhow!("WorkingDirectory contains a NUL byte"))?;
    let working_directory_ptr = if section.working_directory.is_empty() { std::ptr::null() } else { working_directory.as_ptr() };
    let credentials = if fully_privileged || no_setuid { (libc::uid_t::MAX, libc::gid_t::MAX) }
        else { dynamic_user.map_or((security.uid, security.gid), |identity| (identity.uid, identity.gid())) };
    let (selinux_context, selinux_context_ignore) = if fully_privileged { (None, 0) } else { mac_exec_label(&section.se_linux_context, "SELinuxContext")? };
    let (apparmor_profile, apparmor_profile_ignore) = if fully_privileged { (None, 0) } else { mac_exec_label(&section.app_armor_profile, "AppArmorProfile")? };
    let rlimits = compile_rlimits(section);
    let cgroup_procs = cgroup_procs_path.map(|path| CString::new(path.as_os_str().as_bytes())).transpose()
        .map_err(|_| anyhow!("cgroup.procs path contains a NUL byte"))?;
    let mut idle_pipe = [-1, -1];
    if gate_idle_exec && unsafe { libc::pipe2(idle_pipe.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(anyhow!("failed to create Type=idle execution gate: {}", std::io::Error::last_os_error()));
    }
    let identifier = if section.syslog_identifier.is_empty() { unit_name.trim_end_matches(".service") } else { section.syslog_identifier.as_str() };
    let journal_path = std::env::var_os("RUSTD_JOURNAL_STDOUT").map_or_else(|| PathBuf::from(DEFAULT_STDOUT_PATH), PathBuf::from);
    let mut stdout_stream = None; let mut stderr_stream = None; let route_journal = !is_journal_daemon(unit_name);
    let stdout_fd = if route_journal && wants_journal_stdio(&section.standard_output) {
        match connect_service_stream_with_limits(&journal_path, identifier, unit_name, 6, section.log_rate_limit_interval_sec, section.log_rate_limit_burst) {
            Ok(stream) => { let fd = stream.as_raw_fd(); stdout_stream = Some(stream); fd }
            Err(error) => { eprintln!("rustd: {unit_name} StandardOutput=journal unavailable at {}: {error}; using /dev/null", journal_path.display()); open_dev_null(libc::O_WRONLY)? }
        }
    } else { -1 };
    let stderr_mode = if section.standard_error.is_empty() || section.standard_error.eq_ignore_ascii_case("inherit") { section.standard_output.as_str() } else { section.standard_error.as_str() };
    let stderr_fd = if route_journal && wants_journal_stdio(stderr_mode) {
        match connect_service_stream_with_limits(&journal_path, identifier, unit_name, 3, section.log_rate_limit_interval_sec, section.log_rate_limit_burst) {
            Ok(stream) => { let fd = stream.as_raw_fd(); stderr_stream = Some(stream); fd }
            Err(error) => { eprintln!("rustd: {unit_name} StandardError=journal unavailable at {}: {error}; using /dev/null", journal_path.display()); open_dev_null(libc::O_WRONLY)? }
        }
    } else { -1 };

    let params = SdSpawnParams {
        path: path_string.as_ptr(), argv: argv.as_ptr(), envp: if env_strings.is_empty() { std::ptr::null() } else { env.as_ptr() },
        cwd: working_directory_ptr, cgroup_procs_path: cgroup_procs.as_ref().map_or(std::ptr::null(), |path| path.as_ptr()),
        rlimits: if rlimits.is_empty() { std::ptr::null() } else { rlimits.as_ptr() }, n_rlimits: rlimits.len(),
        uid: credentials.0, gid: credentials.1,
        selinux_context: selinux_context.as_ref().map_or(std::ptr::null(), |value| value.as_ptr()), selinux_context_ignore,
        apparmor_profile: apparmor_profile.as_ref().map_or(std::ptr::null(), |value| value.as_ptr()), apparmor_profile_ignore,
        stdin_fd: -1, stdout_fd, stderr_fd, notify_fd, watchdog_usec: watchdog_usec(section, notify_fd),
        sandbox: if sandbox_enabled { std::ptr::addr_of!(sandbox) } else { std::ptr::null() },
        listen_fds: if listen_fds.is_empty() { std::ptr::null() } else { listen_fds.as_ptr() },
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)] n_listen_fds: listen_fds.len() as libc::c_int,
        cap_bounding_set: if fully_privileged { u64::MAX } else { security.cap_bounding_set },
        ambient_caps: if fully_privileged { 0 } else { security.ambient_caps },
        wait_for_exec: libc::c_int::from(section.service_type == ServiceType::Exec), idle_read_fd: idle_pipe[0], idle_write_fd: idle_pipe[1],
    };
    let pid = unsafe { rustd_spawn(&params) };
    drop(stdout_stream); drop(stderr_stream);
    if idle_pipe[0] >= 0 { unsafe { libc::close(idle_pipe[0]) }; }
    if pid < 0 {
        if idle_pipe[1] >= 0 { unsafe { libc::close(idle_pipe[1]) }; }
        return Err(anyhow!("failed to spawn '{}': errno {}", executable_path, -pid));
    }
    Ok(SpawnedProcess { pid, idle_gate_fd: (idle_pipe[1] >= 0).then_some(idle_pipe[1]) })
}

pub(crate) fn release_idle_gate(record: &mut UnitRecord) {
    if let Some(fd) = record.idle_gate_fd.take() { unsafe { libc::close(fd) }; }
}

fn wait_for_command(pid: libc::pid_t, flags: ExecFlags) -> anyhow::Result<CommandOutcome> {
    let mut status = 0i32;
    loop {
        let result = unsafe { libc::waitpid(pid, &mut status, 0) };
        if result == pid { break; }
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) { continue; }
            return Err(anyhow!("waitpid({pid}) failed: {error}"));
        }
    }
    let ignored = flags.contains(ExecFlags::IGNORE_FAILURE);
    if libc::WIFEXITED(status) { Ok(CommandOutcome { exit_code: Some(libc::WEXITSTATUS(status)), signal: None, ignored }) }
    else if libc::WIFSIGNALED(status) { Ok(CommandOutcome { exit_code: None, signal: Some(libc::WTERMSIG(status)), ignored }) }
    else { Ok(CommandOutcome { exit_code: None, signal: None, ignored }) }
}

fn command_failed(phase: &str, command: &ExecCommand, outcome: CommandOutcome) -> anyhow::Error {
    let executable = if command.path.is_empty() { "<empty>" } else { command.path.as_str() };
    if let Some(code) = outcome.exit_code { anyhow!("{phase} command '{executable}' exited with status {code}") }
    else if let Some(signal) = outcome.signal { anyhow!("{phase} command '{executable}' was killed by signal {signal}") }
    else { anyhow!("{phase} command '{executable}' did not exit normally") }
}

fn is_success(exit: &ChildExit, flags: Option<ExecFlags>, section: &ServiceSection) -> bool {
    if flags.is_some_and(|value| value.contains(ExecFlags::IGNORE_FAILURE)) { return true; }
    if exit.code == libc::CLD_EXITED {
        return exit.status == 0 || crate::unit::section_service::exit_status_set_matches(&section.success_exit_status, exit.code, exit.status);
    }
    if exit.code == libc::CLD_KILLED {
        let daemon_clean = section.service_type != ServiceType::Oneshot && matches!(exit.status, libc::SIGHUP | libc::SIGINT | libc::SIGTERM | libc::SIGPIPE);
        return daemon_clean || crate::unit::section_service::exit_status_set_matches(&section.success_exit_status, exit.code, exit.status);
    }
    false
}

pub(crate) fn restart_requested(section: &ServiceSection, exit: &ChildExit, service_result: &str) -> bool {
    use crate::unit::section_service::exit_status_set_matches;
    if exit_status_set_matches(&section.restart_prevent_exit_status, exit.code, exit.status) { return false; }
    if exit_status_set_matches(&section.restart_force_exit_status, exit.code, exit.status) {
        return !(section.service_type == ServiceType::Oneshot && service_result == "success");
    }
    should_restart_result(section.restart, service_result)
}

fn watchdog_usec(section: &ServiceSection, notify_fd: libc::c_int) -> u64 {
    if notify_fd < 0 { return 0; }
    section.watchdog_sec.map_or(0, |duration| u64::try_from(duration.as_micros()).unwrap_or(u64::MAX))
}

fn environment_value<'a>(environment: &'a [String], name: &str) -> Option<&'a str> {
    environment.iter().rev().find_map(|entry| { let (key, value) = entry.split_once('=')?; (key == name).then_some(value) })
}

fn valid_environment_name(name: &str) -> bool {
    let mut chars = name.chars(); let Some(first) = chars.next() else { return false; };
    (first == '_' || first.is_ascii_alphabetic()) && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn split_environment_words(value: &str) -> Vec<String> {
    let mut words = Vec::new(); let mut current = String::new(); let mut chars = value.chars().peekable();
    let mut single = false; let mut double = false; let mut started = false;
    while let Some(ch) = chars.next() {
        match ch {
            '\'' if !double => { single = !single; started = true; }
            '"' if !single => { double = !double; started = true; }
            '\\' if !single => if let Some(next) = chars.next() { current.push(next); started = true; },
            ' ' | '\t' | '\n' | '\r' if !single && !double => if started { words.push(std::mem::take(&mut current)); started = false; },
            _ => { current.push(ch); started = true; }
        }
    }
    if started { words.push(current); } words
}

fn expand_braced_environment(argument: &str, environment: &[String]) -> String {
    let mut output = String::with_capacity(argument.len()); let bytes = argument.as_bytes(); let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'$' && bytes.get(index + 1) == Some(&b'{') {
            let start = index + 2;
            if let Some(relative_end) = argument[start..].find('}') {
                let end = start + relative_end; let name = &argument[start..end];
                if valid_environment_name(name) {
                    if let Some(value) = environment_value(environment, name) { output.push_str(value); }
                    index = end + 1; continue;
                }
            }
        }
        let ch = argument[index..].chars().next().expect("valid UTF-8 boundary"); output.push(ch); index += ch.len_utf8();
    }
    output
}

fn expand_exec_arguments(arguments: &[String], environment: &[String], no_expand: bool) -> Vec<String> {
    if no_expand { return arguments.to_vec(); }
    let mut expanded = Vec::new();
    for argument in arguments {
        if let Some(name) = argument.strip_prefix('$') {
            if valid_environment_name(name) {
                if let Some(value) = environment_value(environment, name) { expanded.extend(split_environment_words(value)); }
                continue;
            }
        }
        expanded.push(expand_braced_environment(argument, environment));
    }
    expanded
}

fn mac_exec_label(raw: &str, directive: &str) -> anyhow::Result<(Option<CString>, libc::c_int)> {
    if raw.is_empty() { return Ok((None, 0)); }
    let (ignore, label) = raw.strip_prefix('-').map_or((false, raw), |value| (true, value));
    if label.is_empty() { return Ok((None, libc::c_int::from(ignore))); }
    let label = CString::new(label).map_err(|_| anyhow!("{directive} contains a NUL byte"))?;
    Ok((Some(label), libc::c_int::from(ignore)))
}

fn passwd_shell(passwd: *const libc::passwd) -> Option<String> {
    if passwd.is_null() { return None; }
    let shell = unsafe { (*passwd).pw_shell }; if shell.is_null() { return None; }
    let shell = unsafe { CStr::from_ptr(shell) }.to_string_lossy().into_owned();
    if shell.is_empty() || shell.ends_with("/nologin") || shell.ends_with("/false") { None } else { Some(shell) }
}

fn selected_login_shell(section: &ServiceSection, dynamic_user: Option<&DynamicUser>) -> String {
    if dynamic_user.is_some() { return "/bin/sh".to_owned(); }
    let passwd = if section.user.is_empty() { unsafe { libc::getpwuid(libc::geteuid()) } }
        else if let Ok(uid) = section.user.parse::<libc::uid_t>() { unsafe { libc::getpwuid(uid) } }
        else if let Ok(user) = CString::new(section.user.as_str()) { unsafe { libc::getpwnam(user.as_ptr()) } }
        else { std::ptr::null_mut() };
    passwd_shell(passwd).unwrap_or_else(|| "/bin/sh".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unit::loader::{LoadedUnit, ParsedUnit};
    use crate::unit::section_install::InstallSection;
    use crate::unit::section_service::{ExecCommand, ExecFlags, RestartPolicy, ServiceSection, ServiceType};
    use crate::unit::section_unit::UnitSection;
    use std::path::PathBuf;

    fn make_service(name: &str, exec_start: &str, service_type: ServiceType) -> UnitRecord {
        let mut section = ServiceSection { service_type, standard_output: "null".into(), standard_error: "null".into(), ..Default::default() };
        if let Some(command) = ExecCommand::parse(exec_start) { section.exec_start.push(command); }
        make_service_with_section(name, section)
    }
    fn make_service_with_section(name: &str, section: ServiceSection) -> UnitRecord {
        let mut section = section; if section.standard_output.is_empty() { section.standard_output = "null".into(); }
        if section.standard_error.is_empty() { section.standard_error = "null".into(); }
        UnitRecord::new(LoadedUnit::Service(Box::new(ParsedUnit { name: name.to_owned(), source_path: PathBuf::from(format!("/fake/{name}")),
            unit: UnitSection::default(), install: InstallSection::default(), specific: section })))
    }
    fn shell_command(script: &str) -> ExecCommand { ExecCommand::parse(&format!("/bin/sh -c '{script}'")).unwrap() }

    #[test]
    fn read_write_paths_require_absolute_entries() {
        let mut section = ServiceSection::default();
        section.read_write_paths = vec!["relative/path".into()];
        assert!(compile_read_write_paths(&section).is_err());
        section.read_write_paths = vec!["/var/lib/rustd".into(), "-/run/optional".into()];
        let (strings, pointers) = compile_read_write_paths(&section).unwrap();
        assert_eq!(strings.len(), 2);
        assert_eq!(pointers.len(), 2);
    }

    #[test]
    fn journal_stdio_connect_failure_falls_back_to_dev_null() {
        let mut section = ServiceSection { service_type: ServiceType::Simple, standard_output: "journal".into(), standard_error: "null".into(), ..Default::default() };
        section.exec_start.push(shell_command("true")); let mut record = make_service_with_section("journal-missing.service", section);
        std::env::set_var("RUSTD_JOURNAL_STDOUT", "/tmp/rustd-journal-stdout-definitely-missing");
        let result = activate(&mut record, &[]); std::env::remove_var("RUSTD_JOURNAL_STDOUT"); result.unwrap();
        assert_eq!(record.state, UnitState::Active); if let Some(pid) = record.active_pid { unsafe { libc::kill(pid, libc::SIGKILL) }; }
    }

    #[test]
    fn journal_daemon_does_not_require_its_own_stdout_socket() {
        let mut section = ServiceSection { service_type: ServiceType::Simple, standard_output: "journal".into(), standard_error: "journal".into(), ..Default::default() };
        section.exec_start.push(shell_command("true")); let mut record = make_service_with_section("rustd-journald.service", section);
        std::env::set_var("RUSTD_JOURNAL_STDOUT", "/tmp/rustd-journal-stdout-definitely-missing"); let result = activate(&mut record, &[]);
        std::env::remove_var("RUSTD_JOURNAL_STDOUT"); result.unwrap(); if let Some(pid) = record.active_pid { unsafe { libc::kill(pid, libc::SIGKILL); libc::waitpid(pid, std::ptr::null_mut(), 0); } }
    }

    #[test]
    fn exec_environment_expansion_matches_systemd_word_rules() {
        let environment = vec!["WORDS=one 'two three' four".to_owned(), "INLINE=hello world".to_owned()];
        let args = vec!["/bin/echo".to_owned(), "$WORDS".to_owned(), "prefix-${INLINE}-suffix".to_owned(), "${MISSING}".to_owned()];
        assert_eq!(expand_exec_arguments(&args, &environment, false), ["/bin/echo", "one", "two three", "four", "prefix-hello world-suffix", ""]);
        assert_eq!(expand_exec_arguments(&args, &environment, true), args);
    }

    #[test]
    fn unset_standalone_environment_word_disappears() {
        let args = vec!["/bin/echo".to_owned(), "$MISSING".to_owned()]; assert_eq!(expand_exec_arguments(&args, &[], false), ["/bin/echo".to_owned()]);
    }

    #[test]
    fn unit_environment_overrides_the_manager_launch_environment() {
        let environment = merge_environment_entries(&["FROM_MANAGER=manager".into(), "UNIT_WINS=manager".into()], &["UNIT_WINS=unit".into(), "FROM_UNIT=unit".into()]);
        assert_eq!(environment, ["FROM_MANAGER=manager", "UNIT_WINS=unit", "FROM_UNIT=unit"]);
    }

    #[test]
    fn service_start_invocation_ids_are_uuid_v4_shaped() {
        let mut record = make_service("invocation.service", "/bin/true", ServiceType::Oneshot); record.assign_invocation_id().unwrap();
        let id = record.invocation_id.unwrap(); assert_eq!(id[6] >> 4, 4); assert_eq!(id[8] >> 6, 2);
    }

    #[test]
    fn dynamic_user_allocation_failure_is_fatal() { assert!(allocate_dynamic_user("invalid/name.service", &ServiceSection { dynamic_user: true, ..Default::default() }).is_err()); }

    #[test]
    fn simple_activate_to_active() {
        let mut record = make_service("test.service", "/bin/sleep 100", ServiceType::Simple); activate(&mut record, &[]).unwrap(); assert_eq!(record.state, UnitState::Active);
        if let Some(pid) = record.active_pid { unsafe { libc::kill(pid, libc::SIGKILL); libc::waitpid(pid, std::ptr::null_mut(), 0); } }
    }

    #[test]
    fn exit_type_cgroup_defers_completion_until_cgroup_empty() {
        let directory = tempfile::tempdir().unwrap(); let procs = directory.path().join("cgroup.procs"); std::fs::write(&procs, "999\n").unwrap();
        let mut record = make_service_with_section("cgroup.service", ServiceSection { exit_type: "cgroup".into(), ..Default::default() }); record.state=UnitState::Active; record.active_pid=Some(42);
        let exit=ChildExit{pid:42,code:libc::CLD_EXITED,status:1}; assert!(on_child_exit_with_notify_in_cgroup(&mut record,&exit,-1,Some(&procs))); assert_eq!(record.state,UnitState::Active);
        std::fs::write(&procs, "").unwrap(); assert!(on_service_cgroup_empty_with_notify_in_cgroup(&mut record,-1,Some(&procs))); assert_eq!(record.state,UnitState::Failed);
    }

    #[test]
    fn restart_mode_direct_keeps_failed_restart_active() {
        let mut record=make_service_with_section("direct.service",ServiceSection{restart:RestartPolicy::Always,restart_mode:"direct".into(),..Default::default()}); record.state=UnitState::Active; record.active_pid=Some(42);
        let exit=ChildExit{pid:42,code:libc::CLD_EXITED,status:1}; assert!(on_child_exit(&mut record,&exit)); assert_eq!(record.state,UnitState::Active);
    }

    #[test]
    fn nofile_limit_is_enforced_for_service_payload() {
        let mut section=ServiceSection{service_type:ServiceType::Oneshot,..Default::default()}; section.apply("LimitNOFILE","32"); section.exec_start.push(ExecCommand::parse("/bin/sh -c 'ulimit -n | grep -qx 32'").unwrap());
        let mut record=make_service_with_section("rlimit.service",section); activate(&mut record,&[]).unwrap(); assert_eq!(record.state,UnitState::Inactive);
    }

    #[test]
    fn exec_type_reports_execve_failure_synchronously() {
        let mut record=make_service("exec-failure.service","/definitely/not/a/rustd-executable",ServiceType::Exec); assert!(activate(&mut record,&[]).is_err()); assert_eq!(record.state,UnitState::Failed);
    }

    #[test]
    fn oneshot_completes_synchronously() { let mut record=make_service("test.service","/bin/true",ServiceType::Oneshot); activate(&mut record,&[]).unwrap(); assert_eq!(record.state,UnitState::Inactive); }

    #[test]
    fn ignore_failure_flag_marks_success() {
        let exit=ChildExit{pid:1,code:libc::CLD_EXITED,status:1}; assert!(is_success(&exit,Some(ExecFlags::IGNORE_FAILURE),&ServiceSection::default())); assert!(!is_success(&exit,Some(ExecFlags::empty()),&ServiceSection::default()));
    }

    #[test]
    fn start_pipeline_runs_in_order() {
        let d=tempfile::tempdir().unwrap(); let trace=d.path().join("trace"); let mut s=ServiceSection{service_type:ServiceType::Oneshot,..Default::default()};
        s.exec_start_pre.push(shell_command(&format!("echo pre >> {}",trace.display()))); s.exec_start.push(shell_command(&format!("echo main >> {}",trace.display()))); s.exec_start_post.push(shell_command(&format!("echo post >> {}",trace.display())));
        let mut r=make_service_with_section("pipeline.service",s); activate(&mut r,&[]).unwrap(); assert_eq!(std::fs::read_to_string(trace).unwrap(),"pre\nmain\npost\n");
    }

    #[test]
    fn success_exit_status_and_clean_daemon_signals_match_v261() {
        let mut section=ServiceSection{service_type:ServiceType::Simple,success_exit_status:vec!["42".into(),"SIGUSR1".into()],..Default::default()};
        assert!(is_success(&ChildExit{pid:1,code:libc::CLD_EXITED,status:42},None,&section)); assert!(is_success(&ChildExit{pid:1,code:libc::CLD_KILLED,status:libc::SIGUSR1},None,&section));
        let term=ChildExit{pid:1,code:libc::CLD_KILLED,status:libc::SIGTERM}; assert!(is_success(&term,None,&section)); section.service_type=ServiceType::Oneshot; assert!(!is_success(&term,None,&section));
    }

    #[test]
    fn restart_exit_status_exceptions_precede_policy() {
        let exit=ChildExit{pid:1,code:libc::CLD_EXITED,status:42}; let mut section=ServiceSection{restart:RestartPolicy::No,restart_force_exit_status:vec!["42".into()],..Default::default()};
        assert!(restart_requested(&section,&exit,"exit-code")); section.restart_prevent_exit_status.push("42".into()); assert!(!restart_requested(&section,&exit,"exit-code"));
    }
}
