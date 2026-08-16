// SPDX-License-Identifier: LGPL-2.1-or-later
//! `io.rustd.Manager1.Service` D-Bus interface.
//!
//! One instance is registered per service unit at its canonical object path,
//! alongside the `io.rustd.Manager1.Unit` interface.
//!
//! Upstream reference: `src/core/dbus-service.c` (v261)

// zbus interface methods must accept &self and owned types for the D-Bus wire
// protocol even when not all are used in the body.
#![allow(
    clippy::unused_self,
    clippy::needless_pass_by_value,
    clippy::unnecessary_wraps,
    clippy::missing_errors_doc,
    clippy::map_unwrap_or,
    clippy::cast_sign_loss
)]

use std::ffi::CString;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use zbus::interface;

use crate::cgroup::CgroupManager;
use crate::config::{ManagerScope, UnitDefaults};
use crate::ipc::UnitInfo;
use crate::resource_control::{CpuQuota, LimitValue};
use crate::sandbox::{resolve_group, resolve_user};
use crate::unit::loader::{LoadedUnit, UnitLoader};
use crate::unit::section_service::{
    parse_signal, ExecCommand, ExecFlags, KillMode, NotifyAccess, ProtectHome, ProtectSystem,
    RestartPolicy, RlimitSpec, RlimitValue, ServiceSection, ServiceType,
};

const DEFAULT_TIMEOUT_USEC: u64 = 90_000_000;
const RESTRICT_ALL_NAMESPACES: u64 =
    0x0002_0000 | 0x0200_0000 | 0x0400_0000 | 0x0800_0000 | 0x1000_0000 | 0x2000_0000 | 0x4000_0000;

type ExecProperty = (String, Vec<String>, bool, u64, u64, u64, u64, u32, i32, i32);
type ExecExProperty = (
    String,
    Vec<String>,
    Vec<String>,
    u64,
    u64,
    u64,
    u64,
    u32,
    i32,
    i32,
);

// ── ServiceInterface ──────────────────────────────────────────────────────

/// The `io.rustd.Manager1.Service` interface object.
///
/// Runtime properties are read from the shared manager snapshot. Parsed
/// configuration properties are loaded through the canonical unit loader so
/// drop-ins, generator output, and the normal unit search path are respected.
pub struct ServiceInterface {
    /// Name of this service unit, e.g. `"systemd-journald.service"`.
    pub name: String,
    /// Shared snapshot updated by the manager loop.
    pub snapshot: Arc<RwLock<Vec<UnitInfo>>>,
    /// Manager scope owning this object.
    pub scope: ManagerScope,
    /// Live Manager defaults inherited by units without explicit settings.
    pub unit_defaults: Arc<RwLock<UnitDefaults>>,
}

impl ServiceInterface {
    /// Look up this unit's current `UnitInfo` from the snapshot.
    fn info(&self) -> Option<UnitInfo> {
        self.snapshot
            .read()
            .ok()?
            .iter()
            .find(|unit| unit.name == self.name)
            .cloned()
    }

    /// Load the effective `[Service]` configuration, including drop-ins.
    fn section(&self) -> Option<ServiceSection> {
        let mut loaded = UnitLoader::for_scope(self.scope).load(&self.name).ok()?;
        if let Ok(defaults) = self.unit_defaults.read() {
            defaults.apply_to_loaded_unit(&mut loaded);
        }
        let LoadedUnit::Service(service) = loaded else {
            return None;
        };
        Some(service.specific)
    }

    /// The cgroup manager uses the same scope and root selection as the
    /// manager that owns this D-Bus object. Constructing this lightweight
    /// handle on demand keeps the interface snapshot-independent while still
    /// reading the live kernel counters.
    fn cgroup(&self) -> CgroupManager {
        CgroupManager::for_scope(self.scope)
    }
}

#[interface(name = "io.rustd.Manager1.Service")]
impl ServiceInterface {
    // ── configuration properties ──────────────────────────────────────

    /// `Type` — service type string.
    #[zbus(name = "Type", property(emits_changed_signal = "const"))]
    fn service_type(&self) -> String {
        self.info()
            .and_then(|unit| unit.service_type)
            .or_else(|| {
                self.section()
                    .map(|service| service_type_name(service.service_type))
            })
            .unwrap_or_else(|| "simple".into())
    }

    /// `ExitType` — whether service completion follows the main PID or cgroup.
    #[zbus(name = "ExitType", property(emits_changed_signal = "const"))]
    fn exit_type(&self) -> String {
        self.section()
            .map(|service| service.exit_type)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "main".into())
    }

    /// `Restart` — restart policy string.
    #[zbus(name = "Restart", property(emits_changed_signal = "const"))]
    fn restart(&self) -> String {
        self.info()
            .and_then(|unit| unit.restart_policy)
            .or_else(|| self.section().map(|service| restart_name(service.restart)))
            .unwrap_or_else(|| "no".into())
    }

    /// `RestartMode` — restart transaction mode.
    #[zbus(name = "RestartMode", property(emits_changed_signal = "const"))]
    fn restart_mode(&self) -> String {
        self.section()
            .map(|service| service.restart_mode)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "normal".into())
    }

    /// `RestartPreventExitStatus` — exits that suppress automatic restart.
    #[zbus(
        name = "RestartPreventExitStatus",
        property(emits_changed_signal = "const")
    )]
    fn restart_prevent_exit_status(&self) -> (Vec<i32>, Vec<i32>) {
        self.section().map_or((Vec::new(), Vec::new()), |service| {
            parse_exit_statuses(&service.restart_prevent_exit_status)
        })
    }

    /// `RestartForceExitStatus` — exits that force automatic restart.
    #[zbus(
        name = "RestartForceExitStatus",
        property(emits_changed_signal = "const")
    )]
    fn restart_force_exit_status(&self) -> (Vec<i32>, Vec<i32>) {
        self.section().map_or((Vec::new(), Vec::new()), |service| {
            parse_exit_statuses(&service.restart_force_exit_status)
        })
    }

    /// `SuccessExitStatus` — additional successful exit statuses.
    #[zbus(name = "SuccessExitStatus", property(emits_changed_signal = "const"))]
    fn success_exit_status(&self) -> (Vec<i32>, Vec<i32>) {
        self.section().map_or((Vec::new(), Vec::new()), |service| {
            parse_exit_statuses(&service.success_exit_status)
        })
    }

    /// `TimeoutStartUSec` — start timeout in microseconds.
    #[zbus(name = "TimeoutStartUSec", property(emits_changed_signal = "const"))]
    fn timeout_start_u_sec(&self) -> u64 {
        self.section()
            .and_then(|service| service.timeout_start_sec)
            .map_or(DEFAULT_TIMEOUT_USEC, duration_usec)
    }

    /// `TimeoutStopUSec` — stop timeout in microseconds.
    #[zbus(name = "TimeoutStopUSec", property(emits_changed_signal = "const"))]
    fn timeout_stop_u_sec(&self) -> u64 {
        self.section()
            .and_then(|service| service.timeout_stop_sec)
            .map_or(DEFAULT_TIMEOUT_USEC, duration_usec)
    }

    /// `WatchdogUSec` — watchdog timeout in microseconds.
    /// 0 means the watchdog is disabled.
    #[zbus(name = "WatchdogUSec", property(emits_changed_signal = "false"))]
    fn watchdog_u_sec(&self) -> u64 {
        self.section()
            .and_then(|service| service.watchdog_sec)
            .map_or(0, duration_usec)
    }

    /// `WatchdogTimestampMonotonic` — last watchdog notification timestamp.
    #[zbus(
        name = "WatchdogTimestampMonotonic",
        property(emits_changed_signal = "false")
    )]
    fn watchdog_timestamp_monotonic(&self) -> u64 {
        self.info()
            .and_then(|unit| unit.service_runtime.watchdog_timestamp_ns)
            .and_then(|timestamp| u64::try_from(timestamp).ok())
            .map_or(0, |timestamp| timestamp / 1_000)
    }

    /// `WatchdogTimestamp` — last watchdog notification in realtime
    /// microseconds since the Unix epoch.
    #[zbus(name = "WatchdogTimestamp", property(emits_changed_signal = "false"))]
    fn watchdog_timestamp(&self) -> u64 {
        self.info()
            .and_then(|unit| unit.service_runtime.watchdog_timestamp_realtime_ns)
            .and_then(|timestamp| u64::try_from(timestamp).ok())
            .map_or(0, |timestamp| timestamp / 1_000)
    }

    /// `PIDFile` — configured PID file for forking services.
    #[zbus(name = "PIDFile", property(emits_changed_signal = "const"))]
    fn pid_file(&self) -> String {
        self.section()
            .map(|service| service.pid_file)
            .unwrap_or_default()
    }

    /// `BusName` — D-Bus name used by `Type=dbus` services.
    #[zbus(name = "BusName", property(emits_changed_signal = "const"))]
    fn bus_name(&self) -> String {
        self.info()
            .and_then(|unit| unit.service_runtime.bus_name)
            .or_else(|| self.section().map(|service| service.bus_name))
            .unwrap_or_default()
    }

    /// `UID` — configured or currently allocated service user ID.
    #[zbus(name = "UID", property)]
    fn uid(&self) -> u32 {
        if let Some(uid) = self
            .info()
            .and_then(|unit| unit.service_runtime.dynamic_user.map(|user| user.uid))
        {
            return uid;
        }
        self.section()
            .and_then(|service| resolve_user(&service.user).ok())
            .unwrap_or(u32::MAX)
    }

    /// `GID` — configured or currently allocated service group ID.
    #[zbus(name = "GID", property)]
    fn gid(&self) -> u32 {
        if let Some(gid) = self
            .info()
            .and_then(|unit| unit.service_runtime.dynamic_user.map(|user| user.uid))
        {
            return gid;
        }
        self.section()
            .and_then(|service| resolve_group(&service.group).ok())
            .unwrap_or(u32::MAX)
    }

    /// `RestartUSec` — initial restart delay.
    #[zbus(name = "RestartUSec", property(emits_changed_signal = "const"))]
    fn restart_u_sec(&self) -> u64 {
        self.section()
            .and_then(|service| service.restart_sec)
            .map_or(100_000, duration_usec)
    }

    /// `RestartSteps` — number of exponential restart-delay steps.
    #[zbus(name = "RestartSteps", property(emits_changed_signal = "const"))]
    fn restart_steps(&self) -> u32 {
        self.section()
            .and_then(|service| service.restart_steps)
            .unwrap_or(0)
    }

    /// `RestartMaxDelayUSec` — maximum restart delay.
    #[zbus(name = "RestartMaxDelayUSec", property(emits_changed_signal = "const"))]
    fn restart_max_delay_u_sec(&self) -> u64 {
        self.section()
            .and_then(|service| service.restart_max_delay_sec)
            .map_or(u64::MAX, duration_usec)
    }

    /// `RestartUSecNext` — delay currently scheduled for the next restart.
    ///
    /// The candidate exposes no pending restart timer through its snapshot;
    /// the v261 idle value is therefore the exact value until a restart is
    /// queued, rather than an inferred copy of `RestartSec`.
    #[zbus(name = "RestartUSecNext", property(emits_changed_signal = "false"))]
    fn restart_u_sec_next(&self) -> u64 {
        0
    }

    /// `TimeoutAbortUSec` — timeout used by abort/watchdog escalation.
    #[zbus(name = "TimeoutAbortUSec", property(emits_changed_signal = "false"))]
    fn timeout_abort_u_sec(&self) -> u64 {
        self.section()
            .and_then(|service| service.timeout_abort_sec.or(service.timeout_stop_sec))
            .map_or(DEFAULT_TIMEOUT_USEC, duration_usec)
    }

    /// `TimeoutStartFailureMode` — action after a start timeout.
    #[zbus(
        name = "TimeoutStartFailureMode",
        property(emits_changed_signal = "const")
    )]
    fn timeout_start_failure_mode(&self) -> String {
        self.section()
            .map(|service| service.timeout_start_failure_mode)
            .filter(|mode| !mode.is_empty())
            .unwrap_or_else(|| "terminate".into())
    }

    /// `TimeoutStopFailureMode` — action after a stop timeout.
    #[zbus(
        name = "TimeoutStopFailureMode",
        property(emits_changed_signal = "const")
    )]
    fn timeout_stop_failure_mode(&self) -> String {
        self.section()
            .map(|service| service.timeout_stop_failure_mode)
            .filter(|mode| !mode.is_empty())
            .unwrap_or_else(|| "terminate".into())
    }

    /// `RuntimeMaxUSec` — maximum service runtime.
    #[zbus(name = "RuntimeMaxUSec", property(emits_changed_signal = "const"))]
    fn runtime_max_u_sec(&self) -> u64 {
        self.section()
            .and_then(|service| service.runtime_max_sec)
            .map_or(u64::MAX, duration_usec)
    }

    /// `RuntimeRandomizedExtraUSec` — additional randomized runtime budget.
    #[zbus(
        name = "RuntimeRandomizedExtraUSec",
        property(emits_changed_signal = "const")
    )]
    fn runtime_randomized_extra_u_sec(&self) -> u64 {
        self.section()
            .and_then(|service| service.runtime_randomized_extra_sec)
            .map_or(0, duration_usec)
    }

    /// `RootDirectoryStartOnly` — apply `RootDirectory=` only to start paths.
    #[zbus(
        name = "RootDirectoryStartOnly",
        property(emits_changed_signal = "const")
    )]
    fn root_directory_start_only(&self) -> bool {
        self.section()
            .is_some_and(|service| service.root_directory_start_only)
    }

    /// `GuessMainPID` — whether the manager guesses a forking service PID.
    #[zbus(name = "GuessMainPID", property(emits_changed_signal = "const"))]
    fn guess_main_pid(&self) -> bool {
        self.section()
            .map_or(true, |service| service.guess_main_pid)
    }

    /// `FileDescriptorStoreMax` — maximum retained descriptor count.
    #[zbus(
        name = "FileDescriptorStoreMax",
        property(emits_changed_signal = "const")
    )]
    fn file_descriptor_store_max(&self) -> u32 {
        self.info()
            .map(|unit| unit.service_runtime.file_descriptor_store_max)
            .or_else(|| {
                self.section()
                    .map(|service| service.file_descriptor_store_max)
            })
            .unwrap_or(0)
    }

    /// `FileDescriptorStorePreserve` — descriptor retention across restarts.
    #[zbus(name = "FileDescriptorStorePreserve", property)]
    fn file_descriptor_store_preserve(&self) -> String {
        self.section()
            .map(|service| service.file_descriptor_store_preserve)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "restart".into())
    }

    /// `OpenFile` — files opened and passed to the service at activation.
    #[zbus(name = "OpenFile", property(emits_changed_signal = "const"))]
    fn open_file(&self) -> Vec<(String, String, u64)> {
        self.section()
            .map(|service| open_file_properties(&service.open_file))
            .unwrap_or_default()
    }

    /// `RefreshOnReload` — resources refreshed by a service reload.
    #[zbus(name = "RefreshOnReload", property(emits_changed_signal = "const"))]
    fn refresh_on_reload(&self) -> Vec<String> {
        self.section()
            .map(|service| service.refresh_on_reload)
            .unwrap_or_default()
    }

    /// Parsed `ExecCondition=` commands and their execution status.
    #[zbus(name = "ExecCondition", property(emits_changed_signal = "invalidates"))]
    fn exec_condition(&self) -> Vec<ExecProperty> {
        self.section()
            .map(|service| exec_command_properties(&service.exec_condition))
            .unwrap_or_default()
    }

    #[zbus(
        name = "ExecConditionEx",
        property(emits_changed_signal = "invalidates")
    )]
    fn exec_condition_ex(&self) -> Vec<ExecExProperty> {
        self.section()
            .map(|service| exec_ex_command_properties(&service.exec_condition))
            .unwrap_or_default()
    }

    /// Parsed `ExecStartPre=` commands and their execution status.
    #[zbus(name = "ExecStartPre", property(emits_changed_signal = "invalidates"))]
    fn exec_start_pre(&self) -> Vec<ExecProperty> {
        self.section()
            .map(|service| exec_command_properties(&service.exec_start_pre))
            .unwrap_or_default()
    }

    #[zbus(
        name = "ExecStartPreEx",
        property(emits_changed_signal = "invalidates")
    )]
    fn exec_start_pre_ex(&self) -> Vec<ExecExProperty> {
        self.section()
            .map(|service| exec_ex_command_properties(&service.exec_start_pre))
            .unwrap_or_default()
    }

    /// Parsed `ExecStart=` commands and their execution status.
    #[zbus(name = "ExecStart", property(emits_changed_signal = "invalidates"))]
    fn exec_start(&self) -> Vec<ExecProperty> {
        self.section()
            .map(|service| exec_command_properties(&service.exec_start))
            .unwrap_or_default()
    }

    #[zbus(name = "ExecStartEx", property(emits_changed_signal = "invalidates"))]
    fn exec_start_ex(&self) -> Vec<ExecExProperty> {
        self.section()
            .map(|service| exec_ex_command_properties(&service.exec_start))
            .unwrap_or_default()
    }

    /// Parsed `ExecStartPost=` commands and their execution status.
    #[zbus(name = "ExecStartPost", property(emits_changed_signal = "invalidates"))]
    fn exec_start_post(&self) -> Vec<ExecProperty> {
        self.section()
            .map(|service| exec_command_properties(&service.exec_start_post))
            .unwrap_or_default()
    }

    #[zbus(
        name = "ExecStartPostEx",
        property(emits_changed_signal = "invalidates")
    )]
    fn exec_start_post_ex(&self) -> Vec<ExecExProperty> {
        self.section()
            .map(|service| exec_ex_command_properties(&service.exec_start_post))
            .unwrap_or_default()
    }

    /// Parsed `ExecReload=` commands and their execution status.
    #[zbus(name = "ExecReload", property(emits_changed_signal = "invalidates"))]
    fn exec_reload(&self) -> Vec<ExecProperty> {
        self.section()
            .map(|service| exec_command_properties(&service.exec_reload))
            .unwrap_or_default()
    }

    #[zbus(name = "ExecReloadEx", property(emits_changed_signal = "invalidates"))]
    fn exec_reload_ex(&self) -> Vec<ExecExProperty> {
        self.section()
            .map(|service| exec_ex_command_properties(&service.exec_reload))
            .unwrap_or_default()
    }

    /// Parsed `ExecReloadPost=` commands and their execution status.
    #[zbus(
        name = "ExecReloadPost",
        property(emits_changed_signal = "invalidates")
    )]
    fn exec_reload_post(&self) -> Vec<ExecProperty> {
        self.section()
            .map(|service| exec_command_properties(&service.exec_reload_post))
            .unwrap_or_default()
    }

    #[zbus(
        name = "ExecReloadPostEx",
        property(emits_changed_signal = "invalidates")
    )]
    fn exec_reload_post_ex(&self) -> Vec<ExecExProperty> {
        self.section()
            .map(|service| exec_ex_command_properties(&service.exec_reload_post))
            .unwrap_or_default()
    }

    /// Parsed `ExecStop=` commands and their execution status.
    #[zbus(name = "ExecStop", property(emits_changed_signal = "invalidates"))]
    fn exec_stop(&self) -> Vec<ExecProperty> {
        self.section()
            .map(|service| exec_command_properties(&service.exec_stop))
            .unwrap_or_default()
    }

    #[zbus(name = "ExecStopEx", property(emits_changed_signal = "invalidates"))]
    fn exec_stop_ex(&self) -> Vec<ExecExProperty> {
        self.section()
            .map(|service| exec_ex_command_properties(&service.exec_stop))
            .unwrap_or_default()
    }

    /// Parsed `ExecStopPost=` commands and their execution status.
    #[zbus(name = "ExecStopPost", property(emits_changed_signal = "invalidates"))]
    fn exec_stop_post(&self) -> Vec<ExecProperty> {
        self.section()
            .map(|service| exec_command_properties(&service.exec_stop_post))
            .unwrap_or_default()
    }

    #[zbus(
        name = "ExecStopPostEx",
        property(emits_changed_signal = "invalidates")
    )]
    fn exec_stop_post_ex(&self) -> Vec<ExecExProperty> {
        self.section()
            .map(|service| exec_ex_command_properties(&service.exec_stop_post))
            .unwrap_or_default()
    }

    /// `RootDirectory` — service root directory.
    #[zbus(name = "RootDirectory", property(emits_changed_signal = "const"))]
    fn root_directory(&self) -> String {
        self.section()
            .map(|service| service.root_directory)
            .unwrap_or_default()
    }

    /// `Environment` — assignments from the unit's `[Service]` context.
    #[zbus(property(emits_changed_signal = "const"))]
    fn environment(&self) -> Vec<String> {
        self.section()
            .map(|service| service.environment)
            .unwrap_or_default()
    }

    /// `EnvironmentFiles` — files and their ignore-failure flags.
    #[zbus(property(emits_changed_signal = "const"))]
    fn environment_files(&self) -> Vec<(String, bool)> {
        self.section()
            .map(|service| {
                service
                    .environment_file
                    .into_iter()
                    .map(|path| {
                        let optional = path.starts_with('-');
                        (path.strip_prefix('-').unwrap_or(&path).to_owned(), optional)
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// `ImportCredential` — credential names imported into the service.
    #[zbus(name = "ImportCredential", property(emits_changed_signal = "const"))]
    fn import_credential(&self) -> Vec<String> {
        self.section()
            .map(|service| service.import_credential)
            .unwrap_or_default()
    }

    /// `PassEnvironment` — inherited variable names passed to services.
    #[zbus(property(emits_changed_signal = "const"))]
    fn pass_environment(&self) -> Vec<String> {
        self.section()
            .map(|service| service.pass_environment)
            .unwrap_or_default()
    }

    /// `UnsetEnvironment` — variable names removed from the service environment.
    #[zbus(property(emits_changed_signal = "const"))]
    fn unset_environment(&self) -> Vec<String> {
        self.section()
            .map(|service| service.unset_environment)
            .unwrap_or_default()
    }

    /// `SupplementaryGroups` — supplementary groups for the service process.
    #[zbus(property(emits_changed_signal = "const"))]
    fn supplementary_groups(&self) -> Vec<String> {
        self.section()
            .map(|service| service.supplementary_groups)
            .unwrap_or_default()
    }

    /// `PAMName` — PAM service name.
    #[zbus(name = "PAMName", property(emits_changed_signal = "const"))]
    fn pam_name(&self) -> String {
        self.section()
            .map(|service| service.pam_name)
            .unwrap_or_default()
    }

    /// `Nice` — process nice value.
    #[zbus(property(emits_changed_signal = "const"))]
    fn nice(&self) -> i32 {
        self.section().and_then(|service| service.nice).unwrap_or(0)
    }

    /// `OOMScoreAdjust` — process OOM score adjustment.
    #[zbus(name = "OOMScoreAdjust", property(emits_changed_signal = "const"))]
    fn oom_score_adjust(&self) -> i32 {
        self.section()
            .and_then(|service| service.oom_score_adjust)
            .unwrap_or(0)
    }

    /// `IOSchedulingClass` — Linux I/O priority class.
    #[zbus(name = "IOSchedulingClass", property(emits_changed_signal = "const"))]
    fn io_scheduling_class(&self) -> i32 {
        self.section()
            .map(|service| io_scheduling_class(&service.io_scheduling_class))
            .unwrap_or(0)
    }

    /// `IOSchedulingPriority` — Linux I/O priority data.
    #[zbus(
        name = "IOSchedulingPriority",
        property(emits_changed_signal = "const")
    )]
    fn io_scheduling_priority(&self) -> i32 {
        self.section()
            .and_then(|service| service.io_scheduling_priority)
            .unwrap_or(0)
    }

    /// `CPUSchedulingPolicy` — Linux CPU scheduling policy.
    #[zbus(name = "CPUSchedulingPolicy", property(emits_changed_signal = "const"))]
    fn cpu_scheduling_policy(&self) -> i32 {
        self.section()
            .map(|service| cpu_scheduling_policy(&service.cpu_scheduling_policy))
            .unwrap_or(0)
    }

    /// `CPUSchedulingPriority` — Linux CPU scheduling priority.
    #[zbus(
        name = "CPUSchedulingPriority",
        property(emits_changed_signal = "const")
    )]
    fn cpu_scheduling_priority(&self) -> i32 {
        self.section()
            .and_then(|service| service.cpu_scheduling_priority)
            .unwrap_or(0)
    }

    /// `CPUSchedulingResetOnFork` — reset scheduling policy after fork.
    #[zbus(
        name = "CPUSchedulingResetOnFork",
        property(emits_changed_signal = "const")
    )]
    fn cpu_scheduling_reset_on_fork(&self) -> bool {
        self.section()
            .map(|service| service.cpu_scheduling_reset_on_fork)
            .unwrap_or(false)
    }

    /// `CPUAffinity` — CPUs selected for service execution.
    #[zbus(name = "CPUAffinity", property(emits_changed_signal = "const"))]
    fn cpu_affinity(&self) -> Vec<u8> {
        self.section()
            .map(|service| cpu_affinity_bitmap(&service.cpu_affinity))
            .unwrap_or_default()
    }

    #[zbus(name = "TimerSlackNSec", property(emits_changed_signal = "const"))]
    fn timer_slack_nsec(&self) -> u64 {
        self.section()
            .and_then(|service| service.timer_slack_nsec)
            .and_then(|duration| u64::try_from(duration.as_nanos()).ok())
            .or_else(|| {
                std::fs::read_to_string("/proc/self/timerslack_ns")
                    .ok()
                    .and_then(|value| value.trim().parse().ok())
            })
            .unwrap_or(50_000)
    }

    /// `RuntimeDirectory` — runtime directories created for the service.
    #[zbus(property(emits_changed_signal = "const"))]
    fn runtime_directory(&self) -> Vec<String> {
        self.section()
            .map(|service| service.runtime_directory)
            .unwrap_or_default()
    }

    /// `RuntimeDirectoryMode` — mode used for runtime directories.
    #[zbus(
        name = "RuntimeDirectoryMode",
        property(emits_changed_signal = "const")
    )]
    fn runtime_directory_mode(&self) -> u32 {
        self.section()
            .and_then(|service| service.runtime_directory_mode)
            .unwrap_or(0o755)
    }

    /// `RuntimeDirectoryPreserve` — runtime-directory cleanup policy.
    #[zbus(
        name = "RuntimeDirectoryPreserve",
        property(emits_changed_signal = "const")
    )]
    fn runtime_directory_preserve(&self) -> String {
        self.section()
            .map(|service| service.runtime_directory_preserve)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "no".into())
    }

    /// `StateDirectory` — state directories created for the service.
    #[zbus(property(emits_changed_signal = "const"))]
    fn state_directory(&self) -> Vec<String> {
        self.section()
            .map(|service| service.state_directory)
            .unwrap_or_default()
    }

    /// `StateDirectoryMode` — mode used for state directories.
    #[zbus(name = "StateDirectoryMode", property(emits_changed_signal = "const"))]
    fn state_directory_mode(&self) -> u32 {
        self.section()
            .and_then(|service| service.state_directory_mode)
            .unwrap_or(0o755)
    }

    /// `CacheDirectory` — cache directories created for the service.
    #[zbus(property(emits_changed_signal = "const"))]
    fn cache_directory(&self) -> Vec<String> {
        self.section()
            .map(|service| service.cache_directory)
            .unwrap_or_default()
    }

    /// `CacheDirectoryMode` — mode used for cache directories.
    #[zbus(name = "CacheDirectoryMode", property(emits_changed_signal = "const"))]
    fn cache_directory_mode(&self) -> u32 {
        self.section()
            .and_then(|service| service.cache_directory_mode)
            .unwrap_or(0o755)
    }

    /// `LogsDirectory` — log directories created for the service.
    #[zbus(property(emits_changed_signal = "const"))]
    fn logs_directory(&self) -> Vec<String> {
        self.section()
            .map(|service| service.logs_directory)
            .unwrap_or_default()
    }

    /// `LogsDirectoryMode` — mode used for log directories.
    #[zbus(name = "LogsDirectoryMode", property(emits_changed_signal = "const"))]
    fn logs_directory_mode(&self) -> u32 {
        self.section()
            .and_then(|service| service.logs_directory_mode)
            .unwrap_or(0o755)
    }

    /// `ConfigurationDirectory` — configuration directories created for the service.
    #[zbus(property(emits_changed_signal = "const"))]
    fn configuration_directory(&self) -> Vec<String> {
        self.section()
            .map(|service| service.configuration_directory)
            .unwrap_or_default()
    }

    /// `ConfigurationDirectoryMode` — mode used for configuration directories.
    #[zbus(
        name = "ConfigurationDirectoryMode",
        property(emits_changed_signal = "const")
    )]
    fn configuration_directory_mode(&self) -> u32 {
        self.section()
            .and_then(|service| service.configuration_directory_mode)
            .unwrap_or(0o755)
    }

    /// `ReadWritePaths` — paths made writable in the service namespace.
    #[zbus(property(emits_changed_signal = "const"))]
    fn read_write_paths(&self) -> Vec<String> {
        self.section()
            .map(|service| service.read_write_paths)
            .unwrap_or_default()
    }

    /// `ReadOnlyPaths` — paths made read-only in the service namespace.
    #[zbus(property(emits_changed_signal = "const"))]
    fn read_only_paths(&self) -> Vec<String> {
        self.section()
            .map(|service| service.read_only_paths)
            .unwrap_or_default()
    }

    /// `InaccessiblePaths` — paths hidden from the service namespace.
    #[zbus(property(emits_changed_signal = "const"))]
    fn inaccessible_paths(&self) -> Vec<String> {
        self.section()
            .map(|service| service.inaccessible_paths)
            .unwrap_or_default()
    }

    /// `ExecPaths` — paths allowed for executable access.
    #[zbus(property(emits_changed_signal = "const"))]
    fn exec_paths(&self) -> Vec<String> {
        self.section()
            .map(|service| service.exec_paths)
            .unwrap_or_default()
    }

    /// `NoExecPaths` — paths denied executable access.
    #[zbus(property(emits_changed_signal = "const"))]
    fn no_exec_paths(&self) -> Vec<String> {
        self.section()
            .map(|service| service.no_exec_paths)
            .unwrap_or_default()
    }

    /// `ExecSearchPath` — configured executable search path entries.
    #[zbus(name = "ExecSearchPath", property(emits_changed_signal = "const"))]
    fn exec_search_path(&self) -> Vec<String> {
        self.section()
            .map(|service| service.exec_search_path)
            .unwrap_or_default()
    }

    /// `RestrictFileSystems` — filesystem allow/deny policy.
    #[zbus(property(emits_changed_signal = "const"))]
    fn restrict_file_systems(&self) -> (bool, Vec<String>) {
        self.section()
            .map(|service| string_policy_list(&service.restrict_filesystems))
            .unwrap_or((true, Vec::new()))
    }

    /// `BindPaths` — writable bind mounts requested by the service.
    #[zbus(property(emits_changed_signal = "const"))]
    fn bind_paths(&self) -> Vec<(String, String, bool, u64)> {
        self.section()
            .map(|service| bind_path_properties(&service.bind_paths, false))
            .unwrap_or_default()
    }

    /// `BindReadOnlyPaths` — read-only bind mounts requested by the service.
    #[zbus(property(emits_changed_signal = "const"))]
    fn bind_read_only_paths(&self) -> Vec<(String, String, bool, u64)> {
        self.section()
            .map(|service| bind_path_properties(&service.bind_read_only_paths, true))
            .unwrap_or_default()
    }

    /// `TemporaryFileSystem` — temporary filesystem mounts requested by the service.
    #[zbus(property(emits_changed_signal = "const"))]
    fn temporary_file_system(&self) -> Vec<(String, String)> {
        self.section()
            .map(|service| temporary_filesystem_properties(&service.temporary_filesystem))
            .unwrap_or_default()
    }

    /// `SystemCallArchitectures` — architectures permitted by seccomp.
    #[zbus(property(emits_changed_signal = "const"))]
    fn system_call_architectures(&self) -> Vec<String> {
        self.section()
            .map(|service| service.system_call_architectures)
            .unwrap_or_default()
    }

    /// `SystemCallErrorNumber` — errno returned for denied system calls.
    #[zbus(
        name = "SystemCallErrorNumber",
        property(emits_changed_signal = "const")
    )]
    fn system_call_error_number(&self) -> i32 {
        self.section()
            .map(|service| syscall_error_number(&service.system_call_error_number))
            .unwrap_or(0)
    }

    /// `RestrictAddressFamilies` — allowed address families.
    #[zbus(property(emits_changed_signal = "const"))]
    fn restrict_address_families(&self) -> (bool, Vec<String>) {
        self.section()
            .map(|service| address_family_list(&service.restrict_address_families))
            .unwrap_or((true, Vec::new()))
    }

    /// `IPAddressAllow` — allowed IPv4/IPv6 network prefixes.
    #[zbus(name = "IPAddressAllow", property(emits_changed_signal = "false"))]
    fn ip_address_allow(&self) -> Vec<(i32, Vec<u8>, u32)> {
        self.section()
            .map(|service| ip_address_properties(&service.ip_address_allow))
            .unwrap_or_default()
    }

    /// `IPAddressDeny` — denied IPv4/IPv6 network prefixes.
    #[zbus(name = "IPAddressDeny", property(emits_changed_signal = "false"))]
    fn ip_address_deny(&self) -> Vec<(i32, Vec<u8>, u32)> {
        self.section()
            .map(|service| ip_address_properties(&service.ip_address_deny))
            .unwrap_or_default()
    }

    /// `SystemCallFilter` — seccomp syscall allow/deny policy.
    #[zbus(name = "SystemCallFilter", property(emits_changed_signal = "const"))]
    fn system_call_filter(&self) -> (bool, Vec<String>) {
        self.section()
            .map(|service| syscall_filter_list(&service.system_call_filter))
            .unwrap_or((false, Vec::new()))
    }

    /// `SystemCallLog` — syscalls whose seccomp decisions are logged.
    #[zbus(name = "SystemCallLog", property(emits_changed_signal = "const"))]
    fn system_call_log(&self) -> (bool, Vec<String>) {
        self.section()
            .map(|service| syscall_log_list(&service.system_call_log))
            .unwrap_or((false, Vec::new()))
    }

    /// `DevicePolicy` — device access policy.
    #[zbus(property(emits_changed_signal = "false"))]
    fn device_policy(&self) -> String {
        self.section()
            .map(|service| service.device_policy)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "auto".into())
    }

    /// `DeviceAllow` — explicitly allowed device nodes and modes.
    #[zbus(property(emits_changed_signal = "false"))]
    fn device_allow(&self) -> Vec<(String, String)> {
        self.section()
            .map(|service| {
                service
                    .device_allow
                    .into_iter()
                    .map(|entry| {
                        let mut fields = entry.split_whitespace();
                        let node_path = fields.next().unwrap_or_default().to_owned();
                        let access_mode = fields.next().unwrap_or_default().to_owned();
                        (node_path, access_mode)
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// `Slice` — cgroup slice containing this service.
    #[zbus(property(emits_changed_signal = "false"))]
    fn slice(&self) -> String {
        self.section()
            .map(|service| service.slice)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| match self.scope {
                ManagerScope::System => "system.slice".into(),
                ManagerScope::User => "app.slice".into(),
            })
    }

    /// `CPUWeight` — cgroup CPU weight, or the v261 unlimited sentinel.
    #[zbus(name = "CPUWeight", property)]
    fn cpu_weight(&self) -> u64 {
        self.section()
            .and_then(|service| {
                if service.resource_control.cpu_idle {
                    Some(0)
                } else {
                    service.resource_control.cpu_weight
                }
            })
            .unwrap_or(u64::MAX)
    }

    /// `CPUQuotaPerSecUSec` — CPU quota expressed per second.
    #[zbus(name = "CPUQuotaPerSecUSec", property)]
    fn cpu_quota_per_sec_u_sec(&self) -> u64 {
        self.section()
            .and_then(|service| service.resource_control.cpu_quota)
            .map(cpu_quota_usec)
            .unwrap_or(u64::MAX)
    }

    /// `CPUQuotaPeriodUSec` — configured quota period.
    #[zbus(name = "CPUQuotaPeriodUSec", property)]
    fn cpu_quota_period_u_sec(&self) -> u64 {
        u64::MAX
    }

    /// `IOWeight` — cgroup I/O weight, or the v261 unlimited sentinel.
    #[zbus(name = "IOWeight", property)]
    fn io_weight(&self) -> u64 {
        self.section()
            .and_then(|service| service.resource_control.io_weight)
            .unwrap_or(u64::MAX)
    }

    #[zbus(name = "LimitCPU", property(emits_changed_signal = "const"))]
    fn limit_cpu(&self) -> u64 {
        rlimit_property(self.section(), |s| s.limit_cpu, libc::RLIMIT_CPU, false)
    }
    #[zbus(name = "LimitCPUSoft", property(emits_changed_signal = "const"))]
    fn limit_cpu_soft(&self) -> u64 {
        rlimit_property(self.section(), |s| s.limit_cpu, libc::RLIMIT_CPU, true)
    }
    #[zbus(name = "LimitFSIZE", property(emits_changed_signal = "const"))]
    fn limit_fsize(&self) -> u64 {
        rlimit_property(self.section(), |s| s.limit_fsize, libc::RLIMIT_FSIZE, false)
    }
    #[zbus(name = "LimitFSIZESoft", property(emits_changed_signal = "const"))]
    fn limit_fsize_soft(&self) -> u64 {
        rlimit_property(self.section(), |s| s.limit_fsize, libc::RLIMIT_FSIZE, true)
    }
    #[zbus(name = "LimitDATA", property(emits_changed_signal = "const"))]
    fn limit_data(&self) -> u64 {
        rlimit_property(self.section(), |s| s.limit_data, libc::RLIMIT_DATA, false)
    }
    #[zbus(name = "LimitDATASoft", property(emits_changed_signal = "const"))]
    fn limit_data_soft(&self) -> u64 {
        rlimit_property(self.section(), |s| s.limit_data, libc::RLIMIT_DATA, true)
    }
    #[zbus(name = "LimitSTACK", property(emits_changed_signal = "const"))]
    fn limit_stack(&self) -> u64 {
        rlimit_property(self.section(), |s| s.limit_stack, libc::RLIMIT_STACK, false)
    }
    #[zbus(name = "LimitSTACKSoft", property(emits_changed_signal = "const"))]
    fn limit_stack_soft(&self) -> u64 {
        rlimit_property(self.section(), |s| s.limit_stack, libc::RLIMIT_STACK, true)
    }
    #[zbus(name = "LimitCORE", property(emits_changed_signal = "const"))]
    fn limit_core(&self) -> u64 {
        rlimit_property(self.section(), |s| s.limit_core, libc::RLIMIT_CORE, false)
    }
    #[zbus(name = "LimitCORESoft", property(emits_changed_signal = "const"))]
    fn limit_core_soft(&self) -> u64 {
        rlimit_property(self.section(), |s| s.limit_core, libc::RLIMIT_CORE, true)
    }
    #[zbus(name = "LimitRSS", property(emits_changed_signal = "const"))]
    fn limit_rss(&self) -> u64 {
        rlimit_property(self.section(), |s| s.limit_rss, libc::RLIMIT_RSS, false)
    }
    #[zbus(name = "LimitRSSSoft", property(emits_changed_signal = "const"))]
    fn limit_rss_soft(&self) -> u64 {
        rlimit_property(self.section(), |s| s.limit_rss, libc::RLIMIT_RSS, true)
    }
    #[zbus(name = "LimitNOFILE", property(emits_changed_signal = "const"))]
    fn limit_nofile(&self) -> u64 {
        rlimit_property(
            self.section(),
            |s| s.limit_nofile,
            libc::RLIMIT_NOFILE,
            false,
        )
    }
    #[zbus(name = "LimitNOFILESoft", property(emits_changed_signal = "const"))]
    fn limit_nofile_soft(&self) -> u64 {
        rlimit_property(
            self.section(),
            |s| s.limit_nofile,
            libc::RLIMIT_NOFILE,
            true,
        )
    }
    #[zbus(name = "LimitAS", property(emits_changed_signal = "const"))]
    fn limit_as(&self) -> u64 {
        rlimit_property(self.section(), |s| s.limit_as, libc::RLIMIT_AS, false)
    }
    #[zbus(name = "LimitASSoft", property(emits_changed_signal = "const"))]
    fn limit_as_soft(&self) -> u64 {
        rlimit_property(self.section(), |s| s.limit_as, libc::RLIMIT_AS, true)
    }
    #[zbus(name = "LimitNPROC", property(emits_changed_signal = "const"))]
    fn limit_nproc(&self) -> u64 {
        rlimit_property(self.section(), |s| s.limit_nproc, libc::RLIMIT_NPROC, false)
    }
    #[zbus(name = "LimitNPROCSoft", property(emits_changed_signal = "const"))]
    fn limit_nproc_soft(&self) -> u64 {
        rlimit_property(self.section(), |s| s.limit_nproc, libc::RLIMIT_NPROC, true)
    }
    #[zbus(name = "LimitMEMLOCK", property(emits_changed_signal = "const"))]
    fn limit_memlock(&self) -> u64 {
        rlimit_property(
            self.section(),
            |s| s.limit_memlock,
            libc::RLIMIT_MEMLOCK,
            false,
        )
    }
    #[zbus(name = "LimitMEMLOCKSoft", property(emits_changed_signal = "const"))]
    fn limit_memlock_soft(&self) -> u64 {
        rlimit_property(
            self.section(),
            |s| s.limit_memlock,
            libc::RLIMIT_MEMLOCK,
            true,
        )
    }
    #[zbus(name = "LimitLOCKS", property(emits_changed_signal = "const"))]
    fn limit_locks(&self) -> u64 {
        rlimit_property(self.section(), |s| s.limit_locks, libc::RLIMIT_LOCKS, false)
    }
    #[zbus(name = "LimitLOCKSSoft", property(emits_changed_signal = "const"))]
    fn limit_locks_soft(&self) -> u64 {
        rlimit_property(self.section(), |s| s.limit_locks, libc::RLIMIT_LOCKS, true)
    }
    #[zbus(name = "LimitSIGPENDING", property(emits_changed_signal = "const"))]
    fn limit_sigpending(&self) -> u64 {
        rlimit_property(
            self.section(),
            |s| s.limit_sigpending,
            libc::RLIMIT_SIGPENDING,
            false,
        )
    }
    #[zbus(name = "LimitSIGPENDINGSoft", property(emits_changed_signal = "const"))]
    fn limit_sigpending_soft(&self) -> u64 {
        rlimit_property(
            self.section(),
            |s| s.limit_sigpending,
            libc::RLIMIT_SIGPENDING,
            true,
        )
    }
    #[zbus(name = "LimitMSGQUEUE", property(emits_changed_signal = "const"))]
    fn limit_msgqueue(&self) -> u64 {
        rlimit_property(
            self.section(),
            |s| s.limit_msgqueue,
            libc::RLIMIT_MSGQUEUE,
            false,
        )
    }
    #[zbus(name = "LimitMSGQUEUESoft", property(emits_changed_signal = "const"))]
    fn limit_msgqueue_soft(&self) -> u64 {
        rlimit_property(
            self.section(),
            |s| s.limit_msgqueue,
            libc::RLIMIT_MSGQUEUE,
            true,
        )
    }
    #[zbus(name = "LimitNICE", property(emits_changed_signal = "const"))]
    fn limit_nice(&self) -> u64 {
        rlimit_property(self.section(), |s| s.limit_nice, libc::RLIMIT_NICE, false)
    }
    #[zbus(name = "LimitNICESoft", property(emits_changed_signal = "const"))]
    fn limit_nice_soft(&self) -> u64 {
        rlimit_property(self.section(), |s| s.limit_nice, libc::RLIMIT_NICE, true)
    }
    #[zbus(name = "LimitRTPRIO", property(emits_changed_signal = "const"))]
    fn limit_rtprio(&self) -> u64 {
        rlimit_property(
            self.section(),
            |s| s.limit_rtprio,
            libc::RLIMIT_RTPRIO,
            false,
        )
    }
    #[zbus(name = "LimitRTPRIOSoft", property(emits_changed_signal = "const"))]
    fn limit_rtprio_soft(&self) -> u64 {
        rlimit_property(
            self.section(),
            |s| s.limit_rtprio,
            libc::RLIMIT_RTPRIO,
            true,
        )
    }
    #[zbus(name = "LimitRTTIME", property(emits_changed_signal = "const"))]
    fn limit_rttime(&self) -> u64 {
        rlimit_property(
            self.section(),
            |s| s.limit_rttime,
            libc::RLIMIT_RTTIME,
            false,
        )
    }
    #[zbus(name = "LimitRTTIMESoft", property(emits_changed_signal = "const"))]
    fn limit_rttime_soft(&self) -> u64 {
        rlimit_property(
            self.section(),
            |s| s.limit_rttime,
            libc::RLIMIT_RTTIME,
            true,
        )
    }

    #[zbus(property)]
    fn memory_min(&self) -> u64 {
        self.section()
            .and_then(|service| service.resource_control.memory_min)
            .map(limit_value)
            .unwrap_or(u64::MAX)
    }

    #[zbus(property)]
    fn memory_low(&self) -> u64 {
        self.section()
            .and_then(|service| service.resource_control.memory_low)
            .map(limit_value)
            .unwrap_or(u64::MAX)
    }

    #[zbus(property)]
    fn memory_high(&self) -> u64 {
        self.section()
            .and_then(|service| service.resource_control.memory_high)
            .map(limit_value)
            .unwrap_or(u64::MAX)
    }

    #[zbus(property)]
    fn memory_max(&self) -> u64 {
        self.section()
            .and_then(|service| service.resource_control.memory_max)
            .map(limit_value)
            .unwrap_or(u64::MAX)
    }

    #[zbus(name = "MemorySwapMax", property)]
    fn memory_swap_max(&self) -> u64 {
        self.section()
            .and_then(|service| service.resource_control.memory_swap_max)
            .map(limit_value)
            .unwrap_or(u64::MAX)
    }

    #[zbus(name = "MemoryZSwapMax", property(emits_changed_signal = "false"))]
    fn memory_zswap_max(&self) -> u64 {
        self.section()
            .and_then(|service| service.resource_control.memory_zswap_max)
            .map(limit_value)
            .unwrap_or(u64::MAX)
    }

    #[zbus(
        name = "MemoryZSwapWriteback",
        property(emits_changed_signal = "false")
    )]
    fn memory_zswap_writeback(&self) -> bool {
        self.section()
            .and_then(|service| service.resource_control.memory_zswap_writeback)
            .unwrap_or(true)
    }

    #[zbus(property)]
    fn tasks_max(&self) -> u64 {
        self.section()
            .and_then(|service| service.resource_control.tasks_max)
            .map(limit_value)
            .unwrap_or(u64::MAX)
    }

    #[zbus(name = "IOAccounting", property(emits_changed_signal = "false"))]
    fn io_accounting(&self) -> bool {
        self.section()
            .is_some_and(|service| service.resource_control.io_accounting)
    }

    #[zbus(name = "MemoryAccounting", property(emits_changed_signal = "false"))]
    fn memory_accounting(&self) -> bool {
        self.section()
            .is_some_and(|service| service.resource_control.memory_accounting)
    }

    #[zbus(name = "TasksAccounting", property(emits_changed_signal = "false"))]
    fn tasks_accounting(&self) -> bool {
        self.section()
            .is_some_and(|service| service.resource_control.tasks_accounting)
    }

    #[zbus(name = "IPAccounting", property(emits_changed_signal = "false"))]
    fn ip_accounting(&self) -> bool {
        self.section()
            .is_some_and(|service| service.resource_control.ip_accounting)
    }

    /// `User` — configured service user.
    #[zbus(property(emits_changed_signal = "const"))]
    fn user(&self) -> String {
        self.section()
            .map(|service| service.user)
            .unwrap_or_default()
    }

    /// `Group` — configured service group.
    #[zbus(property(emits_changed_signal = "const"))]
    fn group(&self) -> String {
        self.section()
            .map(|service| service.group)
            .unwrap_or_default()
    }

    /// `WorkingDirectory` — service working directory.
    #[zbus(property(emits_changed_signal = "const"))]
    fn working_directory(&self) -> String {
        self.section()
            .map(|service| service.working_directory)
            .unwrap_or_default()
    }

    /// `StandardInput` — service standard input mode.
    #[zbus(property(emits_changed_signal = "const"))]
    fn standard_input(&self) -> String {
        self.section()
            .map(|service| service.standard_input)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "null".into())
    }

    /// `StandardOutput` — service standard output mode.
    #[zbus(property(emits_changed_signal = "const"))]
    fn standard_output(&self) -> String {
        self.section()
            .map(|service| service.standard_output)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "journal".into())
    }

    /// `StandardError` — service standard error mode.
    #[zbus(property(emits_changed_signal = "const"))]
    fn standard_error(&self) -> String {
        self.section()
            .map(|service| service.standard_error)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "inherit".into())
    }

    /// `PrivateUsers` — private user namespace setting.
    #[zbus(property(emits_changed_signal = "const"))]
    fn private_users(&self) -> bool {
        self.section().is_some_and(|service| service.private_users)
    }

    /// `PrivateUsersEx` — extended private user namespace mode.
    #[zbus(name = "PrivateUsersEx", property(emits_changed_signal = "const"))]
    fn private_users_ex(&self) -> String {
        self.section().map_or_else(
            || "no".into(),
            |service| {
                if service.private_users {
                    "self".into()
                } else {
                    "no".into()
                }
            },
        )
    }

    /// `PrivateMounts` — private mount namespace setting.
    #[zbus(property(emits_changed_signal = "const"))]
    fn private_mounts(&self) -> bool {
        self.section().is_some_and(|service| service.private_mounts)
    }

    #[zbus(name = "PrivateIPC", property(emits_changed_signal = "const"))]
    fn private_ipc(&self) -> bool {
        self.section().is_some_and(|service| service.private_ipc)
    }

    #[zbus(name = "PrivatePIDs", property(emits_changed_signal = "const"))]
    fn private_pids(&self) -> String {
        self.section()
            .map(|service| service.private_pids)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "no".into())
    }

    #[zbus(name = "ProtectHostname", property(emits_changed_signal = "const"))]
    fn protect_hostname(&self) -> bool {
        self.section()
            .is_some_and(|service| service.protect_hostname)
    }

    /// `ProtectHostnameEx` — hostname protection mode and private hostname.
    #[zbus(name = "ProtectHostnameEx", property(emits_changed_signal = "const"))]
    fn protect_hostname_ex(&self) -> (String, String) {
        self.section().map_or_else(
            || ("no".into(), String::new()),
            |service| {
                (
                    if service.protect_hostname {
                        "yes".into()
                    } else {
                        "no".into()
                    },
                    String::new(),
                )
            },
        )
    }

    #[zbus(name = "ProtectProc", property(emits_changed_signal = "const"))]
    fn protect_proc(&self) -> String {
        self.section()
            .map(|service| service.protect_proc)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "default".into())
    }

    #[zbus(name = "ProcSubset", property(emits_changed_signal = "const"))]
    fn proc_subset(&self) -> String {
        self.section()
            .map(|service| service.proc_subset)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "all".into())
    }

    /// `ProtectKernelTunables` — protect kernel tunables.
    #[zbus(property(emits_changed_signal = "const"))]
    fn protect_kernel_tunables(&self) -> bool {
        self.section()
            .is_some_and(|service| service.protect_kernel_tunables)
    }

    /// `ProtectKernelModules` — protect kernel modules.
    #[zbus(property(emits_changed_signal = "const"))]
    fn protect_kernel_modules(&self) -> bool {
        self.section()
            .is_some_and(|service| service.protect_kernel_modules)
    }

    /// `ProtectKernelLogs` — protect kernel logs.
    #[zbus(property(emits_changed_signal = "const"))]
    fn protect_kernel_logs(&self) -> bool {
        self.section()
            .is_some_and(|service| service.protect_kernel_logs)
    }

    /// `ProtectClock` — protect the system clock.
    #[zbus(property(emits_changed_signal = "const"))]
    fn protect_clock(&self) -> bool {
        self.section().is_some_and(|service| service.protect_clock)
    }

    /// `ProtectControlGroups` — protect the cgroup hierarchy.
    #[zbus(property(emits_changed_signal = "const"))]
    fn protect_control_groups(&self) -> bool {
        self.section()
            .is_some_and(|service| service.protect_control_groups)
    }

    /// `ProtectControlGroupsEx` — extended cgroup hierarchy protection mode.
    #[zbus(
        name = "ProtectControlGroupsEx",
        property(emits_changed_signal = "const")
    )]
    fn protect_control_groups_ex(&self) -> String {
        self.section().map_or_else(
            || "no".into(),
            |service| {
                if service.protect_control_groups {
                    "yes".into()
                } else {
                    "no".into()
                }
            },
        )
    }

    /// `RestrictSUIDSGID` — restrict set-user-ID and set-group-ID operations.
    #[zbus(name = "RestrictSUIDSGID", property(emits_changed_signal = "const"))]
    fn restrict_suid_sgid(&self) -> bool {
        self.section()
            .is_some_and(|service| service.restrict_suid_sgid)
    }

    /// `LockPersonality` — lock the process personality.
    #[zbus(property(emits_changed_signal = "const"))]
    fn lock_personality(&self) -> bool {
        self.section()
            .is_some_and(|service| service.lock_personality)
    }

    /// `RemoveIPC` — remove IPC objects on service exit.
    #[zbus(name = "RemoveIPC", property(emits_changed_signal = "const"))]
    fn remove_ipc(&self) -> bool {
        self.section().is_some_and(|service| service.remove_ipc)
    }

    /// `NonBlocking` — set nonblocking service stdio.
    #[zbus(property(emits_changed_signal = "const"))]
    fn non_blocking(&self) -> bool {
        self.section().is_some_and(|service| service.non_blocking)
    }

    /// `KillMode` — process-group kill policy.
    #[zbus(property(emits_changed_signal = "const"))]
    fn kill_mode(&self) -> String {
        self.section()
            .map(|service| kill_mode_name(service.kill_mode).to_owned())
            .unwrap_or_else(|| "control-group".into())
    }

    /// `KillSignal` — signal used for normal service termination.
    #[zbus(property(emits_changed_signal = "const"))]
    fn kill_signal(&self) -> i32 {
        self.section()
            .and_then(|service| service.kill_signal)
            .unwrap_or(libc::SIGTERM)
    }

    /// `RestartKillSignal` — signal used for restart termination.
    #[zbus(property(emits_changed_signal = "const"))]
    fn restart_kill_signal(&self) -> i32 {
        self.section()
            .and_then(|service| service.restart_kill_signal)
            .unwrap_or(libc::SIGTERM)
    }

    /// `FinalKillSignal` — final signal after timeout escalation.
    #[zbus(property(emits_changed_signal = "const"))]
    fn final_kill_signal(&self) -> i32 {
        self.section()
            .and_then(|service| service.final_kill_signal)
            .unwrap_or(libc::SIGKILL)
    }

    /// `WatchdogSignal` — signal used for watchdog expiration.
    #[zbus(property(emits_changed_signal = "const"))]
    fn watchdog_signal(&self) -> i32 {
        self.section()
            .and_then(|service| service.watchdog_signal)
            .unwrap_or(libc::SIGABRT)
    }

    /// `SendSIGKILL` — whether timeout escalation sends SIGKILL.
    #[zbus(name = "SendSIGKILL", property(emits_changed_signal = "const"))]
    fn send_sigkill(&self) -> bool {
        self.section()
            .and_then(|service| service.send_sigkill)
            .unwrap_or(true)
    }

    /// `SendSIGHUP` — whether service termination sends SIGHUP.
    #[zbus(name = "SendSIGHUP", property(emits_changed_signal = "const"))]
    fn send_sighup(&self) -> bool {
        self.section().is_some_and(|service| service.send_sighup)
    }

    /// `ReloadSignal` — signal used for service reloads.
    #[zbus(property(emits_changed_signal = "const"))]
    fn reload_signal(&self) -> i32 {
        self.section()
            .and_then(|service| parse_signal(&service.reload_signal))
            .unwrap_or(libc::SIGHUP)
    }

    /// `TimeoutCleanUSec` — cleanup timeout in microseconds.
    #[zbus(property(emits_changed_signal = "const"))]
    fn timeout_clean_u_sec(&self) -> u64 {
        self.section()
            .and_then(|service| service.timeout_clean_sec)
            .map_or(u64::MAX, duration_usec)
    }

    /// `UMask` — process file-creation mask.
    #[zbus(name = "UMask", property(emits_changed_signal = "const"))]
    fn umask(&self) -> u32 {
        self.section()
            .map(|service| parse_umask(&service.umask))
            .unwrap_or(0o022)
    }

    /// `OOMPolicy` — action taken when an OOM kill is observed.
    #[zbus(name = "OOMPolicy", property(emits_changed_signal = "const"))]
    fn oom_policy(&self) -> String {
        self.section()
            .map(|service| service.oom_policy)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "stop".into())
    }

    /// `KeyringMode` — service keyring policy.
    #[zbus(property(emits_changed_signal = "const"))]
    fn keyring_mode(&self) -> String {
        self.section()
            .map(|service| service.keyring_mode)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "private".into())
    }

    /// `RemainAfterExit` — whether the unit is considered active after the
    /// main process exits.
    #[zbus(property(emits_changed_signal = "const"))]
    fn remain_after_exit(&self) -> bool {
        self.section()
            .is_some_and(|service| service.remain_after_exit)
    }

    /// `NotifyAccess` — which processes may send `rustd_notify(3)` messages.
    #[zbus(property)]
    fn notify_access(&self) -> String {
        self.section()
            .map(|service| effective_notify_access(&service).to_owned())
            .unwrap_or_else(|| "none".into())
    }

    /// `NRestarts` — number of automatic restart attempts.
    #[zbus(property)]
    fn n_restarts(&self) -> u32 {
        self.info()
            .map_or(0, |unit| unit.service_runtime.restart_count)
    }

    // ── runtime properties ────────────────────────────────────────────

    /// `MainPID` — PID of the main service process (0 if none).
    #[zbus(name = "MainPID", property)]
    fn main_pid(&self) -> u32 {
        self.info()
            .and_then(|unit| unit.main_pid)
            .and_then(|pid| u32::try_from(pid).ok())
            .unwrap_or(0)
    }

    /// `ControlPID` — PID of the current control process (0 if none).
    #[zbus(name = "ControlPID", property)]
    fn control_pid(&self) -> u32 {
        self.info()
            .and_then(|unit| unit.service_runtime.control_pid)
            .and_then(|pid| u32::try_from(pid).ok())
            .unwrap_or(0)
    }

    /// `ExecMainStartTimestamp` — realtime start timestamp in usec.
    #[zbus(name = "ExecMainStartTimestamp", property)]
    fn exec_main_start_timestamp(&self) -> u64 {
        self.info()
            .and_then(|unit| unit.service_runtime.exec_main_start_realtime_ns)
            .and_then(|timestamp| u64::try_from(timestamp).ok())
            .map_or(0, |timestamp| timestamp / 1_000)
    }

    /// `ExecMainStartTimestampMonotonic` — monotonic start timestamp in usec.
    #[zbus(name = "ExecMainStartTimestampMonotonic", property)]
    fn exec_main_start_timestamp_monotonic(&self) -> u64 {
        self.info()
            .and_then(|unit| unit.service_runtime.exec_main_start_monotonic_ns)
            .and_then(|timestamp| u64::try_from(timestamp).ok())
            .map_or(0, |timestamp| timestamp / 1_000)
    }

    /// `ExecMainExitTimestamp` — realtime exit timestamp in usec.
    #[zbus(name = "ExecMainExitTimestamp", property)]
    fn exec_main_exit_timestamp(&self) -> u64 {
        self.info()
            .and_then(|unit| unit.service_runtime.exec_main_exit_realtime_ns)
            .and_then(|timestamp| u64::try_from(timestamp).ok())
            .map_or(0, |timestamp| timestamp / 1_000)
    }

    /// `ExecMainExitTimestampMonotonic` — monotonic exit timestamp in usec.
    #[zbus(name = "ExecMainExitTimestampMonotonic", property)]
    fn exec_main_exit_timestamp_monotonic(&self) -> u64 {
        self.info()
            .and_then(|unit| unit.service_runtime.exec_main_exit_monotonic_ns)
            .and_then(|timestamp| u64::try_from(timestamp).ok())
            .map_or(0, |timestamp| timestamp / 1_000)
    }

    /// `ExecMainPID` — last recorded main process identifier.
    #[zbus(name = "ExecMainPID", property)]
    fn exec_main_pid(&self) -> u32 {
        self.main_pid()
    }

    /// `ControlGroup` — realized unified cgroup path for this service.
    #[zbus(name = "ControlGroup", property(emits_changed_signal = "false"))]
    fn control_group(&self) -> String {
        self.cgroup().service_control_group(&self.name)
    }

    /// `ControlGroupId` — kernel cgroup directory identifier.
    #[zbus(name = "ControlGroupId", property(emits_changed_signal = "false"))]
    fn control_group_id(&self) -> u64 {
        self.cgroup().service_control_group_id(&self.name)
    }

    /// Read a live cgroup-v2 counter, using systemd's infinity sentinel for
    /// units without a realized cgroup.
    #[must_use]
    fn cgroup_value(&self, file: &str) -> u64 {
        self.cgroup().service_cgroup_value(&self.name, file)
    }

    #[zbus(name = "MemoryCurrent", property(emits_changed_signal = "false"))]
    fn memory_current(&self) -> u64 {
        self.cgroup_value("memory.current")
    }

    #[zbus(name = "MemoryPeak", property(emits_changed_signal = "false"))]
    fn memory_peak(&self) -> u64 {
        self.cgroup_value("memory.peak")
    }

    #[zbus(name = "MemorySwapCurrent", property(emits_changed_signal = "false"))]
    fn memory_swap_current(&self) -> u64 {
        self.cgroup_value("memory.swap.current")
    }

    #[zbus(name = "MemorySwapPeak", property(emits_changed_signal = "false"))]
    fn memory_swap_peak(&self) -> u64 {
        self.cgroup_value("memory.swap.peak")
    }

    #[zbus(name = "MemoryZSwapCurrent", property(emits_changed_signal = "false"))]
    fn memory_zswap_current(&self) -> u64 {
        self.cgroup_value("memory.zswap.current")
    }

    #[zbus(name = "MemoryAvailable", property(emits_changed_signal = "false"))]
    fn memory_available(&self) -> u64 {
        self.cgroup().service_memory_available()
    }

    /// `EffectiveMemoryMax` — the kernel-effective memory ceiling.
    #[zbus(name = "EffectiveMemoryMax", property(emits_changed_signal = "false"))]
    fn effective_memory_max(&self) -> u64 {
        self.cgroup_value("memory.max")
    }

    /// `EffectiveMemoryHigh` — the kernel-effective memory throttling limit.
    #[zbus(name = "EffectiveMemoryHigh", property(emits_changed_signal = "false"))]
    fn effective_memory_high(&self) -> u64 {
        self.cgroup_value("memory.high")
    }

    #[zbus(name = "IOReadBytes", property(emits_changed_signal = "false"))]
    fn io_read_bytes(&self) -> u64 {
        self.cgroup().service_io_counter(&self.name, "rbytes")
    }

    #[zbus(name = "IOReadOperations", property(emits_changed_signal = "false"))]
    fn io_read_operations(&self) -> u64 {
        self.cgroup().service_io_counter(&self.name, "rios")
    }

    #[zbus(name = "IOWriteBytes", property(emits_changed_signal = "false"))]
    fn io_write_bytes(&self) -> u64 {
        self.cgroup().service_io_counter(&self.name, "wbytes")
    }

    #[zbus(name = "IOWriteOperations", property(emits_changed_signal = "false"))]
    fn io_write_operations(&self) -> u64 {
        self.cgroup().service_io_counter(&self.name, "wios")
    }

    #[zbus(name = "EffectiveCPUs", property(emits_changed_signal = "false"))]
    fn effective_cpus(&self) -> Vec<u8> {
        self.cgroup()
            .service_cpuset_bitmap(&self.name, "cpuset.cpus.effective")
    }

    #[zbus(
        name = "EffectiveMemoryNodes",
        property(emits_changed_signal = "false")
    )]
    fn effective_memory_nodes(&self) -> Vec<u8> {
        self.cgroup()
            .service_cpuset_bitmap(&self.name, "cpuset.mems.effective")
    }

    #[zbus(name = "AllowedCPUs", property(emits_changed_signal = "false"))]
    fn allowed_cpus(&self) -> Vec<u8> {
        self.effective_cpus()
    }

    #[zbus(name = "AllowedMemoryNodes", property(emits_changed_signal = "false"))]
    fn allowed_memory_nodes(&self) -> Vec<u8> {
        self.effective_memory_nodes()
    }

    #[zbus(name = "CPUUsageNSec", property(emits_changed_signal = "false"))]
    fn cpu_usage_nsec(&self) -> u64 {
        self.cgroup().service_cpu_usage_nsec(&self.name)
    }

    #[zbus(name = "TasksCurrent", property(emits_changed_signal = "false"))]
    fn tasks_current(&self) -> u64 {
        self.cgroup_value("pids.current")
    }

    /// `EffectiveTasksMax` — the kernel-effective task limit.
    #[zbus(name = "EffectiveTasksMax", property(emits_changed_signal = "false"))]
    fn effective_tasks_max(&self) -> u64 {
        self.cgroup_value("pids.max")
    }

    #[zbus(name = "OOMKills", property(emits_changed_signal = "false"))]
    fn oom_kills(&self) -> u64 {
        self.cgroup()
            .service_cgroup_counter(&self.name, "memory.events", "oom_kill")
    }

    #[zbus(name = "ManagedOOMKills", property(emits_changed_signal = "false"))]
    fn managed_oom_kills(&self) -> u64 {
        self.cgroup()
            .service_cgroup_counter(&self.name, "memory.events", "oom_group_kill")
    }

    /// `StatusText` — human-readable status string set by the service via
    /// `rustd_notify(3)` `STATUS=…`.
    #[zbus(property)]
    fn status_text(&self) -> String {
        self.info()
            .and_then(|unit| unit.service_runtime.status_text)
            .unwrap_or_default()
    }

    /// `StatusErrno` — `errno` value set by the service via `rustd_notify`.
    #[zbus(property)]
    fn status_errno(&self) -> i32 {
        self.info()
            .and_then(|unit| unit.service_runtime.status_errno)
            .unwrap_or(0)
    }

    /// `Result` — why the service last stopped.
    #[zbus(property)]
    fn result(&self) -> String {
        self.info().map_or_else(
            || "success".into(),
            |unit| {
                if unit.service_runtime.result.is_empty() {
                    if unit.active_state == "failed" {
                        "exit-code".into()
                    } else {
                        "success".into()
                    }
                } else {
                    unit.service_runtime.result
                }
            },
        )
    }

    /// `NFileDescriptorStore` — descriptors currently retained for the unit.
    #[zbus(
        name = "NFileDescriptorStore",
        property(emits_changed_signal = "false")
    )]
    fn n_file_descriptor_store(&self) -> u32 {
        // The candidate has the v261 capacity/configuration contract but does
        // not yet accept FDSTORE=1 messages, so the live store is empty.
        0
    }

    /// `StatusBusError` — most recent bus activation error, if any.
    #[zbus(name = "StatusBusError", property)]
    fn status_bus_error(&self) -> String {
        String::new()
    }

    /// `StatusVarlinkError` — most recent Varlink activation error, if any.
    #[zbus(name = "StatusVarlinkError", property)]
    fn status_varlink_error(&self) -> String {
        String::new()
    }

    /// `ReloadResult` — last reload transaction result.
    #[zbus(name = "ReloadResult", property)]
    fn reload_result(&self) -> String {
        "success".into()
    }

    /// `CleanResult` — last clean operation result.
    #[zbus(name = "CleanResult", property)]
    fn clean_result(&self) -> String {
        "success".into()
    }

    /// `LiveMountResult` — last live-mount operation result.
    #[zbus(name = "LiveMountResult", property)]
    fn live_mount_result(&self) -> String {
        "success".into()
    }

    /// `ExecMainCode` — `siginfo.si_code` of the last main process.
    #[zbus(property)]
    fn exec_main_code(&self) -> i32 {
        self.info()
            .map_or(0, |unit| unit.service_runtime.exec_main_code)
    }

    /// `ExecMainStatus` — exit status of the last main process.
    #[zbus(property)]
    fn exec_main_status(&self) -> i32 {
        self.info()
            .map_or(0, |unit| unit.service_runtime.exec_main_status)
    }

    // ── execution security properties ─────────────────────────────────

    /// `NoNewPrivileges` — `PR_SET_NO_NEW_PRIVS` flag.
    #[zbus(property(emits_changed_signal = "const"))]
    fn no_new_privileges(&self) -> bool {
        self.section()
            .is_some_and(|service| service.no_new_privileges)
    }

    /// `PrivateTmp` — whether a private `/tmp` is set up.
    #[zbus(property(emits_changed_signal = "const"))]
    fn private_tmp(&self) -> bool {
        self.section().is_some_and(|service| service.private_tmp)
    }

    /// `PrivateTmpEx` — extended private `/tmp` mode.
    #[zbus(name = "PrivateTmpEx", property(emits_changed_signal = "const"))]
    fn private_tmp_ex(&self) -> String {
        self.section().map_or_else(
            || "no".into(),
            |service| {
                if service.private_tmp {
                    "connected".into()
                } else {
                    "no".into()
                }
            },
        )
    }

    /// `PrivateNetwork` — whether a private network namespace is used.
    #[zbus(property(emits_changed_signal = "const"))]
    fn private_network(&self) -> bool {
        self.section()
            .is_some_and(|service| service.private_network)
    }

    /// `PrivateDevices` — whether access to raw hardware devices is restricted.
    #[zbus(property(emits_changed_signal = "const"))]
    fn private_devices(&self) -> bool {
        self.section()
            .is_some_and(|service| service.private_devices)
    }

    /// `ProtectSystem` — filesystem protection level.
    #[zbus(property(emits_changed_signal = "const"))]
    fn protect_system(&self) -> String {
        self.section()
            .map(|service| protect_system_name(service.protect_system).to_owned())
            .unwrap_or_else(|| "no".into())
    }

    /// `ProtectHome` — protection level for `/home`, `/root`, `/run/user`.
    #[zbus(property(emits_changed_signal = "const"))]
    fn protect_home(&self) -> String {
        self.section()
            .map(|service| protect_home_name(service.protect_home).to_owned())
            .unwrap_or_else(|| "no".into())
    }

    /// `DynamicUser` — whether a dynamic UID/GID is allocated.
    #[zbus(property(emits_changed_signal = "const"))]
    fn dynamic_user(&self) -> bool {
        self.section().is_some_and(|service| service.dynamic_user)
    }

    /// `SetLoginEnvironment` — whether `$USER`/`$HOME` login variables are set.
    #[zbus(name = "SetLoginEnvironment", property(emits_changed_signal = "const"))]
    fn set_login_environment(&self) -> bool {
        self.section().is_some_and(|service| {
            service.dynamic_user || !service.user.is_empty() || !service.group.is_empty()
        })
    }

    /// `CapabilityBoundingSet` — bitmask of capabilities in the bounding set.
    #[zbus(property(emits_changed_signal = "const"))]
    fn capability_bounding_set(&self) -> u64 {
        self.section().map_or(u64::MAX, |service| {
            capability_mask(&service.capability_bounding_set, u64::MAX)
        })
    }

    /// `AmbientCapabilities` — bitmask of ambient capabilities.
    #[zbus(property(emits_changed_signal = "const"))]
    fn ambient_capabilities(&self) -> u64 {
        self.section().map_or(0, |service| {
            capability_mask(&service.ambient_capabilities, 0)
        })
    }

    /// `TTYPath` — configured terminal device path.
    #[zbus(name = "TTYPath", property(emits_changed_signal = "const"))]
    fn tty_path(&self) -> String {
        self.section()
            .map(|service| service.tty_path)
            .unwrap_or_default()
    }

    /// `TTYReset` — reset the terminal before service execution.
    #[zbus(name = "TTYReset", property(emits_changed_signal = "const"))]
    fn tty_reset(&self) -> bool {
        self.section().is_some_and(|service| service.tty_reset)
    }

    /// `TTYVHangup` — send a virtual-terminal hangup on shutdown.
    #[zbus(name = "TTYVHangup", property(emits_changed_signal = "const"))]
    fn tty_vhangup(&self) -> bool {
        self.section().is_some_and(|service| service.tty_vhangup)
    }

    /// `TTYVTDisallocate` — deallocate the virtual terminal on shutdown.
    #[zbus(name = "TTYVTDisallocate", property(emits_changed_signal = "const"))]
    fn tty_vt_disallocate(&self) -> bool {
        self.section()
            .is_some_and(|service| service.tty_vt_disallocate)
    }

    /// `TTYRows` — configured terminal rows, saturated to the v261 `q` wire type.
    #[zbus(name = "TTYRows", property(emits_changed_signal = "const"))]
    fn tty_rows(&self) -> u16 {
        self.section()
            .and_then(|service| service.tty_rows)
            .map_or(u16::MAX, |rows| {
                u16::try_from(rows.min(u32::from(u16::MAX))).unwrap_or(u16::MAX)
            })
    }

    /// `TTYColumns` — configured terminal columns, saturated to the v261 `q` wire type.
    #[zbus(name = "TTYColumns", property(emits_changed_signal = "const"))]
    fn tty_columns(&self) -> u16 {
        self.section()
            .and_then(|service| service.tty_columns)
            .map_or(u16::MAX, |columns| {
                u16::try_from(columns.min(u32::from(u16::MAX))).unwrap_or(u16::MAX)
            })
    }

    /// `UtmpIdentifier` — utmp record identifier.
    #[zbus(name = "UtmpIdentifier", property(emits_changed_signal = "const"))]
    fn utmp_identifier(&self) -> String {
        self.section()
            .map(|service| service.utmp_identifier)
            .unwrap_or_default()
    }

    /// `UtmpMode` — utmp record mode.
    #[zbus(name = "UtmpMode", property(emits_changed_signal = "const"))]
    fn utmp_mode(&self) -> String {
        self.section()
            .map(|service| service.utmp_mode)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "init".into())
    }

    /// `SyslogPriority` — combined syslog facility and level priority.
    #[zbus(name = "SyslogPriority", property(emits_changed_signal = "const"))]
    fn syslog_priority(&self) -> i32 {
        self.section().map_or(30, |service| {
            syslog_facility(&service.syslog_facility) * 8 + syslog_level(&service.syslog_level)
        })
    }

    /// `SyslogIdentifier` — identifier used for syslog records.
    #[zbus(name = "SyslogIdentifier", property(emits_changed_signal = "const"))]
    fn syslog_identifier(&self) -> String {
        self.section()
            .map(|service| service.syslog_identifier)
            .unwrap_or_default()
    }

    /// `SyslogLevelPrefix` — whether syslog records include their level prefix.
    #[zbus(name = "SyslogLevelPrefix", property(emits_changed_signal = "const"))]
    fn syslog_level_prefix(&self) -> bool {
        true
    }

    /// `SyslogLevel` — syslog severity level.
    #[zbus(name = "SyslogLevel", property(emits_changed_signal = "const"))]
    fn syslog_level(&self) -> i32 {
        self.section()
            .map_or(6, |service| syslog_level(&service.syslog_level))
    }

    /// `SyslogFacility` — syslog facility.
    #[zbus(name = "SyslogFacility", property(emits_changed_signal = "const"))]
    fn syslog_facility(&self) -> i32 {
        self.section()
            .map_or(3, |service| syslog_facility(&service.syslog_facility))
    }

    /// `LogLevelMax` — maximum log severity accepted by the service.
    #[zbus(name = "LogLevelMax", property(emits_changed_signal = "const"))]
    fn log_level_max(&self) -> i32 {
        self.section()
            .map_or(-1, |service| log_level_max(&service.log_level_max))
    }

    /// `LogRateLimitIntervalUSec` — per-service log rate-limit interval.
    #[zbus(
        name = "LogRateLimitIntervalUSec",
        property(emits_changed_signal = "const")
    )]
    fn log_rate_limit_interval_u_sec(&self) -> u64 {
        self.section()
            .and_then(|service| service.log_rate_limit_interval_sec)
            .map_or(0, duration_usec)
    }

    /// `LogRateLimitBurst` — per-service log rate-limit burst.
    #[zbus(name = "LogRateLimitBurst", property(emits_changed_signal = "const"))]
    fn log_rate_limit_burst(&self) -> u32 {
        self.section()
            .and_then(|service| service.log_rate_limit_burst)
            .unwrap_or(0)
    }

    /// `LogExtraFields` — additional fields attached to log records.
    #[zbus(name = "LogExtraFields", property(emits_changed_signal = "const"))]
    fn log_extra_fields(&self) -> Vec<Vec<u8>> {
        self.section()
            .map(|service| {
                service
                    .log_extra_fields
                    .into_iter()
                    .map(String::into_bytes)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// `LogNamespace` — journald namespace used by the service.
    #[zbus(name = "LogNamespace", property(emits_changed_signal = "const"))]
    fn log_namespace(&self) -> String {
        self.section()
            .map(|service| service.log_namespace)
            .unwrap_or_default()
    }

    /// `SecureBits` — Linux securebits mask.
    #[zbus(name = "SecureBits", property(emits_changed_signal = "const"))]
    fn secure_bits(&self) -> i32 {
        self.section()
            .map_or(0, |service| secure_bits(&service.secure_bits))
    }

    /// `CoredumpFilter` — process coredump memory filter.
    #[zbus(name = "CoredumpFilter", property(emits_changed_signal = "const"))]
    fn coredump_filter(&self) -> u64 {
        self.section()
            .map_or_else(default_coredump_filter, |service| {
                coredump_filter(&service.coredump_filter)
            })
    }

    /// `Personality` — execution personality override.
    #[zbus(name = "Personality", property(emits_changed_signal = "const"))]
    fn personality(&self) -> String {
        self.section()
            .map(|service| service.personality)
            .unwrap_or_default()
    }

    /// `Delegate` — whether the service may manage delegated cgroup state.
    #[zbus(name = "Delegate", property(emits_changed_signal = "const"))]
    fn delegate(&self) -> bool {
        self.section().is_some_and(|service| service.delegate)
    }

    #[zbus(name = "DelegateControllers", property(emits_changed_signal = "false"))]
    fn delegate_controllers(&self) -> Vec<String> {
        self.section()
            .map(|service| service.delegate_controllers)
            .unwrap_or_default()
    }

    #[zbus(name = "DelegateSubgroup", property(emits_changed_signal = "false"))]
    fn delegate_subgroup(&self) -> String {
        self.section()
            .map(|service| service.delegate_subgroup)
            .unwrap_or_default()
    }

    #[zbus(name = "DisableControllers", property(emits_changed_signal = "false"))]
    fn disable_controllers(&self) -> Vec<String> {
        self.section()
            .map(|service| service.disable_controllers)
            .unwrap_or_default()
    }

    #[zbus(name = "CPUSetPartition", property(emits_changed_signal = "false"))]
    fn cpuset_partition(&self) -> String {
        self.section()
            .map(|service| service.cpuset_partition)
            .unwrap_or_default()
    }

    #[zbus(name = "ManagedOOMSwap", property(emits_changed_signal = "false"))]
    fn managed_oom_swap(&self) -> String {
        self.section()
            .map(|service| service.managed_oom_swap)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "auto".to_owned())
    }

    #[zbus(
        name = "ManagedOOMMemoryPressure",
        property(emits_changed_signal = "false")
    )]
    fn managed_oom_memory_pressure(&self) -> String {
        self.section()
            .map(|service| service.managed_oom_memory_pressure)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "auto".to_owned())
    }

    #[zbus(
        name = "ManagedOOMMemoryPressureLimit",
        property(emits_changed_signal = "false")
    )]
    fn managed_oom_memory_pressure_limit(&self) -> u32 {
        self.section()
            .map_or(0, |service| service.managed_oom_memory_pressure_limit)
    }

    #[zbus(
        name = "ManagedOOMMemoryPressureDurationUSec",
        property(emits_changed_signal = "false")
    )]
    fn managed_oom_memory_pressure_duration_u_sec(&self) -> u64 {
        self.section()
            .and_then(|service| service.managed_oom_memory_pressure_duration_sec)
            .map(duration_usec)
            .unwrap_or(u64::MAX)
    }

    #[zbus(
        name = "ManagedOOMPreference",
        property(emits_changed_signal = "false")
    )]
    fn managed_oom_preference(&self) -> String {
        self.section()
            .map(|service| service.managed_oom_preference)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "none".to_owned())
    }

    #[zbus(name = "SameProcessGroup", property(emits_changed_signal = "const"))]
    fn same_process_group(&self) -> bool {
        self.section()
            .is_some_and(|service| service.same_process_group)
    }

    /// `MemoryDenyWriteExecute` — whether `W+X` memory mappings are denied.
    #[zbus(property(emits_changed_signal = "const"))]
    fn memory_deny_write_execute(&self) -> bool {
        self.section()
            .is_some_and(|service| service.memory_deny_write_execute)
    }

    #[zbus(name = "MountAPIVFS", property(emits_changed_signal = "const"))]
    fn mount_api_vfs(&self) -> bool {
        self.section().is_some_and(|service| service.mount_api_vfs)
    }

    #[zbus(name = "MountFlags", property(emits_changed_signal = "const"))]
    fn mount_flags(&self) -> u64 {
        self.section()
            .map(|service| service.mount_flags)
            .unwrap_or(0)
    }

    #[zbus(name = "BindLogSockets", property(emits_changed_signal = "const"))]
    fn bind_log_sockets(&self) -> bool {
        self.section()
            .is_some_and(|service| service.bind_log_sockets)
    }

    #[zbus(name = "MemoryKSM", property(emits_changed_signal = "const"))]
    fn memory_ksm(&self) -> bool {
        self.section().is_some_and(|service| service.memory_ksm)
    }

    #[zbus(name = "MemoryTHP", property(emits_changed_signal = "const"))]
    fn memory_thp(&self) -> String {
        self.section()
            .map(|service| service.memory_thp)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "inherit".into())
    }

    #[zbus(name = "UserNamespacePath", property(emits_changed_signal = "const"))]
    fn user_namespace_path(&self) -> String {
        self.section()
            .map(|service| service.user_namespace_path)
            .unwrap_or_default()
    }

    #[zbus(
        name = "NetworkNamespacePath",
        property(emits_changed_signal = "const")
    )]
    fn network_namespace_path(&self) -> String {
        self.section()
            .map(|service| service.network_namespace_path)
            .unwrap_or_default()
    }

    #[zbus(name = "IPCNamespacePath", property(emits_changed_signal = "const"))]
    fn ipc_namespace_path(&self) -> String {
        self.section()
            .map(|service| service.ipc_namespace_path)
            .unwrap_or_default()
    }

    /// `IgnoreSIGPIPE` — whether SIGPIPE is ignored for service processes.
    #[zbus(name = "IgnoreSIGPIPE", property(emits_changed_signal = "const"))]
    fn ignore_sigpipe(&self) -> bool {
        self.section().is_some_and(|service| service.ignore_sigpipe)
    }

    /// `RestrictRealtime` — whether real-time scheduling is restricted.
    #[zbus(property(emits_changed_signal = "const"))]
    fn restrict_realtime(&self) -> bool {
        self.section()
            .is_some_and(|service| service.restrict_realtime)
    }

    /// `RestrictNamespaces` — bitmask of denied namespace types.
    #[zbus(property(emits_changed_signal = "const"))]
    fn restrict_namespaces(&self) -> u64 {
        if self
            .section()
            .is_some_and(|service| service.restrict_namespaces)
        {
            RESTRICT_ALL_NAMESPACES
        } else {
            0
        }
    }

    /// `SELinuxContext` — optional `SELinux` execution context.
    #[zbus(name = "SELinuxContext", property(emits_changed_signal = "const"))]
    fn selinux_context(&self) -> (bool, String) {
        self.section()
            .map(|service| context_label(&service.se_linux_context))
            .unwrap_or((false, String::new()))
    }

    /// `AppArmorProfile` — optional `AppArmor` execution profile.
    #[zbus(name = "AppArmorProfile", property(emits_changed_signal = "const"))]
    fn apparmor_profile(&self) -> (bool, String) {
        self.section()
            .map(|service| context_label(&service.app_armor_profile))
            .unwrap_or((false, String::new()))
    }

    /// `SmackProcessLabel` — optional SMACK execution label.
    #[zbus(name = "SmackProcessLabel", property(emits_changed_signal = "const"))]
    fn smack_process_label(&self) -> (bool, String) {
        self.section()
            .map(|service| context_label(&service.smack_process_label))
            .unwrap_or((false, String::new()))
    }
}

fn duration_usec(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

fn limit_value(value: LimitValue) -> u64 {
    match value {
        LimitValue::Value(value) => value,
        LimitValue::Max => u64::MAX,
    }
}

fn cpu_quota_usec(value: CpuQuota) -> u64 {
    match value {
        CpuQuota::PercentHundredths(value) => value.saturating_mul(100),
        CpuQuota::Max => u64::MAX,
    }
}

fn rlimit_property(
    section: Option<ServiceSection>,
    select: fn(&ServiceSection) -> Option<RlimitSpec>,
    resource: libc::__rlimit_resource_t,
    soft: bool,
) -> u64 {
    if let Some(spec) = section.and_then(|section| select(&section)) {
        return rlimit_value(if soft { spec.soft } else { spec.hard });
    }
    let mut value = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let result = unsafe { libc::getrlimit(resource, &mut value) };
    if result != 0 {
        return u64::MAX;
    }
    let value = if soft { value.rlim_cur } else { value.rlim_max };
    if value == libc::RLIM_INFINITY {
        u64::MAX
    } else {
        value
    }
}

fn rlimit_value(value: RlimitValue) -> u64 {
    match value {
        RlimitValue::Value(value) => value,
        RlimitValue::Infinity => u64::MAX,
    }
}

/// Convert parsed commands to v261's `a(sasbttttuii)` property tuples.
///
/// The parser owns command argv and the ignore-failure bit. Runtime
/// timestamps/status are populated by the manager only after execution; a
/// command that has not run yet has the all-zero status tuple used by v261.
fn exec_command_properties(commands: &[ExecCommand]) -> Vec<ExecProperty> {
    commands
        .iter()
        .map(|command| {
            (
                command.path.clone(),
                command.argv.clone(),
                command.flags.contains(ExecFlags::IGNORE_FAILURE),
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            )
        })
        .collect()
}

fn exec_ex_command_properties(commands: &[ExecCommand]) -> Vec<ExecExProperty> {
    commands
        .iter()
        .map(|command| {
            let mut flags = Vec::new();
            if command.flags.contains(ExecFlags::IGNORE_FAILURE) {
                flags.push("ignore-failure".to_owned());
            }
            if command.flags.contains(ExecFlags::FULL_PRIVILEGES) {
                flags.push("privileged".to_owned());
            }
            if command.flags.contains(ExecFlags::NO_SETUID) {
                flags.push("no-setuid".to_owned());
            }
            if command.flags.contains(ExecFlags::NO_ENV_EXPAND) {
                flags.push("no-env-expand".to_owned());
            }
            if command.flags.contains(ExecFlags::VIA_SHELL) {
                flags.push("via-shell".to_owned());
            }
            (
                command.path.clone(),
                command.argv.clone(),
                flags,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            )
        })
        .collect()
}

fn context_label(value: &str) -> (bool, String) {
    value.strip_prefix('-').map_or_else(
        || (false, value.to_owned()),
        |label| (true, label.to_owned()),
    )
}

fn open_file_properties(values: &[String]) -> Vec<(String, String, u64)> {
    values
        .iter()
        .filter_map(|value| {
            let mut fields = value.splitn(3, ':');
            let path = fields.next()?.to_owned();
            if path.is_empty() {
                return None;
            }
            let fdname = fields.next().filter(|name| !name.is_empty()).map_or_else(
                || {
                    path.rsplit('/')
                        .next()
                        .filter(|name| !name.is_empty())
                        .unwrap_or("unknown")
                        .to_owned()
                },
                str::to_owned,
            );
            let flags = fields.next().map_or(0, |options| {
                options.split(',').fold(0u64, |flags, option| {
                    flags
                        | match option {
                            "read-only" => 1,
                            "append" => 1 << 1,
                            "truncate" => 1 << 2,
                            "graceful" => 1 << 3,
                            _ => 0,
                        }
                })
            });
            Some((path, fdname, flags))
        })
        .collect()
}

fn cpu_affinity_bitmap(value: &str) -> Vec<u8> {
    let mut cpus = Vec::new();
    for token in value.split_whitespace() {
        let Some((start, end)) = token.split_once('-') else {
            if let Ok(cpu) = token.parse::<usize>() {
                cpus.push(cpu);
            }
            continue;
        };
        let (Ok(start), Ok(end)) = (start.parse::<usize>(), end.parse::<usize>()) else {
            continue;
        };
        cpus.extend(start..=end);
    }
    let Some(max) = cpus.iter().copied().max() else {
        return Vec::new();
    };
    let mut bitmap = vec![0u8; max / 8 + 1];
    for cpu in cpus {
        bitmap[cpu / 8] |= 1 << (cpu % 8);
    }
    bitmap
}

fn string_policy_list(values: &[String]) -> (bool, Vec<String>) {
    let mut allow = true;
    let mut items = Vec::new();
    for value in values {
        if let Some(value) = value.strip_prefix('~') {
            allow = false;
            items.extend(value.split_whitespace().map(str::to_owned));
        } else {
            items.extend(value.split_whitespace().map(str::to_owned));
        }
    }
    (allow, items)
}

fn bind_path_properties(values: &[String], read_only: bool) -> Vec<(String, String, bool, u64)> {
    values
        .iter()
        .filter_map(|value| {
            let mut fields = value.split(':');
            let source = fields.next()?.to_owned();
            if source.is_empty() {
                return None;
            }
            let destination = fields.next().unwrap_or(&source).to_owned();
            Some((source, destination, read_only, 0))
        })
        .collect()
}

fn temporary_filesystem_properties(values: &[String]) -> Vec<(String, String)> {
    values
        .iter()
        .filter_map(|value| {
            let mut fields = value.splitn(2, ':');
            let path = fields.next()?.to_owned();
            if path.is_empty() {
                return None;
            }
            Some((path, fields.next().unwrap_or_default().to_owned()))
        })
        .collect()
}

fn ip_address_properties(values: &[String]) -> Vec<(i32, Vec<u8>, u32)> {
    values
        .iter()
        .filter_map(|value| {
            let value = value.trim();
            if value.eq_ignore_ascii_case("any") {
                return Some((libc::AF_UNSPEC, Vec::new(), 0));
            }
            let (address, prefix) = if let Some((address, prefix)) = value.split_once('/') {
                (address, Some(prefix.parse::<u32>().ok()?))
            } else {
                (value, None)
            };
            let address = address.parse::<std::net::IpAddr>().ok()?;
            match address {
                std::net::IpAddr::V4(address) => {
                    let prefix = prefix.unwrap_or(32);
                    (prefix <= 32).then_some((libc::AF_INET, address.octets().to_vec(), prefix))
                }
                std::net::IpAddr::V6(address) => {
                    let prefix = prefix.unwrap_or(128);
                    (prefix <= 128).then_some((libc::AF_INET6, address.octets().to_vec(), prefix))
                }
            }
        })
        .collect()
}

fn service_type_name(service_type: ServiceType) -> String {
    match service_type {
        ServiceType::Simple => "simple",
        ServiceType::Exec => "exec",
        ServiceType::Forking => "forking",
        ServiceType::Oneshot => "oneshot",
        ServiceType::Dbus => "dbus",
        ServiceType::Notify => "notify",
        ServiceType::NotifyReload => "notify-reload",
        ServiceType::Idle => "idle",
    }
    .to_owned()
}

fn restart_name(restart: RestartPolicy) -> String {
    match restart {
        RestartPolicy::No => "no",
        RestartPolicy::OnSuccess => "on-success",
        RestartPolicy::OnFailure => "on-failure",
        RestartPolicy::OnAbnormal => "on-abnormal",
        RestartPolicy::OnWatchdog => "on-watchdog",
        RestartPolicy::OnAbort => "on-abort",
        RestartPolicy::Always => "always",
    }
    .to_owned()
}

fn kill_mode_name(mode: KillMode) -> &'static str {
    match mode {
        KillMode::ControlGroup => "control-group",
        KillMode::Process => "process",
        KillMode::Mixed => "mixed",
        KillMode::None => "none",
    }
}

fn io_scheduling_class(value: &str) -> i32 {
    match value.trim().to_ascii_lowercase().as_str() {
        "realtime" => 1,
        "best-effort" => 2,
        "idle" => 3,
        _ => 0,
    }
}

fn cpu_scheduling_policy(value: &str) -> i32 {
    match value.trim().to_ascii_lowercase().as_str() {
        "fifo" => libc::SCHED_FIFO,
        "rr" => libc::SCHED_RR,
        "batch" => libc::SCHED_BATCH,
        "idle" => libc::SCHED_IDLE,
        "deadline" => libc::SCHED_DEADLINE,
        _ => libc::SCHED_OTHER,
    }
}

fn syslog_level(value: &str) -> i32 {
    match value.trim().to_ascii_lowercase().as_str() {
        "emerg" | "panic" => 0,
        "alert" => 1,
        "crit" | "critical" => 2,
        "err" | "error" => 3,
        "warning" | "warn" => 4,
        "notice" => 5,
        "info" => 6,
        "debug" => 7,
        value => value.parse().unwrap_or(6),
    }
}

fn syslog_facility(value: &str) -> i32 {
    match value.trim().to_ascii_lowercase().as_str() {
        "kern" | "kernel" => 0,
        "user" => 1,
        "mail" => 2,
        "daemon" => 3,
        "auth" => 4,
        "syslog" => 5,
        "lpr" => 6,
        "news" => 7,
        "uucp" => 8,
        "cron" => 9,
        "authpriv" => 10,
        "ftp" => 11,
        "local0" => 16,
        "local1" => 17,
        "local2" => 18,
        "local3" => 19,
        "local4" => 20,
        "local5" => 21,
        "local6" => 22,
        "local7" => 23,
        value => value.parse().unwrap_or(3),
    }
}

fn log_level_max(value: &str) -> i32 {
    let value = value.trim();
    if value.is_empty() || value.eq_ignore_ascii_case("max") {
        -1
    } else {
        syslog_level(value)
    }
}

fn secure_bits(values: &[String]) -> i32 {
    values.iter().fold(0, |bits, value| {
        bits | match value.as_str() {
            "keep-caps" => 1 << 4,
            "keep-caps-locked" => 1 << 5,
            "no-setuid-fixup" => 1 << 2,
            "no-setuid-fixup-locked" => 1 << 3,
            "noroot" => 1,
            "noroot-locked" => 1 << 1,
            _ => 0,
        }
    })
}

fn coredump_filter(value: &str) -> u64 {
    let value = value.trim().trim_start_matches("0x");
    if value.is_empty() {
        default_coredump_filter()
    } else {
        u64::from_str_radix(value, 16).unwrap_or_else(|_| default_coredump_filter())
    }
}

fn default_coredump_filter() -> u64 {
    std::fs::read_to_string("/proc/self/coredump_filter")
        .ok()
        .and_then(|value| u64::from_str_radix(value.trim().trim_start_matches("0x"), 16).ok())
        .unwrap_or(0x33)
}

fn syscall_error_number(value: &str) -> i32 {
    let value = value.trim();
    if value.is_empty() || value.eq_ignore_ascii_case("kill") {
        return 0;
    }
    crate::seccomp_policy::errno_number(value).unwrap_or(0)
}

fn address_family_list(values: &[String]) -> (bool, Vec<String>) {
    let mut allow = true;
    let mut families = Vec::new();
    for value in values {
        let value = value.trim();
        if let Some(value) = value.strip_prefix('~') {
            allow = false;
            families.extend(
                value
                    .split_whitespace()
                    .filter(|item| !item.is_empty())
                    .map(str::to_owned),
            );
        } else if !value.is_empty() {
            families.extend(value.split_whitespace().map(str::to_owned));
        }
    }
    (allow, families)
}

fn expand_syscall_name(name: &str, output: &mut Vec<String>) {
    if let Some(group) = crate::seccomp_groups::group(name) {
        for item in group {
            expand_syscall_name(item, output);
        }
    } else {
        output.push(name.to_owned());
    }
}

fn normalized_syscall_items(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut output = Vec::new();
    for value in values {
        let (name, suffix) = value
            .split_once(':')
            .map_or((value.as_str(), None), |(name, suffix)| {
                (name, Some(suffix))
            });
        let mut expanded = Vec::new();
        expand_syscall_name(name, &mut expanded);
        for item in expanded {
            output.push(match suffix {
                Some(suffix) => format!("{item}:{suffix}"),
                None => item,
            });
        }
    }
    output.sort_unstable();
    output.dedup();
    output
}

fn syscall_filter_list(
    assignments: &[crate::unit::section_service::SystemCallFilterAssignment],
) -> (bool, Vec<String>) {
    let allow = assignments
        .first()
        .map_or(true, |assignment| !assignment.invert);
    (
        allow,
        normalized_syscall_items(
            assignments
                .iter()
                .flat_map(|assignment| assignment.items.iter().cloned()),
        ),
    )
}

fn syscall_log_list(values: &[String]) -> (bool, Vec<String>) {
    let allow = !values
        .iter()
        .any(|value| value.trim() == "~" || value.trim_start().starts_with('~'));
    (
        allow,
        normalized_syscall_items(values.iter().filter_map(|value| {
            let value = value.trim();
            if value == "~" {
                None
            } else {
                Some(value.strip_prefix('~').unwrap_or(value).to_owned())
            }
        })),
    )
}

fn parse_exit_statuses(values: &[String]) -> (Vec<i32>, Vec<i32>) {
    let mut codes = Vec::new();
    let mut signals = Vec::new();
    for value in values {
        let value = value.trim();
        if let Ok(code) = value.parse::<u8>() {
            codes.push(i32::from(code));
            continue;
        }
        if let Some(code) = exit_status_name(value) {
            codes.push(code);
        } else if let Some(signal) = parse_signal(value) {
            signals.push(signal);
        }
    }
    (codes, signals)
}

fn exit_status_name(value: &str) -> Option<i32> {
    Some(match value {
        "SUCCESS" => 0,
        "FAILURE" => 1,
        "CHDIR" => 200,
        "NICE" => 201,
        "FDS" => 202,
        "EXEC" => 203,
        "MEMORY" => 204,
        "LIMITS" => 205,
        "OOM_ADJUST" => 206,
        "SIGNAL_MASK" => 207,
        "STDIN" => 208,
        "STDOUT" => 209,
        "CHROOT" => 210,
        "IOPRIO" => 211,
        "TIMERSLACK" => 212,
        "SECUREBITS" => 213,
        "SETSCHEDULER" => 214,
        "CPUAFFINITY" => 215,
        "GROUP" => 216,
        "USER" => 217,
        "CAPABILITIES" => 218,
        "CGROUP" => 219,
        "SETSID" => 220,
        "CONFIRM" => 221,
        "STDERR" => 222,
        "PAM" => 224,
        "NETWORK" => 225,
        "NAMESPACE" => 226,
        "NO_NEW_PRIVILEGES" => 227,
        "SECCOMP" => 228,
        "SELINUX_CONTEXT" => 229,
        "PERSONALITY" => 230,
        "APPARMOR" => 231,
        "ADDRESS_FAMILIES" => 232,
        "RUNTIME_DIRECTORY" => 233,
        "CHOWN" => 235,
        "SMACK_PROCESS_LABEL" => 236,
        "KEYRING" => 237,
        "STATE_DIRECTORY" => 238,
        "CACHE_DIRECTORY" => 239,
        "LOGS_DIRECTORY" => 240,
        "CONFIGURATION_DIRECTORY" => 241,
        "NUMA_POLICY" => 242,
        "CREDENTIALS" => 243,
        "BPF" => 244,
        "KSM" => 245,
        "MEMORY_THP" => 246,
        "EXCEPTION" => 255,
        "INVALIDARGUMENT" => 2,
        "NOTIMPLEMENTED" => 3,
        "NOPERMISSION" => 4,
        "NOTINSTALLED" => 5,
        "NOTCONFIGURED" => 6,
        "NOTRUNNING" => 7,
        "USAGE" => 64,
        "DATAERR" => 65,
        "NOINPUT" => 66,
        "NOUSER" => 67,
        "NOHOST" => 68,
        "UNAVAILABLE" => 69,
        "SOFTWARE" => 70,
        "OSERR" => 71,
        "OSFILE" => 72,
        "CANTCREAT" => 73,
        "IOERR" => 74,
        "TEMPFAIL" => 75,
        "PROTOCOL" => 76,
        "NOPERM" => 77,
        "CONFIG" => 78,
        _ => return None,
    })
}

fn parse_umask(value: &str) -> u32 {
    let value = value.trim();
    if value.is_empty() {
        return 0o022;
    }
    if value.chars().all(|character| character == '0') {
        return 0;
    }
    u32::from_str_radix(value.strip_prefix("0o").unwrap_or(value), 8).unwrap_or(0o022)
}

fn effective_notify_access(service: &ServiceSection) -> &'static str {
    match service.notify_access {
        NotifyAccess::Main => "main",
        NotifyAccess::Exec => "exec",
        NotifyAccess::All => "all",
        NotifyAccess::None
            if matches!(
                service.service_type,
                ServiceType::Notify | ServiceType::NotifyReload
            ) || service.watchdog_sec.is_some() =>
        {
            "main"
        }
        NotifyAccess::None => "none",
    }
}

fn protect_system_name(value: ProtectSystem) -> &'static str {
    match value {
        ProtectSystem::No => "no",
        ProtectSystem::Yes => "yes",
        ProtectSystem::Full => "full",
        ProtectSystem::Strict => "strict",
    }
}

fn protect_home_name(value: ProtectHome) -> &'static str {
    match value {
        ProtectHome::No => "no",
        ProtectHome::Yes => "yes",
        ProtectHome::ReadOnly => "read-only",
        ProtectHome::Tmpfs => "tmpfs",
    }
}

fn capability_mask(names: &[String], empty: u64) -> u64 {
    if names.is_empty() {
        return empty;
    }

    names.iter().fold(0, |mask, name| {
        let Ok(name) = CString::new(name.as_str()) else {
            return mask;
        };
        // Safety: the C string is valid for the duration of the call.
        let number = unsafe { crate::ffi::capability::rustd_capability_name_to_num(name.as_ptr()) };
        let Ok(number) = u32::try_from(number) else {
            return mask;
        };
        if number < u64::BITS {
            mask | (1u64 << number)
        } else {
            mask
        }
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, RwLock};

    fn make_snap(units: Vec<UnitInfo>) -> Arc<RwLock<Vec<UnitInfo>>> {
        Arc::new(RwLock::new(units))
    }

    fn make_unit(name: &str, stype: &str, restart: &str) -> UnitInfo {
        UnitInfo {
            name: name.into(),
            load_state: "loaded".into(),
            active_state: "active".into(),
            sub_state: "running".into(),
            description: "Test service".into(),
            main_pid: Some(1234),
            unit_type: "service".into(),
            service_type: Some(stype.into()),
            restart_policy: Some(restart.into()),
            service_runtime: Box::new(crate::ipc::ServiceRuntimeInfo {
                invocation_id: None,
                restart_count: 4,
                bus_name: None,
                control_pid: Some(5678),
                status_text: Some("ready".into()),
                status_errno: Some(5),
                watchdog_timestamp_ns: None,
                watchdog_timestamp_realtime_ns: None,
                exec_main_start_realtime_ns: None,
                exec_main_start_monotonic_ns: None,
                exec_main_exit_realtime_ns: None,
                exec_main_exit_monotonic_ns: None,
                result: "signal".into(),
                exec_main_code: libc::CLD_KILLED,
                exec_main_status: libc::SIGTERM,
                dynamic_user: None,
                file_descriptor_store_max: 0,
            }),
        }
    }

    #[test]
    fn service_type_from_snapshot() {
        let snap = make_snap(vec![make_unit("foo.service", "notify", "on-failure")]);
        let iface = ServiceInterface {
            name: "foo.service".into(),
            snapshot: snap,
            scope: ManagerScope::System,
            unit_defaults: Arc::new(RwLock::new(UnitDefaults::default())),
        };
        assert_eq!(iface.service_type(), "notify");
        assert_eq!(iface.restart(), "on-failure");
        assert_eq!(iface.n_restarts(), 4);
        assert_eq!(iface.control_pid(), 5678);
        assert_eq!(iface.status_text(), "ready");
        assert_eq!(iface.status_errno(), 5);
        assert_eq!(iface.result(), "signal");
        assert_eq!(iface.exec_main_code(), libc::CLD_KILLED);
        assert_eq!(iface.exec_main_status(), libc::SIGTERM);
    }

    #[test]
    fn missing_unit_returns_defaults() {
        let snap = make_snap(vec![]);
        let iface = ServiceInterface {
            name: "missing.service".into(),
            snapshot: snap,
            scope: ManagerScope::System,
            unit_defaults: Arc::new(RwLock::new(UnitDefaults::default())),
        };
        assert_eq!(iface.service_type(), "simple");
        assert_eq!(iface.restart(), "no");
        assert_eq!(iface.main_pid(), 0u32);
        assert!(!iface.dynamic_user());
        assert_eq!(iface.capability_bounding_set(), u64::MAX);
    }

    #[test]
    fn duration_is_reported_in_microseconds() {
        assert_eq!(duration_usec(Duration::from_millis(1500)), 1_500_000);
    }

    #[test]
    fn open_file_properties_match_v261_flag_bits_and_defaults() {
        assert_eq!(
            open_file_properties(&[
                "/etc/example.conf:name:read-only".into(),
                "/var/log/example.log::append,graceful".into(),
            ]),
            vec![
                ("/etc/example.conf".into(), "name".into(), 1),
                ("/var/log/example.log".into(), "example.log".into(), 10),
            ]
        );
        assert!(open_file_properties(&[]).is_empty());
    }

    #[test]
    fn service_context_properties_match_v261_wire_helpers() {
        let command = ExecCommand {
            path: "/usr/bin/example".into(),
            argv: vec!["/usr/bin/example".into(), "--flag".into()],
            flags: ExecFlags::IGNORE_FAILURE,
        };
        assert_eq!(
            exec_command_properties(&[command]),
            vec![(
                "/usr/bin/example".into(),
                vec!["/usr/bin/example".into(), "--flag".into()],
                true,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            )]
        );
        assert_eq!(cpu_affinity_bitmap("0 2-3"), vec![0b0000_1101]);
        assert_eq!(
            context_label("system_u:system_r:daemon_t:s0"),
            (false, "system_u:system_r:daemon_t:s0".into())
        );
        assert_eq!(
            context_label("-profile-name"),
            (true, "profile-name".into())
        );
        assert_eq!(
            string_policy_list(&["~ext4 tmpfs".into()]),
            (false, vec!["ext4".to_owned(), "tmpfs".to_owned()])
        );
        assert_eq!(
            bind_path_properties(&["/src:/dest".into()], false),
            vec![("/src".into(), "/dest".into(), false, 0)]
        );
        assert_eq!(
            bind_path_properties(&["/src".into()], true),
            vec![("/src".into(), "/src".into(), true, 0)]
        );
        assert_eq!(
            temporary_filesystem_properties(&["/var:ro".into()]),
            vec![("/var".into(), "ro".into())]
        );
        assert_eq!(
            ip_address_properties(&["192.0.2.1".into(), "2001:db8::/32".into(), "any".into()]),
            vec![
                (libc::AF_INET, vec![192, 0, 2, 1], 32),
                (
                    libc::AF_INET6,
                    "2001:db8::"
                        .parse::<std::net::Ipv6Addr>()
                        .unwrap()
                        .octets()
                        .to_vec(),
                    32
                ),
                (libc::AF_UNSPEC, Vec::new(), 0),
            ]
        );
        assert!(ip_address_properties(&["192.0.2.1/not-a-prefix".into()]).is_empty());
    }

    #[test]
    fn effective_notify_access_promotes_notify_services() {
        let service = ServiceSection {
            service_type: ServiceType::Notify,
            ..Default::default()
        };
        assert_eq!(effective_notify_access(&service), "main");
    }

    #[test]
    fn capability_mask_handles_known_names() {
        let mask = capability_mask(&["CAP_CHOWN".into()], 0);
        assert_eq!(mask & 1, 1);
    }

    #[test]
    fn syscall_policy_properties_expand_groups_and_preserve_modes() {
        let assignments = vec![crate::unit::section_service::SystemCallFilterAssignment {
            invert: false,
            items: vec!["@basic-io".into(), "read".into()],
        }];
        let (allow, values) = syscall_filter_list(&assignments);
        assert!(allow);
        assert!(values.contains(&"read".to_owned()));
        assert!(values.contains(&"write".to_owned()));
        assert_eq!(values.iter().filter(|value| *value == "read").count(), 1);

        let (allow, values) = syscall_log_list(&["~read".into(), "write".into()]);
        assert!(!allow);
        assert_eq!(values, vec!["read", "write"]);
    }

    #[test]
    fn exit_status_properties_separate_codes_and_signals_like_v261() {
        let values = [
            "0".to_owned(),
            "FAILURE".to_owned(),
            "CHOWN".to_owned(),
            "SIGTERM".to_owned(),
            "RTMIN+1".to_owned(),
            "256".to_owned(),
            "not-a-status".to_owned(),
        ];
        assert_eq!(
            parse_exit_statuses(&values),
            (vec![0, 1, 235], vec![libc::SIGTERM, libc::SIGRTMIN() + 1])
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn service_timing_and_identity_properties_match_v261_defaults() {
        let snap = make_snap(vec![]);
        let iface = ServiceInterface {
            name: "missing.service".into(),
            snapshot: snap,
            scope: ManagerScope::System,
            unit_defaults: Arc::new(RwLock::new(UnitDefaults::default())),
        };

        assert_eq!(iface.pid_file(), "");
        assert_eq!(iface.bus_name(), "");
        assert_eq!(iface.exit_type(), "main");
        assert_eq!(iface.restart_mode(), "normal");
        assert_eq!(iface.restart_u_sec(), 100_000);
        assert_eq!(iface.restart_steps(), 0);
        assert_eq!(iface.restart_max_delay_u_sec(), u64::MAX);
        assert_eq!(iface.restart_u_sec_next(), 0);
        assert_eq!(iface.uid(), u32::MAX);
        assert_eq!(iface.gid(), u32::MAX);
        assert_eq!(iface.timeout_abort_u_sec(), DEFAULT_TIMEOUT_USEC);
        assert_eq!(iface.timeout_start_failure_mode(), "terminate");
        assert_eq!(iface.timeout_stop_failure_mode(), "terminate");
        assert_eq!(iface.runtime_max_u_sec(), u64::MAX);
        assert_eq!(iface.runtime_randomized_extra_u_sec(), 0);
        assert!(!iface.root_directory_start_only());
        assert!(iface.guess_main_pid());
        assert_eq!(iface.file_descriptor_store_max(), 0);
        assert_eq!(iface.n_file_descriptor_store(), 0);
        assert!(iface.open_file().is_empty());
        assert!(iface.refresh_on_reload().is_empty());
        assert_eq!(iface.status_bus_error(), "");
        assert_eq!(iface.status_varlink_error(), "");
        assert_eq!(iface.reload_result(), "success");
        assert_eq!(iface.clean_result(), "success");
        assert_eq!(iface.live_mount_result(), "success");
        assert_eq!(iface.file_descriptor_store_preserve(), "restart");
        assert_eq!(iface.root_directory(), "");
        assert!(iface.environment().is_empty());
        assert!(iface.environment_files().is_empty());
        assert!(iface.import_credential().is_empty());
        assert!(!iface.set_login_environment());
        assert!(iface.pass_environment().is_empty());
        assert!(iface.unset_environment().is_empty());
        assert!(iface.supplementary_groups().is_empty());
        assert_eq!(iface.pam_name(), "");
        assert_eq!(iface.nice(), 0);
        assert_eq!(iface.oom_score_adjust(), 0);
        assert_eq!(iface.io_scheduling_class(), 0);
        assert_eq!(iface.io_scheduling_priority(), 0);
        assert_eq!(iface.cpu_scheduling_policy(), libc::SCHED_OTHER);
        assert_eq!(iface.cpu_scheduling_priority(), 0);
        assert!(!iface.cpu_scheduling_reset_on_fork());
        assert!(iface.cpu_affinity().is_empty());
        assert!(iface.runtime_directory().is_empty());
        assert!(iface.state_directory().is_empty());
        assert!(iface.cache_directory().is_empty());
        assert!(iface.logs_directory().is_empty());
        assert!(iface.configuration_directory().is_empty());
        assert!(iface.read_write_paths().is_empty());
        assert!(iface.read_only_paths().is_empty());
        assert!(iface.inaccessible_paths().is_empty());
        assert!(iface.exec_paths().is_empty());
        assert!(iface.no_exec_paths().is_empty());
        assert_eq!(iface.restrict_file_systems(), (true, Vec::new()));
        assert!(iface.bind_paths().is_empty());
        assert!(iface.bind_read_only_paths().is_empty());
        assert!(iface.temporary_file_system().is_empty());
        assert!(iface.system_call_architectures().is_empty());
        assert_eq!(iface.system_call_error_number(), 0);
        assert_eq!(iface.restrict_address_families(), (true, Vec::new()));
        assert!(iface.ip_address_allow().is_empty());
        assert!(iface.ip_address_deny().is_empty());
        assert!(iface.exec_condition().is_empty());
        assert!(iface.exec_condition_ex().is_empty());
        assert!(iface.exec_search_path().is_empty());
        assert!(iface.exec_start_pre().is_empty());
        assert!(iface.exec_start_pre_ex().is_empty());
        assert!(iface.exec_start().is_empty());
        assert!(iface.exec_start_ex().is_empty());
        assert!(iface.exec_start_post().is_empty());
        assert!(iface.exec_start_post_ex().is_empty());
        assert!(iface.exec_reload().is_empty());
        assert!(iface.exec_reload_ex().is_empty());
        assert!(iface.exec_reload_post().is_empty());
        assert!(iface.exec_reload_post_ex().is_empty());
        assert!(iface.exec_stop().is_empty());
        assert!(iface.exec_stop_ex().is_empty());
        assert!(iface.exec_stop_post().is_empty());
        assert!(iface.exec_stop_post_ex().is_empty());
        assert_eq!(iface.system_call_filter(), (false, Vec::new()));
        assert_eq!(iface.system_call_log(), (false, Vec::new()));
        assert_eq!(iface.device_policy(), "auto");
        assert!(iface.device_allow().is_empty());
        assert_eq!(iface.slice(), "system.slice");
        assert_eq!(iface.cpu_weight(), u64::MAX);
        assert_eq!(iface.cpu_quota_per_sec_u_sec(), u64::MAX);
        assert_eq!(iface.cpu_quota_period_u_sec(), u64::MAX);
        assert_eq!(iface.io_weight(), u64::MAX);
        assert_eq!(iface.memory_min(), u64::MAX);
        assert_eq!(iface.memory_low(), u64::MAX);
        assert_eq!(iface.memory_high(), u64::MAX);
        assert_eq!(iface.memory_max(), u64::MAX);
        assert_eq!(iface.memory_swap_max(), u64::MAX);
        assert_eq!(iface.tasks_max(), u64::MAX);
        assert!(!iface.io_accounting());
        assert!(!iface.memory_accounting());
        assert!(!iface.tasks_accounting());
        assert!(!iface.ip_accounting());
        assert_eq!(iface.effective_memory_max(), u64::MAX);
        assert_eq!(iface.effective_memory_high(), u64::MAX);
        assert_eq!(iface.effective_tasks_max(), u64::MAX);
        assert_eq!(iface.io_read_bytes(), u64::MAX);
        assert_eq!(iface.io_read_operations(), u64::MAX);
        assert_eq!(iface.io_write_bytes(), u64::MAX);
        assert_eq!(iface.io_write_operations(), u64::MAX);
        assert_eq!(
            iface.limit_cpu(),
            rlimit_property(None, |_| None, libc::RLIMIT_CPU, false)
        );
        assert_eq!(
            iface.limit_nofile_soft(),
            rlimit_property(None, |_| None, libc::RLIMIT_NOFILE, true)
        );
        assert_eq!(iface.tty_path(), "");
        assert_eq!(iface.syslog_priority(), 30);
        assert_eq!(iface.syslog_identifier(), "");
        assert!(iface.syslog_level_prefix());
        assert_eq!(iface.syslog_level(), 6);
        assert_eq!(iface.syslog_facility(), 3);
        assert_eq!(iface.log_level_max(), -1);
        assert_eq!(iface.log_rate_limit_interval_u_sec(), 0);
        assert_eq!(iface.log_rate_limit_burst(), 0);
        assert!(iface.log_extra_fields().is_empty());
        assert_eq!(iface.log_namespace(), "");
        assert_eq!(iface.secure_bits(), 0);
        assert_eq!(iface.coredump_filter(), default_coredump_filter());
        assert_eq!(iface.personality(), "");
        assert!(!iface.delegate());
        assert!(iface.delegate_controllers().is_empty());
        assert_eq!(iface.delegate_subgroup(), "");
        assert!(iface.disable_controllers().is_empty());
        assert_eq!(iface.cpuset_partition(), "");
        assert!(!iface.ignore_sigpipe());
        assert!(!iface.private_ipc());
        assert_eq!(iface.private_pids(), "no");
        assert_eq!(iface.private_tmp_ex(), "no");
        assert_eq!(iface.private_users_ex(), "no");
        assert!(!iface.protect_hostname());
        assert_eq!(iface.protect_hostname_ex(), ("no".into(), String::new()));
        assert_eq!(iface.protect_control_groups_ex(), "no");
        assert_eq!(iface.protect_proc(), "default");
        assert_eq!(iface.proc_subset(), "all");
        assert!(!iface.mount_api_vfs());
        assert_eq!(iface.mount_flags(), 0);
        assert!(!iface.bind_log_sockets());
        assert!(!iface.memory_ksm());
        assert_eq!(iface.memory_thp(), "inherit");
        assert_eq!(iface.user_namespace_path(), "");
        assert_eq!(iface.network_namespace_path(), "");
        assert_eq!(iface.ipc_namespace_path(), "");
        assert_eq!(iface.user(), "");
        assert_eq!(iface.group(), "");
        assert_eq!(iface.working_directory(), "");
        assert_eq!(iface.standard_input(), "null");
        assert_eq!(iface.standard_output(), "journal");
        assert_eq!(iface.standard_error(), "inherit");
        assert!(!iface.tty_reset());
        assert!(!iface.tty_vhangup());
        assert!(!iface.tty_vt_disallocate());
        assert_eq!(iface.tty_rows(), u16::MAX);
        assert_eq!(iface.tty_columns(), u16::MAX);
        assert_eq!(iface.utmp_identifier(), "");
        assert_eq!(iface.utmp_mode(), "init");
        assert_eq!(iface.watchdog_timestamp_monotonic(), 0);
        assert_eq!(iface.watchdog_timestamp(), 0);
        assert_eq!(iface.control_group(), "");
        assert_eq!(iface.control_group_id(), 0);
        assert_eq!(iface.memory_current(), u64::MAX);
        assert_eq!(iface.memory_peak(), u64::MAX);
        assert_eq!(iface.memory_swap_current(), u64::MAX);
        assert_eq!(iface.memory_swap_peak(), u64::MAX);
        assert_eq!(iface.memory_zswap_current(), u64::MAX);
        assert!(iface.memory_available() > 0);
        assert!(iface.effective_cpus().is_empty());
        assert!(iface.effective_memory_nodes().is_empty());
        assert_eq!(iface.cpu_usage_nsec(), u64::MAX);
        assert_eq!(iface.tasks_current(), u64::MAX);
        assert_eq!(iface.oom_kills(), u64::MAX);
        assert_eq!(iface.managed_oom_kills(), u64::MAX);
        assert_eq!(iface.managed_oom_swap(), "auto");
        assert_eq!(iface.managed_oom_memory_pressure(), "auto");
        assert_eq!(iface.managed_oom_memory_pressure_limit(), 0);
        assert_eq!(iface.managed_oom_memory_pressure_duration_u_sec(), u64::MAX);
        assert_eq!(iface.managed_oom_preference(), "none");
        assert_eq!(iface.memory_zswap_max(), u64::MAX);
        assert!(iface.memory_zswap_writeback());
        assert_eq!(iface.timer_slack_nsec(), 50_000);
        assert!(!iface.same_process_group());
        assert_eq!(iface.exec_main_start_timestamp(), 0);
        assert_eq!(iface.exec_main_start_timestamp_monotonic(), 0);
        assert_eq!(iface.exec_main_exit_timestamp(), 0);
        assert_eq!(iface.exec_main_exit_timestamp_monotonic(), 0);
        assert_eq!(iface.exec_main_pid(), 0);
        assert_eq!(iface.runtime_directory_mode(), 0o755);
        assert_eq!(iface.runtime_directory_preserve(), "no");
        assert_eq!(iface.state_directory_mode(), 0o755);
        assert_eq!(iface.cache_directory_mode(), 0o755);
        assert_eq!(iface.logs_directory_mode(), 0o755);
        assert_eq!(iface.configuration_directory_mode(), 0o755);
        assert_eq!(iface.kill_mode(), "control-group");
        assert_eq!(iface.kill_signal(), libc::SIGTERM);
        assert_eq!(iface.restart_kill_signal(), libc::SIGTERM);
        assert_eq!(iface.final_kill_signal(), libc::SIGKILL);
        assert_eq!(iface.watchdog_signal(), libc::SIGABRT);
        assert!(iface.send_sigkill());
        assert!(!iface.send_sighup());
        assert_eq!(iface.reload_signal(), libc::SIGHUP);
        assert_eq!(iface.timeout_clean_u_sec(), u64::MAX);
        assert_eq!(iface.umask(), 0o022);
        assert_eq!(iface.oom_policy(), "stop");
        assert_eq!(iface.keyring_mode(), "private");
        assert_eq!(iface.selinux_context(), (false, String::new()));
        assert_eq!(iface.apparmor_profile(), (false, String::new()));
        assert_eq!(iface.smack_process_label(), (false, String::new()));

        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&iface, &mut xml, 0);
        for (name, signature, emits) in [
            ("ExitType", "s", "const"),
            ("RestartMode", "s", "const"),
            ("RestartPreventExitStatus", "(aiai)", "const"),
            ("RestartForceExitStatus", "(aiai)", "const"),
            ("SuccessExitStatus", "(aiai)", "const"),
            ("NFileDescriptorStore", "u", "false"),
            ("StatusBusError", "s", "true"),
            ("StatusVarlinkError", "s", "true"),
            ("ReloadResult", "s", "true"),
            ("CleanResult", "s", "true"),
            ("LiveMountResult", "s", "true"),
            ("Environment", "as", "const"),
            ("EnvironmentFiles", "a(sb)", "const"),
            ("ImportCredential", "as", "const"),
            ("SetLoginEnvironment", "b", "const"),
            ("SELinuxContext", "(bs)", "const"),
            ("AppArmorProfile", "(bs)", "const"),
            ("SmackProcessLabel", "(bs)", "const"),
            ("PassEnvironment", "as", "const"),
            ("UnsetEnvironment", "as", "const"),
            ("SupplementaryGroups", "as", "const"),
            ("PAMName", "s", "const"),
            ("Nice", "i", "const"),
            ("OOMScoreAdjust", "i", "const"),
            ("IOSchedulingClass", "i", "const"),
            ("IOSchedulingPriority", "i", "const"),
            ("CPUSchedulingPolicy", "i", "const"),
            ("CPUSchedulingPriority", "i", "const"),
            ("CPUSchedulingResetOnFork", "b", "const"),
            ("CPUAffinity", "ay", "const"),
            ("RuntimeDirectory", "as", "const"),
            ("RuntimeDirectoryMode", "u", "const"),
            ("RuntimeDirectoryPreserve", "s", "const"),
            ("StateDirectory", "as", "const"),
            ("StateDirectoryMode", "u", "const"),
            ("CacheDirectory", "as", "const"),
            ("CacheDirectoryMode", "u", "const"),
            ("LogsDirectory", "as", "const"),
            ("LogsDirectoryMode", "u", "const"),
            ("ConfigurationDirectory", "as", "const"),
            ("ConfigurationDirectoryMode", "u", "const"),
            ("ReadWritePaths", "as", "const"),
            ("ReadOnlyPaths", "as", "const"),
            ("InaccessiblePaths", "as", "const"),
            ("ExecPaths", "as", "const"),
            ("NoExecPaths", "as", "const"),
            ("ExecSearchPath", "as", "const"),
            ("RestrictFileSystems", "(bas)", "const"),
            ("BindPaths", "a(ssbt)", "const"),
            ("BindReadOnlyPaths", "a(ssbt)", "const"),
            ("TemporaryFileSystem", "a(ss)", "const"),
            ("SystemCallArchitectures", "as", "const"),
            ("SystemCallErrorNumber", "i", "const"),
            ("RestrictAddressFamilies", "(bas)", "const"),
            ("IPAddressAllow", "a(iayu)", "false"),
            ("IPAddressDeny", "a(iayu)", "false"),
            ("ExecCondition", "a(sasbttttuii)", "invalidates"),
            ("ExecConditionEx", "a(sasasttttuii)", "invalidates"),
            ("ExecStartPre", "a(sasbttttuii)", "invalidates"),
            ("ExecStartPreEx", "a(sasasttttuii)", "invalidates"),
            ("ExecStart", "a(sasbttttuii)", "invalidates"),
            ("ExecStartEx", "a(sasasttttuii)", "invalidates"),
            ("ExecStartPost", "a(sasbttttuii)", "invalidates"),
            ("ExecStartPostEx", "a(sasasttttuii)", "invalidates"),
            ("ExecReload", "a(sasbttttuii)", "invalidates"),
            ("ExecReloadEx", "a(sasasttttuii)", "invalidates"),
            ("ExecReloadPost", "a(sasbttttuii)", "invalidates"),
            ("ExecReloadPostEx", "a(sasasttttuii)", "invalidates"),
            ("ExecStop", "a(sasbttttuii)", "invalidates"),
            ("ExecStopEx", "a(sasasttttuii)", "invalidates"),
            ("ExecStopPost", "a(sasbttttuii)", "invalidates"),
            ("ExecStopPostEx", "a(sasasttttuii)", "invalidates"),
            ("SystemCallFilter", "(bas)", "const"),
            ("SystemCallLog", "(bas)", "const"),
            ("DevicePolicy", "s", "false"),
            ("DeviceAllow", "a(ss)", "false"),
            ("Slice", "s", "false"),
            ("CPUWeight", "t", "true"),
            ("CPUQuotaPerSecUSec", "t", "true"),
            ("CPUQuotaPeriodUSec", "t", "true"),
            ("IOWeight", "t", "true"),
            ("MemoryMin", "t", "true"),
            ("MemoryLow", "t", "true"),
            ("MemoryHigh", "t", "true"),
            ("MemoryMax", "t", "true"),
            ("MemorySwapMax", "t", "true"),
            ("MemoryZSwapMax", "t", "false"),
            ("MemoryZSwapWriteback", "b", "false"),
            ("TasksMax", "t", "true"),
            ("IOAccounting", "b", "false"),
            ("MemoryAccounting", "b", "false"),
            ("TasksAccounting", "b", "false"),
            ("IPAccounting", "b", "false"),
            ("LimitCPU", "t", "const"),
            ("LimitCPUSoft", "t", "const"),
            ("LimitFSIZE", "t", "const"),
            ("LimitFSIZESoft", "t", "const"),
            ("LimitDATA", "t", "const"),
            ("LimitDATASoft", "t", "const"),
            ("LimitSTACK", "t", "const"),
            ("LimitSTACKSoft", "t", "const"),
            ("LimitCORE", "t", "const"),
            ("LimitCORESoft", "t", "const"),
            ("LimitRSS", "t", "const"),
            ("LimitRSSSoft", "t", "const"),
            ("LimitNOFILE", "t", "const"),
            ("LimitNOFILESoft", "t", "const"),
            ("LimitAS", "t", "const"),
            ("LimitASSoft", "t", "const"),
            ("LimitNPROC", "t", "const"),
            ("LimitNPROCSoft", "t", "const"),
            ("LimitMEMLOCK", "t", "const"),
            ("LimitMEMLOCKSoft", "t", "const"),
            ("LimitLOCKS", "t", "const"),
            ("LimitLOCKSSoft", "t", "const"),
            ("LimitSIGPENDING", "t", "const"),
            ("LimitSIGPENDINGSoft", "t", "const"),
            ("LimitMSGQUEUE", "t", "const"),
            ("LimitMSGQUEUESoft", "t", "const"),
            ("LimitNICE", "t", "const"),
            ("LimitNICESoft", "t", "const"),
            ("LimitRTPRIO", "t", "const"),
            ("LimitRTPRIOSoft", "t", "const"),
            ("LimitRTTIME", "t", "const"),
            ("LimitRTTIMESoft", "t", "const"),
            ("TTYPath", "s", "const"),
            ("TTYReset", "b", "const"),
            ("TTYVHangup", "b", "const"),
            ("TTYVTDisallocate", "b", "const"),
            ("TTYRows", "q", "const"),
            ("TTYColumns", "q", "const"),
            ("UtmpIdentifier", "s", "const"),
            ("UtmpMode", "s", "const"),
            ("SyslogPriority", "i", "const"),
            ("SyslogIdentifier", "s", "const"),
            ("SyslogLevelPrefix", "b", "const"),
            ("SyslogLevel", "i", "const"),
            ("SyslogFacility", "i", "const"),
            ("LogLevelMax", "i", "const"),
            ("LogRateLimitIntervalUSec", "t", "const"),
            ("LogRateLimitBurst", "u", "const"),
            ("LogExtraFields", "aay", "const"),
            ("LogNamespace", "s", "const"),
            ("SecureBits", "i", "const"),
            ("CoredumpFilter", "t", "const"),
            ("Personality", "s", "const"),
            ("Delegate", "b", "const"),
            ("DelegateControllers", "as", "false"),
            ("DelegateSubgroup", "s", "false"),
            ("CPUSetPartition", "s", "false"),
            ("DisableControllers", "as", "false"),
            ("ManagedOOMSwap", "s", "false"),
            ("ManagedOOMMemoryPressure", "s", "false"),
            ("ManagedOOMMemoryPressureLimit", "u", "false"),
            ("ManagedOOMMemoryPressureDurationUSec", "t", "false"),
            ("ManagedOOMPreference", "s", "false"),
            ("PrivateIPC", "b", "const"),
            ("PrivatePIDs", "s", "const"),
            ("PrivateTmpEx", "s", "const"),
            ("PrivateUsersEx", "s", "const"),
            ("ProtectHostname", "b", "const"),
            ("ProtectHostnameEx", "(ss)", "const"),
            ("ProtectProc", "s", "const"),
            ("ProcSubset", "s", "const"),
            ("MountAPIVFS", "b", "const"),
            ("MountFlags", "t", "const"),
            ("BindLogSockets", "b", "const"),
            ("MemoryKSM", "b", "const"),
            ("MemoryTHP", "s", "const"),
            ("UserNamespacePath", "s", "const"),
            ("NetworkNamespacePath", "s", "const"),
            ("IPCNamespacePath", "s", "const"),
            ("IgnoreSIGPIPE", "b", "const"),
            ("PIDFile", "s", "const"),
            ("BusName", "s", "const"),
            ("RestartUSec", "t", "const"),
            ("RestartSteps", "u", "const"),
            ("RestartMaxDelayUSec", "t", "const"),
            ("RestartUSecNext", "t", "false"),
            ("UID", "u", "true"),
            ("GID", "u", "true"),
            ("TimeoutAbortUSec", "t", "false"),
            ("TimeoutStartFailureMode", "s", "const"),
            ("TimeoutStopFailureMode", "s", "const"),
            ("RuntimeMaxUSec", "t", "const"),
            ("RuntimeRandomizedExtraUSec", "t", "const"),
            ("RootDirectoryStartOnly", "b", "const"),
            ("GuessMainPID", "b", "const"),
            ("FileDescriptorStoreMax", "u", "const"),
            ("FileDescriptorStorePreserve", "s", "true"),
            ("OpenFile", "a(sst)", "const"),
            ("RefreshOnReload", "as", "const"),
            ("RootDirectory", "s", "const"),
            ("User", "s", "const"),
            ("Group", "s", "const"),
            ("WorkingDirectory", "s", "const"),
            ("StandardInput", "s", "const"),
            ("StandardOutput", "s", "const"),
            ("StandardError", "s", "const"),
            ("PrivateUsers", "b", "const"),
            ("PrivateMounts", "b", "const"),
            ("ProtectKernelTunables", "b", "const"),
            ("ProtectKernelModules", "b", "const"),
            ("ProtectKernelLogs", "b", "const"),
            ("ProtectClock", "b", "const"),
            ("ProtectControlGroups", "b", "const"),
            ("ProtectControlGroupsEx", "s", "const"),
            ("RestrictSUIDSGID", "b", "const"),
            ("LockPersonality", "b", "const"),
            ("RemoveIPC", "b", "const"),
            ("NonBlocking", "b", "const"),
            ("KillMode", "s", "const"),
            ("KillSignal", "i", "const"),
            ("RestartKillSignal", "i", "const"),
            ("FinalKillSignal", "i", "const"),
            ("WatchdogSignal", "i", "const"),
            ("WatchdogTimestampMonotonic", "t", "false"),
            ("WatchdogTimestamp", "t", "false"),
            ("ControlGroup", "s", "false"),
            ("ControlGroupId", "t", "false"),
            ("MemoryCurrent", "t", "false"),
            ("MemoryPeak", "t", "false"),
            ("MemorySwapCurrent", "t", "false"),
            ("MemorySwapPeak", "t", "false"),
            ("MemoryZSwapCurrent", "t", "false"),
            ("MemoryAvailable", "t", "false"),
            ("EffectiveMemoryMax", "t", "false"),
            ("EffectiveMemoryHigh", "t", "false"),
            ("IOReadBytes", "t", "false"),
            ("IOReadOperations", "t", "false"),
            ("IOWriteBytes", "t", "false"),
            ("IOWriteOperations", "t", "false"),
            ("EffectiveCPUs", "ay", "false"),
            ("EffectiveMemoryNodes", "ay", "false"),
            ("AllowedCPUs", "ay", "false"),
            ("AllowedMemoryNodes", "ay", "false"),
            ("CPUUsageNSec", "t", "false"),
            ("TasksCurrent", "t", "false"),
            ("EffectiveTasksMax", "t", "false"),
            ("OOMKills", "t", "false"),
            ("ManagedOOMKills", "t", "false"),
            ("TimerSlackNSec", "t", "const"),
            ("SameProcessGroup", "b", "const"),
            ("ExecMainStartTimestamp", "t", "true"),
            ("ExecMainStartTimestampMonotonic", "t", "true"),
            ("ExecMainExitTimestamp", "t", "true"),
            ("ExecMainExitTimestampMonotonic", "t", "true"),
            ("ExecMainPID", "u", "true"),
            ("SendSIGKILL", "b", "const"),
            ("SendSIGHUP", "b", "const"),
            ("ReloadSignal", "i", "const"),
            ("TimeoutCleanUSec", "t", "const"),
            ("UMask", "u", "const"),
            ("OOMPolicy", "s", "const"),
            ("KeyringMode", "s", "const"),
        ] {
            let opening = format!(r#"<property name="{name}" type="{signature}" access="read">"#);
            if emits == "true" {
                assert!(
                    xml.contains(&format!(
                        r#"<property name="{name}" type="{signature}" access="read"/>"#
                    )),
                    "missing {name} in service introspection"
                );
                continue;
            }
            let property = xml
                .split(&opening)
                .nth(1)
                .and_then(|rest| rest.split("</property>").next())
                .unwrap_or_else(|| panic!("missing {name} in service introspection"));
            {
                assert!(
                    property.contains(&format!(
                        r#"<annotation name="org.freedesktop.DBus.Property.EmitsChangedSignal" value="{emits}"/>"#
                    )),
                    "wrong change annotation for {name}: {property}"
                );
            }
        }
    }
}
