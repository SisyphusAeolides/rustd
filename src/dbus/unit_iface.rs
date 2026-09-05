// SPDX-License-Identifier: LGPL-2.1-or-later
//! `io.rustd.Manager1.Unit` D-Bus interface.
//!
//! One instance is registered per unit at its canonical object path.
//!
//! Upstream reference: `src/core/dbus-unit.c` (v261)

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

use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use zbus::interface;

use crate::config::ManagerScope;
use crate::dbus::auth::authorize_privileged_caller;
use crate::dbus::manager_iface::{job_path_for, DbusObjectNamespace};
use crate::event::EventLoopWake;
use crate::ipc::UnitInfo;
use crate::job::{JobKind, JobQueue};
use crate::unit::condition::{self, Condition, ConditionKind};
use crate::unit::enable_state::{query_enable_state, query_system_enable_state};
use crate::unit::loader::{LoadedUnit, UnitLoader};
use crate::unit::section_unit::{CollectMode, UnitAction, UnitSection};

// ── UnitInterface ─────────────────────────────────────────────────────────

/// A single unit's D-Bus object.
///
/// Properties are served from the shared snapshot; the manager updates the
/// snapshot each loop iteration so values are at most one loop-tick stale.
pub struct UnitInterface {
    /// Name of this unit, e.g. `"systemd-journald.service"`.
    pub name: String,
    /// Shared snapshot — read on every property access.
    pub snapshot: Arc<RwLock<Vec<UnitInfo>>>,
    /// Shared manager job queue.
    pub queue: Arc<Mutex<JobQueue>>,
    /// Cross-thread manager event-loop wake handle.
    pub wake: EventLoopWake,
    /// Manager scope owning this object.
    pub scope: ManagerScope,
    /// D-Bus object namespace used for job paths returned by this object.
    pub namespace: DbusObjectNamespace,
}

impl UnitInterface {
    /// Look up this unit's current `UnitInfo` from the snapshot.
    fn info(&self) -> Option<UnitInfo> {
        self.snapshot
            .read()
            .ok()?
            .iter()
            .find(|unit| unit.name == self.name)
            .cloned()
    }

    fn unit_section(&self) -> Option<UnitSection> {
        UnitLoader::for_scope(self.scope)
            .load(&self.name)
            .ok()
            .map(|unit| unit.unit_section().clone())
    }

    fn enqueue(&self, kind: JobKind) -> zbus::fdo::Result<zbus::zvariant::OwnedObjectPath> {
        let job = {
            let mut queue = self.queue.lock().map_err(|_| {
                zbus::fdo::Error::Failed("internal: job queue lock poisoned".into())
            })?;
            queue.enqueue(kind, self.name.clone())
        };
        self.wake.wake().map_err(|error| {
            zbus::fdo::Error::Failed(format!("internal: event loop wake failed: {error}"))
        })?;
        job_path_for(self.namespace, job.id)
    }

    fn validate_mode(mode: &str, request: &'static str) -> zbus::fdo::Result<()> {
        let valid = matches!(
            mode,
            "fail"
                | "lenient"
                | "replace"
                | "replace-irreversibly"
                | "isolate"
                | "flush"
                | "ignore-dependencies"
                | "ignore-requirements"
                | "triggering"
                | "restart-dependencies"
        );
        if !valid {
            return Err(zbus::fdo::Error::InvalidArgs(format!(
                "Job mode {mode} invalid"
            )));
        }
        if request != "start" && mode == "isolate" {
            return Err(zbus::fdo::Error::InvalidArgs(
                "Isolate is only valid for start.".into(),
            ));
        }
        if request != "stop" && mode == "triggering" {
            return Err(zbus::fdo::Error::InvalidArgs(
                "--job-mode=triggering is only valid for stop.".into(),
            ));
        }
        if request != "start" && mode == "restart-dependencies" {
            return Err(zbus::fdo::Error::InvalidArgs(
                "--job-mode=restart-dependencies is only valid for start.".into(),
            ));
        }
        Ok(())
    }

    fn active_or_activating(&self) -> bool {
        self.info()
            .is_some_and(|unit| matches!(unit.active_state.as_str(), "active" | "activating"))
    }

    fn active_or_reloading(&self) -> bool {
        self.info()
            .is_some_and(|unit| matches!(unit.active_state.as_str(), "active" | "reloading"))
    }

    fn has_reload_command(&self) -> bool {
        matches!(
            UnitLoader::for_scope(self.scope).load(&self.name),
            Ok(LoadedUnit::Service(service)) if !service.specific.exec_reload.is_empty()
        )
    }
}

#[interface(name = "io.rustd.Manager1.Unit")]
impl UnitInterface {
    // ── properties ────────────────────────────────────────────────────

    /// `Id` — canonical unit name.
    #[zbus(property)]
    fn id(&self) -> String {
        self.name.clone()
    }

    /// `Names` — all names known for this unit.
    #[zbus(property)]
    fn names(&self) -> Vec<String> {
        vec![self.name.clone()]
    }

    /// `Following` — another unit whose state this unit follows.
    #[zbus(property)]
    fn following(&self) -> &'static str {
        ""
    }

    /// `Description` — human-readable unit description.
    #[zbus(property)]
    fn description(&self) -> String {
        self.info().map(|unit| unit.description).unwrap_or_default()
    }

    /// `LoadState` — `"loaded"`, `"not-found"`, or `"error"`.
    #[zbus(property)]
    fn load_state(&self) -> String {
        self.info()
            .map(|unit| unit.load_state)
            .unwrap_or_else(|| "not-found".into())
    }

    /// `ActiveState` — `"inactive"`, `"activating"`, `"active"`,
    /// `"deactivating"`, or `"failed"`.
    #[zbus(property)]
    fn active_state(&self) -> String {
        self.info()
            .map(|unit| unit.active_state)
            .unwrap_or_else(|| "inactive".into())
    }

    /// `SubState` — type-specific sub-state string.
    #[zbus(property)]
    fn sub_state(&self) -> String {
        self.info()
            .map(|unit| unit.sub_state)
            .unwrap_or_else(|| "dead".into())
    }

    /// `InvocationID` — the 128-bit identity for the current service start.
    ///
    /// Units that have not been launched by the candidate report an empty
    /// byte array, matching v261's unset property representation.
    #[zbus(property, name = "InvocationID")]
    fn invocation_id(&self) -> Vec<u8> {
        self.info()
            .and_then(|unit| unit.service_runtime.invocation_id)
            .map_or_else(Vec::new, |id| id.to_vec())
    }

    /// `UnitFileState` — `"enabled"`, `"disabled"`, `"static"`, etc.
    #[zbus(property)]
    fn unit_file_state(&self) -> String {
        match self.scope {
            ManagerScope::System => query_system_enable_state(&self.name).to_string(),
            ManagerScope::User => {
                let loader = UnitLoader::user();
                let dirs: Vec<&std::path::Path> =
                    loader.search_dirs.iter().map(PathBuf::as_path).collect();
                query_enable_state(&self.name, &dirs).to_string()
            }
        }
    }

    /// `CanStart` — whether the unit supports Start.
    #[zbus(property)]
    fn can_start(&self) -> bool {
        self.info().is_some()
    }

    /// `CanStop` — whether the unit supports Stop.
    #[zbus(property)]
    fn can_stop(&self) -> bool {
        self.info().is_some()
    }

    /// `CanReload` — whether the unit has an `ExecReload=` command.
    #[zbus(property)]
    fn can_reload(&self) -> bool {
        matches!(
            UnitLoader::for_scope(self.scope).load(&self.name),
            Ok(LoadedUnit::Service(service)) if !service.specific.exec_reload.is_empty()
        )
    }

    /// `NeedDaemonReload` — whether files changed since the unit was loaded.
    #[zbus(property)]
    fn need_daemon_reload(&self) -> bool {
        false
    }

    /// `Documentation` — documentation URLs from `[Unit]`.
    #[zbus(name = "Documentation", property(emits_changed_signal = "const"))]
    fn documentation(&self) -> Vec<String> {
        self.unit_section()
            .map(|section| section.documentation)
            .unwrap_or_default()
    }

    /// `SourcePath` — generator/source path for the unit.
    #[zbus(name = "SourcePath", property(emits_changed_signal = "const"))]
    fn source_path(&self) -> String {
        self.unit_section()
            .map(|section| section.source_path)
            .unwrap_or_default()
    }

    /// `Requires` — units required by this unit.
    #[zbus(property(emits_changed_signal = "const"))]
    fn requires(&self) -> Vec<String> {
        self.unit_section()
            .map(|section| section.requires)
            .unwrap_or_default()
    }

    /// `Requisite` — units that must already be active.
    #[zbus(property(emits_changed_signal = "const"))]
    fn requisite(&self) -> Vec<String> {
        self.unit_section()
            .map(|section| section.requisite)
            .unwrap_or_default()
    }

    /// `Wants` — units weakly pulled in by this unit.
    #[zbus(property(emits_changed_signal = "const"))]
    fn wants(&self) -> Vec<String> {
        self.unit_section()
            .map(|section| section.wants)
            .unwrap_or_default()
    }

    /// `BindsTo` — units whose lifetime is bound to this unit.
    #[zbus(property(emits_changed_signal = "const"))]
    fn binds_to(&self) -> Vec<String> {
        self.unit_section()
            .map(|section| section.binds_to)
            .unwrap_or_default()
    }

    /// `PartOf` — units whose stop/restart propagates here.
    #[zbus(property(emits_changed_signal = "const"))]
    fn part_of(&self) -> Vec<String> {
        self.unit_section()
            .map(|section| section.part_of)
            .unwrap_or_default()
    }

    /// `Upholds` — units kept active while this unit is active.
    #[zbus(property(emits_changed_signal = "const"))]
    fn upholds(&self) -> Vec<String> {
        self.unit_section()
            .map(|section| section.upholds)
            .unwrap_or_default()
    }

    /// `Conflicts` — units that conflict with this unit.
    #[zbus(property(emits_changed_signal = "const"))]
    fn conflicts(&self) -> Vec<String> {
        self.unit_section()
            .map(|section| section.conflicts)
            .unwrap_or_default()
    }

    /// `Before` — units ordered after this unit.
    #[zbus(property(emits_changed_signal = "const"))]
    fn before(&self) -> Vec<String> {
        self.unit_section()
            .map(|section| section.before)
            .unwrap_or_default()
    }

    /// `After` — units ordered before this unit.
    #[zbus(property(emits_changed_signal = "const"))]
    fn after(&self) -> Vec<String> {
        self.unit_section()
            .map(|section| section.after)
            .unwrap_or_default()
    }

    /// `OnSuccess` — units started after successful completion.
    #[zbus(property(emits_changed_signal = "const"))]
    fn on_success(&self) -> Vec<String> {
        self.unit_section()
            .map(|section| section.on_success)
            .unwrap_or_default()
    }

    /// `OnFailure` — units started after failure.
    #[zbus(property(emits_changed_signal = "const"))]
    fn on_failure(&self) -> Vec<String> {
        self.unit_section()
            .map(|section| section.on_failure)
            .unwrap_or_default()
    }

    /// `PropagatesReloadTo` — reload propagation targets.
    #[zbus(property(emits_changed_signal = "const"))]
    fn propagates_reload_to(&self) -> Vec<String> {
        self.unit_section()
            .map(|section| section.propagates_reload_to)
            .unwrap_or_default()
    }

    /// `ReloadPropagatedFrom` — units that propagate reload here.
    #[zbus(property(emits_changed_signal = "const"))]
    fn reload_propagated_from(&self) -> Vec<String> {
        self.unit_section()
            .map(|section| section.reload_propagated_from)
            .unwrap_or_default()
    }

    /// `PropagatesStopTo` — stop propagation targets.
    #[zbus(property(emits_changed_signal = "const"))]
    fn propagates_stop_to(&self) -> Vec<String> {
        self.unit_section()
            .map(|section| section.propagates_stop_to)
            .unwrap_or_default()
    }

    /// `StopPropagatedFrom` — units that propagate stop here.
    #[zbus(property(emits_changed_signal = "const"))]
    fn stop_propagated_from(&self) -> Vec<String> {
        self.unit_section()
            .map(|section| section.stop_propagated_from)
            .unwrap_or_default()
    }

    /// `JoinsNamespaceOf` — units sharing this unit's namespaces.
    #[zbus(property(emits_changed_signal = "const"))]
    fn joins_namespace_of(&self) -> Vec<String> {
        self.unit_section()
            .map(|section| section.joins_namespace_of)
            .unwrap_or_default()
    }

    /// `RequiresMountsFor` — mount paths required by this unit.
    #[zbus(property(emits_changed_signal = "const"))]
    fn requires_mounts_for(&self) -> Vec<String> {
        self.unit_section()
            .map(|section| section.requires_mounts_for)
            .unwrap_or_default()
    }

    /// `WantsMountsFor` — mount paths weakly required by this unit.
    #[zbus(property(emits_changed_signal = "const"))]
    fn wants_mounts_for(&self) -> Vec<String> {
        self.unit_section()
            .map(|section| section.wants_mounts_for)
            .unwrap_or_default()
    }

    /// `StopWhenUnneeded` — stop the unit when no dependents need it.
    #[zbus(name = "StopWhenUnneeded", property(emits_changed_signal = "const"))]
    fn stop_when_unneeded(&self) -> bool {
        self.unit_section()
            .is_some_and(|section| section.stop_when_unneeded)
    }

    /// `RefuseManualStart` — reject manual starts.
    #[zbus(name = "RefuseManualStart", property(emits_changed_signal = "const"))]
    fn refuse_manual_start(&self) -> bool {
        self.unit_section()
            .is_some_and(|section| section.refuse_manual_start)
    }

    /// `RefuseManualStop` — reject manual stops.
    #[zbus(name = "RefuseManualStop", property(emits_changed_signal = "const"))]
    fn refuse_manual_stop(&self) -> bool {
        self.unit_section()
            .is_some_and(|section| section.refuse_manual_stop)
    }

    /// `AllowIsolate` — permit isolation jobs for the unit.
    #[zbus(name = "AllowIsolate", property(emits_changed_signal = "const"))]
    fn allow_isolate(&self) -> bool {
        self.unit_section()
            .is_some_and(|section| section.allow_isolate && self.can_start())
    }

    /// `DefaultDependencies` — whether implicit dependencies are enabled.
    #[zbus(name = "DefaultDependencies", property(emits_changed_signal = "const"))]
    fn default_dependencies(&self) -> bool {
        self.unit_section()
            .map_or(true, |section| section.default_dependencies)
    }

    /// `IgnoreOnIsolate` — whether isolation leaves the unit untouched.
    #[zbus(name = "IgnoreOnIsolate", property(emits_changed_signal = "const"))]
    fn ignore_on_isolate(&self) -> bool {
        self.unit_section()
            .is_some_and(|section| section.ignore_on_isolate)
    }

    /// `SurviveFinalKillSignal` — preserve the unit's processes on final kill.
    #[zbus(
        name = "SurviveFinalKillSignal",
        property(emits_changed_signal = "const")
    )]
    fn survive_final_kill_signal(&self) -> bool {
        self.unit_section()
            .is_some_and(|section| section.survive_final_kill_signal)
    }

    /// `OnSuccessJobMode` — job mode for `OnSuccess=` units.
    #[zbus(name = "OnSuccessJobMode", property(emits_changed_signal = "const"))]
    fn on_success_job_mode(&self) -> String {
        self.unit_section()
            .map(|section| job_mode_name(&section.on_success_job_mode, "fail"))
            .unwrap_or_else(|| "fail".into())
    }

    /// `OnFailureJobMode` — job mode for `OnFailure=` units.
    #[zbus(name = "OnFailureJobMode", property(emits_changed_signal = "const"))]
    fn on_failure_job_mode(&self) -> String {
        self.unit_section()
            .map(|section| job_mode_name(&section.on_failure_job_mode, "replace"))
            .unwrap_or_else(|| "replace".into())
    }

    /// `ConditionResult` — current aggregate condition result.
    #[zbus(name = "ConditionResult", property)]
    fn condition_result(&self) -> bool {
        self.unit_section().map_or(true, |section| {
            condition::evaluate_list(&section.conditions)
        })
    }

    /// `AssertResult` — current aggregate assertion result.
    #[zbus(name = "AssertResult", property)]
    fn assert_result(&self) -> bool {
        self.unit_section()
            .map_or(true, |section| condition::evaluate_list(&section.asserts))
    }

    /// `Conditions` — parsed condition entries and their current results.
    #[zbus(name = "Conditions", property(emits_changed_signal = "invalidates"))]
    fn conditions(&self) -> Vec<(String, bool, bool, String, i32)> {
        self.unit_section()
            .map(|section| condition_entries(&section.conditions, false))
            .unwrap_or_default()
    }

    /// `Asserts` — parsed assertion entries and their current results.
    #[zbus(name = "Asserts", property(emits_changed_signal = "invalidates"))]
    fn asserts(&self) -> Vec<(String, bool, bool, String, i32)> {
        self.unit_section()
            .map(|section| condition_entries(&section.asserts, true))
            .unwrap_or_default()
    }

    /// `CollectMode` — inactive-unit collection policy.
    #[zbus(name = "CollectMode", property(emits_changed_signal = "const"))]
    fn collect_mode(&self) -> String {
        self.unit_section().map_or_else(
            || "inactive".into(),
            |section| collect_mode_name(section.collect_mode),
        )
    }

    /// `JobTimeoutUSec` — timeout for queued jobs.
    #[zbus(name = "JobTimeoutUSec", property(emits_changed_signal = "const"))]
    fn job_timeout_u_sec(&self) -> u64 {
        self.unit_section()
            .and_then(|section| section.job_timeout_sec)
            .map_or(u64::MAX, duration_usec)
    }

    /// `JobRunningTimeoutUSec` — timeout for running jobs.
    #[zbus(
        name = "JobRunningTimeoutUSec",
        property(emits_changed_signal = "const")
    )]
    fn job_running_timeout_u_sec(&self) -> u64 {
        self.unit_section()
            .and_then(|section| section.job_running_timeout_sec)
            .map_or(u64::MAX, duration_usec)
    }

    /// `JobTimeoutAction` — action after a queued-job timeout.
    #[zbus(name = "JobTimeoutAction", property(emits_changed_signal = "const"))]
    fn job_timeout_action(&self) -> String {
        self.unit_section().map_or_else(
            || "none".into(),
            |section| unit_action_name(section.job_timeout_action),
        )
    }

    /// `JobTimeoutRebootArgument` — reboot argument for timeout actions.
    #[zbus(
        name = "JobTimeoutRebootArgument",
        property(emits_changed_signal = "const")
    )]
    fn job_timeout_reboot_argument(&self) -> String {
        self.unit_section()
            .map(|section| section.job_timeout_reboot_argument)
            .unwrap_or_default()
    }

    /// `StartLimitIntervalUSec` — start-rate limiting window.
    #[zbus(
        name = "StartLimitIntervalUSec",
        property(emits_changed_signal = "const")
    )]
    fn start_limit_interval_u_sec(&self) -> u64 {
        self.unit_section()
            .and_then(|section| section.start_limit_interval_sec)
            .map_or(10 * 1_000_000, duration_usec)
    }

    /// `StartLimitBurst` — start-rate limiting burst.
    #[zbus(name = "StartLimitBurst", property(emits_changed_signal = "const"))]
    fn start_limit_burst(&self) -> u32 {
        self.unit_section()
            .and_then(|section| section.start_limit_burst)
            .unwrap_or(5)
    }

    /// `StartLimitAction` — action after start-rate limiting.
    #[zbus(name = "StartLimitAction", property(emits_changed_signal = "const"))]
    fn start_limit_action(&self) -> String {
        self.unit_section().map_or_else(
            || "none".into(),
            |section| unit_action_name(section.start_limit_action),
        )
    }

    /// `FailureAction` — action when the unit fails.
    #[zbus(name = "FailureAction", property(emits_changed_signal = "const"))]
    fn failure_action(&self) -> String {
        self.unit_section().map_or_else(
            || "none".into(),
            |section| unit_action_name(section.failure_action),
        )
    }

    /// `SuccessAction` — action after successful completion.
    #[zbus(name = "SuccessAction", property(emits_changed_signal = "const"))]
    fn success_action(&self) -> String {
        self.unit_section().map_or_else(
            || "none".into(),
            |section| unit_action_name(section.success_action),
        )
    }

    /// `FailureActionExitStatus` — exit status for failure actions.
    #[zbus(
        name = "FailureActionExitStatus",
        property(emits_changed_signal = "const")
    )]
    fn failure_action_exit_status(&self) -> i32 {
        self.unit_section()
            .and_then(|section| section.failure_action_exit_status)
            .unwrap_or(0)
    }

    /// `SuccessActionExitStatus` — exit status for success actions.
    #[zbus(
        name = "SuccessActionExitStatus",
        property(emits_changed_signal = "const")
    )]
    fn success_action_exit_status(&self) -> i32 {
        self.unit_section()
            .and_then(|section| section.success_action_exit_status)
            .unwrap_or(0)
    }

    /// `RebootArgument` — argument passed to reboot actions.
    #[zbus(name = "RebootArgument", property(emits_changed_signal = "const"))]
    fn reboot_argument(&self) -> String {
        self.unit_section()
            .map(|section| section.reboot_argument)
            .unwrap_or_default()
    }

    // ── methods ───────────────────────────────────────────────────────

    /// `Start(mode)` → job object path.
    #[zbus(out_args("job"))]
    async fn start(
        &self,
        mode: String,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<(zbus::zvariant::OwnedObjectPath,)> {
        Self::validate_mode(&mode, "start")?;
        authorize_privileged_caller(connection, &header).await?;
        Ok((self.enqueue(JobKind::Start)?,))
    }

    /// `Stop(mode)` → job object path.
    #[zbus(out_args("job"))]
    async fn stop(
        &self,
        mode: String,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<(zbus::zvariant::OwnedObjectPath,)> {
        Self::validate_mode(&mode, "stop")?;
        authorize_privileged_caller(connection, &header).await?;
        Ok((self.enqueue(JobKind::Stop)?,))
    }

    /// `Restart(mode)` → job object path.
    #[zbus(out_args("job"))]
    async fn restart(
        &self,
        mode: String,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<(zbus::zvariant::OwnedObjectPath,)> {
        Self::validate_mode(&mode, "restart")?;
        authorize_privileged_caller(connection, &header).await?;
        Ok((self.enqueue(JobKind::Restart)?,))
    }

    /// `Reload(mode)` → job object path.
    #[zbus(out_args("job"))]
    async fn reload(
        &self,
        mode: String,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<(zbus::zvariant::OwnedObjectPath,)> {
        Self::validate_mode(&mode, "reload")?;
        authorize_privileged_caller(connection, &header).await?;
        Ok((self.enqueue(JobKind::Reload)?,))
    }

    /// `TryRestart(mode)` → job object path.
    #[zbus(out_args("job"))]
    async fn try_restart(
        &self,
        mode: String,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<(zbus::zvariant::OwnedObjectPath,)> {
        Self::validate_mode(&mode, "try-restart")?;
        authorize_privileged_caller(connection, &header).await?;
        let kind = if self.active_or_activating() {
            JobKind::Restart
        } else {
            JobKind::Nop
        };
        Ok((self.enqueue(kind)?,))
    }

    /// `ReloadOrRestart(mode)` → job object path.
    #[zbus(out_args("job"))]
    async fn reload_or_restart(
        &self,
        mode: String,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<(zbus::zvariant::OwnedObjectPath,)> {
        Self::validate_mode(&mode, "reload-or-restart")?;
        authorize_privileged_caller(connection, &header).await?;
        let kind = if self.has_reload_command() {
            if self.active_or_reloading() {
                JobKind::Reload
            } else {
                JobKind::Start
            }
        } else {
            JobKind::Restart
        };
        Ok((self.enqueue(kind)?,))
    }

    /// `ReloadOrTryRestart(mode)` → job object path.
    #[zbus(out_args("job"))]
    async fn reload_or_try_restart(
        &self,
        mode: String,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<(zbus::zvariant::OwnedObjectPath,)> {
        Self::validate_mode(&mode, "reload-or-try-restart")?;
        authorize_privileged_caller(connection, &header).await?;
        let kind = if self.has_reload_command() {
            if self.active_or_reloading() {
                JobKind::Reload
            } else {
                JobKind::Nop
            }
        } else if self.active_or_activating() {
            JobKind::Restart
        } else {
            JobKind::Nop
        };
        Ok((self.enqueue(kind)?,))
    }
}

fn duration_usec(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

fn collect_mode_name(mode: CollectMode) -> String {
    match mode {
        CollectMode::Inactive => "inactive",
        CollectMode::InactiveOrFailed => "inactive-or-failed",
    }
    .into()
}

fn unit_action_name(action: UnitAction) -> String {
    match action {
        UnitAction::None => "none",
        UnitAction::Reboot => "reboot",
        UnitAction::RebootForce => "reboot-force",
        UnitAction::RebootImmediate => "reboot-immediate",
        UnitAction::Poweroff => "poweroff",
        UnitAction::PoweroffForce => "poweroff-force",
        UnitAction::PoweroffImmediate => "poweroff-immediate",
        UnitAction::Exit => "exit",
        UnitAction::ExitForce => "exit-force",
        UnitAction::SoftReboot => "soft-reboot",
        UnitAction::SoftRebootForce => "soft-reboot-force",
        UnitAction::Halt => "halt",
        UnitAction::KExec => "kexec",
    }
    .into()
}

fn job_mode_name(value: &str, default: &str) -> String {
    match value {
        "fail"
        | "lenient"
        | "replace"
        | "replace-irreversibly"
        | "isolate"
        | "flush"
        | "ignore-dependencies"
        | "ignore-requirements"
        | "triggering"
        | "restart-dependencies" => value.to_owned(),
        _ => default.to_owned(),
    }
}

fn condition_type_name(kind: &ConditionKind, is_assert: bool) -> String {
    let prefix = if is_assert { "Assert" } else { "Condition" };
    let suffix = match kind {
        ConditionKind::PathExists => "PathExists",
        ConditionKind::PathExistsGlob => "PathExistsGlob",
        ConditionKind::PathIsDirectory => "PathIsDirectory",
        ConditionKind::PathIsSymbolicLink => "PathIsSymbolicLink",
        ConditionKind::PathIsMountPoint => "PathIsMountPoint",
        ConditionKind::PathIsReadWrite => "PathIsReadWrite",
        ConditionKind::PathIsEncrypted => "PathIsEncrypted",
        ConditionKind::DirectoryNotEmpty => "DirectoryNotEmpty",
        ConditionKind::Virtualization => "Virtualization",
        ConditionKind::Host => "Host",
        ConditionKind::KernelCommandLine => "KernelCommandLine",
        ConditionKind::KernelVersion | ConditionKind::Version => "Version",
        ConditionKind::Credential => "Credential",
        ConditionKind::Environment => "Environment",
        ConditionKind::Security => "Security",
        ConditionKind::Capability => "Capability",
        ConditionKind::ACPower => "ACPower",
        ConditionKind::NeedsUpdate => "NeedsUpdate",
        ConditionKind::FirstBoot => "FirstBoot",
        ConditionKind::Architecture => "Architecture",
        ConditionKind::Firmware => "Firmware",
        ConditionKind::Memory => "Memory",
        ConditionKind::CPUs => "CPUs",
        ConditionKind::CPUFeature => "CPUFeature",
        ConditionKind::Unknown(value) => return format!("{prefix}{value}"),
    };
    format!("{prefix}{suffix}")
}

fn condition_entries(
    conditions: &[Condition],
    is_assert: bool,
) -> Vec<(String, bool, bool, String, i32)> {
    conditions
        .iter()
        .map(|condition| {
            (
                condition_type_name(&condition.kind, is_assert),
                condition.trigger,
                condition.negate,
                condition.value.clone(),
                if condition::evaluate(condition) {
                    1
                } else {
                    -1
                },
            )
        })
        .collect()
}

/// Adapter that exports a unit through the standard systemd D-Bus interface
/// name while retaining one implementation of the unit behavior.
pub struct SystemdUnitInterface {
    inner: UnitInterface,
}

impl SystemdUnitInterface {
    /// Wrap a unit configured for the compatibility object namespace.
    #[must_use]
    pub fn new(inner: UnitInterface) -> Self {
        Self { inner }
    }
}

#[zbus::export::async_trait::async_trait]
impl zbus::object_server::Interface for SystemdUnitInterface {
    fn name() -> zbus::names::InterfaceName<'static> {
        zbus::names::InterfaceName::from_static_str_unchecked("org.freedesktop.systemd1.Unit")
    }

    async fn get(
        &self,
        property_name: &str,
    ) -> Option<zbus::fdo::Result<zbus::zvariant::OwnedValue>> {
        <UnitInterface as zbus::object_server::Interface>::get(&self.inner, property_name).await
    }

    async fn get_all(
        &self,
    ) -> zbus::fdo::Result<std::collections::HashMap<String, zbus::zvariant::OwnedValue>> {
        <UnitInterface as zbus::object_server::Interface>::get_all(&self.inner).await
    }

    fn set<'call>(
        &'call self,
        property_name: &'call str,
        value: &'call zbus::zvariant::Value<'_>,
        ctxt: &'call zbus::object_server::SignalContext<'_>,
    ) -> zbus::object_server::DispatchResult<'call> {
        <UnitInterface as zbus::object_server::Interface>::set(
            &self.inner,
            property_name,
            value,
            ctxt,
        )
    }

    async fn set_mut(
        &mut self,
        property_name: &str,
        value: &zbus::zvariant::Value<'_>,
        ctxt: &zbus::object_server::SignalContext<'_>,
    ) -> Option<zbus::fdo::Result<()>> {
        <UnitInterface as zbus::object_server::Interface>::set_mut(
            &mut self.inner,
            property_name,
            value,
            ctxt,
        )
        .await
    }

    fn call<'call>(
        &'call self,
        server: &'call zbus::ObjectServer,
        connection: &'call zbus::Connection,
        message: &'call zbus::message::Message,
        name: zbus::names::MemberName<'call>,
    ) -> zbus::object_server::DispatchResult<'call> {
        <UnitInterface as zbus::object_server::Interface>::call(
            &self.inner,
            server,
            connection,
            message,
            name,
        )
    }

    fn call_mut<'call>(
        &'call mut self,
        server: &'call zbus::ObjectServer,
        connection: &'call zbus::Connection,
        message: &'call zbus::message::Message,
        name: zbus::names::MemberName<'call>,
    ) -> zbus::object_server::DispatchResult<'call> {
        <UnitInterface as zbus::object_server::Interface>::call_mut(
            &mut self.inner,
            server,
            connection,
            message,
            name,
        )
    }

    fn introspect_to_writer(&self, writer: &mut dyn std::fmt::Write, level: usize) {
        let mut generated = String::new();
        <UnitInterface as zbus::object_server::Interface>::introspect_to_writer(
            &self.inner,
            &mut generated,
            level,
        );
        let generated =
            generated.replace("io.rustd.Manager1.Unit", "org.freedesktop.systemd1.Unit");
        writer
            .write_str(&generated)
            .expect("writing D-Bus introspection XML cannot fail");
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_snapshot(units: Vec<UnitInfo>) -> Arc<RwLock<Vec<UnitInfo>>> {
        Arc::new(RwLock::new(units))
    }

    fn make_interface(name: &str, units: Vec<UnitInfo>) -> UnitInterface {
        UnitInterface {
            name: name.into(),
            snapshot: make_snapshot(units),
            queue: Arc::new(Mutex::new(JobQueue::default())),
            wake: EventLoopWake::create().unwrap(),
            scope: ManagerScope::System,
            namespace: DbusObjectNamespace::Native,
        }
    }

    #[test]
    fn properties_from_snapshot() {
        let snap = make_snapshot(vec![UnitInfo {
            name: "foo.service".into(),
            description: "Test service".into(),
            load_state: "loaded".into(),
            active_state: "active".into(),
            sub_state: "running".into(),
            main_pid: Some(1234),
            unit_type: "service".into(),
            service_type: Some("simple".into()),
            restart_policy: Some("no".into()),
            service_runtime: Box::default(),
        }]);
        let iface = UnitInterface {
            name: "foo.service".into(),
            snapshot: snap,
            queue: Arc::new(Mutex::new(JobQueue::default())),
            wake: EventLoopWake::create().unwrap(),
            scope: ManagerScope::System,
            namespace: DbusObjectNamespace::Native,
        };
        assert_eq!(iface.id(), "foo.service");
        assert_eq!(iface.names(), vec!["foo.service"]);
        assert_eq!(iface.description(), "Test service");
        assert_eq!(iface.active_state(), "active");
        assert_eq!(iface.invocation_id(), [] as [u8; 0]);
        assert!(iface.can_start());
        assert!(iface.can_stop());
    }

    #[test]
    fn invocation_id_property_uses_the_live_service_runtime() {
        let invocation_id = [
            0x4a, 0x8b, 0x81, 0x15, 0x50, 0xcb, 0x4f, 0xa4, 0x97, 0x7d, 0x47, 0x59, 0x0f, 0x57,
            0xad, 0x29,
        ];
        let interface = make_interface(
            "invocation.service",
            vec![UnitInfo {
                name: "invocation.service".into(),
                description: "Invocation service".into(),
                load_state: "loaded".into(),
                active_state: "active".into(),
                sub_state: "running".into(),
                main_pid: Some(1234),
                unit_type: "service".into(),
                service_type: Some("simple".into()),
                restart_policy: Some("no".into()),
                service_runtime: Box::new(crate::ipc::ServiceRuntimeInfo {
                    invocation_id: Some(invocation_id),
                    ..Default::default()
                }),
            }],
        );
        assert_eq!(interface.invocation_id(), invocation_id);

        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        assert!(xml.contains(r#"<property name="InvocationID" type="ay" access="read"/>"#));
    }

    #[test]
    fn missing_unit_returns_defaults() {
        let iface = make_interface("missing.service", Vec::new());
        assert_eq!(iface.active_state(), "inactive");
        assert_eq!(iface.load_state(), "not-found");
        assert!(!iface.can_start());
        assert!(!iface.can_stop());
        assert_eq!(iface.unit_file_state(), "disabled");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn unit_policy_properties_match_v261_defaults() {
        let iface = make_interface("missing.service", Vec::new());

        assert_eq!(iface.documentation(), [] as [std::string::String; 0]);
        assert_eq!(iface.source_path(), "");
        assert_eq!(iface.requires(), [] as [std::string::String; 0]);
        assert_eq!(iface.requisite(), [] as [std::string::String; 0]);
        assert_eq!(iface.wants(), [] as [std::string::String; 0]);
        assert_eq!(iface.binds_to(), [] as [std::string::String; 0]);
        assert_eq!(iface.part_of(), [] as [std::string::String; 0]);
        assert_eq!(iface.upholds(), [] as [std::string::String; 0]);
        assert_eq!(iface.conflicts(), [] as [std::string::String; 0]);
        assert_eq!(iface.before(), [] as [std::string::String; 0]);
        assert_eq!(iface.after(), [] as [std::string::String; 0]);
        assert_eq!(iface.on_success(), [] as [std::string::String; 0]);
        assert_eq!(iface.on_failure(), [] as [std::string::String; 0]);
        assert_eq!(iface.propagates_reload_to(), [] as [std::string::String; 0]);
        assert_eq!(
            iface.reload_propagated_from(),
            [] as [std::string::String; 0]
        );
        assert_eq!(iface.propagates_stop_to(), [] as [std::string::String; 0]);
        assert_eq!(iface.stop_propagated_from(), [] as [std::string::String; 0]);
        assert_eq!(iface.joins_namespace_of(), [] as [std::string::String; 0]);
        assert_eq!(iface.requires_mounts_for(), [] as [std::string::String; 0]);
        assert_eq!(iface.wants_mounts_for(), [] as [std::string::String; 0]);
        assert!(!iface.stop_when_unneeded());
        assert!(!iface.refuse_manual_start());
        assert!(!iface.refuse_manual_stop());
        assert!(!iface.allow_isolate());
        assert!(iface.default_dependencies());
        assert!(!iface.ignore_on_isolate());
        assert_eq!(iface.collect_mode(), "inactive");
        assert!(!iface.survive_final_kill_signal());
        assert_eq!(iface.on_success_job_mode(), "fail");
        assert_eq!(iface.on_failure_job_mode(), "replace");
        assert!(iface.condition_result());
        assert!(iface.assert_result());
        assert_eq!(
            iface.conditions(),
            [] as [(std::string::String, bool, bool, std::string::String, i32); 0]
        );
        assert_eq!(
            iface.asserts(),
            [] as [(std::string::String, bool, bool, std::string::String, i32); 0]
        );
        assert_eq!(iface.job_timeout_u_sec(), u64::MAX);
        assert_eq!(iface.job_running_timeout_u_sec(), u64::MAX);
        assert_eq!(iface.job_timeout_action(), "none");
        assert_eq!(iface.job_timeout_reboot_argument(), "");
        assert_eq!(iface.start_limit_interval_u_sec(), 10_000_000);
        assert_eq!(iface.start_limit_burst(), 5);
        assert_eq!(iface.start_limit_action(), "none");
        assert_eq!(iface.failure_action(), "none");
        assert_eq!(iface.success_action(), "none");
        assert_eq!(iface.failure_action_exit_status(), 0);
        assert_eq!(iface.success_action_exit_status(), 0);
        assert_eq!(iface.reboot_argument(), "");

        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&iface, &mut xml, 0);
        for (name, ty) in [
            ("Documentation", "as"),
            ("SourcePath", "s"),
            ("Requires", "as"),
            ("Requisite", "as"),
            ("Wants", "as"),
            ("BindsTo", "as"),
            ("PartOf", "as"),
            ("Upholds", "as"),
            ("Conflicts", "as"),
            ("Before", "as"),
            ("After", "as"),
            ("OnSuccess", "as"),
            ("OnFailure", "as"),
            ("PropagatesReloadTo", "as"),
            ("ReloadPropagatedFrom", "as"),
            ("PropagatesStopTo", "as"),
            ("StopPropagatedFrom", "as"),
            ("JoinsNamespaceOf", "as"),
            ("RequiresMountsFor", "as"),
            ("WantsMountsFor", "as"),
            ("StopWhenUnneeded", "b"),
            ("RefuseManualStart", "b"),
            ("RefuseManualStop", "b"),
            ("AllowIsolate", "b"),
            ("DefaultDependencies", "b"),
            ("IgnoreOnIsolate", "b"),
            ("SurviveFinalKillSignal", "b"),
            ("OnSuccessJobMode", "s"),
            ("OnFailureJobMode", "s"),
            ("ConditionResult", "b"),
            ("AssertResult", "b"),
            ("Conditions", "a(sbbsi)"),
            ("Asserts", "a(sbbsi)"),
            ("CollectMode", "s"),
            ("JobTimeoutUSec", "t"),
            ("JobRunningTimeoutUSec", "t"),
            ("JobTimeoutAction", "s"),
            ("JobTimeoutRebootArgument", "s"),
            ("StartLimitIntervalUSec", "t"),
            ("StartLimitBurst", "u"),
            ("StartLimitAction", "s"),
            ("FailureAction", "s"),
            ("SuccessAction", "s"),
            ("FailureActionExitStatus", "i"),
            ("SuccessActionExitStatus", "i"),
            ("RebootArgument", "s"),
        ] {
            let property = format!(r#"<property name="{name}" type="{ty}" access="read""#);
            assert!(xml.contains(&property), "missing {property} in {xml}");
        }
        assert!(xml.contains(
            r#"<annotation name="org.freedesktop.DBus.Property.EmitsChangedSignal" value="const"/>"#
        ));
    }

    #[test]
    fn condition_properties_use_v261_tuple_names_and_results() {
        let condition = Condition::parse("ConditionPathExists", "|!/definitely-missing");
        let assertion = Condition::parse("AssertKernelVersion", "systemd");
        let conditions = condition_entries(&[condition], false);
        let asserts = condition_entries(&[assertion], true);

        assert_eq!(conditions[0].0, "ConditionPathExists");
        assert!(conditions[0].1);
        assert!(conditions[0].2);
        assert_eq!(conditions[0].3, "/definitely-missing");
        assert_eq!(conditions[0].4, 1);
        assert_eq!(asserts[0].0, "AssertVersion");
        assert_eq!(asserts[0].3, "systemd");
        assert!(matches!(asserts[0].4, 1 | -1));
    }

    #[test]
    fn enqueue_wakes_manager_event_loop() {
        let iface = make_interface("foo.service", Vec::new());
        let queue = Arc::clone(&iface.queue);
        let wake = iface.wake.clone();

        let path = iface.enqueue(JobKind::Start).unwrap();

        assert_eq!(path.as_str(), "/io/rustd/Manager1/job/1");
        assert_eq!(queue.lock().unwrap().len(), 1);
        // Safety: the descriptor is owned by `wake` for this test.
        let counter = unsafe { crate::ffi::event::rustd_eventfd_read(wake.raw_fd()) };
        assert_eq!(counter, 1);
    }

    #[test]
    fn lifecycle_methods_match_v261_names_and_validate_modes() {
        let iface = make_interface("foo.service", Vec::new());
        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&iface, &mut xml, 0);
        for method in [
            "Start",
            "Stop",
            "Restart",
            "Reload",
            "TryRestart",
            "ReloadOrRestart",
            "ReloadOrTryRestart",
        ] {
            assert!(xml.contains(&format!(r#"<method name="{method}">"#)));
        }
        for method in [
            "Start",
            "Stop",
            "Restart",
            "Reload",
            "TryRestart",
            "ReloadOrRestart",
            "ReloadOrTryRestart",
        ] {
            let body = xml
                .split(&format!(r#"<method name="{method}">"#))
                .nth(1)
                .and_then(|rest| rest.split("</method>").next())
                .expect("method body");
            assert!(body.contains(r#"<arg name="mode" type="s" direction="in"/>"#));
            assert!(
                body.contains(r#"<arg name="job" type="o" direction="out"/>"#),
                "{method}: {body}"
            );
        }
        assert!(UnitInterface::validate_mode("isolate", "start").is_ok());
        assert!(UnitInterface::validate_mode("triggering", "stop").is_ok());
        assert!(UnitInterface::validate_mode("not-a-mode", "start").is_err());
        assert!(UnitInterface::validate_mode("isolate", "reload").is_err());
    }
}
