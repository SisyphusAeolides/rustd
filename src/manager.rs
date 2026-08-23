// SPDX-License-Identifier: LGPL-2.1-or-later
//! Service manager — unit registry, job runner, event loop integration.
//!
//! `Manager` owns the unit registry (`HashMap<String, UnitRecord>`), the
//! `EventLoop`, the `JobQueue`, and the `NotifyServer`.  The `run()` method
//! enters the event loop, draining ready jobs and dispatching child exits
//! each iteration.
//!
//! Upstream reference: `src/core/manager.c` (v261)

use std::collections::{HashMap, HashSet};
use std::sync::{
    atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicU8, Ordering},
    Arc, Mutex, RwLock,
};
use std::time::{Duration, Instant};

use anyhow::anyhow;

use crate::cgroup::CgroupManager;
use crate::config::ManagerConfig;
use crate::dbus::manager_iface::{
    manager_environment_from_process, write_set_property_dropin, ManagerEnvironment, ManagerSignal,
    SetUnitPropertiesError, SetUnitPropertiesRequest, SetUnitPropertiesRequests, SetUnitProperty,
    UnitLoadRequest, UnitLoadRequests, SHUTDOWN_HALT, SHUTDOWN_KEXEC, SHUTDOWN_NONE,
    SHUTDOWN_POWEROFF, SHUTDOWN_REBOOT,
};
use crate::dbus::server::DbusServer;
use crate::deps::{resolve_start_order, DepUnit};
use crate::event::child::reap_children;
use crate::event::loop_::{EventLoop, LoopResult};
use crate::event::timer::clock_now;
use crate::event::{ClockId, EventLoopWake, SourceId};
use crate::ipc::{DynamicUserInfo, ServiceRuntimeInfo, UnitInfo};
use crate::ipc_server::{IpcServer, ResetFailedRequests};
use crate::job::{Job, JobEvent, JobInfo, JobKind, JobQueue, JobRegistry, JobResult, JobState};
use crate::kill_context::{signal_cgroup_members, signal_primary, KillOperation, KillPolicy};
use crate::notify::NotifyServer;
use crate::oom::{self, OomBaselines, OomEventSource, OomPolicy, PendingOomEvents};
use crate::restart::{
    arm_service_timeout_event, schedule_restart, ServiceTimeoutEvent, ServiceTimeoutPhase,
};
use crate::service::{
    activate_with_notify_in_cgroup, attach_manager_environment,
    complete_dbus_start_with_notify_in_cgroup, complete_notify_start_with_notify_in_cgroup,
    deactivate_with_notify_in_cgroup, forking_pid_file_pending,
    on_child_exit_with_notify_in_cgroup, on_forking_cgroup_empty_with_notify_in_cgroup,
    on_forking_control_exit_with_notify_in_cgroup, on_service_cgroup_empty_with_notify_in_cgroup,
    release_idle_gate, reload_with_notify_in_cgroup, restart_requested,
    retry_forking_pid_file_with_notify_in_cgroup, UnitRecord,
};
use crate::service::{
    finish_timeout_failure_with_notify_in_cgroup, on_timeout_cgroup_empty_with_notify_in_cgroup,
};
use crate::socket_unit::{activate_socket, deactivate_socket, SocketRecord};
use crate::target::try_activate_target;
use crate::unit::loader::{LoadedUnit, UnitLoader};
use crate::unit::section_service::RestartPolicy;
use crate::unit::section_service::{NotifyAccess, ServiceSection, ServiceType};
use crate::unit::UnitState;

/// The central service manager.
pub struct Manager {
    /// All loaded units, keyed by name.
    pub units: HashMap<String, UnitRecord>,
    /// Runtime state for active socket units (fds + bookkeeping).
    pub socket_records: HashMap<String, SocketRecord>,
    /// Inotify event source registered for each active path unit.
    path_sources: HashMap<String, SourceId>,
    /// The epoll-driven event loop.
    pub event_loop: EventLoop,
    /// Global manager configuration.
    pub config: ManagerConfig,
    /// Pending activation/deactivation jobs.
    pub job_queue: JobQueue,
    /// Registry of all externally visible waiting and running jobs.
    pub job_registry: JobRegistry,
    /// `rustd_notify` socket server (None if socket creation failed).
    pub notify: Option<NotifyServer>,
    /// Cgroup tree manager.
    pub cgroup: CgroupManager,
    /// Registered `cgroup.events` source for each managed service cgroup.
    cgroup_sources: HashMap<String, SourceId>,
    /// Unit names whose cgroup hierarchy reported `populated 0`.
    cgroup_empty_events: Arc<Mutex<Vec<String>>>,
    /// Registered `memory.events` source for each managed service cgroup.
    oom_sources: HashMap<String, SourceId>,
    /// Unit names whose cgroup `oom_kill` counter increased.
    oom_events: PendingOomEvents,
    /// Per-cgroup cumulative `oom_kill` baselines shared with event sources.
    oom_baselines: OomBaselines,
    /// Units being stopped specifically because of an OOM policy action.
    oom_stopping: HashSet<String>,
    /// Recent OOM notifications retained long enough to classify matching SIGCHLD.
    oom_recent: HashMap<String, Instant>,
    /// Activating `Type=dbus` units whose configured name gained an owner.
    dbus_ready_events: Arc<Mutex<Vec<String>>>,
    /// Start-timeout source for each service awaiting readiness.
    start_timeouts: HashMap<String, SourceId>,
    /// Stop-timeout source for each service waiting for processes to exit.
    stop_timeouts: HashMap<String, SourceId>,
    /// Timeout events fired by manager-owned service timers.
    service_timeout_events: Arc<Mutex<Vec<ServiceTimeoutEvent>>>,
    /// Units whose restart transaction is waiting for deactivation.
    restart_pending: HashSet<String>,
    /// Unit sets retained by each running isolate transaction.
    isolate_jobs: HashMap<u32, HashSet<String>>,
    /// Unit loader used for on-demand loading.
    pub loader: UnitLoader,
    /// Shared job queue for timer unit handlers AND the IPC server.
    shared_queue: Arc<Mutex<JobQueue>>,
    /// D-Bus requests that must load units on the manager event-loop thread.
    unit_load_requests: UnitLoadRequests,
    /// D-Bus `SetUnitProperties` requests consumed by the manager loop.
    set_unit_property_requests: SetUnitPropertiesRequests,
    /// Snapshot of unit state published to the IPC server thread each loop.
    unit_snapshot: Arc<RwLock<Vec<UnitInfo>>>,
    /// IPC control socket server (None if socket bind failed).
    _ipc_server: Option<IpcServer>,
    /// Shared daemon-reload request flag used by IPC and D-Bus.
    reload_requested: Arc<AtomicBool>,
    /// Number of completed daemon-reload transactions during this manager
    /// lifetime, shared with the Manager D-Bus property.
    reload_count: Arc<AtomicU64>,
    /// Status code returned when this manager next exits, shared with D-Bus.
    exit_code: Arc<AtomicU8>,
    /// D-Bus `Exit()` request consumed by the manager event loop.
    exit_requested: Arc<AtomicBool>,
    /// D-Bus `Reexecute()` request consumed by the manager event loop.
    reexecute_requested: Arc<AtomicBool>,
    /// D-Bus shutdown objective consumed by the manager event loop.
    shutdown_action: Arc<AtomicU8>,
    /// Kernel transition held until the shutdown transaction reaches idle.
    pending_shutdown_result: Option<LoopResult>,
    /// Realtime timestamp captured when shutdown begins.
    shutdown_start_realtime_ns: Arc<AtomicI64>,
    /// Monotonic timestamp captured when shutdown begins.
    shutdown_start_monotonic_ns: Arc<AtomicI64>,
    /// Monotonic clock reading captured before initial unit activation.
    startup_monotonic_ns: i64,
    /// Realtime timestamp captured when the initial startup jobs finish.
    finish_realtime_ns: Arc<AtomicI64>,
    /// Monotonic timestamp captured when the initial startup jobs finish.
    finish_monotonic_ns: Arc<AtomicI64>,
    /// Realtime timestamp captured before the initial dependency closure loads.
    units_load_start_realtime_ns: Arc<AtomicI64>,
    /// Monotonic timestamp captured before the initial dependency closure loads.
    units_load_start_monotonic_ns: Arc<AtomicI64>,
    /// Realtime timestamp captured after the initial dependency closure loads.
    units_load_finish_realtime_ns: Arc<AtomicI64>,
    /// Monotonic timestamp captured after the initial dependency closure loads.
    units_load_finish_monotonic_ns: Arc<AtomicI64>,
    /// Realtime timestamp captured at the start of the most recent reload.
    units_load_timestamp_realtime_ns: Arc<AtomicI64>,
    /// Monotonic timestamp captured at the start of the most recent reload.
    units_load_timestamp_monotonic_ns: Arc<AtomicI64>,
    /// Whether the one-shot `StartupFinished` signal has been emitted.
    startup_finished_emitted: bool,
    /// Startup and client-managed environment inherited by service launches.
    environment: ManagerEnvironment,
    /// Client requests to clear failed unit state, consumed by the event loop.
    reset_failed_requests: ResetFailedRequests,
    /// D-Bus server (None if D-Bus is unavailable).
    pub dbus_server: Option<DbusServer>,
    /// Sender for manager D-Bus change signals (None if D-Bus is unavailable).
    signal_tx: Option<tokio::sync::mpsc::UnboundedSender<ManagerSignal>>,
    /// Previous snapshot — used to diff for UnitNew/UnitRemoved signals.
    prev_snapshot: Vec<String>,
}

fn target_dependency_snapshot(record: &UnitRecord) -> UnitRecord {
    let mut snapshot = UnitRecord::new(LoadedUnit::Target(Box::new(
        crate::unit::loader::ParsedUnit {
            name: record.loaded.name().to_owned(),
            source_path: std::path::PathBuf::new(),
            unit: crate::unit::section_unit::UnitSection::default(),
            install: crate::unit::section_install::InstallSection::default(),
            specific: (),
        },
    )));
    snapshot.state = record.state;
    snapshot.status_text.clone_from(&record.status_text);
    snapshot.status_errno = record.status_errno;
    snapshot.watchdog_timestamp_ns = record.watchdog_timestamp_ns;
    snapshot.watchdog_timestamp_realtime_ns = record.watchdog_timestamp_realtime_ns;
    snapshot.exec_main_start_realtime_ns = record.exec_main_start_realtime_ns;
    snapshot.exec_main_start_monotonic_ns = record.exec_main_start_monotonic_ns;
    snapshot.exec_main_exit_realtime_ns = record.exec_main_exit_realtime_ns;
    snapshot.exec_main_exit_monotonic_ns = record.exec_main_exit_monotonic_ns;
    snapshot.watchdog_triggered = record.watchdog_triggered;
    snapshot.service_result.clone_from(&record.service_result);
    snapshot.exec_main_code = record.exec_main_code;
    snapshot.exec_main_status = record.exec_main_status;
    snapshot
}

impl Manager {
    /// Create the manager with system defaults.
    ///
    /// # Errors
    /// Returns an error if the event loop cannot be created.
    #[allow(clippy::too_many_lines)]
    pub fn new(config: ManagerConfig) -> anyhow::Result<Self> {
        let scope = config.scope;
        // Capture the dual startup timestamp before constructing the event
        // loop or loading units.  This is the state exposed by v261's
        // UserspaceTimestamp properties.
        let startup_realtime_ns = clock_now(ClockId::Realtime).unwrap_or(0);
        let startup_monotonic_ns = clock_now(ClockId::Monotonic).unwrap_or(0);
        let mut event_loop = EventLoop::new()?;
        let event_wake = EventLoopWake::create()?;
        event_loop.add_io(
            event_wake.raw_fd(),
            libc::EPOLLIN as u32,
            event_wake.io_handler(),
        )?;
        let notify = NotifyServer::new().ok();
        if let Some(server) = notify.as_ref() {
            event_loop.add_io(server.raw_fd(), libc::EPOLLIN as u32, server.io_handler())?;
        }
        let cgroup = CgroupManager::for_scope(scope);
        let _ = cgroup.setup_root();
        let cgroup_empty_events = Arc::new(Mutex::new(Vec::new()));
        let oom_events = Arc::new(Mutex::new(Vec::new()));
        let oom_baselines = Arc::new(Mutex::new(HashMap::new()));
        let service_timeout_events = Arc::new(Mutex::new(Vec::new()));
        let dbus_ready_events = Arc::new(Mutex::new(Vec::new()));
        let job_registry = JobRegistry::default();
        let shared_queue = Arc::new(Mutex::new(JobQueue::with_registry(job_registry.clone())));
        let unit_load_requests: UnitLoadRequests = Arc::new(Mutex::new(Vec::new()));
        let set_unit_property_requests: SetUnitPropertiesRequests =
            Arc::new(Mutex::new(Vec::new()));
        let unit_snapshot: Arc<RwLock<Vec<UnitInfo>>> = Arc::new(RwLock::new(Vec::new()));
        let reload_requested = Arc::new(AtomicBool::new(false));
        let reload_count = Arc::new(AtomicU64::new(0));
        let exit_code = Arc::new(AtomicU8::new(0));
        let exit_requested = Arc::new(AtomicBool::new(false));
        let reexecute_requested = Arc::new(AtomicBool::new(false));
        let shutdown_action = Arc::new(AtomicU8::new(SHUTDOWN_NONE));
        let shutdown_start_realtime_ns = Arc::new(AtomicI64::new(0));
        let shutdown_start_monotonic_ns = Arc::new(AtomicI64::new(0));
        let finish_realtime_ns = Arc::new(AtomicI64::new(0));
        let finish_monotonic_ns = Arc::new(AtomicI64::new(0));
        let units_load_start_realtime_ns = Arc::new(AtomicI64::new(0));
        let units_load_start_monotonic_ns = Arc::new(AtomicI64::new(0));
        let units_load_finish_realtime_ns = Arc::new(AtomicI64::new(0));
        let units_load_finish_monotonic_ns = Arc::new(AtomicI64::new(0));
        let units_load_timestamp_realtime_ns = Arc::new(AtomicI64::new(0));
        let units_load_timestamp_monotonic_ns = Arc::new(AtomicI64::new(0));
        let environment = manager_environment_from_process();
        let reset_failed_requests: ResetFailedRequests = Arc::new(Mutex::new(Vec::new()));

        // Start IPC server; non-fatal if socket bind fails (e.g. in tests).
        let ipc = IpcServer::start(
            scope,
            &unit_snapshot,
            &shared_queue,
            event_wake.clone(),
            &reload_requested,
            &reset_failed_requests,
        )
        .ok();

        // Start D-Bus server; non-fatal if D-Bus is unavailable.
        let dbus_result = DbusServer::start(
            scope,
            cgroup.clone(),
            Arc::clone(&config.unit_defaults),
            config.default_timeout_start_sec,
            config.default_timeout_stop_sec,
            Arc::clone(&unit_snapshot),
            Arc::clone(&shared_queue),
            Arc::clone(&unit_load_requests),
            Arc::clone(&set_unit_property_requests),
            job_registry.clone(),
            event_wake,
            Arc::clone(&reload_requested),
            Arc::clone(&reload_count),
            Arc::clone(&exit_code),
            Arc::clone(&exit_requested),
            Arc::clone(&reexecute_requested),
            Arc::clone(&shutdown_action),
            Arc::clone(&shutdown_start_realtime_ns),
            Arc::clone(&shutdown_start_monotonic_ns),
            startup_realtime_ns,
            startup_monotonic_ns,
            Arc::clone(&finish_realtime_ns),
            Arc::clone(&finish_monotonic_ns),
            Arc::clone(&units_load_start_realtime_ns),
            Arc::clone(&units_load_start_monotonic_ns),
            Arc::clone(&units_load_finish_realtime_ns),
            Arc::clone(&units_load_finish_monotonic_ns),
            Arc::clone(&units_load_timestamp_realtime_ns),
            Arc::clone(&units_load_timestamp_monotonic_ns),
            Arc::clone(&environment),
            config.log_level.clone(),
            config.log_target.clone(),
            Arc::clone(&reset_failed_requests),
            Arc::clone(&dbus_ready_events),
        )
        .ok();
        let (dbus, signal_tx) = match dbus_result {
            Some((server, tx)) => (Some(server), Some(tx)),
            None => (None, None),
        };

        Ok(Self {
            units: HashMap::new(),
            socket_records: HashMap::new(),
            path_sources: HashMap::new(),
            event_loop,
            config,
            job_queue: JobQueue::with_registry(job_registry.clone()),
            job_registry,
            notify,
            cgroup,
            cgroup_sources: HashMap::new(),
            cgroup_empty_events,
            oom_sources: HashMap::new(),
            oom_events,
            oom_baselines,
            oom_stopping: HashSet::new(),
            oom_recent: HashMap::new(),
            dbus_ready_events,
            start_timeouts: HashMap::new(),
            stop_timeouts: HashMap::new(),
            service_timeout_events,
            restart_pending: HashSet::new(),
            isolate_jobs: HashMap::new(),
            loader: UnitLoader::for_scope(scope),
            shared_queue,
            unit_load_requests,
            set_unit_property_requests,
            unit_snapshot,
            _ipc_server: ipc,
            reload_requested,
            reload_count,
            exit_code,
            exit_requested,
            reexecute_requested,
            shutdown_action,
            pending_shutdown_result: None,
            shutdown_start_realtime_ns,
            shutdown_start_monotonic_ns,
            startup_monotonic_ns,
            finish_realtime_ns,
            finish_monotonic_ns,
            units_load_start_realtime_ns,
            units_load_start_monotonic_ns,
            units_load_finish_realtime_ns,
            units_load_finish_monotonic_ns,
            units_load_timestamp_realtime_ns,
            units_load_timestamp_monotonic_ns,
            startup_finished_emitted: false,
            environment,
            reset_failed_requests,
            dbus_server: dbus,
            signal_tx,
            prev_snapshot: Vec::new(),
        })
    }

    /// Return the D-Bus-configurable status code for the next manager exit.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        self.exit_code.load(Ordering::Acquire)
    }

    /// Load a unit by name into the registry.
    ///
    /// If the unit is already loaded, this is a no-op.
    ///
    /// # Errors
    /// Returns an error if the unit file cannot be found or parsed.
    pub fn load_unit(&mut self, name: &str) -> anyhow::Result<()> {
        if self.units.contains_key(name) {
            return Ok(());
        }
        let loaded = self.loader.load(name)?;
        self.units
            .insert(name.to_owned(), self.new_unit_record(loaded));
        Ok(())
    }

    fn new_unit_record(&self, loaded: LoadedUnit) -> UnitRecord {
        let mut loaded = loaded;
        if let Ok(defaults) = self.config.unit_defaults.read() {
            defaults.apply_to_loaded_unit(&mut loaded);
        }
        let mut record = UnitRecord::new(loaded);
        attach_manager_environment(&mut record, Arc::clone(&self.environment));
        record
    }

    /// Resolve the full dependency closure for `target` and enqueue `Start`
    /// jobs in topological order.
    ///
    /// # Errors
    /// Returns an error if a `Requires=` dep cannot be loaded or a cycle is
    /// found.
    pub fn enqueue_start(&mut self, target: &str) -> anyhow::Result<()> {
        let capture_units_load_timestamps = self
            .units_load_start_realtime_ns
            .compare_exchange(
                0,
                clock_now(ClockId::Realtime).unwrap_or(0),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok();
        if capture_units_load_timestamps {
            self.units_load_start_monotonic_ns.store(
                clock_now(ClockId::Monotonic).unwrap_or(0),
                Ordering::Release,
            );
        }
        // Ensure target is loaded.
        self.load_unit(target)?;

        let known: HashMap<String, DepUnit<'_>> = self
            .units
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    DepUnit {
                        loaded: &v.loaded,
                        state: v.state,
                    },
                )
            })
            .collect();

        let loader = &self.loader;
        let order = resolve_start_order(target, &known, |name| loader.load(name).ok())?;

        for name in order {
            // Load any deps discovered during resolution.
            if !self.units.contains_key(&name) {
                if let Ok(loaded) = self.loader.load(&name) {
                    let record = self.new_unit_record(loaded);
                    self.units.insert(name.clone(), record);
                }
            }
            self.job_queue.enqueue(JobKind::Start, name);
        }
        if capture_units_load_timestamps {
            self.units_load_finish_realtime_ns
                .store(clock_now(ClockId::Realtime).unwrap_or(0), Ordering::Release);
            self.units_load_finish_monotonic_ns.store(
                clock_now(ClockId::Monotonic).unwrap_or(0),
                Ordering::Release,
            );
        }
        Ok(())
    }

    /// Run the manager event loop.
    ///
    /// Each iteration:
    /// 1. Drain the shared timer-queue into the main job queue.
    /// 2. Reap exited children and apply state transitions.
    /// 3. Apply pending notify transitions.
    /// 4. Drain and execute ready jobs.
    /// 5. Try to activate any pending targets.
    /// 6. Poll the event loop once.
    ///
    /// # Errors
    /// Propagates errors from `EventLoop::run_once`.
    pub fn run(&mut self) -> anyhow::Result<LoopResult> {
        self.run_inner(false)
    }

    /// Run until all units and jobs are settled.
    ///
    /// This bounded mode exists for integration tests and embedding. A real
    /// manager must use [`Self::run`] so it remains available for later jobs.
    ///
    /// # Errors
    /// Propagates errors from `EventLoop::run_once`.
    pub fn run_until_idle(&mut self) -> anyhow::Result<LoopResult> {
        self.run_inner(true)
    }

    #[allow(clippy::too_many_lines)]
    fn run_inner(&mut self, exit_when_idle: bool) -> anyhow::Result<LoopResult> {
        loop {
            // 1. Drain shared queue (timers + IPC-injected jobs) into main queue.
            //    Load units on-demand so IPC start requests work even for
            //    units not yet in the registry.
            if let Ok(mut shared) = self.shared_queue.lock() {
                while let Some(job) = shared.pop_front() {
                    if !self.units.contains_key(&job.unit_name) {
                        if let Ok(loaded) = self.loader.load(&job.unit_name) {
                            let record = self.new_unit_record(loaded);
                            self.units.insert(job.unit_name.clone(), record);
                        }
                    }
                    self.job_queue.push_existing(job);
                }
            }

            self.apply_unit_load_requests();

            self.apply_set_unit_property_requests();

            self.apply_reset_failed_requests();

            // Publish JobNew before executing newly queued work.
            self.publish_job_events();

            // 2a. Reap any children that exited before we entered epoll.
            // Synchronize memory.events before applying those exits so a
            // kernel OOM kill is never mistaken for an ordinary SIGKILL.
            let exits = reap_children();
            self.sync_oom_counters();
            self.apply_oom_events();
            self.apply_child_exits(exits);
            self.cleanup_empty_cgroups();
            self.retry_pending_forking_pid_files();
            self.apply_service_timeout_events();

            // 3. Apply readiness transitions and watchdogs.
            self.apply_notify_events();
            self.apply_dbus_ready_events();
            self.expire_watchdogs();

            // 4. Drain and execute ready jobs.
            let mut afters: HashMap<String, Vec<String>> = self
                .units
                .iter()
                .map(|(k, v)| (k.clone(), v.loaded.unit_section().after.clone()))
                .collect();
            for (name, record) in &self.units {
                for later in &record.loaded.unit_section().before {
                    afters.entry(later.clone()).or_default().push(name.clone());
                }
            }
            for dependencies in afters.values_mut() {
                dependencies.sort();
                dependencies.dedup();
            }
            self.job_queue.refresh_ordering(&afters);
            let states: HashMap<String, UnitState> = self
                .units
                .iter()
                .map(|(k, v)| (k.clone(), v.state))
                .collect();

            // Dispatch one job, then rebuild states and ordering. Draining the
            // whole ready set against a single pre-dispatch snapshot lets an
            // `After=` successor appear ready while its predecessor is still
            // merely Inactive with a queued start job.
            let ready = self
                .job_queue
                .pop_ready(&states, &afters)
                .into_iter()
                .collect::<Vec<_>>();
            let dispatched_jobs = !ready.is_empty();
            self.run_ready_jobs(ready);

            // 5. Try to activate pending targets.
            let target_names: Vec<String> = self
                .units
                .iter()
                .filter(|(_, record)| {
                    matches!(record.loaded, LoadedUnit::Target(_))
                        && record.state == UnitState::Activating
                })
                .map(|(k, _)| k.clone())
                .collect();

            for name in target_names {
                // We need an immutable snapshot of other units for the check.
                // Safety: we only mutate `name`'s record, not others.
                let other_units: HashMap<String, UnitRecord> = self
                    .units
                    .iter()
                    .filter(|(key, _)| key.as_str() != name)
                    .map(|(key, value)| (key.clone(), target_dependency_snapshot(value)))
                    .collect();
                if let Some(record) = self.units.get_mut(&name) {
                    try_activate_target(record, &other_units);
                }
            }

            // 6. Finish asynchronous jobs whose unit state has settled.
            self.complete_running_jobs();

            // 7. Publish unit state before JobRemoved, matching upstream signal order.
            self.publish_snapshot();
            self.publish_job_events();

            self.publish_startup_finished_if_ready();

            // 8. Check the daemon-reload flag shared by IPC and D-Bus.
            if self.reload_requested.swap(false, Ordering::AcqRel) {
                self.units_load_timestamp_realtime_ns
                    .store(clock_now(ClockId::Realtime).unwrap_or(0), Ordering::Release);
                self.units_load_timestamp_monotonic_ns.store(
                    clock_now(ClockId::Monotonic).unwrap_or(0),
                    Ordering::Release,
                );
                #[allow(deprecated)]
                let _ =
                    self.reload_count
                        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                            Some(count.saturating_add(1))
                        });
                if let Some(tx) = self.signal_tx.as_ref() {
                    let _ = tx.send(ManagerSignal::Reloading { active: true });
                }
                self.reload_unit_files();
                if let Some(tx) = self.signal_tx.as_ref() {
                    let _ = tx.send(ManagerSignal::UnitFilesChanged);
                    let _ = tx.send(ManagerSignal::Reloading { active: false });
                }
            }

            if let Some(result) = self.requested_lifecycle_result() {
                return Ok(result);
            }

            // A completed dispatch batch may make ordered successor jobs
            // runnable without producing an fd event. Re-enter scheduling
            // immediately instead of sleeping until an unrelated wakeup or
            // the bounded poll timeout.
            if dispatched_jobs {
                continue;
            }

            if exit_when_idle && self.is_idle() {
                return Ok(LoopResult::Exit);
            }

            // 9. Poll until an event or the nearest watchdog deadline.
            let poll_timeout_ms = self.next_poll_timeout_ms();
            let r = self.event_loop.run_once_timeout(poll_timeout_ms)?;

            // 2b. Apply any child exits collected inside run_once (via SIGCHLD).
            let exits = self.event_loop.drain_child_exits();
            self.sync_oom_counters();
            self.apply_oom_events();
            self.apply_child_exits(exits);
            self.cleanup_empty_cgroups();

            if matches!(
                r,
                LoopResult::Reboot | LoopResult::Poweroff | LoopResult::Halt | LoopResult::Kexec
            ) {
                let requested = self.event_loop.take_result();
                if let Some(result) = self.queue_shutdown_transaction(requested) {
                    return Ok(result);
                }
                continue;
            }
            if r != LoopResult::Continue {
                return Ok(r);
            }

            if exit_when_idle && self.is_idle() {
                return Ok(LoopResult::Exit);
            }
        }
    }

    fn requested_lifecycle_result(&mut self) -> Option<LoopResult> {
        if self.pending_shutdown_result.is_some() {
            return self
                .is_idle()
                .then(|| self.pending_shutdown_result.take())
                .flatten();
        }
        if self.reexecute_requested.swap(false, Ordering::AcqRel) {
            Some(LoopResult::Reexecute)
        } else if self.exit_requested.swap(false, Ordering::AcqRel) {
            Some(LoopResult::Exit)
        } else {
            let requested = match self.shutdown_action.swap(SHUTDOWN_NONE, Ordering::AcqRel) {
                SHUTDOWN_REBOOT => Some(LoopResult::Reboot),
                SHUTDOWN_POWEROFF => Some(LoopResult::Poweroff),
                SHUTDOWN_HALT => Some(LoopResult::Halt),
                SHUTDOWN_KEXEC => Some(LoopResult::Kexec),
                _ => None,
            };
            if let Some(result) = requested {
                return self.queue_shutdown_transaction(result);
            }
            None
        }
    }

    fn queue_shutdown_transaction(&mut self, result: LoopResult) -> Option<LoopResult> {
        self.capture_shutdown_start_timestamp();
        self.begin_shutdown_transaction();
        self.pending_shutdown_result = Some(result);
        self.is_idle()
            .then(|| self.pending_shutdown_result.take())
            .flatten()
    }

    fn begin_shutdown_transaction(&mut self) {
        if self.enqueue_isolate(0, "shutdown.target").is_ok() {
            return;
        }

        // A damaged or incomplete unit installation must still stop every
        // supervised workload before PID 1 invokes the kernel transition.
        let active: Vec<String> = self
            .units
            .iter()
            .filter(|(_, record)| {
                matches!(
                    record.state,
                    UnitState::Active | UnitState::Activating | UnitState::Failed
                )
            })
            .map(|(name, _)| name.clone())
            .collect();
        for name in active {
            self.job_queue.enqueue_internal(JobKind::Stop, name);
        }
    }

    fn capture_shutdown_start_timestamp(&self) {
        let realtime_ns = clock_now(ClockId::Realtime).unwrap_or(0);
        if self
            .shutdown_start_realtime_ns
            .compare_exchange(0, realtime_ns, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.shutdown_start_monotonic_ns.store(
                clock_now(ClockId::Monotonic).unwrap_or(0),
                Ordering::Release,
            );
        }
    }

    /// Emit the v261 `StartupFinished` signal once the initial transaction has
    /// reached a stable idle state.  This manager has no boot-loader or
    /// initrd timestamp sources, so those phases are zero (the same values
    /// used by systemd for user managers and managers running in a
    /// container).  The userspace and total durations are measured from the
    /// manager's real monotonic startup clock.
    fn publish_startup_finished_if_ready(&mut self) {
        if self.startup_finished_emitted || !self.all_settled() {
            return;
        }
        self.startup_finished_emitted = true;
        let finish_realtime_ns = clock_now(ClockId::Realtime).unwrap_or(0);
        let finish_monotonic_ns =
            clock_now(ClockId::Monotonic).unwrap_or(self.startup_monotonic_ns);
        self.finish_realtime_ns
            .store(finish_realtime_ns, Ordering::Release);
        self.finish_monotonic_ns
            .store(finish_monotonic_ns, Ordering::Release);
        let now = finish_monotonic_ns;
        let elapsed_ns = now.saturating_sub(self.startup_monotonic_ns).max(0);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let elapsed_usec = (elapsed_ns as u64) / 1_000;
        if let Some(tx) = self.signal_tx.as_ref() {
            let _ = tx.send(ManagerSignal::StartupFinished {
                firmware: 0,
                loader: 0,
                kernel: 0,
                initrd: 0,
                userspace: elapsed_usec,
                total: elapsed_usec,
            });
        }
    }

    // ── Private helpers ─────────────────────────────────────────────────

    fn apply_unit_load_requests(&mut self) {
        let requests = if let Ok(mut pending) = self.unit_load_requests.lock() {
            std::mem::take(&mut *pending)
        } else {
            eprintln!("rustd: unit load request queue lock poisoned");
            return;
        };
        if requests.is_empty() {
            return;
        }

        let mut changed = false;
        let mut replies = Vec::with_capacity(requests.len());
        for UnitLoadRequest { name, reply } in requests {
            if !self.units.contains_key(&name) {
                if let Ok(loaded) = self.loader.load(&name) {
                    let record = self.new_unit_record(loaded);
                    self.units.insert(name.clone(), record);
                    changed = true;
                }
            }
            let info = self.units.get(&name).map(unit_record_to_info);
            replies.push((reply, info));
        }

        if changed {
            self.publish_snapshot();
        }
        for (reply, info) in replies {
            let _ = reply.send(info);
        }
    }

    fn apply_set_unit_property_requests(&mut self) {
        let requests = if let Ok(mut pending) = self.set_unit_property_requests.lock() {
            std::mem::take(&mut *pending)
        } else {
            eprintln!("rustd: SetUnitProperties request queue lock poisoned");
            return;
        };
        if requests.is_empty() {
            return;
        }

        let mut changed = false;
        for request in requests {
            let SetUnitPropertiesRequest {
                name,
                runtime,
                properties,
                reply,
            } = request;
            let result = self.apply_set_unit_properties(&name, runtime, &properties);
            if result.is_ok() {
                changed = true;
            }
            let _ = reply.send(result);
        }
        if changed {
            self.publish_snapshot();
        }
    }

    fn apply_set_unit_properties(
        &mut self,
        name: &str,
        runtime: bool,
        properties: &[SetUnitProperty],
    ) -> Result<(), SetUnitPropertiesError> {
        if !self.units.contains_key(name) {
            let loaded = self.loader.load(name).map_err(|error| {
                if error.to_string().to_ascii_lowercase().contains("masked") {
                    SetUnitPropertiesError::UnitMasked(format!("Unit {name} is masked."))
                } else if is_not_found(&error) {
                    SetUnitPropertiesError::NoSuchUnit(format!("Unit {name} not found."))
                } else {
                    SetUnitPropertiesError::BadUnitSetting(format!(
                        "Unit {name} has a bad unit file setting: {error}"
                    ))
                }
            })?;
            self.units
                .insert(name.to_owned(), self.new_unit_record(loaded));
        }

        let loaded = &self
            .units
            .get(name)
            .ok_or_else(|| SetUnitPropertiesError::NoSuchUnit(format!("Unit {name} not found.")))?
            .loaded;
        validate_set_unit_properties(loaded, properties)?;
        let has_resource_control = properties.iter().any(set_unit_property_is_resource);

        // Persist the exact typed values first.  The subsequent reload is
        // the same parser path used by daemon-reload, so manager state never
        // diverges from the control drop-in that was written.
        write_set_property_dropin(self.config.scope, runtime, name, properties).map_err(
            |error| {
                SetUnitPropertiesError::Failed(format!("failed to write unit properties: {error}"))
            },
        )?;
        let mut loaded = self.loader.load(name).map_err(|error| {
            SetUnitPropertiesError::BadUnitSetting(format!(
                "Unit {name} has a bad unit file setting: {error}"
            ))
        })?;
        if let Ok(defaults) = self.config.unit_defaults.read() {
            defaults.apply_to_loaded_unit(&mut loaded);
        }

        if has_resource_control {
            if let LoadedUnit::Service(service) = &loaded {
                let control = &service.specific.resource_control;
                self.cgroup.create_unit_cgroup(name).map_err(|error| {
                    SetUnitPropertiesError::Failed(format!(
                        "failed to realize cgroup for {name}: {error}"
                    ))
                })?;
                self.cgroup
                    .apply_resource_control(name, control)
                    .map_err(|error| {
                        SetUnitPropertiesError::Failed(format!(
                            "failed to apply cgroup properties for {name}: {error}"
                        ))
                    })?;
            }
        }

        if let Some(record) = self.units.get_mut(name) {
            record.loaded = loaded;
        }
        Ok(())
    }

    fn apply_reset_failed_requests(&mut self) {
        let requests = if let Ok(mut pending) = self.reset_failed_requests.lock() {
            std::mem::take(&mut *pending)
        } else {
            eprintln!("rustd: reset-failed request queue lock poisoned");
            return;
        };
        for requested in requests {
            let names = if requested.is_empty() {
                self.units.keys().cloned().collect()
            } else {
                requested
            };
            for name in names {
                self.restart_pending.remove(&name);
                if let Some(record) = self.units.get_mut(&name) {
                    reset_failed_record(record);
                }
                self.cleanup_unit_cgroup_if_empty(&name);
            }
        }
    }

    fn run_ready_jobs(&mut self, ready: Vec<Job>) {
        for job in ready {
            if job.id != 0 && !self.job_registry.is_live(job.id) {
                continue;
            }
            if job.id != 0 {
                self.job_registry.mark_running(job.id);
            }

            let result = if job.kind == JobKind::Isolate {
                self.enqueue_isolate(job.id, &job.unit_name)
            } else {
                self.run_job(job.kind, &job.unit_name)
            };

            match result {
                Ok(()) => {
                    if job.id != 0 {
                        if let Some(result) = self.immediate_job_result(&job) {
                            self.job_registry.finish(job.id, result);
                            self.isolate_jobs.remove(&job.id);
                        }
                    }
                }
                Err(error) => {
                    eprintln!(
                        "rustd: {:?} job for '{}' failed: {error}",
                        job.kind, job.unit_name
                    );
                    if job.id != 0 {
                        self.job_registry.finish(job.id, JobResult::Failed);
                        self.isolate_jobs.remove(&job.id);
                    }
                }
            }
        }
        self.release_idle_services_after_dispatch();
    }

    fn release_idle_services_after_dispatch(&mut self) {
        if !self.job_queue.is_empty() {
            return;
        }
        let shared_empty = self
            .shared_queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty();
        if !shared_empty {
            return;
        }
        for record in self.units.values_mut() {
            release_idle_gate(record);
        }
    }

    fn immediate_job_result(&self, job: &Job) -> Option<JobResult> {
        if job.kind == JobKind::Nop {
            return Some(JobResult::Done);
        }
        let state = self.units.get(&job.unit_name)?.state;
        match job.kind {
            JobKind::Nop => unreachable!("no-op jobs return before unit lookup"),
            JobKind::Start => match state {
                UnitState::Active | UnitState::Inactive => Some(JobResult::Done),
                UnitState::Failed | UnitState::Maintenance => Some(JobResult::Failed),
                UnitState::Activating | UnitState::Deactivating => None,
            },
            JobKind::Stop => match state {
                UnitState::Inactive => Some(JobResult::Done),
                UnitState::Failed | UnitState::Maintenance => Some(JobResult::Failed),
                UnitState::Active | UnitState::Activating | UnitState::Deactivating => None,
            },
            JobKind::Restart => match state {
                UnitState::Active | UnitState::Inactive => Some(JobResult::Done),
                UnitState::Failed | UnitState::Maintenance => Some(JobResult::Failed),
                UnitState::Activating | UnitState::Deactivating => None,
            },
            JobKind::Isolate => match state {
                UnitState::Failed | UnitState::Maintenance => Some(JobResult::Failed),
                UnitState::Inactive
                | UnitState::Activating
                | UnitState::Active
                | UnitState::Deactivating => None,
            },
            JobKind::Reload => Some(JobResult::Done),
        }
    }

    fn complete_running_jobs(&mut self) {
        let running: Vec<_> = self
            .job_registry
            .list()
            .into_iter()
            .filter(|job| job.state == JobState::Running)
            .collect();
        let mut completed = Vec::new();
        for job in running {
            let result = if job.kind == JobKind::Isolate {
                self.isolate_job_result(&job)
            } else {
                self.settled_job_result(&job)
            };
            if let Some(result) = result {
                completed.push((job.id, result));
            }
        }
        for (id, result) in completed {
            self.job_registry.finish(id, result);
            self.isolate_jobs.remove(&id);
        }
        let registry = self.job_registry.clone();
        self.isolate_jobs.retain(|id, _| registry.is_live(*id));
    }

    fn settled_job_result(&self, job: &JobInfo) -> Option<JobResult> {
        if job.kind == JobKind::Nop {
            return Some(JobResult::Done);
        }
        let state = self
            .units
            .get(&job.unit_name)
            .map_or(UnitState::Failed, |record| record.state);
        match job.kind {
            JobKind::Nop => unreachable!("no-op jobs return before state evaluation"),
            JobKind::Start => match state {
                UnitState::Active => Some(JobResult::Done),
                UnitState::Inactive | UnitState::Failed | UnitState::Maintenance => {
                    Some(JobResult::Failed)
                }
                UnitState::Activating | UnitState::Deactivating => None,
            },
            JobKind::Stop => match state {
                UnitState::Inactive => Some(JobResult::Done),
                UnitState::Failed | UnitState::Maintenance => Some(JobResult::Failed),
                UnitState::Active | UnitState::Activating | UnitState::Deactivating => None,
            },
            JobKind::Reload => Some(JobResult::Done),
            JobKind::Restart => match state {
                UnitState::Active | UnitState::Inactive => Some(JobResult::Done),
                UnitState::Failed | UnitState::Maintenance => Some(JobResult::Failed),
                UnitState::Activating | UnitState::Deactivating => None,
            },
            JobKind::Isolate => None,
        }
    }

    fn isolate_job_result(&self, job: &JobInfo) -> Option<JobResult> {
        let keep = self.isolate_jobs.get(&job.id)?;
        let target_state = self
            .units
            .get(&job.unit_name)
            .map_or(UnitState::Failed, |record| record.state);
        if matches!(target_state, UnitState::Failed | UnitState::Maintenance) {
            return Some(JobResult::Failed);
        }
        if keep.iter().any(|name| {
            name != &job.unit_name
                && self.units.get(name).is_some_and(|record| {
                    matches!(record.state, UnitState::Failed | UnitState::Maintenance)
                })
        }) {
            return Some(JobResult::Dependency);
        }
        let unwanted_running = self.units.iter().any(|(name, record)| {
            !keep.contains(name)
                && matches!(
                    record.state,
                    UnitState::Active | UnitState::Activating | UnitState::Deactivating
                )
        });
        if target_state == UnitState::Active && !unwanted_running {
            Some(JobResult::Done)
        } else {
            None
        }
    }

    fn publish_job_events(&self) {
        let events = self.job_registry.drain_events();
        let Some(tx) = self.signal_tx.as_ref() else {
            return;
        };
        for event in events {
            match event {
                JobEvent::New(job) => {
                    let path = crate::dbus::manager_iface::job_path(job.id)
                        .map_or_else(|_| "/".into(), |path| path.as_str().to_owned());
                    let _ = tx.send(ManagerSignal::JobNew { job, path });
                }
                JobEvent::StateChanged(job) => {
                    let path = crate::dbus::manager_iface::job_path(job.id)
                        .map_or_else(|_| "/".into(), |path| path.as_str().to_owned());
                    let _ = tx.send(ManagerSignal::JobStateChanged { job, path });
                }
                JobEvent::Removed { job, result } => {
                    let path = crate::dbus::manager_iface::job_path(job.id)
                        .map_or_else(|_| "/".into(), |path| path.as_str().to_owned());
                    let _ = tx.send(ManagerSignal::JobRemoved {
                        job,
                        path,
                        result: result.as_str().to_owned(),
                    });
                }
            }
        }
    }

    fn apply_notify_pid_change(
        &mut self,
        unit_name: &str,
        old_pid: Option<libc::pid_t>,
        new_pid: libc::pid_t,
    ) {
        if let Some(server) = self.notify.as_ref() {
            if let Some(old_pid) = old_pid {
                server.replace_pid(old_pid, new_pid);
            } else if let Some(access) = self.units.get(unit_name).and_then(|record| match &record
                .loaded
            {
                LoadedUnit::Service(service) => effective_notify_access(&service.specific),
                _ => None,
            }) {
                server.register_pid(new_pid, unit_name.to_owned(), access);
            }
        }
        let _ = self.cgroup.attach_pid(unit_name, new_pid);
    }

    fn apply_notify_events(&mut self) {
        let events = self
            .notify
            .as_ref()
            .map_or_else(Vec::new, NotifyServer::drain_events);
        for event in events {
            let now = clock_now(ClockId::Monotonic).ok();
            let now_realtime = clock_now(ClockId::Realtime).ok();
            let mut cancel_start_timeout = false;
            let mut pid_change = None;
            let mut ready_requested = false;
            let mut stopping_timeout = None;

            if let Some(record) = self.units.get_mut(&event.unit_name) {
                if let Some(status) = event.message.status {
                    record.status_text = Some(status);
                }
                if let Some(errno) = event.message.errno {
                    record.status_errno = Some(errno);
                }
                if let Some(new_pid) = event.message.main_pid.filter(|pid| *pid > 0) {
                    if record.active_pid != Some(new_pid) {
                        pid_change = Some((record.active_pid, new_pid));
                        record.active_pid = Some(new_pid);
                    }
                }
                if event.message.ready && record.state == UnitState::Activating {
                    ready_requested = true;
                }
                if event.message.watchdog && watchdog_interval_ns(record).is_some() {
                    record.watchdog_timestamp_ns = now;
                    record.watchdog_timestamp_realtime_ns = now_realtime;
                    record.watchdog_triggered = false;
                }
                if event.message.stopping
                    && matches!(record.state, UnitState::Active | UnitState::Activating)
                {
                    record.state = UnitState::Deactivating;
                    record.watchdog_timestamp_ns = None;
                    record.watchdog_timestamp_realtime_ns = None;
                    record.watchdog_triggered = false;
                    cancel_start_timeout = true;
                    ready_requested = false;
                    stopping_timeout =
                        stop_timeout_for_record(record, self.config.default_timeout_stop_sec);
                }
            }

            if ready_requested {
                let listen_fds = self.collect_listen_fds_for(&event.unit_name);
                let cgroup_procs_path = self.cgroup.unit_procs_path(&event.unit_name);
                let cgroup_procs_path = cgroup_procs_path.exists().then_some(cgroup_procs_path);
                let notify_fd = self.notify.as_ref().map_or(-1, NotifyServer::raw_fd);
                let readiness = self
                    .units
                    .get_mut(&event.unit_name)
                    .map_or(Ok(false), |record| {
                        complete_notify_start_with_notify_in_cgroup(
                            record,
                            &listen_fds,
                            notify_fd,
                            cgroup_procs_path.as_deref(),
                        )
                    });
                match readiness {
                    Ok(true) => {
                        cancel_start_timeout = true;
                        if let Some(record) = self.units.get_mut(&event.unit_name) {
                            if watchdog_interval_ns(record).is_some() {
                                record.watchdog_timestamp_ns = now;
                                record.watchdog_timestamp_realtime_ns = now_realtime;
                                record.watchdog_triggered = false;
                            }
                        }
                    }
                    Ok(false) => {}
                    Err(error) => {
                        cancel_start_timeout = true;
                        eprintln!(
                            "rustd: notify readiness for '{}' failed: {error}",
                            event.unit_name
                        );
                    }
                }
            }

            if cancel_start_timeout {
                self.cancel_start_timeout(&event.unit_name);
            }
            if let Some((pid, timeout)) = stopping_timeout {
                let _ = pid;
                self.arm_service_stop_timeout(&event.unit_name, timeout, ServiceTimeoutPhase::Stop);
            }
            if let Some((old_pid, new_pid)) = pid_change {
                self.apply_notify_pid_change(&event.unit_name, old_pid, new_pid);
            }
        }
    }

    fn apply_dbus_ready_events(&mut self) {
        let ready = {
            let mut events = self
                .dbus_ready_events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::take(&mut *events)
        };
        for name in ready {
            let listen_fds = self.collect_listen_fds_for(&name);
            let cgroup_procs_path = self.cgroup.unit_procs_path(&name);
            let cgroup_procs_path = cgroup_procs_path.exists().then_some(cgroup_procs_path);
            let notify_access = self
                .units
                .get(&name)
                .and_then(|record| match &record.loaded {
                    LoadedUnit::Service(service) => effective_notify_access(&service.specific),
                    _ => None,
                });
            let notify_fd = if notify_access.is_some() {
                self.notify.as_ref().map_or(-1, NotifyServer::raw_fd)
            } else {
                -1
            };
            let result = self.units.get_mut(&name).map_or(Ok(false), |record| {
                complete_dbus_start_with_notify_in_cgroup(
                    record,
                    &listen_fds,
                    notify_fd,
                    cgroup_procs_path.as_deref(),
                )
            });
            match result {
                Ok(true) => self.cancel_start_timeout(&name),
                Ok(false) => {}
                Err(error) => {
                    self.cancel_start_timeout(&name);
                    eprintln!("rustd: D-Bus readiness for '{name}' failed: {error}");
                }
            }
        }
    }

    fn retry_pending_forking_pid_files(&mut self) {
        let pending: Vec<String> = self
            .units
            .iter()
            .filter(|(_, record)| forking_pid_file_pending(record))
            .map(|(name, _)| name.clone())
            .collect();

        for name in pending {
            let notify_access = self
                .units
                .get(&name)
                .and_then(|record| match &record.loaded {
                    LoadedUnit::Service(service) => effective_notify_access(&service.specific),
                    _ => None,
                });
            let cgroup_procs_path = self.cgroup.unit_procs_path(&name);
            let cgroup_procs_path = cgroup_procs_path.exists().then_some(cgroup_procs_path);
            let notify_fd = if notify_access.is_some() {
                self.notify.as_ref().map_or(-1, NotifyServer::raw_fd)
            } else {
                -1
            };
            let result = self.units.get_mut(&name).map_or(Ok(false), |record| {
                retry_forking_pid_file_with_notify_in_cgroup(
                    record,
                    notify_fd,
                    cgroup_procs_path.as_deref(),
                )
            });
            match result {
                Ok(true) => {
                    self.cancel_start_timeout(&name);
                    if let (Some(record), Some(access), Some(server)) =
                        (self.units.get(&name), notify_access, self.notify.as_ref())
                    {
                        if let Some(pid) = record.active_pid {
                            server.register_pid(pid, name.clone(), access);
                        }
                    }
                }
                Ok(false) => {}
                Err(error) => {
                    self.cancel_start_timeout(&name);
                    eprintln!("rustd: PIDFile adoption for '{name}' failed: {error}");
                }
            }
        }
    }

    fn expire_watchdogs(&mut self) {
        let Ok(now) = clock_now(ClockId::Monotonic) else {
            return;
        };
        let mut expired = Vec::new();
        for (name, record) in &mut self.units {
            if record.watchdog_triggered {
                continue;
            }
            let (Some(interval), Some(last), Some(_pid)) = (
                watchdog_interval_ns(record),
                record.watchdog_timestamp_ns,
                record.active_pid,
            ) else {
                continue;
            };
            if now.saturating_sub(last) >= interval {
                record.watchdog_triggered = true;
                record.status_text = Some("Watchdog timeout".into());
                record.service_result = "watchdog".into();
                record.stop_requested = false;
                record.state = UnitState::Deactivating;
                expired.push(name.clone());
            }
        }
        for name in expired {
            eprintln!("rustd: watchdog timeout for '{name}'");
            let abort_timeout = self.timeout_policy(&name).map_or(
                Duration::from_secs(self.config.default_timeout_stop_sec),
                |value| value.3,
            );
            let sent = self.signal_timeout_operation(&name, KillOperation::Watchdog);
            if sent == 0 {
                self.finalize_timeout_without_exit(&name, "watchdog");
            } else {
                self.arm_service_stop_timeout(&name, abort_timeout, ServiceTimeoutPhase::Abort);
            }
        }
    }

    fn next_poll_timeout_ms(&self) -> i32 {
        let Ok(now) = clock_now(ClockId::Monotonic) else {
            return 30_000;
        };
        let mut nearest_ns = 30_000_000_000i64;
        if self.units.values().any(forking_pid_file_pending) {
            nearest_ns = nearest_ns.min(50_000_000);
        }
        for record in self.units.values() {
            if record.watchdog_triggered {
                continue;
            }
            let (Some(interval), Some(last)) =
                (watchdog_interval_ns(record), record.watchdog_timestamp_ns)
            else {
                continue;
            };
            let remaining = last.saturating_add(interval).saturating_sub(now).max(0);
            nearest_ns = nearest_ns.min(remaining);
        }
        let milliseconds = nearest_ns.saturating_add(999_999) / 1_000_000;
        i32::try_from(milliseconds.min(30_000)).unwrap_or(30_000)
    }

    fn apply_service_timeout_events(&mut self) {
        let events = {
            let mut events = self
                .service_timeout_events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::take(&mut *events)
        };
        for event in events {
            self.apply_service_timeout_event(&event);
        }
    }

    fn apply_service_timeout_event(&mut self, event: &ServiceTimeoutEvent) {
        let valid = match event.phase {
            ServiceTimeoutPhase::Start => self
                .start_timeouts
                .remove(&event.unit_name)
                .is_some_and(|source| source == event.source_id),
            ServiceTimeoutPhase::Stop | ServiceTimeoutPhase::Abort => self
                .stop_timeouts
                .remove(&event.unit_name)
                .is_some_and(|source| source == event.source_id),
        };
        if !valid {
            return;
        }
        let _ = self.event_loop.remove_timer(event.source_id);
        match event.phase {
            ServiceTimeoutPhase::Start => self.apply_start_deadline(&event.unit_name),
            ServiceTimeoutPhase::Stop => self.apply_stop_deadline(&event.unit_name),
            ServiceTimeoutPhase::Abort => self.apply_abort_deadline(&event.unit_name),
        }
    }

    fn timeout_policy(&self, name: &str) -> Option<(String, String, Duration, Duration)> {
        let record = self.units.get(name)?;
        let LoadedUnit::Service(service) = &record.loaded else {
            return None;
        };
        let stop = service
            .specific
            .timeout_stop_sec
            .unwrap_or(Duration::from_secs(self.config.default_timeout_stop_sec));
        let abort = service.specific.timeout_abort_sec.unwrap_or(stop);
        Some((
            service.specific.timeout_start_failure_mode.clone(),
            service.specific.timeout_stop_failure_mode.clone(),
            stop,
            abort,
        ))
    }

    fn signal_timeout_operation(&self, name: &str, operation: KillOperation) -> usize {
        let Some((policy, main_pid, control_pid)) = self.service_kill_policy(name) else {
            return 0;
        };
        let mut sent = signal_primary(policy, main_pid, control_pid, operation);
        match signal_cgroup_members(&self.cgroup, name, policy, main_pid, control_pid, operation) {
            Ok(group_sent) => sent = sent.saturating_add(group_sent),
            Err(error) => eprintln!("rustd: timeout cgroup signal for '{name}' failed: {error}"),
        }
        sent
    }

    fn mark_timeout_deactivating(&mut self, name: &str, result: &str) {
        if let Some(record) = self.units.get_mut(name) {
            record.service_result = result.into();
            record.stop_requested = false;
            record.state = UnitState::Deactivating;
            record.watchdog_timestamp_ns = None;
            record.watchdog_timestamp_realtime_ns = None;
        }
    }

    fn finalize_timeout_without_exit(&mut self, name: &str, result: &str) {
        self.cancel_start_timeout(name);
        self.cancel_stop_timeout(name);
        let notify_fd = self.notify.as_ref().map_or(-1, NotifyServer::raw_fd);
        let cgroup_procs_path = self.cgroup.unit_procs_path(name);
        let cgroup_procs_path = cgroup_procs_path.exists().then_some(cgroup_procs_path);
        if let Some(record) = self.units.get_mut(name) {
            if let Some(server) = self.notify.as_ref() {
                if let Some(pid) = record.active_pid {
                    server.unregister_pid(pid);
                }
            }
            finish_timeout_failure_with_notify_in_cgroup(
                record,
                result,
                notify_fd,
                cgroup_procs_path.as_deref(),
            );
        }
    }

    fn apply_start_deadline(&mut self, name: &str) {
        if !self
            .units
            .get(name)
            .is_some_and(|record| record.state == UnitState::Activating)
        {
            return;
        }
        let Some((start_mode, _stop_mode, stop_timeout, abort_timeout)) = self.timeout_policy(name)
        else {
            return;
        };
        self.mark_timeout_deactivating(name, "timeout");
        match start_mode.as_str() {
            "kill" => self.apply_final_kill(name),
            "abort" => {
                let sent = self.signal_timeout_operation(name, KillOperation::Watchdog);
                if sent == 0 {
                    self.finalize_timeout_without_exit(name, "timeout");
                } else {
                    self.arm_service_stop_timeout(name, abort_timeout, ServiceTimeoutPhase::Abort);
                }
            }
            _ => {
                let sent = self.signal_timeout_operation(name, KillOperation::Terminate);
                if sent == 0 {
                    self.finalize_timeout_without_exit(name, "timeout");
                } else {
                    self.arm_service_stop_timeout(name, stop_timeout, ServiceTimeoutPhase::Stop);
                }
            }
        }
    }

    fn apply_stop_deadline(&mut self, name: &str) {
        let Some((_start_mode, stop_mode, _stop_timeout, abort_timeout)) =
            self.timeout_policy(name)
        else {
            return;
        };
        if !self
            .units
            .get(name)
            .is_some_and(|record| record.state == UnitState::Deactivating)
        {
            return;
        }
        if let Some(record) = self.units.get_mut(name) {
            record.service_result = "timeout".into();
        }
        if stop_mode == "abort" {
            let sent = self.signal_timeout_operation(name, KillOperation::Watchdog);
            if sent == 0 {
                self.finalize_timeout_without_exit(name, "timeout");
            } else {
                self.arm_service_stop_timeout(name, abort_timeout, ServiceTimeoutPhase::Abort);
            }
        } else {
            self.apply_final_kill(name);
        }
    }

    fn apply_abort_deadline(&mut self, name: &str) {
        if self
            .units
            .get(name)
            .is_some_and(|record| record.state == UnitState::Deactivating)
        {
            self.apply_final_kill(name);
        }
    }

    fn apply_final_kill(&mut self, name: &str) {
        let result = self
            .units
            .get(name)
            .map_or("timeout", |record| match record.service_result.as_str() {
                "watchdog" => "watchdog",
                _ => "timeout",
            })
            .to_owned();
        let sent = self.signal_timeout_operation(name, KillOperation::Kill);
        if sent == 0 {
            self.finalize_timeout_without_exit(name, &result);
        }
    }

    fn cancel_start_timeout(&mut self, name: &str) {
        if let Some(source) = self.start_timeouts.remove(name) {
            let _ = self.event_loop.remove_timer(source);
        }
    }

    fn arm_service_stop_timeout(
        &mut self,
        name: &str,
        timeout: Duration,
        phase: ServiceTimeoutPhase,
    ) {
        self.cancel_stop_timeout(name);
        match arm_service_timeout_event(
            &mut self.event_loop,
            timeout,
            Arc::clone(&self.service_timeout_events),
            name.to_owned(),
            phase,
        ) {
            Ok(source) => {
                self.stop_timeouts.insert(name.to_owned(), source);
            }
            Err(error) => {
                eprintln!("rustd: failed to arm service timeout for '{name}': {error}");
                self.apply_final_kill(name);
            }
        }
    }

    fn cancel_stop_timeout(&mut self, name: &str) {
        if let Some(source) = self.stop_timeouts.remove(name) {
            let _ = self.event_loop.remove_timer(source);
        }
    }

    /// Apply a batch of child exits to the unit registry.
    ///
    /// Called both before and after `run_once` so exits are never lost
    /// regardless of whether they arrived before or during `epoll_wait`.
    #[allow(clippy::too_many_lines)]
    fn apply_child_exits(&mut self, exits: Vec<crate::event::child::ChildExit>) {
        for exit in exits {
            let exit_realtime = clock_now(ClockId::Realtime).ok();
            let exit_monotonic = clock_now(ClockId::Monotonic).ok();
            let mut exited_unit = None;
            for record in self.units.values_mut() {
                let name = record.loaded.name().to_owned();
                let oom_related = self.oom_stopping.contains(&name)
                    || self
                        .oom_recent
                        .get(&name)
                        .is_some_and(|expires| *expires > Instant::now());
                let explicitly_stopping = record.stop_requested && !oom_related;
                let notify_fd = if matches!(
                    &record.loaded,
                    LoadedUnit::Service(service)
                        if effective_notify_access(&service.specific).is_some()
                ) {
                    self.notify.as_ref().map_or(-1, NotifyServer::raw_fd)
                } else {
                    -1
                };
                let cgroup_procs_path = self.cgroup.unit_procs_path(&name);
                let cgroup_procs_path = cgroup_procs_path.exists().then_some(cgroup_procs_path);
                if record.control_pid == Some(exit.pid) {
                    let result = on_forking_control_exit_with_notify_in_cgroup(
                        record,
                        &exit,
                        notify_fd,
                        cgroup_procs_path.as_deref(),
                    );
                    if record.state != UnitState::Activating {
                        if let Some(source) = self.start_timeouts.remove(&name) {
                            let _ = self.event_loop.remove_timer(source);
                        }
                    }
                    if explicitly_stopping {
                        if let Some(source) = self.stop_timeouts.remove(&name) {
                            let _ = self.event_loop.remove_timer(source);
                        }
                    }
                    if let Err(error) = result {
                        eprintln!("rustd: forking start for '{name}' failed: {error}");
                    }
                    if oom_related {
                        record.service_result = "oom-kill".into();
                        if record.state != UnitState::Active {
                            record.state = UnitState::Failed;
                        }
                    }
                    if record.state == UnitState::Failed && !explicitly_stopping {
                        if let Some(restart_sec) = automatic_restart_delay(record, &exit) {
                            let restart_name = name.clone();
                            let restart_queue = Arc::clone(&self.shared_queue);
                            if schedule_restart(&mut self.event_loop, restart_sec, move |_| {
                                if let Ok(mut queue) = restart_queue.lock() {
                                    queue.enqueue_internal(JobKind::Start, restart_name.clone());
                                }
                            })
                            .is_err()
                            {
                                self.job_queue
                                    .enqueue_internal(JobKind::Start, name.clone());
                            }
                        }
                    }
                    exited_unit = Some(name);
                    break;
                }
                if on_child_exit_with_notify_in_cgroup(
                    record,
                    &exit,
                    notify_fd,
                    cgroup_procs_path.as_deref(),
                ) {
                    record.exec_main_exit_realtime_ns = exit_realtime;
                    record.exec_main_exit_monotonic_ns = exit_monotonic;
                    if oom_related {
                        record.service_result = "oom-kill".into();
                        if record.state != UnitState::Active {
                            record.state = UnitState::Failed;
                        }
                    }
                    if record.state == UnitState::Failed && !explicitly_stopping {
                        eprintln!(
                            "rustd: service '{name}' from {} exited unsuccessfully: code={} status={}",
                            record.loaded.source_path().display(),
                            exit.code,
                            exit.status
                        );
                    }
                    if let Some(source) = self.start_timeouts.remove(&name) {
                        let _ = self.event_loop.remove_timer(source);
                    }
                    if let Some(source) = self.stop_timeouts.remove(&name) {
                        let _ = self.event_loop.remove_timer(source);
                    }
                    if let Some(server) = self.notify.as_ref() {
                        server.unregister_pid(exit.pid);
                    }
                    record.watchdog_timestamp_ns = None;
                    record.watchdog_timestamp_realtime_ns = None;
                    record.watchdog_triggered = false;

                    if self.restart_pending.remove(&name) {
                        self.job_queue
                            .enqueue_internal(JobKind::Start, name.clone());
                    } else if !explicitly_stopping {
                        if let Some(restart_sec) = automatic_restart_delay(record, &exit) {
                            let restart_name = name.clone();
                            let restart_queue = Arc::clone(&self.shared_queue);
                            if schedule_restart(&mut self.event_loop, restart_sec, move |_| {
                                if let Ok(mut queue) = restart_queue.lock() {
                                    queue.enqueue_internal(JobKind::Start, restart_name.clone());
                                }
                            })
                            .is_err()
                            {
                                self.job_queue
                                    .enqueue_internal(JobKind::Start, name.clone());
                            }
                        }
                    }
                    exited_unit = Some(name);
                    break;
                }
            }
            if let Some(name) = exited_unit {
                self.set_trigger_sockets_enabled(&name, true);
                // A normal Continue-policy OOM classification applies to the
                // matching child exit only. Stop/Kill policy state remains
                // set until the service cgroup is empty so every process
                // reaped during the manager-driven teardown remains an OOM
                // failure rather than being rewritten as an explicit stop.
                if !self.oom_stopping.contains(&name) {
                    self.oom_recent.remove(&name);
                }
                self.cleanup_unit_cgroup_if_empty(&name);
            }
        }
    }

    fn run_job(&mut self, kind: JobKind, name: &str) -> anyhow::Result<()> {
        if kind == JobKind::Nop {
            return Ok(());
        }
        if kind == JobKind::Restart {
            return self.restart_unit(name);
        }
        if kind == JobKind::Isolate {
            return Err(anyhow!("isolate jobs require transaction context"));
        }

        if self
            .units
            .get(name)
            .is_some_and(|record| matches!(record.loaded, LoadedUnit::Service(_)))
        {
            return self.run_service_job(kind, name);
        }

        let record = self
            .units
            .get_mut(name)
            .ok_or_else(|| anyhow!("unit '{name}' not in registry"))?;

        match kind {
            JobKind::Nop => unreachable!("no-op jobs return before unit dispatch"),
            JobKind::Start => match &record.loaded {
                LoadedUnit::Service(_) => unreachable!("service jobs use run_service_job"),
                LoadedUnit::Socket(_) => {
                    if record.state == UnitState::Inactive || record.state == UnitState::Failed {
                        let socket_record = self.socket_records.entry(name.to_owned()).or_default();
                        activate_socket(
                            record,
                            socket_record,
                            &mut self.event_loop,
                            &self.shared_queue,
                        )?;
                    }
                }
                LoadedUnit::Target(_) => {
                    record.state = UnitState::Activating;
                }
                LoadedUnit::Timer(_) => {
                    crate::timer_unit::activate_timer(
                        record,
                        &mut self.event_loop,
                        &self.shared_queue,
                    )?;
                }
                LoadedUnit::Mount(_) => crate::filesystem_unit::activate_mount(record)?,
                LoadedUnit::Swap(_) => crate::filesystem_unit::activate_swap(record)?,
                LoadedUnit::Path(_) => {
                    let source_id = crate::path_unit::activate_path(
                        record,
                        &mut self.event_loop,
                        &self.shared_queue,
                    )?;
                    self.path_sources.insert(name.to_owned(), source_id);
                }
                LoadedUnit::Automount(_) => {
                    return Err(anyhow!(
                        "automount unit '{name}' cannot start without an autofs mount"
                    ));
                }
                _ => {
                    record.state = UnitState::Active;
                }
            },
            JobKind::Stop => {
                if let LoadedUnit::Socket(_) = &record.loaded {
                    if let Some(socket_record) = self.socket_records.get_mut(name) {
                        deactivate_socket(record, socket_record, &mut self.event_loop);
                    } else {
                        record.state = UnitState::Inactive;
                    }
                } else if matches!(record.loaded, LoadedUnit::Mount(_)) {
                    crate::filesystem_unit::deactivate_mount(record)?;
                } else if matches!(record.loaded, LoadedUnit::Swap(_)) {
                    crate::filesystem_unit::deactivate_swap(record)?;
                } else if matches!(record.loaded, LoadedUnit::Path(_)) {
                    if let Some(source_id) = self.path_sources.remove(name) {
                        self.event_loop.remove_inotify(source_id)?;
                    }
                    record.state = UnitState::Inactive;
                } else {
                    record.state = UnitState::Inactive;
                }
            }
            JobKind::Reload => {
                return Err(anyhow!("unit '{name}' does not support reload"));
            }
            JobKind::Restart => unreachable!("restart jobs expand before unit dispatch"),
            JobKind::Isolate => unreachable!("isolate jobs expand before unit dispatch"),
        }
        Ok(())
    }

    fn run_service_job(&mut self, kind: JobKind, name: &str) -> anyhow::Result<()> {
        let default_timeout = Duration::from_secs(self.config.default_timeout_start_sec);
        let (notify_access, watchdog, start_timeout) = {
            let record = self
                .units
                .get(name)
                .ok_or_else(|| anyhow!("unit '{name}' not in registry"))?;
            let LoadedUnit::Service(service) = &record.loaded else {
                unreachable!("run_service_job requires a service")
            };
            (
                effective_notify_access(&service.specific),
                service.specific.watchdog_sec,
                service
                    .specific
                    .timeout_start_sec
                    .unwrap_or(default_timeout),
            )
        };
        let notify_fd = if notify_access.is_some() {
            self.notify.as_ref().map_or(-1, NotifyServer::raw_fd)
        } else {
            -1
        };

        match kind {
            JobKind::Nop => unreachable!("no-op jobs return before service dispatch"),
            JobKind::Start => {
                self.start_service(name, notify_fd, notify_access, watchdog, start_timeout)
            }
            JobKind::Stop => {
                self.stop_service(name, notify_fd);
                Ok(())
            }
            JobKind::Reload => {
                let record = self
                    .units
                    .get_mut(name)
                    .ok_or_else(|| anyhow!("unit '{name}' not in registry"))?;
                let cgroup_procs_path = self.cgroup.unit_procs_path(name);
                let cgroup_procs_path = cgroup_procs_path.exists().then_some(cgroup_procs_path);
                reload_with_notify_in_cgroup(record, notify_fd, cgroup_procs_path.as_deref())
            }
            JobKind::Restart => unreachable!("restart jobs expand before unit dispatch"),
            JobKind::Isolate => unreachable!("isolate jobs expand before unit dispatch"),
        }
    }

    fn prepare_service_cgroup(
        &mut self,
        name: &str,
    ) -> anyhow::Result<(bool, Option<std::path::PathBuf>)> {
        let requested = self.units.get(name).is_some_and(|record| {
            matches!(
                &record.loaded,
                LoadedUnit::Service(service)
                    if service.specific.resource_control.is_configured()
            )
        });

        let path = match self.cgroup.create_unit_cgroup(name) {
            Ok(path) => path,
            Err(error) => {
                if requested {
                    if let Some(record) = self.units.get_mut(name) {
                        record.state = UnitState::Failed;
                        record.service_result = "resources".into();
                    }
                    return Err(anyhow!(
                        "failed to create cgroup for requested resource controls on '{name}': {error}"
                    ));
                }
                eprintln!("rustd: creating cgroup for '{name}' failed: {error}");
                return Ok((requested, None));
            }
        };

        if let Err(error) = self.ensure_cgroup_event_source(name) {
            eprintln!("rustd: monitoring cgroup hierarchy for '{name}' failed: {error}");
        }
        if let Err(error) = self.ensure_oom_event_source(name) {
            eprintln!("rustd: monitoring cgroup OOM events for '{name}' failed: {error}");
        }
        if let Err(error) = self.apply_service_resource_control(name) {
            self.cleanup_unit_cgroup_if_empty(name);
            if requested {
                if let Some(record) = self.units.get_mut(name) {
                    record.state = UnitState::Failed;
                    record.service_result = "resources".into();
                }
                return Err(anyhow!(
                    "failed to apply requested cgroup resource controls for '{name}': {error}"
                ));
            }
            eprintln!("rustd: applying resource controls for '{name}' failed: {error}");
            return Ok((requested, None));
        }
        if let Err(error) = self.apply_service_oom_group(name) {
            eprintln!("rustd: applying OOM group policy for '{name}' failed: {error}");
        }

        let procs = path.join("cgroup.procs");
        Ok((requested, procs.exists().then_some(procs)))
    }

    fn start_service(
        &mut self,
        name: &str,
        notify_fd: libc::c_int,
        notify_access: Option<NotifyAccess>,
        watchdog: Option<Duration>,
        start_timeout: Duration,
    ) -> anyhow::Result<()> {
        let should_start = self
            .units
            .get(name)
            .is_some_and(|record| matches!(record.state, UnitState::Inactive | UnitState::Failed));
        if !should_start {
            return Ok(());
        }

        self.cancel_start_timeout(name);
        let listen_fds = self.collect_listen_fds_for(name);

        // Mark activation before realizing the cgroup so an empty-hierarchy
        // notification cannot delete the path out from under the spawn helper.
        if let Some(record) = self.units.get_mut(name) {
            record.state = UnitState::Activating;
        }

        let (resource_control_requested, cgroup_procs_path) = self.prepare_service_cgroup(name)?;

        let activation = {
            let record = self
                .units
                .get_mut(name)
                .ok_or_else(|| anyhow!("unit '{name}' not in registry"))?;
            record.status_text = None;
            record.status_errno = None;
            record.last_start_ns = clock_now(ClockId::Monotonic).unwrap_or(0);
            record.exec_main_start_monotonic_ns = Some(record.last_start_ns);
            record.exec_main_start_realtime_ns = clock_now(ClockId::Realtime).ok();
            record.exec_main_exit_realtime_ns = None;
            record.exec_main_exit_monotonic_ns = None;
            record.watchdog_timestamp_ns = None;
            record.watchdog_timestamp_realtime_ns = None;
            record.watchdog_triggered = false;
            record
                .assign_invocation_id()
                .map_err(|error| anyhow!("failed to generate invocation ID: {error}"))?;
            activate_with_notify_in_cgroup(
                record,
                &listen_fds,
                notify_fd,
                cgroup_procs_path.as_deref(),
            )
        };
        if let Err(error) = activation {
            self.cleanup_unit_cgroup_if_empty(name);
            return Err(error);
        }

        let (active_pid, control_pid, state) = self
            .units
            .get(name)
            .map_or((None, None, UnitState::Failed), |record| {
                (record.active_pid, record.control_pid, record.state)
            });
        let Some(pid) = active_pid.or(control_pid) else {
            self.cleanup_unit_cgroup_if_empty(name);
            return Ok(());
        };

        if let (Some(main_pid), Some(access), Some(server)) =
            (active_pid, notify_access, self.notify.as_ref())
        {
            server.register_pid(main_pid, name.to_owned(), access);
        }
        if cgroup_procs_path.is_none() {
            if let Err(error) = self.cgroup.attach_pid(name, pid) {
                if resource_control_requested {
                    if let Some(record) = self.units.get_mut(name) {
                        record.state = UnitState::Failed;
                        record.service_result = "resources".into();
                    }
                    if let Some(server) = self.notify.as_ref() {
                        server.unregister_pid(pid);
                    }
                    // Safety: pid is the service process returned by activation.
                    unsafe {
                        libc::kill(pid, libc::SIGTERM);
                    }
                    return Err(anyhow!(
                        "failed to attach '{name}' to its requested resource-control cgroup: {error}"
                    ));
                }
                eprintln!("rustd: attaching pid {pid} to '{name}' failed: {error}");
            }
        }

        if state == UnitState::Activating {
            let source = arm_service_timeout_event(
                &mut self.event_loop,
                start_timeout,
                Arc::clone(&self.service_timeout_events),
                name.to_owned(),
                ServiceTimeoutPhase::Start,
            )?;
            self.start_timeouts.insert(name.to_owned(), source);
        } else if state == UnitState::Active && watchdog.is_some() {
            if let Some(record) = self.units.get_mut(name) {
                record.watchdog_timestamp_ns = clock_now(ClockId::Monotonic).ok();
                record.watchdog_timestamp_realtime_ns = clock_now(ClockId::Realtime).ok();
            }
        }
        self.set_trigger_sockets_enabled(name, false);
        Ok(())
    }

    fn set_trigger_sockets_enabled(&mut self, service_name: &str, enabled: bool) {
        use crate::socket_unit::triggered_service_name;
        let source_ids: Vec<_> = self
            .socket_records
            .iter()
            .filter_map(|(socket_name, socket_record)| {
                let unit = self.units.get(socket_name)?;
                let LoadedUnit::Socket(socket) = &unit.loaded else {
                    return None;
                };
                (triggered_service_name(socket_name, &socket.specific.service) == service_name)
                    .then_some(socket_record.source_ids.iter().copied())
            })
            .flatten()
            .collect();
        for source_id in source_ids {
            if let Err(error) = self.event_loop.set_io_enabled(source_id, enabled) {
                eprintln!("rustd: changing socket readiness for '{service_name}' failed: {error}");
            }
        }
    }

    fn service_kill_policy(
        &self,
        name: &str,
    ) -> Option<(KillPolicy, Option<libc::pid_t>, Option<libc::pid_t>)> {
        let record = self.units.get(name)?;
        let LoadedUnit::Service(service) = &record.loaded else {
            return None;
        };
        Some((
            KillPolicy::from_service(&service.specific),
            record.active_pid,
            record.control_pid,
        ))
    }

    fn stop_service(&mut self, name: &str, notify_fd: libc::c_int) {
        self.cancel_start_timeout(name);
        self.cancel_stop_timeout(name);
        let old_pid = self
            .units
            .get(name)
            .and_then(|record| record.active_pid.or(record.control_pid));
        let kill_context = self.service_kill_policy(name);
        let operation = if self.restart_pending.contains(name) {
            KillOperation::Restart
        } else {
            KillOperation::Terminate
        };
        let cgroup_procs_path = self.cgroup.unit_procs_path(name);
        let cgroup_procs_path = cgroup_procs_path.exists().then_some(cgroup_procs_path);
        let stopped_without_pid = if let Some(record) = self.units.get_mut(name) {
            record.watchdog_timestamp_ns = None;
            record.watchdog_timestamp_realtime_ns = None;
            record.watchdog_triggered = false;
            deactivate_with_notify_in_cgroup(
                record,
                notify_fd,
                cgroup_procs_path.as_deref(),
                operation,
            );
            record.active_pid.is_none() && record.control_pid.is_none()
        } else {
            true
        };
        if !stopped_without_pid {
            if let Some((policy, main_pid, control_pid)) = kill_context {
                if let Err(error) = signal_cgroup_members(
                    &self.cgroup,
                    name,
                    policy,
                    main_pid,
                    control_pid,
                    operation,
                ) {
                    eprintln!("rustd: signaling cgroup for '{name}' failed: {error}");
                }
            }
        }

        if stopped_without_pid {
            if let (Some(pid), Some(server)) = (old_pid, self.notify.as_ref()) {
                server.unregister_pid(pid);
            }
            if let Some(record) = self.units.get_mut(name) {
                record.watchdog_timestamp_ns = None;
                record.watchdog_timestamp_realtime_ns = None;
                record.watchdog_triggered = false;
            }
        } else if old_pid.is_some() {
            let timeout = self
                .units
                .get(name)
                .and_then(|record| {
                    stop_timeout_for_record(record, self.config.default_timeout_stop_sec)
                })
                .map_or(
                    Duration::from_secs(self.config.default_timeout_stop_sec),
                    |(_, timeout)| timeout,
                );
            self.arm_service_stop_timeout(name, timeout, ServiceTimeoutPhase::Stop);
        }
    }

    fn reload_unit_files(&mut self) {
        let fresh_defaults = crate::config::UnitDefaults::load(self.config.scope);
        if let Ok(mut defaults) = self.config.unit_defaults.write() {
            *defaults = fresh_defaults.clone();
        }
        self.loader = UnitLoader::for_scope(self.config.scope);
        let names: Vec<String> = self.units.keys().cloned().collect();
        for name in names {
            let Ok(mut loaded) = self.loader.load(&name) else {
                continue;
            };
            fresh_defaults.apply_to_loaded_unit(&mut loaded);
            if let Some(record) = self.units.get_mut(&name) {
                record.loaded = loaded;
            }
            if let Err(error) = self.apply_service_resource_control(&name) {
                eprintln!("rustd: applying resource controls for '{name}' failed: {error}");
            }
            if let Err(error) = self.apply_service_oom_group(&name) {
                eprintln!("rustd: applying OOM group policy for '{name}' failed: {error}");
            }
        }
    }

    fn apply_service_resource_control(&self, name: &str) -> anyhow::Result<()> {
        let Some(record) = self.units.get(name) else {
            return Ok(());
        };
        let LoadedUnit::Service(service) = &record.loaded else {
            return Ok(());
        };
        let mut control = service.specific.resource_control.clone();
        if control.tasks_max_default && !self.cgroup.unit_control_available(name, "pids.max") {
            control.tasks_max = None;
        }
        self.cgroup.apply_resource_control(name, &control)
    }

    fn apply_service_oom_group(&self, name: &str) -> anyhow::Result<()> {
        let Some(record) = self.units.get(name) else {
            return Ok(());
        };
        let LoadedUnit::Service(service) = &record.loaded else {
            return Ok(());
        };
        let policy = OomPolicy::resolve(self.config.scope, &service.specific.oom_policy);
        oom::configure_group_kill(&self.cgroup, name, policy == OomPolicy::Kill)
    }

    fn ensure_oom_event_source(&mut self, name: &str) -> anyhow::Result<()> {
        if self.oom_sources.contains_key(name) {
            return Ok(());
        }
        let source = OomEventSource::for_unit(
            &self.cgroup,
            name,
            Arc::clone(&self.oom_events),
            Arc::clone(&self.oom_baselines),
        )?;
        let descriptor = source.raw_fd();
        let events = (libc::EPOLLPRI | libc::EPOLLERR | libc::EPOLLHUP) as u32;
        let source_id = self
            .event_loop
            .add_io(descriptor, events, Box::new(source))?;
        self.oom_sources.insert(name.to_owned(), source_id);
        Ok(())
    }

    fn sync_oom_counters(&mut self) {
        let now = Instant::now();
        self.oom_recent.retain(|_, expires| *expires > now);
        let names: Vec<String> = self.oom_sources.keys().cloned().collect();
        for name in names {
            if let Err(error) =
                oom::sync_unit(&self.cgroup, &name, &self.oom_events, &self.oom_baselines)
            {
                if !is_not_found(&error) {
                    eprintln!("rustd: synchronizing OOM state for '{name}' failed: {error}");
                }
            }
        }
    }

    fn apply_oom_events(&mut self) {
        let pending = {
            let mut events = self
                .oom_events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::take(&mut *events)
        };
        for name in pending {
            let policy = self.units.get(&name).and_then(|record| {
                let LoadedUnit::Service(service) = &record.loaded else {
                    return None;
                };
                Some(OomPolicy::resolve(
                    self.config.scope,
                    &service.specific.oom_policy,
                ))
            });
            let Some(policy) = policy else {
                continue;
            };
            if let Some(record) = self.units.get_mut(&name) {
                record.service_result = "oom-kill".into();
            }
            self.oom_recent
                .insert(name.clone(), Instant::now() + Duration::from_secs(2));
            eprintln!("rustd: service '{name}' observed a cgroup OOM kill (policy={policy:?})");
            match policy {
                OomPolicy::Continue => {}
                OomPolicy::Stop | OomPolicy::Kill => {
                    self.oom_stopping.insert(name.clone());
                    let notify_fd = self.notify.as_ref().map_or(-1, NotifyServer::raw_fd);
                    self.stop_service(&name, notify_fd);
                    if policy == OomPolicy::Kill {
                        if let Err(error) = self.cgroup.signal_unit(&name, libc::SIGKILL, &[]) {
                            eprintln!(
                                "rustd: killing remaining cgroup members for '{name}' after OOM failed: {error}"
                            );
                        }
                    }
                }
            }
        }
    }

    fn ensure_cgroup_event_source(&mut self, name: &str) -> anyhow::Result<()> {
        if self.cgroup_sources.contains_key(name) {
            return Ok(());
        }
        let source = self
            .cgroup
            .event_source(name, Arc::clone(&self.cgroup_empty_events))?;
        let descriptor = source.raw_fd();
        let events = (libc::EPOLLPRI | libc::EPOLLERR | libc::EPOLLHUP) as u32;
        let source_id = self
            .event_loop
            .add_io(descriptor, events, Box::new(source))?;
        self.cgroup_sources.insert(name.to_owned(), source_id);
        Ok(())
    }

    fn cleanup_empty_cgroups(&mut self) {
        let pending = {
            let mut guard = self
                .cgroup_empty_events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::take(&mut *guard)
        };
        for name in pending {
            let cgroup_procs_path = self.cgroup.unit_procs_path(&name);
            let cgroup_procs_path = cgroup_procs_path.exists().then_some(cgroup_procs_path);
            let notify_fd = self.notify.as_ref().map_or(-1, NotifyServer::raw_fd);
            let mut restart_delay = None;
            if let Some(record) = self.units.get_mut(&name) {
                let completed_cgroup_exit = on_service_cgroup_empty_with_notify_in_cgroup(
                    record,
                    notify_fd,
                    cgroup_procs_path.as_deref(),
                );
                if !completed_cgroup_exit
                    && !on_timeout_cgroup_empty_with_notify_in_cgroup(
                        record,
                        notify_fd,
                        cgroup_procs_path.as_deref(),
                    )
                {
                    on_forking_cgroup_empty_with_notify_in_cgroup(
                        record,
                        notify_fd,
                        cgroup_procs_path.as_deref(),
                    );
                }
                if completed_cgroup_exit && !record.stop_requested {
                    let exit = crate::event::child::ChildExit {
                        pid: 0,
                        code: record.exec_main_code,
                        status: record.exec_main_status,
                    };
                    restart_delay = automatic_restart_delay(record, &exit);
                }
            }
            if let Some(delay) = restart_delay {
                let restart_name = name.clone();
                let restart_queue = Arc::clone(&self.shared_queue);
                if schedule_restart(&mut self.event_loop, delay, move |_| {
                    if let Ok(mut queue) = restart_queue.lock() {
                        queue.enqueue_internal(JobKind::Start, restart_name.clone());
                    }
                })
                .is_err()
                {
                    self.job_queue
                        .enqueue_internal(JobKind::Start, name.clone());
                }
            }
            self.cleanup_unit_cgroup_if_empty(&name);
        }
    }

    fn cleanup_unit_cgroup_if_empty(&mut self, name: &str) {
        // An activating service creates its cgroup before the helper moves into
        // it. Treating that still-empty hierarchy as garbage deletes the path
        // the helper is about to open and every subsequent spawn fails with
        // ENOENT.
        if self
            .units
            .get(name)
            .is_some_and(unit_cgroup_must_remain_realized)
        {
            return;
        }

        match self.cgroup.is_unit_populated(name) {
            Ok(true) => {}
            Ok(false) => {
                if let Some(source) = self.cgroup_sources.remove(name) {
                    let _ = self.event_loop.remove_io(source);
                }
                if let Some(source) = self.oom_sources.remove(name) {
                    let _ = self.event_loop.remove_io(source);
                }
                oom::remove_baseline(name, &self.oom_baselines);
                self.oom_stopping.remove(name);
                self.oom_recent.remove(name);
                if let Err(error) = self.cgroup.remove_unit_cgroup(name) {
                    eprintln!("rustd: removing empty cgroup for '{name}' failed: {error}");
                    if let Err(register_error) = self.ensure_cgroup_event_source(name) {
                        eprintln!(
                            "rustd: restoring cgroup monitor for '{name}' failed: {register_error}"
                        );
                    }
                    if let Err(register_error) = self.ensure_oom_event_source(name) {
                        eprintln!(
                            "rustd: restoring OOM monitor for '{name}' failed: {register_error}"
                        );
                    }
                }
            }
            Err(error) if is_not_found(&error) => {
                if let Some(source) = self.cgroup_sources.remove(name) {
                    let _ = self.event_loop.remove_io(source);
                }
                if let Some(source) = self.oom_sources.remove(name) {
                    let _ = self.event_loop.remove_io(source);
                }
                oom::remove_baseline(name, &self.oom_baselines);
                self.oom_stopping.remove(name);
                self.oom_recent.remove(name);
            }
            Err(error) => {
                eprintln!("rustd: reading cgroup state for '{name}' failed: {error}");
            }
        }
    }

    /// Start a unit again only after its current process has deactivated.
    fn restart_unit(&mut self, name: &str) -> anyhow::Result<()> {
        self.load_unit(name)?;
        let is_service = self
            .units
            .get(name)
            .is_some_and(|record| matches!(record.loaded, LoadedUnit::Service(_)));

        if !is_service {
            self.run_job(JobKind::Stop, name)?;
            return self.run_job(JobKind::Start, name);
        }

        let state = self
            .units
            .get(name)
            .map_or(UnitState::Inactive, |record| record.state);
        if matches!(
            state,
            UnitState::Inactive | UnitState::Failed | UnitState::Maintenance
        ) {
            return self.run_job(JobKind::Start, name);
        }

        self.restart_pending.insert(name.to_owned());
        if state != UnitState::Deactivating {
            self.run_job(JobKind::Stop, name)?;
        }

        let waiting_for_process = self
            .units
            .get(name)
            .is_some_and(|record| record.active_pid.is_some() || record.control_pid.is_some());
        if !waiting_for_process {
            self.restart_pending.remove(name);
            self.run_job(JobKind::Start, name)?;
        }
        Ok(())
    }

    /// Expand an isolate request into one stop/start transaction.
    fn enqueue_isolate(&mut self, job_id: u32, target: &str) -> anyhow::Result<()> {
        self.load_unit(target)?;

        let target_record = self
            .units
            .get(target)
            .ok_or_else(|| anyhow!("unit '{target}' not in registry"))?;
        if !matches!(target_record.loaded, LoadedUnit::Target(_)) {
            return Err(anyhow!("unit '{target}' is not a target"));
        }
        if !target_record.loaded.unit_section().allow_isolate {
            return Err(anyhow!("unit '{target}' does not permit isolation"));
        }

        let known: HashMap<String, DepUnit<'_>> = self
            .units
            .iter()
            .map(|(name, record)| {
                (
                    name.clone(),
                    DepUnit {
                        loaded: &record.loaded,
                        state: record.state,
                    },
                )
            })
            .collect();
        let loader = &self.loader;
        let start_order = resolve_start_order(target, &known, |name| loader.load(name).ok())?;

        for name in &start_order {
            if !self.units.contains_key(name) {
                if let Ok(loaded) = self.loader.load(name) {
                    let record = self.new_unit_record(loaded);
                    self.units.insert(name.clone(), record);
                }
            }
        }

        let mut keep: HashSet<String> = start_order.iter().cloned().collect();
        keep.extend(
            self.units
                .iter()
                .filter(|(_, record)| record.loaded.unit_section().ignore_on_isolate)
                .map(|(name, _)| name.clone()),
        );
        if job_id != 0 {
            self.isolate_jobs.insert(job_id, keep.clone());
        }
        if let Some(record) = self.units.get_mut(target) {
            record.state = UnitState::Activating;
        }

        let stop_order: Vec<String> = self
            .units
            .iter()
            .filter(|(name, record)| {
                !keep.contains(name.as_str())
                    && matches!(
                        record.state,
                        UnitState::Active | UnitState::Activating | UnitState::Failed
                    )
            })
            .map(|(name, _)| name.clone())
            .collect();

        for name in stop_order {
            self.job_queue.enqueue_internal(JobKind::Stop, name);
        }
        for name in start_order {
            self.job_queue.enqueue_internal(JobKind::Start, name);
        }
        Ok(())
    }

    /// Collect all open listener fds from socket units that trigger `svc_name`.
    ///
    /// A socket unit triggers a service if its derived or explicit `Service=`
    /// name matches `svc_name`.
    fn collect_listen_fds_for(&self, svc_name: &str) -> Vec<libc::c_int> {
        use crate::socket_unit::triggered_service_name;
        let mut fds = Vec::new();
        for (sock_name, sock_rec) in &self.socket_records {
            if let Some(unit_rec) = self.units.get(sock_name) {
                if let LoadedUnit::Socket(ref s) = unit_rec.loaded {
                    let triggered = triggered_service_name(sock_name, &s.specific.service);
                    if triggered == svc_name {
                        #[allow(clippy::cast_possible_truncation)]
                        fds.extend(sock_rec.listen_fds.iter().map(|&fd| fd as libc::c_int));
                    }
                }
            }
        }
        fds
    }

    fn is_idle(&self) -> bool {
        let shared_idle = self.shared_queue.lock().is_ok_and(|queue| queue.is_empty());
        let unit_load_idle = self
            .unit_load_requests
            .lock()
            .is_ok_and(|requests| requests.is_empty());
        self.job_queue.is_empty()
            && shared_idle
            && unit_load_idle
            && self.job_registry.is_empty()
            && self.all_settled()
    }

    /// True when all units are in a stable state (no Activating/Deactivating).
    fn all_settled(&self) -> bool {
        self.units
            .values()
            .all(|r| !matches!(r.state, UnitState::Activating | UnitState::Deactivating))
    }

    /// Build a fresh `Vec<UnitInfo>` snapshot, publish it to the IPC server,
    /// and emit `UnitNew`/`UnitRemoved` D-Bus signals for any changes.
    fn publish_snapshot(&mut self) {
        let snap: Vec<UnitInfo> = self.units.values().map(unit_record_to_info).collect();

        // Publish first so a D-Bus UnitNew consumer can register the object
        // from the same snapshot before the signal is emitted.
        if let Ok(mut guard) = self.unit_snapshot.write() {
            guard.clone_from(&snap);
        }

        // Diff against previous snapshot to emit D-Bus change signals.
        if let Some(ref tx) = self.signal_tx {
            let new_names: std::collections::HashSet<&str> =
                snap.iter().map(|u| u.name.as_str()).collect();
            let old_names: std::collections::HashSet<&str> =
                self.prev_snapshot.iter().map(String::as_str).collect();

            for name in new_names.difference(&old_names) {
                use crate::dbus::manager_iface::unit_path;
                let path = unit_path(name).map_or_else(|_| "/".into(), |p| p.as_str().to_owned());
                let _ = tx.send(ManagerSignal::UnitNew {
                    id: (*name).to_owned(),
                    path,
                });
            }
            for name in old_names.difference(&new_names) {
                use crate::dbus::manager_iface::unit_path;
                let path = unit_path(name).map_or_else(|_| "/".into(), |p| p.as_str().to_owned());
                let _ = tx.send(ManagerSignal::UnitRemoved {
                    id: (*name).to_owned(),
                    path,
                });
            }
        }

        self.prev_snapshot = snap.iter().map(|u| u.name.clone()).collect();
    }
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

fn reset_failed_record(record: &mut UnitRecord) {
    if matches!(record.state, UnitState::Failed | UnitState::Maintenance) {
        record.state = UnitState::Inactive;
    }
    record.restart_count = 0;
    record.last_start_ns = 0;
    record.start_limit_window_ns = 0;
    record.start_limit_count = 0;
    record.watchdog_triggered = false;
    record.service_result = "success".to_owned();
    record.exec_main_code = 0;
    record.exec_main_status = 0;
}

fn unit_cgroup_must_remain_realized(record: &UnitRecord) -> bool {
    matches!(
        record.state,
        UnitState::Activating
            | UnitState::Deactivating
            | UnitState::Failed
            | UnitState::Maintenance
    ) || record.active_pid.is_some()
        || record.control_pid.is_some()
}

fn automatic_restart_delay(
    record: &mut UnitRecord,
    exit: &crate::event::child::ChildExit,
) -> Option<Duration> {
    let now_ns = clock_now(ClockId::Monotonic).unwrap_or(0);
    automatic_restart_delay_at(record, exit, now_ns)
}

fn automatic_restart_delay_at(
    record: &mut UnitRecord,
    exit: &crate::event::child::ChildExit,
    now_ns: i64,
) -> Option<Duration> {
    let LoadedUnit::Service(service) = &record.loaded else {
        return None;
    };
    let section = &service.specific;
    if !restart_requested(section, exit, &record.service_result) {
        return None;
    }

    let next_restart = record.restart_count.saturating_add(1);
    let unit_sec = record.loaded.unit_section();
    // Match systemd's defaults when the unit does not set its own limit.
    let burst = unit_sec.start_limit_burst.unwrap_or(5);
    let interval = unit_sec
        .start_limit_interval_sec
        .unwrap_or(Duration::from_secs(10));
    if burst > 0 && !interval.is_zero() {
        let interval_ns = i64::try_from(interval.as_nanos()).unwrap_or(i64::MAX);
        if record.start_limit_window_ns == 0
            || now_ns.saturating_sub(record.start_limit_window_ns) >= interval_ns
        {
            record.start_limit_window_ns = now_ns;
            record.start_limit_count = 0;
        }
        let next_start = record.start_limit_count.saturating_add(1);
        if next_start > burst {
            eprintln!(
                "rustd: start limit hit for '{}': {} starts within {:?}",
                record.loaded.name(),
                burst,
                interval
            );
            record.state = UnitState::Failed;
            record.service_result = "start-limit-hit".into();
            return None;
        }
        record.start_limit_count = next_start;
    }

    let delay = restart_delay_for(section, next_restart);
    record.restart_count = next_restart;
    Some(delay)
}

fn restart_delay_for(section: &ServiceSection, next_restart: u32) -> Duration {
    let initial = section.restart_sec.unwrap_or(Duration::from_millis(100));
    let steps = section.restart_steps.unwrap_or(0);
    let Some(maximum) = section.restart_max_delay_sec else {
        return initial;
    };

    if next_restart <= 1 || steps == 0 || initial.is_zero() || initial >= maximum {
        return initial;
    }
    if next_restart > steps {
        return maximum;
    }

    let initial_seconds = initial.as_secs_f64();
    let maximum_seconds = maximum.as_secs_f64();
    let exponent = f64::from(next_restart - 1) / f64::from(steps);
    let seconds = initial_seconds * (maximum_seconds / initial_seconds).powf(exponent);
    Duration::from_secs_f64(seconds.min(maximum_seconds))
}

fn stop_timeout_for_record(
    record: &UnitRecord,
    default_timeout_stop_sec: u64,
) -> Option<(libc::pid_t, Duration)> {
    let pid = record.active_pid.or(record.control_pid)?;
    let timeout = match &record.loaded {
        LoadedUnit::Service(service) => service.specific.timeout_stop_sec,
        _ => None,
    }
    .unwrap_or(Duration::from_secs(default_timeout_stop_sec));
    Some((pid, timeout))
}

fn watchdog_interval_ns(record: &UnitRecord) -> Option<i64> {
    let LoadedUnit::Service(service) = &record.loaded else {
        return None;
    };
    service
        .specific
        .watchdog_sec
        .map(|duration| i64::try_from(duration.as_nanos()).unwrap_or(i64::MAX))
}

fn is_not_found(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|source| source.kind() == std::io::ErrorKind::NotFound)
}

fn set_unit_property_is_resource(property: &SetUnitProperty) -> bool {
    !matches!(property, SetUnitProperty::Description(_))
}

fn validate_set_unit_properties(
    loaded: &LoadedUnit,
    properties: &[SetUnitProperty],
) -> Result<(), SetUnitPropertiesError> {
    for property in properties {
        if matches!(property, SetUnitProperty::Description(_)) {
            continue;
        }
        if !matches!(loaded, LoadedUnit::Service(_)) {
            let name = match property {
                SetUnitProperty::IoAccounting(_) => "IOAccounting",
                SetUnitProperty::MemoryAccounting(_) => "MemoryAccounting",
                SetUnitProperty::TasksAccounting(_) => "TasksAccounting",
                SetUnitProperty::IpAccounting(_) => "IPAccounting",
                SetUnitProperty::CpuWeight(_) => "CPUWeight",
                SetUnitProperty::CpuQuota(_) => "CPUQuotaPerSecUSec",
                SetUnitProperty::IoWeight(_) => "IOWeight",
                SetUnitProperty::MemoryMin(_) => "MemoryMin",
                SetUnitProperty::MemoryLow(_) => "MemoryLow",
                SetUnitProperty::MemoryHigh(_) => "MemoryHigh",
                SetUnitProperty::MemoryMax(_) => "MemoryMax",
                SetUnitProperty::MemorySwapMax(_) => "MemorySwapMax",
                SetUnitProperty::MemoryZSwapMax(_) => "MemoryZSwapMax",
                SetUnitProperty::MemoryZSwapWriteback(_) => "MemoryZSwapWriteback",
                SetUnitProperty::TasksMax(_) => "TasksMax",
                SetUnitProperty::Description(_) => unreachable!(),
            };
            return Err(SetUnitPropertiesError::PropertyReadOnly(format!(
                "Cannot set property {name}, or unknown property."
            )));
        }
    }
    Ok(())
}

/// Convert a `UnitRecord` to the IPC-visible `UnitInfo` type.
#[must_use]
pub fn unit_record_to_info(r: &crate::service::UnitRecord) -> UnitInfo {
    let unit_type = match &r.loaded {
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
    };
    let active_state = match r.state {
        UnitState::Inactive => "inactive",
        UnitState::Activating => "activating",
        UnitState::Active => "active",
        UnitState::Deactivating => "deactivating",
        UnitState::Failed => "failed",
        UnitState::Maintenance => "maintenance",
    };
    let (service_type, restart_policy, bus_name) = if let LoadedUnit::Service(svc) = &r.loaded {
        let stype = match svc.specific.service_type {
            ServiceType::Simple => "simple",
            ServiceType::Exec => "exec",
            ServiceType::Forking => "forking",
            ServiceType::Oneshot => "oneshot",
            ServiceType::Dbus => "dbus",
            ServiceType::Notify => "notify",
            ServiceType::NotifyReload => "notify-reload",
            ServiceType::Idle => "idle",
        };
        let rpol = match svc.specific.restart {
            RestartPolicy::No => "no",
            RestartPolicy::OnSuccess => "on-success",
            RestartPolicy::OnFailure => "on-failure",
            RestartPolicy::OnAbnormal => "on-abnormal",
            RestartPolicy::OnWatchdog => "on-watchdog",
            RestartPolicy::OnAbort => "on-abort",
            RestartPolicy::Always => "always",
        };
        let bus_name = (!svc.specific.bus_name.is_empty()).then(|| svc.specific.bus_name.clone());
        (Some(stype.to_owned()), Some(rpol.to_owned()), bus_name)
    } else {
        (None, None, None)
    };
    UnitInfo {
        name: r.loaded.name().to_owned(),
        load_state: "loaded".into(),
        active_state: active_state.into(),
        sub_state: active_state.into(),
        description: r.loaded.unit_section().description.clone(),
        main_pid: r.active_pid,
        unit_type: unit_type.into(),
        service_type,
        restart_policy,
        service_runtime: Box::new(ServiceRuntimeInfo {
            invocation_id: r.invocation_id,
            restart_count: r.restart_count,
            bus_name,
            control_pid: r.control_pid,
            status_text: r.status_text.clone(),
            status_errno: r.status_errno,
            watchdog_timestamp_ns: r.watchdog_timestamp_ns,
            watchdog_timestamp_realtime_ns: r.watchdog_timestamp_realtime_ns,
            exec_main_start_realtime_ns: r.exec_main_start_realtime_ns,
            exec_main_start_monotonic_ns: r.exec_main_start_monotonic_ns,
            exec_main_exit_realtime_ns: r.exec_main_exit_realtime_ns,
            exec_main_exit_monotonic_ns: r.exec_main_exit_monotonic_ns,
            result: r.service_result.clone(),
            exec_main_code: r.exec_main_code,
            exec_main_status: r.exec_main_status,
            dynamic_user: r.dynamic_user.as_ref().map(|identity| DynamicUserInfo {
                uid: identity.uid,
                name: identity.name.clone(),
            }),
            file_descriptor_store_max: match &r.loaded {
                LoadedUnit::Service(service) => service.specific.file_descriptor_store_max,
                _ => 0,
            },
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dbus::manager_iface::manager_environment_modify;
    use crate::unit::loader::UnitLoader;
    use std::io::Write;
    use tempfile::NamedTempFile;

    static MANAGER_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn manager_new_succeeds() {
        let _manager_test_guard = MANAGER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let m = Manager::new(ManagerConfig::default_system());
        assert!(m.is_ok());
    }

    #[test]
    fn daemon_reload_increments_the_shared_reload_counter() {
        let _manager_test_guard = MANAGER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut manager = Manager::new(ManagerConfig::default_system()).unwrap();
        assert_eq!(manager.reload_count.load(Ordering::Acquire), 0);

        manager.reload_requested.store(true, Ordering::Release);
        assert_eq!(manager.run_until_idle().unwrap(), LoopResult::Exit);
        assert_eq!(manager.reload_count.load(Ordering::Acquire), 1);

        manager.reload_requested.store(true, Ordering::Release);
        assert_eq!(manager.run_until_idle().unwrap(), LoopResult::Exit);
        assert_eq!(manager.reload_count.load(Ordering::Acquire), 2);

        manager.reload_count.store(u64::MAX, Ordering::Release);
        manager.reload_requested.store(true, Ordering::Release);
        assert_eq!(manager.run_until_idle().unwrap(), LoopResult::Exit);
        assert_eq!(manager.reload_count.load(Ordering::Acquire), u64::MAX);
    }

    #[test]
    fn shutdown_start_timestamp_is_captured_once_at_lifecycle_transition() {
        let _manager_test_guard = MANAGER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut manager = Manager::new(ManagerConfig::default_system()).unwrap();
        assert_eq!(
            manager.shutdown_start_realtime_ns.load(Ordering::Acquire),
            0
        );
        assert_eq!(
            manager.shutdown_start_monotonic_ns.load(Ordering::Acquire),
            0
        );

        manager
            .shutdown_action
            .store(SHUTDOWN_REBOOT, Ordering::Release);
        assert_eq!(
            manager.requested_lifecycle_result(),
            Some(LoopResult::Reboot)
        );
        let realtime = manager.shutdown_start_realtime_ns.load(Ordering::Acquire);
        let monotonic = manager.shutdown_start_monotonic_ns.load(Ordering::Acquire);
        assert!(realtime > 0);
        assert!(monotonic > 0);

        manager
            .shutdown_action
            .store(SHUTDOWN_HALT, Ordering::Release);
        assert_eq!(manager.requested_lifecycle_result(), Some(LoopResult::Halt));
        assert_eq!(
            manager.shutdown_start_realtime_ns.load(Ordering::Acquire),
            realtime
        );
        assert_eq!(
            manager.shutdown_start_monotonic_ns.load(Ordering::Acquire),
            monotonic
        );
    }

    #[test]
    fn exit_code_is_shared_with_the_manager_lifecycle_state() {
        let _manager_test_guard = MANAGER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let manager = Manager::new(ManagerConfig::default_system()).unwrap();

        assert_eq!(manager.exit_code(), 0);
        manager.exit_code.store(73, Ordering::Release);
        assert_eq!(manager.exit_code(), 73);
    }

    #[test]
    fn manager_environment_updates_are_inherited_by_new_service_launches() {
        let _manager_test_guard = MANAGER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let units = tempfile::tempdir().unwrap();
        let first = units.path().join("first-environment");
        let second = units.path().join("second-environment");
        let command = |output: &std::path::Path| {
            format!(
                "/bin/sh -c 'printf \"%%s|%%s\" \"${{RUSTD_MANAGER_ENV_TEST-unset}}\" \"$RUSTD_UNIT_ENV_TEST\" > {}'",
                output.display()
            )
        };
        for (name, output) in [
            ("first-environment.service", &first),
            ("second-environment.service", &second),
        ] {
            std::fs::write(
                units.path().join(name),
                format!(
                    "[Service]\nType=oneshot\nStandardOutput=null\nStandardError=null\nEnvironment=RUSTD_UNIT_ENV_TEST=unit\nExecStart={}\n",
                    command(output)
                ),
            )
            .unwrap();
        }

        let mut manager = Manager::new(ManagerConfig::default_system()).unwrap();
        manager.loader = UnitLoader::with_dirs(vec![units.path().to_path_buf()]);
        manager.load_unit("first-environment.service").unwrap();
        manager.load_unit("second-environment.service").unwrap();

        manager_environment_modify(
            &manager.environment,
            &[],
            &[
                "RUSTD_MANAGER_ENV_TEST=from-manager".into(),
                "RUSTD_UNIT_ENV_TEST=manager".into(),
            ],
        )
        .unwrap();
        manager
            .run_service_job(JobKind::Start, "first-environment.service")
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(&first).unwrap(),
            "from-manager|unit"
        );

        manager_environment_modify(
            &manager.environment,
            &[
                "RUSTD_MANAGER_ENV_TEST".into(),
                "RUSTD_UNIT_ENV_TEST".into(),
            ],
            &[],
        )
        .unwrap();
        manager
            .run_service_job(JobKind::Start, "second-environment.service")
            .unwrap();
        assert_eq!(std::fs::read_to_string(&second).unwrap(), "unset|unit");
    }

    #[test]
    fn load_journald_service() {
        let _manager_test_guard = MANAGER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut m = Manager::new(ManagerConfig::default_system()).unwrap();
        // Skip if system unit file not present.
        if m.load_unit("systemd-journald.service").is_err() {
            return;
        }
        assert!(m.units.contains_key("systemd-journald.service"));
    }

    #[test]
    fn dbus_unit_load_requests_use_the_manager_loader_and_publish_snapshot() {
        let _manager_test_guard = MANAGER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let units = tempfile::tempdir().unwrap();
        std::fs::write(
            units.path().join("on-demand.service"),
            "[Unit]\nDescription=On-demand unit\n[Service]\nType=oneshot\nStandardOutput=null\nStandardError=null\nExecStart=/bin/true\n",
        )
        .unwrap();

        let mut manager = Manager::new(ManagerConfig::default_system()).unwrap();
        manager.loader = UnitLoader::with_dirs(vec![units.path().to_path_buf()]);
        let (reply, response) = tokio::sync::oneshot::channel();
        manager
            .unit_load_requests
            .lock()
            .unwrap()
            .push(UnitLoadRequest {
                name: "on-demand.service".to_owned(),
                reply,
            });

        manager.apply_unit_load_requests();
        let info = response.blocking_recv().unwrap().unwrap();
        assert_eq!(info.name, "on-demand.service");
        assert_eq!(info.description, "On-demand unit");
        assert_eq!(info.load_state, "loaded");
        assert_eq!(info.active_state, "inactive");
        assert!(manager.units.contains_key("on-demand.service"));
        assert!(manager
            .unit_snapshot
            .read()
            .unwrap()
            .iter()
            .any(|unit| unit.name == "on-demand.service"));

        let (reply, response) = tokio::sync::oneshot::channel();
        manager
            .unit_load_requests
            .lock()
            .unwrap()
            .push(UnitLoadRequest {
                name: "missing.service".to_owned(),
                reply,
            });
        manager.apply_unit_load_requests();
        assert!(response.blocking_recv().unwrap().is_none());
        assert!(!manager.units.contains_key("missing.service"));
    }

    #[test]
    fn target_start_job_reaches_active_and_completes() {
        let _manager_test_guard = MANAGER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("test.target"),
            "[Unit]\nDescription=Test Target\n",
        )
        .unwrap();

        let mut manager = Manager::new(ManagerConfig::default_system()).unwrap();
        manager.loader = UnitLoader::with_dirs(vec![dir.path().to_path_buf()]);
        manager.load_unit("test.target").unwrap();
        let job = manager.job_queue.enqueue(JobKind::Start, "test.target");

        assert_eq!(manager.run_until_idle().unwrap(), LoopResult::Exit);
        assert_eq!(manager.units["test.target"].state, UnitState::Active);
        assert!(!manager.job_registry.is_live(job.id));
    }

    #[test]
    fn unsupported_automount_does_not_fake_active_while_slices_activate() {
        let _manager_test_guard = MANAGER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("srv-data.automount"), "[Automount]\n").unwrap();
        std::fs::write(
            dir.path().join("srv-data.mount"),
            "[Mount]\nWhere=/srv/data\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("batch.slice"), "[Slice]\n").unwrap();

        let mut manager = Manager::new(ManagerConfig::default_system()).unwrap();
        manager.loader = UnitLoader::with_dirs(vec![dir.path().to_path_buf()]);

        manager.load_unit("srv-data.automount").unwrap();
        manager.load_unit("-.slice").unwrap();
        manager.load_unit("batch.slice").unwrap();
        let error = manager
            .run_job(JobKind::Start, "srv-data.automount")
            .unwrap_err();
        assert!(error.to_string().contains("without an autofs mount"));
        manager.run_job(JobKind::Start, "-.slice").unwrap();
        manager.run_job(JobKind::Start, "batch.slice").unwrap();
        assert_ne!(manager.units["srv-data.automount"].state, UnitState::Active);
        assert_eq!(manager.units["batch.slice"].state, UnitState::Active);
        assert_eq!(manager.units["-.slice"].state, UnitState::Active);
        assert_eq!(
            unit_record_to_info(&manager.units["srv-data.automount"]).unit_type,
            "automount"
        );
    }

    #[test]
    fn service_snapshot_publishes_control_pid() {
        let _manager_test_guard = MANAGER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut record = crate::service::UnitRecord::new(
            UnitLoader::with_dirs(vec![])
                .load("definitely-missing.service")
                .err()
                .map(|_| {
                    LoadedUnit::Service(Box::new(crate::unit::loader::ParsedUnit {
                        name: "control.service".into(),
                        source_path: std::path::PathBuf::new(),
                        unit: crate::unit::section_unit::UnitSection::default(),
                        install: crate::unit::section_install::InstallSection::default(),
                        specific: ServiceSection::default(),
                    }))
                })
                .unwrap(),
        );
        record.control_pid = Some(4321);
        let info = unit_record_to_info(&record);
        assert_eq!(info.service_runtime.control_pid, Some(4321));
    }

    #[test]
    fn service_snapshot_publishes_realized_dynamic_user() {
        let temporary = tempfile::tempdir().unwrap();
        let loaded = LoadedUnit::Service(Box::new(crate::unit::loader::ParsedUnit {
            name: "dynamic.service".into(),
            source_path: std::path::PathBuf::new(),
            unit: crate::unit::section_unit::UnitSection::default(),
            install: crate::unit::section_install::InstallSection::default(),
            specific: ServiceSection::default(),
        }));
        let mut record = UnitRecord::new(loaded);
        record.dynamic_user = Some(
            crate::dynamic_user::DynamicUser::allocate_in("dynamic.service", temporary.path())
                .unwrap(),
        );

        let info = unit_record_to_info(&record);
        assert_eq!(
            info.service_runtime.dynamic_user,
            Some(DynamicUserInfo {
                uid: crate::dynamic_user::DYNAMIC_UID_MIN,
                name: "dynamic.service".into(),
            })
        );
    }

    #[test]
    fn service_snapshot_publishes_descriptor_store_limit() {
        let service = ServiceSection {
            file_descriptor_store_max: 4,
            ..Default::default()
        };
        let loaded = LoadedUnit::Service(Box::new(crate::unit::loader::ParsedUnit {
            name: "descriptor-store.service".into(),
            source_path: std::path::PathBuf::new(),
            unit: crate::unit::section_unit::UnitSection::default(),
            install: crate::unit::section_install::InstallSection::default(),
            specific: service,
        }));

        let info = unit_record_to_info(&UnitRecord::new(loaded));
        assert_eq!(info.service_runtime.file_descriptor_store_max, 4);
    }

    #[test]
    fn reset_failed_record_clears_failure_runtime_state() {
        let loaded = LoadedUnit::Service(Box::new(crate::unit::loader::ParsedUnit {
            name: "reset.service".into(),
            source_path: std::path::PathBuf::new(),
            unit: crate::unit::section_unit::UnitSection::default(),
            install: crate::unit::section_install::InstallSection::default(),
            specific: ServiceSection::default(),
        }));
        let mut record = UnitRecord::new(loaded);
        record.state = UnitState::Failed;
        record.restart_count = 4;
        record.last_start_ns = 7;
        record.watchdog_triggered = true;
        record.service_result = "exit-code".into();
        record.exec_main_code = 1;
        record.exec_main_status = 42;
        assert!(unit_cgroup_must_remain_realized(&record));

        reset_failed_record(&mut record);

        assert!(!unit_cgroup_must_remain_realized(&record));
        assert_eq!(record.state, UnitState::Inactive);
        assert_eq!(record.restart_count, 0);
        assert_eq!(record.last_start_ns, 0);
        assert!(!record.watchdog_triggered);
        assert_eq!(record.service_result, "success");
        assert_eq!(record.exec_main_code, 0);
        assert_eq!(record.exec_main_status, 0);
    }

    #[test]
    fn pending_forking_pidfile_forces_short_poll_interval() {
        let _manager_test_guard = MANAGER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut manager = Manager::new(ManagerConfig::default_system()).unwrap();
        let loaded = LoadedUnit::Service(Box::new(crate::unit::loader::ParsedUnit {
            name: "late.service".into(),
            source_path: std::path::PathBuf::new(),
            unit: crate::unit::section_unit::UnitSection::default(),
            install: crate::unit::section_install::InstallSection::default(),
            specific: ServiceSection {
                service_type: ServiceType::Forking,
                pid_file: "/run/late.pid".into(),
                ..Default::default()
            },
        }));
        let mut record = UnitRecord::new(loaded);
        record.state = UnitState::Activating;
        record.control_pid = None;
        record.active_pid = None;
        manager.units.insert("late.service".into(), record);
        assert!(manager.next_poll_timeout_ms() <= 50);
    }

    #[test]
    fn manual_stop_arms_stop_timeout() {
        let _manager_test_guard = MANAGER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut manager = Manager::new(ManagerConfig::default_system()).unwrap();
        let loaded = LoadedUnit::Service(Box::new(crate::unit::loader::ParsedUnit {
            name: "stop-timeout.service".into(),
            source_path: std::path::PathBuf::new(),
            unit: crate::unit::section_unit::UnitSection::default(),
            install: crate::unit::section_install::InstallSection::default(),
            specific: ServiceSection {
                timeout_stop_sec: Some(Duration::from_millis(20)),
                ..Default::default()
            },
        }));
        let mut record = UnitRecord::new(loaded);
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe {
                libc::signal(libc::SIGTERM, libc::SIG_IGN);
                loop {
                    libc::pause();
                }
            }
        }
        record.active_pid = Some(pid);
        record.state = UnitState::Active;
        manager.units.insert("stop-timeout.service".into(), record);

        manager.stop_service("stop-timeout.service", -1);
        assert!(manager.stop_timeouts.contains_key("stop-timeout.service"));

        // The low-level timeout tests exercise the real SIGKILL deadline with
        // a SIGTERM-resistant child. This manager-level regression verifies
        // ownership bookkeeping independently of the global SIGCHLD reaper.
        manager.apply_child_exits(vec![crate::event::child::ChildExit {
            pid,
            code: libc::CLD_KILLED,
            status: libc::SIGKILL,
        }]);
        assert!(!manager.stop_timeouts.contains_key("stop-timeout.service"));

        // Safety: the synthetic exit above does not reap the actual test child.
        unsafe { libc::kill(pid, libc::SIGKILL) };
        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
    }

    #[test]
    fn automatic_restart_waits_for_restart_timer() {
        let _manager_test_guard = MANAGER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("restart-delay.service"),
            "[Service]\nType=simple\nStandardOutput=null\nStandardError=null\nRestart=on-failure\nRestartSec=5s\nExecStart=/bin/false\n",
        )
        .unwrap();

        let mut manager = Manager::new(ManagerConfig::default_system()).unwrap();
        manager.loader = UnitLoader::with_dirs(vec![dir.path().to_path_buf()]);
        manager.load_unit("restart-delay.service").unwrap();
        {
            let record = manager.units.get_mut("restart-delay.service").unwrap();
            record.state = UnitState::Active;
            record.active_pid = Some(42_424);
        }

        manager.apply_child_exits(vec![crate::event::child::ChildExit {
            pid: 42_424,
            code: libc::CLD_EXITED,
            status: 1,
        }]);

        let record = &manager.units["restart-delay.service"];
        assert_eq!(record.restart_count, 1);
        assert!(manager.job_queue.is_empty());
        assert!(manager.shared_queue.lock().unwrap().is_empty());
    }

    #[test]
    fn requested_resource_control_failure_aborts_service_start() {
        let _manager_test_guard = MANAGER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let units = tempfile::tempdir().unwrap();
        std::fs::write(
            units.path().join("limited.service"),
            "[Service]\nType=simple\nStandardOutput=null\nStandardError=null\nCPUWeight=200\nExecStart=/bin/sleep 30\n",
        )
        .unwrap();
        let cgroups = tempfile::tempdir().unwrap();
        let cgroup = crate::cgroup::CgroupManager::with_root(cgroups.path());
        cgroup.setup_root().unwrap();
        let unit_path = cgroup.create_unit_cgroup("limited.service").unwrap();
        std::fs::create_dir(unit_path.join("cpu.weight")).unwrap();

        let mut manager = Manager::new(ManagerConfig::default_system()).unwrap();
        manager.loader = UnitLoader::with_dirs(vec![units.path().to_path_buf()]);
        manager.cgroup = cgroup;
        manager.load_unit("limited.service").unwrap();

        assert!(manager
            .run_service_job(JobKind::Start, "limited.service")
            .is_err());
        let record = &manager.units["limited.service"];
        assert_eq!(record.state, UnitState::Failed);
        assert_eq!(record.service_result, "resources");
        if let Some(pid) = record.active_pid {
            // Safety: this test owns the spawned service process.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                libc::waitpid(pid, std::ptr::null_mut(), 0);
            }
        }
    }

    #[test]
    fn start_timeout_kill_preserves_timeout_result() {
        let _manager_test_guard = MANAGER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let units = tempfile::tempdir().unwrap();
        std::fs::write(
            units.path().join("timeout-kill.service"),
            "[Service]\nType=notify\nStandardOutput=null\nStandardError=null\nTimeoutStartSec=50ms\nTimeoutStartFailureMode=kill\nFinalKillSignal=SIGKILL\nExecStart=/bin/sleep 5\n",
        )
        .unwrap();
        let mut manager = Manager::new(ManagerConfig::default_system()).unwrap();
        manager.loader = UnitLoader::with_dirs(vec![units.path().to_path_buf()]);
        manager.load_unit("timeout-kill.service").unwrap();
        manager
            .job_queue
            .enqueue(JobKind::Start, "timeout-kill.service");
        assert_eq!(manager.run_until_idle().unwrap(), LoopResult::Exit);
        let record = &manager.units["timeout-kill.service"];
        assert_eq!(record.state, UnitState::Failed);
        assert_eq!(record.service_result, "timeout");
    }

    #[test]
    fn start_timeout_abort_delivers_watchdog_signal() {
        let _manager_test_guard = MANAGER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let units = tempfile::tempdir().unwrap();
        let marker_dir = tempfile::tempdir().unwrap();
        let marker = marker_dir.path().join("watchdog-signal");
        let command = format!(
            "/bin/sh -c 'trap \"printf watchdog > {}\" USR1; while :; do :; done'",
            marker.display()
        );
        std::fs::write(
            units.path().join("timeout-abort.service"),
            format!(
                "[Service]\nType=notify\nStandardOutput=null\nStandardError=null\nTimeoutStartSec=100ms\nTimeoutAbortSec=100ms\nTimeoutStartFailureMode=abort\nWatchdogSignal=SIGUSR1\nFinalKillSignal=SIGKILL\nExecStart={command}\n"
            ),
        )
        .unwrap();
        let mut manager = Manager::new(ManagerConfig::default_system()).unwrap();
        manager.loader = UnitLoader::with_dirs(vec![units.path().to_path_buf()]);
        manager.load_unit("timeout-abort.service").unwrap();
        manager
            .job_queue
            .enqueue(JobKind::Start, "timeout-abort.service");
        assert_eq!(manager.run_until_idle().unwrap(), LoopResult::Exit);
        assert!(marker.exists());
        let record = &manager.units["timeout-abort.service"];
        assert_eq!(record.state, UnitState::Failed);
        assert_eq!(record.service_result, "timeout");
    }

    #[test]
    fn idle_service_executes_after_ready_batch_dispatch() {
        let _manager_test_guard = MANAGER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let units = tempfile::tempdir().unwrap();
        let marker = units.path().join("idle-ran");
        std::fs::write(
            units.path().join("idle.service"),
            format!(
                "[Service]\nType=idle\nStandardOutput=null\nStandardError=null\nExecStart=/bin/sh -c 'printf ready > {}'\n",
                marker.display()
            ),
        )
        .unwrap();

        let mut manager = Manager::new(ManagerConfig::default_system()).unwrap();
        manager.loader = UnitLoader::with_dirs(vec![units.path().to_path_buf()]);
        manager.load_unit("idle.service").unwrap();
        manager.job_queue.enqueue(JobKind::Start, "idle.service");

        assert_eq!(manager.run_until_idle().unwrap(), LoopResult::Exit);
        assert_eq!(manager.units["idle.service"].state, UnitState::Active);
        assert!(manager.units["idle.service"].idle_gate_fd.is_none());

        for _ in 0..50 {
            if marker.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), "ready");

        if let Some(pid) = manager.units["idle.service"].active_pid {
            // Safety: the test owns the service process.
            unsafe {
                libc::waitpid(pid, std::ptr::null_mut(), 0);
            }
        }
    }

    #[test]
    fn integration_sleep_service() {
        let _manager_test_guard = MANAGER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Write a minimal service file to a temp dir.
        let dir = tempfile::tempdir().unwrap();
        let mut f = NamedTempFile::new_in(dir.path()).unwrap();
        write!(
            f,
            "[Unit]\nDescription=Test Sleep\n[Service]\nType=oneshot\nStandardOutput=null\nStandardError=null\nExecStart=/bin/sleep 0.1\n"
        )
        .unwrap();
        let service_path = f.path().to_path_buf();
        let service_name = service_path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        // Rename to .service.
        let service_file = dir.path().join(format!("{service_name}.service"));
        std::fs::rename(&service_path, service_file).unwrap();
        let service_name = format!("{service_name}.service");

        let mut m = Manager::new(ManagerConfig::default_system()).unwrap();
        m.loader = UnitLoader::with_dirs(vec![dir.path().to_path_buf()]);

        m.load_unit(&service_name).unwrap();
        let job = m.job_queue.enqueue(JobKind::Start, &service_name);
        assert_eq!(job.id, 1);

        // Run manager until settled (service completes).
        let result = m.run_until_idle().unwrap();
        assert!(matches!(result, LoopResult::Exit));

        let final_state = m.units[&service_name].state;
        assert!(m.job_registry.is_empty());
        assert!(
            matches!(final_state, UnitState::Inactive | UnitState::Active),
            "unexpected state: {final_state:?}"
        );
    }

    #[test]
    fn restart_backoff_matches_v261_geometric_steps() {
        let section = ServiceSection {
            restart_sec: Some(Duration::from_secs(1)),
            restart_max_delay_sec: Some(Duration::from_secs(8)),
            restart_steps: Some(3),
            ..Default::default()
        };
        assert_eq!(restart_delay_for(&section, 1), Duration::from_secs(1));
        assert_eq!(restart_delay_for(&section, 2), Duration::from_secs(2));
        assert_eq!(restart_delay_for(&section, 3), Duration::from_secs(4));
        assert_eq!(restart_delay_for(&section, 4), Duration::from_secs(8));
    }

    #[test]
    fn start_limit_window_expires_instead_of_counting_for_process_lifetime() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join("limited.service"),
            "[Unit]\nStartLimitBurst=2\nStartLimitIntervalSec=1s\n\
             [Service]\nType=simple\nRestart=always\nExecStart=/bin/false\n",
        )
        .unwrap();
        let loader = UnitLoader::with_dirs(vec![directory.path().to_path_buf()]);
        let mut record = UnitRecord::new(loader.load("limited.service").unwrap());
        let exit = crate::event::child::ChildExit {
            pid: 1,
            code: libc::CLD_EXITED,
            status: 1,
        };

        assert!(automatic_restart_delay_at(&mut record, &exit, 1).is_some());
        assert!(automatic_restart_delay_at(&mut record, &exit, 2).is_some());
        assert!(automatic_restart_delay_at(&mut record, &exit, 3).is_none());
        assert_eq!(record.service_result, "start-limit-hit");

        record.state = UnitState::Inactive;
        record.service_result = "exit-code".to_owned();
        assert!(
            automatic_restart_delay_at(&mut record, &exit, 1_000_000_001).is_some(),
            "the unit must be startable after StartLimitIntervalSec elapses"
        );
        assert_eq!(record.start_limit_count, 1);
    }
}
