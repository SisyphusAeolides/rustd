// SPDX-License-Identifier: LGPL-2.1-or-later
//! D-Bus server lifecycle for the native RustD manager API.
//!
//! Spawns a single-threaded tokio runtime on a dedicated OS thread.  The
//! runtime hosts the zbus `Connection` and serves all D-Bus calls without
//! touching the PID-1 epoll loop.
//!
//! Upstream reference: `src/core/dbus.c bus_init()` (v261)

use std::collections::HashSet;
use std::sync::{
    atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicU8},
    Arc, Mutex, RwLock,
};
use std::thread;
use std::time::Duration;

use anyhow::anyhow;
use tokio::sync::mpsc::UnboundedSender;

use crate::cgroup::CgroupManager;
use crate::config::{ManagerScope, UnitDefaults};
use crate::dbus::job_iface::JobInterface;
use crate::dbus::manager_iface::{
    clear_unit_references_for_sender, invocation_id_path, job_path, manager_log_from_config,
    unit_path, ManagerEnvironment, ManagerInterface, ManagerInterfaceApi, ManagerSignal,
    SetUnitPropertiesRequests, UnitLoadRequests, UnitReferences,
};
use crate::dbus::service_iface::ServiceInterface;
use crate::dbus::unit_iface::UnitInterface;
use crate::event::EventLoopWake;
use crate::ipc::UnitInfo;
use crate::ipc_server::ResetFailedRequests;
use crate::job::{JobInfo, JobQueue, JobRegistry};

/// Well-known bus name for the RustD manager.
pub const RUSTD_BUS_NAME: &str = "io.rustd.Manager1";
/// Root object path.
pub const RUSTD_OBJECT_PATH: &str = "/io/rustd/Manager1";

// ── DbusServer ────────────────────────────────────────────────────────────

/// Handle to the background D-Bus server thread.
///
/// Dropping this handle signals the runtime to shut down.
pub struct DbusServer {
    /// Shutdown sender — signals the tokio runtime to stop.
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
    /// Join handle for the OS thread running the runtime.
    _thread: thread::JoinHandle<()>,
}

impl DbusServer {
    /// Start the D-Bus server on a background thread.
    ///
    /// Connects to the session bus (or system bus when running as PID 1).
    /// The `ManagerInterface` is registered at [`RUSTD_OBJECT_PATH`].
    ///
    /// Returns `None` (non-fatal) if D-Bus is unavailable in the environment.
    ///
    /// # Errors
    /// Returns an error if the tokio runtime cannot be created.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn start(
        scope: ManagerScope,
        cgroup: CgroupManager,
        unit_defaults: Arc<RwLock<UnitDefaults>>,
        default_timeout_start_sec: u64,
        default_timeout_stop_sec: u64,
        snapshot: Arc<RwLock<Vec<UnitInfo>>>,
        queue: Arc<Mutex<JobQueue>>,
        unit_load_requests: UnitLoadRequests,
        set_unit_property_requests: SetUnitPropertiesRequests,
        jobs: JobRegistry,
        wake: EventLoopWake,
        reload_requested: Arc<AtomicBool>,
        reload_count: Arc<AtomicU64>,
        exit_code: Arc<AtomicU8>,
        exit_requested: Arc<AtomicBool>,
        reexecute_requested: Arc<AtomicBool>,
        shutdown_action: Arc<AtomicU8>,
        shutdown_start_realtime_ns: Arc<AtomicI64>,
        shutdown_start_monotonic_ns: Arc<AtomicI64>,
        startup_realtime_ns: i64,
        startup_monotonic_ns: i64,
        finish_realtime_ns: Arc<AtomicI64>,
        finish_monotonic_ns: Arc<AtomicI64>,
        units_load_start_realtime_ns: Arc<AtomicI64>,
        units_load_start_monotonic_ns: Arc<AtomicI64>,
        units_load_finish_realtime_ns: Arc<AtomicI64>,
        units_load_finish_monotonic_ns: Arc<AtomicI64>,
        units_load_timestamp_realtime_ns: Arc<AtomicI64>,
        units_load_timestamp_monotonic_ns: Arc<AtomicI64>,
        environment: ManagerEnvironment,
        log_level: String,
        log_target: String,
        reset_failed_requests: ResetFailedRequests,
        dbus_ready_events: Arc<Mutex<Vec<String>>>,
    ) -> anyhow::Result<(Self, UnboundedSender<ManagerSignal>)> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| anyhow!("dbus: failed to build tokio runtime: {e}"))?;

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let (signal_tx, signal_rx) = tokio::sync::mpsc::unbounded_channel::<ManagerSignal>();
        let signal_tx_clone = signal_tx.clone();

        let handle = thread::Builder::new()
            .name("rustd-dbus".into())
            .spawn(move || {
                rt.block_on(async move {
                    if let Err(e) = run_server(
                        scope,
                        cgroup,
                        unit_defaults,
                        default_timeout_start_sec,
                        default_timeout_stop_sec,
                        snapshot,
                        queue,
                        unit_load_requests,
                        set_unit_property_requests,
                        jobs,
                        wake,
                        reload_requested,
                        reload_count,
                        exit_code,
                        exit_requested,
                        reexecute_requested,
                        shutdown_action,
                        shutdown_start_realtime_ns,
                        shutdown_start_monotonic_ns,
                        startup_realtime_ns,
                        startup_monotonic_ns,
                        finish_realtime_ns,
                        finish_monotonic_ns,
                        units_load_start_realtime_ns,
                        units_load_start_monotonic_ns,
                        units_load_finish_realtime_ns,
                        units_load_finish_monotonic_ns,
                        units_load_timestamp_realtime_ns,
                        units_load_timestamp_monotonic_ns,
                        environment,
                        log_level,
                        log_target,
                        reset_failed_requests,
                        dbus_ready_events,
                        signal_tx_clone,
                        signal_rx,
                        shutdown_rx,
                    )
                    .await
                    {
                        // Non-fatal: D-Bus may not be available in all environments.
                        eprintln!("dbus: server error: {e}");
                    }
                });
            })
            .map_err(|e| anyhow!("dbus: failed to spawn thread: {e}"))?;

        Ok((
            Self {
                shutdown_tx,
                _thread: handle,
            },
            signal_tx,
        ))
    }

    /// Request the D-Bus server to stop.
    pub fn stop(self) {
        let _ = self.shutdown_tx.send(());
    }
}

// ── async server ──────────────────────────────────────────────────────────

// Keep the server bootstrap in one dependency-injection boundary: its
// registration order mirrors the manager's v261 D-Bus setup.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn run_server(
    scope: ManagerScope,
    cgroup: CgroupManager,
    unit_defaults: Arc<RwLock<UnitDefaults>>,
    default_timeout_start_sec: u64,
    default_timeout_stop_sec: u64,
    snapshot: Arc<RwLock<Vec<UnitInfo>>>,
    queue: Arc<Mutex<JobQueue>>,
    unit_load_requests: UnitLoadRequests,
    set_unit_property_requests: SetUnitPropertiesRequests,
    jobs: JobRegistry,
    wake: EventLoopWake,
    reload_requested: Arc<AtomicBool>,
    reload_count: Arc<AtomicU64>,
    exit_code: Arc<AtomicU8>,
    exit_requested: Arc<AtomicBool>,
    reexecute_requested: Arc<AtomicBool>,
    shutdown_action: Arc<AtomicU8>,
    shutdown_start_realtime_ns: Arc<AtomicI64>,
    shutdown_start_monotonic_ns: Arc<AtomicI64>,
    startup_realtime_ns: i64,
    startup_monotonic_ns: i64,
    finish_realtime_ns: Arc<AtomicI64>,
    finish_monotonic_ns: Arc<AtomicI64>,
    units_load_start_realtime_ns: Arc<AtomicI64>,
    units_load_start_monotonic_ns: Arc<AtomicI64>,
    units_load_finish_realtime_ns: Arc<AtomicI64>,
    units_load_finish_monotonic_ns: Arc<AtomicI64>,
    units_load_timestamp_realtime_ns: Arc<AtomicI64>,
    units_load_timestamp_monotonic_ns: Arc<AtomicI64>,
    environment: ManagerEnvironment,
    log_level: String,
    log_target: String,
    reset_failed_requests: ResetFailedRequests,
    dbus_ready_events: Arc<Mutex<Vec<String>>>,
    signal_tx: UnboundedSender<ManagerSignal>,
    mut signal_rx: tokio::sync::mpsc::UnboundedReceiver<ManagerSignal>,
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    // Try system bus first (for PID 1), fall back to session bus.
    let conn = connect_bus(scope).await?;

    let subscribers = Arc::new(Mutex::new(HashSet::<String>::new()));
    let unit_references: UnitReferences = Arc::new(Mutex::new(std::collections::HashMap::new()));

    // Register the Manager interface.
    let manager = ManagerInterface {
        scope,
        cgroup,
        unit_defaults: Arc::clone(&unit_defaults),
        default_timeout_start_sec,
        default_timeout_stop_sec,
        snapshot: Arc::clone(&snapshot),
        queue: Arc::clone(&queue),
        unit_load_requests: Some(unit_load_requests),
        set_unit_property_requests: Some(set_unit_property_requests),
        jobs: jobs.clone(),
        wake: wake.clone(),
        reload_requested,
        reload_count,
        exit_code,
        show_status: Arc::new(AtomicBool::new(false)),
        exit_requested,
        reexecute_requested,
        shutdown_action,
        shutdown_start_realtime_ns,
        shutdown_start_monotonic_ns,
        startup_realtime_ns,
        startup_monotonic_ns,
        finish_realtime_ns,
        finish_monotonic_ns,
        units_load_start_realtime_ns,
        units_load_start_monotonic_ns,
        units_load_finish_realtime_ns,
        units_load_finish_monotonic_ns,
        units_load_timestamp_realtime_ns,
        units_load_timestamp_monotonic_ns,
        environment,
        log: manager_log_from_config(log_level, log_target),
        reset_failed_requests,
        subscribers,
        unit_references: Arc::clone(&unit_references),
        signal_tx,
    };
    conn.object_server()
        .at(RUSTD_OBJECT_PATH, ManagerInterfaceApi::new(manager))
        .await
        .map_err(|e| anyhow!("dbus: failed to register manager object: {e}"))?;

    // Register per-unit and per-job interfaces for current state.
    register_unit_objects(scope, &unit_defaults, &conn, &snapshot, &queue, &wake).await;
    register_job_objects(&conn, &jobs, &queue, &wake).await;

    // Request the well-known name.
    conn.request_name(RUSTD_BUS_NAME)
        .await
        .map_err(|e| anyhow!("dbus: failed to request bus name '{RUSTD_BUS_NAME}': {e}"))?;

    // Get the signal context for the Manager object.
    let signal_ctxt = conn
        .object_server()
        .interface::<_, ManagerInterfaceApi>(RUSTD_OBJECT_PATH)
        .await
        .map_err(|e| anyhow!("dbus: failed to get manager interface context: {e}"))?;

    let dbus_proxy = zbus::fdo::DBusProxy::new(&conn)
        .await
        .map_err(|e| anyhow!("dbus: failed to create bus daemon proxy: {e}"))?;
    let reference_monitor =
        tokio::spawn(monitor_unit_reference_owners(conn.clone(), unit_references));
    let mut readiness_timer = tokio::time::interval(Duration::from_millis(50));
    readiness_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut reported_ready = HashSet::<String>::new();
    let mut invocation_paths = HashSet::<String>::new();
    sync_invocation_unit_objects(
        scope,
        &unit_defaults,
        &conn,
        &snapshot,
        &queue,
        &wake,
        &mut invocation_paths,
    )
    .await;

    // Dispatch loop: wait for signals, D-Bus readiness, or shutdown.
    let mut shutdown_rx = std::pin::pin!(shutdown_rx);

    loop {
        tokio::select! {
            _ = &mut shutdown_rx => break,
            _ = readiness_timer.tick() => {
                sync_invocation_unit_objects(
                    scope,
                    &unit_defaults,
                    &conn,
                    &snapshot,
                    &queue,
                    &wake,
                    &mut invocation_paths,
                ).await;
                poll_dbus_service_readiness(
                    &dbus_proxy,
                    &snapshot,
                    &dbus_ready_events,
                    &wake,
                    &mut reported_ready,
                ).await;
            }
            Some(sig) = signal_rx.recv() => {
                dispatch_signal(
                    scope,
                    &unit_defaults,
                    &conn,
                    &signal_ctxt,
                    &snapshot,
                    &queue,
                    &jobs,
                    &wake,
                    sig,
                )
                .await;
            }
        }
    }

    reference_monitor.abort();

    Ok(())
}

/// Remove `RefUnit` state when a caller's unique bus name disappears.
///
/// Upstream uses a recursive `rustd_bus_track`, which receives the equivalent
/// `NameOwnerChanged` disconnect notification from the bus daemon.  Keeping
/// this monitor on the same connection gives the candidate the same lifetime
/// semantics without coupling the manager loop to zbus message handling.
async fn monitor_unit_reference_owners(conn: zbus::Connection, references: UnitReferences) {
    use zbus::export::futures_util::StreamExt;

    let Ok(proxy) = zbus::fdo::DBusProxy::new(&conn).await else {
        return;
    };
    let Ok(mut stream) = proxy.receive_name_owner_changed_with_args(&[]).await else {
        return;
    };
    while let Some(signal) = stream.next().await {
        let Ok(args) = signal.args() else {
            continue;
        };
        if args.new_owner().as_ref().is_some() {
            continue;
        }
        let sender = args.name().as_str();
        if sender.starts_with(':') {
            clear_unit_references_for_sender(&references, sender);
        }
    }
}

fn dbus_readiness_candidates(snapshot: &Arc<RwLock<Vec<UnitInfo>>>) -> Vec<(String, String)> {
    let Ok(units) = snapshot.read() else {
        return Vec::new();
    };
    units
        .iter()
        .filter(|unit| {
            unit.active_state == "activating" && unit.service_type.as_deref() == Some("dbus")
        })
        .filter_map(|unit| {
            unit.service_runtime
                .bus_name
                .as_ref()
                .map(|name| (unit.name.clone(), name.clone()))
        })
        .collect()
}

async fn poll_dbus_service_readiness(
    proxy: &zbus::fdo::DBusProxy<'_>,
    snapshot: &Arc<RwLock<Vec<UnitInfo>>>,
    ready_events: &Arc<Mutex<Vec<String>>>,
    wake: &EventLoopWake,
    reported: &mut HashSet<String>,
) {
    let candidates = dbus_readiness_candidates(snapshot);
    let active: HashSet<&str> = candidates.iter().map(|(unit, _)| unit.as_str()).collect();
    reported.retain(|unit| active.contains(unit.as_str()));

    for (unit, name) in candidates {
        if reported.contains(&unit) {
            continue;
        }
        let Ok(bus_name) = zbus::names::BusName::try_from(name.as_str()) else {
            continue;
        };
        if !proxy.name_has_owner(bus_name).await.unwrap_or(false) {
            continue;
        }
        let mut events = ready_events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !events.contains(&unit) {
            events.push(unit.clone());
        }
        drop(events);
        reported.insert(unit);
        let _ = wake.wake();
    }
}

/// Register the native RustD unit and service interfaces
/// objects for the current snapshot.
async fn register_unit_objects(
    scope: ManagerScope,
    unit_defaults: &Arc<RwLock<UnitDefaults>>,
    conn: &zbus::Connection,
    snapshot: &Arc<RwLock<Vec<UnitInfo>>>,
    queue: &Arc<Mutex<JobQueue>>,
    wake: &EventLoopWake,
) {
    let units = match snapshot.read() {
        Ok(guard) => guard.clone(),
        Err(_) => return,
    };
    for info in &units {
        register_unit_object(scope, unit_defaults, conn, snapshot, queue, wake, info).await;
    }
}

async fn register_unit_object(
    scope: ManagerScope,
    unit_defaults: &Arc<RwLock<UnitDefaults>>,
    conn: &zbus::Connection,
    snapshot: &Arc<RwLock<Vec<UnitInfo>>>,
    queue: &Arc<Mutex<JobQueue>>,
    wake: &EventLoopWake,
    info: &UnitInfo,
) {
    let Ok(path) = unit_path(&info.name) else {
        return;
    };
    register_unit_object_at(
        scope,
        unit_defaults,
        conn,
        snapshot,
        queue,
        wake,
        info,
        path,
    )
    .await;
    if let Some(invocation_id) = info.service_runtime.invocation_id {
        if let Ok(path) = invocation_id_path(&invocation_id) {
            register_unit_object_at(
                scope,
                unit_defaults,
                conn,
                snapshot,
                queue,
                wake,
                info,
                path,
            )
            .await;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn register_unit_object_at(
    scope: ManagerScope,
    unit_defaults: &Arc<RwLock<UnitDefaults>>,
    conn: &zbus::Connection,
    snapshot: &Arc<RwLock<Vec<UnitInfo>>>,
    queue: &Arc<Mutex<JobQueue>>,
    wake: &EventLoopWake,
    info: &UnitInfo,
    path: zbus::zvariant::OwnedObjectPath,
) {
    let unit_iface = UnitInterface {
        name: info.name.clone(),
        snapshot: Arc::clone(snapshot),
        queue: Arc::clone(queue),
        wake: wake.clone(),
        scope,
    };
    let _ = conn.object_server().at(path.clone(), unit_iface).await;

    if info.unit_type == "service" {
        let service_iface = ServiceInterface {
            name: info.name.clone(),
            snapshot: Arc::clone(snapshot),
            scope,
            unit_defaults: Arc::clone(unit_defaults),
        };
        let _ = conn.object_server().at(path, service_iface).await;
    }
}

/// Keep v261's per-invocation Unit object aliases in sync with manager state.
///
/// A service gets its ID when it starts, after its stable name object has
/// already been exported. The server's existing 50 ms readiness poll is also
/// an appropriate place to add the alias and remove an obsolete one after a
/// restart; no manager lifecycle work is performed here.
#[allow(clippy::too_many_arguments)]
async fn sync_invocation_unit_objects(
    scope: ManagerScope,
    unit_defaults: &Arc<RwLock<UnitDefaults>>,
    conn: &zbus::Connection,
    snapshot: &Arc<RwLock<Vec<UnitInfo>>>,
    queue: &Arc<Mutex<JobQueue>>,
    wake: &EventLoopWake,
    registered: &mut HashSet<String>,
) {
    let units = match snapshot.read() {
        Ok(guard) => guard.clone(),
        Err(_) => return,
    };
    let current: HashSet<String> = units
        .iter()
        .filter_map(|unit| unit.service_runtime.invocation_id)
        .filter_map(|id| invocation_id_path(&id).ok())
        .map(|path| path.as_str().to_owned())
        .collect();

    for path in registered.difference(&current) {
        let _ = conn
            .object_server()
            .remove::<ServiceInterface, _>(path.as_str())
            .await;
        let _ = conn
            .object_server()
            .remove::<UnitInterface, _>(path.as_str())
            .await;
    }
    for info in &units {
        let Some(invocation_id) = info.service_runtime.invocation_id else {
            continue;
        };
        let Ok(path) = invocation_id_path(&invocation_id) else {
            continue;
        };
        if !registered.contains(path.as_str()) {
            register_unit_object_at(
                scope,
                unit_defaults,
                conn,
                snapshot,
                queue,
                wake,
                info,
                path,
            )
            .await;
        }
    }
    *registered = current;
}

/// Register all jobs that were queued before the D-Bus connection came up.
async fn register_job_objects(
    conn: &zbus::Connection,
    jobs: &JobRegistry,
    queue: &Arc<Mutex<JobQueue>>,
    wake: &EventLoopWake,
) {
    for info in jobs.list() {
        register_job_object(conn, jobs, queue, wake, &info).await;
    }
}

async fn register_job_object(
    conn: &zbus::Connection,
    jobs: &JobRegistry,
    queue: &Arc<Mutex<JobQueue>>,
    wake: &EventLoopWake,
    info: &JobInfo,
) {
    let Ok(path) = job_path(info.id) else {
        return;
    };
    let interface = JobInterface::new(info.clone(), jobs.clone(), Arc::clone(queue), wake.clone());
    let _ = conn.object_server().at(path, interface).await;
}

/// Emit a single `ManagerSignal` on the D-Bus connection.
#[allow(clippy::too_many_arguments)]
async fn dispatch_signal(
    scope: ManagerScope,
    unit_defaults: &Arc<RwLock<UnitDefaults>>,
    conn: &zbus::Connection,
    ctxt_iface: &zbus::InterfaceRef<ManagerInterfaceApi>,
    snapshot: &Arc<RwLock<Vec<UnitInfo>>>,
    queue: &Arc<Mutex<JobQueue>>,
    jobs: &JobRegistry,
    wake: &EventLoopWake,
    sig: ManagerSignal,
) {
    let signal_ctxt = ctxt_iface.signal_context();
    match sig {
        ManagerSignal::UnitNew { id, path } => {
            let info = snapshot
                .read()
                .ok()
                .and_then(|guard| guard.iter().find(|unit| unit.name == id).cloned());
            if let Some(info) = info {
                register_unit_object(scope, unit_defaults, conn, snapshot, queue, wake, &info)
                    .await;
            }
            if let Ok(obj_path) = zbus::zvariant::ObjectPath::try_from(path.as_str()) {
                let _ = ManagerInterface::unit_new(signal_ctxt, &id, obj_path).await;
            }
        }
        ManagerSignal::UnitRemoved { id, path } => {
            if let Ok(obj_path) = zbus::zvariant::ObjectPath::try_from(path.as_str()) {
                let _ = ManagerInterface::unit_removed(signal_ctxt, &id, obj_path).await;
            }
            let _ = conn
                .object_server()
                .remove::<ServiceInterface, _>(path.as_str())
                .await;
            let _ = conn
                .object_server()
                .remove::<UnitInterface, _>(path.as_str())
                .await;
        }
        ManagerSignal::JobNew { job, path } => {
            register_job_object(conn, jobs, queue, wake, &job).await;
            if let Ok(obj_path) = zbus::zvariant::ObjectPath::try_from(path.as_str()) {
                let _ =
                    ManagerInterface::job_new(signal_ctxt, job.id, obj_path, &job.unit_name).await;
            }
        }
        ManagerSignal::JobStateChanged { job, path } => {
            if let Ok(interface_ref) = conn
                .object_server()
                .interface::<_, JobInterface>(path.as_str())
                .await
            {
                let mut interface = interface_ref.get_mut().await;
                interface.set_state(job.state);
                let _ = interface
                    .state_changed(interface_ref.signal_context())
                    .await;
            }
        }
        ManagerSignal::JobRemoved { job, path, result } => {
            if let Ok(obj_path) = zbus::zvariant::ObjectPath::try_from(path.as_str()) {
                let _ = ManagerInterface::job_removed(
                    signal_ctxt,
                    job.id,
                    obj_path,
                    &job.unit_name,
                    &result,
                )
                .await;
            }
            let _ = conn
                .object_server()
                .remove::<JobInterface, _>(path.as_str())
                .await;
        }
        ManagerSignal::Reloading { active } => {
            let _ = ManagerInterface::reloading(signal_ctxt, active).await;
        }
        ManagerSignal::UnitFilesChanged => {
            let _ = ManagerInterface::unit_files_changed(signal_ctxt).await;
        }
        ManagerSignal::StartupFinished {
            firmware,
            loader,
            kernel,
            initrd,
            userspace,
            total,
        } => {
            let _ = ManagerInterface::startup_finished(
                signal_ctxt,
                firmware,
                loader,
                kernel,
                initrd,
                userspace,
                total,
            )
            .await;
        }
    }
}

/// Connect to D-Bus — system bus if running as root, session bus otherwise.
async fn connect_bus(scope: ManagerScope) -> anyhow::Result<zbus::Connection> {
    match scope {
        ManagerScope::System => zbus::Connection::system()
            .await
            .map_err(|e| anyhow!("dbus: system bus connection failed: {e}")),
        ManagerScope::User => zbus::Connection::session()
            .await
            .map_err(|e| anyhow!("dbus: session bus connection failed: {e}")),
    }
}

#[cfg(test)]
mod readiness_tests {
    use super::*;

    #[test]
    fn selects_only_activating_dbus_services_with_bus_names() {
        let mut dbus = UnitInfo {
            name: "demo.service".into(),
            load_state: "loaded".into(),
            active_state: "activating".into(),
            sub_state: "activating".into(),
            description: String::new(),
            main_pid: Some(123),
            unit_type: "service".into(),
            service_type: Some("dbus".into()),
            restart_policy: Some("no".into()),
            service_runtime: Box::default(),
        };
        dbus.service_runtime.bus_name = Some("org.example.Demo".into());
        let mut active = dbus.clone();
        active.name = "active.service".into();
        active.active_state = "active".into();
        let snapshot = Arc::new(RwLock::new(vec![dbus, active]));
        assert_eq!(
            dbus_readiness_candidates(&snapshot),
            vec![("demo.service".into(), "org.example.Demo".into())]
        );
    }
}
