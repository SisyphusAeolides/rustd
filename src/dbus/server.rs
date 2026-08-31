// SPDX-License-Identifier: LGPL-2.1-or-later
//! D-Bus server lifecycle for the native `RustD` manager API.
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
use crate::dbus::job_iface::{JobInterface, SystemdJobInterface};
use crate::dbus::manager_iface::{
    clear_unit_references_for_sender, invocation_id_path_for, job_path_for,
    manager_log_from_config, unit_path_for, DbusObjectNamespace, ManagerEnvironment,
    ManagerInterface, ManagerInterfaceApi, ManagerSignal, SetUnitPropertiesRequests,
    SystemdManagerInterfaceApi, UnitLoadRequests, UnitReferences,
};
use crate::dbus::service_iface::{ServiceInterface, SystemdServiceInterface};
use crate::dbus::unit_iface::{SystemdUnitInterface, UnitInterface};
use crate::event::EventLoopWake;
use crate::ipc::UnitInfo;
use crate::ipc_server::ResetFailedRequests;
use crate::job::{JobInfo, JobQueue, JobRegistry};

/// Well-known bus name for the `RustD` manager.
pub const RUSTD_BUS_NAME: &str = "io.rustd.Manager1";
/// Root object path.
pub const RUSTD_OBJECT_PATH: &str = "/io/rustd/Manager1";
/// Standard systemd-compatible manager bus name.
pub const SYSTEMD_BUS_NAME: &str = "org.freedesktop.systemd1";
/// Standard systemd-compatible manager object path.
pub const SYSTEMD_OBJECT_PATH: &str = "/org/freedesktop/systemd1";

// ── DbusServer ────────────────────────────────────────────────────────────

/// Handle to the background D-Bus server thread.
///
/// Dropping this handle signals the runtime to shut down.
pub struct DbusServer {
    /// Shared shutdown flag observed by the reconnecting worker.
    shutdown: Arc<AtomicBool>,
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

        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = Arc::clone(&shutdown);
        let (signal_tx, mut signal_rx) = tokio::sync::mpsc::unbounded_channel::<ManagerSignal>();
        let signal_tx_clone = signal_tx.clone();

        let handle = thread::Builder::new()
            .name("rustd-dbus".into())
            .spawn(move || {
                if let Err(error) = crate::event::signal::block_all_signals_for_current_thread() {
                    eprintln!("rustd: D-Bus worker signal mask setup failed: {error}");
                    return;
                }
                rt.block_on(async move {
                    while !worker_shutdown.load(std::sync::atomic::Ordering::Acquire) {
                        if let Err(e) = run_server(
                            scope,
                            cgroup.clone(),
                            Arc::clone(&unit_defaults),
                            default_timeout_start_sec,
                            default_timeout_stop_sec,
                            Arc::clone(&snapshot),
                            Arc::clone(&queue),
                            Arc::clone(&unit_load_requests),
                            Arc::clone(&set_unit_property_requests),
                            jobs.clone(),
                            wake.clone(),
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
                            environment.clone(),
                            log_level.clone(),
                            log_target.clone(),
                            Arc::clone(&reset_failed_requests),
                            Arc::clone(&dbus_ready_events),
                            signal_tx_clone.clone(),
                            &mut signal_rx,
                            Arc::clone(&worker_shutdown),
                        )
                        .await
                        {
                            eprintln!("dbus: server error: {e}");
                        }
                        if !worker_shutdown.load(std::sync::atomic::Ordering::Acquire) {
                            tokio::time::sleep(Duration::from_millis(250)).await;
                        }
                    }
                });
            })
            .map_err(|e| anyhow!("dbus: failed to spawn thread: {e}"))?;

        Ok((
            Self {
                shutdown,
                _thread: handle,
            },
            signal_tx,
        ))
    }

    /// Request the D-Bus server to stop.
    pub fn stop(self) {
        self.shutdown
            .store(true, std::sync::atomic::Ordering::Release);
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
    signal_rx: &mut tokio::sync::mpsc::UnboundedReceiver<ManagerSignal>,
    shutdown: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    // Try system bus first (for PID 1), fall back to session bus.
    let conn = connect_bus(scope).await?;

    let subscribers = Arc::new(Mutex::new(HashSet::<String>::new()));
    let unit_references: UnitReferences = Arc::new(Mutex::new(std::collections::HashMap::new()));

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
        namespace: DbusObjectNamespace::Native,
    };
    let mut compat_manager = manager.clone();
    compat_manager.namespace = DbusObjectNamespace::Compatibility;
    conn.object_server()
        .at(RUSTD_OBJECT_PATH, ManagerInterfaceApi::new(manager))
        .await
        .map_err(|e| anyhow!("dbus: failed to register manager object: {e}"))?;
    conn.object_server()
        .at(
            SYSTEMD_OBJECT_PATH,
            SystemdManagerInterfaceApi::new(compat_manager),
        )
        .await
        .map_err(|e| anyhow!("dbus: failed to register systemd compatibility object: {e}"))?;

    // Register per-unit and per-job interfaces for current state.
    register_unit_objects(scope, &unit_defaults, &conn, &snapshot, &queue, &wake).await;
    register_job_objects(&conn, &jobs, &queue, &wake).await;

    // Request the well-known name.
    conn.request_name(RUSTD_BUS_NAME)
        .await
        .map_err(|e| anyhow!("dbus: failed to request bus name '{RUSTD_BUS_NAME}': {e}"))?;
    conn.request_name(SYSTEMD_BUS_NAME)
        .await
        .map_err(|e| anyhow!("dbus: failed to request bus name '{SYSTEMD_BUS_NAME}': {e}"))?;

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
    loop {
        tokio::select! {
            _ = readiness_timer.tick() => {
                if shutdown.load(std::sync::atomic::Ordering::Acquire) {
                    break;
                }
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

const OBJECT_NAMESPACES: [DbusObjectNamespace; 2] = [
    DbusObjectNamespace::Native,
    DbusObjectNamespace::Compatibility,
];

/// Register both the native RustD and standard systemd-compatible unit and
/// service objects for the current snapshot.
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
    for namespace in OBJECT_NAMESPACES {
        let Ok(path) = unit_path_for(namespace, &info.name) else {
            continue;
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
            namespace,
        )
        .await;
        if let Some(invocation_id) = info.service_runtime.invocation_id {
            if let Ok(path) = invocation_id_path_for(namespace, &invocation_id) {
                register_unit_object_at(
                    scope,
                    unit_defaults,
                    conn,
                    snapshot,
                    queue,
                    wake,
                    info,
                    path,
                    namespace,
                )
                .await;
            }
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
    namespace: DbusObjectNamespace,
) {
    let unit_iface = UnitInterface {
        name: info.name.clone(),
        snapshot: Arc::clone(snapshot),
        queue: Arc::clone(queue),
        wake: wake.clone(),
        scope,
        namespace,
    };
    if namespace == DbusObjectNamespace::Native {
        let _ = conn.object_server().at(path.clone(), unit_iface).await;
    } else {
        let _ = conn
            .object_server()
            .at(path.clone(), SystemdUnitInterface::new(unit_iface))
            .await;
    }

    if info.unit_type == "service" {
        let service_iface = ServiceInterface {
            name: info.name.clone(),
            snapshot: Arc::clone(snapshot),
            scope,
            unit_defaults: Arc::clone(unit_defaults),
        };
        if namespace == DbusObjectNamespace::Native {
            let _ = conn.object_server().at(path, service_iface).await;
        } else {
            let _ = conn
                .object_server()
                .at(path, SystemdServiceInterface::new(service_iface))
                .await;
        }
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
        .flat_map(|id| {
            OBJECT_NAMESPACES
                .into_iter()
                .filter_map(move |namespace| invocation_id_path_for(namespace, &id).ok())
        })
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
        let _ = conn
            .object_server()
            .remove::<SystemdServiceInterface, _>(path.as_str())
            .await;
        let _ = conn
            .object_server()
            .remove::<SystemdUnitInterface, _>(path.as_str())
            .await;
    }
    for info in &units {
        let Some(invocation_id) = info.service_runtime.invocation_id else {
            continue;
        };
        for namespace in OBJECT_NAMESPACES {
            let Ok(path) = invocation_id_path_for(namespace, &invocation_id) else {
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
                    namespace,
                )
                .await;
            }
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
    for namespace in OBJECT_NAMESPACES {
        let Ok(path) = job_path_for(namespace, info.id) else {
            continue;
        };
        let interface = JobInterface::new_in_namespace(
            info.clone(),
            jobs.clone(),
            Arc::clone(queue),
            wake.clone(),
            namespace,
        );
        if namespace == DbusObjectNamespace::Native {
            let _ = conn.object_server().at(path, interface).await;
        } else {
            let _ = conn
                .object_server()
                .at(path, SystemdJobInterface::new(interface))
                .await;
        }
    }
}

/// Emit a signal on the standard systemd-compatible manager interface.
///
/// The generated RustD signal helpers intentionally retain the native
/// interface name, so the compatibility namespace uses zbus's low-level
/// signal emitter for the same wire payload.
async fn emit_systemd_manager_signal<B>(conn: &zbus::Connection, name: &str, body: &B)
where
    B: serde::ser::Serialize + zbus::zvariant::DynamicType,
{
    let _ = conn
        .emit_signal(
            None::<&str>,
            SYSTEMD_OBJECT_PATH,
            "org.freedesktop.systemd1.Manager",
            name,
            body,
        )
        .await;
}

/// Emit a standard `org.freedesktop.DBus.Properties.PropertiesChanged` signal
/// for a compatibility object.
async fn emit_systemd_property_changed(
    conn: &zbus::Connection,
    path: &str,
    interface: &str,
    property: &str,
    value: zbus::zvariant::OwnedValue,
) {
    let changed = std::collections::HashMap::from([(property.to_owned(), value)]);
    let body = (interface, changed, Vec::<String>::new());
    let _ = conn
        .emit_signal(
            None::<&str>,
            path,
            "org.freedesktop.DBus.Properties",
            "PropertiesChanged",
            &body,
        )
        .await;
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
            if let Ok(compat_path) = unit_path_for(DbusObjectNamespace::Compatibility, &id) {
                emit_systemd_manager_signal(conn, "UnitNew", &(id.as_str(), compat_path)).await;
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
            if let Ok(compat_path) = unit_path_for(DbusObjectNamespace::Compatibility, &id) {
                let compat_path_string = compat_path.as_str().to_owned();
                let _ = conn
                    .object_server()
                    .remove::<SystemdServiceInterface, _>(compat_path_string.as_str())
                    .await;
                let _ = conn
                    .object_server()
                    .remove::<SystemdUnitInterface, _>(compat_path_string.as_str())
                    .await;
                emit_systemd_manager_signal(conn, "UnitRemoved", &(id.as_str(), compat_path)).await;
            }
        }
        ManagerSignal::JobNew { job, path } => {
            register_job_object(conn, jobs, queue, wake, &job).await;
            if let Ok(obj_path) = zbus::zvariant::ObjectPath::try_from(path.as_str()) {
                let _ =
                    ManagerInterface::job_new(signal_ctxt, job.id, obj_path, &job.unit_name).await;
            }
            if let Ok(compat_job) = job_path_for(DbusObjectNamespace::Compatibility, job.id) {
                emit_systemd_manager_signal(
                    conn,
                    "JobNew",
                    &(job.id, compat_job, job.unit_name.as_str()),
                )
                .await;
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
            if let Ok(compat_path) = job_path_for(DbusObjectNamespace::Compatibility, job.id) {
                let compat_path_string = compat_path.as_str().to_owned();
                if let Ok(interface_ref) = conn
                    .object_server()
                    .interface::<_, SystemdJobInterface>(compat_path_string.as_str())
                    .await
                {
                    interface_ref.get_mut().await.set_state(job.state);
                }
                emit_systemd_property_changed(
                    conn,
                    &compat_path_string,
                    "org.freedesktop.systemd1.Job",
                    "State",
                    zbus::zvariant::OwnedValue::try_from(zbus::zvariant::Value::from(
                        job.state.as_str(),
                    ))
                    .expect("job state is a valid D-Bus string value"),
                )
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
            if let Ok(compat_job_path) = job_path_for(DbusObjectNamespace::Compatibility, job.id) {
                let compat_job_string = compat_job_path.as_str().to_owned();
                emit_systemd_manager_signal(
                    conn,
                    "JobRemoved",
                    &(
                        job.id,
                        compat_job_path,
                        job.unit_name.as_str(),
                        result.as_str(),
                    ),
                )
                .await;
                let _ = conn
                    .object_server()
                    .remove::<SystemdJobInterface, _>(compat_job_string.as_str())
                    .await;
            }
        }
        ManagerSignal::Reloading { active } => {
            let _ = ManagerInterface::reloading(signal_ctxt, active).await;
            emit_systemd_manager_signal(conn, "Reloading", &(active,)).await;
        }
        ManagerSignal::UnitFilesChanged => {
            let _ = ManagerInterface::unit_files_changed(signal_ctxt).await;
            emit_systemd_manager_signal(conn, "UnitFilesChanged", &()).await;
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
            emit_systemd_manager_signal(
                conn,
                "StartupFinished",
                &(firmware, loader, kernel, initrd, userspace, total),
            )
            .await;
        }
    }
}

/// Connect to D-Bus — system bus if running as root, session bus otherwise.
async fn connect_bus(scope: ManagerScope) -> anyhow::Result<zbus::Connection> {
    match scope {
        ManagerScope::System => {
            if std::env::var_os("DBUS_SYSTEM_BUS_ADDRESS").is_some() {
                return zbus::Connection::system()
                    .await
                    .map_err(|e| anyhow!("dbus: system bus connection failed: {e}"));
            }

            const RUNTIME_BUS: &str = "/run/dbus/system_bus_socket";
            let mut last_error = None;
            // Early-boot service activation can legitimately take longer on
            // live media while the system bus and its SELinux labels settle.
            // Keep retrying long enough to cover that startup window instead
            // of turning a transient race into a manager error.
            const MAX_ATTEMPTS: usize = 600;
            for attempt in 0..MAX_ATTEMPTS {
                if std::path::Path::new(RUNTIME_BUS).exists() {
                    match zbus::connection::Builder::address(
                        "unix:path=/run/dbus/system_bus_socket",
                    )?
                    .build()
                    .await
                    {
                        Ok(connection) => return Ok(connection),
                        Err(error) => last_error = Some(error),
                    }
                }
                if attempt + 1 < MAX_ATTEMPTS {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
            let detail = last_error.map_or_else(
                || format!("{RUNTIME_BUS} was not created"),
                |error| error.to_string(),
            );
            Err(anyhow!("dbus: system bus connection failed: {detail}"))
        }
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
