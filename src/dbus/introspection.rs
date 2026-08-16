// SPDX-License-Identifier: LGPL-2.1-or-later
//! Offline D-Bus introspection for the manager executable.
//!
//! Callers and release tooling can inspect the compiled interface without a
//! running system or session bus. Keep this output sourced from the actual
//! zbus interface implementations rather than a hand-maintained XML copy.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::sync::{
    atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicU8},
    Arc, Mutex, RwLock,
};

use crate::cgroup::CgroupManager;
use crate::config::{ManagerScope, UnitDefaults};
use crate::dbus::job_iface::JobInterface;
use crate::dbus::manager_iface::{
    manager_environment_from_process, manager_log_from_config, ManagerInterface,
    ManagerInterfaceApi, SHUTDOWN_NONE,
};
use crate::dbus::service_iface::ServiceInterface;
use crate::dbus::unit_iface::UnitInterface;
use crate::event::EventLoopWake;
use crate::job::{JobInfo, JobKind, JobQueue, JobState};

const MANAGER_PATH: &str = "/io/rustd/Manager1";
const UNIT_PATH: &str = "/io/rustd/Manager1/unit";
const JOB_PATH: &str = "/io/rustd/Manager1/job";

const DOCTYPE: &str = concat!(
    "<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n",
    "\"https://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n",
    "<node>\n",
);

const STANDARD_INTERFACES: &str = r#" <interface name="org.freedesktop.DBus.Peer">
  <method name="Ping"/>
  <method name="GetMachineId">
   <arg type="s" name="machine_uuid" direction="out"/>
  </method>
 </interface>
 <interface name="org.freedesktop.DBus.Introspectable">
  <method name="Introspect">
   <arg name="xml_data" type="s" direction="out"/>
  </method>
 </interface>
 <interface name="org.freedesktop.DBus.Properties">
  <method name="Get">
   <arg name="interface_name" direction="in" type="s"/>
   <arg name="property_name" direction="in" type="s"/>
   <arg name="value" direction="out" type="v"/>
  </method>
  <method name="GetAll">
   <arg name="interface_name" direction="in" type="s"/>
   <arg name="props" direction="out" type="a{sv}"/>
  </method>
  <method name="Set">
   <arg name="interface_name" direction="in" type="s"/>
   <arg name="property_name" direction="in" type="s"/>
   <arg name="value" direction="in" type="v"/>
  </method>
  <signal name="PropertiesChanged">
   <arg type="s" name="interface_name"/>
   <arg type="a{sv}" name="changed_properties"/>
   <arg type="as" name="invalidated_properties"/>
  </signal>
 </interface>
"#;

/// Return the compiled object-path/interface inventory.
#[must_use]
pub fn interface_list() -> &'static str {
    concat!(
        "/io/rustd/Manager1\tio.rustd.Manager1.Manager\n",
        "/io/rustd/Manager1/job\tio.rustd.Manager1.Job\n",
        "/io/rustd/Manager1/unit\tio.rustd.Manager1.Unit\n",
        "/io/rustd/Manager1/unit\tio.rustd.Manager1.Service\n",
    )
}

fn append_interface<I: zbus::object_server::Interface>(xml: &mut String, interface: &I) {
    <I as zbus::object_server::Interface>::introspect_to_writer(interface, xml, 1);
}

fn manager_interface() -> anyhow::Result<ManagerInterfaceApi> {
    let queue = Arc::new(Mutex::new(JobQueue::default()));
    let jobs = queue
        .lock()
        .map_err(|_| anyhow::anyhow!("job queue lock poisoned"))?
        .registry();
    let wake = EventLoopWake::create()?;
    let (signal_tx, _signal_rx) = tokio::sync::mpsc::unbounded_channel();

    Ok(ManagerInterfaceApi::new(ManagerInterface {
        scope: ManagerScope::System,
        cgroup: CgroupManager::with_root("/nonexistent/rustd-introspection-cgroup"),
        unit_defaults: Arc::new(RwLock::new(UnitDefaults::default())),
        default_timeout_start_sec: 90,
        default_timeout_stop_sec: 90,
        snapshot: Arc::new(RwLock::new(Vec::new())),
        queue,
        unit_load_requests: None,
        set_unit_property_requests: None,
        jobs,
        wake,
        reload_requested: Arc::new(AtomicBool::new(false)),
        reload_count: Arc::new(AtomicU64::new(0)),
        exit_code: Arc::new(AtomicU8::new(0)),
        show_status: Arc::new(AtomicBool::new(false)),
        exit_requested: Arc::new(AtomicBool::new(false)),
        reexecute_requested: Arc::new(AtomicBool::new(false)),
        shutdown_action: Arc::new(AtomicU8::new(SHUTDOWN_NONE)),
        shutdown_start_realtime_ns: Arc::new(AtomicI64::new(0)),
        shutdown_start_monotonic_ns: Arc::new(AtomicI64::new(0)),
        startup_realtime_ns: 0,
        startup_monotonic_ns: 0,
        finish_realtime_ns: Arc::new(AtomicI64::new(0)),
        finish_monotonic_ns: Arc::new(AtomicI64::new(0)),
        units_load_start_realtime_ns: Arc::new(AtomicI64::new(0)),
        units_load_start_monotonic_ns: Arc::new(AtomicI64::new(0)),
        units_load_finish_realtime_ns: Arc::new(AtomicI64::new(0)),
        units_load_finish_monotonic_ns: Arc::new(AtomicI64::new(0)),
        units_load_timestamp_realtime_ns: Arc::new(AtomicI64::new(0)),
        units_load_timestamp_monotonic_ns: Arc::new(AtomicI64::new(0)),
        environment: manager_environment_from_process(),
        log: manager_log_from_config("info".to_owned(), "journal-or-kmsg".to_owned()),
        reset_failed_requests: Arc::new(Mutex::new(Vec::new())),
        subscribers: Arc::new(Mutex::new(HashSet::new())),
        unit_references: Arc::new(Mutex::new(HashMap::new())),
        signal_tx,
    }))
}

fn unit_interfaces() -> anyhow::Result<(UnitInterface, ServiceInterface)> {
    let snapshot = Arc::new(RwLock::new(Vec::new()));
    let queue = Arc::new(Mutex::new(JobQueue::default()));
    let wake = EventLoopWake::create()?;
    Ok((
        UnitInterface {
            name: "introspection.service".to_owned(),
            snapshot: Arc::clone(&snapshot),
            queue,
            wake,
            scope: ManagerScope::System,
        },
        ServiceInterface {
            name: "introspection.service".to_owned(),
            snapshot,
            scope: ManagerScope::System,
            unit_defaults: Arc::new(RwLock::new(UnitDefaults::default())),
        },
    ))
}

fn job_interface() -> anyhow::Result<JobInterface> {
    let queue = Arc::new(Mutex::new(JobQueue::default()));
    let registry = queue
        .lock()
        .map_err(|_| anyhow::anyhow!("job queue lock poisoned"))?
        .registry();
    Ok(JobInterface::new(
        JobInfo {
            id: 1,
            kind: JobKind::Start,
            unit_name: "introspection.service".to_owned(),
            state: JobState::Waiting,
        },
        registry,
        queue,
        EventLoopWake::create()?,
    ))
}

/// Render complete offline introspection XML for one compiled object path.
///
/// # Errors
/// Returns an error if the temporary eventfd-backed interface state cannot be
/// constructed. `Ok(None)` means the object path is not in the compiled
/// inventory.
pub fn introspect_path(path: &str) -> anyhow::Result<Option<String>> {
    let mut xml = String::from(DOCTYPE);
    xml.push_str(STANDARD_INTERFACES);

    match path {
        MANAGER_PATH => append_interface(&mut xml, &manager_interface()?),
        UNIT_PATH => {
            let (unit, service) = unit_interfaces()?;
            append_interface(&mut xml, &unit);
            append_interface(&mut xml, &service);
        }
        JOB_PATH => append_interface(&mut xml, &job_interface()?),
        _ => return Ok(None),
    }

    writeln!(xml, "</node>").expect("writing to a String cannot fail");
    Ok(Some(xml))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_contains_only_compiled_interfaces() {
        assert_eq!(interface_list().lines().count(), 4);
        assert!(interface_list().contains("io.rustd.Manager1.Manager"));
        assert!(interface_list().contains("io.rustd.Manager1.Service"));
    }

    #[test]
    fn manager_unit_service_and_job_xml_are_generated_from_interfaces() {
        let manager = introspect_path(MANAGER_PATH).unwrap().unwrap();
        assert!(manager.contains("<interface name=\"io.rustd.Manager1.Manager\">"));
        assert!(manager.contains("<method name=\"StartUnit\">"));
        assert!(!manager.contains("name=\"r#type\""));

        let unit = introspect_path(UNIT_PATH).unwrap().unwrap();
        assert!(unit.contains("<interface name=\"io.rustd.Manager1.Unit\">"));
        assert!(unit.contains("<interface name=\"io.rustd.Manager1.Service\">"));

        let job = introspect_path(JOB_PATH).unwrap().unwrap();
        assert!(job.contains("<interface name=\"io.rustd.Manager1.Job\">"));
        assert!(introspect_path("/not/compiled").unwrap().is_none());
    }
}
