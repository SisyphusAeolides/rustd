// SPDX-License-Identifier: LGPL-2.1-or-later
//! `io.rustd.Manager1.Job` D-Bus interface.
//!
//! One object is registered for every live exported manager job at the
//! canonical numeric path `/io/rustd/Manager1/job/<id>`.
//!
//! Upstream reference: `src/core/dbus-job.c` (v261)

#![allow(
    clippy::unused_self,
    clippy::needless_pass_by_value,
    clippy::unnecessary_wraps,
    clippy::missing_errors_doc
)]

use std::sync::{Arc, Mutex};

use zbus::interface;

use crate::dbus::auth::authorize_privileged_caller;
use crate::dbus::manager_iface::{
    job_list_entry_for, unit_path_for, DbusObjectNamespace, JobListEntry,
};
use crate::event::EventLoopWake;
use crate::job::{JobInfo, JobKind, JobQueue, JobRegistry, JobState};

/// A live job's D-Bus object.
pub struct JobInterface {
    id: u32,
    unit_name: String,
    kind: JobKind,
    last_state: JobState,
    registry: JobRegistry,
    queue: Arc<Mutex<JobQueue>>,
    wake: EventLoopWake,
    namespace: DbusObjectNamespace,
}

impl JobInterface {
    /// Construct an interface from the job identity carried by `JobNew`.
    #[must_use]
    pub fn new(
        info: JobInfo,
        registry: JobRegistry,
        queue: Arc<Mutex<JobQueue>>,
        wake: EventLoopWake,
    ) -> Self {
        Self::new_in_namespace(info, registry, queue, wake, DbusObjectNamespace::Native)
    }

    /// Construct a job interface in a selected D-Bus object namespace.
    #[must_use]
    pub fn new_in_namespace(
        info: JobInfo,
        registry: JobRegistry,
        queue: Arc<Mutex<JobQueue>>,
        wake: EventLoopWake,
        namespace: DbusObjectNamespace,
    ) -> Self {
        Self {
            id: info.id,
            unit_name: info.unit_name,
            kind: info.kind,
            last_state: info.state,
            registry,
            queue,
            wake,
            namespace,
        }
    }

    fn unit_object_path(&self) -> zbus::zvariant::OwnedObjectPath {
        unit_path_for(self.namespace, &self.unit_name).unwrap_or_else(|_| {
            zbus::zvariant::OwnedObjectPath::try_from("/")
                .expect("the D-Bus root object path is valid")
        })
    }

    /// Retain the last state long enough to emit the change before removal.
    pub fn set_state(&mut self, state: JobState) {
        self.last_state = state;
    }
}

#[interface(name = "io.rustd.Manager1.Job")]
impl JobInterface {
    /// Cancel the job. Already-started unit work is not forcibly rolled back.
    async fn cancel(
        &self,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<()> {
        let sender = header.sender().map(ToString::to_string);
        let owner = sender
            .as_deref()
            .is_some_and(|sender| self.registry.is_owner(self.id, sender));
        if !owner {
            authorize_privileged_caller(connection, &header).await?;
        }
        let canceled = {
            let mut queue = self.queue.lock().map_err(|_| {
                zbus::fdo::Error::Failed("internal: job queue lock poisoned".into())
            })?;
            queue.cancel(self.id)
        };
        if !canceled {
            return Err(zbus::fdo::Error::Failed(format!(
                "Job {} does not exist.",
                self.id
            )));
        }
        self.wake.wake().map_err(|error| {
            zbus::fdo::Error::Failed(format!("internal: event loop wake failed: {error}"))
        })
    }

    /// Jobs that are waiting for this job to finish.
    fn get_after(&self) -> Vec<JobListEntry> {
        self.registry
            .get_after(self.id)
            .iter()
            .filter_map(|job| job_list_entry_for(self.namespace, job))
            .collect()
    }

    /// Jobs that must finish before this job may run.
    fn get_before(&self) -> Vec<JobListEntry> {
        self.registry
            .get_before(self.id)
            .iter()
            .filter_map(|job| job_list_entry_for(self.namespace, job))
            .collect()
    }

    /// Numeric job identifier.
    #[zbus(property)]
    fn id(&self) -> u32 {
        self.id
    }

    /// Unit name and canonical unit object path.
    #[zbus(property)]
    fn unit(&self) -> (String, zbus::zvariant::OwnedObjectPath) {
        (self.unit_name.clone(), self.unit_object_path())
    }

    /// Canonical job type string.
    #[zbus(property)]
    fn job_type(&self) -> String {
        self.kind.as_str().to_owned()
    }

    /// Current job state (`waiting` or `running`).
    #[zbus(property)]
    fn state(&self) -> String {
        self.registry
            .get(self.id)
            .map_or(self.last_state, |job| job.state)
            .as_str()
            .to_owned()
    }

    /// Activation detail key/value pairs. No details are currently attached.
    #[zbus(property)]
    fn activation_details(&self) -> Vec<(String, String)> {
        Vec::new()
    }
}

/// Adapter that exports a job through the standard systemd D-Bus interface
/// name while retaining one implementation of job behavior.
pub struct SystemdJobInterface {
    inner: JobInterface,
}

impl SystemdJobInterface {
    /// Wrap a job configured for the compatibility object namespace.
    #[must_use]
    pub fn new(inner: JobInterface) -> Self {
        Self { inner }
    }

    /// Update the state carried by the compatibility object before emitting
    /// its standard `PropertiesChanged` signal.
    pub fn set_state(&mut self, state: JobState) {
        self.inner.set_state(state);
    }
}

#[zbus::export::async_trait::async_trait]
impl zbus::object_server::Interface for SystemdJobInterface {
    fn name() -> zbus::names::InterfaceName<'static> {
        zbus::names::InterfaceName::from_static_str_unchecked("org.freedesktop.systemd1.Job")
    }

    async fn get(
        &self,
        property_name: &str,
    ) -> Option<zbus::fdo::Result<zbus::zvariant::OwnedValue>> {
        <JobInterface as zbus::object_server::Interface>::get(&self.inner, property_name).await
    }

    async fn get_all(
        &self,
    ) -> zbus::fdo::Result<std::collections::HashMap<String, zbus::zvariant::OwnedValue>> {
        <JobInterface as zbus::object_server::Interface>::get_all(&self.inner).await
    }

    fn set<'call>(
        &'call self,
        property_name: &'call str,
        value: &'call zbus::zvariant::Value<'_>,
        ctxt: &'call zbus::object_server::SignalContext<'_>,
    ) -> zbus::object_server::DispatchResult<'call> {
        <JobInterface as zbus::object_server::Interface>::set(
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
        <JobInterface as zbus::object_server::Interface>::set_mut(
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
        <JobInterface as zbus::object_server::Interface>::call(
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
        <JobInterface as zbus::object_server::Interface>::call_mut(
            &mut self.inner,
            server,
            connection,
            message,
            name,
        )
    }

    fn introspect_to_writer(&self, writer: &mut dyn std::fmt::Write, level: usize) {
        let mut generated = String::new();
        <JobInterface as zbus::object_server::Interface>::introspect_to_writer(
            &self.inner,
            &mut generated,
            level,
        );
        let generated = generated.replace("io.rustd.Manager1.Job", "org.freedesktop.systemd1.Job");
        writer
            .write_str(&generated)
            .expect("writing D-Bus introspection XML cannot fail");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job::{JobKind, JobQueue};

    fn make_interface() -> (JobInterface, JobRegistry, Arc<Mutex<JobQueue>>) {
        let registry = JobRegistry::default();
        let mut queue = JobQueue::with_registry(registry.clone());
        let info = {
            let job = queue.enqueue(JobKind::Start, "foo.service");
            registry.get(job.id).unwrap()
        };
        let queue = Arc::new(Mutex::new(queue));
        let interface = JobInterface::new(
            info,
            registry.clone(),
            Arc::clone(&queue),
            EventLoopWake::create().unwrap(),
        );
        (interface, registry, queue)
    }

    #[test]
    fn properties_follow_registry_state() {
        let (interface, registry, _) = make_interface();
        assert_eq!(interface.id(), 1);
        assert_eq!(interface.job_type(), "start");
        assert_eq!(interface.state(), "waiting");
        assert_eq!(interface.unit().0, "foo.service");
        assert!(registry.mark_running(1));
        assert_eq!(interface.state(), "running");
    }

    #[test]
    fn queue_cancel_removes_job() {
        let (interface, registry, queue) = make_interface();
        assert!(queue.lock().unwrap().cancel(interface.id));
        assert!(!registry.is_live(interface.id));
    }

    #[test]
    fn ordering_methods_export_live_job_edges() {
        let (interface, registry, queue) = make_interface();
        let second = queue.lock().unwrap().enqueue(JobKind::Start, "bar.service");
        let ordering = std::collections::HashMap::from([(
            "bar.service".to_owned(),
            vec!["foo.service".to_owned()],
        )]);
        queue.lock().unwrap().refresh_ordering(&ordering);

        let after = interface.get_after();
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].0, second.id);

        let second_interface = JobInterface::new(
            registry.get(second.id).unwrap(),
            registry,
            Arc::clone(&queue),
            EventLoopWake::create().unwrap(),
        );
        let before = second_interface.get_before();
        assert_eq!(before.len(), 1);
        assert_eq!(before[0].0, interface.id);
    }
}
