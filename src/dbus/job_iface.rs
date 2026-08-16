// SPDX-License-Identifier: LGPL-2.1-or-later
//! `org.freedesktop.systemd1.Job` D-Bus interface.
//!
//! One object is registered for every live exported manager job at the
//! canonical numeric path `/org/freedesktop/systemd1/job/<id>`.
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
use crate::dbus::manager_iface::{job_list_entry, unit_path, JobListEntry};
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
        Self {
            id: info.id,
            unit_name: info.unit_name,
            kind: info.kind,
            last_state: info.state,
            registry,
            queue,
            wake,
        }
    }

    fn unit_object_path(&self) -> zbus::zvariant::OwnedObjectPath {
        unit_path(&self.unit_name).unwrap_or_else(|_| {
            zbus::zvariant::OwnedObjectPath::try_from("/")
                .expect("the D-Bus root object path is valid")
        })
    }

    /// Retain the last state long enough to emit the change before removal.
    pub fn set_state(&mut self, state: JobState) {
        self.last_state = state;
    }
}

#[interface(name = "org.freedesktop.systemd1.Job")]
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
            .filter_map(job_list_entry)
            .collect()
    }

    /// Jobs that must finish before this job may run.
    fn get_before(&self) -> Vec<JobListEntry> {
        self.registry
            .get_before(self.id)
            .iter()
            .filter_map(job_list_entry)
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
