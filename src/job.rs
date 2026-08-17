// SPDX-License-Identifier: LGPL-2.1-or-later
//! Job queue and live job registry.
//!
//! A `Job` is an intent to start, stop, reload, restart, or isolate a named
//! unit. Job identifiers are allocated once per manager lifetime and remain
//! stable while jobs move between the cross-thread queue and the manager's
//! ordered execution queue.
//!
//! Upstream reference: `src/core/job.c job_run_and_invalidate()`,
//! `src/core/dbus-job.c` (v261)

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::{Arc, RwLock};

use crate::unit::UnitState;

/// The kind of work a job requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobKind {
    /// A completed no-op transaction for a conditional request that does not
    /// apply to the unit's current state.
    Nop,
    /// Activate the unit.
    Start,
    /// Deactivate the unit.
    Stop,
    /// Run the unit's reload transaction.
    Reload,
    /// Stop the unit and start it again after deactivation completes.
    Restart,
    /// Replace the active unit graph with an isolatable target transaction.
    Isolate,
}

impl JobKind {
    /// Canonical D-Bus job type string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Nop => "nop",
            Self::Start | Self::Isolate => "start",
            Self::Stop => "stop",
            Self::Reload => "reload",
            Self::Restart => "restart",
        }
    }
}

/// Runtime state exported by `io.rustd.Manager1.Job.State`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobState {
    /// The job is queued behind ordering prerequisites.
    Waiting,
    /// The manager has begun executing the job.
    Running,
}

impl JobState {
    /// Canonical D-Bus state string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Waiting => "waiting",
            Self::Running => "running",
        }
    }
}

/// Completion result exported in the Manager `JobRemoved` signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobResult {
    Done,
    Canceled,
    Timeout,
    Failed,
    Dependency,
    Skipped,
    Invalid,
    Frozen,
    Concurrency,
}

impl JobResult {
    /// Canonical D-Bus result string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Done => "done",
            Self::Canceled => "canceled",
            Self::Timeout => "timeout",
            Self::Failed => "failed",
            Self::Dependency => "dependency",
            Self::Skipped => "skipped",
            Self::Invalid => "invalid",
            Self::Frozen => "frozen",
            Self::Concurrency => "concurrency",
        }
    }

    const fn increments_failed_counter(self) -> bool {
        matches!(
            self,
            Self::Failed | Self::Invalid | Self::Frozen | Self::Concurrency
        )
    }
}

/// A single pending or running unit operation.
#[derive(Debug, Clone)]
pub struct Job {
    /// Monotonically increasing identifier. Zero is reserved for internal
    /// implementation steps that are not exported on D-Bus.
    pub id: u32,
    /// What to do.
    pub kind: JobKind,
    /// Name of the unit this job targets.
    pub unit_name: String,
}

/// Immutable identity plus mutable state for one live exported job.
#[derive(Debug, Clone)]
pub struct JobInfo {
    pub id: u32,
    pub kind: JobKind,
    pub unit_name: String,
    pub state: JobState,
}

/// Ordered registry event consumed by the manager's D-Bus signal publisher.
#[derive(Debug, Clone)]
pub enum JobEvent {
    /// A new job object must be registered and announced.
    New(JobInfo),
    /// A live job changed between the waiting and running states.
    StateChanged(JobInfo),
    /// A job completed and its object must be removed.
    Removed { job: JobInfo, result: JobResult },
}

#[derive(Debug)]
struct JobRegistryInner {
    next_id: u32,
    n_installed: u32,
    n_failed: u32,
    live: BTreeMap<u32, JobInfo>,
    owners: HashMap<u32, BTreeSet<String>>,
    before: HashMap<u32, BTreeSet<u32>>,
    after: HashMap<u32, BTreeSet<u32>>,
    events: VecDeque<JobEvent>,
}

impl Default for JobRegistryInner {
    fn default() -> Self {
        Self {
            next_id: 1,
            n_installed: 0,
            n_failed: 0,
            live: BTreeMap::new(),
            owners: HashMap::new(),
            before: HashMap::new(),
            after: HashMap::new(),
            events: VecDeque::new(),
        }
    }
}

/// Shared registry of all externally visible jobs.
#[derive(Debug, Clone, Default)]
pub struct JobRegistry {
    inner: Arc<RwLock<JobRegistryInner>>,
}

impl JobRegistry {
    fn allocate(&self, kind: JobKind, unit_name: String, owner: Option<String>) -> Job {
        let mut inner = self
            .inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let id = inner.next_id;
        inner.next_id = inner
            .next_id
            .checked_add(1)
            .expect("rustd job identifier space exhausted");
        let info = JobInfo {
            id,
            kind,
            unit_name: unit_name.clone(),
            state: JobState::Waiting,
        };
        inner.live.insert(id, info.clone());
        inner.n_installed = inner.n_installed.saturating_add(1);
        if let Some(owner) = owner.filter(|owner| !owner.is_empty()) {
            inner.owners.entry(id).or_default().insert(owner);
        }
        inner.events.push_back(JobEvent::New(info));
        Job {
            id,
            kind,
            unit_name,
        }
    }

    /// Return the total number of externally visible jobs installed by this
    /// manager instance.
    #[must_use]
    pub fn n_installed(&self) -> u32 {
        self.inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .n_installed
    }

    /// Return the total number of jobs that completed with an upstream
    /// failure-counted result.
    ///
    /// This mirrors the upstream manager counter: `failed`, `invalid`,
    /// `frozen`, and `concurrency` are included; timeout, dependency, and
    /// canceled outcomes are not.
    #[must_use]
    pub fn n_failed(&self) -> u32 {
        self.inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .n_failed
    }

    /// Return a copy of one live job.
    #[must_use]
    pub fn get(&self, id: u32) -> Option<JobInfo> {
        self.inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .live
            .get(&id)
            .cloned()
    }

    /// Return all live jobs in numeric identifier order.
    #[must_use]
    pub fn list(&self) -> Vec<JobInfo> {
        self.inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .live
            .values()
            .cloned()
            .collect()
    }

    /// True when no exported job is waiting or running.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .live
            .is_empty()
    }

    /// Return the oldest live job attached to `unit_name`.
    #[must_use]
    pub fn for_unit(&self, unit_name: &str) -> Option<JobInfo> {
        self.inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .live
            .values()
            .find(|job| job.unit_name == unit_name)
            .cloned()
    }

    /// True when the exported job still exists.
    #[must_use]
    pub fn is_live(&self, id: u32) -> bool {
        self.inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .live
            .contains_key(&id)
    }

    /// Return whether `sender` created or otherwise owns the job.
    #[must_use]
    pub fn is_owner(&self, id: u32, sender: &str) -> bool {
        self.inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .owners
            .get(&id)
            .is_some_and(|owners| owners.contains(sender))
    }

    /// Return jobs that must finish before `id` may run, ordered by job ID.
    #[must_use]
    pub fn get_before(&self, id: u32) -> Vec<JobInfo> {
        let inner = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(ids) = inner.before.get(&id) else {
            return Vec::new();
        };
        ids.iter()
            .filter_map(|other_id| inner.live.get(other_id).cloned())
            .collect()
    }

    /// Return jobs that are waiting for `id`, ordered by job ID.
    #[must_use]
    pub fn get_after(&self, id: u32) -> Vec<JobInfo> {
        let inner = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(ids) = inner.after.get(&id) else {
            return Vec::new();
        };
        ids.iter()
            .filter_map(|other_id| inner.live.get(other_id).cloned())
            .collect()
    }

    /// Rebuild live job ordering from canonical unit `After=` relationships.
    pub fn refresh_ordering(&self, afters: &HashMap<String, Vec<String>>) {
        let mut inner = self
            .inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.before.clear();
        inner.after.clear();

        let jobs: Vec<JobInfo> = inner.live.values().cloned().collect();
        for job in &jobs {
            let Some(dependencies) = afters.get(&job.unit_name) else {
                continue;
            };
            for dependency in dependencies {
                for other in jobs
                    .iter()
                    .filter(|other| other.unit_name == dependency.as_str())
                {
                    if job.id == other.id {
                        continue;
                    }

                    if orders_as_stop(job.kind) {
                        inner.before.entry(other.id).or_default().insert(job.id);
                        inner.after.entry(job.id).or_default().insert(other.id);
                    } else {
                        inner.before.entry(job.id).or_default().insert(other.id);
                        inner.after.entry(other.id).or_default().insert(job.id);
                    }
                }
            }
        }
    }

    /// Transition a waiting job to running.
    pub fn mark_running(&self, id: u32) -> bool {
        let mut inner = self
            .inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let changed = {
            let Some(job) = inner.live.get_mut(&id) else {
                return false;
            };
            if job.state == JobState::Running {
                return true;
            }
            job.state = JobState::Running;
            job.clone()
        };
        inner.events.push_back(JobEvent::StateChanged(changed));
        true
    }

    /// Remove a live job and queue its completion event.
    pub fn finish(&self, id: u32, result: JobResult) -> Option<JobInfo> {
        let mut inner = self
            .inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let job = inner.live.remove(&id)?;
        if result.increments_failed_counter() {
            inner.n_failed = inner.n_failed.saturating_add(1);
        }
        inner.owners.remove(&id);
        inner.before.remove(&id);
        inner.after.remove(&id);
        for ids in inner.before.values_mut() {
            ids.remove(&id);
        }
        for ids in inner.after.values_mut() {
            ids.remove(&id);
        }
        inner.before.retain(|_, ids| !ids.is_empty());
        inner.after.retain(|_, ids| !ids.is_empty());
        inner.events.push_back(JobEvent::Removed {
            job: job.clone(),
            result,
        });
        Some(job)
    }

    /// Drain queued job lifecycle events in creation order.
    pub fn drain_events(&self) -> Vec<JobEvent> {
        let mut inner = self
            .inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.events.drain(..).collect()
    }
}

/// Ordered queue of pending jobs.
#[derive(Debug)]
pub struct JobQueue {
    registry: JobRegistry,
    pending: VecDeque<Job>,
}

impl Default for JobQueue {
    fn default() -> Self {
        Self::with_registry(JobRegistry::default())
    }
}

impl JobQueue {
    /// Create an empty queue attached to an existing live-job registry.
    #[must_use]
    pub fn with_registry(registry: JobRegistry) -> Self {
        Self {
            registry,
            pending: VecDeque::new(),
        }
    }

    /// Return a clone of the shared registry used by this queue.
    #[must_use]
    pub fn registry(&self) -> JobRegistry {
        self.registry.clone()
    }

    /// Append a new exported job and return its stable identity.
    pub fn enqueue(&mut self, kind: JobKind, unit_name: impl Into<String>) -> Job {
        self.enqueue_owned(kind, unit_name, None)
    }

    /// Append a new exported job and associate it with a D-Bus owner.
    pub fn enqueue_owned(
        &mut self,
        kind: JobKind,
        unit_name: impl Into<String>,
        owner: Option<String>,
    ) -> Job {
        let job = self.registry.allocate(kind, unit_name.into(), owner);
        self.pending.push_back(job.clone());
        job
    }

    /// Append an unexported implementation step.
    pub fn enqueue_internal(&mut self, kind: JobKind, unit_name: impl Into<String>) {
        self.pending.push_back(Job {
            id: 0,
            kind,
            unit_name: unit_name.into(),
        });
    }

    /// Move an already allocated job into this queue without changing its ID.
    pub fn push_existing(&mut self, job: Job) {
        if job.id == 0 || self.registry.is_live(job.id) {
            self.pending.push_back(job);
        }
    }

    /// Remove and return the oldest queued job, preserving its identity.
    pub fn pop_front(&mut self) -> Option<Job> {
        while let Some(job) = self.pending.pop_front() {
            if job.id == 0 || self.registry.is_live(job.id) {
                return Some(job);
            }
        }
        None
    }

    /// Rebuild ordering edges shared with the scheduler and D-Bus job objects.
    pub fn refresh_ordering(&self, afters: &HashMap<String, Vec<String>>) {
        self.registry.refresh_ordering(afters);
    }

    /// Return the next job whose ordering prerequisites are satisfied.
    ///
    /// A `Start` job is ready when all `After=` dependencies of the target
    /// unit are settled and every live prerequisite job has completed.
    /// Stop/restart ordering is reversed exactly like upstream systemd.
    pub fn pop_ready(
        &mut self,
        states: &HashMap<String, UnitState>,
        afters: &HashMap<String, Vec<String>>,
    ) -> Option<Job> {
        self.pending
            .retain(|job| job.id == 0 || self.registry.is_live(job.id));
        let pos = self.pending.iter().position(|job| {
            (job.id == 0 || self.registry.get_before(job.id).is_empty())
                && job_is_ready(job, states, afters)
        })?;
        self.pending.remove(pos)
    }

    /// Drain all currently-ready jobs, returning them in order.
    pub fn drain_ready(
        &mut self,
        states: &HashMap<String, UnitState>,
        afters: &HashMap<String, Vec<String>>,
    ) -> Vec<Job> {
        let mut out = Vec::new();
        while let Some(job) = self.pop_ready(states, afters) {
            out.push(job);
        }
        out
    }

    /// Cancel a job whether it is still in this queue or already running.
    pub fn cancel(&mut self, id: u32) -> bool {
        if id == 0 {
            return false;
        }
        self.pending.retain(|job| job.id != id);
        self.registry.finish(id, JobResult::Canceled).is_some()
    }

    /// Cancel every live job and return the number that were canceled.
    pub fn cancel_all(&mut self) -> usize {
        let ids: Vec<u32> = self.registry.list().iter().map(|job| job.id).collect();
        ids.into_iter().filter(|id| self.cancel(*id)).count()
    }

    /// Number of runnable or waiting jobs still present in the registry.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pending
            .iter()
            .filter(|job| job.id == 0 || self.registry.is_live(job.id))
            .count()
    }

    /// True if no live jobs are waiting in this queue.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

const fn orders_as_stop(kind: JobKind) -> bool {
    matches!(kind, JobKind::Stop | JobKind::Restart)
}

fn job_is_ready(
    job: &Job,
    states: &HashMap<String, UnitState>,
    afters: &HashMap<String, Vec<String>>,
) -> bool {
    if !matches!(job.kind, JobKind::Start) {
        return true;
    }
    // After= only orders against units that are actually part of the
    // transaction. Live job-to-job edges are enforced via `get_before`; an
    // After= reference to a unit that was never loaded/started must not pin
    // the queue forever (upstream semantics: After= does not pull deps in).
    let empty = Vec::new();
    let deps = afters.get(&job.unit_name).unwrap_or(&empty);
    deps.iter().all(|dep| match states.get(dep.as_str()) {
        None => true,
        Some(
            UnitState::Active | UnitState::Inactive | UnitState::Failed | UnitState::Maintenance,
        ) => true,
        Some(_) => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn states(pairs: &[(&str, UnitState)]) -> HashMap<String, UnitState> {
        pairs.iter().map(|(k, v)| ((*k).to_owned(), *v)).collect()
    }

    fn afters(pairs: &[(&str, &[&str])]) -> HashMap<String, Vec<String>> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.iter().map(|s| (*s).to_owned()).collect()))
            .collect()
    }

    #[test]
    fn identifiers_are_stable_across_queues() {
        let registry = JobRegistry::default();
        let mut ingress = JobQueue::with_registry(registry.clone());
        let mut manager = JobQueue::with_registry(registry.clone());
        let first = ingress.enqueue(JobKind::Start, "one.service");
        let second = ingress.enqueue(JobKind::Stop, "two.service");
        assert_eq!(first.id, 1);
        assert_eq!(second.id, 2);

        manager.push_existing(ingress.pop_front().unwrap());
        let moved = manager.pop_ready(&states(&[]), &afters(&[])).unwrap();
        assert_eq!(moved.id, first.id);
        assert_eq!(registry.get(first.id).unwrap().state, JobState::Waiting);
    }

    #[test]
    fn running_and_completion_events_are_tracked() {
        let mut queue = JobQueue::default();
        let registry = queue.registry();
        let job = queue.enqueue(JobKind::Start, "foo.service");
        assert!(registry.mark_running(job.id));
        assert_eq!(registry.get(job.id).unwrap().state, JobState::Running);
        assert!(registry.finish(job.id, JobResult::Done).is_some());
        assert!(registry.get(job.id).is_none());
        let events = registry.drain_events();
        assert!(matches!(&events[0], JobEvent::New(_)));
        assert!(matches!(&events[1], JobEvent::StateChanged(_)));
        assert!(matches!(
            &events[2],
            JobEvent::Removed {
                result: JobResult::Done,
                ..
            }
        ));
    }

    #[test]
    fn lifetime_counters_track_installations_and_only_failed_results() {
        let mut queue = JobQueue::default();
        let registry = queue.registry();
        let done = queue.enqueue(JobKind::Start, "done.service");
        let timeout = queue.enqueue(JobKind::Start, "timeout.service");
        let dependency = queue.enqueue(JobKind::Start, "dependency.service");
        let canceled = queue.enqueue(JobKind::Start, "canceled.service");
        let failed = queue.enqueue(JobKind::Start, "failed.service");
        let invalid = queue.enqueue(JobKind::Start, "invalid.service");
        let frozen = queue.enqueue(JobKind::Start, "frozen.service");
        let concurrency = queue.enqueue(JobKind::Start, "concurrency.service");

        assert_eq!(registry.n_installed(), 8);
        assert_eq!(registry.n_failed(), 0);
        assert_eq!(JobResult::Invalid.as_str(), "invalid");
        assert_eq!(JobResult::Frozen.as_str(), "frozen");
        assert_eq!(JobResult::Concurrency.as_str(), "concurrency");

        registry.finish(done.id, JobResult::Done);
        registry.finish(timeout.id, JobResult::Timeout);
        registry.finish(dependency.id, JobResult::Dependency);
        registry.finish(canceled.id, JobResult::Canceled);
        assert_eq!(registry.n_failed(), 0);

        registry.finish(failed.id, JobResult::Failed);
        registry.finish(invalid.id, JobResult::Invalid);
        registry.finish(frozen.id, JobResult::Frozen);
        registry.finish(concurrency.id, JobResult::Concurrency);
        assert_eq!(registry.n_failed(), 4);
        assert_eq!(registry.n_installed(), 8);

        queue.enqueue_internal(JobKind::Start, "internal.service");
        assert_eq!(registry.n_installed(), 8);
    }

    #[test]
    fn cancel_removes_exported_job() {
        let mut queue = JobQueue::default();
        let registry = queue.registry();
        let job = queue.enqueue(JobKind::Start, "foo.service");
        assert!(queue.cancel(job.id));
        assert!(!registry.is_live(job.id));
        assert!(queue.is_empty());
    }

    #[test]
    fn cancel_all_removes_every_live_job() {
        let mut queue = JobQueue::default();
        let registry = queue.registry();
        queue.enqueue(JobKind::Start, "one.service");
        queue.enqueue(JobKind::Stop, "two.service");
        assert_eq!(queue.cancel_all(), 2);
        assert!(registry.is_empty());
        assert!(queue.is_empty());
    }

    #[test]
    fn stop_always_ready() {
        let mut queue = JobQueue::default();
        queue.enqueue(JobKind::Stop, "foo.service");
        let jobs = queue.drain_ready(&states(&[]), &afters(&[]));
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].kind, JobKind::Stop);
    }

    #[test]
    fn reload_always_ready() {
        let mut queue = JobQueue::default();
        queue.enqueue(JobKind::Reload, "foo.service");
        let jobs = queue.drain_ready(&states(&[]), &afters(&[]));
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].kind, JobKind::Reload);
    }

    #[test]
    fn restart_always_ready() {
        let mut queue = JobQueue::default();
        queue.enqueue(JobKind::Restart, "foo.service");
        let jobs = queue.drain_ready(&states(&[]), &afters(&[]));
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].kind, JobKind::Restart);
    }

    #[test]
    fn isolate_always_ready() {
        let mut queue = JobQueue::default();
        queue.enqueue(JobKind::Isolate, "rescue.target");
        let jobs = queue.drain_ready(&states(&[]), &afters(&[]));
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].kind, JobKind::Isolate);
        assert_eq!(jobs[0].kind.as_str(), "start");
    }

    #[test]
    fn start_no_deps_ready() {
        let mut queue = JobQueue::default();
        queue.enqueue(JobKind::Start, "foo.service");
        let jobs = queue.drain_ready(&states(&[]), &afters(&[]));
        assert_eq!(jobs.len(), 1);
    }

    #[test]
    fn start_dep_activating_blocks() {
        let mut queue = JobQueue::default();
        queue.enqueue(JobKind::Start, "foo.service");
        let st = states(&[("bar.service", UnitState::Activating)]);
        let af = afters(&[("foo.service", &["bar.service"])]);
        let jobs = queue.drain_ready(&st, &af);
        assert!(jobs.is_empty());
    }

    #[test]
    fn start_dep_active_unblocks() {
        let mut queue = JobQueue::default();
        queue.enqueue(JobKind::Start, "foo.service");
        let st = states(&[("bar.service", UnitState::Active)]);
        let af = afters(&[("foo.service", &["bar.service"])]);
        let jobs = queue.drain_ready(&st, &af);
        assert_eq!(jobs.len(), 1);
    }

    #[test]
    fn start_dep_failed_is_ordering_settled() {
        let mut queue = JobQueue::default();
        queue.enqueue(JobKind::Start, "foo.service");
        let states = states(&[("bar.service", UnitState::Failed)]);
        let afters = afters(&[("foo.service", &["bar.service"])]);
        let jobs = queue.drain_ready(&states, &afters);
        assert_eq!(jobs.len(), 1);
    }

    #[test]
    fn start_absent_after_dep_does_not_block() {
        let mut queue = JobQueue::default();
        queue.enqueue(JobKind::Start, "sshd.service");
        let af = afters(&[("sshd.service", &["network.target"])]);
        let jobs = queue.drain_ready(&states(&[]), &af);
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].unit_name, "sshd.service");
    }

    #[test]
    fn ordered_drain() {
        let mut queue = JobQueue::default();
        let later = queue.enqueue(JobKind::Start, "b.service");
        let earlier = queue.enqueue(JobKind::Start, "a.service");
        let registry = queue.registry();
        let af = afters(&[("b.service", &["a.service"])]);
        queue.refresh_ordering(&af);
        assert_eq!(registry.get_before(later.id)[0].id, earlier.id);
        assert_eq!(registry.get_after(earlier.id)[0].id, later.id);

        let st_empty = states(&[]);
        let first = queue.drain_ready(&st_empty, &af);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].unit_name, "a.service");
        registry.finish(earlier.id, JobResult::Done);

        let st_a = states(&[("a.service", UnitState::Active)]);
        let second = queue.drain_ready(&st_a, &af);
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].unit_name, "b.service");
    }

    #[test]
    fn stop_order_is_reverse_of_start_order() {
        let mut queue = JobQueue::default();
        let earlier_start = queue.enqueue(JobKind::Stop, "a.service");
        let later_start = queue.enqueue(JobKind::Stop, "b.service");
        let registry = queue.registry();
        let af = afters(&[("b.service", &["a.service"])]);
        queue.refresh_ordering(&af);

        assert_eq!(registry.get_before(earlier_start.id)[0].id, later_start.id);
        let ready = queue.drain_ready(&states(&[]), &af);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].id, later_start.id);
    }

    #[test]
    fn dbus_owner_is_tracked_until_completion() {
        let mut queue = JobQueue::default();
        let registry = queue.registry();
        let job = queue.enqueue_owned(JobKind::Start, "foo.service", Some(":1.42".to_owned()));
        assert!(registry.is_owner(job.id, ":1.42"));
        assert!(!registry.is_owner(job.id, ":1.43"));
        registry.finish(job.id, JobResult::Done);
        assert!(!registry.is_owner(job.id, ":1.42"));
    }
}
