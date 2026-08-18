// SPDX-License-Identifier: LGPL-2.1-or-later
//! Kernel-backed cgroup OOM event monitoring.
//!
//! Linux cgroup v2 exposes cumulative OOM counters in `memory.events`.
//! RustD tracks `oom_kill` deltas instead of inferring OOM from SIGKILL, so
//! unrelated administrative kills cannot accidentally trigger `OOMPolicy=`.

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex};

use crate::cgroup::CgroupManager;
use crate::config::ManagerScope;
use crate::event::loop_::IoHandler;

/// Manager action selected by `OOMPolicy=`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OomPolicy {
    Continue,
    Stop,
    Kill,
}

impl OomPolicy {
    /// Resolve a service setting, applying the v261-compatible manager default.
    #[must_use]
    pub fn resolve(scope: ManagerScope, configured: &str) -> Self {
        match configured.trim() {
            "continue" => Self::Continue,
            "stop" => Self::Stop,
            "kill" => Self::Kill,
            _ if scope == ManagerScope::System => Self::Stop,
            _ => Self::Continue,
        }
    }
}

pub type PendingOomEvents = Arc<Mutex<Vec<String>>>;
pub type OomBaselines = Arc<Mutex<HashMap<String, u64>>>;

/// Epoll source for a service cgroup's `memory.events` file.
#[derive(Debug)]
pub struct OomEventSource {
    file: File,
    unit_name: String,
    pending: PendingOomEvents,
    baselines: OomBaselines,
}

impl OomEventSource {
    /// Open `memory.events` and register its current `oom_kill` counter as the
    /// baseline so pre-existing OOM events are never replayed after manager
    /// startup or daemon-reload.
    ///
    /// # Errors
    /// Returns an error if the service cgroup or `oom_kill` counter cannot be
    /// opened/read.
    pub fn for_unit(
        cgroup: &CgroupManager,
        unit_name: &str,
        pending: PendingOomEvents,
        baselines: OomBaselines,
    ) -> anyhow::Result<Self> {
        let procs = cgroup.unit_procs_path(unit_name);
        let directory = procs.parent().ok_or_else(|| {
            anyhow::anyhow!("unit cgroup path has no parent: {}", procs.display())
        })?;
        let mut file = File::open(directory.join("memory.events"))?;
        let current = read_counter(&mut file, "oom_kill")?;
        baselines
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(unit_name.to_owned(), current);
        Ok(Self {
            file,
            unit_name: unit_name.to_owned(),
            pending,
            baselines,
        })
    }

    #[must_use]
    pub fn raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }

    fn refresh(&mut self) {
        let Ok(current) = read_counter(&mut self.file, "oom_kill") else {
            return;
        };
        observe_value(&self.unit_name, current, &self.pending, &self.baselines);
    }
}

impl IoHandler for OomEventSource {
    fn on_io(&mut self, _fd: RawFd, _events: u32) {
        self.refresh();
    }
}

/// Synchronously sample a unit's `memory.events` counter.
///
/// This is used immediately before SIGCHLD processing to close the race where
/// the child-exit notification becomes visible before epoll delivers the
/// corresponding cgroup `memory.events` update.
///
/// # Errors
/// Returns an error if `memory.events` cannot be opened/read.
pub fn sync_unit(
    cgroup: &CgroupManager,
    unit_name: &str,
    pending: &PendingOomEvents,
    baselines: &OomBaselines,
) -> anyhow::Result<()> {
    let procs = cgroup.unit_procs_path(unit_name);
    let directory = procs.parent().ok_or_else(|| {
        anyhow::anyhow!("unit cgroup path has no parent: {}", procs.display())
    })?;
    let mut file = File::open(directory.join("memory.events"))?;
    let current = read_counter(&mut file, "oom_kill")?;
    observe_value(unit_name, current, pending, baselines);
    Ok(())
}

/// Configure the kernel's atomic cgroup OOM kill mode.
///
/// `memory.oom.group=1` makes the kernel kill the entire service cgroup for
/// `OOMPolicy=kill`; other policies explicitly clear the bit so a live
/// daemon-reload can weaken the policy again.
///
/// # Errors
/// Returns an error if the service cgroup has no writable `memory.oom.group`.
pub fn configure_group_kill(
    cgroup: &CgroupManager,
    unit_name: &str,
    enabled: bool,
) -> anyhow::Result<()> {
    let procs = cgroup.unit_procs_path(unit_name);
    let directory = procs.parent().ok_or_else(|| {
        anyhow::anyhow!("unit cgroup path has no parent: {}", procs.display())
    })?;
    std::fs::write(
        directory.join("memory.oom.group"),
        if enabled { "1\n" } else { "0\n" },
    )?;
    Ok(())
}

pub fn remove_baseline(unit_name: &str, baselines: &OomBaselines) {
    baselines
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(unit_name);
}

fn observe_value(
    unit_name: &str,
    current: u64,
    pending: &PendingOomEvents,
    baselines: &OomBaselines,
) {
    let increased = {
        let mut values = baselines
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match values.insert(unit_name.to_owned(), current) {
            Some(previous) => current > previous,
            None => false,
        }
    };
    if !increased {
        return;
    }
    let mut events = pending
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if !events.iter().any(|name| name == unit_name) {
        events.push(unit_name.to_owned());
    }
}

fn read_counter(file: &mut File, key: &str) -> anyhow::Result<u64> {
    file.seek(SeekFrom::Start(0))?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    parse_counter(&contents, key)
        .ok_or_else(|| anyhow::anyhow!("memory.events has no valid {key} counter"))
}

fn parse_counter(contents: &str, key: &str) -> Option<u64> {
    contents.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        (fields.next()? == key)
            .then(|| fields.next()?.parse::<u64>().ok())
            .flatten()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fake_source(
        initial: &str,
    ) -> (
        tempfile::TempDir,
        CgroupManager,
        PendingOomEvents,
        OomBaselines,
        OomEventSource,
    ) {
        let temporary = tempfile::tempdir().unwrap();
        let cgroup = CgroupManager::with_root(temporary.path());
        cgroup.setup_root().unwrap();
        let path = cgroup.create_unit_cgroup("demo.service").unwrap();
        fs::write(path.join("cgroup.procs"), "").unwrap();
        fs::write(path.join("memory.events"), initial).unwrap();
        let pending = Arc::new(Mutex::new(Vec::new()));
        let baselines = Arc::new(Mutex::new(HashMap::new()));
        let source = OomEventSource::for_unit(
            &cgroup,
            "demo.service",
            Arc::clone(&pending),
            Arc::clone(&baselines),
        )
        .unwrap();
        (temporary, cgroup, pending, baselines, source)
    }

    #[test]
    fn policy_defaults_match_manager_scope() {
        assert_eq!(OomPolicy::resolve(ManagerScope::System, ""), OomPolicy::Stop);
        assert_eq!(OomPolicy::resolve(ManagerScope::User, ""), OomPolicy::Continue);
        assert_eq!(OomPolicy::resolve(ManagerScope::System, "kill"), OomPolicy::Kill);
    }

    #[test]
    fn parses_oom_kill_counter() {
        assert_eq!(
            parse_counter("low 2\nhigh 3\noom 4\noom_kill 5\noom_group_kill 1\n", "oom_kill"),
            Some(5)
        );
        assert_eq!(parse_counter("oom 4\n", "oom_kill"), None);
    }

    #[test]
    fn baseline_does_not_replay_old_oom_kills() {
        let (_temporary, _cgroup, pending, _baselines, mut source) =
            fake_source("low 0\nhigh 0\nmax 0\noom 7\noom_kill 3\noom_group_kill 0\n");
        source.on_io(source.raw_fd(), libc::EPOLLPRI as u32);
        assert!(pending.lock().unwrap().is_empty());
    }

    #[test]
    fn queues_unit_once_when_oom_kill_increases() {
        let (_temporary, cgroup, pending, _baselines, mut source) =
            fake_source("low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n");
        let directory = cgroup.unit_procs_path("demo.service").parent().unwrap().to_path_buf();
        fs::write(
            directory.join("memory.events"),
            "low 0\nhigh 0\nmax 1\noom 1\noom_kill 1\noom_group_kill 0\n",
        )
        .unwrap();

        source.on_io(source.raw_fd(), libc::EPOLLPRI as u32);
        source.on_io(source.raw_fd(), libc::EPOLLPRI as u32);

        assert_eq!(pending.lock().unwrap().as_slice(), ["demo.service"]);
    }

    #[test]
    fn synchronous_scan_shares_the_event_baseline() {
        let (_temporary, cgroup, pending, baselines, mut source) =
            fake_source("low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n");
        let directory = cgroup.unit_procs_path("demo.service").parent().unwrap().to_path_buf();
        fs::write(
            directory.join("memory.events"),
            "low 0\nhigh 0\nmax 0\noom 1\noom_kill 1\noom_group_kill 0\n",
        )
        .unwrap();
        sync_unit(&cgroup, "demo.service", &pending, &baselines).unwrap();
        source.on_io(source.raw_fd(), libc::EPOLLPRI as u32);
        assert_eq!(pending.lock().unwrap().as_slice(), ["demo.service"]);
    }

    #[test]
    fn unrelated_memory_events_do_not_queue_oom_policy() {
        let (_temporary, cgroup, pending, _baselines, mut source) =
            fake_source("low 0\nhigh 0\nmax 0\noom 0\noom_kill 2\noom_group_kill 0\n");
        let directory = cgroup.unit_procs_path("demo.service").parent().unwrap().to_path_buf();
        fs::write(
            directory.join("memory.events"),
            "low 1\nhigh 2\nmax 3\noom 4\noom_kill 2\noom_group_kill 0\n",
        )
        .unwrap();

        source.on_io(source.raw_fd(), libc::EPOLLPRI as u32);

        assert!(pending.lock().unwrap().is_empty());
    }

    #[test]
    fn configures_kernel_group_kill_mode() {
        let (_temporary, cgroup, _pending, _baselines, _source) =
            fake_source("low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n");
        let directory = cgroup.unit_procs_path("demo.service").parent().unwrap().to_path_buf();
        fs::write(directory.join("memory.oom.group"), "0\n").unwrap();
        configure_group_kill(&cgroup, "demo.service", true).unwrap();
        assert_eq!(fs::read_to_string(directory.join("memory.oom.group")).unwrap(), "1\n");
        configure_group_kill(&cgroup, "demo.service", false).unwrap();
        assert_eq!(fs::read_to_string(directory.join("memory.oom.group")).unwrap(), "0\n");
    }

    #[test]
    fn lower_counter_rebaselines_recreated_cgroup() {
        let (_temporary, cgroup, pending, _baselines, mut source) =
            fake_source("low 0\nhigh 0\nmax 0\noom 3\noom_kill 3\noom_group_kill 0\n");
        let directory = cgroup.unit_procs_path("demo.service").parent().unwrap().to_path_buf();
        fs::write(
            directory.join("memory.events"),
            "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n",
        )
        .unwrap();
        source.on_io(source.raw_fd(), libc::EPOLLPRI as u32);
        assert!(pending.lock().unwrap().is_empty());

        fs::write(
            directory.join("memory.events"),
            "low 0\nhigh 0\nmax 1\noom 1\noom_kill 1\noom_group_kill 0\n",
        )
        .unwrap();
        source.on_io(source.raw_fd(), libc::EPOLLPRI as u32);
        assert_eq!(pending.lock().unwrap().as_slice(), ["demo.service"]);
    }
}
