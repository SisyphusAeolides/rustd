// SPDX-License-Identifier: LGPL-2.1-or-later
//! Service process kill policy shared by stop, restart, watchdog, and timeout paths.
//!
//! Upstream reference: src/core/kill.c `kill_context_init()` and
//! src/core/unit.c `unit_kill_context()` (v261).

use crate::cgroup::CgroupManager;
use crate::unit::section_service::{KillMode, ServiceSection};

/// Signal operation selected by the service state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KillOperation {
    Terminate,
    Restart,
    Kill,
    Watchdog,
}

/// Effective `KillContext` defaults plus configured overrides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KillPolicy {
    pub mode: KillMode,
    pub kill_signal: libc::c_int,
    pub restart_kill_signal: libc::c_int,
    pub final_kill_signal: libc::c_int,
    pub watchdog_signal: libc::c_int,
    pub send_sigkill: bool,
    pub send_sighup: bool,
}

impl KillPolicy {
    #[must_use]
    pub fn from_service(section: &ServiceSection) -> Self {
        let kill_signal = section.kill_signal.unwrap_or(libc::SIGTERM);
        Self {
            mode: section.kill_mode,
            kill_signal,
            restart_kill_signal: section.restart_kill_signal.unwrap_or(kill_signal),
            final_kill_signal: section.final_kill_signal.unwrap_or(libc::SIGKILL),
            watchdog_signal: section.watchdog_signal.unwrap_or(libc::SIGABRT),
            send_sigkill: section.send_sigkill.unwrap_or(true),
            send_sighup: section.send_sighup,
        }
    }

    #[must_use]
    pub fn signal(self, operation: KillOperation) -> Option<libc::c_int> {
        if self.mode == KillMode::None {
            return None;
        }
        match operation {
            KillOperation::Terminate => Some(self.kill_signal),
            KillOperation::Restart => Some(self.restart_kill_signal),
            KillOperation::Kill => self.send_sigkill.then_some(self.final_kill_signal),
            KillOperation::Watchdog => Some(self.watchdog_signal),
        }
    }

    #[must_use]
    fn send_hup(self, operation: KillOperation) -> bool {
        self.send_sighup && matches!(operation, KillOperation::Terminate | KillOperation::Restart)
    }

    #[must_use]
    fn signal_group(self, operation: KillOperation) -> bool {
        self.mode == KillMode::ControlGroup
            || (self.mode == KillMode::Mixed && operation == KillOperation::Kill)
    }
}

/// Signal the tracked main/control PIDs according to `KillContext`.
pub(crate) fn signal_primary(
    policy: KillPolicy,
    main_pid: Option<libc::pid_t>,
    control_pid: Option<libc::pid_t>,
    operation: KillOperation,
) -> usize {
    let Some(signal) = policy.signal(operation) else {
        return 0;
    };
    let mut sent = 0;
    let mut seen = None;
    for pid in [main_pid, control_pid].into_iter().flatten() {
        if pid <= 0 || seen == Some(pid) {
            continue;
        }
        seen = Some(pid);
        // Safety: the manager recorded this PID as belonging to the service.
        let result = unsafe { libc::kill(pid, signal) };
        if result == 0 {
            sent += 1;
        }
        if policy.send_hup(operation) {
            // Safety: same tracked service process as above.
            unsafe { libc::kill(pid, libc::SIGHUP) };
        }
    }
    sent
}

/// Signal remaining unit-cgroup members according to `KillMode`.
pub(crate) fn signal_cgroup_members(
    cgroup: &CgroupManager,
    unit_name: &str,
    policy: KillPolicy,
    main_pid: Option<libc::pid_t>,
    control_pid: Option<libc::pid_t>,
    operation: KillOperation,
) -> anyhow::Result<usize> {
    let Some(signal) = policy.signal(operation) else {
        return Ok(0);
    };
    if !policy.signal_group(operation) {
        return Ok(0);
    }
    let excluded: Vec<libc::pid_t> = [main_pid, control_pid].into_iter().flatten().collect();
    let mut sent = cgroup.signal_unit(unit_name, signal, &excluded)?;
    if policy.send_hup(operation) {
        sent = sent.saturating_add(cgroup.signal_unit(unit_name, libc::SIGHUP, &excluded)?);
    }
    Ok(sent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unit::section_service::ServiceSection;

    #[test]
    fn upstream_defaults_are_effective() {
        let policy = KillPolicy::from_service(&ServiceSection::default());
        assert_eq!(policy.mode, KillMode::ControlGroup);
        assert_eq!(policy.kill_signal, libc::SIGTERM);
        assert_eq!(policy.restart_kill_signal, libc::SIGTERM);
        assert_eq!(policy.final_kill_signal, libc::SIGKILL);
        assert_eq!(policy.watchdog_signal, libc::SIGABRT);
        assert!(policy.send_sigkill);
        assert!(!policy.send_sighup);
    }

    #[test]
    fn mixed_only_signals_group_on_final_kill() {
        let policy = KillPolicy {
            mode: KillMode::Mixed,
            kill_signal: libc::SIGTERM,
            restart_kill_signal: libc::SIGTERM,
            final_kill_signal: libc::SIGKILL,
            watchdog_signal: libc::SIGABRT,
            send_sigkill: true,
            send_sighup: false,
        };
        assert!(!policy.signal_group(KillOperation::Terminate));
        assert!(!policy.signal_group(KillOperation::Watchdog));
        assert!(policy.signal_group(KillOperation::Kill));
    }
}
