// SPDX-License-Identifier: LGPL-2.1-or-later
//! Restart policy and timeout escalation.
//!
//! `should_restart` decides whether to re-activate a service after it exits.
//! `schedule_restart` arms a one-shot monotonic timer that fires after
//! `RestartSec=` and calls `service::activate`.
//! `arm_start_timeout` / `arm_stop_timeout` set up escalating SIGTERM→SIGKILL
//! timers for activation and deactivation timeouts.
//!
//! Upstream reference: `src/core/service.c service_enter_restart()`,
//!   `service_start_timeout()`, `service_stop_timeout()` (v261)

use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::event::child::ChildExit;
use crate::event::loop_::{EventLoop, TimerHandler};
use crate::event::source::SourceId;
use crate::event::timer::{ClockId, TimerSpec};
use crate::unit::section_service::RestartPolicy;

/// Decide whether the restart policy calls for a restart from the normalized
/// service result used by systemd v261.
#[must_use]
pub fn should_restart_result(policy: RestartPolicy, result: &str) -> bool {
    match policy {
        RestartPolicy::No => false,
        RestartPolicy::Always => true,
        RestartPolicy::OnSuccess => result == "success",
        RestartPolicy::OnFailure => result != "success" && result != "skip-condition",
        RestartPolicy::OnAbnormal => !matches!(result, "success" | "exit-code" | "skip-condition"),
        RestartPolicy::OnAbort => matches!(result, "signal" | "core-dump"),
        RestartPolicy::OnWatchdog => result == "watchdog",
    }
}

/// Decide whether the restart policy calls for a restart given a raw child
/// exit. Callers that already have a service result should use
/// [`should_restart_result`] so timeout/watchdog/custom-success semantics are
/// preserved.
#[must_use]
pub fn should_restart(policy: RestartPolicy, exit: &ChildExit) -> bool {
    let result = if exit.code == libc::CLD_EXITED {
        if exit.status == 0 {
            "success"
        } else {
            "exit-code"
        }
    } else if exit.code == libc::CLD_DUMPED {
        "core-dump"
    } else if exit.code == libc::CLD_KILLED {
        "signal"
    } else {
        "resources"
    };
    should_restart_result(policy, result)
}

/// Arm a one-shot restart timer.
///
/// When the timer fires `on_restart` is called.  The caller is responsible
/// for incrementing `restart_count` before calling this function.
///
/// # Errors
/// Propagates errors from `EventLoop::add_timer`.
pub fn schedule_restart<F>(
    loop_: &mut EventLoop,
    delay: Duration,
    on_restart: F,
) -> anyhow::Result<SourceId>
where
    F: FnMut(SourceId) + Send + 'static,
{
    #[allow(clippy::cast_possible_truncation)]
    let delay_ns = delay.as_nanos() as i64;
    let spec = TimerSpec::once(delay_ns.max(1_000_000)); // minimum 1 ms
    loop_.add_timer(
        ClockId::Monotonic,
        spec,
        Box::new(OneShotCallback(Some(on_restart))),
    )
}

/// Service timeout state-machine phase delivered back to the manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServiceTimeoutPhase {
    Start,
    Stop,
    Abort,
}

/// One fired service timeout, bound to the timer source that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServiceTimeoutEvent {
    pub unit_name: String,
    pub phase: ServiceTimeoutPhase,
    pub source_id: SourceId,
}

/// Arm a one-shot manager-owned service timeout event.
///
/// # Errors
/// Propagates errors from `EventLoop::add_timer`.
pub(crate) fn arm_service_timeout_event(
    loop_: &mut EventLoop,
    timeout: Duration,
    events: Arc<Mutex<Vec<ServiceTimeoutEvent>>>,
    unit_name: String,
    phase: ServiceTimeoutPhase,
) -> anyhow::Result<SourceId> {
    #[allow(clippy::cast_possible_truncation)]
    let timeout_ns = timeout.as_nanos().min(i64::MAX as u128) as i64;
    loop_.add_timer(
        ClockId::Monotonic,
        TimerSpec::once(timeout_ns.max(1)),
        Box::new(ServiceTimeoutCallback {
            events,
            unit_name,
            phase,
        }),
    )
}

struct ServiceTimeoutCallback {
    events: Arc<Mutex<Vec<ServiceTimeoutEvent>>>,
    unit_name: String,
    phase: ServiceTimeoutPhase,
}

impl TimerHandler for ServiceTimeoutCallback {
    fn on_timer(&mut self, source_id: SourceId, _expirations: i64) {
        let mut events = self
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        events.push(ServiceTimeoutEvent {
            unit_name: self.unit_name.clone(),
            phase: self.phase,
            source_id,
        });
    }
}

/// Arm a start-timeout timer.
///
/// On the first expiry the activating process receives SIGTERM. If it is still
/// alive after `stop_timeout`, the repeating timer fires again and sends
/// SIGKILL. The manager removes the timer as soon as the child exits.
///
/// # Errors
/// Propagates errors from `EventLoop::add_timer`.
pub fn arm_start_timeout(
    loop_: &mut EventLoop,
    pid: libc::pid_t,
    timeout: Duration,
    stop_timeout: Duration,
) -> anyhow::Result<SourceId> {
    let timeout_ns = duration_ns(timeout);
    let stop_ns = duration_ns(stop_timeout);
    let spec = TimerSpec::repeating(timeout_ns, stop_ns);
    loop_.add_timer(
        ClockId::Monotonic,
        spec,
        Box::new(StartTimeoutKillHandler { pid, phase: 0 }),
    )
}

/// Arm a stop-timeout timer.
///
/// The normal stop path sends SIGTERM immediately. If the process remains
/// after `timeout`, this one-shot deadline sends SIGKILL.
///
/// # Errors
/// Propagates errors from `EventLoop::add_timer`.
pub fn arm_stop_timeout(
    loop_: &mut EventLoop,
    pid: libc::pid_t,
    timeout: Duration,
) -> anyhow::Result<SourceId> {
    loop_.add_timer(
        ClockId::Monotonic,
        TimerSpec::once(duration_ns(timeout)),
        Box::new(StopTimeoutKillHandler { pid }),
    )
}

fn duration_ns(duration: Duration) -> i64 {
    i64::try_from(duration.as_nanos())
        .unwrap_or(i64::MAX)
        .max(1_000_000)
}

// ── Timer handler implementations ─────────────────────────────────────────

struct OneShotCallback<F: FnMut(SourceId) + Send>(Option<F>);

impl<F: FnMut(SourceId) + Send> TimerHandler for OneShotCallback<F> {
    fn on_timer(&mut self, id: SourceId, _expirations: i64) {
        if let Some(mut f) = self.0.take() {
            f(id);
        }
    }
}

/// Start timeout: SIGTERM on first expiry, SIGKILL on second expiry.
struct StartTimeoutKillHandler {
    pid: libc::pid_t,
    phase: u8,
}

impl TimerHandler for StartTimeoutKillHandler {
    fn on_timer(&mut self, _id: SourceId, _expirations: i64) {
        match self.phase {
            0 => {
                // Safety: the manager tracks this service process.
                unsafe { libc::kill(self.pid, libc::SIGTERM) };
                self.phase = 1;
            }
            1 => {
                // Safety: the process did not exit during TimeoutStopSec.
                unsafe { libc::kill(self.pid, libc::SIGKILL) };
                self.phase = 2;
            }
            _ => {}
        }
    }
}

/// Stop timeout: the normal stop path already sent SIGTERM.
struct StopTimeoutKillHandler {
    pid: libc::pid_t,
}

impl TimerHandler for StopTimeoutKillHandler {
    fn on_timer(&mut self, _id: SourceId, _expirations: i64) {
        // Safety: the process remained after its stop deadline.
        unsafe { libc::kill(self.pid, libc::SIGKILL) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exit(code: i32, status: i32) -> ChildExit {
        ChildExit {
            pid: 1,
            code,
            status,
        }
    }

    #[test]
    fn policy_no_never_restarts() {
        assert!(!should_restart(
            RestartPolicy::No,
            &exit(libc::CLD_EXITED, 0)
        ));
        assert!(!should_restart(
            RestartPolicy::No,
            &exit(libc::CLD_EXITED, 1)
        ));
    }

    #[test]
    fn policy_always_always_restarts() {
        assert!(should_restart(
            RestartPolicy::Always,
            &exit(libc::CLD_EXITED, 0)
        ));
        assert!(should_restart(
            RestartPolicy::Always,
            &exit(libc::CLD_EXITED, 1)
        ));
        assert!(should_restart(
            RestartPolicy::Always,
            &exit(libc::CLD_KILLED, libc::SIGKILL)
        ));
    }

    #[test]
    fn policy_on_success_only_on_zero() {
        assert!(should_restart(
            RestartPolicy::OnSuccess,
            &exit(libc::CLD_EXITED, 0)
        ));
        assert!(!should_restart(
            RestartPolicy::OnSuccess,
            &exit(libc::CLD_EXITED, 1)
        ));
        assert!(!should_restart(
            RestartPolicy::OnSuccess,
            &exit(libc::CLD_KILLED, libc::SIGKILL)
        ));
    }

    #[test]
    fn policy_on_failure_only_on_nonzero() {
        assert!(!should_restart(
            RestartPolicy::OnFailure,
            &exit(libc::CLD_EXITED, 0)
        ));
        assert!(should_restart(
            RestartPolicy::OnFailure,
            &exit(libc::CLD_EXITED, 1)
        ));
        assert!(should_restart(
            RestartPolicy::OnFailure,
            &exit(libc::CLD_KILLED, libc::SIGKILL)
        ));
    }

    #[test]
    fn policy_on_abnormal_excludes_normal_nonzero_exit() {
        assert!(!should_restart(
            RestartPolicy::OnAbnormal,
            &exit(libc::CLD_EXITED, 0)
        ));
        assert!(!should_restart(
            RestartPolicy::OnAbnormal,
            &exit(libc::CLD_EXITED, 1)
        ));
        assert!(should_restart(
            RestartPolicy::OnAbnormal,
            &exit(libc::CLD_KILLED, libc::SIGKILL)
        ));
    }

    #[test]
    fn policy_on_abort_only_signals() {
        assert!(!should_restart(
            RestartPolicy::OnAbort,
            &exit(libc::CLD_EXITED, 0)
        ));
        assert!(!should_restart(
            RestartPolicy::OnAbort,
            &exit(libc::CLD_EXITED, 1)
        ));
        assert!(should_restart(
            RestartPolicy::OnAbort,
            &exit(libc::CLD_KILLED, libc::SIGKILL)
        ));
    }
    #[test]
    fn policy_on_watchdog_requires_watchdog_result() {
        assert!(should_restart_result(RestartPolicy::OnWatchdog, "watchdog"));
        assert!(!should_restart_result(RestartPolicy::OnWatchdog, "signal"));
        assert!(!should_restart(
            RestartPolicy::OnWatchdog,
            &exit(libc::CLD_KILLED, libc::SIGABRT)
        ));
    }
}
