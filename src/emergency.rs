// SPDX-License-Identifier: LGPL-2.1-or-later
//! Emergency and rescue target handling for PID 1.
//!
//! When the manager detects a critical failure (all units failed, boot to
//! emergency/rescue target requested on kernel cmdline, or the default target
//! itself fails) it switches to `emergency.target` or `rescue.target`.
//!
//! Upstream reference: `src/core/emergency-action.c`,
//!   `src/core/main.c` (v261)

use crate::event::loop_::LoopResult;
use crate::job::{JobKind, JobQueue};

// ── BootMode ──────────────────────────────────────────────────────────────

/// The boot mode implied by the kernel command line or an internal fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BootMode {
    /// Normal boot — start `default.target` (or `systemd.unit=` override).
    #[default]
    Normal,
    /// `rescue` / `single` / `s` / `1` on the kernel cmdline.
    Rescue,
    /// `emergency` on the kernel cmdline, or escalated from a failed rescue.
    Emergency,
}

impl BootMode {
    /// Return the canonical target unit name for this mode.
    #[must_use]
    pub fn target_name(self) -> &'static str {
        match self {
            Self::Normal => "default.target",
            Self::Rescue => "rescue.target",
            Self::Emergency => "emergency.target",
        }
    }
}

// ── EmergencyAction ───────────────────────────────────────────────────────

/// What the manager should do after all emergency hooks have run.
///
/// Matches `EmergencyAction` from `src/core/emergency-action.h` (v261).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EmergencyAction {
    /// No automatic action — wait for administrator intervention.
    #[default]
    None,
    /// Exit the manager (user instance only).
    Exit,
    /// Reboot the machine.
    Reboot,
    /// Power off the machine.
    Poweroff,
    /// Halt the machine.
    Halt,
    /// Jump into a kexec kernel.
    Kexec,
}

impl EmergencyAction {
    /// Convert to the `LoopResult` that should be returned from `run()`.
    #[must_use]
    pub fn to_loop_result(self) -> Option<LoopResult> {
        match self {
            Self::None => None,
            Self::Exit => Some(LoopResult::Exit),
            // Kexec falls back to reboot if no kexec kernel is loaded.
            Self::Reboot | Self::Kexec => Some(LoopResult::Reboot),
            Self::Poweroff => Some(LoopResult::Poweroff),
            Self::Halt => Some(LoopResult::Halt),
        }
    }
}

// ── helpers ───────────────────────────────────────────────────────────────

/// Enqueue the emergency or rescue target into `queue`.
///
/// Called when a critical failure is detected so the manager activates the
/// appropriate fallback target on the next loop iteration.
pub fn enqueue_fallback(mode: BootMode, queue: &mut JobQueue) {
    queue.enqueue(JobKind::Start, mode.target_name());
}

/// Log a critical boot failure message to stderr / kmsg.
///
/// In a real PID 1 this would go to the journal and `/dev/kmsg`.  Here we
/// use stderr so test output remains legible.
pub fn log_boot_failure(reason: &str) {
    eprintln!("rustd: boot failure — {reason}");
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_mode_target_names() {
        assert_eq!(BootMode::Normal.target_name(), "default.target");
        assert_eq!(BootMode::Rescue.target_name(), "rescue.target");
        assert_eq!(BootMode::Emergency.target_name(), "emergency.target");
    }

    #[test]
    fn emergency_action_loop_result() {
        assert_eq!(EmergencyAction::None.to_loop_result(), None);
        assert_eq!(
            EmergencyAction::Exit.to_loop_result(),
            Some(LoopResult::Exit)
        );
        assert_eq!(
            EmergencyAction::Reboot.to_loop_result(),
            Some(LoopResult::Reboot)
        );
        assert_eq!(
            EmergencyAction::Poweroff.to_loop_result(),
            Some(LoopResult::Poweroff)
        );
    }

    #[test]
    fn enqueue_fallback_rescue() {
        let mut q = crate::job::JobQueue::default();
        enqueue_fallback(BootMode::Rescue, &mut q);
        let states = std::collections::HashMap::default();
        let afters = std::collections::HashMap::default();
        let jobs = q.drain_ready(&states, &afters);
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].unit_name, "rescue.target");
    }

    #[test]
    fn enqueue_fallback_emergency() {
        let mut q = crate::job::JobQueue::default();
        enqueue_fallback(BootMode::Emergency, &mut q);
        let states = std::collections::HashMap::default();
        let afters = std::collections::HashMap::default();
        let jobs = q.drain_ready(&states, &afters);
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].unit_name, "emergency.target");
    }
}
