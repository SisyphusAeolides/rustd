// SPDX-License-Identifier: LGPL-2.1-or-later
//! Timer unit activation.
//!
//! Arms a `timerfd` event for each `OnBootSec=`, `OnActiveSec=`,
//! `OnUnitActiveSec=`, or `OnUnitInactiveSec=` value.  When the timer fires,
//! a `Start` job is enqueued for the timer's `Unit=`.
//!
//! Upstream reference: `src/core/timer.c timer_enter_running()` (v261)

use std::sync::{Arc, Mutex};

use crate::event::loop_::{EventLoop, TimerHandler};
use crate::event::source::SourceId;
use crate::event::timer::{ClockId, TimerSpec};
use crate::job::{JobKind, JobQueue};
use crate::service::UnitRecord;
use crate::unit::loader::LoadedUnit;
use crate::unit::UnitState;

/// Activate a timer unit by arming timerfds for each configured trigger.
///
/// `queue` is shared with the manager; the timer handler will push `Start`
/// jobs into it when the timer fires.
///
/// # Errors
/// Propagates errors from `EventLoop::add_timer`.
pub fn activate_timer(
    record: &mut UnitRecord,
    loop_: &mut EventLoop,
    queue: &Arc<Mutex<JobQueue>>,
) -> anyhow::Result<()> {
    let LoadedUnit::Timer(ref timer) = record.loaded else {
        return Err(anyhow::anyhow!(
            "activate_timer called on non-timer unit '{}'",
            record.loaded.name()
        ));
    };

    let unit_target = if timer.specific.unit.is_empty() {
        // Default: replace .timer suffix with .service.
        let name = record.loaded.name();
        name.strip_suffix(".timer")
            .map_or_else(|| name.to_owned(), |s| format!("{s}.service"))
    } else {
        timer.specific.unit.clone()
    };

    // Arm each configured trigger.
    let triggers: Vec<std::time::Duration> = [
        timer.specific.on_boot_sec,
        timer.specific.on_active_sec,
        timer.specific.on_unit_active_sec,
        timer.specific.on_unit_inactive_sec,
    ]
    .into_iter()
    .flatten()
    .collect();

    for delay in triggers {
        #[allow(clippy::cast_possible_truncation)]
        let delay_ns = delay.as_nanos() as i64;
        if delay_ns <= 0 {
            continue;
        }
        let spec = TimerSpec::once(delay_ns);
        let target = unit_target.clone();
        let q = Arc::clone(queue);
        loop_.add_timer(
            ClockId::Boottime,
            spec,
            Box::new(TimerFiredHandler {
                unit_name: target,
                queue: q,
            }),
        )?;
    }

    record.state = UnitState::Active;
    Ok(())
}

// ── Handler ────────────────────────────────────────────────────────────────

struct TimerFiredHandler {
    unit_name: String,
    queue: Arc<Mutex<JobQueue>>,
}

impl TimerHandler for TimerFiredHandler {
    fn on_timer(&mut self, _id: SourceId, _expirations: i64) {
        if let Ok(mut q) = self.queue.lock() {
            q.enqueue(JobKind::Start, self.unit_name.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unit::loader::{LoadedUnit, ParsedUnit};
    use crate::unit::section_install::InstallSection;
    use crate::unit::section_timer::TimerSection;
    use crate::unit::section_unit::UnitSection;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::time::Duration;

    fn make_timer_record(name: &str, on_boot_sec: Option<Duration>, unit: &str) -> UnitRecord {
        let timer = TimerSection {
            on_boot_sec,
            unit: unit.to_owned(),
            ..Default::default()
        };
        let loaded = LoadedUnit::Timer(Box::new(ParsedUnit {
            name: name.to_owned(),
            source_path: PathBuf::from(format!("/fake/{name}")),
            unit: UnitSection::default(),
            install: InstallSection::default(),
            specific: timer,
        }));
        UnitRecord::new(loaded)
    }

    #[test]
    fn timer_activate_sets_active() {
        let mut record = make_timer_record(
            "test.timer",
            Some(Duration::from_millis(50)),
            "test.service",
        );
        let mut loop_ = EventLoop::new().unwrap();
        let queue = Arc::new(Mutex::new(JobQueue::default()));
        activate_timer(&mut record, &mut loop_, &Arc::clone(&queue)).unwrap();
        assert_eq!(record.state, UnitState::Active);
    }

    #[test]
    fn timer_fires_enqueues_job() {
        let mut record = make_timer_record(
            "test.timer",
            Some(Duration::from_millis(20)),
            "test.service",
        );
        let mut loop_ = EventLoop::new().unwrap();
        let queue = Arc::new(Mutex::new(JobQueue::default()));
        activate_timer(&mut record, &mut loop_, &Arc::clone(&queue)).unwrap();

        // Run the event loop briefly to let the timer fire.
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(200);
        while std::time::Instant::now() < deadline {
            let r = loop_.run_once().unwrap();
            if r != crate::event::loop_::LoopResult::Continue {
                break;
            }
            if !queue.lock().unwrap().is_empty() {
                break;
            }
        }

        let jobs: Vec<_> = {
            let mut q = queue.lock().unwrap();
            q.drain_ready(&HashMap::default(), &HashMap::default())
        };
        assert!(!jobs.is_empty(), "timer did not enqueue a job within 200ms");
        assert_eq!(jobs[0].unit_name, "test.service");
        assert_eq!(jobs[0].kind, JobKind::Start);
    }
}
