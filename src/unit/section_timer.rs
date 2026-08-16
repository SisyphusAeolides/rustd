// SPDX-License-Identifier: LGPL-2.1-or-later
//! Typed `[Timer]` section.
//!
//! Upstream reference: `src/core/timer.c`, `systemd.timer(5)` (v261)

use crate::unit::duration::parse_duration;
use std::time::Duration;

fn parse_bool(s: &str) -> bool {
    matches!(s.to_ascii_lowercase().as_str(), "yes" | "true" | "1" | "on")
}

/// Parsed `[Timer]` section.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Default, Clone)]
pub struct TimerSection {
    pub on_active_sec: Option<Duration>,
    pub on_boot_sec: Option<Duration>,
    pub on_startup_sec: Option<Duration>,
    pub on_unit_active_sec: Option<Duration>,
    pub on_unit_inactive_sec: Option<Duration>,
    /// Raw calendar expression string.  Full parsing is a separate gate.
    pub on_calendar: Vec<String>,
    pub on_clock_change: bool,
    pub on_timezone_change: bool,
    pub accuracy_sec: Option<Duration>,
    pub randomized_delay_sec: Option<Duration>,
    pub fixed_random_delay: bool,
    pub on_clock_change_unit: String,
    pub persistent: bool,
    pub wake_system: bool,
    pub remain_after_elapse: bool,
    pub unit: String,
}

impl TimerSection {
    /// Apply a single `(key, value)` pair from the `[Timer]` section.
    pub fn apply(&mut self, key: &str, value: &str) {
        let dv = || parse_duration(value);
        let bv = || parse_bool(value);
        match key {
            "OnActiveSec" => self.on_active_sec = dv(),
            "OnBootSec" => self.on_boot_sec = dv(),
            "OnStartupSec" => self.on_startup_sec = dv(),
            "OnUnitActiveSec" => self.on_unit_active_sec = dv(),
            "OnUnitInactiveSec" => self.on_unit_inactive_sec = dv(),
            "OnCalendar" => {
                if value.is_empty() {
                    self.on_calendar.clear();
                } else {
                    self.on_calendar.push(value.to_owned());
                }
            }
            "OnClockChange" => self.on_clock_change = bv(),
            "OnTimezoneChange" => self.on_timezone_change = bv(),
            "AccuracySec" => self.accuracy_sec = dv(),
            "RandomizedDelaySec" => self.randomized_delay_sec = dv(),
            "FixedRandomDelay" => self.fixed_random_delay = bv(),
            "Persistent" => self.persistent = bv(),
            "WakeSystem" => self.wake_system = bv(),
            "RemainAfterElapse" => self.remain_after_elapse = bv(),
            "Unit" => value.clone_into(&mut self.unit),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unit::ini::parse_unit_text;

    #[test]
    fn tmpfiles_clean_timer() {
        let path = "/usr/lib/systemd/system/systemd-tmpfiles-clean.timer";
        let Ok(text) = std::fs::read_to_string(path) else {
            return;
        };
        let entries = parse_unit_text(&text);
        let mut t = TimerSection::default();
        for e in entries.iter().filter(|e| e.section == "Timer") {
            t.apply(&e.key, &e.value);
        }
        assert!(t.on_boot_sec.is_some());
        assert!(t.on_unit_active_sec.is_some());
    }
}
