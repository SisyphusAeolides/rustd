// SPDX-License-Identifier: LGPL-2.1-or-later
//! Typed `[Automount]` section.
//!
//! Upstream reference: `src/core/automount.c`, `systemd.automount(5)` (v261).

use std::time::Duration;

/// Parsed `[Automount]` section.
#[derive(Debug, Clone)]
pub struct AutomountSection {
    /// Absolute path managed by the autofs mount. The loader derives this
    /// from the unit name when `Where=` is not configured.
    pub where_: String,
    /// Additional autofs mount options, after unit specifier expansion.
    pub extra_options: String,
    /// Mode used to create a missing automount directory.
    pub directory_mode: u32,
    /// Idle-unmount timeout. `None` means disabled (`TimeoutIdleSec=0`).
    pub timeout_idle_sec: Option<Duration>,
    /// The related mount unit derived from this automount unit name.
    pub trigger_unit: String,
}

impl Default for AutomountSection {
    fn default() -> Self {
        Self {
            where_: String::new(),
            extra_options: String::new(),
            directory_mode: 0o755,
            timeout_idle_sec: None,
            trigger_unit: String::new(),
        }
    }
}

impl AutomountSection {
    /// Apply a single `(key, value)` pair from the `[Automount]` section.
    pub fn apply(&mut self, key: &str, value: &str) {
        match key {
            "Where" => value.clone_into(&mut self.where_),
            "ExtraOptions" => value.clone_into(&mut self.extra_options),
            "DirectoryMode" => {
                if let Some(mode) = parse_mode(value) {
                    self.directory_mode = mode;
                }
            }
            "TimeoutIdleSec" => {
                let value = value.trim();
                if matches!(value, "0" | "infinity") {
                    self.timeout_idle_sec = None;
                } else if let Some(timeout) = crate::unit::duration::parse_duration(value) {
                    self.timeout_idle_sec = Some(timeout);
                }
            }
            _ => {}
        }
    }
}

fn parse_mode(value: &str) -> Option<u32> {
    let value = value.trim();
    if value.is_empty() || value.starts_with(['+', '-']) {
        return None;
    }
    let mode = u32::from_str_radix(value, 8).ok()?;
    (mode <= 0o7777).then_some(mode)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_v261_automount_directives() {
        let mut section = AutomountSection::default();
        section.apply("Where", "/srv/archive");
        section.apply("ExtraOptions", "browse,ghost");
        section.apply("DirectoryMode", "0711");
        section.apply("TimeoutIdleSec", "5min");

        assert_eq!(section.where_, "/srv/archive");
        assert_eq!(section.extra_options, "browse,ghost");
        assert_eq!(section.directory_mode, 0o711);
        assert_eq!(section.timeout_idle_sec, Some(Duration::from_secs(300)));
    }

    #[test]
    fn idle_timeout_zero_disables_expiration() {
        let mut section = AutomountSection::default();
        section.apply("TimeoutIdleSec", "30s");
        section.apply("TimeoutIdleSec", "0");
        assert_eq!(section.timeout_idle_sec, None);
    }

    #[test]
    fn invalid_mode_keeps_the_previous_value() {
        let mut section = AutomountSection::default();
        section.apply("DirectoryMode", "0700");
        section.apply("DirectoryMode", "999");
        assert_eq!(section.directory_mode, 0o700);
    }
}
