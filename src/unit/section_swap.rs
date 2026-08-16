// SPDX-License-Identifier: LGPL-2.1-or-later
//! Typed `[Swap]` section.
//!
//! Upstream reference: `src/core/swap.c`, `systemd.swap(5)` (v261)

use crate::unit::duration::parse_duration;

/// Parsed `[Swap]` section.
#[derive(Debug, Default, Clone)]
pub struct SwapSection {
    pub what: String,
    pub priority: Option<i32>,
    pub options: String,
    pub timeout_sec: Option<std::time::Duration>,
}

impl SwapSection {
    /// Apply a single `(key, value)` pair from the `[Swap]` section.
    pub fn apply(&mut self, key: &str, value: &str) {
        match key {
            "What" => value.clone_into(&mut self.what),
            "Priority" => self.priority = value.parse().ok(),
            "Options" => value.clone_into(&mut self.options),
            "TimeoutSec" => self.timeout_sec = parse_duration(value),
            _ => {}
        }
    }
}
