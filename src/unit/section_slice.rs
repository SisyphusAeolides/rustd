// SPDX-License-Identifier: LGPL-2.1-or-later
//! Typed `[Slice]` section.
//!
//! Upstream reference: `src/core/slice.c`, `systemd.slice(5)` (v261).

use crate::resource_control::ResourceControl;

/// An unlimited slice concurrency limit.
pub const CONCURRENCY_UNLIMITED: u32 = u32::MAX;

/// Parsed `[Slice]` section.
#[derive(Debug, Clone)]
pub struct SliceSection {
    /// Maximum active descendants before starts are delayed.
    pub concurrency_soft_max: u32,
    /// Maximum active or pending descendants before starts are refused.
    pub concurrency_hard_max: u32,
    /// Cgroup-v2 controls inherited by member units.
    pub resource_control: ResourceControl,
}

impl Default for SliceSection {
    fn default() -> Self {
        Self {
            concurrency_soft_max: CONCURRENCY_UNLIMITED,
            concurrency_hard_max: CONCURRENCY_UNLIMITED,
            resource_control: ResourceControl::default(),
        }
    }
}

impl SliceSection {
    /// Apply a single `(key, value)` pair from the `[Slice]` section.
    pub fn apply(&mut self, key: &str, value: &str) {
        if self.resource_control.apply(key, value) {
            return;
        }
        match key {
            "ConcurrencySoftMax" => {
                if let Some(limit) = parse_concurrency_max(value) {
                    self.concurrency_soft_max = limit;
                }
            }
            "ConcurrencyHardMax" => {
                if let Some(limit) = parse_concurrency_max(value) {
                    self.concurrency_hard_max = limit;
                }
            }
            _ => {}
        }
    }
}

fn parse_concurrency_max(value: &str) -> Option<u32> {
    let value = value.trim();
    if value.is_empty() || value == "infinity" {
        return Some(CONCURRENCY_UNLIMITED);
    }
    value.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource_control::{LimitValue, ResourceControl};

    #[test]
    fn parses_slice_concurrency_and_cgroup_controls() {
        let mut section = SliceSection::default();
        section.apply("ConcurrencySoftMax", "4");
        section.apply("ConcurrencyHardMax", "8");
        section.apply("MemoryMax", "16M");

        assert_eq!(section.concurrency_soft_max, 4);
        assert_eq!(section.concurrency_hard_max, 8);
        assert_eq!(
            section.resource_control,
            ResourceControl {
                memory_max: Some(LimitValue::Value(16 * 1024 * 1024)),
                ..ResourceControl::default()
            }
        );
    }

    #[test]
    fn empty_and_infinity_mean_unlimited() {
        let mut section = SliceSection {
            concurrency_soft_max: 4,
            concurrency_hard_max: 8,
            ..Default::default()
        };
        section.apply("ConcurrencySoftMax", "");
        section.apply("ConcurrencyHardMax", "infinity");
        assert_eq!(section.concurrency_soft_max, CONCURRENCY_UNLIMITED);
        assert_eq!(section.concurrency_hard_max, CONCURRENCY_UNLIMITED);
    }
}
