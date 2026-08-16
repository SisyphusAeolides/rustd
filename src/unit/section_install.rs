// SPDX-License-Identifier: LGPL-2.1-or-later
//! Typed `[Install]` section.
//!
//! Upstream reference: `src/core/unit-file.c`, `systemd.unit(5)` `[Install]` (v261)

/// Parsed `[Install]` section.
#[derive(Debug, Default, Clone)]
pub struct InstallSection {
    pub wanted_by: Vec<String>,
    pub required_by: Vec<String>,
    pub upheld_by: Vec<String>,
    pub also: Vec<String>,
    pub alias: Vec<String>,
    pub default_instance: String,
}

fn apply_list(list: &mut Vec<String>, value: &str) {
    if value.is_empty() {
        list.clear();
    } else {
        list.extend(value.split_whitespace().map(str::to_owned));
    }
}

impl InstallSection {
    /// Apply a single `(key, value)` pair from the `[Install]` section.
    pub fn apply(&mut self, key: &str, value: &str) {
        match key {
            "WantedBy" => apply_list(&mut self.wanted_by, value),
            "RequiredBy" => apply_list(&mut self.required_by, value),
            "UpheldBy" => apply_list(&mut self.upheld_by, value),
            "Also" => apply_list(&mut self.also, value),
            "Alias" => apply_list(&mut self.alias, value),
            "DefaultInstance" => value.clone_into(&mut self.default_instance),
            _ => {}
        }
    }
}
