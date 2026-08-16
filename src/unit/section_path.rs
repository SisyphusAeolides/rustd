// SPDX-License-Identifier: LGPL-2.1-or-later
//! Typed `[Path]` section.
//!
//! Upstream reference: `src/core/path.c`, `systemd.path(5)` (v261)

fn parse_bool(s: &str) -> bool {
    matches!(s.to_ascii_lowercase().as_str(), "yes" | "true" | "1" | "on")
}

/// A `Path*=` directive with the kind and the path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathSpec {
    /// `"PathExists"`, `"PathExistsGlob"`, `"PathChanged"`,
    /// `"PathModified"`, or `"DirectoryNotEmpty"`.
    pub kind: String,
    pub path: String,
}

/// Parsed `[Path]` section.
#[derive(Debug, Default, Clone)]
pub struct PathSection {
    pub watches: Vec<PathSpec>,
    pub unit: String,
    pub make_directory: bool,
    pub directory_mode: String,
    pub trigger_limit_interval_sec: Option<std::time::Duration>,
    pub trigger_limit_burst: Option<u32>,
}

impl PathSection {
    /// Apply a single `(key, value)` pair from the `[Path]` section.
    pub fn apply(&mut self, key: &str, value: &str) {
        match key {
            "PathExists" | "PathExistsGlob" | "PathChanged" | "PathModified"
            | "DirectoryNotEmpty" => {
                if value.is_empty() {
                    self.watches.retain(|w| w.kind != key);
                } else {
                    self.watches.push(PathSpec {
                        kind: key.to_owned(),
                        path: value.to_owned(),
                    });
                }
            }
            "Unit" => value.clone_into(&mut self.unit),
            "MakeDirectory" => self.make_directory = parse_bool(value),
            "DirectoryMode" => value.clone_into(&mut self.directory_mode),
            "TriggerLimitIntervalSec" => {
                self.trigger_limit_interval_sec = crate::unit::duration::parse_duration(value);
            }
            "TriggerLimitBurst" => self.trigger_limit_burst = value.parse().ok(),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unit::ini::parse_unit_text;

    #[test]
    fn apport_path() {
        // Use any installed .path unit.
        let paths = &[
            "/usr/lib/systemd/system/apport-autoreport.path",
            "/usr/lib/systemd/system/systemd-ask-password-console.path",
        ];
        for p in paths {
            let Ok(text) = std::fs::read_to_string(p) else {
                continue;
            };
            let entries = parse_unit_text(&text);
            let mut s = PathSection::default();
            for e in entries.iter().filter(|e| e.section == "Path") {
                s.apply(&e.key, &e.value);
            }
            assert!(!s.watches.is_empty(), "no watches parsed from {p}");
            return;
        }
    }
}
