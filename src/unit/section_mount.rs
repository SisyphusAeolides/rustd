// SPDX-License-Identifier: LGPL-2.1-or-later
//! Typed `[Mount]` section.
//!
//! Upstream reference: `src/core/mount.c`, `systemd.mount(5)` (v261)

use crate::unit::duration::parse_duration;

fn parse_bool(s: &str) -> bool {
    matches!(s.to_ascii_lowercase().as_str(), "yes" | "true" | "1" | "on")
}

/// Parsed `[Mount]` section.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Default, Clone)]
pub struct MountSection {
    pub what: String,
    pub where_: String,
    pub r#type: String,
    pub options: String,
    pub sloppy_options: bool,
    pub lazy_unmount: bool,
    pub read_write_only: bool,
    pub force_unmount: bool,
    pub directory_mode: String,
    pub timeout_sec: Option<std::time::Duration>,
}

impl MountSection {
    /// Apply a single `(key, value)` pair from the `[Mount]` section.
    pub fn apply(&mut self, key: &str, value: &str) {
        match key {
            "What" => value.clone_into(&mut self.what),
            "Where" => value.clone_into(&mut self.where_),
            "Type" => value.clone_into(&mut self.r#type),
            "Options" => value.clone_into(&mut self.options),
            "SloppyOptions" => self.sloppy_options = parse_bool(value),
            "LazyUnmount" => self.lazy_unmount = parse_bool(value),
            "ReadWriteOnly" => self.read_write_only = parse_bool(value),
            "ForceUnmount" => self.force_unmount = parse_bool(value),
            "DirectoryMode" => value.clone_into(&mut self.directory_mode),
            "TimeoutSec" => self.timeout_sec = parse_duration(value),
            _ => {}
        }
    }
}
