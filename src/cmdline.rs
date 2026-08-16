// SPDX-License-Identifier: LGPL-2.1-or-later
//! Kernel command-line parser for RustD — reads `/proc/cmdline` and exposes
//! native RustD manager parameters as a typed struct.

use std::fs;
use std::str::FromStr;

// ── KernelCmdline ─────────────────────────────────────────────────────────

/// Parsed kernel command-line parameters relevant to the RustD service manager.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Default, PartialEq)]
pub struct KernelCmdline {
    /// `rustd.unit=<name>` — override default.target.
    pub unit: Option<String>,
    /// `rustd.default_timeout_start_sec=<secs>`.
    pub default_timeout_start_sec: Option<u64>,
    /// `rustd.log_level=<level>`.
    pub log_level: Option<String>,
    /// `rustd.log_target=<target>`.
    pub log_target: Option<String>,
    /// `emergency` or `rustd.unit=emergency.target`.
    pub emergency: bool,
    /// `rescue` or `rustd.unit=rescue.target` or `single` / `s` / `1`.
    pub rescue: bool,
    /// `quiet` — suppress informational messages on the console.
    pub quiet: bool,
    /// `debug` — enable verbose debug logging.
    pub debug: bool,
    /// `rd.rustd.unit=<name>` — override default unit in initrd context.
    pub rd_unit: Option<String>,
    /// `rustd.crash_shell` — drop to shell on crash.
    pub crash_shell: bool,
    /// `rustd.crash_reboot` — reboot after crash instead of waiting.
    pub crash_reboot: bool,
    /// `rustd.confirm_spawn=<bool|path>` — confirm each spawn.
    pub confirm_spawn: Option<String>,
    /// `rustd.show_status=<bool>` — control status display.
    pub show_status: Option<String>,
    /// All unrecognised tokens, preserved for diagnostics.
    pub unknown: Vec<String>,
}

impl KernelCmdline {
    /// Parse `/proc/cmdline` and return a `KernelCmdline`.
    ///
    /// Non-fatal: returns `Default` if `/proc/cmdline` cannot be read.
    #[must_use]
    pub fn from_proc() -> Self {
        let Ok(line) = fs::read_to_string("/proc/cmdline") else {
            return Self::default();
        };
        Self::parse(line.trim())
    }

    /// Parse an arbitrary cmdline string (for unit tests).
    #[must_use]
    pub fn parse(line: &str) -> Self {
        let mut out = Self::default();
        for token in line.split_whitespace() {
            out.apply_token(token);
        }
        out
    }

    /// Apply a single whitespace-separated cmdline token.
    fn apply_token(&mut self, token: &str) {
        match token {
            "emergency" => {
                self.emergency = true;
                self.unit.get_or_insert_with(|| "emergency.target".into());
            }
            "rescue" | "single" | "s" | "1" => {
                self.rescue = true;
                self.unit.get_or_insert_with(|| "rescue.target".into());
            }
            "quiet" => self.quiet = true,
            "debug" => self.debug = true,
            _ => {
                if let Some(val) = token.strip_prefix("rustd.unit=") {
                    self.unit = Some(val.to_owned());
                } else if let Some(val) = token.strip_prefix("rd.rustd.unit=") {
                    self.rd_unit = Some(val.to_owned());
                } else if let Some(val) = token.strip_prefix("rustd.log_level=") {
                    self.log_level = Some(val.to_owned());
                } else if let Some(val) = token.strip_prefix("rustd.log_target=") {
                    self.log_target = Some(val.to_owned());
                } else if let Some(val) = token.strip_prefix("rustd.default_timeout_start_sec=") {
                    if let Ok(secs) = u64::from_str(val) {
                        self.default_timeout_start_sec = Some(secs);
                    }
                } else if token.starts_with("rustd.crash_shell") {
                    self.crash_shell = parse_bool_suffix(token, "rustd.crash_shell");
                } else if token.starts_with("rustd.crash_reboot") {
                    self.crash_reboot = parse_bool_suffix(token, "rustd.crash_reboot");
                } else if let Some(val) = token.strip_prefix("rustd.confirm_spawn=") {
                    self.confirm_spawn = Some(val.to_owned());
                } else if let Some(val) = token.strip_prefix("rustd.show_status=") {
                    self.show_status = Some(val.to_owned());
                } else {
                    self.unknown.push(token.to_owned());
                }
            }
        }
    }

    /// Return the default target implied by the cmdline.
    ///
    /// Precedence:
    /// 1. Explicit `rustd.unit=` value.
    /// 2. `emergency` → `emergency.target`.
    /// 3. `rescue` / `single` / `s` / `1` → `rescue.target`.
    /// 4. `None` (caller supplies the compiled-in default).
    #[must_use]
    pub fn default_unit(&self) -> Option<&str> {
        self.unit.as_deref()
    }
}

/// Parse an optional `=<bool>` suffix on a key token.
///
/// `rustd.crash_shell` (bare) → true\
/// `rustd.crash_shell=yes` → true\
/// `rustd.crash_shell=no`  → false
fn parse_bool_suffix(token: &str, key: &str) -> bool {
    if let Some(val) = token.strip_prefix(&format!("{key}=")) {
        matches!(val, "1" | "yes" | "true" | "on")
    } else {
        // bare key → true
        token == key
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_cmdline() {
        let c = KernelCmdline::parse("");
        assert!(!c.emergency);
        assert!(!c.rescue);
        assert!(c.unit.is_none());
    }

    #[test]
    fn emergency_token() {
        let c = KernelCmdline::parse("emergency");
        assert!(c.emergency);
        assert_eq!(c.unit.as_deref(), Some("emergency.target"));
    }

    #[test]
    fn rescue_token() {
        let c = KernelCmdline::parse("rescue");
        assert!(c.rescue);
        assert_eq!(c.unit.as_deref(), Some("rescue.target"));
    }

    #[test]
    fn single_alias() {
        let c = KernelCmdline::parse("single");
        assert!(c.rescue);
        assert_eq!(c.unit.as_deref(), Some("rescue.target"));
    }

    #[test]
    fn rustd_unit_overrides() {
        let c = KernelCmdline::parse("rustd.unit=graphical.target quiet");
        assert_eq!(c.unit.as_deref(), Some("graphical.target"));
        assert!(c.quiet);
    }

    #[test]
    fn initrd_unit_parsed() {
        let c = KernelCmdline::parse("rd.rustd.unit=initrd.target");
        assert_eq!(c.rd_unit.as_deref(), Some("initrd.target"));
    }

    #[test]
    fn timeout_parsed() {
        let c = KernelCmdline::parse("rustd.default_timeout_start_sec=120");
        assert_eq!(c.default_timeout_start_sec, Some(120));
    }

    #[test]
    fn log_controls_are_native() {
        let c = KernelCmdline::parse("rustd.log_level=debug rustd.log_target=console");
        assert_eq!(c.log_level.as_deref(), Some("debug"));
        assert_eq!(c.log_target.as_deref(), Some("console"));
    }

    #[test]
    fn debug_flag() {
        let c = KernelCmdline::parse("debug");
        assert!(c.debug);
    }

    #[test]
    fn crash_shell_bare() {
        let c = KernelCmdline::parse("rustd.crash_shell");
        assert!(c.crash_shell);
    }

    #[test]
    fn crash_shell_explicit_no() {
        let c = KernelCmdline::parse("rustd.crash_shell=no");
        assert!(!c.crash_shell);
    }

    #[test]
    fn unknown_tokens_collected() {
        let c = KernelCmdline::parse("root=/dev/sda1 ro splash");
        assert_eq!(c.unknown, vec!["root=/dev/sda1", "ro", "splash"]);
    }

    #[test]
    fn legacy_manager_prefix_is_not_native_control() {
        let c = KernelCmdline::parse("systemd.unit=graphical.target");
        assert!(c.unit.is_none());
        assert_eq!(c.unknown, vec!["systemd.unit=graphical.target"]);
    }

    #[test]
    fn default_unit_precedence() {
        let c = KernelCmdline::parse("rescue rustd.unit=multi-user.target");
        // rustd.unit= was parsed last and overwrites the rescue default.
        assert_eq!(c.default_unit(), Some("multi-user.target"));
    }
}
