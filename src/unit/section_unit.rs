// SPDX-License-Identifier: LGPL-2.1-or-later
//! Typed `[Unit]` section for systemd unit files.
//!
//! Upstream reference: `src/core/load-fragment.c` `[Unit]` keys (v261)

use crate::unit::condition::Condition;

/// Parsed `[Unit]` section.
///
/// All dependency list fields accumulate across repeated keys.
/// An empty-value key (`Key=`) resets the corresponding list.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Default, Clone)]
pub struct UnitSection {
    // Descriptive
    pub description: String,
    pub documentation: Vec<String>,
    // Dependencies
    pub wants: Vec<String>,
    pub requires: Vec<String>,
    pub requisite: Vec<String>,
    pub binds_to: Vec<String>,
    pub part_of: Vec<String>,
    pub upholds: Vec<String>,
    pub conflicts: Vec<String>,
    pub before: Vec<String>,
    pub after: Vec<String>,
    pub on_failure: Vec<String>,
    pub on_success: Vec<String>,
    pub propagates_reload_to: Vec<String>,
    pub reload_propagated_from: Vec<String>,
    pub propagates_stop_to: Vec<String>,
    pub stop_propagated_from: Vec<String>,
    pub joins_namespace_of: Vec<String>,
    pub requires_mounts_for: Vec<String>,
    pub wants_mounts_for: Vec<String>,
    // Behaviour flags
    pub default_dependencies: bool,
    pub ignore_on_isolate: bool,
    pub stop_when_unneeded: bool,
    pub refuse_manual_start: bool,
    pub refuse_manual_stop: bool,
    pub allow_isolate: bool,
    pub collect_mode: CollectMode,
    pub survive_final_kill_signal: bool,
    pub on_success_job_mode: String,
    pub on_failure_job_mode: String,
    // Failure/success actions
    pub failure_action: UnitAction,
    pub success_action: UnitAction,
    pub failure_action_exit_status: Option<i32>,
    pub success_action_exit_status: Option<i32>,
    // Job timeouts
    pub job_timeout_sec: Option<std::time::Duration>,
    pub job_running_timeout_sec: Option<std::time::Duration>,
    pub job_timeout_action: UnitAction,
    pub job_timeout_reboot_argument: String,
    // Start limits
    pub start_limit_interval_sec: Option<std::time::Duration>,
    pub start_limit_burst: Option<u32>,
    pub start_limit_action: UnitAction,
    pub reboot_argument: String,
    // Conditions and assertions
    pub conditions: Vec<Condition>,
    pub asserts: Vec<Condition>,
    // Source path (set by loader, not parsed from file)
    pub source_path: String,
}

/// Action to take on failure, success, or timeout.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum UnitAction {
    #[default]
    None,
    Reboot,
    RebootForce,
    RebootImmediate,
    Poweroff,
    PoweroffForce,
    PoweroffImmediate,
    Exit,
    ExitForce,
    SoftReboot,
    SoftRebootForce,
    Halt,
    KExec,
}

impl UnitAction {
    fn parse(s: &str) -> Self {
        match s {
            "reboot" => Self::Reboot,
            "reboot-force" => Self::RebootForce,
            "reboot-immediate" => Self::RebootImmediate,
            "poweroff" => Self::Poweroff,
            "poweroff-force" => Self::PoweroffForce,
            "poweroff-immediate" => Self::PoweroffImmediate,
            "exit" => Self::Exit,
            "exit-force" => Self::ExitForce,
            "soft-reboot" => Self::SoftReboot,
            "soft-reboot-force" => Self::SoftRebootForce,
            "halt" => Self::Halt,
            "kexec" => Self::KExec,
            _ => Self::None,
        }
    }
}

/// `CollectMode=` setting.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum CollectMode {
    #[default]
    Inactive,
    InactiveOrFailed,
}

impl CollectMode {
    fn parse(s: &str) -> Self {
        match s {
            "inactive-or-failed" => Self::InactiveOrFailed,
            _ => Self::Inactive,
        }
    }
}

/// Parse a boolean value the same way systemd does.
fn parse_bool(s: &str) -> bool {
    matches!(s.to_ascii_lowercase().as_str(), "yes" | "true" | "1" | "on")
}

/// Split a space-separated unit name list, filtering empty strings.
fn split_units(s: &str) -> Vec<String> {
    s.split_whitespace().map(str::to_owned).collect()
}

/// Apply a space-separated duration string to a list field,
/// resetting on empty value.
fn apply_list(list: &mut Vec<String>, value: &str) {
    if value.is_empty() {
        list.clear();
    } else {
        list.extend(split_units(value));
    }
}

impl UnitSection {
    /// Apply a single `(key, value)` pair from the `[Unit]` section.
    ///
    /// Unknown keys are silently ignored, matching upstream permissive behaviour.
    pub fn apply(&mut self, key: &str, value: &str) {
        match key {
            "Description" => value.clone_into(&mut self.description),
            "Documentation" => apply_list(&mut self.documentation, value),
            "Wants" => apply_list(&mut self.wants, value),
            "Requires" => apply_list(&mut self.requires, value),
            "Requisite" => apply_list(&mut self.requisite, value),
            "BindsTo" => apply_list(&mut self.binds_to, value),
            "PartOf" => apply_list(&mut self.part_of, value),
            "Upholds" => apply_list(&mut self.upholds, value),
            "Conflicts" => apply_list(&mut self.conflicts, value),
            "Before" => apply_list(&mut self.before, value),
            "After" => apply_list(&mut self.after, value),
            "OnFailure" => apply_list(&mut self.on_failure, value),
            "OnSuccess" => apply_list(&mut self.on_success, value),
            "PropagatesReloadTo" => apply_list(&mut self.propagates_reload_to, value),
            "ReloadPropagatedFrom" => apply_list(&mut self.reload_propagated_from, value),
            "PropagatesStopTo" => apply_list(&mut self.propagates_stop_to, value),
            "StopPropagatedFrom" => apply_list(&mut self.stop_propagated_from, value),
            "JoinsNamespaceOf" => apply_list(&mut self.joins_namespace_of, value),
            "RequiresMountsFor" => apply_list(&mut self.requires_mounts_for, value),
            "WantsMountsFor" => apply_list(&mut self.wants_mounts_for, value),
            "DefaultDependencies" => self.default_dependencies = parse_bool(value),
            "IgnoreOnIsolate" => self.ignore_on_isolate = parse_bool(value),
            "StopWhenUnneeded" => self.stop_when_unneeded = parse_bool(value),
            "RefuseManualStart" => self.refuse_manual_start = parse_bool(value),
            "RefuseManualStop" => self.refuse_manual_stop = parse_bool(value),
            "AllowIsolate" => self.allow_isolate = parse_bool(value),
            "CollectMode" => self.collect_mode = CollectMode::parse(value),
            "SurviveFinalKillSignal" => self.survive_final_kill_signal = parse_bool(value),
            "OnSuccessJobMode" => value.clone_into(&mut self.on_success_job_mode),
            "OnFailureJobMode" => value.clone_into(&mut self.on_failure_job_mode),
            "OnFailureIsolate" => self.on_failure_job_mode = "isolate".to_owned(),
            "FailureAction" => self.failure_action = UnitAction::parse(value),
            "SuccessAction" => self.success_action = UnitAction::parse(value),
            "FailureActionExitStatus" => {
                self.failure_action_exit_status = value.parse().ok();
            }
            "SuccessActionExitStatus" => {
                self.success_action_exit_status = value.parse().ok();
            }
            "JobTimeoutSec" => {
                self.job_timeout_sec = crate::unit::duration::parse_duration(value);
            }
            "JobRunningTimeoutSec" => {
                self.job_running_timeout_sec = crate::unit::duration::parse_duration(value);
            }
            "JobTimeoutAction" => self.job_timeout_action = UnitAction::parse(value),
            "JobTimeoutRebootArgument" => {
                value.clone_into(&mut self.job_timeout_reboot_argument);
            }
            "StartLimitIntervalSec" => {
                self.start_limit_interval_sec = crate::unit::duration::parse_duration(value);
            }
            "StartLimitBurst" => {
                self.start_limit_burst = value.parse().ok();
            }
            "StartLimitAction" => self.start_limit_action = UnitAction::parse(value),
            "RebootArgument" => value.clone_into(&mut self.reboot_argument),
            "SourcePath" => value.clone_into(&mut self.source_path),
            key if Condition::is_key(key) => {
                let is_assert = key.starts_with("Assert");
                if value.is_empty() {
                    if is_assert {
                        self.asserts.clear();
                    } else {
                        self.conditions.clear();
                    }
                } else {
                    let cond = Condition::parse(key, value);
                    if cond.is_assert {
                        self.asserts.push(cond);
                    } else {
                        self.conditions.push(cond);
                    }
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unit::ini::parse_unit_text;

    fn load_journald() -> Option<UnitSection> {
        let path = "/usr/lib/systemd/system/systemd-journald.service";
        let text = std::fs::read_to_string(path).ok()?;
        let entries = parse_unit_text(&text);
        let mut s = UnitSection {
            default_dependencies: true,
            ..Default::default()
        };
        for e in entries.iter().filter(|e| e.section == "Unit") {
            s.apply(&e.key, &e.value);
        }
        Some(s)
    }

    #[test]
    fn journald_description() {
        let Some(s) = load_journald() else { return };
        assert_ne!(s.description, "");
    }

    #[test]
    fn journald_requires() {
        let Some(s) = load_journald() else { return };
        assert!(s.requires.iter().any(|u| u.contains("journald")));
    }

    #[test]
    fn journald_after() {
        let Some(s) = load_journald() else { return };
        assert!(s.after.iter().any(|u| u.contains("journald")));
    }

    #[test]
    fn journald_before() {
        let Some(s) = load_journald() else { return };
        assert!(s.before.iter().any(|u| u == "sysinit.target"));
    }

    #[test]
    fn default_dependencies_default() {
        // When no DefaultDependencies= key is present, default is true.
        let s = UnitSection {
            default_dependencies: true,
            ..Default::default()
        };
        assert!(s.default_dependencies);
    }

    #[test]
    fn list_reset_on_empty() {
        let mut s = UnitSection::default();
        s.apply("After", "a.target");
        s.apply("After", "");
        s.apply("After", "b.target");
        assert_eq!(s.after, vec!["b.target"]);
    }

    #[test]
    fn parses_v261_condition_and_job_policy_directives() {
        let mut section = UnitSection {
            default_dependencies: true,
            ..Default::default()
        };
        section.apply("ConditionPathExists", "|!/run/example");
        section.apply("AssertArchitecture", "x86-64");
        section.apply("WantsMountsFor", "/var/lib/example");
        section.apply("SurviveFinalKillSignal", "yes");
        section.apply("OnSuccessJobMode", "replace-irreversibly");
        section.apply("OnFailureIsolate", "yes");

        assert_eq!(section.conditions.len(), 1);
        assert_eq!(section.conditions[0].value, "/run/example");
        assert!(section.conditions[0].trigger);
        assert!(section.conditions[0].negate);
        assert_eq!(section.asserts.len(), 1);
        assert_eq!(section.wants_mounts_for, vec!["/var/lib/example"]);
        assert!(section.survive_final_kill_signal);
        assert_eq!(section.on_success_job_mode, "replace-irreversibly");
        assert_eq!(section.on_failure_job_mode, "isolate");
    }
}
