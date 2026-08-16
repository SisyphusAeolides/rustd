// SPDX-License-Identifier: LGPL-2.1-or-later
//! Configuration types for the rustd service manager.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use crate::limits::{RlimitResource, RlimitSpec, TasksMaxSpec};
use crate::resource_control::LimitValue;
use crate::unit::ini::parse_unit_text;
use crate::unit::loader::LoadedUnit;
use crate::unit::section_service::ServiceSection;

/// Runtime scope of the service manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ManagerScope {
    /// System manager (normally PID 1).
    #[default]
    System,
    /// Per-user service manager.
    User,
}

/// Top-level manager configuration, parsed from manager defaults and drop-ins.
#[derive(Debug)]
pub struct ManagerConfig {
    /// System or per-user manager scope.
    pub scope: ManagerScope,
    /// Default timeout for service activation, in seconds.
    pub default_timeout_start_sec: u64,
    /// Default timeout for service stop, in seconds.
    pub default_timeout_stop_sec: u64,
    /// Log level: "emerg", "alert", "crit", "err", "warning", "notice",
    /// "info", "debug".
    pub log_level: String,
    /// Log target: "console", "journal", "kmsg", "journal-or-kmsg".
    pub log_target: String,
    /// Parsed `[Manager]` defaults shared with the D-Bus server and unit
    /// loader. The lock is replaced transactionally during daemon-reload.
    pub unit_defaults: Arc<RwLock<UnitDefaults>>,
}

impl ManagerConfig {
    #[must_use]
    pub fn default_system() -> Self {
        Self {
            scope: ManagerScope::System,
            default_timeout_start_sec: 90,
            default_timeout_stop_sec: 90,
            log_level: "info".into(),
            log_target: "journal-or-kmsg".into(),
            unit_defaults: Arc::new(RwLock::new(UnitDefaults::load(ManagerScope::System))),
        }
    }

    #[must_use]
    pub fn default_user() -> Self {
        Self {
            scope: ManagerScope::User,
            default_timeout_start_sec: 90,
            default_timeout_stop_sec: 90,
            log_level: "info".into(),
            log_target: "console".into(),
            unit_defaults: Arc::new(RwLock::new(UnitDefaults::load(ManagerScope::User))),
        }
    }
}

/// Parsed `RustD` `[Manager]` unit defaults.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UnitDefaults {
    /// Configured soft/hard rlimit pairs, indexed by [`RlimitResource`].
    /// `None` preserves the manager-process fallback behavior.
    pub rlimits: [Option<RlimitSpec>; 16],
    /// Default task limit, including percentage scale information.
    pub tasks_max: TasksMaxSpec,
}

impl UnitDefaults {
    /// Parse the system or user manager configuration using `RustD` precedence.
    #[must_use]
    pub fn load(scope: ManagerScope) -> Self {
        let (main, dropins) = manager_config_paths(scope);
        Self::load_paths(scope, &main, &dropins)
    }

    fn load_paths(scope: ManagerScope, main: &[PathBuf], dropins: &[PathBuf]) -> Self {
        let mut defaults = Self::default();

        if let Some(path) = main.iter().find(|path| path.is_file()) {
            defaults.apply_file(path);
        }

        let mut files = Vec::new();
        for directory in dropins {
            let Ok(entries) = std::fs::read_dir(directory) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                let Some(name) = path.file_name() else {
                    continue;
                };
                if files.iter().any(|existing: &PathBuf| {
                    existing
                        .file_name()
                        .is_some_and(|existing_name| existing_name == name)
                }) {
                    continue;
                }
                files.push(path);
            }
        }
        files.sort_by(|left, right| {
            left.file_name()
                .cmp(&right.file_name())
                .then_with(|| left.cmp(right))
        });
        for path in files {
            defaults.apply_file(&path);
        }
        defaults.apply_process_fallbacks(scope);
        defaults
    }

    fn apply_process_fallbacks(&mut self, scope: ManagerScope) {
        if self.rlimit(RlimitResource::Nofile).is_none() {
            let mut fallback = process_rlimit(RlimitResource::Nofile);
            if let Some(spec) = fallback.as_mut() {
                spec.soft = min_rlimit(spec.soft, 1024);
                if scope == ManagerScope::System {
                    let nr_open = std::fs::read_to_string("/proc/sys/fs/nr_open")
                        .ok()
                        .and_then(|value| value.trim().parse::<u64>().ok())
                        .unwrap_or(u64::MAX);
                    spec.hard = min_rlimit(max_rlimit(spec.hard, 512 * 1024), nr_open);
                }
            }
            self.rlimits[RlimitResource::Nofile.index()] = fallback;
        }

        if self.rlimit(RlimitResource::Memlock).is_none() {
            let mut fallback = process_rlimit(RlimitResource::Memlock);
            if scope == ManagerScope::System {
                if let Some(spec) = fallback.as_mut() {
                    const DEFAULT_MEMLOCK: u64 = 8 * 1024 * 1024;
                    spec.soft = max_rlimit(spec.soft, DEFAULT_MEMLOCK);
                    spec.hard = max_rlimit(spec.hard, DEFAULT_MEMLOCK);
                }
            }
            self.rlimits[RlimitResource::Memlock.index()] = fallback;
        }
    }

    fn apply_file(&mut self, path: &Path) {
        let Ok(text) = std::fs::read_to_string(path) else {
            return;
        };
        for entry in parse_unit_text(&text) {
            if entry.section == "Manager" {
                self.apply_entry(&entry.key, &entry.value);
            }
        }
    }

    /// Apply one Manager assignment. Invalid rlimit values leave the prior
    /// value intact.
    pub fn apply_entry(&mut self, key: &str, value: &str) {
        if let Some(resource) = RlimitResource::ALL
            .into_iter()
            .find(|resource| key == format!("DefaultLimit{}", resource.key()))
        {
            if let Some(parsed) = RlimitSpec::parse(value, resource.kind()) {
                self.rlimits[resource.index()] = Some(parsed);
            }
            return;
        }
        if key == "DefaultTasksMax" {
            if let Some(parsed) = TasksMaxSpec::parse(value) {
                self.tasks_max = parsed;
            }
        }
    }

    /// Return a configured rlimit, if this manager has one.
    #[must_use]
    pub fn rlimit(&self, resource: RlimitResource) -> Option<RlimitSpec> {
        self.rlimits[resource.index()]
    }

    /// Return the resolved manager `DefaultTasksMax` value.
    #[must_use]
    pub fn tasks_max_value(&self) -> u64 {
        self.tasks_max.resolve()
    }

    /// Apply manager defaults to a newly parsed unit. Explicit unit values
    /// win. Slices deliberately do not inherit `DefaultTasksMax`.
    pub fn apply_to_loaded_unit(&self, loaded: &mut LoadedUnit) {
        let LoadedUnit::Service(service) = loaded else {
            return;
        };
        apply_service_defaults(&mut service.specific, self);
    }
}

fn process_rlimit(resource: RlimitResource) -> Option<RlimitSpec> {
    let mut value = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(resource.libc_resource(), &mut value) } != 0 {
        return None;
    }
    Some(RlimitSpec {
        soft: libc_rlimit_value(value.rlim_cur),
        hard: libc_rlimit_value(value.rlim_max),
    })
}

fn libc_rlimit_value(value: libc::rlim_t) -> crate::limits::RlimitValue {
    if value == libc::RLIM_INFINITY {
        crate::limits::RlimitValue::Infinity
    } else {
        crate::limits::RlimitValue::Value(value)
    }
}

fn min_rlimit(value: crate::limits::RlimitValue, maximum: u64) -> crate::limits::RlimitValue {
    match value {
        crate::limits::RlimitValue::Value(value) => {
            crate::limits::RlimitValue::Value(value.min(maximum))
        }
        crate::limits::RlimitValue::Infinity => crate::limits::RlimitValue::Value(maximum),
    }
}

fn max_rlimit(value: crate::limits::RlimitValue, minimum: u64) -> crate::limits::RlimitValue {
    match value {
        crate::limits::RlimitValue::Value(value) => {
            crate::limits::RlimitValue::Value(value.max(minimum))
        }
        crate::limits::RlimitValue::Infinity => crate::limits::RlimitValue::Infinity,
    }
}

fn apply_service_defaults(service: &mut ServiceSection, defaults: &UnitDefaults) {
    for resource in RlimitResource::ALL {
        let inherited = defaults.rlimit(resource);
        let target = service_limit_mut(service, resource);
        if target.is_none() {
            *target = inherited;
        }
    }
    if service.resource_control.tasks_max.is_none() {
        service.resource_control.tasks_max = Some(match defaults.tasks_max.resolve() {
            value if value == u64::MAX => LimitValue::Max,
            value => LimitValue::Value(value),
        });
        service.resource_control.tasks_max_default = true;
    }
}

fn service_limit_mut(
    service: &mut ServiceSection,
    resource: RlimitResource,
) -> &mut Option<RlimitSpec> {
    match resource {
        RlimitResource::Cpu => &mut service.limit_cpu,
        RlimitResource::Fsize => &mut service.limit_fsize,
        RlimitResource::Data => &mut service.limit_data,
        RlimitResource::Stack => &mut service.limit_stack,
        RlimitResource::Core => &mut service.limit_core,
        RlimitResource::Rss => &mut service.limit_rss,
        RlimitResource::Nofile => &mut service.limit_nofile,
        RlimitResource::As => &mut service.limit_as,
        RlimitResource::Nproc => &mut service.limit_nproc,
        RlimitResource::Memlock => &mut service.limit_memlock,
        RlimitResource::Locks => &mut service.limit_locks,
        RlimitResource::Sigpending => &mut service.limit_sigpending,
        RlimitResource::Msgqueue => &mut service.limit_msgqueue,
        RlimitResource::Nice => &mut service.limit_nice,
        RlimitResource::Rtprio => &mut service.limit_rtprio,
        RlimitResource::Rttime => &mut service.limit_rttime,
    }
}

fn manager_config_paths(scope: ManagerScope) -> (Vec<PathBuf>, Vec<PathBuf>) {
    if let Some(path) = std::env::var_os("RUSTD_MANAGER_CONFIG") {
        let dropins = std::env::var_os("RUSTD_MANAGER_DROPIN_DIRS")
            .map(|value| std::env::split_paths(&value).collect())
            .unwrap_or_default();
        return (vec![PathBuf::from(path)], dropins);
    }

    let (main, dirs) = match scope {
        ManagerScope::System => (
            vec![
                PathBuf::from("/etc/rustd/system.conf"),
                PathBuf::from("/run/rustd/system.conf"),
                PathBuf::from("/usr/local/lib/rustd/system.conf"),
                PathBuf::from("/usr/lib/rustd/system.conf"),
            ],
            vec![
                PathBuf::from("/etc/rustd/system.conf.d"),
                PathBuf::from("/run/rustd/system.conf.d"),
                PathBuf::from("/usr/local/lib/rustd/system.conf.d"),
                PathBuf::from("/usr/lib/rustd/system.conf.d"),
            ],
        ),
        ManagerScope::User => {
            let config_home = std::env::var_os("XDG_CONFIG_HOME").map_or_else(
                || {
                    std::env::var_os("HOME")
                        .map_or_else(|| PathBuf::from("/home/unknown"), PathBuf::from)
                        .join(".config")
                },
                PathBuf::from,
            );
            (
                vec![
                    config_home.join("rustd/user.conf"),
                    PathBuf::from("/etc/rustd/user.conf"),
                    PathBuf::from("/run/rustd/user.conf"),
                    PathBuf::from("/usr/local/lib/rustd/user.conf"),
                    PathBuf::from("/usr/lib/rustd/user.conf"),
                ],
                vec![
                    config_home.join("rustd/user.conf.d"),
                    PathBuf::from("/etc/rustd/user.conf.d"),
                    PathBuf::from("/run/rustd/user.conf.d"),
                    PathBuf::from("/usr/local/lib/rustd/user.conf.d"),
                    PathBuf::from("/usr/lib/rustd/user.conf.d"),
                ],
            )
        }
    };
    (main, dirs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manager_assignments_are_transactional_on_invalid_values() {
        let mut defaults = UnitDefaults::default();
        defaults.apply_entry("DefaultLimitNOFILE", "55:66");
        defaults.apply_entry("DefaultLimitNOFILE", "200:100");
        defaults.apply_entry("DefaultLimitNOFILE", "");
        assert_eq!(
            defaults.rlimit(RlimitResource::Nofile).unwrap().hard,
            crate::limits::RlimitValue::Value(66)
        );
        defaults.apply_entry("DefaultTasksMax", "15%");
        assert_eq!(
            defaults.tasks_max,
            TasksMaxSpec {
                value: 1500,
                scale: 10_000
            }
        );
        defaults.apply_entry("DefaultTasksMax", "invalid");
        assert_eq!(
            defaults.tasks_max,
            TasksMaxSpec {
                value: 1500,
                scale: 10_000
            }
        );
        defaults.apply_entry("DefaultTasksMax", "");
        assert_eq!(defaults.tasks_max, TasksMaxSpec::unlimited());
    }

    #[test]
    fn explicit_service_values_override_manager_defaults() {
        let mut defaults = UnitDefaults::default();
        defaults.apply_entry("DefaultLimitNOFILE", "123:456");
        defaults.apply_entry("DefaultTasksMax", "15%");
        let mut service = ServiceSection::default();
        apply_service_defaults(&mut service, &defaults);
        assert_eq!(
            service.limit_nofile.unwrap().soft,
            crate::limits::RlimitValue::Value(123)
        );
        assert!(service.resource_control.tasks_max_default);

        let explicit = RlimitSpec::parse("7:8", crate::limits::RlimitKind::Count).unwrap();
        service.limit_nofile = Some(explicit);
        service.resource_control.tasks_max = Some(LimitValue::Value(9));
        service.resource_control.tasks_max_default = false;
        apply_service_defaults(&mut service, &defaults);
        assert_eq!(service.limit_nofile, Some(explicit));
        assert_eq!(
            service.resource_control.tasks_max,
            Some(LimitValue::Value(9))
        );
    }

    #[test]
    fn empty_unit_tasks_max_restores_manager_default() {
        let mut defaults = UnitDefaults::default();
        defaults.apply_entry("DefaultTasksMax", "37");
        let mut service = ServiceSection::default();
        assert!(service.resource_control.apply("TasksMax", "9"));
        assert!(service.resource_control.apply("TasksMax", ""));

        apply_service_defaults(&mut service, &defaults);
        assert_eq!(
            service.resource_control.tasks_max,
            Some(LimitValue::Value(37))
        );
        assert!(service.resource_control.tasks_max_default);
    }

    #[test]
    fn manager_config_precedence_shadows_duplicate_dropin_basenames() {
        let temporary = tempfile::tempdir().unwrap();
        let main_high = temporary.path().join("high.conf");
        let main_low = temporary.path().join("low.conf");
        let dropin_high = temporary.path().join("high.d");
        let dropin_low = temporary.path().join("low.d");
        std::fs::create_dir_all(&dropin_high).unwrap();
        std::fs::create_dir_all(&dropin_low).unwrap();
        std::fs::write(
            &main_high,
            "[Manager]\nDefaultLimitNOFILE=10:20\nDefaultLimitCPU=1s\n",
        )
        .unwrap();
        std::fs::write(
            &main_low,
            "[Manager]\nDefaultLimitNOFILE=30:40\nDefaultLimitCPU=2s\n",
        )
        .unwrap();
        std::fs::write(
            dropin_low.join("10-duplicate.conf"),
            "[Manager]\nDefaultLimitCPU=3s\n",
        )
        .unwrap();
        std::fs::write(
            dropin_high.join("10-duplicate.conf"),
            "[Manager]\nDefaultLimitCPU=4s\n",
        )
        .unwrap();
        std::fs::write(
            dropin_low.join("20-later.conf"),
            "[Manager]\nDefaultLimitNOFILE=50:60\n",
        )
        .unwrap();

        let defaults = UnitDefaults::load_paths(
            ManagerScope::User,
            &[main_high, main_low],
            &[dropin_high, dropin_low],
        );
        assert_eq!(
            defaults.rlimit(RlimitResource::Cpu).unwrap().hard,
            crate::limits::RlimitValue::Value(4)
        );
        assert_eq!(
            defaults.rlimit(RlimitResource::Nofile).unwrap().hard,
            crate::limits::RlimitValue::Value(60)
        );
    }
}
