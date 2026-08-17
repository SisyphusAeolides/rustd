// SPDX-License-Identifier: LGPL-2.1-or-later
//! `RustD` unit loader: search paths, drop-ins, and template instantiation.
//!
//! `UnitLoader` finds a `RustD` unit file on disk, applies drop-in overlays, and
//! returns a fully parsed `LoadedUnit`.
//!
//! Native system unit search directory priority (highest first):
//! 1. `/etc/rustd/system/`
//! 2. `/run/rustd/system/`
//! 3. `/usr/local/lib/rustd/system/`
//! 4. `/usr/lib/rustd/system/`

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::config::ManagerScope;
use crate::unit::{
    ini::parse_unit_text,
    section_automount::AutomountSection,
    section_install::InstallSection,
    section_mount::MountSection,
    section_path::PathSection,
    section_service::{ServiceSection, ServiceType},
    section_slice::SliceSection,
    section_socket::SocketSection,
    section_swap::SwapSection,
    section_timer::TimerSection,
    section_unit::UnitSection,
    specifier::{split_unit_name, SpecifierContext},
};

// ── LoadedUnit ────────────────────────────────────────────────────────────

/// A fully parsed and resolved `RustD` unit file.
#[derive(Debug)]
pub enum LoadedUnit {
    Service(Box<ParsedUnit<ServiceSection>>),
    Socket(Box<ParsedUnit<SocketSection>>),
    Automount(Box<ParsedUnit<AutomountSection>>),
    Timer(Box<ParsedUnit<TimerSection>>),
    Path(Box<ParsedUnit<PathSection>>),
    Mount(Box<ParsedUnit<MountSection>>),
    Swap(Box<ParsedUnit<SwapSection>>),
    Target(Box<ParsedUnit<()>>),
    Slice(Box<ParsedUnit<SliceSection>>),
    Scope(Box<ParsedUnit<()>>),
}

impl LoadedUnit {
    /// The unit name (e.g. `"rustd-journald.service"`).
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Service(u) => &u.name,
            Self::Socket(u) => &u.name,
            Self::Automount(u) => &u.name,
            Self::Timer(u) => &u.name,
            Self::Path(u) => &u.name,
            Self::Mount(u) => &u.name,
            Self::Swap(u) => &u.name,
            Self::Slice(u) => &u.name,
            Self::Target(u) | Self::Scope(u) => &u.name,
        }
    }

    /// The `[Unit]` section, common to all unit types.
    #[must_use]
    pub fn unit_section(&self) -> &UnitSection {
        match self {
            Self::Service(u) => &u.unit,
            Self::Socket(u) => &u.unit,
            Self::Automount(u) => &u.unit,
            Self::Timer(u) => &u.unit,
            Self::Path(u) => &u.unit,
            Self::Mount(u) => &u.unit,
            Self::Swap(u) => &u.unit,
            Self::Slice(u) => &u.unit,
            Self::Target(u) | Self::Scope(u) => &u.unit,
        }
    }

    /// Mutable access to the common `[Unit]` section for manager-side live
    /// property updates.
    pub fn unit_section_mut(&mut self) -> &mut UnitSection {
        match self {
            Self::Service(u) => &mut u.unit,
            Self::Socket(u) => &mut u.unit,
            Self::Automount(u) => &mut u.unit,
            Self::Timer(u) => &mut u.unit,
            Self::Path(u) => &mut u.unit,
            Self::Mount(u) => &mut u.unit,
            Self::Swap(u) => &mut u.unit,
            Self::Slice(u) => &mut u.unit,
            Self::Target(u) | Self::Scope(u) => &mut u.unit,
        }
    }

    /// The source path of the loaded unit file.
    #[must_use]
    pub fn source_path(&self) -> &Path {
        match self {
            Self::Service(u) => &u.source_path,
            Self::Socket(u) => &u.source_path,
            Self::Automount(u) => &u.source_path,
            Self::Timer(u) => &u.source_path,
            Self::Path(u) => &u.source_path,
            Self::Mount(u) => &u.source_path,
            Self::Swap(u) => &u.source_path,
            Self::Slice(u) => &u.source_path,
            Self::Target(u) | Self::Scope(u) => &u.source_path,
        }
    }

    /// The `[Install]` section, common to all unit types.
    #[must_use]
    pub fn install_section(&self) -> &InstallSection {
        match self {
            Self::Service(u) => &u.install,
            Self::Socket(u) => &u.install,
            Self::Automount(u) => &u.install,
            Self::Timer(u) => &u.install,
            Self::Path(u) => &u.install,
            Self::Mount(u) => &u.install,
            Self::Swap(u) => &u.install,
            Self::Slice(u) => &u.install,
            Self::Target(u) | Self::Scope(u) => &u.install,
        }
    }
}

/// A parsed unit with its common sections and a type-specific section `T`.
#[derive(Debug)]
pub struct ParsedUnit<T> {
    /// The unit name, e.g. `"rustd-journald.service"`.
    pub name: String,
    /// Path to the unit file on disk.
    pub source_path: PathBuf,
    /// The `[Unit]` section.
    pub unit: UnitSection,
    /// The `[Install]` section.
    pub install: InstallSection,
    /// The type-specific section (`[Service]`, `[Socket]`, etc.).
    pub specific: T,
}

fn standard_unit_search_dirs() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/etc/rustd/system"),
        PathBuf::from("/run/rustd/system"),
        PathBuf::from("/usr/local/lib/rustd/system"),
        PathBuf::from("/usr/lib/rustd/system"),
    ]
}

/// Collect unit names enabled under `<dir>/<unit_name>.<kind>/`.
fn collect_dependency_links(directory: &Path, unit_name: &str, kind: &str, into: &mut Vec<String>) {
    let wants_dir = directory.join(format!("{unit_name}.{kind}"));
    let Ok(entries) = std::fs::read_dir(&wants_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.is_empty() || name.starts_with('.') {
            continue;
        }
        if !into.iter().any(|existing| existing == name) {
            into.push(name.to_owned());
        }
    }
}

fn unit_control_dirs() -> Vec<PathBuf> {
    vec![
        std::env::var_os("RUSTD_SYSTEM_CONTROL_PATH")
            .map_or_else(|| PathBuf::from("/etc/rustd/system.control"), PathBuf::from),
        std::env::var_os("RUSTD_RUNTIME_CONTROL_PATH")
            .map_or_else(|| PathBuf::from("/run/rustd/system.control"), PathBuf::from),
    ]
}

fn unit_search_dirs(override_value: Option<&OsStr>) -> Vec<PathBuf> {
    let defaults = standard_unit_search_dirs();
    let Some(value) = override_value else {
        return defaults;
    };

    let append_defaults = value.to_string_lossy().ends_with(':');
    let mut search_dirs: Vec<PathBuf> = std::env::split_paths(value)
        .filter(|path| !path.as_os_str().is_empty())
        .collect();
    if append_defaults {
        search_dirs.extend(defaults);
    }
    search_dirs
}

fn user_home_dir() -> PathBuf {
    std::env::var_os("HOME").map_or_else(
        || PathBuf::from(format!("/home/{}", unsafe { libc::getuid() })),
        PathBuf::from,
    )
}

fn user_config_home() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map_or_else(|| user_home_dir().join(".config"), PathBuf::from)
}

fn user_data_home() -> PathBuf {
    std::env::var_os("XDG_DATA_HOME")
        .map_or_else(|| user_home_dir().join(".local/share"), PathBuf::from)
}

fn user_runtime_dir() -> Option<PathBuf> {
    std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from)
}

fn xdg_search_dirs(variable: &str, default: &str, suffix: &str) -> Vec<PathBuf> {
    let value = std::env::var_os(variable).unwrap_or_else(|| default.into());
    std::env::split_paths(&value)
        .filter(|path| !path.as_os_str().is_empty())
        .map(|path| path.join(suffix))
        .collect()
}

fn standard_user_unit_search_dirs() -> Vec<PathBuf> {
    let config_home = user_config_home();
    let data_home = user_data_home();
    let runtime = user_runtime_dir();
    let mut paths = Vec::new();

    paths.push(config_home.join("rustd/user.control"));
    if let Some(runtime) = &runtime {
        paths.push(runtime.join("rustd/user.control"));
        paths.push(runtime.join("rustd/transient"));
        paths.push(runtime.join("rustd/generator.early"));
    }
    paths.push(config_home.join("rustd/user"));
    paths.push(config_home.join("rustd/user.attached"));
    paths.extend(xdg_search_dirs("XDG_CONFIG_DIRS", "/etc/xdg", "rustd/user"));
    paths.push(PathBuf::from("/etc/rustd/user"));
    if let Some(runtime) = &runtime {
        paths.push(runtime.join("rustd/user"));
        paths.push(runtime.join("rustd/user.attached"));
    }
    paths.push(PathBuf::from("/run/rustd/user"));
    if let Some(runtime) = &runtime {
        paths.push(runtime.join("rustd/generator"));
    }
    paths.push(data_home.join("rustd/user"));
    paths.extend(xdg_search_dirs(
        "XDG_DATA_DIRS",
        "/usr/local/share:/usr/share",
        "rustd/user",
    ));
    paths.extend([
        PathBuf::from("/usr/local/lib/rustd/user"),
        PathBuf::from("/usr/local/share/rustd/user"),
        PathBuf::from("/usr/lib/rustd/user"),
        PathBuf::from("/usr/share/rustd/user"),
    ]);
    if let Some(runtime) = runtime {
        paths.push(runtime.join("rustd/generator.late"));
    }
    paths.dedup();
    paths
}

fn user_unit_control_dirs() -> Vec<PathBuf> {
    let persistent = std::env::var_os("RUSTD_SYSTEM_CONTROL_PATH").map_or_else(
        || user_config_home().join("rustd/user.control"),
        PathBuf::from,
    );
    let mut dirs = vec![persistent];
    let runtime = std::env::var_os("RUSTD_RUNTIME_CONTROL_PATH").map_or_else(
        || user_runtime_dir().map(|path| path.join("rustd/user.control")),
        |path| Some(PathBuf::from(path)),
    );
    if let Some(runtime) = runtime {
        dirs.push(runtime);
    }
    dirs
}

fn user_unit_search_dirs(override_value: Option<&OsStr>) -> Vec<PathBuf> {
    let defaults = standard_user_unit_search_dirs();
    let Some(value) = override_value else {
        return defaults;
    };
    let append_defaults = value.to_string_lossy().ends_with(':');
    let mut search_dirs: Vec<PathBuf> = std::env::split_paths(value)
        .filter(|path| !path.as_os_str().is_empty())
        .collect();
    if append_defaults {
        search_dirs.extend(defaults);
    }
    search_dirs
}

// ── UnitLoader ────────────────────────────────────────────────────────────

/// Loads `RustD` unit files from disk.
pub struct UnitLoader {
    /// Search directories in priority order (highest priority first).
    pub search_dirs: Vec<PathBuf>,
    /// High-priority drop-in roots used by `rustctl set-property`.
    control_dirs: Vec<PathBuf>,
    scope: ManagerScope,
}

impl Default for UnitLoader {
    fn default() -> Self {
        Self::system()
    }
}

impl UnitLoader {
    /// Create a loader with the standard `RustD` system search paths.
    #[must_use]
    pub fn system() -> Self {
        let override_value = std::env::var_os("RUSTD_UNIT_PATH");
        Self {
            search_dirs: unit_search_dirs(override_value.as_deref()),
            control_dirs: unit_control_dirs(),
            scope: ManagerScope::System,
        }
    }

    /// Create a loader with the `RustD` user/XDG search hierarchy.
    #[must_use]
    pub fn user() -> Self {
        let override_value = std::env::var_os("RUSTD_UNIT_PATH");
        Self {
            search_dirs: user_unit_search_dirs(override_value.as_deref()),
            control_dirs: user_unit_control_dirs(),
            scope: ManagerScope::User,
        }
    }

    /// Create a loader for the selected manager scope.
    #[must_use]
    pub fn for_scope(scope: ManagerScope) -> Self {
        match scope {
            ManagerScope::System => Self::system(),
            ManagerScope::User => Self::user(),
        }
    }

    /// Create a loader with custom search paths (useful for testing).
    #[must_use]
    pub fn with_dirs(dirs: Vec<PathBuf>) -> Self {
        Self {
            search_dirs: dirs,
            control_dirs: Vec::new(),
            scope: ManagerScope::System,
        }
    }

    /// Create a loader with custom unit and control drop-in roots.
    #[must_use]
    pub fn with_dirs_and_control(dirs: Vec<PathBuf>, control_dirs: Vec<PathBuf>) -> Self {
        Self {
            search_dirs: dirs,
            control_dirs,
            scope: ManagerScope::System,
        }
    }

    /// Load `unit_name` from disk, applying drop-ins and resolving templates.
    ///
    /// # Errors
    /// Returns an error if the unit file cannot be found or read.
    pub fn load(&self, unit_name: &str) -> anyhow::Result<LoadedUnit> {
        if let Some(unit) = self.builtin_slice(unit_name) {
            return Ok(unit);
        }
        let (unit_path, template_instance) = self.find_unit_file(unit_name)?;
        let ctx = self.build_context(unit_name, template_instance.as_deref());

        let base_text = std::fs::read_to_string(&unit_path)?;
        let mut entries = parse_unit_text(&base_text);

        let dropin_entries = self.collect_dropins(unit_name, template_instance.as_deref());
        entries.extend(dropin_entries);

        let suffix = unit_path.extension().and_then(|e| e.to_str()).unwrap_or("");

        let loaded =
            Self::build_loaded_unit(unit_name, &unit_path, suffix, &entries, &ctx, self.scope)?;
        if let LoadedUnit::Automount(automount) = &loaded {
            self.find_unit_file(&automount.specific.trigger_unit)
                .map_err(|_| {
                    anyhow::anyhow!(
                        "automount unit '{unit_name}' has no matching mount unit '{}'",
                        automount.specific.trigger_unit
                    )
                })?;
        }
        Ok(self.apply_dependency_directories(unit_name, loaded))
    }

    /// Merge units enabled via `*.wants/` and `*.requires/` into the loaded unit.
    ///
    /// `RustD` packages install enablement symlinks in the native search roots.
    fn apply_dependency_directories(&self, unit_name: &str, mut loaded: LoadedUnit) -> LoadedUnit {
        let mut wants = Vec::new();
        let mut requires = Vec::new();
        for directory in &self.search_dirs {
            collect_dependency_links(directory, unit_name, "wants", &mut wants);
            collect_dependency_links(directory, unit_name, "requires", &mut requires);
        }

        if wants.is_empty() && requires.is_empty() {
            return loaded;
        }

        let section = loaded.unit_section_mut();
        for name in wants {
            if !section.wants.iter().any(|existing| existing == &name) {
                section.wants.push(name);
            }
        }
        for name in requires {
            if !section.requires.iter().any(|existing| existing == &name) {
                section.requires.push(name);
            }
        }
        loaded
    }

    fn find_unit_file(&self, unit_name: &str) -> anyhow::Result<(PathBuf, Option<String>)> {
        for dir in &self.search_dirs {
            let p = dir.join(unit_name);
            if p.exists() {
                return Ok((p, None));
            }
        }

        let (prefix, instance, suffix) = split_unit_name(unit_name);
        if !instance.is_empty() {
            let template = format!("{prefix}@.{suffix}");
            for dir in &self.search_dirs {
                let p = dir.join(&template);
                if p.exists() {
                    return Ok((p, Some(instance)));
                }
            }
        }

        Err(anyhow::anyhow!("unit file not found: {unit_name}"))
    }

    fn builtin_slice(&self, unit_name: &str) -> Option<LoadedUnit> {
        let description = match unit_name {
            "-.slice" => "Root Slice",
            "system.slice" if self.scope == ManagerScope::System => "System Slice",
            _ => return None,
        };
        Some(LoadedUnit::Slice(Box::new(ParsedUnit {
            name: unit_name.to_owned(),
            source_path: PathBuf::new(),
            unit: UnitSection {
                description: description.to_owned(),
                default_dependencies: false,
                ignore_on_isolate: true,
                ..Default::default()
            },
            install: InstallSection::default(),
            specific: SliceSection::default(),
        })))
    }

    fn build_context(&self, unit_name: &str, instance: Option<&str>) -> SpecifierContext {
        let mut ctx = match self.scope {
            ManagerScope::System => SpecifierContext::for_system_unit(unit_name),
            ManagerScope::User => SpecifierContext::for_user_unit(unit_name),
        };
        if let Some(inst) = instance {
            inst.clone_into(&mut ctx.instance);
        }
        ctx
    }

    fn collect_dropins(
        &self,
        unit_name: &str,
        _instance: Option<&str>,
    ) -> Vec<crate::unit::ini::RawEntry> {
        self.dropin_paths(unit_name)
            .into_iter()
            .filter_map(|path| std::fs::read_to_string(path).ok())
            .flat_map(|text| parse_unit_text(&text))
            .collect()
    }

    /// Return the drop-in files applied to `unit_name`, in application order.
    #[must_use]
    pub fn dropin_paths(&self, unit_name: &str) -> Vec<PathBuf> {
        let dirs: Vec<PathBuf> = self
            .search_dirs
            .iter()
            .rev()
            .chain(self.control_dirs.iter())
            .flat_map(|directory| {
                [directory.join(format!("{unit_name}.d")), {
                    let (prefix, instance, suffix) = split_unit_name(unit_name);
                    if instance.is_empty() {
                        PathBuf::new()
                    } else {
                        directory.join(format!("{prefix}@.{suffix}.d"))
                    }
                }]
                .into_iter()
                .filter(|path| !path.as_os_str().is_empty() && path.is_dir())
            })
            .collect();

        let mut paths = Vec::new();
        for directory in dirs {
            let mut files: Vec<PathBuf> = std::fs::read_dir(directory)
                .into_iter()
                .flatten()
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| {
                    path.extension().and_then(|extension| extension.to_str()) == Some("conf")
                })
                .collect();
            files.sort();
            paths.extend(files);
        }
        paths
    }

    #[allow(clippy::too_many_lines)]
    fn build_loaded_unit(
        unit_name: &str,
        unit_path: &Path,
        suffix: &str,
        entries: &[crate::unit::ini::RawEntry],
        ctx: &SpecifierContext,
        scope: ManagerScope,
    ) -> anyhow::Result<LoadedUnit> {
        let mut unit_sec = UnitSection {
            default_dependencies: true,
            ignore_on_isolate: matches!(suffix, "automount" | "slice"),
            ..Default::default()
        };
        let mut install_sec = InstallSection::default();

        for e in entries.iter().filter(|e| e.section == "Unit") {
            unit_sec.apply(&e.key, &e.value);
        }
        for e in entries.iter().filter(|e| e.section == "Install") {
            install_sec.apply(&e.key, &e.value);
        }
        unit_sec.source_path = unit_path.display().to_string();
        unit_sec.description = crate::unit::specifier::expand(&unit_sec.description, ctx);

        let name = unit_name.to_owned();
        let source_path = unit_path.to_path_buf();

        macro_rules! make_unit {
            ($variant:ident, $section_ty:ty, $section_name:expr) => {{
                let mut specific = <$section_ty>::default();
                for e in entries.iter().filter(|e| e.section == $section_name) {
                    specific.apply(&e.key, &e.value);
                }
                LoadedUnit::$variant(Box::new(ParsedUnit {
                    name,
                    source_path,
                    unit: unit_sec,
                    install: install_sec,
                    specific,
                }))
            }};
        }

        let loaded = match suffix {
            "service" => {
                let mut specific = ServiceSection {
                    guess_main_pid: true,
                    ..Default::default()
                };
                for e in entries.iter().filter(|e| e.section == "Service") {
                    specific.apply(&e.key, &e.value);
                }
                if specific.service_type == ServiceType::Oneshot && specific.exit_type == "cgroup" {
                    return Err(anyhow::anyhow!(
                        "service '{unit_name}' has ExitType=cgroup, which is not allowed for Type=oneshot"
                    ));
                }
                expand_service_specifiers(&mut specific, ctx);
                LoadedUnit::Service(Box::new(ParsedUnit {
                    name,
                    source_path,
                    unit: unit_sec,
                    install: install_sec,
                    specific,
                }))
            }
            "socket" => {
                let mut specific = SocketSection::default();
                for e in entries.iter().filter(|e| e.section == "Socket") {
                    specific.apply(&e.key, &e.value);
                }
                expand_socket_specifiers(&mut specific, ctx);
                LoadedUnit::Socket(Box::new(ParsedUnit {
                    name,
                    source_path,
                    unit: unit_sec,
                    install: install_sec,
                    specific,
                }))
            }
            "automount" => {
                let mut specific = AutomountSection::default();
                for e in entries.iter().filter(|e| e.section == "Automount") {
                    specific.apply(&e.key, &e.value);
                }
                finalize_automount(&mut specific, unit_name, ctx)?;
                add_automount_dependencies(&mut unit_sec, &specific, scope);
                LoadedUnit::Automount(Box::new(ParsedUnit {
                    name,
                    source_path,
                    unit: unit_sec,
                    install: install_sec,
                    specific,
                }))
            }
            "timer" => make_unit!(Timer, TimerSection, "Timer"),
            "path" => {
                let mut specific = PathSection::default();
                for entry in entries.iter().filter(|entry| entry.section == "Path") {
                    specific.apply(&entry.key, &entry.value);
                }
                for watch in &mut specific.watches {
                    watch.path = crate::unit::specifier::expand(&watch.path, ctx);
                }
                specific.unit = crate::unit::specifier::expand(&specific.unit, ctx);
                LoadedUnit::Path(Box::new(ParsedUnit {
                    name,
                    source_path,
                    unit: unit_sec,
                    install: install_sec,
                    specific,
                }))
            }
            "mount" => make_unit!(Mount, MountSection, "Mount"),
            "swap" => make_unit!(Swap, SwapSection, "Swap"),
            "target" | "slice" | "scope" => match suffix {
                "slice" => {
                    let mut specific = SliceSection::default();
                    for e in entries.iter().filter(|e| e.section == "Slice") {
                        specific.apply(&e.key, &e.value);
                    }
                    finalize_slice(&mut unit_sec, unit_name)?;
                    LoadedUnit::Slice(Box::new(ParsedUnit {
                        name,
                        source_path,
                        unit: unit_sec,
                        install: install_sec,
                        specific,
                    }))
                }
                "scope" => LoadedUnit::Scope(Box::new(ParsedUnit {
                    name,
                    source_path,
                    unit: unit_sec,
                    install: install_sec,
                    specific: (),
                })),
                _ => LoadedUnit::Target(Box::new(ParsedUnit {
                    name,
                    source_path,
                    unit: unit_sec,
                    install: install_sec,
                    specific: (),
                })),
            },
            other => {
                return Err(anyhow::anyhow!("unknown unit suffix: {other}"));
            }
        };

        Ok(loaded)
    }
}

fn add_unique(values: &mut Vec<String>, value: String) {
    if !values.iter().any(|existing| existing == &value) {
        values.push(value);
    }
}

fn simplify_absolute_path(path: &str) -> Option<String> {
    if !path.starts_with('/') {
        return None;
    }
    let mut components = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            _ => components.push(component),
        }
    }
    Some(if components.is_empty() {
        "/".to_owned()
    } else {
        format!("/{}", components.join("/"))
    })
}

fn decode_unit_path_stem(stem: &str) -> anyhow::Result<String> {
    if stem.is_empty() {
        anyhow::bail!("unit path stem is empty");
    }
    if stem == "-" {
        return Ok("/".to_owned());
    }

    let bytes = stem.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len() + 1);
    decoded.push(b'/');
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'-' => {
                decoded.push(b'/');
                index += 1;
            }
            b'\\' if index + 3 < bytes.len() && bytes[index + 1] == b'x' => {
                let high = (bytes[index + 2] as char)
                    .to_digit(16)
                    .ok_or_else(|| anyhow::anyhow!("invalid unit-name escape in '{stem}'"))?;
                let low = (bytes[index + 3] as char)
                    .to_digit(16)
                    .ok_or_else(|| anyhow::anyhow!("invalid unit-name escape in '{stem}'"))?;
                decoded.push(
                    u8::try_from((high << 4) | low)
                        .map_err(|_| anyhow::anyhow!("invalid unit-name escape in '{stem}'"))?,
                );
                index += 4;
            }
            b'\\' => anyhow::bail!("invalid unit-name escape in '{stem}'"),
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(decoded).map_err(|_| anyhow::anyhow!("unit path is not UTF-8"))
}

fn path_from_unit_name(unit_name: &str, suffix: &str) -> anyhow::Result<String> {
    let stem = unit_name
        .strip_suffix(suffix)
        .ok_or_else(|| anyhow::anyhow!("unit '{unit_name}' does not end in '{suffix}'"))?;
    decode_unit_path_stem(stem)
}

fn escape_path_for_unit(path: &str, suffix: &str) -> anyhow::Result<String> {
    let path = simplify_absolute_path(path)
        .ok_or_else(|| anyhow::anyhow!("unit path '{path}' is not absolute"))?;
    if path == "/" {
        return Ok(format!("-{suffix}"));
    }

    let mut name = String::with_capacity(path.len() + suffix.len());
    for byte in path.as_bytes().iter().copied().skip(1) {
        match byte {
            b'/' => name.push('-'),
            b'-' => name.push_str("\\x2d"),
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b':' | b'_' | b'.' => {
                name.push(char::from(byte));
            }
            _ => {
                let _ = write!(name, "\\x{byte:02x}");
            }
        }
    }
    name.push_str(suffix);
    Ok(name)
}

fn expand_exec_command(
    command: &mut crate::unit::section_service::ExecCommand,
    ctx: &SpecifierContext,
) {
    command.path = crate::unit::specifier::expand(&command.path, ctx);
    for arg in &mut command.argv {
        *arg = crate::unit::specifier::expand(arg, ctx);
    }
}

fn expand_exec_list(
    commands: &mut [crate::unit::section_service::ExecCommand],
    ctx: &SpecifierContext,
) {
    for command in commands {
        expand_exec_command(command, ctx);
    }
}

fn expand_service_specifiers(service: &mut ServiceSection, ctx: &SpecifierContext) {
    expand_exec_list(&mut service.exec_condition, ctx);
    expand_exec_list(&mut service.exec_start_pre, ctx);
    expand_exec_list(&mut service.exec_start, ctx);
    expand_exec_list(&mut service.exec_start_post, ctx);
    expand_exec_list(&mut service.exec_reload, ctx);
    expand_exec_list(&mut service.exec_stop, ctx);
    expand_exec_list(&mut service.exec_stop_post, ctx);
    service.working_directory = crate::unit::specifier::expand(&service.working_directory, ctx);
    service.root_directory = crate::unit::specifier::expand(&service.root_directory, ctx);
    service.tty_path = crate::unit::specifier::expand(&service.tty_path, ctx);
    service.pid_file = crate::unit::specifier::expand(&service.pid_file, ctx);
    service.bus_name = crate::unit::specifier::expand(&service.bus_name, ctx);
    for value in &mut service.environment {
        *value = crate::unit::specifier::expand(value, ctx);
    }
}

fn expand_socket_specifiers(socket: &mut SocketSection, ctx: &SpecifierContext) {
    for listen in &mut socket.listen {
        listen.address = crate::unit::specifier::expand(&listen.address, ctx);
    }
    for command in &mut socket.exec_start_pre {
        *command = crate::unit::specifier::expand(command, ctx);
    }
    for command in &mut socket.exec_start_post {
        *command = crate::unit::specifier::expand(command, ctx);
    }
    for command in &mut socket.exec_stop_pre {
        *command = crate::unit::specifier::expand(command, ctx);
    }
    for command in &mut socket.exec_stop_post {
        *command = crate::unit::specifier::expand(command, ctx);
    }
    socket.service = crate::unit::specifier::expand(&socket.service, ctx);
}

fn finalize_automount(
    automount: &mut AutomountSection,
    unit_name: &str,
    ctx: &SpecifierContext,
) -> anyhow::Result<()> {
    const AUTOMOUNT_SUFFIX: &str = ".automount";
    const RESERVED_OPTIONS: &[&str] = &["fd", "pgrp", "minproto", "maxproto", "direct", "indirect"];

    let stem = unit_name
        .strip_suffix(AUTOMOUNT_SUFFIX)
        .ok_or_else(|| anyhow::anyhow!("invalid automount unit name '{unit_name}'"))?;
    if stem.contains('@') {
        anyhow::bail!("automount units cannot be templated: '{unit_name}'");
    }

    let derived_where = path_from_unit_name(unit_name, AUTOMOUNT_SUFFIX)?;
    let configured_where = crate::unit::specifier::expand(&automount.where_, ctx);
    let where_ = if configured_where.is_empty() {
        derived_where
    } else {
        simplify_absolute_path(&configured_where).ok_or_else(|| {
            anyhow::anyhow!("Automount.Where= for '{unit_name}' is not an absolute path")
        })?
    };
    if where_ == "/" {
        anyhow::bail!("automount unit '{unit_name}' cannot manage the root directory");
    }
    let expected_name = escape_path_for_unit(&where_, AUTOMOUNT_SUFFIX)?;
    if unit_name != expected_name {
        anyhow::bail!(
            "Automount.Where= '{where_}' does not match unit name '{unit_name}' (expected '{expected_name}')"
        );
    }

    automount.where_ = where_;
    automount.extra_options = crate::unit::specifier::expand(&automount.extra_options, ctx);
    if automount.extra_options.split(',').any(|option| {
        let name = option
            .trim()
            .split_once('=')
            .map_or(option.trim(), |(name, _)| name);
        RESERVED_OPTIONS.contains(&name)
    }) {
        anyhow::bail!("Automount.ExtraOptions= contains a reserved autofs option");
    }
    automount.trigger_unit = format!("{stem}.mount");
    Ok(())
}

fn add_automount_dependencies(
    unit: &mut UnitSection,
    automount: &AutomountSection,
    scope: ManagerScope,
) {
    add_unique(&mut unit.before, automount.trigger_unit.clone());
    if unit.default_dependencies && scope == ManagerScope::System {
        add_unique(&mut unit.before, "local-fs.target".to_owned());
        add_unique(&mut unit.after, "local-fs-pre.target".to_owned());
        add_unique(&mut unit.before, "umount.target".to_owned());
        add_unique(&mut unit.conflicts, "umount.target".to_owned());
    }
}

fn slice_parent_name(unit_name: &str) -> anyhow::Result<Option<String>> {
    let stem = unit_name
        .strip_suffix(".slice")
        .ok_or_else(|| anyhow::anyhow!("invalid slice unit name '{unit_name}'"))?;
    if stem == "-" {
        return Ok(None);
    }
    if stem.is_empty()
        || stem.contains('@')
        || stem.starts_with('-')
        || stem.ends_with('-')
        || stem.split('-').any(str::is_empty)
        || !valid_escaped_unit_stem(stem)
    {
        anyhow::bail!("invalid slice unit name '{unit_name}'");
    }
    Ok(stem.rsplit_once('-').map_or_else(
        || Some("-.slice".to_owned()),
        |(parent, _)| Some(format!("{parent}.slice")),
    ))
}

fn valid_escaped_unit_stem(stem: &str) -> bool {
    let bytes = stem.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b':' | b'_' | b'.' | b'-' => {
                index += 1;
            }
            b'\\'
                if index + 3 < bytes.len()
                    && bytes[index + 1] == b'x'
                    && (bytes[index + 2] as char).is_ascii_hexdigit()
                    && (bytes[index + 3] as char).is_ascii_hexdigit() =>
            {
                index += 4;
            }
            _ => return false,
        }
    }
    true
}

fn finalize_slice(unit: &mut UnitSection, unit_name: &str) -> anyhow::Result<()> {
    if let Some(parent) = slice_parent_name(unit_name)? {
        add_unique(&mut unit.requires, parent.clone());
        add_unique(&mut unit.after, parent);
    }
    if unit.default_dependencies {
        add_unique(&mut unit.before, "shutdown.target".to_owned());
        add_unique(&mut unit.conflicts, "shutdown.target".to_owned());
    }
    if unit.description.is_empty() {
        let path = path_from_unit_name(unit_name, ".slice")?;
        unit.description = format!("Slice {path}");
    }
    Ok(())
}

/// Return true if `cond` is satisfied on the live system.
///
/// Used by the service manager before activating a unit.
#[must_use]
pub fn all_conditions_pass(unit: &UnitSection) -> bool {
    crate::unit::condition::evaluate_list(&unit.conditions)
}

/// Return true if all assertions hold.
#[must_use]
pub fn all_asserts_pass(unit: &UnitSection) -> bool {
    crate::unit::condition::evaluate_list(&unit.asserts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unit::section_service::ServiceType;

    #[test]
    fn unit_path_override_replaces_defaults() {
        let dirs = unit_search_dirs(Some(OsStr::new("/tmp/units-a:/tmp/units-b")));
        assert_eq!(
            dirs,
            vec![PathBuf::from("/tmp/units-a"), PathBuf::from("/tmp/units-b")]
        );
    }

    #[test]
    fn trailing_colon_appends_standard_paths() {
        let dirs = unit_search_dirs(Some(OsStr::new("/tmp/units:")));
        assert_eq!(
            dirs.first().map(PathBuf::as_path),
            Some(Path::new("/tmp/units"))
        );
        assert!(dirs.contains(&PathBuf::from("/usr/lib/rustd/system")));
    }

    #[test]
    fn user_loader_prefers_rustd_xdg_config_and_runtime_paths() {
        let home = tempfile::tempdir().unwrap();
        let runtime = tempfile::tempdir().unwrap();
        let old_home = std::env::var_os("HOME");
        let old_config = std::env::var_os("XDG_CONFIG_HOME");
        let old_runtime = std::env::var_os("XDG_RUNTIME_DIR");
        let old_unit_path = std::env::var_os("RUSTD_UNIT_PATH");
        std::env::set_var("HOME", home.path());
        std::env::set_var("XDG_CONFIG_HOME", home.path().join("cfg"));
        std::env::set_var("XDG_RUNTIME_DIR", runtime.path());
        std::env::remove_var("RUSTD_UNIT_PATH");
        let loader = UnitLoader::user();
        assert_eq!(
            loader.search_dirs[0],
            home.path().join("cfg/rustd/user.control")
        );
        assert!(loader
            .search_dirs
            .contains(&home.path().join("cfg/rustd/user")));
        assert!(loader
            .search_dirs
            .contains(&runtime.path().join("rustd/user")));
        for (key, value) in [
            ("HOME", old_home),
            ("XDG_CONFIG_HOME", old_config),
            ("XDG_RUNTIME_DIR", old_runtime),
            ("RUSTD_UNIT_PATH", old_unit_path),
        ] {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }

    #[test]
    fn expands_template_specifiers_in_exec_and_listen() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("getty@.service"),
            "[Service]\nExecStart=/usr/bin/agetty --noclear %I linux\nTTYPath=/dev/%I\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("agent@.socket"),
            "[Socket]\nListenStream=%f/S.agent\n",
        )
        .unwrap();
        let loader = UnitLoader::with_dirs(vec![dir.path().to_path_buf()]);
        let LoadedUnit::Service(svc) = loader.load("getty@tty1.service").unwrap() else {
            panic!("expected service");
        };
        assert_eq!(svc.specific.exec_start[0].argv[1], "--noclear");
        assert_eq!(svc.specific.exec_start[0].argv[2], "tty1");
        assert_eq!(svc.specific.tty_path, "/dev/tty1");

        let LoadedUnit::Socket(sock) = loader.load("agent@etc-pacman.d-gnupg.socket").unwrap()
        else {
            panic!("expected socket");
        };
        assert_eq!(
            sock.specific.listen[0].address,
            "/etc/pacman.d/gnupg/S.agent"
        );
    }

    #[test]
    fn load_rustd_journald_service() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("rustd-journald.service"),
            "[Unit]\nDescription=RustD Journal Service\n[Service]\nType=notify-reload\nExecStart=/usr/lib/rustd/rustd-journald\n",
        )
        .unwrap();
        let loader = UnitLoader::with_dirs(vec![dir.path().to_path_buf()]);
        let unit = loader.load("rustd-journald.service").unwrap();
        assert_eq!(unit.name(), "rustd-journald.service");
        let LoadedUnit::Service(svc) = unit else {
            panic!("expected Service variant");
        };
        assert!(!svc.unit.description.is_empty());
        assert_eq!(svc.specific.service_type, ServiceType::NotifyReload);
        assert!(!svc.specific.exec_start.is_empty());
    }

    #[test]
    fn service_defaults_guess_main_pid() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("forking.service"),
            "[Service]\nType=forking\nExecStart=/bin/true\n",
        )
        .unwrap();
        let loader = UnitLoader::with_dirs(vec![dir.path().to_path_buf()]);
        let LoadedUnit::Service(service) = loader.load("forking.service").unwrap() else {
            panic!("expected service");
        };
        assert!(service.specific.guess_main_pid);
    }

    #[test]
    fn oneshot_exit_type_cgroup_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("invalid.service"),
            "[Service]\nType=oneshot\nExitType=cgroup\nExecStart=/bin/true\n",
        )
        .unwrap();
        let loader = UnitLoader::with_dirs(vec![dir.path().to_path_buf()]);
        let error = loader.load("invalid.service").unwrap_err().to_string();
        assert!(error.contains("ExitType=cgroup"));
    }

    #[test]
    fn load_rustd_journald_socket() {
        let loader = UnitLoader::system();
        let Ok(unit) = loader.load("rustd-journald.socket") else {
            return;
        };
        let LoadedUnit::Socket(sock) = unit else {
            panic!("expected Socket variant");
        };
        assert!(sock.specific.listen.iter().any(|l| l.kind == "Datagram"));
    }

    #[test]
    fn load_template_getty() {
        let loader = UnitLoader::system();
        let Ok(unit) = loader.load("getty@tty1.service") else {
            return;
        };
        assert_eq!(unit.name(), "getty@tty1.service");
    }

    #[test]
    fn load_multi_user_target() {
        let loader = UnitLoader::system();
        let Ok(unit) = loader.load("multi-user.target") else {
            return;
        };
        let LoadedUnit::Target(_) = unit else {
            panic!("expected Target variant");
        };
    }

    #[test]
    fn automount_loader_validates_name_and_matching_mount() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("srv-archive.automount"),
            "[Unit]\nDescription=Archive automount\n\
             [Automount]\nWhere=/srv/archive\nExtraOptions=browse,tag=%n\n\
             DirectoryMode=0710\nTimeoutIdleSec=2min\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("srv-archive.mount"),
            "[Mount]\nWhat=none\nWhere=/srv/archive\n",
        )
        .unwrap();

        let loader = UnitLoader::with_dirs(vec![dir.path().to_path_buf()]);
        let LoadedUnit::Automount(automount) = loader.load("srv-archive.automount").unwrap() else {
            panic!("expected automount unit");
        };

        assert_eq!(automount.specific.where_, "/srv/archive");
        assert_eq!(automount.specific.trigger_unit, "srv-archive.mount");
        assert_eq!(
            automount.specific.extra_options,
            "browse,tag=srv-archive.automount"
        );
        assert_eq!(automount.specific.directory_mode, 0o710);
        assert_eq!(
            automount.specific.timeout_idle_sec,
            Some(std::time::Duration::from_secs(120))
        );
        assert!(automount.unit.ignore_on_isolate);
        assert!(automount
            .unit
            .before
            .contains(&"srv-archive.mount".to_owned()));
        assert!(automount
            .unit
            .before
            .contains(&"local-fs.target".to_owned()));
        assert!(automount
            .unit
            .after
            .contains(&"local-fs-pre.target".to_owned()));
        assert!(automount
            .unit
            .conflicts
            .contains(&"umount.target".to_owned()));
    }

    #[test]
    fn automount_derives_where_and_rejects_invalid_pairs() {
        let dir = tempfile::tempdir().unwrap();
        let name = "var-lib\\x2ddata.automount";
        std::fs::write(dir.path().join(name), "[Automount]\nTimeoutIdleSec=0\n").unwrap();
        std::fs::write(
            dir.path().join("var-lib\\x2ddata.mount"),
            "[Mount]\nWhere=/var/lib-data\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("broken.automount"),
            "[Automount]\nWhere=/does-not-match\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("broken.mount"), "[Mount]\nWhere=/broken\n").unwrap();
        std::fs::write(dir.path().join("missing.automount"), "[Automount]\n").unwrap();

        let loader = UnitLoader::with_dirs(vec![dir.path().to_path_buf()]);
        let LoadedUnit::Automount(automount) = loader.load(name).unwrap() else {
            panic!("expected automount unit");
        };
        assert_eq!(automount.specific.where_, "/var/lib-data");
        assert_eq!(automount.specific.timeout_idle_sec, None);
        assert!(loader.load("broken.automount").is_err());
        assert!(loader.load("missing.automount").is_err());
    }

    #[test]
    fn slice_loader_adds_parent_dependencies_and_parses_section() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("batch-workers.slice"),
            "[Slice]\nConcurrencySoftMax=4\nConcurrencyHardMax=8\nCPUWeight=250\n",
        )
        .unwrap();

        let loader = UnitLoader::with_dirs(vec![dir.path().to_path_buf()]);
        let LoadedUnit::Slice(slice) = loader.load("batch-workers.slice").unwrap() else {
            panic!("expected slice unit");
        };
        assert_eq!(slice.specific.concurrency_soft_max, 4);
        assert_eq!(slice.specific.concurrency_hard_max, 8);
        assert_eq!(slice.specific.resource_control.cpu_weight, Some(250));
        assert!(slice.unit.requires.contains(&"batch.slice".to_owned()));
        assert!(slice.unit.after.contains(&"batch.slice".to_owned()));
        assert!(slice.unit.before.contains(&"shutdown.target".to_owned()));
        assert!(slice.unit.conflicts.contains(&"shutdown.target".to_owned()));
        assert!(slice.unit.ignore_on_isolate);
        assert_eq!(slice.unit.description, "Slice /batch/workers");

        let LoadedUnit::Slice(root) = loader.load("-.slice").unwrap() else {
            panic!("expected built-in root slice");
        };
        assert_eq!(root.unit.description, "Root Slice");
        assert!(!root.unit.default_dependencies);
        assert!(slice_parent_name("bad\\escape.slice").is_err());
    }

    #[test]
    fn control_dropin_overrides_base_service_properties() {
        let units = tempfile::tempdir().unwrap();
        let controls = tempfile::tempdir().unwrap();
        std::fs::write(
            units.path().join("resource.service"),
            "[Service]\nExecStart=/bin/true\nCPUWeight=100\n",
        )
        .unwrap();
        let dropin = controls.path().join("resource.service.d");
        std::fs::create_dir_all(&dropin).unwrap();
        std::fs::write(
            dropin.join("50-resource.conf"),
            "[Service]\nCPUWeight=250\n",
        )
        .unwrap();
        let loader = UnitLoader::with_dirs_and_control(
            vec![units.path().to_path_buf()],
            vec![controls.path().to_path_buf()],
        );

        let LoadedUnit::Service(service) = loader.load("resource.service").unwrap() else {
            panic!("expected service unit");
        };
        assert_eq!(service.specific.resource_control.cpu_weight, Some(250));
    }

    #[test]
    fn load_nonexistent_errors() {
        let loader = UnitLoader::system();
        assert!(loader.load("totally-nonexistent-xyz.service").is_err());
    }
}
