// SPDX-License-Identifier: LGPL-2.1-or-later
//! Unit enable/disable state query.
//!
//! Determines whether a unit is enabled, disabled, masked, static, etc.
//! by scanning symlinks in the unit search directories.
//!
//! Upstream reference: `src/core/unit-file.c unit_file_get_state()` (v261)

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::glob::matches_no_escape;
use crate::unit::ini::parse_unit_text;

const MAX_SYMLINK_DEPTH: usize = 40;

/// Failure while looking up a unit file through the system unit search path.
///
/// `GetUnitFileState` exposes these distinctions over D-Bus: an invalid unit
/// name, a missing unit file, and a unit file that could not be inspected are
/// not interchangeable states.
#[derive(Debug)]
pub enum UnitFileLookupError {
    /// The supplied string is not a valid unit file name.
    InvalidName(String),
    /// No matching unit file was found in the selected unit search path.
    NotFound(String),
    /// A unit-file symlink points at a missing unit.
    UnresolvableAlias(String),
    /// The default target is masked by a `/dev/null` link.
    DefaultTargetMasked,
    /// A requested unit file is masked by a `/dev/null` link.
    UnitMasked(PathBuf),
    /// The default-target link already exists and force was not requested.
    UnitExists {
        /// Existing destination path.
        path: PathBuf,
        /// Existing symlink target, when the destination is a symlink.
        target: Option<PathBuf>,
    },
    /// The filesystem could not be inspected.
    Io(std::io::Error),
}

/// One filesystem change reported by Manager unit-file mutation methods.
pub type UnitFileChange = (String, String, String);

/// Ordered unit-file changes returned by a mutation operation.
pub type UnitFileChanges = Vec<UnitFileChange>;

/// Preset operation modes accepted by the v261 Manager preset methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresetMode {
    /// Apply both preset disables and enables.
    Full,
    /// Apply only preset enables.
    EnableOnly,
    /// Apply only preset disables.
    DisableOnly,
}

impl PresetMode {
    /// Parse the wire spelling used by `Preset*UnitFiles`.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "" | "full" => Some(Self::Full),
            "enable-only" => Some(Self::EnableOnly),
            "disable-only" => Some(Self::DisableOnly),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PresetAction {
    Enable,
    Disable,
    Ignore,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PresetRule {
    action: PresetAction,
    pattern: String,
    instances: Vec<String>,
}

impl std::fmt::Display for UnitFileLookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidName(name) => write!(f, "Invalid unit file name: {name}"),
            Self::NotFound(name) => write!(f, "Unit file {name} not found"),
            Self::UnresolvableAlias(name) => {
                write!(f, "Unit file {name} is an unresolvable alias")
            }
            Self::DefaultTargetMasked => write!(f, "Default target unit file is masked."),
            Self::UnitMasked(path) => write!(f, "Unit file {} is masked", path.display()),
            Self::UnitExists { path, target } => {
                write!(f, "File '{}' already exists", path.display())?;
                if let Some(target) = target {
                    write!(f, " and is a symlink to {}", target.display())?;
                }
                Ok(())
            }
            Self::Io(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for UnitFileLookupError {}

impl From<std::io::Error> for UnitFileLookupError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// The enable state of a unit, as reported by `rustctl is-enabled`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnableState {
    /// Symlink exists in `*.wants/` or `*.requires/`.
    Enabled,
    /// Symlink exists under `/run/` only.
    EnabledRuntime,
    /// Direct symlink to the unit file (not via .wants/).
    Linked,
    /// Direct symlink under `/run/` only.
    LinkedRuntime,
    /// Alias symlink exists.
    Alias,
    /// Symlink to `/dev/null`.
    Masked,
    /// Masked under `/run/` only.
    MaskedRuntime,
    /// Unit has no `[Install]` section — cannot be enabled.
    Static,
    /// Unit enables other units via `Also=`.
    Indirect,
    /// Not enabled and has an `[Install]` section.
    Disabled,
    /// Unit file is broken or has conflicting state.
    Bad,
    /// Produced by a generator.
    Generated,
    /// Created dynamically at runtime.
    Transient,
}

/// A unit file selected from the manager's unit search path.
///
/// `path` is the winning file's original location, rather than a resolved
/// symlink target. This is the path returned by Manager `ListUnitFiles`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitFileListEntry {
    /// Path of the highest-precedence unit file.
    pub path: PathBuf,
    /// Enable state computed for that unit file.
    pub state: EnableState,
}

/// Apply the Manager `SetDefaultTarget(name, force)` operation to a rooted
/// system unit tree and return the v261 install-change tuples.
///
/// This is intentionally filesystem-backed: the target must be an existing
/// target unit and `/etc/systemd/system/default.target` is replaced only when
/// `force` is true.
///
/// # Errors
///
/// Returns a lookup or filesystem error when `name` is invalid, the target is
/// unavailable, or the destination cannot be created/replaced.
pub fn set_root_default_target(
    name: &str,
    force: bool,
    root: &Path,
) -> Result<Vec<(String, String, String)>, UnitFileLookupError> {
    set_default_target_in_search(
        name,
        force,
        &rooted_unit_search_dirs(root),
        &root.join("etc/systemd/system"),
        root,
    )
}

/// Apply `SetDefaultTarget` using an explicitly supplied user-unit search
/// path and persistent configuration directory.
///
/// # Errors
///
/// Returns a lookup or filesystem error when `name` is invalid, the target is
/// unavailable, or the destination cannot be created/replaced.
pub fn set_user_default_target(
    name: &str,
    force: bool,
    search_dirs: &[PathBuf],
    config_dir: &Path,
) -> Result<Vec<(String, String, String)>, UnitFileLookupError> {
    set_default_target_in_search(name, force, search_dirs, config_dir, Path::new("/"))
}

/// Mask unit files in a persistent or runtime control directory.
///
/// # Errors
///
/// Returns a lookup or filesystem error when a unit name is invalid or an
/// existing non-mask entry prevents the `/dev/null` link from being created.
pub fn mask_unit_files(
    names: &[String],
    _force: bool,
    config_dir: &Path,
) -> Result<Vec<(String, String, String)>, UnitFileLookupError> {
    std::fs::create_dir_all(config_dir)?;
    let mut changes = Vec::new();
    for name in names {
        if !valid_unit_file_name(name) {
            return Err(UnitFileLookupError::InvalidName(name.clone()));
        }
        let path = config_dir.join(name);
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink()
                    && std::fs::read_link(&path).ok().as_deref() == Some(Path::new("/dev/null"))
                {
                    continue;
                }
                let target = if metadata.file_type().is_symlink() {
                    std::fs::read_link(&path).ok()
                } else {
                    None
                };
                return Err(UnitFileLookupError::UnitExists { path, target });
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        std::os::unix::fs::symlink("/dev/null", &path)?;
        changes.push((
            "symlink".to_owned(),
            path.display().to_string(),
            "/dev/null".to_owned(),
        ));
    }
    Ok(changes)
}

/// Remove `/dev/null` masks from unit files in a control directory.
///
/// # Errors
///
/// Returns a lookup or filesystem error when a unit name is invalid or the
/// control directory cannot be inspected.
pub fn unmask_unit_files(
    names: &[String],
    config_dir: &Path,
) -> Result<Vec<(String, String, String)>, UnitFileLookupError> {
    let mut changes = Vec::new();
    for name in names {
        if !valid_unit_file_name(name) {
            return Err(UnitFileLookupError::InvalidName(name.clone()));
        }
        let path = config_dir.join(name);
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if !metadata.file_type().is_symlink()
            || std::fs::read_link(&path).ok().as_deref() != Some(Path::new("/dev/null"))
        {
            continue;
        }
        std::fs::remove_file(&path)?;
        changes.push((
            "unlink".to_owned(),
            path.display().to_string(),
            String::new(),
        ));
    }
    Ok(changes)
}

/// Enable unit files using their `[Install]` relationships.
///
/// # Errors
///
/// Returns a lookup or filesystem error when a unit is invalid, unavailable,
/// or an existing link cannot be reconciled with the requested relationship.
#[allow(clippy::too_many_lines)]
pub fn enable_unit_files(
    names: &[String],
    force: bool,
    config_dir: &Path,
    search_dirs: &[PathBuf],
) -> Result<(bool, UnitFileChanges), UnitFileLookupError> {
    std::fs::create_dir_all(config_dir)?;
    let mut carries_install_info = false;
    let mut changes = Vec::new();
    let mut pending = names.to_vec();
    let mut next = 0;
    let mut seen = BTreeSet::new();

    while next < pending.len() {
        let requested = pending[next].clone();
        next += 1;
        let (name, requested_path, source, outside_search_path) = if requested.starts_with('/') {
            let path = PathBuf::from(&requested);
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| UnitFileLookupError::InvalidName(requested.clone()))?
                .to_owned();
            if !valid_unit_file_name(&name) {
                return Err(UnitFileLookupError::InvalidName(requested));
            }
            match std::fs::symlink_metadata(&path) {
                Ok(metadata)
                    if metadata.file_type().is_file() || metadata.file_type().is_symlink() => {}
                Ok(_) => return Err(UnitFileLookupError::NotFound(requested.clone())),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Err(UnitFileLookupError::NotFound(requested.clone()));
                }
                Err(error) => return Err(error.into()),
            }
            let source = match resolve_unit_path(&path, Path::new("/"))? {
                ResolvedUnitPath::Path(source) => source,
                ResolvedUnitPath::Masked => {
                    return Err(UnitFileLookupError::UnitMasked(path));
                }
                ResolvedUnitPath::Dangling => {
                    return Err(UnitFileLookupError::NotFound(requested.clone()));
                }
            };
            let outside = !is_in_unit_search_path(&source, search_dirs);
            (name, path, source, outside)
        } else {
            (requested.clone(), PathBuf::new(), PathBuf::new(), false)
        };
        if !seen.insert(name.clone()) {
            continue;
        }
        let (source, outside_search_path) = if requested_path.as_os_str().is_empty() {
            if !valid_unit_file_name(&name) {
                return Err(UnitFileLookupError::InvalidName(name));
            }
            let Some((candidate, _)) = find_unit_file(&name, search_dirs)? else {
                return Err(UnitFileLookupError::NotFound(name));
            };
            let source = match resolve_unit_path(&candidate, Path::new("/"))? {
                ResolvedUnitPath::Path(source) => source,
                ResolvedUnitPath::Masked => {
                    return Err(UnitFileLookupError::UnitMasked(candidate));
                }
                ResolvedUnitPath::Dangling => {
                    return Err(UnitFileLookupError::NotFound(name));
                }
            };
            (source, false)
        } else {
            (source, outside_search_path)
        };
        let contents = std::fs::read_to_string(&source)?;
        let install = install_entries(&contents);
        if install.is_empty() {
            continue;
        }
        carries_install_info = true;
        let link_source = if outside_search_path {
            let destination = config_dir.join(&name);
            create_install_symlink(&destination, &source, force, &mut changes, search_dirs)?;
            destination
        } else {
            source.clone()
        };
        for (key, value) in &install {
            if key == "Also" {
                pending.extend(value.split_whitespace().map(str::to_owned));
            }
        }
        for (key, value) in &install {
            if key == "Alias" {
                for alias in value.split_whitespace() {
                    if !valid_unit_file_name(alias) {
                        return Err(UnitFileLookupError::InvalidName(alias.to_owned()));
                    }
                    create_install_symlink(
                        &config_dir.join(alias),
                        &link_source,
                        force,
                        &mut changes,
                        search_dirs,
                    )?;
                }
            }
        }
        for (key, value) in &install {
            if matches!(key.as_str(), "WantedBy" | "RequiredBy" | "UpheldBy") {
                let relationship = match key.as_str() {
                    "WantedBy" => "wants",
                    "RequiredBy" => "requires",
                    "UpheldBy" => "upholds",
                    _ => unreachable!(),
                };
                for target in value.split_whitespace() {
                    if !valid_unit_file_name(target) {
                        return Err(UnitFileLookupError::InvalidName(target.to_owned()));
                    }
                    create_install_symlink(
                        &config_dir.join(format!("{target}.{relationship}/{name}")),
                        &source,
                        true,
                        &mut changes,
                        search_dirs,
                    )?;
                }
            }
        }
    }

    Ok((carries_install_info, changes))
}

/// Apply preset rules to a selected set of unit files.
///
/// Preset files are read in the same precedence order as systemd v261:
/// `/etc`, `/run`, `/usr/local/lib`, and `/usr/lib`, with the first file of a
/// duplicate basename winning. A unit without a matching rule follows the
/// upstream default-enable rule. The actual enable and disable operations are
/// delegated to the filesystem-backed helpers above, so the returned changes
/// describe real links rather than an in-memory approximation.
///
/// # Errors
///
/// Returns [`UnitFileLookupError::InvalidName`] for malformed unit names,
/// [`UnitFileLookupError::NotFound`] when a requested unit is absent,
/// [`UnitFileLookupError::UnitMasked`] for a `/dev/null` mask, and
/// [`UnitFileLookupError::Io`] when preset or unit files cannot be read.
#[allow(clippy::too_many_arguments)]
pub fn preset_unit_files(
    names: &[String],
    mode: PresetMode,
    force: bool,
    config_dir: &Path,
    search_dirs: &[PathBuf],
    preset_dirs: &[PathBuf],
) -> Result<(bool, UnitFileChanges), UnitFileLookupError> {
    let rules = read_preset_rules(preset_dirs)?;
    let selection = select_preset_units(names, &rules, search_dirs)?;
    let mut changes = Vec::new();

    if !matches!(mode, PresetMode::EnableOnly) {
        changes.extend(disable_unit_files(
            &selection.disable,
            config_dir,
            search_dirs,
        )?);
    }
    if !matches!(mode, PresetMode::DisableOnly) {
        let (_, enable_changes) =
            enable_unit_files(&selection.enable, force, config_dir, search_dirs)?;
        changes.extend(enable_changes);
    }

    let carries_install_info = match mode {
        PresetMode::Full => selection.carries_enable || selection.carries_disable,
        PresetMode::EnableOnly => selection.carries_enable,
        PresetMode::DisableOnly => selection.carries_disable,
    };
    Ok((carries_install_info, changes))
}

/// Apply preset rules to every visible unit file for a manager scope.
///
/// The first occurrence of a unit filename in `search_dirs` wins, matching
/// systemd's lookup-path precedence. Preset errors for the selected files are
/// surfaced unchanged so callers can preserve v261's D-Bus error class.
///
/// # Errors
///
/// Returns [`UnitFileLookupError::Io`] when a search directory cannot be
/// inspected, or any filesystem error returned by [`preset_unit_files`].
pub fn preset_all_unit_files(
    mode: PresetMode,
    force: bool,
    config_dir: &Path,
    search_dirs: &[PathBuf],
    preset_dirs: &[PathBuf],
) -> Result<UnitFileChanges, UnitFileLookupError> {
    let names = visible_unit_file_names(search_dirs)?;
    let (_, changes) =
        preset_unit_files(&names, mode, force, config_dir, search_dirs, preset_dirs)?;
    Ok(changes)
}

#[derive(Debug, Default)]
struct PresetSelection {
    enable: Vec<String>,
    disable: Vec<String>,
    carries_enable: bool,
    carries_disable: bool,
}

fn select_preset_units(
    names: &[String],
    rules: &[PresetRule],
    search_dirs: &[PathBuf],
) -> Result<PresetSelection, UnitFileLookupError> {
    let mut selection = PresetSelection::default();

    for name in names {
        if !valid_unit_file_name(name) {
            return Err(UnitFileLookupError::InvalidName(name.clone()));
        }
        let Some((candidate, _)) = find_unit_file(name, search_dirs)? else {
            return Err(UnitFileLookupError::NotFound(name.clone()));
        };
        let source = match resolve_unit_path(&candidate, Path::new("/"))? {
            ResolvedUnitPath::Path(source) => source,
            ResolvedUnitPath::Masked => return Err(UnitFileLookupError::UnitMasked(candidate)),
            ResolvedUnitPath::Dangling => {
                return Err(UnitFileLookupError::UnresolvableAlias(name.clone()));
            }
        };

        // Preset processing skips aliases. The install context applies a
        // rule to the canonical unit only; enabling an alias separately
        // would create links that upstream deliberately does not create.
        let canonical_name = source
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| UnitFileLookupError::InvalidName(name.clone()))?;
        if canonical_name != name {
            continue;
        }

        let has_install_info = !install_entries(&std::fs::read_to_string(&source)?).is_empty();
        match preset_action_for(name, rules) {
            PresetAction::Enable => {
                selection.carries_enable |= has_install_info;
                push_unique(&mut selection.enable, name);
            }
            PresetAction::Disable => {
                selection.carries_disable |= has_install_info;
                push_unique(&mut selection.disable, name);
            }
            PresetAction::Ignore => {}
        }
    }

    Ok(selection)
}

fn push_unique(names: &mut Vec<String>, name: &str) {
    if !names.iter().any(|existing| existing == name) {
        names.push(name.to_owned());
    }
}

fn preset_action_for(name: &str, rules: &[PresetRule]) -> PresetAction {
    rules
        .iter()
        .find(|rule| preset_rule_matches(rule, name))
        .map_or(PresetAction::Enable, |rule| rule.action)
}

fn preset_rule_matches(rule: &PresetRule, name: &str) -> bool {
    if matches_no_escape(&rule.pattern, name) {
        return true;
    }

    // v261 permits an instance list after a template rule, for example
    // `enable foo@.service seat0 seat1`. Match instantiated names against
    // that explicit list while leaving ordinary fnmatch rules untouched.
    if rule.instances.is_empty() {
        return false;
    }
    let Some((template_prefix, suffix)) = rule.pattern.split_once("@.") else {
        return false;
    };
    let Some((name_prefix, instance_and_suffix)) = name.split_once('@') else {
        return false;
    };
    if name_prefix != template_prefix {
        return false;
    }
    let Some(instance) = instance_and_suffix.strip_suffix(&format!(".{suffix}")) else {
        return false;
    };
    rule.instances.iter().any(|candidate| candidate == instance)
}

fn read_preset_rules(preset_dirs: &[PathBuf]) -> Result<Vec<PresetRule>, UnitFileLookupError> {
    let mut selected = BTreeMap::new();
    for directory in preset_dirs {
        let entries = match std::fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        for entry in entries {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if !file_type.is_file() && !file_type.is_symlink() {
                continue;
            }
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("preset") {
                continue;
            }
            let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            selected
                .entry(name.to_owned())
                .or_insert_with(|| path.clone());
        }
    }

    let mut rules = Vec::new();
    for path in selected.values() {
        let contents = std::fs::read_to_string(path)?;
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            let mut fields = line.split_whitespace();
            let Some(action) = fields.next() else {
                continue;
            };
            let Some(pattern) = fields.next() else {
                continue;
            };
            let Some(action) = (match action {
                "enable" => Some(PresetAction::Enable),
                "disable" => Some(PresetAction::Disable),
                "ignore" => Some(PresetAction::Ignore),
                _ => None,
            }) else {
                continue;
            };
            rules.push(PresetRule {
                action,
                pattern: pattern.to_owned(),
                instances: fields.map(str::to_owned).collect(),
            });
        }
    }
    Ok(rules)
}

fn visible_unit_file_names(search_dirs: &[PathBuf]) -> Result<Vec<String>, UnitFileLookupError> {
    let mut names = BTreeSet::new();
    for directory in search_dirs {
        let entries = match std::fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        for entry in entries {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if !file_type.is_file() && !file_type.is_symlink() {
                continue;
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if valid_unit_file_name(name) {
                names.insert(name.to_owned());
            }
        }
    }
    Ok(names.into_iter().collect())
}

/// Add `Wants=` or `Requires=` dependency links for unit files.
///
/// This is the filesystem half of v261's `AddDependencyUnitFiles` manager
/// method. The dependency target and every requested unit are resolved
/// through the selected unit search path first. Relationship links are then
/// created below the persistent or runtime control directory and point at the
/// resolved unit-file paths, preserving vendor aliases and the change tuples
/// returned by systemd's install API.
///
/// `requires` selects `.requires/` when true and `.wants/` otherwise. The
/// relationship itself is always reconciled (`force` only matters to the
/// direct link for an out-of-tree source, matching systemd's install context).
///
/// # Errors
///
/// Returns [`UnitFileLookupError::InvalidName`] for malformed unit names,
/// [`UnitFileLookupError::NotFound`] for absent units,
/// [`UnitFileLookupError::UnresolvableAlias`] for dangling unit aliases,
/// [`UnitFileLookupError::UnitMasked`] for `/dev/null` masks,
/// [`UnitFileLookupError::UnitExists`] for a conflicting control-directory
/// entry, and [`UnitFileLookupError::Io`] for other filesystem failures.
pub fn add_dependency_unit_files(
    names: &[String],
    target: &str,
    requires: bool,
    force: bool,
    config_dir: &Path,
    search_dirs: &[PathBuf],
) -> Result<UnitFileChanges, UnitFileLookupError> {
    let (target_name, _target_source) = resolve_dependency_unit_file(target, search_dirs)?;
    let relationship = if requires { "requires" } else { "wants" };
    let resolved_names: Vec<_> = names
        .iter()
        .map(|name| resolve_dependency_unit_file(name, search_dirs))
        .collect::<Result<_, _>>()?;
    let mut changes = Vec::new();

    for (name, source) in resolved_names {
        // A source outside the manager's search path first receives a direct
        // control-directory link. This mirrors install_context_apply(); the
        // relationship link itself is always force-reconciled by systemd.
        if !is_in_unit_search_path(&source, search_dirs) {
            create_install_symlink(
                &config_dir.join(&name),
                &source,
                force,
                &mut changes,
                search_dirs,
            )?;
        }
        create_install_symlink(
            &config_dir.join(format!("{target_name}.{relationship}/{name}")),
            &source,
            true,
            &mut changes,
            search_dirs,
        )?;
    }

    Ok(changes)
}

fn resolve_dependency_unit_file(
    name_or_path: &str,
    search_dirs: &[PathBuf],
) -> Result<(String, PathBuf), UnitFileLookupError> {
    let requested_path = if name_or_path.starts_with('/') {
        let path = PathBuf::from(name_or_path);
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() || metadata.file_type().is_symlink() => {
            }
            Ok(_) => return Err(UnitFileLookupError::NotFound(name_or_path.to_owned())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(UnitFileLookupError::NotFound(name_or_path.to_owned()))
            }
            Err(error) => return Err(error.into()),
        }
        path
    } else {
        if !valid_unit_file_name(name_or_path) {
            return Err(UnitFileLookupError::InvalidName(name_or_path.to_owned()));
        }
        find_unit_file(name_or_path, search_dirs)?
            .map(|(path, _)| path)
            .ok_or_else(|| UnitFileLookupError::NotFound(name_or_path.to_owned()))?
    };
    let requested_name = requested_path
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| valid_unit_file_name(value))
        .ok_or_else(|| UnitFileLookupError::InvalidName(name_or_path.to_owned()))?
        .to_owned();
    let source = match resolve_unit_path(&requested_path, Path::new("/"))? {
        ResolvedUnitPath::Path(source) => source,
        ResolvedUnitPath::Masked => return Err(UnitFileLookupError::UnitMasked(requested_path)),
        ResolvedUnitPath::Dangling => {
            let is_alias = std::fs::symlink_metadata(&requested_path)
                .is_ok_and(|metadata| metadata.file_type().is_symlink());
            return Err(if is_alias {
                UnitFileLookupError::UnresolvableAlias(name_or_path.to_owned())
            } else {
                UnitFileLookupError::NotFound(name_or_path.to_owned())
            });
        }
    };
    let source_metadata = std::fs::symlink_metadata(&source)?;
    if !source_metadata.file_type().is_file() {
        return Err(UnitFileLookupError::NotFound(name_or_path.to_owned()));
    }
    let source_name = source
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| valid_unit_file_name(value))
        .ok_or_else(|| UnitFileLookupError::InvalidName(name_or_path.to_owned()))?
        .to_owned();
    // An absolute path is treated as a linked unit by systemd and retains
    // the requested basename for both the direct link and dependency link.
    // A name found through the search path follows aliases and uses the
    // resolved unit basename instead.
    let link_name = if name_or_path.starts_with('/') {
        requested_name
    } else {
        source_name
    };
    Ok((link_name, source))
}

/// Link absolute unit-file paths into the manager's unit-file directory.
///
/// # Errors
///
/// Returns a lookup or filesystem error when a path is not absolute, does not
/// name a unit file, or cannot be linked into the control directory.
pub fn link_unit_files(
    names: &[String],
    force: bool,
    config_dir: &Path,
    search_dirs: &[PathBuf],
) -> Result<Vec<UnitFileChange>, UnitFileLookupError> {
    std::fs::create_dir_all(config_dir)?;
    let mut changes = Vec::new();
    for requested in names {
        if !requested.starts_with('/') {
            return Err(UnitFileLookupError::InvalidName(requested.clone()));
        }
        let path = PathBuf::from(requested);
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| UnitFileLookupError::InvalidName(requested.clone()))?;
        if !valid_unit_file_name(name) {
            return Err(UnitFileLookupError::InvalidName(requested.clone()));
        }
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() || metadata.file_type().is_symlink() => {
            }
            Ok(_) => return Err(UnitFileLookupError::NotFound(requested.clone())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(UnitFileLookupError::NotFound(requested.clone()));
            }
            Err(error) => return Err(error.into()),
        }
        let source = match resolve_unit_path(&path, Path::new("/"))? {
            ResolvedUnitPath::Path(source) => source,
            ResolvedUnitPath::Masked => return Err(UnitFileLookupError::UnitMasked(path)),
            ResolvedUnitPath::Dangling => {
                return Err(UnitFileLookupError::NotFound(requested.clone()));
            }
        };
        if is_in_unit_search_path(&source, search_dirs) {
            continue;
        }
        create_install_symlink(
            &config_dir.join(name),
            &source,
            force,
            &mut changes,
            search_dirs,
        )?;
    }
    Ok(changes)
}

/// Disable unit files by removing links created from their `[Install]` data.
///
/// # Errors
///
/// Returns a lookup or filesystem error when a unit is invalid, unavailable,
/// or the control directory cannot be inspected.
pub fn disable_unit_files(
    names: &[String],
    config_dir: &Path,
    search_dirs: &[PathBuf],
) -> Result<Vec<(String, String, String)>, UnitFileLookupError> {
    let mut tracked = BTreeSet::new();
    let mut changes = Vec::new();
    let mut pending = names.to_vec();
    let mut next = 0;
    while next < pending.len() {
        let name = pending[next].clone();
        next += 1;
        if !valid_unit_file_name(&name) {
            return Err(UnitFileLookupError::InvalidName(name));
        }
        let Some((candidate, _)) = find_unit_file(&name, search_dirs)? else {
            return Err(UnitFileLookupError::NotFound(name));
        };
        let source = match resolve_unit_path(&candidate, Path::new("/"))? {
            ResolvedUnitPath::Path(source) => source,
            ResolvedUnitPath::Masked => {
                changes.push((
                    "masked".to_owned(),
                    candidate.display().to_string(),
                    String::new(),
                ));
                continue;
            }
            ResolvedUnitPath::Dangling => {
                return Err(UnitFileLookupError::NotFound(name));
            }
        };
        if tracked.insert((name.clone(), source.clone())) {
            if let Ok(contents) = std::fs::read_to_string(&source) {
                for (key, value) in install_entries(&contents) {
                    if key == "Also" {
                        pending.extend(value.split_whitespace().map(str::to_owned));
                    }
                }
            }
        }
    }

    let mut relationship_paths = Vec::new();
    let mut direct_paths = Vec::new();
    collect_symlink_paths(config_dir, &mut relationship_paths, &mut direct_paths)?;
    relationship_paths.sort();
    direct_paths.sort();
    relationship_paths.extend(direct_paths);
    for path in relationship_paths {
        let target = std::fs::read_link(&path)?;
        let resolved_target = if target.is_absolute() {
            target.clone()
        } else {
            path.parent().unwrap_or(config_dir).join(&target)
        };
        let target_name = resolved_target.file_name().and_then(|name| name.to_str());
        if tracked.iter().any(|(name, source)| {
            resolved_target == *source
                || target_name == Some(name.as_str())
                || path.file_name().and_then(|value| value.to_str()) == Some(name.as_str())
        }) {
            std::fs::remove_file(&path)?;
            changes.push((
                "unlink".to_owned(),
                path.display().to_string(),
                String::new(),
            ));
            remove_empty_parent_dirs(path.parent(), config_dir);
        }
    }
    Ok(changes)
}

/// Revert unit-file overrides and drop-ins back to their vendor state.
///
/// This is the filesystem-backed portion of systemd's `unit_file_revert`.
/// Drop-ins in persistent, runtime, control, and transient directories are
/// removed first (with file changes reported before their now-empty
/// directories).  A unit-file override is removed only when a vendor copy is
/// present in the selected search path.  Generated unit trees are deliberately
/// left alone: they are owned by generators and are not user configuration.
///
/// # Errors
///
/// Returns [`UnitFileLookupError::InvalidName`] for an invalid unit name and
/// [`UnitFileLookupError::Io`] when the selected unit trees cannot be read or
/// modified.
pub fn revert_unit_files(
    names: &[String],
    persistent_config: &Path,
    runtime_config: &Path,
    search_dirs: &[PathBuf],
    root: &Path,
) -> Result<UnitFileChanges, UnitFileLookupError> {
    let managed_dirs = [persistent_config, runtime_config];
    let mut dropin_dirs = vec![
        persistent_config.to_path_buf(),
        runtime_config.to_path_buf(),
    ];
    for directory in search_dirs {
        let text = directory.to_string_lossy();
        if text.ends_with(".control") || text.ends_with("/transient") {
            dropin_dirs.push(directory.clone());
        }
    }
    dropin_dirs.sort();
    dropin_dirs.dedup();

    let mut changes = Vec::new();
    for name in names {
        if !valid_unit_file_name(name) {
            return Err(UnitFileLookupError::InvalidName(name.clone()));
        }

        let has_vendor = search_dirs.iter().any(|directory| {
            let path = directory.join(name);
            let regular = std::fs::metadata(&path).is_ok_and(|metadata| metadata.is_file());
            regular
                && !managed_dirs.iter().any(|managed| path.starts_with(managed))
                && is_vendor_or_generator_path(&path, root)
        });

        let mut seen_dropins = BTreeSet::new();
        for directory in &dropin_dirs {
            let dropin = directory.join(format!("{name}.d"));
            let metadata = match std::fs::symlink_metadata(&dropin) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            if !metadata.is_dir() || !seen_dropins.insert(dropin.clone()) {
                continue;
            }

            let mut entries = Vec::new();
            let mut directories = Vec::new();
            collect_revert_entries(&dropin, &mut entries, &mut directories)?;
            entries.sort();
            for entry in entries {
                std::fs::remove_file(&entry)?;
                changes.push((
                    "unlink".to_owned(),
                    entry.display().to_string(),
                    String::new(),
                ));
            }
            directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
            for directory in directories {
                std::fs::remove_dir(&directory)?;
                changes.push((
                    "unlink".to_owned(),
                    directory.display().to_string(),
                    String::new(),
                ));
            }
            std::fs::remove_dir(&dropin)?;
            changes.push((
                "unlink".to_owned(),
                dropin.display().to_string(),
                String::new(),
            ));
        }

        if has_vendor {
            for directory in managed_dirs {
                let path = directory.join(name);
                match std::fs::symlink_metadata(&path) {
                    Ok(metadata) if metadata.is_file() || metadata.file_type().is_symlink() => {
                        std::fs::remove_file(&path)?;
                        changes.push((
                            "unlink".to_owned(),
                            path.display().to_string(),
                            String::new(),
                        ));
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
    }

    Ok(changes)
}

fn is_vendor_or_generator_path(path: &Path, root: &Path) -> bool {
    [
        root.join("usr/local/lib/systemd"),
        root.join("usr/local/share/systemd"),
        root.join("usr/lib/systemd"),
        root.join("usr/share/systemd"),
        root.join("lib/systemd"),
        root.join("run/systemd/generator.early"),
        root.join("run/systemd/generator"),
        root.join("run/systemd/generator.late"),
    ]
    .iter()
    .any(|directory| path.starts_with(directory))
}

fn collect_revert_entries(
    directory: &Path,
    files: &mut Vec<PathBuf>,
    directories: &mut Vec<PathBuf>,
) -> Result<(), UnitFileLookupError> {
    let mut children = std::fs::read_dir(directory)
        .map_err(UnitFileLookupError::Io)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(UnitFileLookupError::Io)?;
    children.sort_by_key(std::fs::DirEntry::path);
    for child in children {
        let path = child.path();
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.is_dir() {
            collect_revert_entries(&path, files, directories)?;
            directories.push(path);
        } else {
            files.push(path);
        }
    }
    Ok(())
}

fn install_entries(contents: &str) -> Vec<(String, String)> {
    parse_unit_text(contents)
        .into_iter()
        .filter(|entry| {
            entry.section == "Install"
                && !entry.value.trim().is_empty()
                && matches!(
                    entry.key.as_str(),
                    "WantedBy" | "RequiredBy" | "UpheldBy" | "Alias" | "Also"
                )
        })
        .map(|entry| (entry.key, entry.value))
        .collect()
}

/// Return whether any requested unit carries `[Install]` metadata.
///
/// # Errors
///
/// Returns [`UnitFileLookupError::InvalidName`] for invalid names,
/// [`UnitFileLookupError::NotFound`] when a requested unit is absent, and
/// [`UnitFileLookupError::Io`] when a unit file cannot be read.
pub fn unit_files_carry_install_info(
    names: &[String],
    search_dirs: &[PathBuf],
) -> Result<bool, UnitFileLookupError> {
    for name in names {
        if !valid_unit_file_name(name) {
            return Err(UnitFileLookupError::InvalidName(name.clone()));
        }
        let Some((path, _)) = find_unit_file(name, search_dirs)? else {
            return Err(UnitFileLookupError::NotFound(name.clone()));
        };
        let source = match resolve_unit_path(&path, Path::new("/"))? {
            ResolvedUnitPath::Path(source) => source,
            ResolvedUnitPath::Masked | ResolvedUnitPath::Dangling => continue,
        };
        if !install_entries(&std::fs::read_to_string(source)?).is_empty() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn create_install_symlink(
    destination: &Path,
    source: &Path,
    force: bool,
    changes: &mut Vec<(String, String, String)>,
    search_dirs: &[PathBuf],
) -> Result<(), UnitFileLookupError> {
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match std::os::unix::fs::symlink(source, destination) {
        Ok(()) => {
            changes.push((
                "symlink".to_owned(),
                destination.display().to_string(),
                source.display().to_string(),
            ));
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = std::fs::symlink_metadata(destination)?;
            let target = if metadata.file_type().is_symlink() {
                std::fs::read_link(destination).ok()
            } else {
                None
            };
            if target.as_deref().is_some_and(|target| {
                symlink_targets_equivalent(destination, target, source, search_dirs)
            }) {
                return Ok(());
            }
            if force && metadata.file_type().is_symlink() {
                std::fs::remove_file(destination)?;
                changes.push((
                    "unlink".to_owned(),
                    destination.display().to_string(),
                    String::new(),
                ));
                std::os::unix::fs::symlink(source, destination)?;
                changes.push((
                    "symlink".to_owned(),
                    destination.display().to_string(),
                    source.display().to_string(),
                ));
                return Ok(());
            }
            Err(UnitFileLookupError::UnitExists {
                path: destination.to_owned(),
                target,
            })
        }
        Err(error) => Err(error.into()),
    }
}

fn collect_symlink_paths(
    directory: &Path,
    relationship_paths: &mut Vec<PathBuf>,
    direct_paths: &mut Vec<PathBuf>,
) -> Result<(), UnitFileLookupError> {
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            let is_relationship = entry.file_name().to_str().is_some_and(|name| {
                Path::new(name).extension().is_some_and(|extension| {
                    matches!(extension.to_str(), Some("wants" | "requires" | "upholds"))
                })
            });
            if is_relationship {
                for child in std::fs::read_dir(&path)? {
                    let child = child?;
                    if child.file_type()?.is_symlink() {
                        relationship_paths.push(child.path());
                    }
                }
            }
        } else if entry.file_type()?.is_symlink() {
            direct_paths.push(path);
        }
    }
    Ok(())
}

fn symlink_targets_equivalent(
    destination: &Path,
    existing: &Path,
    requested: &Path,
    search_dirs: &[PathBuf],
) -> bool {
    let existing = if existing.is_absolute() {
        existing.to_owned()
    } else {
        destination
            .parent()
            .map_or_else(|| existing.to_owned(), |parent| parent.join(existing))
    };
    if existing == requested {
        return true;
    }
    let Some(existing_name) = existing.file_name() else {
        return false;
    };
    existing_name == requested.file_name().unwrap_or_default()
        && is_in_unit_search_path(&existing, search_dirs)
        && is_in_unit_search_path(requested, search_dirs)
}

fn remove_empty_parent_dirs(mut directory: Option<&Path>, root: &Path) {
    while let Some(path) = directory {
        if path == root || !path.starts_with(root) {
            break;
        }
        match std::fs::remove_dir(path) {
            Ok(()) => directory = path.parent(),
            Err(_) => break,
        }
    }
}

fn set_default_target_in_search(
    name: &str,
    force: bool,
    search_dirs: &[PathBuf],
    config_dir: &Path,
    root: &Path,
) -> Result<Vec<(String, String, String)>, UnitFileLookupError> {
    if !valid_unit_file_name(name) || !name.ends_with(".target") || name == "default.target" {
        return Err(UnitFileLookupError::InvalidName(name.to_owned()));
    }
    let Some((source, _)) = find_unit_file(name, search_dirs)? else {
        return Err(UnitFileLookupError::NotFound(name.to_owned()));
    };
    if matches!(
        resolve_unit_path(&source, root)?,
        ResolvedUnitPath::Masked | ResolvedUnitPath::Dangling
    ) {
        return Err(UnitFileLookupError::NotFound(name.to_owned()));
    }
    std::fs::create_dir_all(config_dir)?;
    let destination = config_dir.join("default.target");
    match std::fs::symlink_metadata(&destination) {
        Ok(metadata) if !force => {
            if metadata.file_type().is_symlink()
                && std::fs::read_link(&destination).ok().as_deref() == Some(source.as_path())
            {
                return Ok(Vec::new());
            }
            let target = if metadata.file_type().is_symlink() {
                std::fs::read_link(&destination).ok()
            } else {
                None
            };
            return Err(UnitFileLookupError::UnitExists {
                path: destination,
                target,
            });
        }
        Ok(_) => std::fs::remove_file(&destination)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    std::os::unix::fs::symlink(&source, &destination)?;
    Ok(vec![(
        "symlink".to_owned(),
        destination.display().to_string(),
        source.display().to_string(),
    )])
}

enum ResolvedUnitPath {
    Path(PathBuf),
    Masked,
    Dangling,
}

impl std::fmt::Display for EnableState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Enabled => "enabled",
            Self::EnabledRuntime => "enabled-runtime",
            Self::Linked => "linked",
            Self::LinkedRuntime => "linked-runtime",
            Self::Alias => "alias",
            Self::Masked => "masked",
            Self::MaskedRuntime => "masked-runtime",
            Self::Static => "static",
            Self::Indirect => "indirect",
            Self::Disabled => "disabled",
            Self::Bad => "bad",
            Self::Generated => "generated",
            Self::Transient => "transient",
        };
        write!(f, "{s}")
    }
}

/// Query the enable state of `unit_name` by scanning `search_dirs`.
///
/// `search_dirs` should be in priority order:
/// `["/etc/systemd/system", "/run/systemd/system", "/usr/lib/systemd/system"]`
#[must_use]
pub fn query_enable_state(unit_name: &str, search_dirs: &[&Path]) -> EnableState {
    // Check for masking first (symlink to /dev/null).
    for dir in search_dirs {
        let unit_path = dir.join(unit_name);
        if let Ok(target) = std::fs::read_link(&unit_path) {
            if target == Path::new("/dev/null") {
                return if dir.starts_with("/run") {
                    EnableState::MaskedRuntime
                } else {
                    EnableState::Masked
                };
            }
            // Symlink to actual file → Linked or Alias.
            if target.is_absolute() {
                return if dir.starts_with("/run") {
                    EnableState::LinkedRuntime
                } else {
                    EnableState::Linked
                };
            }
        }
    }

    // Check for enabled state: look for symlinks in *.wants/ and *.requires/
    // directories under each search dir.
    for (idx, dir) in search_dirs.iter().enumerate() {
        if is_enabled_in(unit_name, dir) {
            return if idx == 0 && dir.starts_with("/run") {
                EnableState::EnabledRuntime
            } else {
                EnableState::Enabled
            };
        }
    }

    let Some(unit_path) = search_dirs
        .iter()
        .map(|dir| dir.join(unit_name))
        .find(|path| path.exists() || path.is_symlink())
    else {
        return EnableState::Disabled;
    };

    let Ok(contents) = std::fs::read_to_string(unit_path) else {
        return EnableState::Bad;
    };
    let entries = parse_unit_text(&contents);
    let install_entries: Vec<_> = entries
        .iter()
        .filter(|entry| entry.section == "Install" && !entry.value.trim().is_empty())
        .collect();
    if install_entries.is_empty() {
        return EnableState::Static;
    }
    if install_entries.iter().any(|entry| {
        matches!(
            entry.key.as_str(),
            "WantedBy" | "RequiredBy" | "UpheldBy" | "Alias"
        )
    }) {
        EnableState::Disabled
    } else if install_entries.iter().any(|entry| entry.key == "Also") {
        EnableState::Indirect
    } else {
        EnableState::Static
    }
}

/// Search all `*.wants/` and `*.requires/` directories under `base` for a
/// symlink pointing to `unit_name`.
fn is_enabled_in(unit_name: &str, base: &Path) -> bool {
    let suffixes = [".wants", ".requires"];
    let Ok(entries) = std::fs::read_dir(base) else {
        return false;
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let is_wants_dir = suffixes.iter().any(|s| name.ends_with(s));
        if !is_wants_dir || !entry.path().is_dir() {
            continue;
        }
        // Check if a symlink to unit_name exists in this .wants/.requires dir.
        let link = entry.path().join(unit_name);
        if link.exists() || link.is_symlink() {
            return true;
        }
    }
    false
}

/// Query a unit-file state relative to an alternate filesystem root.
///
/// This mirrors `rustctl --root=` semantics: `/etc`, `/run`, and `/usr` are
/// resolved inside `root`, while symlink targets remain paths as seen inside
/// the target filesystem.
#[must_use]
pub fn query_root_enable_state(unit_name: &str, root: &Path) -> EnableState {
    let etc = root.join("etc/systemd/system");
    let run = root.join("run/systemd/system");
    let usr = root.join("usr/lib/systemd/system");
    let lib = root.join("lib/systemd/system");

    for (dir, masked_state, linked_state) in [
        (&etc, EnableState::Masked, EnableState::Linked),
        (&run, EnableState::MaskedRuntime, EnableState::LinkedRuntime),
    ] {
        let unit_path = dir.join(unit_name);
        if let Ok(target) = std::fs::read_link(&unit_path) {
            if target == Path::new("/dev/null") {
                return masked_state;
            }
            if target.is_absolute() {
                return linked_state;
            }
        }
    }

    if is_enabled_in(unit_name, &etc) {
        return EnableState::Enabled;
    }
    if is_enabled_in(unit_name, &run) {
        return EnableState::EnabledRuntime;
    }

    let search_dirs = [&etc, &run, &usr, &lib];
    let Some(unit_path) = search_dirs
        .iter()
        .map(|dir| dir.join(unit_name))
        .find(|path| path.exists() || path.is_symlink())
    else {
        return EnableState::Disabled;
    };

    let Ok(contents) = std::fs::read_to_string(unit_path) else {
        return EnableState::Bad;
    };
    let entries = parse_unit_text(&contents);
    let install_entries: Vec<_> = entries
        .iter()
        .filter(|entry| entry.section == "Install" && !entry.value.trim().is_empty())
        .collect();
    if install_entries.is_empty() {
        return EnableState::Static;
    }
    let has_direct_enablement = install_entries.iter().any(|entry| {
        matches!(
            entry.key.as_str(),
            "WantedBy" | "RequiredBy" | "UpheldBy" | "Alias"
        )
    });
    if has_direct_enablement {
        EnableState::Disabled
    } else if install_entries.iter().any(|entry| entry.key == "Also") {
        EnableState::Indirect
    } else {
        EnableState::Static
    }
}

/// Query the unit-file state relative to an alternate filesystem root.
///
/// Unlike [`query_root_enable_state`], this preserves the `ENOENT` and
/// `EINVAL` outcomes used by the Manager D-Bus API. The search order follows
/// the normal system manager unit lookup paths, including control and
/// generator directories.
///
/// # Errors
/// Returns [`UnitFileLookupError::InvalidName`] for malformed unit names and
/// [`UnitFileLookupError::NotFound`] when no unit file is present.
pub fn query_root_enable_state_checked(
    unit_name: &str,
    root: &Path,
) -> Result<EnableState, UnitFileLookupError> {
    if !valid_unit_file_name(unit_name) {
        return Err(UnitFileLookupError::InvalidName(unit_name.to_owned()));
    }

    let search_dirs = rooted_unit_search_dirs(root);
    let Some((candidate, source_dir)) = find_unit_file(unit_name, &search_dirs)? else {
        return Err(UnitFileLookupError::NotFound(unit_name.to_owned()));
    };

    state_for_unit_file(unit_name, &candidate, source_dir, root, &search_dirs)
}

/// Enumerate unit files visible from an alternate system root.
///
/// At most one entry is returned for each unit filename: a unit file in an
/// earlier manager search directory masks the same filename in every later
/// directory. The result is sorted by filename so callers get stable output
/// even when the filesystem returns directory entries in a different order.
///
/// # Errors
/// Returns [`UnitFileLookupError::Io`] when an existing unit search directory
/// cannot be read or one of its entries cannot be inspected.
pub fn list_root_unit_files(root: &Path) -> Result<Vec<UnitFileListEntry>, UnitFileLookupError> {
    let search_dirs = rooted_unit_search_dirs(root);
    let mut candidates = BTreeMap::new();

    for dir in &search_dirs {
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };

        for entry in entries {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if !file_type.is_file() && !file_type.is_symlink() {
                continue;
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !valid_unit_file_name(name) {
                continue;
            }
            candidates
                .entry(name.to_owned())
                .or_insert_with(|| (entry.path(), dir.as_path()));
        }
    }

    candidates
        .into_iter()
        .map(|(name, (path, source_dir))| {
            state_for_unit_file(&name, &path, source_dir, root, &search_dirs)
                .map(|state| UnitFileListEntry { path, state })
        })
        .collect()
}

fn state_for_unit_file(
    unit_name: &str,
    candidate: &Path,
    source_dir: &Path,
    root: &Path,
    search_dirs: &[PathBuf],
) -> Result<EnableState, UnitFileLookupError> {
    match resolve_unit_path(candidate, root)? {
        ResolvedUnitPath::Masked => Ok(if is_runtime_path(source_dir, root) {
            EnableState::MaskedRuntime
        } else {
            EnableState::Masked
        }),
        ResolvedUnitPath::Dangling => Ok(EnableState::Bad),
        ResolvedUnitPath::Path(resolved) => {
            if candidate != resolved
                && is_in_unit_search_path(&resolved, search_dirs)
                && resolved
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name != unit_name)
            {
                return Ok(EnableState::Alias);
            }

            if candidate != resolved && !is_in_unit_search_path(&resolved, search_dirs) {
                return Ok(if is_runtime_path(source_dir, root) {
                    EnableState::LinkedRuntime
                } else {
                    EnableState::Linked
                });
            }

            if is_generator_path(source_dir, root) {
                return Ok(EnableState::Generated);
            }
            if is_transient_path(source_dir, root) {
                return Ok(EnableState::Transient);
            }

            if is_enabled_in(unit_name, &root.join("etc/systemd/system")) {
                return Ok(EnableState::Enabled);
            }
            if is_enabled_in(unit_name, &root.join("run/systemd/system")) {
                return Ok(EnableState::EnabledRuntime);
            }

            state_from_install_section(&resolved)
        }
    }
}

/// Query the configured default target relative to an alternate filesystem
/// root.
///
/// The returned name is the final target filename after following the
/// highest-precedence `default.target` symlink, matching
/// `unit_file_get_default()`.
///
/// # Errors
/// Returns [`UnitFileLookupError::NotFound`] if no default target exists and
/// [`UnitFileLookupError::DefaultTargetMasked`] when it is masked.
pub fn query_root_default_target(root: &Path) -> Result<String, UnitFileLookupError> {
    let search_dirs = rooted_unit_search_dirs(root);
    let Some((candidate, _)) = find_unit_file("default.target", &search_dirs)? else {
        return Err(UnitFileLookupError::NotFound("default.target".to_owned()));
    };

    match resolve_unit_path(&candidate, root)? {
        ResolvedUnitPath::Masked => Err(UnitFileLookupError::DefaultTargetMasked),
        ResolvedUnitPath::Dangling => {
            Err(UnitFileLookupError::NotFound("default.target".to_owned()))
        }
        ResolvedUnitPath::Path(path) => path
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_owned)
            .ok_or_else(|| UnitFileLookupError::NotFound("default.target".to_owned())),
    }
}

/// Query the host system manager's default target.
///
/// # Errors
/// Propagates the unit-file lookup error from the standard system root.
pub fn query_system_default_target() -> Result<String, UnitFileLookupError> {
    query_root_default_target(Path::new("/"))
}

/// List the unit-file links that `disable` would remove without modifying the
/// filesystem.
///
/// This is the read-only operation exposed by Manager `GetUnitFileLinks`.
/// `runtime` selects the runtime configuration tree (`/run/systemd/system`)
/// instead of the persistent tree (`/etc/systemd/system`).  Links owned by
/// auxiliary units named through `[Install] Also=` are included as they are
/// by upstream's dry-run `unit_file_disable()` operation.
///
/// # Errors
/// Returns [`UnitFileLookupError::InvalidName`] when `unit_name` is malformed
/// and [`UnitFileLookupError::Io`] when the selected configuration tree cannot
/// be inspected.
pub fn get_root_unit_file_links(
    unit_name: &str,
    runtime: bool,
    root: &Path,
) -> Result<Vec<PathBuf>, UnitFileLookupError> {
    let search_dirs = rooted_unit_search_dirs(root);
    let config_dir = root.join(if runtime {
        "run/systemd/system"
    } else {
        "etc/systemd/system"
    });
    get_unit_file_links(unit_name, &config_dir, &search_dirs, root)
}

/// List the unit-file links that `disable` would remove using an explicit
/// manager search path and control directory.
///
/// This is the scope-aware counterpart to [`get_root_unit_file_links`].  User
/// managers use XDG-controlled unit directories rather than the system
/// `/etc/systemd/system` tree, so callers must provide the same search path
/// and control directory used by their manager.
///
/// `root` is used only when resolving symlinks in a rooted test tree; normal
/// system and user-manager callers pass `/`.
///
/// # Errors
///
/// Returns [`UnitFileLookupError::InvalidName`] for malformed unit names and
/// [`UnitFileLookupError::Io`] when the selected control tree cannot be read.
pub fn get_unit_file_links(
    unit_name: &str,
    config_dir: &Path,
    search_dirs: &[PathBuf],
    root: &Path,
) -> Result<Vec<PathBuf>, UnitFileLookupError> {
    if !valid_unit_file_name(unit_name) {
        return Err(UnitFileLookupError::InvalidName(unit_name.to_owned()));
    }

    let tracked_names = unit_file_disable_names(unit_name, root, search_dirs)?;
    let mut links = Vec::new();
    collect_unit_file_links(config_dir, root, &tracked_names, &mut links)?;
    Ok(links)
}

fn unit_file_disable_names(
    unit_name: &str,
    root: &Path,
    search_dirs: &[PathBuf],
) -> Result<BTreeSet<String>, UnitFileLookupError> {
    let mut names = BTreeSet::from([unit_name.to_owned()]);
    let mut pending = vec![unit_name.to_owned()];

    while let Some(name) = pending.pop() {
        let Some((candidate, _)) = find_unit_file(&name, search_dirs)? else {
            continue;
        };
        let ResolvedUnitPath::Path(path) = resolve_unit_path(&candidate, root)? else {
            continue;
        };
        let contents = match std::fs::read_to_string(path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };

        for entry in parse_unit_text(&contents) {
            if entry.section != "Install" || !matches!(entry.key.as_str(), "Also" | "Alias") {
                continue;
            }
            for linked_name in entry.value.split_whitespace() {
                if names.insert(linked_name.to_owned()) {
                    pending.push(linked_name.to_owned());
                }
            }
        }
    }

    Ok(names)
}

fn collect_unit_file_links(
    directory: &Path,
    root: &Path,
    tracked_names: &BTreeSet<String>,
    links: &mut Vec<PathBuf>,
) -> Result<(), UnitFileLookupError> {
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };

    for entry in entries {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let path = entry.path();
        if file_type.is_dir() {
            collect_unit_file_links(&path, root, tracked_names, links)?;
            continue;
        }
        if !file_type.is_symlink() {
            continue;
        }

        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !valid_unit_file_name(&name) {
            continue;
        }
        if unit_file_link_matches(&name, &path, root, tracked_names)? {
            links.push(path);
        }
    }

    Ok(())
}

fn unit_file_link_matches(
    name: &str,
    path: &Path,
    root: &Path,
    tracked_names: &BTreeSet<String>,
) -> Result<bool, UnitFileLookupError> {
    if tracked_unit_name(name, tracked_names) {
        return Ok(true);
    }

    let ResolvedUnitPath::Path(destination) = resolve_unit_path(path, root)? else {
        return Ok(false);
    };
    Ok(destination
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| tracked_unit_name(name, tracked_names)))
}

fn tracked_unit_name(name: &str, tracked_names: &BTreeSet<String>) -> bool {
    if tracked_names.contains(name) {
        return true;
    }

    let Some((prefix, suffix)) = name.rsplit_once('.') else {
        return false;
    };
    let Some((template, _instance)) = prefix.split_once('@') else {
        return false;
    };
    tracked_names.contains(&format!("{template}@.{suffix}"))
}

/// Standard unit-file search paths for `root` in priority order.
#[must_use]
pub fn rooted_unit_search_dirs(root: &Path) -> Vec<PathBuf> {
    vec![
        root.join("etc/systemd/system.control"),
        root.join("run/systemd/system.control"),
        root.join("run/systemd/transient"),
        root.join("run/systemd/generator.early"),
        root.join("etc/systemd/system"),
        root.join("etc/systemd/system.attached"),
        root.join("run/systemd/system"),
        root.join("run/systemd/system.attached"),
        root.join("run/systemd/generator"),
        root.join("usr/local/lib/systemd/system"),
        root.join("usr/lib/systemd/system"),
        root.join("lib/systemd/system"),
        root.join("run/systemd/generator.late"),
    ]
}

/// Convenience: query using the host system root.
#[must_use]
pub fn query_system_enable_state(unit_name: &str) -> EnableState {
    query_root_enable_state(unit_name, Path::new("/"))
}

fn valid_unit_file_name(name: &str) -> bool {
    if name.is_empty() || name.len() >= 256 {
        return false;
    }

    let Some((prefix, suffix)) = name.rsplit_once('.') else {
        return false;
    };
    if prefix.is_empty()
        || !matches!(
            suffix,
            "service"
                | "socket"
                | "timer"
                | "path"
                | "mount"
                | "automount"
                | "swap"
                | "target"
                | "slice"
                | "scope"
                | "device"
        )
    {
        return false;
    }

    let mut at = None;
    for (index, character) in prefix.char_indices() {
        if character == '@' && at.is_none() {
            at = Some(index);
        }
        if !(character.is_ascii_alphanumeric()
            || matches!(character, ':' | '-' | '_' | '.' | '\\' | '@'))
        {
            return false;
        }
    }
    at != Some(0)
}

fn find_unit_file<'a>(
    unit_name: &str,
    search_dirs: &'a [PathBuf],
) -> Result<Option<(PathBuf, &'a Path)>, UnitFileLookupError> {
    for dir in search_dirs {
        let path = dir.join(unit_name);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => return Ok(Some((path, dir))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(None)
}

fn resolve_unit_path(path: &Path, root: &Path) -> Result<ResolvedUnitPath, UnitFileLookupError> {
    let mut current = path.to_path_buf();
    for _ in 0..MAX_SYMLINK_DEPTH {
        let metadata = match std::fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(ResolvedUnitPath::Dangling);
            }
            Err(error) => return Err(error.into()),
        };
        if !metadata.file_type().is_symlink() {
            return Ok(ResolvedUnitPath::Path(current));
        }

        let target = std::fs::read_link(&current)?;
        if target == Path::new("/dev/null") {
            return Ok(ResolvedUnitPath::Masked);
        }
        current = if target.is_absolute() {
            root.join(target.strip_prefix("/").unwrap_or(&target))
        } else {
            current
                .parent()
                .map_or_else(|| target.clone(), |parent| parent.join(&target))
        };
    }
    Ok(ResolvedUnitPath::Dangling)
}

fn is_in_unit_search_path(path: &Path, search_dirs: &[PathBuf]) -> bool {
    search_dirs.iter().any(|dir| path.starts_with(dir))
}

fn is_runtime_path(path: &Path, root: &Path) -> bool {
    path.strip_prefix(root)
        .is_ok_and(|relative| relative.starts_with("run"))
}

fn is_generator_path(path: &Path, root: &Path) -> bool {
    path.strip_prefix(root).is_ok_and(|relative| {
        relative == Path::new("run/systemd/generator.early")
            || relative == Path::new("run/systemd/generator")
            || relative == Path::new("run/systemd/generator.late")
    })
}

fn is_transient_path(path: &Path, root: &Path) -> bool {
    path.strip_prefix(root)
        .is_ok_and(|relative| relative == Path::new("run/systemd/transient"))
}

fn state_from_install_section(path: &Path) -> Result<EnableState, UnitFileLookupError> {
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(EnableState::Bad),
        Err(error) => return Err(error.into()),
    };
    let entries = parse_unit_text(&contents);
    let install_entries: Vec<_> = entries
        .iter()
        .filter(|entry| entry.section == "Install" && !entry.value.trim().is_empty())
        .collect();
    if install_entries.is_empty() {
        return Ok(EnableState::Static);
    }
    if install_entries.iter().any(|entry| {
        matches!(
            entry.key.as_str(),
            "WantedBy" | "RequiredBy" | "UpheldBy" | "Alias"
        )
    }) {
        Ok(EnableState::Disabled)
    } else if install_entries.iter().any(|entry| entry.key == "Also") {
        Ok(EnableState::Indirect)
    } else {
        Ok(EnableState::Static)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn existing_unit_not_bad() {
        let state = query_system_enable_state("systemd-journald.service");
        assert_ne!(state, EnableState::Bad);
    }

    #[test]
    fn nonexistent_unit_disabled() {
        let state = query_system_enable_state("totally-nonexistent-xyz.service");
        assert_eq!(state, EnableState::Disabled);
    }

    #[test]
    fn rooted_state_distinguishes_disabled_and_static() {
        let root = tempfile::tempdir().unwrap();
        let usr = root.path().join("usr/lib/systemd/system");
        std::fs::create_dir_all(&usr).unwrap();
        std::fs::write(
            usr.join("disabled.service"),
            "[Service]\nExecStart=/bin/true\n[Install]\nWantedBy=multi-user.target\n",
        )
        .unwrap();
        std::fs::write(
            usr.join("static.service"),
            "[Service]\nExecStart=/bin/true\n",
        )
        .unwrap();
        assert_eq!(
            query_root_enable_state("disabled.service", root.path()),
            EnableState::Disabled
        );
        assert_eq!(
            query_root_enable_state("static.service", root.path()),
            EnableState::Static
        );
    }

    #[test]
    fn rooted_runtime_enablement_is_distinct() {
        let root = tempfile::tempdir().unwrap();
        let usr = root.path().join("usr/lib/systemd/system");
        let wants = root
            .path()
            .join("run/systemd/system/multi-user.target.wants");
        std::fs::create_dir_all(&usr).unwrap();
        std::fs::create_dir_all(&wants).unwrap();
        std::fs::write(
            usr.join("demo.service"),
            "[Service]\nExecStart=/bin/true\n[Install]\nWantedBy=multi-user.target\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(
            "/usr/lib/systemd/system/demo.service",
            wants.join("demo.service"),
        )
        .unwrap();
        assert_eq!(
            query_root_enable_state("demo.service", root.path()),
            EnableState::EnabledRuntime
        );
    }

    #[test]
    fn checked_rooted_query_preserves_missing_and_invalid_inputs() {
        let root = tempfile::tempdir().unwrap();
        let usr = root.path().join("usr/lib/systemd/system");
        std::fs::create_dir_all(&usr).unwrap();
        std::fs::write(
            usr.join("disabled.service"),
            "[Service]\nExecStart=/bin/true\n[Install]\nWantedBy=multi-user.target\n",
        )
        .unwrap();
        std::fs::write(
            usr.join("static.service"),
            "[Service]\nExecStart=/bin/true\n",
        )
        .unwrap();
        std::os::unix::fs::symlink("disabled.service", usr.join("alias.service")).unwrap();

        assert_eq!(
            query_root_enable_state_checked("disabled.service", root.path()).unwrap(),
            EnableState::Disabled
        );
        assert_eq!(
            query_root_enable_state_checked("static.service", root.path()).unwrap(),
            EnableState::Static
        );
        assert_eq!(
            query_root_enable_state_checked("alias.service", root.path()).unwrap(),
            EnableState::Alias
        );
        assert!(matches!(
            query_root_enable_state_checked("missing.service", root.path()),
            Err(UnitFileLookupError::NotFound(name)) if name == "missing.service"
        ));
        assert!(matches!(
            query_root_enable_state_checked("../invalid.service", root.path()),
            Err(UnitFileLookupError::InvalidName(name)) if name == "../invalid.service"
        ));
        assert!(matches!(
            query_root_enable_state_checked("invalid#.service", root.path()),
            Err(UnitFileLookupError::InvalidName(name)) if name == "invalid#.service"
        ));
        assert!(matches!(
            query_root_enable_state_checked("@invalid.service", root.path()),
            Err(UnitFileLookupError::InvalidName(name)) if name == "@invalid.service"
        ));
        assert!(matches!(
            query_root_enable_state_checked("valid@@instance.service", root.path()),
            Err(UnitFileLookupError::NotFound(name)) if name == "valid@@instance.service"
        ));
    }

    #[test]
    fn checked_rooted_query_observes_runtime_enablement_and_masks() {
        let root = tempfile::tempdir().unwrap();
        let usr = root.path().join("usr/lib/systemd/system");
        let run = root.path().join("run/systemd/system");
        let wants = run.join("multi-user.target.wants");
        std::fs::create_dir_all(&usr).unwrap();
        std::fs::create_dir_all(&wants).unwrap();
        std::fs::write(
            usr.join("enabled.service"),
            "[Service]\nExecStart=/bin/true\n[Install]\nWantedBy=multi-user.target\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(
            "/usr/lib/systemd/system/enabled.service",
            wants.join("enabled.service"),
        )
        .unwrap();
        assert_eq!(
            query_root_enable_state_checked("enabled.service", root.path()).unwrap(),
            EnableState::EnabledRuntime
        );

        let etc = root.path().join("etc/systemd/system");
        std::fs::create_dir_all(&etc).unwrap();
        std::os::unix::fs::symlink("/dev/null", etc.join("enabled.service")).unwrap();
        assert_eq!(
            query_root_enable_state_checked("enabled.service", root.path()).unwrap(),
            EnableState::Masked
        );
    }

    #[test]
    fn rooted_default_target_follows_precedence_and_symlinks() {
        let root = tempfile::tempdir().unwrap();
        let usr = root.path().join("usr/lib/systemd/system");
        let etc = root.path().join("etc/systemd/system");
        std::fs::create_dir_all(&usr).unwrap();
        std::fs::create_dir_all(&etc).unwrap();
        std::fs::write(usr.join("graphical.target"), "[Unit]\n").unwrap();
        std::fs::write(usr.join("multi-user.target"), "[Unit]\n").unwrap();
        std::os::unix::fs::symlink("graphical.target", usr.join("default.target")).unwrap();
        assert_eq!(
            query_root_default_target(root.path()).unwrap(),
            "graphical.target"
        );

        std::os::unix::fs::symlink(
            "/usr/lib/systemd/system/multi-user.target",
            etc.join("default.target"),
        )
        .unwrap();
        assert_eq!(
            query_root_default_target(root.path()).unwrap(),
            "multi-user.target"
        );
    }

    #[test]
    fn rooted_default_target_reports_missing_and_masked() {
        let root = tempfile::tempdir().unwrap();
        assert!(matches!(
            query_root_default_target(root.path()),
            Err(UnitFileLookupError::NotFound(name)) if name == "default.target"
        ));

        let etc = root.path().join("etc/systemd/system");
        std::fs::create_dir_all(&etc).unwrap();
        std::os::unix::fs::symlink("/dev/null", etc.join("default.target")).unwrap();
        assert!(matches!(
            query_root_default_target(root.path()),
            Err(UnitFileLookupError::DefaultTargetMasked)
        ));
    }

    #[test]
    fn set_root_default_target_creates_and_forces_v261_symlink() {
        let root = tempfile::tempdir().unwrap();
        let usr = root.path().join("usr/lib/systemd/system");
        std::fs::create_dir_all(&usr).unwrap();
        std::fs::write(usr.join("parity.target"), "[Unit]\n").unwrap();
        let changes = set_root_default_target("parity.target", false, root.path()).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].0, "symlink");
        assert_eq!(
            std::fs::read_link(root.path().join("etc/systemd/system/default.target")).unwrap(),
            usr.join("parity.target")
        );
        assert!(set_root_default_target("default.target", false, root.path()).is_err());
        std::fs::write(usr.join("other.target"), "[Unit]\n").unwrap();
        assert!(set_root_default_target("other.target", false, root.path()).is_err());
        assert_eq!(
            set_root_default_target("other.target", true, root.path()).unwrap()[0].0,
            "symlink"
        );
    }

    #[test]
    fn mask_and_unmask_unit_files_match_v261_changes() {
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join("etc/systemd/system");
        let names = vec!["missing.service".to_owned()];
        let changes = mask_unit_files(&names, false, &config).unwrap();
        assert_eq!(
            changes,
            vec![(
                "symlink".to_owned(),
                config.join("missing.service").display().to_string(),
                "/dev/null".to_owned()
            )]
        );
        assert!(mask_unit_files(&names, false, &config).unwrap().is_empty());
        let changes = unmask_unit_files(&names, &config).unwrap();
        assert_eq!(changes[0].0, "unlink");
        assert!(unmask_unit_files(&names, &config).unwrap().is_empty());
    }

    #[test]
    fn revert_unit_files_restores_vendor_and_removes_dropins_in_v261_order() {
        let root = tempfile::tempdir().unwrap();
        let vendor = root.path().join("usr/lib/systemd/system");
        let config = root.path().join("etc/systemd/system");
        let runtime = root.path().join("run/systemd/system");
        let search = vec![config.clone(), runtime.clone(), vendor.clone()];
        std::fs::create_dir_all(&vendor).unwrap();
        std::fs::create_dir_all(config.join("vendor.service.d")).unwrap();
        std::fs::create_dir_all(runtime.join("vendor.service.d")).unwrap();
        std::fs::write(vendor.join("vendor.service"), "[Unit]\n").unwrap();
        std::fs::write(config.join("vendor.service"), "[Unit]\n# override\n").unwrap();
        std::fs::write(config.join("vendor.service.d/10.conf"), "[Service]\n").unwrap();
        std::fs::write(runtime.join("vendor.service.d/20.conf"), "[Service]\n").unwrap();

        let changes = revert_unit_files(
            &["vendor.service".to_owned()],
            &config,
            &runtime,
            &search,
            root.path(),
        )
        .unwrap();
        assert_eq!(
            changes
                .iter()
                .map(|change| change.1.as_str())
                .collect::<Vec<_>>(),
            vec![
                config.join("vendor.service.d/10.conf").to_str().unwrap(),
                config.join("vendor.service.d").to_str().unwrap(),
                runtime.join("vendor.service.d/20.conf").to_str().unwrap(),
                runtime.join("vendor.service.d").to_str().unwrap(),
                config.join("vendor.service").to_str().unwrap(),
            ]
        );
        assert!(vendor.join("vendor.service").is_file());
        assert!(!config.join("vendor.service").exists());
        assert!(!config.join("vendor.service.d").exists());
        assert!(!runtime.join("vendor.service.d").exists());
    }

    #[test]
    fn revert_unit_files_drops_user_snippets_without_removing_local_override() {
        let root = tempfile::tempdir().unwrap();
        let vendor = root.path().join("usr/lib/systemd/system");
        let config = root.path().join("etc/systemd/system");
        let runtime = root.path().join("run/systemd/system");
        let search = vec![config.clone(), runtime.clone(), vendor];
        std::fs::create_dir_all(config.join("local.service.d")).unwrap();
        std::fs::write(config.join("local.service"), "[Unit]\n").unwrap();
        std::fs::write(config.join("local.service.d/10.conf"), "[Unit]\n").unwrap();

        let changes = revert_unit_files(
            &["local.service".to_owned()],
            &config,
            &runtime,
            &search,
            root.path(),
        )
        .unwrap();
        assert_eq!(changes.len(), 2);
        assert!(config.join("local.service").is_file());
        assert!(!config.join("local.service.d").exists());
    }

    #[test]
    fn enable_and_disable_unit_files_match_v261_order_and_force_rules() {
        let root = tempfile::tempdir().unwrap();
        let vendor = root.path().join("usr/lib/systemd/user");
        let config = root.path().join("config/systemd/user");
        std::fs::create_dir_all(&vendor).unwrap();
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(
            vendor.join("demo.service"),
            "[Install]\nWantedBy=default.target\nAlias=demo-alias.service\n",
        )
        .unwrap();
        let search = vec![config.clone(), vendor.clone()];
        let (carries, changes) =
            enable_unit_files(&["demo.service".to_owned()], false, &config, &search).unwrap();
        assert!(carries);
        assert_eq!(changes.len(), 2);
        assert!(changes[0].1.ends_with("demo-alias.service"));
        assert!(changes[1].1.ends_with("default.target.wants/demo.service"));

        let disabled = disable_unit_files(&["demo.service".to_owned()], &config, &search).unwrap();
        assert_eq!(disabled.len(), 2);
        assert!(disabled[0].1.ends_with("default.target.wants/demo.service"));
        assert!(disabled[1].1.ends_with("demo-alias.service"));
        assert!(!config.join("default.target.wants").exists());

        std::fs::create_dir_all(config.join("default.target.wants")).unwrap();
        std::os::unix::fs::symlink(
            "/usr/lib/systemd/user/other.service",
            config.join("default.target.wants/demo.service"),
        )
        .unwrap();
        let (_, forced) =
            enable_unit_files(&["demo.service".to_owned()], false, &config, &search).unwrap();
        assert!(forced.iter().any(|change| {
            change.0 == "unlink" && change.1.ends_with("default.target.wants/demo.service")
        }));
        assert!(forced.iter().any(|change| {
            change.0 == "symlink" && change.1.ends_with("default.target.wants/demo.service")
        }));
    }

    #[test]
    fn preset_unit_files_apply_first_matching_rules_and_modes() {
        let root = tempfile::tempdir().unwrap();
        let vendor = root.path().join("usr/lib/systemd/user");
        let config = root.path().join("config/systemd/user");
        let presets = root.path().join("usr/lib/systemd/user-preset");
        std::fs::create_dir_all(&vendor).unwrap();
        std::fs::create_dir_all(&config).unwrap();
        std::fs::create_dir_all(&presets).unwrap();
        std::fs::write(
            vendor.join("disabled.service"),
            "[Install]\nWantedBy=default.target\n",
        )
        .unwrap();
        std::fs::write(
            vendor.join("enabled.service"),
            "[Install]\nWantedBy=default.target\n",
        )
        .unwrap();
        std::fs::write(
            presets.join("90-test.preset"),
            "disable disabled.service\nenable enabled.service\n",
        )
        .unwrap();
        std::fs::create_dir_all(config.join("default.target.wants")).unwrap();
        std::os::unix::fs::symlink(
            vendor.join("disabled.service"),
            config.join("default.target.wants/disabled.service"),
        )
        .unwrap();

        let search = vec![config.clone(), vendor.clone()];
        let (carries, changes) = preset_unit_files(
            &["disabled.service".to_owned(), "enabled.service".to_owned()],
            PresetMode::Full,
            false,
            &config,
            &search,
            &[presets],
        )
        .unwrap();
        assert!(carries);
        assert_eq!(changes.len(), 2);
        assert_eq!(changes[0].0, "unlink");
        assert!(changes[0]
            .1
            .ends_with("default.target.wants/disabled.service"));
        assert_eq!(changes[1].0, "symlink");
        assert!(changes[1]
            .1
            .ends_with("default.target.wants/enabled.service"));

        let (carries, changes) = preset_unit_files(
            &["enabled.service".to_owned()],
            PresetMode::DisableOnly,
            false,
            &config,
            &search,
            &[],
        )
        .unwrap();
        assert!(!carries);
        assert!(changes.is_empty());
        assert_eq!(PresetMode::parse(""), Some(PresetMode::Full));
        assert_eq!(
            PresetMode::parse("enable-only"),
            Some(PresetMode::EnableOnly)
        );
        assert_eq!(
            PresetMode::parse("disable-only"),
            Some(PresetMode::DisableOnly)
        );
        assert_eq!(PresetMode::parse("invalid"), None);
    }

    #[test]
    fn preset_all_unit_files_uses_visible_precedence_and_default_enable() {
        let root = tempfile::tempdir().unwrap();
        let vendor = root.path().join("usr/lib/systemd/user");
        let config = root.path().join("config/systemd/user");
        let presets = root.path().join("usr/lib/systemd/user-preset");
        std::fs::create_dir_all(&vendor).unwrap();
        std::fs::create_dir_all(&config).unwrap();
        std::fs::create_dir_all(&presets).unwrap();
        std::fs::write(
            vendor.join("all.service"),
            "[Install]\nWantedBy=default.target\n",
        )
        .unwrap();
        // A higher-priority static override masks the vendor unit filename;
        // PresetAll must inspect the visible override only.
        std::fs::write(config.join("all.service"), "[Unit]\nDescription=override\n").unwrap();

        let changes = preset_all_unit_files(
            PresetMode::EnableOnly,
            false,
            &config,
            &[config.clone(), vendor],
            &[presets],
        )
        .unwrap();
        assert!(changes.is_empty());
        assert!(!config.join("default.target.wants/all.service").exists());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn add_dependency_unit_files_matches_v261_resolved_links_and_force_rules() {
        let root = tempfile::tempdir().unwrap();
        let vendor = root.path().join("usr/lib/systemd/user");
        let config = root.path().join("config/systemd/user");
        std::fs::create_dir_all(&vendor).unwrap();
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(vendor.join("real.target"), "[Unit]\n").unwrap();
        std::fs::write(vendor.join("real.service"), "[Unit]\n").unwrap();
        std::os::unix::fs::symlink("real.target", vendor.join("alias.target")).unwrap();
        std::os::unix::fs::symlink("real.service", vendor.join("alias.service")).unwrap();
        let search = vec![config.clone(), vendor.clone()];

        let changes = add_dependency_unit_files(
            &["alias.service".to_owned()],
            "alias.target",
            false,
            false,
            &config,
            &search,
        )
        .unwrap();
        assert_eq!(
            changes,
            vec![(
                "symlink".to_owned(),
                config
                    .join("real.target.wants/real.service")
                    .display()
                    .to_string(),
                vendor.join("real.service").display().to_string(),
            ),]
        );
        assert_eq!(
            std::fs::read_link(config.join("real.target.wants/real.service")).unwrap(),
            vendor.join("real.service")
        );
        assert!(add_dependency_unit_files(
            &["alias.service".to_owned()],
            "alias.target",
            false,
            false,
            &config,
            &search,
        )
        .unwrap()
        .is_empty());

        let linked_source = root.path().join("linked-real.service");
        let linked_alias = root.path().join("linked-alias.service");
        std::fs::write(&linked_source, "[Unit]\n").unwrap();
        std::os::unix::fs::symlink(&linked_source, &linked_alias).unwrap();
        let linked_changes = add_dependency_unit_files(
            &[linked_alias.display().to_string()],
            "alias.target",
            false,
            false,
            &config,
            &search,
        )
        .unwrap();
        assert_eq!(
            linked_changes,
            vec![
                (
                    "symlink".to_owned(),
                    config.join("linked-alias.service").display().to_string(),
                    linked_source.display().to_string(),
                ),
                (
                    "symlink".to_owned(),
                    config
                        .join("real.target.wants/linked-alias.service")
                        .display()
                        .to_string(),
                    linked_source.display().to_string(),
                ),
            ]
        );

        std::fs::write(vendor.join("atomic.service"), "[Unit]\n").unwrap();
        let atomic_link = config.join("real.target.wants/atomic.service");
        assert!(matches!(
            add_dependency_unit_files(
                &["atomic.service".to_owned(), "../invalid.service".to_owned()],
                "alias.target",
                false,
                false,
                &config,
                &search,
            ),
            Err(UnitFileLookupError::InvalidName(name)) if name == "../invalid.service"
        ));
        assert!(!atomic_link.exists());

        std::fs::write(vendor.join("other.service"), "[Unit]\n").unwrap();
        std::fs::create_dir_all(config.join("real.target.requires")).unwrap();
        std::os::unix::fs::symlink(
            vendor.join("other.service"),
            config.join("real.target.requires/real.service"),
        )
        .unwrap();
        let forced = add_dependency_unit_files(
            &["alias.service".to_owned()],
            "alias.target",
            true,
            false,
            &config,
            &search,
        )
        .unwrap();
        assert_eq!(forced.len(), 2);
        assert_eq!(forced[0].0, "unlink");
        assert_eq!(forced[1].0, "symlink");
        assert!(forced[1].1.ends_with("real.target.requires/real.service"));
        assert_eq!(
            std::fs::read_link(config.join("real.target.requires/real.service")).unwrap(),
            vendor.join("real.service")
        );

        assert!(matches!(
            add_dependency_unit_files(
                &["../invalid.service".to_owned()],
                "alias.target",
                false,
                false,
                &config,
                &search,
            ),
            Err(UnitFileLookupError::InvalidName(name)) if name == "../invalid.service"
        ));
        assert!(matches!(
            add_dependency_unit_files(
                &["alias.service".to_owned()],
                "missing.target",
                false,
                false,
                &config,
                &search,
            ),
            Err(UnitFileLookupError::NotFound(name)) if name == "missing.target"
        ));
    }

    #[test]
    fn enable_absolute_unit_file_creates_search_path_link_and_alias() {
        let root = tempfile::tempdir().unwrap();
        let external = root.path().join("external");
        let config = root.path().join("config/systemd/user");
        std::fs::create_dir_all(&external).unwrap();
        std::fs::create_dir_all(&config).unwrap();
        let source = external.join("external.service");
        std::fs::write(
            &source,
            "[Install]\nWantedBy=default.target\nAlias=external-alias.service\n",
        )
        .unwrap();
        let (carries, changes) = enable_unit_files(
            &[source.display().to_string()],
            false,
            &config,
            std::slice::from_ref(&config),
        )
        .unwrap();
        assert!(carries);
        assert_eq!(changes.len(), 3);
        assert_eq!(
            std::fs::read_link(config.join("external.service")).unwrap(),
            source
        );
        assert_eq!(
            std::fs::read_link(config.join("external-alias.service")).unwrap(),
            config.join("external.service")
        );
    }

    #[test]
    fn disable_unit_files_removes_also_units() {
        let root = tempfile::tempdir().unwrap();
        let vendor = root.path().join("usr/lib/systemd/user");
        let config = root.path().join("config/systemd/user");
        std::fs::create_dir_all(&vendor).unwrap();
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(
            vendor.join("main.service"),
            "[Install]\nAlias=main-alias.service\nAlso=helper.service\n",
        )
        .unwrap();
        std::fs::write(
            vendor.join("helper.service"),
            "[Install]\nAlias=helper-alias.service\n",
        )
        .unwrap();
        let search = vec![config.clone(), vendor];
        enable_unit_files(&["main.service".to_owned()], false, &config, &search).unwrap();
        let changes = disable_unit_files(&["main.service".to_owned()], &config, &search).unwrap();
        assert_eq!(changes.len(), 2);
        assert!(changes
            .iter()
            .any(|change| change.1.ends_with("main-alias.service")));
        assert!(changes
            .iter()
            .any(|change| change.1.ends_with("helper-alias.service")));
    }

    #[test]
    fn disable_masked_unit_reports_masked_change_without_unlinking() {
        let root = tempfile::tempdir().unwrap();
        let vendor = root.path().join("usr/lib/systemd/user");
        let config = root.path().join("config/systemd/user");
        std::fs::create_dir_all(&vendor).unwrap();
        std::fs::create_dir_all(&config).unwrap();
        std::os::unix::fs::symlink("/dev/null", config.join("masked.service")).unwrap();
        let changes = disable_unit_files(
            &["masked.service".to_owned()],
            &config,
            &[config.clone(), vendor],
        )
        .unwrap();
        assert_eq!(
            changes,
            vec![(
                "masked".to_owned(),
                config.join("masked.service").display().to_string(),
                String::new(),
            )]
        );
        assert!(config.join("masked.service").is_symlink());
    }

    #[test]
    fn enable_unit_files_creates_upholds_relationships() {
        let root = tempfile::tempdir().unwrap();
        let vendor = root.path().join("usr/lib/systemd/user");
        let config = root.path().join("config/systemd/user");
        std::fs::create_dir_all(&vendor).unwrap();
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(
            vendor.join("upheld.service"),
            "[Install]\nUpheldBy=watch.target\n",
        )
        .unwrap();
        let search = vec![config.clone(), vendor];
        let (_, changes) =
            enable_unit_files(&["upheld.service".to_owned()], false, &config, &search).unwrap();
        assert_eq!(changes.len(), 1);
        assert!(changes[0]
            .1
            .ends_with("watch.target.upholds/upheld.service"));
    }

    #[test]
    fn rooted_unit_file_links_follow_auxiliary_alias_and_instance_links() {
        let root = tempfile::tempdir().unwrap();
        let usr = root.path().join("usr/lib/systemd/system");
        let etc = root.path().join("etc/systemd/system");
        let run = root.path().join("run/systemd/system");
        std::fs::create_dir_all(usr.join("multi-user.target.wants")).unwrap();
        std::fs::create_dir_all(etc.join("multi-user.target.wants")).unwrap();
        std::fs::create_dir_all(run.join("multi-user.target.wants")).unwrap();

        std::fs::write(
            usr.join("primary.service"),
            "[Service]\nExecStart=/bin/true\n[Install]\nAlso=secondary.service\nAlias=primary-alias.service\n",
        )
        .unwrap();
        std::fs::write(
            usr.join("secondary.service"),
            "[Service]\nExecStart=/bin/true\n[Install]\nAlias=secondary-alias.service\n",
        )
        .unwrap();
        std::fs::write(
            usr.join("template@.service"),
            "[Service]\nExecStart=/bin/true\n",
        )
        .unwrap();

        std::os::unix::fs::symlink(
            "/usr/lib/systemd/system/primary.service",
            etc.join("multi-user.target.wants/primary.service"),
        )
        .unwrap();
        std::os::unix::fs::symlink(
            "/usr/lib/systemd/system/primary.service",
            etc.join("primary-alias.service"),
        )
        .unwrap();
        std::os::unix::fs::symlink(
            "/usr/lib/systemd/system/secondary.service",
            etc.join("multi-user.target.wants/secondary.service"),
        )
        .unwrap();
        std::os::unix::fs::symlink(
            "/usr/lib/systemd/system/secondary.service",
            etc.join("secondary-alias.service"),
        )
        .unwrap();
        std::os::unix::fs::symlink(
            "/usr/lib/systemd/system/template@.service",
            etc.join("multi-user.target.wants/template@seat0.service"),
        )
        .unwrap();
        std::os::unix::fs::symlink(
            "/usr/lib/systemd/system/primary.service",
            run.join("multi-user.target.wants/primary.service"),
        )
        .unwrap();

        let mut persistent =
            get_root_unit_file_links("primary.service", false, root.path()).unwrap();
        persistent.sort();
        assert_eq!(
            persistent,
            vec![
                etc.join("multi-user.target.wants/primary.service"),
                etc.join("multi-user.target.wants/secondary.service"),
                etc.join("primary-alias.service"),
                etc.join("secondary-alias.service"),
            ]
        );
        assert_eq!(
            get_root_unit_file_links("primary.service", true, root.path()).unwrap(),
            vec![run.join("multi-user.target.wants/primary.service")]
        );
        assert_eq!(
            get_root_unit_file_links("template@.service", false, root.path()).unwrap(),
            vec![etc.join("multi-user.target.wants/template@seat0.service")]
        );
    }

    #[test]
    fn rooted_unit_file_links_keep_missing_units_empty_and_reject_bad_names() {
        let root = tempfile::tempdir().unwrap();
        assert!(
            get_root_unit_file_links("missing.service", false, root.path())
                .unwrap()
                .is_empty()
        );
        assert!(matches!(
            get_root_unit_file_links("../bad.service", false, root.path()),
            Err(UnitFileLookupError::InvalidName(name)) if name == "../bad.service"
        ));
    }

    #[test]
    fn scoped_unit_file_links_use_explicit_user_search_and_control_dirs() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("usr/lib/systemd/user");
        let control = root.path().join("config/systemd/user");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::create_dir_all(&control).unwrap();
        std::fs::write(
            source.join("scoped.service"),
            "[Unit]\n[Install]\nAlias=scoped-alias.service\nWantedBy=default.target\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(
            source.join("scoped.service"),
            control.join("scoped-alias.service"),
        )
        .unwrap();
        std::fs::create_dir_all(control.join("default.target.wants")).unwrap();
        std::os::unix::fs::symlink(
            source.join("scoped.service"),
            control.join("default.target.wants/scoped.service"),
        )
        .unwrap();

        let mut links = get_unit_file_links(
            "scoped.service",
            &control,
            std::slice::from_ref(&source),
            root.path(),
        )
        .unwrap();
        links.sort();
        assert_eq!(
            links,
            vec![
                control.join("default.target.wants/scoped.service"),
                control.join("scoped-alias.service"),
            ]
        );
    }

    #[test]
    fn rooted_list_unit_files_uses_precedence_and_special_states() {
        let root = tempfile::tempdir().unwrap();
        let usr = root.path().join("usr/lib/systemd/system");
        let etc = root.path().join("etc/systemd/system");
        let generator = root.path().join("run/systemd/generator");
        let transient = root.path().join("run/systemd/transient");
        std::fs::create_dir_all(&usr).unwrap();
        std::fs::create_dir_all(&etc).unwrap();
        std::fs::create_dir_all(&generator).unwrap();
        std::fs::create_dir_all(&transient).unwrap();

        std::fs::write(
            usr.join("preferred.service"),
            "[Service]\nExecStart=/bin/true\n[Install]\nWantedBy=multi-user.target\n",
        )
        .unwrap();
        std::fs::write(
            etc.join("preferred.service"),
            "[Service]\nExecStart=/bin/true\n",
        )
        .unwrap();
        std::os::unix::fs::symlink("preferred.service", usr.join("alias.service")).unwrap();

        std::fs::write(usr.join("masked.service"), "[Service]\n").unwrap();
        std::os::unix::fs::symlink("/dev/null", etc.join("masked.service")).unwrap();
        std::fs::write(generator.join("generated.service"), "[Service]\n").unwrap();
        std::fs::write(transient.join("session-1.scope"), "[Scope]\n").unwrap();
        std::fs::write(etc.join("not-a-unit.txt"), "ignored\n").unwrap();
        std::fs::create_dir(etc.join("nested.service")).unwrap();

        let entries = list_root_unit_files(root.path()).unwrap();
        let relative: Vec<_> = entries
            .iter()
            .map(|entry| {
                (
                    entry.path.strip_prefix(root.path()).unwrap().to_path_buf(),
                    entry.state,
                )
            })
            .collect();
        assert_eq!(
            relative,
            vec![
                (
                    PathBuf::from("usr/lib/systemd/system/alias.service"),
                    EnableState::Alias
                ),
                (
                    PathBuf::from("run/systemd/generator/generated.service"),
                    EnableState::Generated
                ),
                (
                    PathBuf::from("etc/systemd/system/masked.service"),
                    EnableState::Masked
                ),
                (
                    PathBuf::from("etc/systemd/system/preferred.service"),
                    EnableState::Static
                ),
                (
                    PathBuf::from("run/systemd/transient/session-1.scope"),
                    EnableState::Transient
                ),
            ]
        );
    }

    #[test]
    fn masked_unit_detection() {
        // Create a temp masked unit to verify detection logic.
        let dir = tempfile::tempdir().unwrap();
        let unit = dir.path().join("test-masked.service");
        std::os::unix::fs::symlink("/dev/null", unit).unwrap();
        let state = query_enable_state("test-masked.service", &[dir.path()]);
        assert_eq!(state, EnableState::Masked);
    }
}
