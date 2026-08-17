// SPDX-License-Identifier: LGPL-2.1-or-later
//! `io.rustd.Manager1.Manager` D-Bus interface.
//!
//! Upstream reference: `src/core/dbus-manager.c` (v261)

// zbus interface methods must accept &self and owned types for the D-Bus wire
// protocol even when not all are used in the body.
#![allow(
    clippy::unused_self,
    clippy::needless_pass_by_value,
    clippy::unnecessary_wraps,
    clippy::used_underscore_binding,
    clippy::missing_errors_doc,
    clippy::map_unwrap_or,
    clippy::cast_sign_loss
)]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::CStr;
use std::fs;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicU8, Ordering},
    Arc, Mutex, RwLock,
};
use std::time::Duration;

use tokio::sync::{mpsc::UnboundedSender, oneshot};
use zbus::interface;

use crate::cgroup::CgroupManager;
use crate::config::{ManagerScope, UnitDefaults};
use crate::dbus::auth::{authorize_privileged_caller, caller_uid};
use crate::event::EventLoopWake;
use crate::glob::matches_no_escape;
use crate::ipc::UnitInfo;
use crate::ipc_server::ResetFailedRequests;
use crate::job::{Job, JobInfo, JobKind, JobQueue, JobRegistry};
use crate::limits::{rlimit_value, RlimitResource};
use crate::resource_control::{CpuQuota, LimitValue};
use crate::sandbox::resolve_user;
use crate::unit::enable_state::{
    add_dependency_unit_files as add_dependency_unit_files_to_disk, disable_unit_files,
    enable_unit_files, get_unit_file_links, link_unit_files, list_root_unit_files, mask_unit_files,
    preset_all_unit_files as preset_all_unit_files_to_disk,
    preset_unit_files as preset_unit_files_to_disk, query_root_enable_state_checked,
    query_system_default_target, revert_unit_files, rooted_unit_search_dirs,
    set_root_default_target, set_user_default_target, unit_files_carry_install_info,
    unmask_unit_files, PresetMode, UnitFileLookupError,
};
use crate::unit::loader::{LoadedUnit, UnitLoader};

const MAX_STATES_PER_CALL: usize = 256;
const MAX_PATTERNS_PER_CALL: usize = 4096;
const MAX_NAMES_PER_CALL: usize = 65_536;
const UNIT_NAME_MAX: usize = 256;
const USEC_PER_SEC: u64 = 1_000_000;
const DEFAULT_RESTART_USEC: u64 = 100_000;
const DEFAULT_TIMER_ACCURACY_USEC: u64 = 60 * USEC_PER_SEC;
const DEFAULT_DEVICE_TIMEOUT_USEC: u64 = 90 * USEC_PER_SEC;
const DEFAULT_START_LIMIT_INTERVAL_USEC: u64 = 10 * USEC_PER_SEC;
const DEFAULT_START_LIMIT_BURST: u32 = 5;
const EVENT_LOOP_RATE_LIMIT_INTERVAL_USEC: u64 = USEC_PER_SEC;
const EVENT_LOOP_RATE_LIMIT_BURST: u32 = 50_000;
const WATCHDOG_NEVER_PINGED_USEC: u64 = u64::MAX;
const ENVIRONMENT_ASSIGNMENTS_MAX: usize = 16_384;
const UNIT_FILE_FLAG_RUNTIME: u64 = 1 << 0;
const UNIT_FILE_FLAG_FORCE: u64 = 1 << 1;
const UNIT_FILE_FLAG_PORTABLE: u64 = 1 << 2;
const UNIT_FILE_FLAGS_PUBLIC: u64 =
    UNIT_FILE_FLAG_RUNTIME | UNIT_FILE_FLAG_FORCE | UNIT_FILE_FLAG_PORTABLE;

/// Values shared with the manager loop for D-Bus shutdown objectives.
pub const SHUTDOWN_NONE: u8 = 0;
pub const SHUTDOWN_REBOOT: u8 = 1;
pub const SHUTDOWN_POWEROFF: u8 = 2;
pub const SHUTDOWN_HALT: u8 = 3;
pub const SHUTDOWN_KEXEC: u8 = 4;

/// Manager-owned environment state shared with the D-Bus interface.
///
/// systemd keeps the environment inherited at manager startup separate from
/// the mutable client environment. `UnsetEnvironment` removes only client
/// assignments, so a startup value with the same name remains effective.
#[derive(Debug)]
pub struct ManagerEnvironmentState {
    baseline: Vec<String>,
    client: Vec<String>,
}

/// Shared manager environment state.
pub type ManagerEnvironment = Arc<RwLock<ManagerEnvironmentState>>;

#[derive(Debug)]
pub struct ManagerLogState {
    original_level: String,
    original_target: String,
    level: String,
    target: String,
}

pub type ManagerLog = Arc<RwLock<ManagerLogState>>;

#[must_use]
pub fn manager_log_from_config(level: String, target: String) -> ManagerLog {
    Arc::new(RwLock::new(ManagerLogState {
        original_level: level.clone(),
        original_target: target.clone(),
        level,
        target,
    }))
}

impl ManagerEnvironmentState {
    fn from_process() -> Self {
        let mut baseline: Vec<String> = std::env::vars()
            .map(|(name, value)| format!("{name}={value}"))
            .collect();
        baseline.sort_unstable();
        Self {
            baseline,
            client: Vec::new(),
        }
    }

    #[cfg(test)]
    fn with_baseline(baseline: Vec<String>) -> Self {
        Self {
            baseline,
            client: Vec::new(),
        }
    }

    fn effective(&self) -> Vec<String> {
        merge_environment_entries(&self.baseline, &self.client)
    }

    fn modify(&mut self, minus: &[String], plus: &[String]) {
        delete_environment_entries(&mut self.client, minus);
        self.client = merge_environment_entries(&self.client, plus);
    }
}

/// Snapshot the process environment used by a newly created manager.
#[must_use]
pub fn manager_environment_from_process() -> ManagerEnvironment {
    Arc::new(RwLock::new(ManagerEnvironmentState::from_process()))
}

/// Return the current effective manager environment for one service launch.
///
/// The caller owns the returned snapshot, so a concurrent D-Bus environment
/// update affects only launches started after the update, as in v261.
#[must_use]
pub(crate) fn manager_environment_effective(environment: &ManagerEnvironment) -> Vec<String> {
    environment
        .read()
        .map_or_else(|_| Vec::new(), |state| state.effective())
}

/// Apply a validated manager client-environment update.
pub(crate) fn manager_environment_modify(
    environment: &ManagerEnvironment,
    minus: &[String],
    plus: &[String],
) -> zbus::fdo::Result<()> {
    let mut environment = environment.write().map_err(|_| {
        zbus::fdo::Error::Failed("internal: manager environment lock poisoned".into())
    })?;
    environment.modify(minus, plus);
    Ok(())
}

/// Merge environment assignments with the right-hand side taking precedence.
#[must_use]
pub(crate) fn merge_environment_entries(base: &[String], plus: &[String]) -> Vec<String> {
    let mut merged = base.to_vec();
    for assignment in plus {
        let key = environment_key(assignment);
        if let Some(entry) = merged
            .iter_mut()
            .find(|entry| environment_key(entry) == key)
        {
            entry.clone_from(assignment);
        } else {
            merged.push(assignment.clone());
        }
    }
    merged
}

/// The conditional Manager job requests added in systemd v261.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManagerJobRequest {
    Reload,
    TryRestart,
    ReloadOrRestart,
    ReloadOrTryRestart,
}

/// Accepted `JobMode=` spellings in systemd v261.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JobMode {
    Fail,
    Lenient,
    Replace,
    ReplaceIrreversibly,
    Isolate,
    Flush,
    IgnoreDependencies,
    IgnoreRequirements,
    Triggering,
    RestartDependencies,
}

impl JobMode {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "fail" => Some(Self::Fail),
            "lenient" => Some(Self::Lenient),
            "replace" => Some(Self::Replace),
            "replace-irreversibly" => Some(Self::ReplaceIrreversibly),
            "isolate" => Some(Self::Isolate),
            "flush" => Some(Self::Flush),
            "ignore-dependencies" => Some(Self::IgnoreDependencies),
            "ignore-requirements" => Some(Self::IgnoreRequirements),
            "triggering" => Some(Self::Triggering),
            "restart-dependencies" => Some(Self::RestartDependencies),
            _ => None,
        }
    }
}

/// A request for the manager loop to load a unit into its authoritative registry.
pub struct UnitLoadRequest {
    /// Validated unit name requested through the Manager D-Bus interface.
    pub name: String,
    /// The manager replies with the newly published unit snapshot entry, if load succeeded.
    pub reply: oneshot::Sender<Option<UnitInfo>>,
}

/// Queue shared between the D-Bus server thread and the manager event loop.
pub type UnitLoadRequests = Arc<Mutex<Vec<UnitLoadRequest>>>;

/// A typed property accepted by the Manager `SetUnitProperties` method.
///
/// The wire method deliberately accepts `a(sv)`, but the manager loop must
/// never receive an unvalidated dynamic value.  Keeping this enum separate
/// from the D-Bus wire representation also makes the validate-before-mutate
/// transaction explicit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SetUnitProperty {
    /// Common `[Unit]` description.
    Description(String),
    /// Cgroup accounting switches.
    IoAccounting(bool),
    /// Cgroup accounting switches.
    MemoryAccounting(bool),
    /// Cgroup accounting switches.
    TasksAccounting(bool),
    /// Cgroup accounting switches.
    IpAccounting(bool),
    /// CPU weight in the kernel's range, with zero selecting idle scheduling
    /// and `u64::MAX` selecting the unlimited/unset sentinel.
    CpuWeight(u64),
    /// CPU quota in the Manager D-Bus per-second usec representation.
    CpuQuota(CpuQuota),
    /// IO weight in the kernel's 1..=10000 range.
    IoWeight(Option<u64>),
    /// Memory and task limits.
    MemoryMin(LimitValue),
    /// Memory and task limits.
    MemoryLow(LimitValue),
    /// Memory and task limits.
    MemoryHigh(LimitValue),
    /// Memory and task limits.
    MemoryMax(LimitValue),
    /// Memory and task limits.
    MemorySwapMax(LimitValue),
    /// Memory and task limits.
    MemoryZSwapMax(LimitValue),
    /// Whether zswap writeback is enabled.
    MemoryZSwapWriteback(bool),
    /// Maximum number of tasks.
    TasksMax(LimitValue),
}

/// Errors returned by the Manager `SetUnitProperties` method and its
/// manager-loop request queue.
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "io.rustd")]
pub(crate) enum SetUnitPropertiesError {
    #[zbus(name = "DBus.Error.InvalidArgs")]
    InvalidArgs(String),
    #[zbus(name = "DBus.Error.AccessDenied")]
    AccessDenied(String),
    #[zbus(name = "DBus.Error.Failed")]
    Failed(String),
    #[zbus(name = "DBus.Error.PropertyReadOnly")]
    PropertyReadOnly(String),
    #[zbus(name = "Manager1.NoSuchUnit")]
    NoSuchUnit(String),
    #[zbus(name = "Manager1.BadUnitSetting")]
    BadUnitSetting(String),
    #[zbus(name = "Manager1.UnitMasked")]
    UnitMasked(String),
}

/// A validated `SetUnitProperties` request consumed by the manager event loop.
pub(crate) struct SetUnitPropertiesRequest {
    /// Unit name selected by the D-Bus caller.
    pub(crate) name: String,
    /// Whether the setting is written to the runtime control hierarchy.
    pub(crate) runtime: bool,
    /// Typed properties, validated before entering this queue.
    pub(crate) properties: Vec<SetUnitProperty>,
    /// Reply delivered after the manager has applied the transaction.
    pub(crate) reply: oneshot::Sender<Result<(), SetUnitPropertiesError>>,
}

/// Queue shared between the D-Bus server thread and the manager event loop.
pub(crate) type SetUnitPropertiesRequests = Arc<Mutex<Vec<SetUnitPropertiesRequest>>>;

/// Per-sender references held on loaded units by `RefUnit`.
///
/// systemd's `rustd_bus_track` keeps a recursive count for every `(sender,
/// unit)` pair.  The D-Bus server removes all entries for a sender when the
/// bus reports that its unique name has disappeared.
pub(crate) type UnitReferences = Arc<Mutex<HashMap<(String, String), u32>>>;

// ── Signal type ───────────────────────────────────────────────────────────

/// Events that the manager emits as D-Bus signals.
///
/// Produced by the manager loop and consumed by the signal-dispatch task
/// running inside the D-Bus server thread.
///
/// Upstream reference: `src/core/dbus-manager.c` UnitNew/UnitRemoved/JobNew/
///   `JobRemoved` signals (v261)
#[derive(Debug)]
pub enum ManagerSignal {
    /// A unit has appeared in the registry.
    UnitNew {
        /// Unit id (`"foo.service"`).
        id: String,
        /// D-Bus object path for the unit.
        path: String,
    },
    /// A unit has been removed from the registry.
    UnitRemoved {
        /// Unit id.
        id: String,
        /// D-Bus object path for the unit.
        path: String,
    },
    /// A job has been queued.
    JobNew {
        /// Complete job identity and current state.
        job: JobInfo,
        /// Canonical numeric D-Bus object path for the job.
        path: String,
    },
    /// A job changed between waiting and running.
    JobStateChanged {
        /// Complete job identity and current state.
        job: JobInfo,
        /// Canonical numeric D-Bus object path for the job.
        path: String,
    },
    /// A job has completed.
    JobRemoved {
        /// Complete job identity at removal time.
        job: JobInfo,
        /// Canonical numeric D-Bus object path for the job.
        path: String,
        /// Result string: `"done"`, `"failed"`, `"timeout"`, etc.
        result: String,
    },
    /// The manager is beginning or finishing a daemon-reload.
    Reloading {
        /// True while unit files are being reloaded.
        active: bool,
    },
    /// Unit-file metadata changed after a daemon-reload.
    UnitFilesChanged,
    /// Initial manager startup completed.
    StartupFinished {
        /// Firmware time in microseconds.
        firmware: u64,
        /// Boot loader time in microseconds.
        loader: u64,
        /// Kernel time in microseconds.
        kernel: u64,
        /// Initrd time in microseconds.
        initrd: u64,
        /// Userspace initialization time in microseconds.
        userspace: u64,
        /// Total startup time in microseconds.
        total: u64,
    },
}

// ── wire types ────────────────────────────────────────────────────────────

/// Wire representation for `ListUnits` reply.
///
/// Tuple: (id, description, `load_state`, `active_state`, `sub_state`,
///         following, `object_path`, `job_id`, `job_type`, `job_object_path`)
pub type UnitListEntry = (
    String,
    String,
    String,
    String,
    String,
    String,
    zbus::zvariant::OwnedObjectPath,
    u32,
    String,
    zbus::zvariant::OwnedObjectPath,
);

/// Wire representation for `ListJobs`, `GetAfter`, and `GetBefore`.
///
/// Tuple: (id, unit, type, state, job object path, unit object path).
pub type JobListEntry = (
    u32,
    String,
    String,
    String,
    zbus::zvariant::OwnedObjectPath,
    zbus::zvariant::OwnedObjectPath,
);

/// Wire representation for `ListUnitFiles` and `ListUnitFilesByPatterns`.
///
/// Tuple: (selected unit-file path, enable state).
pub type UnitFileListEntry = (String, String);

/// Wire representation for `GetDynamicUsers`.
///
/// Tuple: (UID, dynamic account name).
pub type DynamicUserEntry = (u32, String);

/// Wire representation for `GetUnitProcesses`.
///
/// Tuple: (absolute cgroup path, PID, command line).
pub type UnitProcessEntry = (String, u32, String);

/// Wire representation for `DumpUnitFileDescriptorStore`.
///
/// Tuple: (name, mode, device major, device minor, inode, rdev major,
/// rdev minor, path, status flags).
pub type FileDescriptorStoreEntry = (String, u32, u32, u32, u64, u32, u32, String, u32);

/// Errors returned by the Manager's read-only unit-file queries.
///
/// The standard Manager interface uses both freedesktop D-Bus errors and the
/// systemd-specific `UnitMasked` error for these methods.
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "io.rustd")]
enum UnitFileMethodError {
    #[zbus(name = "DBus.Error.InvalidArgs")]
    InvalidArgs(String),
    #[zbus(name = "DBus.Error.FileNotFound")]
    FileNotFound(String),
    #[zbus(name = "DBus.Error.Failed")]
    Failed(String),
    #[zbus(name = "Manager1.UnitMasked")]
    UnitMasked(String),
}

/// Errors returned by `SetDefaultTarget`.
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "io.rustd")]
enum SetDefaultTargetMethodError {
    #[zbus(name = "DBus.Error.InvalidArgs")]
    InvalidArgs(String),
    #[zbus(name = "DBus.Error.AccessDenied")]
    AccessDenied(String),
    #[zbus(name = "DBus.Error.Failed")]
    Failed(String),
    #[zbus(name = "Manager1.NoSuchUnit")]
    NoSuchUnit(String),
    #[zbus(name = "Manager1.UnitExists")]
    UnitExists(String),
    #[zbus(name = "Manager1.UnitMasked")]
    UnitMasked(String),
}

/// Errors returned by Manager unit-file mask operations.
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "io.rustd")]
enum UnitFileMutationError {
    #[zbus(name = "DBus.Error.InvalidArgs")]
    InvalidArgs(String),
    #[zbus(name = "DBus.Error.AccessDenied")]
    AccessDenied(String),
    #[zbus(name = "DBus.Error.Failed")]
    Failed(String),
    #[zbus(name = "Manager1.UnitExists")]
    UnitExists(String),
}

impl From<UnitFileLookupError> for UnitFileMutationError {
    fn from(error: UnitFileLookupError) -> Self {
        match error {
            UnitFileLookupError::InvalidName(_) => Self::InvalidArgs("Invalid argument".to_owned()),
            UnitFileLookupError::UnitExists { path, target } => {
                let mut message = format!("File '{}' already exists", path.display());
                if let Some(target) = target {
                    message.push_str(&format!(" and is a symlink to {}", target.display()));
                }
                Self::UnitExists(message)
            }
            UnitFileLookupError::NotFound(_)
            | UnitFileLookupError::UnresolvableAlias(_)
            | UnitFileLookupError::DefaultTargetMasked
            | UnitFileLookupError::UnitMasked(_)
            | UnitFileLookupError::Io(_) => Self::Failed(error.to_string()),
        }
    }
}

/// Errors returned by `EnableUnitFiles`.
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "io.rustd")]
enum UnitFileEnableError {
    #[zbus(name = "DBus.Error.InvalidArgs")]
    InvalidArgs(String),
    #[zbus(name = "DBus.Error.AccessDenied")]
    AccessDenied(String),
    #[zbus(name = "DBus.Error.Failed")]
    Failed(String),
    #[zbus(name = "Manager1.NoSuchUnit")]
    NoSuchUnit(String),
    #[zbus(name = "Manager1.UnitExists")]
    UnitExists(String),
    #[zbus(name = "Manager1.UnitMasked")]
    UnitMasked(String),
}

/// Errors returned by `AddDependencyUnitFiles`.
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "io.rustd")]
enum AddDependencyUnitFilesError {
    #[zbus(name = "DBus.Error.InvalidArgs")]
    InvalidArgs(String),
    #[zbus(name = "DBus.Error.AccessDenied")]
    AccessDenied(String),
    #[zbus(name = "DBus.Error.Failed")]
    Failed(String),
    #[zbus(name = "Manager1.NoSuchUnit")]
    NoSuchUnit(String),
    #[zbus(name = "Manager1.UnitExists")]
    UnitExists(String),
    #[zbus(name = "Manager1.UnitMasked")]
    UnitMasked(String),
    #[zbus(name = "Manager1.BadUnitSetting")]
    BadUnitSetting(String),
}

impl AddDependencyUnitFilesError {
    fn from_lookup(error: UnitFileLookupError, invalid_file: bool) -> Self {
        match error {
            UnitFileLookupError::InvalidName(name) if invalid_file => {
                Self::InvalidArgs(format!("File {name}: Invalid argument"))
            }
            UnitFileLookupError::InvalidName(name) => {
                Self::BadUnitSetting(format!("Invalid unit name {name}"))
            }
            UnitFileLookupError::NotFound(name) => {
                Self::NoSuchUnit(format!("Unit {name} does not exist"))
            }
            UnitFileLookupError::UnresolvableAlias(name) => {
                Self::NoSuchUnit(format!("Unit {name} is an unresolvable alias"))
            }
            UnitFileLookupError::UnitMasked(path) => {
                Self::UnitMasked(format!("Unit {} is masked", path.display()))
            }
            UnitFileLookupError::UnitExists { path, target } => {
                let mut message = format!("File '{}' already exists", path.display());
                if let Some(target) = target {
                    message.push_str(&format!(" and is a symlink to {}", target.display()));
                }
                Self::UnitExists(message)
            }
            UnitFileLookupError::DefaultTargetMasked => {
                Self::Failed("Default target unit file is masked.".to_owned())
            }
            UnitFileLookupError::Io(error) => Self::Failed(error.to_string()),
        }
    }
}

impl From<UnitFileLookupError> for UnitFileEnableError {
    fn from(error: UnitFileLookupError) -> Self {
        match error {
            UnitFileLookupError::InvalidName(name) => {
                Self::InvalidArgs(format!("File {name}: Invalid argument"))
            }
            UnitFileLookupError::NotFound(name) => {
                Self::NoSuchUnit(format!("Unit {name} does not exist"))
            }
            UnitFileLookupError::UnresolvableAlias(name) => {
                Self::NoSuchUnit(format!("Unit {name} is an unresolvable alias"))
            }
            UnitFileLookupError::UnitExists { path, target } => {
                let mut message = format!("File '{}' already exists", path.display());
                if let Some(target) = target {
                    message.push_str(&format!(" and is a symlink to {}", target.display()));
                }
                Self::UnitExists(message)
            }
            UnitFileLookupError::UnitMasked(path) => {
                Self::UnitMasked(format!("Unit {} is masked", path.display()))
            }
            UnitFileLookupError::DefaultTargetMasked | UnitFileLookupError::Io(_) => {
                Self::Failed(error.to_string())
            }
        }
    }
}

/// Errors returned by `DisableUnitFiles`.
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "io.rustd")]
enum UnitFileDisableError {
    #[zbus(name = "DBus.Error.InvalidArgs")]
    InvalidArgs(String),
    #[zbus(name = "DBus.Error.AccessDenied")]
    AccessDenied(String),
    #[zbus(name = "DBus.Error.Failed")]
    Failed(String),
    #[zbus(name = "Manager1.NoSuchUnit")]
    NoSuchUnit(String),
}

impl From<UnitFileLookupError> for UnitFileDisableError {
    fn from(error: UnitFileLookupError) -> Self {
        match error {
            UnitFileLookupError::InvalidName(name) => {
                Self::InvalidArgs(format!("File {name}: Invalid argument"))
            }
            UnitFileLookupError::NotFound(name) => {
                Self::NoSuchUnit(format!("Unit {name} does not exist"))
            }
            UnitFileLookupError::UnresolvableAlias(name) => {
                Self::NoSuchUnit(format!("Unit {name} is an unresolvable alias"))
            }
            UnitFileLookupError::DefaultTargetMasked
            | UnitFileLookupError::UnitMasked(_)
            | UnitFileLookupError::UnitExists { .. }
            | UnitFileLookupError::Io(_) => Self::Failed(error.to_string()),
        }
    }
}

impl From<UnitFileLookupError> for SetDefaultTargetMethodError {
    fn from(error: UnitFileLookupError) -> Self {
        match error {
            UnitFileLookupError::InvalidName(_) => Self::InvalidArgs("Invalid argument".to_owned()),
            UnitFileLookupError::NotFound(name) => {
                Self::NoSuchUnit(format!("Unit {name} does not exist"))
            }
            UnitFileLookupError::UnresolvableAlias(name) => {
                Self::NoSuchUnit(format!("Unit {name} is an unresolvable alias"))
            }
            UnitFileLookupError::DefaultTargetMasked => {
                Self::UnitMasked("Default target unit file is masked.".to_owned())
            }
            UnitFileLookupError::UnitMasked(path) => {
                Self::UnitMasked(format!("Unit {} is masked", path.display()))
            }
            UnitFileLookupError::UnitExists { path, target } => {
                let mut message = format!("File '{}' already exists", path.display());
                if let Some(target) = target {
                    message.push_str(&format!(" and is a symlink to {}", target.display()));
                }
                Self::UnitExists(message)
            }
            UnitFileLookupError::Io(error) => Self::Failed(error.to_string()),
        }
    }
}

impl From<UnitFileLookupError> for UnitFileMethodError {
    fn from(error: UnitFileLookupError) -> Self {
        match error {
            UnitFileLookupError::InvalidName(_) => Self::InvalidArgs("Invalid argument".to_owned()),
            UnitFileLookupError::NotFound(_) | UnitFileLookupError::UnresolvableAlias(_) => {
                Self::FileNotFound("No such file or directory".to_owned())
            }
            UnitFileLookupError::DefaultTargetMasked => {
                Self::UnitMasked("Default target unit file is masked.".to_owned())
            }
            UnitFileLookupError::UnitMasked(path) => {
                Self::Failed(format!("Unit file {} is masked", path.display()))
            }
            UnitFileLookupError::UnitExists { path, target } => {
                let mut message = format!("File '{}' already exists", path.display());
                if let Some(target) = target {
                    message.push_str(&format!(" and is a symlink to {}", target.display()));
                }
                Self::Failed(message)
            }
            UnitFileLookupError::Io(error) => Self::Failed(error.to_string()),
        }
    }
}

/// Errors returned by `GetUnitFileLinks`.
///
/// Upstream returns the raw `-EUCLEAN` failure for a malformed unit name from
/// its dry-run disable path, which the D-Bus layer exposes as
/// `System.Error.EUCLEAN` rather than `InvalidArgs`.
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "System.Error")]
enum UnitFileLinksMethodError {
    #[zbus(name = "EUCLEAN")]
    Euclean(String),
    #[zbus(name = "EIO")]
    Io(String),
}

impl From<UnitFileLookupError> for UnitFileLinksMethodError {
    fn from(error: UnitFileLookupError) -> Self {
        match error {
            UnitFileLookupError::InvalidName(_) => {
                Self::Euclean("Structure needs cleaning".to_owned())
            }
            UnitFileLookupError::Io(error) => Self::Io(error.to_string()),
            UnitFileLookupError::NotFound(_)
            | UnitFileLookupError::UnresolvableAlias(_)
            | UnitFileLookupError::DefaultTargetMasked
            | UnitFileLookupError::UnitMasked(_)
            | UnitFileLookupError::UnitExists { .. } => Self::Io(error.to_string()),
        }
    }
}

/// Errors returned by Manager job lookup methods.
///
/// `GetJob`, `GetJobAfter`, and `GetJobBefore` all use the same
/// systemd-specific error when the requested live job has disappeared.
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "io.rustd")]
enum JobMethodError {
    #[zbus(name = "Manager1.NoSuchJob")]
    NoSuchJob(String),
    #[zbus(name = "DBus.Error.AccessDenied")]
    AccessDenied(String),
    #[zbus(name = "DBus.Error.Failed")]
    Failed(String),
}

/// Errors returned by `GetUnitByControlGroup`.
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "io.rustd")]
enum CgroupLookupError {
    #[zbus(name = "DBus.Error.InvalidArgs")]
    InvalidArgs(String),
    #[zbus(name = "Manager1.NoSuchUnit")]
    NoSuchUnit(String),
    #[zbus(name = "DBus.Error.Failed")]
    Failed(String),
}

/// Errors returned by the Manager dynamic-user query methods.
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "io.rustd")]
enum DynamicUserMethodError {
    #[zbus(name = "DBus.Error.NotSupported")]
    NotSupported(String),
    #[zbus(name = "DBus.Error.InvalidArgs")]
    InvalidArgs(String),
    #[zbus(name = "Manager1.NoSuchDynamicUser")]
    NoSuchDynamicUser(String),
    #[zbus(name = "DBus.Error.Failed")]
    Failed(String),
}

/// Errors returned by the Manager diagnostic-dump methods.
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "io.rustd")]
enum DumpMethodError {
    #[zbus(name = "DBus.Error.LimitsExceeded")]
    LimitsExceeded(String),
    #[zbus(name = "DBus.Error.Failed")]
    Failed(String),
}

/// Errors returned by `GetUnitByPIDFD`.
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "io.rustd")]
enum PidFdLookupError {
    #[zbus(name = "DBus.Error.Failed")]
    Failed(String),
    #[zbus(name = "Manager1.NoUnitForPID")]
    NoUnitForPid(String),
    #[zbus(name = "Manager1.NoSuchProcess")]
    NoSuchProcess(String),
}

/// Errors returned by `GetUnitByPID`.
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "io.rustd")]
enum PidLookupError {
    #[zbus(name = "DBus.Error.InvalidArgs")]
    InvalidArgs(String),
    #[zbus(name = "DBus.Error.Failed")]
    Failed(String),
    #[zbus(name = "Manager1.NoUnitForPID")]
    NoUnitForPid(String),
}

/// Errors returned by `GetUnitByInvocationID`.
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "io.rustd")]
enum InvocationIdLookupError {
    #[zbus(name = "DBus.Error.InvalidArgs")]
    InvalidArgs(String),
    #[zbus(name = "Manager1.NoSuchUnit")]
    NoSuchUnit(String),
    #[zbus(name = "Manager1.NoUnitForInvocationID")]
    NoUnitForInvocationId(String),
    #[zbus(name = "DBus.Error.Failed")]
    Failed(String),
}

/// Errors returned by `KillUnit`.
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "io.rustd")]
enum KillUnitMethodError {
    #[zbus(name = "DBus.Error.InvalidArgs")]
    InvalidArgs(String),
    #[zbus(name = "DBus.Error.AccessDenied")]
    AccessDenied(String),
    #[zbus(name = "DBus.Error.Failed")]
    Failed(String),
    #[zbus(name = "DBus.Error.NotSupported")]
    NotSupported(String),
    #[zbus(name = "Manager1.NoSuchProcess")]
    NoSuchProcess(String),
    #[zbus(name = "Manager1.NoSuchUnit")]
    NoSuchUnit(String),
}

/// Errors returned by `FreezeUnit` and `ThawUnit`.
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "io.rustd")]
enum FreezerMethodError {
    #[zbus(name = "DBus.Error.AccessDenied")]
    AccessDenied(String),
    #[zbus(name = "DBus.Error.Failed")]
    Failed(String),
    #[zbus(name = "DBus.Error.NotSupported")]
    NotSupported(String),
    #[zbus(name = "Manager1.NoSuchUnit")]
    NoSuchUnit(String),
    #[zbus(name = "Manager1.UnitBusy")]
    UnitBusy(String),
    #[zbus(name = "Manager1.UnitInactive")]
    UnitInactive(String),
    #[zbus(name = "Manager1.FrozenByParent")]
    FrozenByParent(String),
}

/// Errors returned by delegated cgroup process migration and removal.
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "io.rustd")]
enum CgroupDelegationMethodError {
    #[zbus(name = "DBus.Error.InvalidArgs")]
    InvalidArgs(String),
    #[zbus(name = "DBus.Error.AccessDenied")]
    AccessDenied(String),
    #[zbus(name = "DBus.Error.Failed")]
    Failed(String),
    #[zbus(name = "DBus.Error.UnixProcessIdUnknown")]
    UnixProcessIdUnknown(String),
    #[zbus(name = "Manager1.NoSuchUnit")]
    NoSuchUnit(String),
    #[zbus(name = "Manager1.BadUnitSetting")]
    BadUnitSetting(String),
    #[zbus(name = "Manager1.UnitMasked")]
    UnitMasked(String),
}

/// Process subset accepted by v261 `KillUnit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KillWhom {
    Main,
    Control,
    All,
    MainFail,
    ControlFail,
    AllFail,
    Cgroup,
    CgroupFail,
}

impl KillWhom {
    fn parse(value: &str) -> Result<Self, KillUnitMethodError> {
        match value {
            "main" => Ok(Self::Main),
            "control" => Ok(Self::Control),
            "all" | "" => Ok(Self::All),
            "main-fail" => Ok(Self::MainFail),
            "control-fail" => Ok(Self::ControlFail),
            "all-fail" => Ok(Self::AllFail),
            "cgroup" => Ok(Self::Cgroup),
            "cgroup-fail" => Ok(Self::CgroupFail),
            _ => Err(KillUnitMethodError::InvalidArgs(format!(
                "Invalid whom argument: {value}"
            ))),
        }
    }

    const fn is_fail(self) -> bool {
        matches!(
            self,
            Self::MainFail | Self::ControlFail | Self::AllFail | Self::CgroupFail
        )
    }

    const fn includes_main(self) -> bool {
        matches!(
            self,
            Self::Main | Self::MainFail | Self::All | Self::AllFail
        )
    }

    const fn includes_control(self) -> bool {
        matches!(
            self,
            Self::Control | Self::ControlFail | Self::All | Self::AllFail
        )
    }

    const fn includes_cgroup(self) -> bool {
        matches!(
            self,
            Self::All | Self::AllFail | Self::Cgroup | Self::CgroupFail
        )
    }
}

/// Errors returned by `GetUnit`.
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "io.rustd")]
enum UnitLookupError {
    #[zbus(name = "Manager1.NoSuchUnit")]
    NoSuchUnit(String),
    #[zbus(name = "DBus.Error.Failed")]
    Failed(String),
}

/// Errors returned by `RefUnit` and `UnrefUnit`.
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "io.rustd")]
enum UnitReferenceMethodError {
    #[zbus(name = "DBus.Error.InvalidArgs")]
    InvalidArgs(String),
    #[zbus(name = "DBus.Error.AccessDenied")]
    AccessDenied(String),
    #[zbus(name = "DBus.Error.Failed")]
    Failed(String),
    #[zbus(name = "Manager1.NoSuchUnit")]
    NoSuchUnit(String),
    #[zbus(name = "Manager1.BadUnitSetting")]
    BadUnitSetting(String),
    #[zbus(name = "Manager1.UnitMasked")]
    UnitMasked(String),
    #[zbus(name = "Manager1.NotReferenced")]
    NotReferenced(String),
}

/// Errors returned by `EnqueueUnitJob` after validating the requested job.
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "io.rustd")]
enum EnqueueUnitJobError {
    #[zbus(name = "DBus.Error.InvalidArgs")]
    InvalidArgs(String),
    #[zbus(name = "DBus.Error.AccessDenied")]
    AccessDenied(String),
    #[zbus(name = "DBus.Error.Failed")]
    Failed(String),
    #[zbus(name = "Manager1.NoSuchUnit")]
    NoSuchUnit(String),
}

/// Errors returned by `LoadUnit` before the manager creates its object.
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "io.rustd")]
enum LoadUnitError {
    #[zbus(name = "DBus.Error.InvalidArgs")]
    InvalidArgs(String),
    #[zbus(name = "DBus.Error.Failed")]
    Failed(String),
}

/// Errors returned by `DumpUnitFileDescriptorStore`.
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "io.rustd")]
enum FileDescriptorStoreMethodError {
    #[zbus(name = "DBus.Error.Failed")]
    Failed(String),
    #[zbus(name = "DBus.Error.NotSupported")]
    NotSupported(String),
    #[zbus(name = "Manager1.NoSuchUnit")]
    NoSuchUnit(String),
    #[zbus(name = "Manager1.FileDescriptorStoreDisabled")]
    Disabled(String),
}

// ── ManagerInterface ──────────────────────────────────────────────────────

/// The `io.rustd.Manager1.Manager` interface object.
pub struct ManagerInterface {
    /// Manager scope selecting system or user lookup paths.
    pub scope: ManagerScope,
    /// Cgroup controller that owns the manager's unit hierarchy.
    pub cgroup: CgroupManager,
    /// Parsed `[Manager]` defaults shared with the manager reload path.
    pub unit_defaults: Arc<RwLock<UnitDefaults>>,
    /// Configured default start timeout, in whole seconds.
    pub default_timeout_start_sec: u64,
    /// Configured default stop timeout, in whole seconds.
    pub default_timeout_stop_sec: u64,
    /// Shared unit snapshot updated by the manager loop.
    pub snapshot: Arc<RwLock<Vec<UnitInfo>>>,
    /// Shared job queue for injecting Start/Stop/Restart requests.
    pub queue: Arc<Mutex<JobQueue>>,
    /// On-demand unit loads performed exclusively by the manager loop.
    pub unit_load_requests: Option<UnitLoadRequests>,
    /// `SetUnitProperties` requests consumed by the manager event loop.
    pub(crate) set_unit_property_requests: Option<SetUnitPropertiesRequests>,
    /// Registry of all live exported jobs.
    pub jobs: JobRegistry,
    /// Cross-thread wake source for the manager event loop.
    pub wake: EventLoopWake,
    /// Shared daemon-reload request flag.
    pub reload_requested: Arc<AtomicBool>,
    /// Count of daemon-reload transactions completed by the manager loop.
    pub reload_count: Arc<AtomicU64>,
    /// Status code used when the manager next exits.
    pub exit_code: Arc<AtomicU8>,
    /// Whether the manager currently emits progress status on the console.
    ///
    /// v261 keeps the setting in the manager even though user managers
    /// deliberately report `ShowStatus=false` and ignore `SetShowStatus`.
    pub show_status: Arc<AtomicBool>,
    /// Request for the manager event loop to terminate normally.
    pub exit_requested: Arc<AtomicBool>,
    /// Request for the manager event loop to re-execute in place.
    pub reexecute_requested: Arc<AtomicBool>,
    /// System shutdown objective requested by a privileged Manager method.
    pub shutdown_action: Arc<AtomicU8>,
    /// Realtime timestamp captured when shutdown begins.
    pub shutdown_start_realtime_ns: Arc<AtomicI64>,
    /// Monotonic timestamp captured when shutdown begins.
    pub shutdown_start_monotonic_ns: Arc<AtomicI64>,
    /// Realtime manager-start timestamp in nanoseconds.
    pub startup_realtime_ns: i64,
    /// Monotonic manager-start timestamp in nanoseconds.
    pub startup_monotonic_ns: i64,
    /// Realtime timestamp captured when the initial startup jobs finish.
    pub finish_realtime_ns: Arc<AtomicI64>,
    /// Monotonic timestamp captured when the initial startup jobs finish.
    pub finish_monotonic_ns: Arc<AtomicI64>,
    /// Realtime timestamp captured before the initial dependency closure loads.
    pub units_load_start_realtime_ns: Arc<AtomicI64>,
    /// Monotonic timestamp captured before the initial dependency closure loads.
    pub units_load_start_monotonic_ns: Arc<AtomicI64>,
    /// Realtime timestamp captured after the initial dependency closure loads.
    pub units_load_finish_realtime_ns: Arc<AtomicI64>,
    /// Monotonic timestamp captured after the initial dependency closure loads.
    pub units_load_finish_monotonic_ns: Arc<AtomicI64>,
    /// Realtime timestamp captured at the start of the most recent reload.
    pub units_load_timestamp_realtime_ns: Arc<AtomicI64>,
    /// Monotonic timestamp captured at the start of the most recent reload.
    pub units_load_timestamp_monotonic_ns: Arc<AtomicI64>,
    /// Startup and client-managed environment used by Manager environment APIs.
    pub environment: ManagerEnvironment,
    /// Mutable Manager logging policy exposed through LogLevel/LogTarget.
    pub log: ManagerLog,
    /// Requests to clear failure state, consumed by the manager event loop.
    pub reset_failed_requests: ResetFailedRequests,
    /// Set of D-Bus unique names that have called `Subscribe()`.
    pub subscribers: Arc<Mutex<HashSet<String>>>,
    /// Recursive `RefUnit` counts keyed by sender unique name and unit ID.
    pub(crate) unit_references: UnitReferences,
    /// Sender for manager signals; the server task forwards them to D-Bus.
    pub signal_tx: UnboundedSender<ManagerSignal>,
}

fn default_rlimit(
    defaults: &Arc<RwLock<UnitDefaults>>,
    resource: RlimitResource,
    soft: bool,
) -> u64 {
    if let Ok(defaults) = defaults.read() {
        if let Some(spec) = defaults.rlimit(resource) {
            return rlimit_value(if soft { spec.soft } else { spec.hard });
        }
    }
    let mut value = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(resource.libc_resource(), &mut value) } != 0 {
        return u64::MAX;
    }
    let value = if soft { value.rlim_cur } else { value.rlim_max };
    if value == libc::RLIM_INFINITY {
        u64::MAX
    } else {
        value
    }
}

#[interface(name = "io.rustd.Manager1.Manager")]
impl ManagerInterface {
    // ── properties ────────────────────────────────────────────────────

    /// `Version` property — matches upstream `Version` D-Bus property.
    #[zbus(property)]
    fn version(&self) -> &'static str {
        "261"
    }

    /// `Features` property — compiled-in feature flags string.
    #[zbus(property)]
    fn features(&self) -> &'static str {
        "+PAM +AUDIT +SELINUX +IMA +APPARMOR +SMACK +SECCOMP +GCRYPT +GNUTLS +OPENSSL +ACL +BLKID +CURL +ELFUTILS +FIDO2 +IDN2 +IDN +IPTC +KMOD +LIBCRYPTSETUP +LIBFDISK +PCRE2 -PWQUALITY +P11KIT -QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB +ZSTD -BPF_FRAMEWORK +XKBCOMMON +UTMP +SYSVINIT default-hierarchy=unified"
    }

    /// `Virtualization` property.
    ///
    /// v261 reports the empty string rather than the detector's `"none"`
    /// spelling on bare metal.
    #[zbus(property(emits_changed_signal = "const"))]
    fn virtualization(&self) -> String {
        let virtualization = crate::unit::condition::detect_virtualization();
        if virtualization != "none" {
            virtualization
        } else {
            Default::default()
        }
    }

    /// Confidential virtualization is empty when no confidential guest
    /// backend is active, matching the current host's v261 detector result.
    #[zbus(property(emits_changed_signal = "const"))]
    fn confidential_virtualization(&self) -> &'static str {
        ""
    }

    /// `Architecture` property.
    #[zbus(property)]
    fn architecture(&self) -> &'static str {
        systemd_architecture()
    }

    /// `TimerSlackNSec` property — the manager process's current timer slack.
    #[zbus(property(emits_changed_signal = "const"))]
    fn timer_slack_n_sec(&self) -> u64 {
        let slack = unsafe { libc::prctl(libc::PR_GET_TIMERSLACK) };
        u64::try_from(slack).unwrap_or_default()
    }

    /// `DefaultOOMScoreAdjust` — the candidate manager process's effective
    /// OOM score adjustment. The candidate has no manager-default override,
    /// so this follows v261's fallback branch when no override is configured.
    #[zbus(
        name = "DefaultOOMScoreAdjust",
        property(emits_changed_signal = "const")
    )]
    fn default_oom_score_adjust(&self) -> i32 {
        current_oom_score_adjust()
    }

    /// `DefaultLimitCPU` hard limit.
    #[zbus(name = "DefaultLimitCPU", property(emits_changed_signal = "const"))]
    fn default_limit_cpu(&self) -> u64 {
        default_rlimit(&self.unit_defaults, RlimitResource::Cpu, false)
    }

    /// `DefaultLimitCPUSoft` soft limit.
    #[zbus(name = "DefaultLimitCPUSoft", property(emits_changed_signal = "const"))]
    fn default_limit_cpu_soft(&self) -> u64 {
        default_rlimit(&self.unit_defaults, RlimitResource::Cpu, true)
    }

    /// `DefaultLimitFSIZE` hard limit.
    #[zbus(name = "DefaultLimitFSIZE", property(emits_changed_signal = "const"))]
    fn default_limit_fsize(&self) -> u64 {
        default_rlimit(&self.unit_defaults, RlimitResource::Fsize, false)
    }

    /// `DefaultLimitFSIZESoft` soft limit.
    #[zbus(
        name = "DefaultLimitFSIZESoft",
        property(emits_changed_signal = "const")
    )]
    fn default_limit_fsize_soft(&self) -> u64 {
        default_rlimit(&self.unit_defaults, RlimitResource::Fsize, true)
    }

    /// `DefaultLimitDATA` hard limit.
    #[zbus(name = "DefaultLimitDATA", property(emits_changed_signal = "const"))]
    fn default_limit_data(&self) -> u64 {
        default_rlimit(&self.unit_defaults, RlimitResource::Data, false)
    }

    /// `DefaultLimitDATASoft` soft limit.
    #[zbus(
        name = "DefaultLimitDATASoft",
        property(emits_changed_signal = "const")
    )]
    fn default_limit_data_soft(&self) -> u64 {
        default_rlimit(&self.unit_defaults, RlimitResource::Data, true)
    }

    /// `DefaultLimitSTACK` hard limit.
    #[zbus(name = "DefaultLimitSTACK", property(emits_changed_signal = "const"))]
    fn default_limit_stack(&self) -> u64 {
        default_rlimit(&self.unit_defaults, RlimitResource::Stack, false)
    }

    /// `DefaultLimitSTACKSoft` soft limit.
    #[zbus(
        name = "DefaultLimitSTACKSoft",
        property(emits_changed_signal = "const")
    )]
    fn default_limit_stack_soft(&self) -> u64 {
        default_rlimit(&self.unit_defaults, RlimitResource::Stack, true)
    }

    /// `DefaultLimitCORE` hard limit.
    #[zbus(name = "DefaultLimitCORE", property(emits_changed_signal = "const"))]
    fn default_limit_core(&self) -> u64 {
        default_rlimit(&self.unit_defaults, RlimitResource::Core, false)
    }

    /// `DefaultLimitCORESoft` soft limit.
    #[zbus(
        name = "DefaultLimitCORESoft",
        property(emits_changed_signal = "const")
    )]
    fn default_limit_core_soft(&self) -> u64 {
        default_rlimit(&self.unit_defaults, RlimitResource::Core, true)
    }

    /// `DefaultLimitRSS` hard limit.
    #[zbus(name = "DefaultLimitRSS", property(emits_changed_signal = "const"))]
    fn default_limit_rss(&self) -> u64 {
        default_rlimit(&self.unit_defaults, RlimitResource::Rss, false)
    }

    /// `DefaultLimitRSSSoft` soft limit.
    #[zbus(name = "DefaultLimitRSSSoft", property(emits_changed_signal = "const"))]
    fn default_limit_rss_soft(&self) -> u64 {
        default_rlimit(&self.unit_defaults, RlimitResource::Rss, true)
    }

    /// `DefaultLimitNOFILE` hard limit.
    #[zbus(name = "DefaultLimitNOFILE", property(emits_changed_signal = "const"))]
    fn default_limit_nofile(&self) -> u64 {
        default_rlimit(&self.unit_defaults, RlimitResource::Nofile, false)
    }

    /// `DefaultLimitNOFILESoft` soft limit.
    #[zbus(
        name = "DefaultLimitNOFILESoft",
        property(emits_changed_signal = "const")
    )]
    fn default_limit_nofile_soft(&self) -> u64 {
        default_rlimit(&self.unit_defaults, RlimitResource::Nofile, true)
    }

    /// `DefaultLimitAS` hard limit.
    #[zbus(name = "DefaultLimitAS", property(emits_changed_signal = "const"))]
    fn default_limit_as(&self) -> u64 {
        default_rlimit(&self.unit_defaults, RlimitResource::As, false)
    }

    /// `DefaultLimitASSoft` soft limit.
    #[zbus(name = "DefaultLimitASSoft", property(emits_changed_signal = "const"))]
    fn default_limit_as_soft(&self) -> u64 {
        default_rlimit(&self.unit_defaults, RlimitResource::As, true)
    }

    /// `DefaultLimitNPROC` hard limit.
    #[zbus(name = "DefaultLimitNPROC", property(emits_changed_signal = "const"))]
    fn default_limit_nproc(&self) -> u64 {
        default_rlimit(&self.unit_defaults, RlimitResource::Nproc, false)
    }

    /// `DefaultLimitNPROCSoft` soft limit.
    #[zbus(
        name = "DefaultLimitNPROCSoft",
        property(emits_changed_signal = "const")
    )]
    fn default_limit_nproc_soft(&self) -> u64 {
        default_rlimit(&self.unit_defaults, RlimitResource::Nproc, true)
    }

    /// `DefaultLimitMEMLOCK` hard limit.
    #[zbus(name = "DefaultLimitMEMLOCK", property(emits_changed_signal = "const"))]
    fn default_limit_memlock(&self) -> u64 {
        default_rlimit(&self.unit_defaults, RlimitResource::Memlock, false)
    }

    /// `DefaultLimitMEMLOCKSoft` soft limit.
    #[zbus(
        name = "DefaultLimitMEMLOCKSoft",
        property(emits_changed_signal = "const")
    )]
    fn default_limit_memlock_soft(&self) -> u64 {
        default_rlimit(&self.unit_defaults, RlimitResource::Memlock, true)
    }

    /// `DefaultLimitLOCKS` hard limit.
    #[zbus(name = "DefaultLimitLOCKS", property(emits_changed_signal = "const"))]
    fn default_limit_locks(&self) -> u64 {
        default_rlimit(&self.unit_defaults, RlimitResource::Locks, false)
    }

    /// `DefaultLimitLOCKSSoft` soft limit.
    #[zbus(
        name = "DefaultLimitLOCKSSoft",
        property(emits_changed_signal = "const")
    )]
    fn default_limit_locks_soft(&self) -> u64 {
        default_rlimit(&self.unit_defaults, RlimitResource::Locks, true)
    }

    /// `DefaultLimitSIGPENDING` hard limit.
    #[zbus(
        name = "DefaultLimitSIGPENDING",
        property(emits_changed_signal = "const")
    )]
    fn default_limit_sigpending(&self) -> u64 {
        default_rlimit(&self.unit_defaults, RlimitResource::Sigpending, false)
    }

    /// `DefaultLimitSIGPENDINGSoft` soft limit.
    #[zbus(
        name = "DefaultLimitSIGPENDINGSoft",
        property(emits_changed_signal = "const")
    )]
    fn default_limit_sigpending_soft(&self) -> u64 {
        default_rlimit(&self.unit_defaults, RlimitResource::Sigpending, true)
    }

    /// `DefaultLimitMSGQUEUE` hard limit.
    #[zbus(
        name = "DefaultLimitMSGQUEUE",
        property(emits_changed_signal = "const")
    )]
    fn default_limit_msgqueue(&self) -> u64 {
        default_rlimit(&self.unit_defaults, RlimitResource::Msgqueue, false)
    }

    /// `DefaultLimitMSGQUEUESoft` soft limit.
    #[zbus(
        name = "DefaultLimitMSGQUEUESoft",
        property(emits_changed_signal = "const")
    )]
    fn default_limit_msgqueue_soft(&self) -> u64 {
        default_rlimit(&self.unit_defaults, RlimitResource::Msgqueue, true)
    }

    /// `DefaultLimitNICE` hard limit.
    #[zbus(name = "DefaultLimitNICE", property(emits_changed_signal = "const"))]
    fn default_limit_nice(&self) -> u64 {
        default_rlimit(&self.unit_defaults, RlimitResource::Nice, false)
    }

    /// `DefaultLimitNICESoft` soft limit.
    #[zbus(
        name = "DefaultLimitNICESoft",
        property(emits_changed_signal = "const")
    )]
    fn default_limit_nice_soft(&self) -> u64 {
        default_rlimit(&self.unit_defaults, RlimitResource::Nice, true)
    }

    /// `DefaultLimitRTPRIO` hard limit.
    #[zbus(name = "DefaultLimitRTPRIO", property(emits_changed_signal = "const"))]
    fn default_limit_rtprio(&self) -> u64 {
        default_rlimit(&self.unit_defaults, RlimitResource::Rtprio, false)
    }

    /// `DefaultLimitRTPRIOSoft` soft limit.
    #[zbus(
        name = "DefaultLimitRTPRIOSoft",
        property(emits_changed_signal = "const")
    )]
    fn default_limit_rtprio_soft(&self) -> u64 {
        default_rlimit(&self.unit_defaults, RlimitResource::Rtprio, true)
    }

    /// `DefaultLimitRTTIME` hard limit.
    #[zbus(name = "DefaultLimitRTTIME", property(emits_changed_signal = "const"))]
    fn default_limit_rttime(&self) -> u64 {
        default_rlimit(&self.unit_defaults, RlimitResource::Rttime, false)
    }

    /// `DefaultLimitRTTIMESoft` soft limit.
    #[zbus(
        name = "DefaultLimitRTTIMESoft",
        property(emits_changed_signal = "const")
    )]
    fn default_limit_rttime_soft(&self) -> u64 {
        default_rlimit(&self.unit_defaults, RlimitResource::Rttime, true)
    }

    /// Resolved `DefaultTasksMax` value.
    #[zbus(name = "DefaultTasksMax", property(emits_changed_signal = "false"))]
    fn default_tasks_max(&self) -> u64 {
        self.unit_defaults
            .read()
            .map_or(u64::MAX, |defaults| defaults.tasks_max_value())
    }

    /// `ShowStatus` — whether console status output is currently enabled.
    ///
    /// The candidate has no console status renderer yet, but it keeps the
    /// manager-owned state and exposes the same wire-level value as v261.
    /// User managers always report false, matching `manager_get_show_status()`.
    #[zbus(property)]
    fn show_status(&self) -> bool {
        self.scope == ManagerScope::System && self.show_status.load(Ordering::Acquire)
    }

    /// `NFailedUnits` property — number of currently failed loaded units.
    ///
    /// This follows the manager's live unit-state accounting: units in
    /// `maintenance` are not reported as failed unless their active state is
    /// explicitly `failed`.
    #[zbus(property)]
    fn n_failed_units(&self) -> u32 {
        let count = self.snapshot.read().map_or(0, |snapshot| {
            snapshot
                .iter()
                .filter(|unit| unit.active_state == "failed")
                .count()
        });
        u32::try_from(count).unwrap_or(u32::MAX)
    }

    /// `NNames` property — number of registered unit names.
    #[zbus(property)]
    fn n_names(&self) -> u32 {
        let count = self.snapshot.read().map_or(0, |snapshot| snapshot.len());
        u32::try_from(count).unwrap_or(u32::MAX)
    }

    /// `NJobs` property — number of waiting or running jobs.
    #[zbus(property(emits_changed_signal = "false"))]
    fn n_jobs(&self) -> u32 {
        u32::try_from(self.jobs.list().len()).unwrap_or(u32::MAX)
    }

    /// `NInstalledJobs` property — total jobs installed by this manager.
    #[zbus(property(emits_changed_signal = "false"))]
    fn n_installed_jobs(&self) -> u32 {
        self.jobs.n_installed()
    }

    /// `NFailedJobs` property — total jobs completed with a failure-counted result.
    #[zbus(property(emits_changed_signal = "false"))]
    fn n_failed_jobs(&self) -> u32 {
        self.jobs.n_failed()
    }

    /// `Progress` property — the fraction of installed candidate jobs that
    /// have completed. With no installed jobs, the manager is fully idle.
    #[zbus(property(emits_changed_signal = "false"))]
    fn progress(&self) -> f64 {
        let installed = self.jobs.n_installed();
        if installed == 0 {
            return 1.0;
        }
        let live = u32::try_from(self.jobs.list().len()).unwrap_or(u32::MAX);
        1.0 - f64::from(live) / f64::from(installed)
    }

    /// `ControlGroup` property — the candidate manager process's own unified
    /// cgroup path, with the root cgroup represented by the empty string.
    #[zbus(property(emits_changed_signal = "false"))]
    fn control_group(&self) -> String {
        manager_control_group()
    }

    /// `SystemState` property — aggregate manager state derived from live
    /// candidate unit state using the v261 state precedence.
    #[zbus(property(emits_changed_signal = "false"))]
    fn system_state(&self) -> String {
        let Ok(snapshot) = self.snapshot.read() else {
            return "maintenance".to_owned();
        };
        candidate_system_state(self.scope, &snapshot).to_owned()
    }

    /// `ExitCode` property — the manager's current exit-status value.
    #[zbus(property(emits_changed_signal = "false"))]
    fn exit_code(&self) -> u8 {
        self.exit_code.load(Ordering::Acquire)
    }

    /// `ReloadCount` property — completed daemon-reload transactions.
    ///
    /// The value starts at zero and saturates at the unsigned 64-bit maximum,
    /// matching the v261 manager's `saturate_add()` accounting.
    #[zbus(property(emits_changed_signal = "false"))]
    fn reload_count(&self) -> u64 {
        self.reload_count.load(Ordering::Acquire)
    }

    /// `Environment` property — effective environment inherited by services
    /// before unit-specific `Environment=` assignments are applied.
    #[zbus(property(emits_changed_signal = "false"))]
    fn environment(&self) -> Vec<String> {
        self.environment
            .read()
            .map_or_else(|_| Vec::new(), |environment| environment.effective())
    }

    /// Current Manager log level, matching v261's writable property.
    #[zbus(property(emits_changed_signal = "false"))]
    fn log_level(&self) -> String {
        self.log
            .read()
            .map_or_else(|_| "info".to_owned(), |state| state.level.clone())
    }

    /// Set Manager log level; an empty value restores the startup setting.
    #[zbus(property)]
    fn set_log_level(&mut self, value: String) -> zbus::fdo::Result<()> {
        if !value.is_empty() && !valid_log_level(&value) {
            return Err(zbus::fdo::Error::InvalidArgs(format!(
                "Invalid log level '{value}'"
            )));
        }
        let mut state = self
            .log
            .write()
            .map_err(|_| zbus::fdo::Error::Failed("internal: log state lock poisoned".into()))?;
        if value.is_empty() {
            state.level = state.original_level.clone();
        } else {
            state.level = value;
        }
        Ok(())
    }

    /// Current Manager log target, matching v261's writable property.
    #[zbus(property(emits_changed_signal = "false"))]
    fn log_target(&self) -> String {
        self.log.read().map_or_else(
            |_| "journal-or-kmsg".to_owned(),
            |state| state.target.clone(),
        )
    }

    /// Set Manager log target; an empty value restores the startup setting.
    #[zbus(property)]
    fn set_log_target(&mut self, value: String) -> zbus::fdo::Result<()> {
        if !value.is_empty() && !valid_log_target(&value) {
            return Err(zbus::fdo::Error::InvalidArgs(format!(
                "Invalid log target '{value}'"
            )));
        }
        let mut state = self
            .log
            .write()
            .map_err(|_| zbus::fdo::Error::Failed("internal: log state lock poisoned".into()))?;
        if value.is_empty() {
            state.target = state.original_target.clone();
        } else {
            state.target = value;
        }
        Ok(())
    }

    /// `ConfirmSpawn` property — the candidate does not implement an
    /// interactive spawn confirmation step.
    #[zbus(property(emits_changed_signal = "const"))]
    fn confirm_spawn(&self) -> bool {
        false
    }

    /// `UnitPath` property — canonical system-manager unit lookup paths.
    #[zbus(property)]
    fn unit_path(&self) -> Vec<String> {
        match self.scope {
            ManagerScope::System => manager_system_unit_search_paths(Path::new("/")),
            ManagerScope::User => manager_user_unit_search_paths(),
        }
    }

    /// `DefaultStandardOutput` property — the native launcher preserves the
    /// manager process's standard output unless a unit redirects it.
    #[zbus(property(emits_changed_signal = "const"))]
    fn default_standard_output(&self) -> &'static str {
        "inherit"
    }

    /// `DefaultStandardError` property — the native launcher preserves the
    /// manager process's standard error unless a unit redirects it.
    #[zbus(property(emits_changed_signal = "const"))]
    fn default_standard_error(&self) -> &'static str {
        "inherit"
    }

    /// `WatchdogDevice` — this manager has no hardware-watchdog backend.
    ///
    /// systemd reports the empty string when no device has been configured;
    /// see v261 `watchdog_get_device()`.
    #[zbus(property(emits_changed_signal = "const"))]
    fn watchdog_device(&self) -> &'static str {
        ""
    }

    /// `WatchdogLastPingTimestamp` — no watchdog ping has occurred.
    ///
    /// v261 represents an unset watchdog timestamp as `USEC_INFINITY` on
    /// the D-Bus wire.
    #[zbus(property(emits_changed_signal = "false"))]
    const fn watchdog_last_ping_timestamp(&self) -> u64 {
        WATCHDOG_NEVER_PINGED_USEC
    }

    /// `WatchdogLastPingTimestampMonotonic` — no watchdog ping has occurred.
    #[zbus(property(emits_changed_signal = "false"))]
    const fn watchdog_last_ping_timestamp_monotonic(&self) -> u64 {
        WATCHDOG_NEVER_PINGED_USEC
    }

    /// `UserspaceTimestamp` — realtime timestamp captured at manager start.
    ///
    /// v261 exposes this together with `UserspaceTimestampMonotonic` through
    /// its dual-timestamp helper. The candidate stores nanoseconds internally
    /// and publishes the D-Bus contract's unsigned microseconds.
    #[zbus(name = "UserspaceTimestamp", property(emits_changed_signal = "const"))]
    fn userspace_timestamp(&self) -> u64 {
        nanoseconds_to_usec(self.startup_realtime_ns)
    }

    /// `UserspaceTimestampMonotonic` — monotonic timestamp captured at
    /// manager start, in microseconds since boot.
    #[zbus(
        name = "UserspaceTimestampMonotonic",
        property(emits_changed_signal = "const")
    )]
    fn userspace_timestamp_monotonic(&self) -> u64 {
        nanoseconds_to_usec(self.startup_monotonic_ns)
    }

    /// `FinishTimestamp` — realtime timestamp captured when startup jobs
    /// finish, in microseconds since the Unix epoch.
    #[zbus(name = "FinishTimestamp", property(emits_changed_signal = "const"))]
    fn finish_timestamp(&self) -> u64 {
        nanoseconds_to_usec(self.finish_realtime_ns.load(Ordering::Acquire))
    }

    /// `FinishTimestampMonotonic` — monotonic timestamp captured when
    /// startup jobs finish, in microseconds since boot.
    #[zbus(
        name = "FinishTimestampMonotonic",
        property(emits_changed_signal = "const")
    )]
    fn finish_timestamp_monotonic(&self) -> u64 {
        nanoseconds_to_usec(self.finish_monotonic_ns.load(Ordering::Acquire))
    }

    /// `UnitsLoadStartTimestamp` — realtime timestamp captured before the
    /// initial dependency closure is loaded, in microseconds since the Unix
    /// epoch.
    #[zbus(
        name = "UnitsLoadStartTimestamp",
        property(emits_changed_signal = "const")
    )]
    fn units_load_start_timestamp(&self) -> u64 {
        nanoseconds_to_usec(self.units_load_start_realtime_ns.load(Ordering::Acquire))
    }

    /// `UnitsLoadStartTimestampMonotonic` — monotonic timestamp captured
    /// before the initial dependency closure is loaded, in microseconds since
    /// boot.
    #[zbus(
        name = "UnitsLoadStartTimestampMonotonic",
        property(emits_changed_signal = "const")
    )]
    fn units_load_start_timestamp_monotonic(&self) -> u64 {
        nanoseconds_to_usec(self.units_load_start_monotonic_ns.load(Ordering::Acquire))
    }

    /// `UnitsLoadFinishTimestamp` — realtime timestamp captured after the
    /// initial dependency closure is loaded, in microseconds since the Unix
    /// epoch.
    #[zbus(
        name = "UnitsLoadFinishTimestamp",
        property(emits_changed_signal = "const")
    )]
    fn units_load_finish_timestamp(&self) -> u64 {
        nanoseconds_to_usec(self.units_load_finish_realtime_ns.load(Ordering::Acquire))
    }

    /// `UnitsLoadFinishTimestampMonotonic` — monotonic timestamp captured
    /// after the initial dependency closure is loaded, in microseconds since
    /// boot.
    #[zbus(
        name = "UnitsLoadFinishTimestampMonotonic",
        property(emits_changed_signal = "const")
    )]
    fn units_load_finish_timestamp_monotonic(&self) -> u64 {
        nanoseconds_to_usec(self.units_load_finish_monotonic_ns.load(Ordering::Acquire))
    }

    /// `UnitsLoadTimestamp` — realtime timestamp captured at the start of
    /// the most recent manager reload, in microseconds since the Unix epoch.
    #[zbus(name = "UnitsLoadTimestamp", property(emits_changed_signal = "const"))]
    fn units_load_timestamp(&self) -> u64 {
        nanoseconds_to_usec(
            self.units_load_timestamp_realtime_ns
                .load(Ordering::Acquire),
        )
    }

    /// `UnitsLoadTimestampMonotonic` — monotonic timestamp captured at the
    /// start of the most recent manager reload, in microseconds since boot.
    #[zbus(
        name = "UnitsLoadTimestampMonotonic",
        property(emits_changed_signal = "const")
    )]
    fn units_load_timestamp_monotonic(&self) -> u64 {
        nanoseconds_to_usec(
            self.units_load_timestamp_monotonic_ns
                .load(Ordering::Acquire),
        )
    }

    /// `ShutdownStartTimestamp` — realtime timestamp captured when a
    /// supported system-manager shutdown objective begins, in microseconds
    /// since the Unix epoch.
    #[zbus(
        name = "ShutdownStartTimestamp",
        property(emits_changed_signal = "const")
    )]
    fn shutdown_start_timestamp(&self) -> u64 {
        nanoseconds_to_usec(self.shutdown_start_realtime_ns.load(Ordering::Acquire))
    }

    /// `ShutdownStartTimestampMonotonic` — monotonic timestamp captured when
    /// a supported system-manager shutdown objective begins, in microseconds
    /// since boot.
    #[zbus(
        name = "ShutdownStartTimestampMonotonic",
        property(emits_changed_signal = "const")
    )]
    fn shutdown_start_timestamp_monotonic(&self) -> u64 {
        nanoseconds_to_usec(self.shutdown_start_monotonic_ns.load(Ordering::Acquire))
    }

    /// `DefaultTimeoutStartUSec` — configured service start timeout.
    #[zbus(property(emits_changed_signal = "const"))]
    fn default_timeout_start_u_sec(&self) -> u64 {
        seconds_to_usec(self.default_timeout_start_sec)
    }

    /// `DefaultTimeoutStopUSec` — configured service stop timeout.
    #[zbus(property(emits_changed_signal = "const"))]
    fn default_timeout_stop_u_sec(&self) -> u64 {
        seconds_to_usec(self.default_timeout_stop_sec)
    }

    /// `DefaultTimeoutAbortUSec` — the candidate's abort timeout falls back
    /// to its configured stop timeout when `TimeoutAbortSec=` is omitted.
    #[zbus(property(emits_changed_signal = "false"))]
    fn default_timeout_abort_u_sec(&self) -> u64 {
        seconds_to_usec(self.default_timeout_stop_sec)
    }

    /// `DefaultRestartUSec` — the native service state machine's fallback
    /// restart delay when `RestartSec=` is omitted.
    #[zbus(property(emits_changed_signal = "const"))]
    fn default_restart_u_sec(&self) -> u64 {
        DEFAULT_RESTART_USEC
    }

    /// `DefaultTimerAccuracyUSec` — the manager's fixed default timer
    /// coalescing window.
    #[zbus(property(emits_changed_signal = "const"))]
    fn default_timer_accuracy_u_sec(&self) -> u64 {
        DEFAULT_TIMER_ACCURACY_USEC
    }

    /// `DefaultDeviceTimeoutUSec` — the default time allowed for device jobs.
    #[zbus(property(emits_changed_signal = "const"))]
    fn default_device_timeout_u_sec(&self) -> u64 {
        DEFAULT_DEVICE_TIMEOUT_USEC
    }

    /// `DefaultStartLimitIntervalUSec` — the fixed window used by the
    /// manager's default start limiter.
    #[zbus(property(emits_changed_signal = "const"))]
    fn default_start_limit_interval_u_sec(&self) -> u64 {
        DEFAULT_START_LIMIT_INTERVAL_USEC
    }

    /// `DefaultStartLimitBurst` — the maximum starts in the default window.
    #[zbus(property(emits_changed_signal = "const"))]
    fn default_start_limit_burst(&self) -> u32 {
        DEFAULT_START_LIMIT_BURST
    }

    /// `EventLoopRateLimitIntervalUSec` — the event-loop ratelimit window.
    #[zbus(property(emits_changed_signal = "const"))]
    fn event_loop_rate_limit_interval_u_sec(&self) -> u64 {
        EVENT_LOOP_RATE_LIMIT_INTERVAL_USEC
    }

    /// `EventLoopRateLimitBurst` — events allowed in one ratelimit window.
    #[zbus(property(emits_changed_signal = "const"))]
    fn event_loop_rate_limit_burst(&self) -> u32 {
        EVENT_LOOP_RATE_LIMIT_BURST
    }

    /// v261 manager resource defaults for services without an explicit
    /// per-unit override. These are the candidate's fixed manager defaults;
    /// parsing of system.conf overrides remains a separate parity area.
    #[zbus(
        name = "DefaultMemoryAccounting",
        property(emits_changed_signal = "const")
    )]
    fn default_memory_accounting(&self) -> bool {
        true
    }

    #[zbus(
        name = "DefaultTasksAccounting",
        property(emits_changed_signal = "const")
    )]
    fn default_tasks_accounting(&self) -> bool {
        true
    }

    #[zbus(name = "DefaultIOAccounting", property(emits_changed_signal = "const"))]
    fn default_io_accounting(&self) -> bool {
        false
    }

    #[zbus(name = "DefaultIPAccounting", property(emits_changed_signal = "const"))]
    fn default_ip_accounting(&self) -> bool {
        false
    }

    #[zbus(
        name = "DefaultMemoryZSwapWriteback",
        property(emits_changed_signal = "const")
    )]
    fn default_memory_z_swap_writeback(&self) -> bool {
        true
    }

    #[zbus(
        name = "DefaultRestrictSUIDSGID",
        property(emits_changed_signal = "const")
    )]
    fn default_restrict_suid_sgid(&self) -> bool {
        false
    }

    #[zbus(name = "DefaultOOMPolicy", property(emits_changed_signal = "const"))]
    fn default_oom_policy(&self) -> &'static str {
        "stop"
    }

    // ── methods ───────────────────────────────────────────────────────

    /// `SetUnitProperties(name, runtime, properties)` updates a loaded
    /// unit's typed settings and queues the live/persistent work on the
    /// manager event-loop thread.
    #[zbus(name = "SetUnitProperties")]
    async fn set_unit_properties(
        &self,
        name: String,
        runtime: bool,
        properties: Vec<(String, zbus::zvariant::OwnedValue)>,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<(), SetUnitPropertiesError> {
        if !valid_unit_name(&name) {
            return Err(SetUnitPropertiesError::InvalidArgs(format!(
                "Unit name {name} is not valid."
            )));
        }
        authorize_privileged_caller(connection, &header)
            .await
            .map_err(|error| SetUnitPropertiesError::AccessDenied(error.to_string()))?;
        self.request_unit_load(name.clone())
            .await
            .map_err(|error| SetUnitPropertiesError::Failed(error.to_string()))?
            .ok_or_else(|| SetUnitPropertiesError::NoSuchUnit(format!("Unit {name} not found.")))?;
        let properties = decode_set_unit_properties(properties)?;
        if properties.is_empty() {
            return Ok(());
        }
        let requests = self.set_unit_property_requests.as_ref().ok_or_else(|| {
            SetUnitPropertiesError::Failed("manager request queue unavailable".to_owned())
        })?;
        let (reply, response) = oneshot::channel();
        requests
            .lock()
            .map_err(|_| {
                SetUnitPropertiesError::Failed("manager request queue lock poisoned".to_owned())
            })?
            .push(SetUnitPropertiesRequest {
                name,
                runtime,
                properties,
                reply,
            });
        self.wake
            .wake()
            .map_err(|error| SetUnitPropertiesError::Failed(error.to_string()))?;
        tokio::time::timeout(Duration::from_secs(5), response)
            .await
            .map_err(|_| SetUnitPropertiesError::Failed("manager request timed out".to_owned()))?
            .map_err(|_| SetUnitPropertiesError::Failed("manager reply was dropped".to_owned()))?
    }

    /// `SetEnvironment(assignments)` updates the manager's client environment.
    async fn set_environment(
        &self,
        assignments: Vec<String>,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<()> {
        validate_environment_assignments(&assignments)?;
        authorize_privileged_caller(connection, &header).await?;
        manager_environment_modify(&self.environment, &[], &assignments)
    }

    /// `UnsetEnvironment(names)` removes client assignments by name or value.
    async fn unset_environment(
        &self,
        names: Vec<String>,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<()> {
        validate_environment_unset_patterns(&names)?;
        authorize_privileged_caller(connection, &header).await?;
        manager_environment_modify(&self.environment, &names, &[])
    }

    /// `UnsetAndSetEnvironment(names, assignments)` deletes then merges.
    async fn unset_and_set_environment(
        &self,
        names: Vec<String>,
        assignments: Vec<String>,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<()> {
        validate_environment_unset_and_set(&names, &assignments)?;
        authorize_privileged_caller(connection, &header).await?;
        manager_environment_modify(&self.environment, &names, &assignments)
    }

    /// `SetExitCode(number)` sets the value returned when the manager exits.
    fn set_exit_code(&self, number: u8) -> zbus::fdo::Result<()> {
        self.set_exit_code_value(number);
        Ok(())
    }

    /// `Exit()` terminates the manager using the current `ExitCode`.
    fn exit(&self) -> zbus::fdo::Result<()> {
        self.request_exit()
    }

    /// `Reboot()` requests a system-manager reboot objective.
    async fn reboot(
        &self,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<()> {
        self.request_system_shutdown("Reboot", SHUTDOWN_REBOOT, connection, &header)
            .await
    }

    /// `PowerOff()` requests a system-manager poweroff objective.
    async fn power_off(
        &self,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<()> {
        self.request_system_shutdown("Powering off", SHUTDOWN_POWEROFF, connection, &header)
            .await
    }

    /// `Halt()` requests a system-manager halt objective.
    async fn halt(
        &self,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<()> {
        self.request_system_shutdown("Halt", SHUTDOWN_HALT, connection, &header)
            .await
    }

    /// `KExec()` requests a system-manager kexec objective.
    async fn k_exec(
        &self,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<()> {
        self.request_system_shutdown("KExec", SHUTDOWN_KEXEC, connection, &header)
            .await
    }

    /// `StartUnit(name, mode)` → job object path.
    #[zbus(out_args("job"))]
    async fn start_unit(
        &self,
        name: String,
        mode: String,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<(zbus::zvariant::OwnedObjectPath,)> {
        let _ = mode;
        authorize_privileged_caller(connection, &header).await?;
        let owner = header.sender().map(ToString::to_string);
        let job = self.enqueue(JobKind::Start, &name, owner)?;
        Ok((job_path(job.id)?,))
    }

    /// `RefUnit(name)` holds a recursive reference on behalf of the caller.
    ///
    /// v261 loads and validates a named unit before forwarding to the unit's
    /// sender track.  The empty name retains the generic Manager operation's
    /// caller-unit lookup behavior.
    async fn ref_unit(
        &self,
        name: String,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<(), UnitReferenceMethodError> {
        let name = if name.is_empty() {
            let pid = caller_process_id(connection, &header)
                .await
                .map_err(UnitReferenceMethodError::Failed)?;
            self.unit_name_for_pid(pid)
                .map_err(UnitReferenceMethodError::Failed)?
                .ok_or_else(|| {
                    UnitReferenceMethodError::NoSuchUnit(
                        "Client not member of any unit.".to_owned(),
                    )
                })?
        } else {
            if !valid_unit_name(&name) {
                return Err(UnitReferenceMethodError::InvalidArgs(format!(
                    "Unit name {name} is not valid."
                )));
            }
            name
        };

        let loaded = self
            .snapshot
            .read()
            .map_err(|_| {
                UnitReferenceMethodError::Failed("internal: unit snapshot lock poisoned".into())
            })?
            .iter()
            .find(|unit| unit.name == name)
            .cloned();
        let unit = match loaded {
            Some(unit) => unit,
            None => self
                .request_unit_load(name.clone())
                .await
                .map_err(|error| UnitReferenceMethodError::Failed(error.to_string()))?
                .ok_or_else(|| {
                    UnitReferenceMethodError::NoSuchUnit(format!("Unit {name} not found."))
                })?,
        };
        validate_reference_unit_load_state(&unit.name, &unit.load_state)?;

        authorize_privileged_caller(connection, &header)
            .await
            .map_err(|error| UnitReferenceMethodError::AccessDenied(error.to_string()))?;
        let sender = sender_name(&header)?;
        self.add_unit_reference(&sender, &unit.name)
    }

    /// `UnrefUnit(name)` drops one reference held by the caller.
    ///
    /// Unlike `RefUnit`, v261 does not load or validate the unit before
    /// removing the sender's track entry.
    async fn unref_unit(
        &self,
        name: String,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<(), UnitReferenceMethodError> {
        let name = if name.is_empty() {
            let pid = caller_process_id(connection, &header)
                .await
                .map_err(UnitReferenceMethodError::Failed)?;
            self.unit_name_for_pid(pid)
                .map_err(UnitReferenceMethodError::Failed)?
                .ok_or_else(|| {
                    UnitReferenceMethodError::NoSuchUnit(
                        "Client not member of any unit.".to_owned(),
                    )
                })?
        } else {
            name
        };
        self.get_explicit_unit(&name)
            .map_err(unit_reference_lookup_error)?;
        let sender = sender_name(&header)?;
        self.remove_unit_reference(&sender, &name)
    }

    /// `StartUnitReplace(old_unit, new_unit, mode)` → job object path.
    ///
    /// The candidate shares its real start queue with `StartUnit`; retaining
    /// both names here preserves the v261 wire contract while the manager
    /// loop performs the replacement transaction on the new unit.
    #[zbus(out_args("job"))]
    async fn start_unit_replace(
        &self,
        old_unit: String,
        new_unit: String,
        mode: String,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<(zbus::zvariant::OwnedObjectPath,), UnitLookupError> {
        validate_start_unit_with_flags(&mode, 0)
            .map_err(|error| UnitLookupError::Failed(error.to_string()))?;
        self.get_explicit_unit(&old_unit).map(|_| ())?;
        authorize_privileged_caller(connection, &header)
            .await
            .map_err(|error| UnitLookupError::Failed(error.to_string()))?;
        let owner = header.sender().map(ToString::to_string);
        let job = self
            .enqueue(JobKind::Start, &new_unit, owner)
            .map_err(|error| UnitLookupError::Failed(error.to_string()))?;
        job_path(job.id)
            .map(|path| (path,))
            .map_err(|error| UnitLookupError::Failed(error.to_string()))
    }

    /// `StartUnitWithFlags(name, mode, flags)` → job object path.
    ///
    /// v261 publishes this as the flags-aware counterpart of `StartUnit`,
    /// but currently accepts only a zero flags value.  Validate the wire
    /// arguments before the privileged operation so callers get the standard
    /// `InvalidArgs` diagnostics without queuing a job.
    #[zbus(out_args("job"))]
    async fn start_unit_with_flags(
        &self,
        name: String,
        mode: String,
        flags: u64,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<(zbus::zvariant::OwnedObjectPath,)> {
        validate_start_unit_with_flags(&mode, flags)?;
        authorize_privileged_caller(connection, &header).await?;
        let owner = header.sender().map(ToString::to_string);
        let job = self.enqueue(JobKind::Start, &name, owner)?;
        Ok((job_path(job.id)?,))
    }

    /// `SetShowStatus(mode)` — update the manager's console-status policy.
    ///
    /// v261 accepts no value (auto), no, error, temporary, and yes.  User
    /// managers accept the call but intentionally keep `ShowStatus` false.
    fn set_show_status(&self, mode: String) -> zbus::fdo::Result<()> {
        let enabled = parse_show_status_mode(&mode)?;
        if self.scope == ManagerScope::System {
            self.show_status.store(enabled, Ordering::Release);
        }
        Ok(())
    }

    /// `StopUnit(name, mode)` → job object path.
    #[zbus(out_args("job"))]
    async fn stop_unit(
        &self,
        name: String,
        mode: String,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<(zbus::zvariant::OwnedObjectPath,)> {
        let _ = mode;
        authorize_privileged_caller(connection, &header).await?;
        let owner = header.sender().map(ToString::to_string);
        let job = self.enqueue(JobKind::Stop, &name, owner)?;
        Ok((job_path(job.id)?,))
    }

    /// `RestartUnit(name, mode)` → job object path.
    #[zbus(out_args("job"))]
    async fn restart_unit(
        &self,
        name: String,
        mode: String,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<(zbus::zvariant::OwnedObjectPath,)> {
        let _ = mode;
        authorize_privileged_caller(connection, &header).await?;
        let owner = header.sender().map(ToString::to_string);
        let job = self.enqueue(JobKind::Restart, &name, owner)?;
        Ok((job_path(job.id)?,))
    }

    /// `ReloadUnit(name, mode)` → job object path.
    #[zbus(out_args("job"))]
    async fn reload_unit(
        &self,
        name: String,
        mode: String,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<(zbus::zvariant::OwnedObjectPath,)> {
        let kind = self.manager_job_kind(ManagerJobRequest::Reload, &name, &mode)?;
        authorize_privileged_caller(connection, &header).await?;
        let owner = header.sender().map(ToString::to_string);
        Ok((job_path(self.enqueue(kind, &name, owner)?.id)?,))
    }

    /// `TryRestartUnit(name, mode)` → job object path.
    #[zbus(out_args("job"))]
    async fn try_restart_unit(
        &self,
        name: String,
        mode: String,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<(zbus::zvariant::OwnedObjectPath,)> {
        let kind = self.manager_job_kind(ManagerJobRequest::TryRestart, &name, &mode)?;
        authorize_privileged_caller(connection, &header).await?;
        let owner = header.sender().map(ToString::to_string);
        Ok((job_path(self.enqueue(kind, &name, owner)?.id)?,))
    }

    /// `ReloadOrRestartUnit(name, mode)` → job object path.
    #[zbus(out_args("job"))]
    async fn reload_or_restart_unit(
        &self,
        name: String,
        mode: String,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<(zbus::zvariant::OwnedObjectPath,)> {
        let kind = self.manager_job_kind(ManagerJobRequest::ReloadOrRestart, &name, &mode)?;
        authorize_privileged_caller(connection, &header).await?;
        let owner = header.sender().map(ToString::to_string);
        Ok((job_path(self.enqueue(kind, &name, owner)?.id)?,))
    }

    /// `ReloadOrTryRestartUnit(name, mode)` → job object path.
    #[zbus(out_args("job"))]
    async fn reload_or_try_restart_unit(
        &self,
        name: String,
        mode: String,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<(zbus::zvariant::OwnedObjectPath,)> {
        let kind = self.manager_job_kind(ManagerJobRequest::ReloadOrTryRestart, &name, &mode)?;
        authorize_privileged_caller(connection, &header).await?;
        let owner = header.sender().map(ToString::to_string);
        Ok((job_path(self.enqueue(kind, &name, owner)?.id)?,))
    }

    /// `EnqueueUnitJob(name, job_type, job_mode)` → complete job description.
    #[zbus(out_args(
        "job_id",
        "job_path",
        "unit_id",
        "unit_path",
        "job_type",
        "affected_jobs"
    ))]
    async fn enqueue_unit_job(
        &self,
        name: String,
        job_type: String,
        job_mode: String,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<
        (
            u32,
            zbus::zvariant::OwnedObjectPath,
            String,
            zbus::zvariant::OwnedObjectPath,
            String,
            Vec<(
                u32,
                zbus::zvariant::OwnedObjectPath,
                String,
                zbus::zvariant::OwnedObjectPath,
                String,
            )>,
        ),
        EnqueueUnitJobError,
    > {
        let kind = parse_enqueued_job_type(&job_type)
            .map_err(|error| EnqueueUnitJobError::InvalidArgs(error.to_string()))?;
        let mode = JobMode::parse(&job_mode).ok_or_else(|| {
            EnqueueUnitJobError::InvalidArgs(format!("Job mode {job_mode} invalid"))
        })?;
        validate_job_mode_for_request(mode)
            .map_err(|error| EnqueueUnitJobError::InvalidArgs(error.to_string()))?;
        let unit_path = self.get_explicit_unit(&name).map_err(|error| match error {
            UnitLookupError::NoSuchUnit(message) => EnqueueUnitJobError::NoSuchUnit(message),
            UnitLookupError::Failed(message) => EnqueueUnitJobError::Failed(message),
        })?;
        authorize_privileged_caller(connection, &header)
            .await
            .map_err(|error| EnqueueUnitJobError::AccessDenied(error.to_string()))?;
        let owner = header.sender().map(ToString::to_string);
        let job = self
            .enqueue(kind, &name, owner)
            .map_err(|error| EnqueueUnitJobError::Failed(error.to_string()))?;
        let job_path =
            job_path(job.id).map_err(|error| EnqueueUnitJobError::Failed(error.to_string()))?;
        Ok((
            job.id,
            job_path,
            name.clone(),
            unit_path,
            kind.as_str().to_owned(),
            Vec::new(),
        ))
    }

    /// `KillUnit(name, whom, signal)` sends a signal to the candidate's
    /// tracked service processes and/or its managed unit cgroup.
    async fn kill_unit(
        &self,
        name: String,
        whom: String,
        signal: i32,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<(), KillUnitMethodError> {
        self.validate_kill_unit(&name, &whom, signal)?;
        authorize_privileged_caller(connection, &header)
            .await
            .map_err(|error| KillUnitMethodError::AccessDenied(error.to_string()))?;
        self.kill_unit_for_request(&name, &whom, signal)
    }

    /// `KillUnitSubgroup(name, whom, subgroup, signal)` sends a signal to a
    /// unit cgroup subtree.  This is the Manager-level entry point used by
    /// v261; an empty `whom` selects the cgroup rather than all processes.
    async fn kill_unit_subgroup(
        &self,
        name: String,
        whom: String,
        subgroup: String,
        signal: i32,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<(), KillUnitMethodError> {
        self.validate_kill_unit_subgroup(&name, &whom, &subgroup, signal)?;
        authorize_privileged_caller(connection, &header)
            .await
            .map_err(|error| KillUnitMethodError::AccessDenied(error.to_string()))?;
        self.kill_unit_subgroup_for_request(&name, &whom, &subgroup, signal)
    }

    /// `QueueSignalUnit(name, whom, signal, value)` sends a queued signal
    /// carrying an integer payload to the selected unit processes.
    async fn queue_signal_unit(
        &self,
        name: String,
        whom: String,
        signal: i32,
        value: i32,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<(), KillUnitMethodError> {
        self.validate_queue_signal_unit(&name, &whom, signal)?;
        authorize_privileged_caller(connection, &header)
            .await
            .map_err(|error| KillUnitMethodError::AccessDenied(error.to_string()))?;
        self.queue_signal_unit_for_request(&name, &whom, signal, value)
    }

    /// `FreezeUnit(name)` freezes every process in an active unit cgroup.
    async fn freeze_unit(
        &self,
        name: String,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<(), FreezerMethodError> {
        authorize_privileged_caller(connection, &header)
            .await
            .map_err(|error| FreezerMethodError::AccessDenied(error.to_string()))?;
        self.apply_freezer_action(&name, true).await
    }

    /// `ThawUnit(name)` resumes every process in a frozen unit cgroup.
    async fn thaw_unit(
        &self,
        name: String,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<(), FreezerMethodError> {
        authorize_privileged_caller(connection, &header)
            .await
            .map_err(|error| FreezerMethodError::AccessDenied(error.to_string()))?;
        self.apply_freezer_action(&name, false).await
    }

    /// Attach caller-owned processes to an active delegated unit cgroup.
    ///
    /// This is the Manager v261 entry point backed by
    /// `unit_attach_pids_to_cgroup()`. The candidate uses the same service
    /// Delegate= state parsed by the unit loader and writes the requested
    /// PIDs to the kernel cgroup2 cgroup.procs file.
    #[zbus(name = "AttachProcessesToUnit")]
    #[allow(clippy::too_many_arguments)]
    async fn attach_processes_to_unit(
        &self,
        unit_name: String,
        subcgroup: String,
        pids: Vec<u32>,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<(), CgroupDelegationMethodError> {
        let unit = self
            .resolve_cgroup_unit(&unit_name, connection, &header, false)
            .await?;
        validate_cgroup_unit_load_state(&unit.name, &unit.load_state)?;

        if !subcgroup.is_empty() && !is_normalized_absolute_cgroup_path(&subcgroup) {
            let message = if subcgroup.starts_with('/') {
                format!("Control group path is not normalized: {subcgroup}")
            } else {
                format!("Control group path is not absolute: {subcgroup}")
            };
            return Err(CgroupDelegationMethodError::InvalidArgs(message));
        }
        if !self.cgroup_unit_is_delegated(&unit.name) {
            return Err(CgroupDelegationMethodError::InvalidArgs(
                "Process migration not available on non-delegated units.".to_owned(),
            ));
        }
        if matches!(unit.active_state.as_str(), "inactive" | "failed") {
            return Err(CgroupDelegationMethodError::InvalidArgs(
                "Unit is not active, refusing.".to_owned(),
            ));
        }

        let sender_uid = caller_uid(connection, &header)
            .await
            .map_err(|error| CgroupDelegationMethodError::AccessDenied(error.to_string()))?;
        let manager_uid = crate::native::current_uid();
        let validate_ownership = sender_uid != 0 && sender_uid != manager_uid;
        let target_uid = self.cgroup_unit_reference_uid(&unit.name, &unit);
        if validate_ownership && target_uid.is_none() {
            return Err(CgroupDelegationMethodError::AccessDenied(
                "Refusing to attach processes to unit with unknown user credentials.".to_owned(),
            ));
        }

        let caller_pid = if pids.contains(&0) {
            Some(
                caller_process_id(connection, &header)
                    .await
                    .map_err(CgroupDelegationMethodError::Failed)?,
            )
        } else {
            None
        };
        let mut seen = HashSet::with_capacity(pids.len());
        let mut validated = Vec::with_capacity(pids.len());
        for requested in pids {
            let pid = if requested == 0 {
                caller_pid.unwrap_or_default()
            } else {
                i32::try_from(requested).map_err(|_| {
                    CgroupDelegationMethodError::InvalidArgs(
                        "Process identifier is not valid.".to_owned(),
                    )
                })?
            };
            if !seen.insert(pid) {
                continue;
            }
            validate_attachable_pid(pid)?;

            if validate_ownership {
                let process_uid = process_effective_uid(pid).map_err(|error| {
                    CgroupDelegationMethodError::Failed(format!(
                        "Failed to check if process {pid} is owned by client's UID: {error}"
                    ))
                })?;
                if process_uid != sender_uid {
                    return Err(CgroupDelegationMethodError::AccessDenied(format!(
                        "Process {pid} not owned by client's UID. Refusing."
                    )));
                }
                if process_uid != target_uid.unwrap_or(u32::MAX) {
                    return Err(CgroupDelegationMethodError::AccessDenied(format!(
                        "Process {pid} not owned by target unit's UID. Refusing."
                    )));
                }
            }
            validated.push(pid);
        }

        self.cgroup
            .attach_pids_to_unit_subgroup(&unit.name, &subcgroup, &validated)
            .map_err(|error| {
                CgroupDelegationMethodError::Failed(format!(
                    "Failed to attach processes to control group: {error}"
                ))
            })
    }

    /// Remove a delegated unit cgroup subgroup.
    ///
    /// v261 currently defines no flags; a non-zero value is rejected before
    /// delegation, path, or caller-UID checks.
    #[zbus(name = "RemoveSubgroupFromUnit")]
    #[allow(clippy::too_many_arguments)]
    async fn remove_subgroup_from_unit(
        &self,
        unit_name: String,
        subcgroup: String,
        flags: u64,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<(), CgroupDelegationMethodError> {
        let unit = self
            .resolve_cgroup_unit(&unit_name, connection, &header, true)
            .await?;
        validate_cgroup_unit_load_state(&unit.name, &unit.load_state)?;
        if flags != 0 {
            return Err(CgroupDelegationMethodError::InvalidArgs(format!(
                "Invalid 'flags' parameter '{flags}'"
            )));
        }
        if !self.cgroup_unit_is_delegated(&unit.name) {
            return Err(CgroupDelegationMethodError::InvalidArgs(
                "Subcgroup removal not available on non-delegated units.".to_owned(),
            ));
        }
        if !is_normalized_absolute_cgroup_path(&subcgroup) {
            let message = if subcgroup.starts_with('/') {
                format!("Control group path is not normalized: {subcgroup}")
            } else {
                format!("Control group path is not absolute: {subcgroup}")
            };
            return Err(CgroupDelegationMethodError::InvalidArgs(message));
        }

        let sender_uid = caller_uid(connection, &header)
            .await
            .map_err(|error| CgroupDelegationMethodError::AccessDenied(error.to_string()))?;
        let manager_uid = crate::native::current_uid();
        let target_uid = self.cgroup_unit_reference_uid(&unit.name, &unit);
        if sender_uid != 0 && sender_uid != manager_uid && target_uid != Some(sender_uid) {
            return Err(CgroupDelegationMethodError::AccessDenied(
                "Client is not permitted to alter cgroup.".to_owned(),
            ));
        }

        self.cgroup
            .remove_unit_subgroup(&unit.name, &subcgroup)
            .map_err(|error| {
                CgroupDelegationMethodError::Failed(format!(
                    "Failed to remove subgroup {subcgroup}: {error}"
                ))
            })
    }

    /// `GetUnit(name)` → unit object path.
    #[zbus(out_args("unit"))]
    async fn get_unit(
        &self,
        name: String,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<(zbus::zvariant::OwnedObjectPath,), UnitLookupError> {
        if name.is_empty() {
            let pid = caller_process_id(connection, &header)
                .await
                .map_err(UnitLookupError::Failed)?;
            let unit = self
                .unit_name_for_pid(pid)
                .map_err(UnitLookupError::Failed)?
                .ok_or_else(|| {
                    UnitLookupError::NoSuchUnit(format!("Client {pid} not member of any unit."))
                })?;
            return unit_path(&unit)
                .map(|path| (path,))
                .map_err(|error| UnitLookupError::Failed(error.to_string()));
        }
        self.get_explicit_unit(&name).map(|path| (path,))
    }

    /// `LoadUnit(name)` → the canonical unit object path.
    ///
    /// Loading is deliberately routed through the manager event loop, just
    /// like `ListUnitsByNames`; a missing unit is still represented by its
    /// stable object path with the host's `not-found` state.
    #[zbus(out_args("unit"))]
    async fn load_unit(
        &self,
        name: String,
    ) -> Result<(zbus::zvariant::OwnedObjectPath,), LoadUnitError> {
        if !valid_unit_name(&name) {
            return Err(LoadUnitError::InvalidArgs(format!(
                "Unit name {name} is not valid."
            )));
        }
        self.request_unit_load(name.clone())
            .await
            .map_err(|error| LoadUnitError::Failed(error.to_string()))?;
        unit_path(&name)
            .map(|path| (path,))
            .map_err(|error| LoadUnitError::Failed(error.to_string()))
    }

    /// `ListUnits()` → array of unit info tuples.
    #[zbus(out_args("units"))]
    fn list_units(&self) -> (Vec<UnitListEntry>,) {
        (self.list_units_matching(&[], &[]),)
    }

    /// `ListUnitsFiltered(states)` → units matching any requested state.
    #[zbus(out_args("units"))]
    fn list_units_filtered(&self, states: Vec<String>) -> zbus::fdo::Result<(Vec<UnitListEntry>,)> {
        validate_unit_list_filters(&states, &[])?;
        Ok((self.list_units_matching(&states, &[]),))
    }

    /// `ListUnitsByPatterns(states, patterns)` → matching unit info tuples.
    #[zbus(out_args("units"))]
    fn list_units_by_patterns(
        &self,
        states: Vec<String>,
        patterns: Vec<String>,
    ) -> zbus::fdo::Result<(Vec<UnitListEntry>,)> {
        validate_unit_list_filters(&states, &patterns)?;
        Ok((self.list_units_matching(&states, &patterns),))
    }

    /// `ListUnitsByNames(names)` → requested unit info tuples in request order.
    #[zbus(out_args("units"))]
    async fn list_units_by_names(
        &self,
        names: Vec<String>,
    ) -> zbus::fdo::Result<(Vec<UnitListEntry>,)> {
        Ok((self.list_units_by_names_with_loader(names).await?,))
    }

    /// `ListUnitFiles()` → every visible system unit file and its enable state.
    #[zbus(out_args("unit_files"))]
    fn list_unit_files(&self) -> zbus::fdo::Result<(Vec<UnitFileListEntry>,)> {
        Ok((list_system_unit_files()?,))
    }

    /// `ListUnitFilesByPatterns(states, patterns)` → matching unit files.
    #[zbus(out_args("unit_files"))]
    fn list_unit_files_by_patterns(
        &self,
        states: Vec<String>,
        patterns: Vec<String>,
    ) -> zbus::fdo::Result<(Vec<UnitFileListEntry>,)> {
        validate_unit_list_filters(&states, &patterns)?;
        Ok((filter_unit_file_entries(
            list_system_unit_files()?,
            &states,
            &patterns,
        ),))
    }

    /// `GetUnitFileState(file)` → the unit-file enable state.
    #[zbus(out_args("state"))]
    fn get_unit_file_state(&self, file: String) -> Result<(String,), UnitFileMethodError> {
        query_root_enable_state_checked(&file, std::path::Path::new("/"))
            .map(|state| (state.to_string(),))
            .map_err(Into::into)
    }

    /// `GetDefaultTarget()` → the configured default target unit name.
    #[zbus(out_args("name"))]
    fn get_default_target(&self) -> Result<(String,), UnitFileMethodError> {
        query_system_default_target()
            .map(|target| (target,))
            .map_err(Into::into)
    }

    /// `SetDefaultTarget(name, force)` → install-change tuples.
    #[zbus(out_args("changes"))]
    async fn set_default_target(
        &self,
        name: String,
        force: bool,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<(Vec<(String, String, String)>,), SetDefaultTargetMethodError> {
        authorize_privileged_caller(connection, &header)
            .await
            .map_err(|error| SetDefaultTargetMethodError::AccessDenied(error.to_string()))?;
        let changes = match self.scope {
            ManagerScope::System => set_root_default_target(&name, force, Path::new("/")),
            ManagerScope::User => {
                let config_home = std::env::var_os("XDG_CONFIG_HOME").map_or_else(
                    || {
                        std::env::var_os("HOME")
                            .map_or_else(|| PathBuf::from("."), PathBuf::from)
                            .join(".config")
                    },
                    PathBuf::from,
                );
                set_user_default_target(
                    &name,
                    force,
                    &UnitLoader::user().search_dirs,
                    &config_home.join("systemd/user"),
                )
            }
        };
        changes.map(|changes| (changes,)).map_err(Into::into)
    }

    /// `AddDependencyUnitFiles(files, target, type, runtime, force)` creates
    /// real `.wants/` or `.requires/` links below the manager's control tree.
    #[zbus(out_args("changes"))]
    // Five owned D-Bus inputs plus zbus's header and connection arguments are
    // required by the v261 method signature; keep this arity explicit.
    #[allow(clippy::too_many_arguments)]
    async fn add_dependency_unit_files(
        &self,
        files: Vec<String>,
        target: String,
        r#type: String,
        runtime: bool,
        force: bool,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<(Vec<(String, String, String)>,), AddDependencyUnitFilesError> {
        authorize_privileged_caller(connection, &header)
            .await
            .map_err(|error| AddDependencyUnitFilesError::AccessDenied(error.to_string()))?;
        let requires = match r#type.as_str() {
            "Wants" => false,
            "Requires" => true,
            _ => {
                return Err(AddDependencyUnitFilesError::InvalidArgs(
                    "Invalid argument".to_owned(),
                ));
            }
        };
        let config_dir = manager_unit_file_control_dir(self.scope, runtime);
        let search_dirs = manager_unit_file_search_dirs(self.scope);
        // Resolve the target before touching any dependency file. v261
        // reports malformed targets as BadUnitSetting and missing targets as
        // NoSuchUnit, while malformed file names use InvalidArgs.
        add_dependency_unit_files_to_disk(&[], &target, requires, force, &config_dir, &search_dirs)
            .map_err(|error| AddDependencyUnitFilesError::from_lookup(error, false))?;
        add_dependency_unit_files_to_disk(
            &files,
            &target,
            requires,
            force,
            &config_dir,
            &search_dirs,
        )
        .map(|changes| (changes,))
        .map_err(|error| AddDependencyUnitFilesError::from_lookup(error, true))
    }

    /// `MaskUnitFiles(files, runtime, force)` → install-change tuples.
    #[zbus(out_args("changes"))]
    async fn mask_unit_files(
        &self,
        files: Vec<String>,
        runtime: bool,
        force: bool,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<(Vec<(String, String, String)>,), UnitFileMutationError> {
        authorize_privileged_caller(connection, &header)
            .await
            .map_err(|error| UnitFileMutationError::AccessDenied(error.to_string()))?;
        let config_dir = manager_unit_file_control_dir(self.scope, runtime);
        mask_unit_files(&files, force, &config_dir)
            .map(|changes| (changes,))
            .map_err(Into::into)
    }

    /// `UnmaskUnitFiles(files, runtime)` → install-change tuples.
    #[zbus(out_args("changes"))]
    async fn unmask_unit_files(
        &self,
        files: Vec<String>,
        runtime: bool,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<(Vec<(String, String, String)>,), UnitFileMutationError> {
        authorize_privileged_caller(connection, &header)
            .await
            .map_err(|error| UnitFileMutationError::AccessDenied(error.to_string()))?;
        let config_dir = manager_unit_file_control_dir(self.scope, runtime);
        unmask_unit_files(&files, &config_dir)
            .map(|changes| (changes,))
            .map_err(Into::into)
    }

    /// `EnableUnitFiles(files, runtime, force)` → install information and changes.
    #[zbus(out_args("carries_install_info", "changes"))]
    async fn enable_unit_files(
        &self,
        files: Vec<String>,
        runtime: bool,
        force: bool,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<(bool, Vec<(String, String, String)>), UnitFileEnableError> {
        authorize_privileged_caller(connection, &header)
            .await
            .map_err(|error| UnitFileEnableError::AccessDenied(error.to_string()))?;
        let config_dir = manager_unit_file_control_dir(self.scope, runtime);
        let search_dirs = manager_unit_file_search_dirs(self.scope);
        enable_unit_files(&files, force, &config_dir, &search_dirs).map_err(Into::into)
    }

    /// `EnableUnitFilesWithFlags(files, flags)` → install information and changes.
    #[zbus(out_args("carries_install_info", "changes"))]
    async fn enable_unit_files_with_flags(
        &self,
        files: Vec<String>,
        flags: u64,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<(bool, Vec<(String, String, String)>), UnitFileEnableError> {
        if flags & !UNIT_FILE_FLAGS_PUBLIC != 0 {
            return Err(UnitFileEnableError::InvalidArgs(format!(
                "Invalid flags {flags}"
            )));
        }
        authorize_privileged_caller(connection, &header)
            .await
            .map_err(|error| UnitFileEnableError::AccessDenied(error.to_string()))?;
        let runtime = flags & UNIT_FILE_FLAG_RUNTIME != 0;
        let force = flags & UNIT_FILE_FLAG_FORCE != 0;
        let config_dir = manager_unit_file_control_dir(self.scope, runtime);
        let search_dirs = manager_unit_file_search_dirs(self.scope);
        enable_unit_files(&files, force, &config_dir, &search_dirs).map_err(Into::into)
    }

    /// `ReenableUnitFiles(files, runtime, force)` → refreshed install links.
    #[zbus(out_args("carries_install_info", "changes"))]
    async fn reenable_unit_files(
        &self,
        files: Vec<String>,
        runtime: bool,
        force: bool,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<(bool, Vec<(String, String, String)>), UnitFileEnableError> {
        authorize_privileged_caller(connection, &header)
            .await
            .map_err(|error| UnitFileEnableError::AccessDenied(error.to_string()))?;
        let config_dir = manager_unit_file_control_dir(self.scope, runtime);
        let search_dirs = manager_unit_file_search_dirs(self.scope);
        let mut changes = disable_unit_files(&files, &config_dir, &search_dirs)
            .map_err(UnitFileEnableError::from)?;
        let (carries_install_info, mut enable_changes) =
            enable_unit_files(&files, force, &config_dir, &search_dirs)
                .map_err(UnitFileEnableError::from)?;
        changes.append(&mut enable_changes);
        Ok((carries_install_info, changes))
    }

    /// `LinkUnitFiles(files, runtime, force)` → direct link changes.
    #[zbus(out_args("changes"))]
    async fn link_unit_files(
        &self,
        files: Vec<String>,
        runtime: bool,
        force: bool,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<(Vec<(String, String, String)>,), UnitFileEnableError> {
        authorize_privileged_caller(connection, &header)
            .await
            .map_err(|error| UnitFileEnableError::AccessDenied(error.to_string()))?;
        let config_dir = manager_unit_file_control_dir(self.scope, runtime);
        let search_dirs = manager_unit_file_search_dirs(self.scope);
        link_unit_files(&files, force, &config_dir, &search_dirs)
            .map(|changes| (changes,))
            .map_err(Into::into)
    }

    /// `PresetUnitFiles(files, runtime, force)` applies the v261 preset rules.
    #[zbus(out_args("carries_install_info", "changes"))]
    async fn preset_unit_files(
        &self,
        files: Vec<String>,
        runtime: bool,
        force: bool,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<(bool, Vec<(String, String, String)>), UnitFileEnableError> {
        authorize_privileged_caller(connection, &header)
            .await
            .map_err(|error| UnitFileEnableError::AccessDenied(error.to_string()))?;
        let config_dir = manager_unit_file_control_dir(self.scope, runtime);
        let search_dirs = manager_unit_file_search_dirs(self.scope);
        let preset_dirs = manager_unit_file_preset_dirs(self.scope);
        preset_unit_files_to_disk(
            &files,
            PresetMode::Full,
            force,
            &config_dir,
            &search_dirs,
            &preset_dirs,
        )
        .map_err(Into::into)
    }

    /// `PresetUnitFilesWithMode(files, mode, runtime, force)` applies a
    /// selected v261 preset mode. An empty mode means `full`.
    #[zbus(out_args("carries_install_info", "changes"))]
    async fn preset_unit_files_with_mode(
        &self,
        files: Vec<String>,
        mode: String,
        runtime: bool,
        force: bool,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<(bool, Vec<(String, String, String)>), UnitFileEnableError> {
        let mode = PresetMode::parse(&mode)
            .ok_or_else(|| UnitFileEnableError::InvalidArgs("Invalid argument".to_owned()))?;
        authorize_privileged_caller(connection, &header)
            .await
            .map_err(|error| UnitFileEnableError::AccessDenied(error.to_string()))?;
        let config_dir = manager_unit_file_control_dir(self.scope, runtime);
        let search_dirs = manager_unit_file_search_dirs(self.scope);
        let preset_dirs = manager_unit_file_preset_dirs(self.scope);
        preset_unit_files_to_disk(&files, mode, force, &config_dir, &search_dirs, &preset_dirs)
            .map_err(Into::into)
    }

    /// `PresetAllUnitFiles(mode, runtime, force)` applies presets to every
    /// visible unit file in this manager's lookup path.
    #[zbus(out_args("changes"))]
    async fn preset_all_unit_files(
        &self,
        mode: String,
        runtime: bool,
        force: bool,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<(Vec<(String, String, String)>,), UnitFileMutationError> {
        let mode = PresetMode::parse(&mode)
            .ok_or_else(|| UnitFileMutationError::InvalidArgs("Invalid argument".to_owned()))?;
        authorize_privileged_caller(connection, &header)
            .await
            .map_err(|error| UnitFileMutationError::AccessDenied(error.to_string()))?;
        let config_dir = manager_unit_file_control_dir(self.scope, runtime);
        let search_dirs = manager_unit_file_search_dirs(self.scope);
        let preset_dirs = manager_unit_file_preset_dirs(self.scope);
        preset_all_unit_files_to_disk(mode, force, &config_dir, &search_dirs, &preset_dirs)
            .map(|changes| (changes,))
            .map_err(Into::into)
    }

    /// `DisableUnitFiles(files, runtime)` → install-change tuples.
    #[zbus(out_args("changes"))]
    async fn disable_unit_files(
        &self,
        files: Vec<String>,
        runtime: bool,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<(Vec<(String, String, String)>,), UnitFileDisableError> {
        authorize_privileged_caller(connection, &header)
            .await
            .map_err(|error| UnitFileDisableError::AccessDenied(error.to_string()))?;
        let config_dir = manager_unit_file_control_dir(self.scope, runtime);
        let search_dirs = manager_unit_file_search_dirs(self.scope);
        disable_unit_files(&files, &config_dir, &search_dirs)
            .map(|changes| (changes,))
            .map_err(Into::into)
    }

    /// `DisableUnitFilesWithFlags(files, flags)` → install changes.
    #[zbus(out_args("changes"))]
    async fn disable_unit_files_with_flags(
        &self,
        files: Vec<String>,
        flags: u64,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<(Vec<(String, String, String)>,), UnitFileDisableError> {
        if flags & !UNIT_FILE_FLAGS_PUBLIC != 0 || flags & UNIT_FILE_FLAG_FORCE != 0 {
            return Err(UnitFileDisableError::InvalidArgs(format!(
                "Invalid flags {flags}"
            )));
        }
        authorize_privileged_caller(connection, &header)
            .await
            .map_err(|error| UnitFileDisableError::AccessDenied(error.to_string()))?;
        let runtime = flags & UNIT_FILE_FLAG_RUNTIME != 0;
        let config_dir = manager_unit_file_control_dir(self.scope, runtime);
        let search_dirs = manager_unit_file_search_dirs(self.scope);
        disable_unit_files(&files, &config_dir, &search_dirs)
            .map(|changes| (changes,))
            .map_err(Into::into)
    }

    /// `DisableUnitFilesWithFlagsAndInstallInfo(files, flags)` → install info and changes.
    #[zbus(out_args("carries_install_info", "changes"))]
    async fn disable_unit_files_with_flags_and_install_info(
        &self,
        files: Vec<String>,
        flags: u64,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<(bool, Vec<(String, String, String)>), UnitFileEnableError> {
        if flags & !UNIT_FILE_FLAGS_PUBLIC != 0 || flags & UNIT_FILE_FLAG_FORCE != 0 {
            return Err(UnitFileEnableError::InvalidArgs(format!(
                "Invalid flags {flags}"
            )));
        }
        authorize_privileged_caller(connection, &header)
            .await
            .map_err(|error| UnitFileEnableError::AccessDenied(error.to_string()))?;
        let runtime = flags & UNIT_FILE_FLAG_RUNTIME != 0;
        let config_dir = manager_unit_file_control_dir(self.scope, runtime);
        let search_dirs = manager_unit_file_search_dirs(self.scope);
        let carries_install_info = unit_files_carry_install_info(&files, &search_dirs)
            .map_err(UnitFileEnableError::from)?;
        let changes = disable_unit_files(&files, &config_dir, &search_dirs)
            .map_err(UnitFileEnableError::from)?;
        Ok((carries_install_info, changes))
    }

    /// `RevertUnitFiles(files)` → removed overrides and drop-ins.
    #[zbus(out_args("changes"))]
    async fn revert_unit_files(
        &self,
        files: Vec<String>,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<(Vec<(String, String, String)>,), UnitFileMutationError> {
        authorize_privileged_caller(connection, &header)
            .await
            .map_err(|error| UnitFileMutationError::AccessDenied(error.to_string()))?;
        let persistent = manager_unit_file_control_dir(self.scope, false);
        let runtime = manager_unit_file_control_dir(self.scope, true);
        let search_dirs = manager_unit_file_search_dirs(self.scope);
        revert_unit_files(&files, &persistent, &runtime, &search_dirs, Path::new("/"))
            .map(|changes| (changes,))
            .map_err(Into::into)
    }

    /// `GetUnitFileLinks(name, runtime)` → links removed by a dry-run disable.
    #[zbus(out_args("links"))]
    fn get_unit_file_links(
        &self,
        name: String,
        runtime: bool,
    ) -> Result<(Vec<String>,), UnitFileLinksMethodError> {
        let search_dirs = manager_unit_file_search_dirs(self.scope);
        let config_dir = manager_unit_file_control_dir(self.scope, runtime);
        get_unit_file_links(&name, &config_dir, &search_dirs, Path::new("/"))
            .map(|links| {
                (links
                    .into_iter()
                    .map(|path| path.display().to_string())
                    .collect(),)
            })
            .map_err(Into::into)
    }

    /// `Reload()` — trigger daemon-reload.
    async fn reload(
        &self,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<()> {
        authorize_privileged_caller(connection, &header).await?;
        self.request_reload()
    }

    /// `Reexecute()` — restart the manager image in-place.
    async fn reexecute(
        &self,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<()> {
        authorize_privileged_caller(connection, &header).await?;
        self.request_reexecute()
    }

    /// `ResetFailedUnit(name)` — clear failure state for one unit.
    fn reset_failed_unit(&self, name: String) -> zbus::fdo::Result<()> {
        self.request_reset_failed(vec![name])
    }

    /// `ResetFailed()` — clear failure state for every loaded unit.
    fn reset_failed(&self) -> zbus::fdo::Result<()> {
        self.request_reset_failed(Vec::new())
    }

    /// `GetUnitByPID(pid)` → unit object path.
    #[zbus(name = "GetUnitByPID", out_args("unit"))]
    #[allow(clippy::cast_possible_wrap)]
    async fn get_unit_by_pid(
        &self,
        pid: u32,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<(zbus::zvariant::OwnedObjectPath,), PidLookupError> {
        let caller_pid = if pid == 0 {
            Some(
                caller_process_id(connection, &header)
                    .await
                    .map_err(PidLookupError::Failed)?,
            )
        } else {
            None
        };
        let pid = pid_for_unit_lookup(pid, caller_pid);
        self.get_unit_by_pid_for_pid(pid)
    }

    /// `GetUnitByPIDFD(pidfd)` → the owning unit, its ID, and invocation ID.
    #[zbus(name = "GetUnitByPIDFD", out_args("unit", "unit_id", "invocation_id"))]
    fn get_unit_by_pidfd(
        &self,
        pidfd: zbus::zvariant::OwnedFd,
    ) -> Result<(zbus::zvariant::OwnedObjectPath, String, Vec<u8>), PidFdLookupError> {
        let pid = pid_from_pidfd(pidfd.as_raw_fd()).map_err(pidfd_lookup_failed)?;
        let unit = self
            .snapshot
            .read()
            .map_err(|_| {
                PidFdLookupError::Failed("internal: unit snapshot lock poisoned".to_owned())
            })?
            .iter()
            .find_map(|unit| {
                (unit.main_pid == Some(pid)
                    || unit_cgroup_contains_pid(&self.cgroup, &unit.name, pid))
                .then(|| unit.clone())
            })
            .ok_or_else(|| {
                PidFdLookupError::NoUnitForPid(format!(
                    "PID {pid} does not belong to any loaded unit."
                ))
            })?;

        match pid_from_pidfd(pidfd.as_raw_fd()) {
            Ok(current_pid) if current_pid == pid => {}
            Ok(_) => {
                return Err(PidFdLookupError::NoSuchProcess(format!(
                    "The PIDFD's PID {pid} changed during the lookup operation."
                )));
            }
            Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {
                return Err(PidFdLookupError::NoSuchProcess(format!(
                    "The PIDFD's PID {pid} changed during the lookup operation."
                )));
            }
            Err(error) => return Err(pidfd_lookup_failed(error)),
        }

        /* v261 keeps the PIDFD lookup result on the stable, name-derived unit
         * object path.  Unlike GetUnitByInvocationID(), this method does not
         * select the invocation-ID alias. */
        let path =
            unit_path(&unit.name).map_err(|error| PidFdLookupError::Failed(error.to_string()))?;
        Ok((
            path,
            unit.name,
            unit.service_runtime
                .invocation_id
                .unwrap_or([0; 16])
                .to_vec(),
        ))
    }

    /// `GetUnitByInvocationID(invocation_id)` → current unit object path.
    #[zbus(name = "GetUnitByInvocationID", out_args("unit"))]
    async fn get_unit_by_invocation_id(
        &self,
        invocation_id: Vec<u8>,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<(zbus::zvariant::OwnedObjectPath,), InvocationIdLookupError> {
        let invocation_id: [u8; 16] = invocation_id.try_into().map_err(|_| {
            InvocationIdLookupError::InvalidArgs("Invalid invocation ID".to_owned())
        })?;
        if invocation_id == [0; 16] {
            let pid = caller_process_id(connection, &header)
                .await
                .map_err(InvocationIdLookupError::Failed)?;
            return self.get_unit_by_invocation_id_for_pid(pid);
        }
        self.get_unit_by_invocation_id_for_id(invocation_id)
    }

    /// `GetUnitProcesses(name)` → processes in the unit's cgroup subtree.
    ///
    /// This is deliberately derived from the candidate manager's live
    /// cgroup-v2 hierarchy rather than the unit's cached main PID. A unit may
    /// own helper processes and nested cgroups in addition to its main
    /// process, and the standard Manager method reports all of them.
    #[zbus(out_args("processes"))]
    fn get_unit_processes(
        &self,
        name: String,
    ) -> Result<(Vec<UnitProcessEntry>,), CgroupLookupError> {
        let snapshot = self.snapshot.read().map_err(|_| {
            CgroupLookupError::Failed("internal: unit snapshot lock poisoned".to_owned())
        })?;
        // Do not trigger a unit-file load for this inspection query. A unit
        // that failed during loading can nevertheless retain a live cgroup,
        // which the host still reports here.
        if !snapshot.iter().any(|unit| unit.name == name) && !self.cgroup.has_unit_cgroup(&name) {
            return Err(CgroupLookupError::NoSuchUnit(format!(
                "Unit {name} not loaded."
            )));
        }
        drop(snapshot);

        let cgroup_procs = self.cgroup.unit_procs_path(&name);
        let Some(cgroup_root) = cgroup_procs.parent() else {
            return Ok((Vec::new(),));
        };
        let dbus_cgroup_root = self.cgroup.unit_cgroup_path_for_dbus(&name);

        Ok((collect_unit_processes(cgroup_root, &dbus_cgroup_root),))
    }

    /// `LookupDynamicUserByName(name)` → dynamic UID.
    #[zbus(out_args("uid"))]
    fn lookup_dynamic_user_by_name(&self, name: String) -> Result<(u32,), DynamicUserMethodError> {
        self.ensure_dynamic_user_scope()?;
        if !is_valid_dynamic_user_name(&name) {
            return Err(DynamicUserMethodError::InvalidArgs(format!(
                "User name invalid: {name}"
            )));
        }
        let uid = self
            .dynamic_user_entries()?
            .into_iter()
            .find_map(|(uid, candidate)| (candidate == name).then_some(uid))
            .ok_or_else(|| {
                DynamicUserMethodError::NoSuchDynamicUser(format!(
                    "Dynamic user {name} does not exist."
                ))
            })?;
        Ok((uid,))
    }

    /// `LookupDynamicUserByUID(uid)` → dynamic account name.
    #[zbus(name = "LookupDynamicUserByUID", out_args("name"))]
    fn lookup_dynamic_user_by_uid(&self, uid: u32) -> Result<(String,), DynamicUserMethodError> {
        self.ensure_dynamic_user_scope()?;
        if uid == u32::MAX {
            return Err(DynamicUserMethodError::InvalidArgs(format!(
                "User ID invalid: {uid}"
            )));
        }
        let name = self
            .dynamic_user_entries()?
            .into_iter()
            .find_map(|(candidate, name)| (candidate == uid).then_some(name))
            .ok_or_else(|| {
                DynamicUserMethodError::NoSuchDynamicUser(format!(
                    "Dynamic user ID {uid} does not exist."
                ))
            })?;
        Ok((name,))
    }

    /// `GetDynamicUsers()` → every live dynamic user allocation.
    #[zbus(out_args("users"))]
    fn get_dynamic_users(&self) -> Result<(Vec<DynamicUserEntry>,), DynamicUserMethodError> {
        Ok((self.dynamic_user_entries()?,))
    }

    /// `DumpUnitFileDescriptorStore(name)` → metadata for every descriptor
    /// currently retained by a configured service's live store.
    #[zbus(out_args("entries"))]
    fn dump_unit_file_descriptor_store(
        &self,
        name: String,
    ) -> Result<(Vec<FileDescriptorStoreEntry>,), FileDescriptorStoreMethodError> {
        let snapshot = self.snapshot.read().map_err(|_| {
            FileDescriptorStoreMethodError::Failed(
                "internal: unit snapshot lock poisoned".to_owned(),
            )
        })?;
        let unit = snapshot
            .iter()
            .find(|unit| unit.name == name)
            .ok_or_else(|| {
                FileDescriptorStoreMethodError::NoSuchUnit(format!("Unit {name} not loaded."))
            })?;
        if unit.unit_type != "service" {
            return Err(FileDescriptorStoreMethodError::NotSupported(format!(
                "DumpUnitFileDescriptorStore operation is not supported for unit type '{}'",
                unit.unit_type
            )));
        }
        if unit.service_runtime.file_descriptor_store_max == 0 {
            return Err(FileDescriptorStoreMethodError::Disabled(format!(
                "File descriptor store not enabled for {name}."
            )));
        }

        // The candidate has no FDSTORE protocol producer yet. Consequently a
        // configured service has a genuine, currently empty descriptor store.
        Ok((Vec::new(),))
    }

    /// `Dump()` → a textual snapshot of the candidate manager's live state.
    #[zbus(out_args("output"))]
    fn dump(&self) -> Result<(String,), DumpMethodError> {
        Ok((self.dump_output(None)?,))
    }

    /// `DumpUnitsMatchingPatterns(patterns)` → matching unit diagnostics.
    #[zbus(out_args("output"))]
    fn dump_units_matching_patterns(
        &self,
        patterns: Vec<String>,
    ) -> Result<(String,), DumpMethodError> {
        Ok((self.dump_output(Some(&patterns))?,))
    }

    /// `DumpByFileDescriptor()` → a sealed memfd containing `Dump()` output.
    #[zbus(out_args("fd"))]
    fn dump_by_file_descriptor(&self) -> Result<(zbus::zvariant::OwnedFd,), DumpMethodError> {
        let output = self.dump_output(None)?;
        dump_to_memfd(&output)
            .map(|fd| (fd,))
            .map_err(DumpMethodError::Failed)
    }

    /// `DumpUnitsMatchingPatternsByFileDescriptor(patterns)` → a sealed
    /// memfd containing matching unit diagnostics.
    #[zbus(out_args("fd"))]
    fn dump_units_matching_patterns_by_file_descriptor(
        &self,
        patterns: Vec<String>,
    ) -> Result<(zbus::zvariant::OwnedFd,), DumpMethodError> {
        let output = self.dump_output(Some(&patterns))?;
        dump_to_memfd(&output)
            .map(|fd| (fd,))
            .map_err(DumpMethodError::Failed)
    }

    /// `GetUnitByControlGroup(cgroup)` → the closest owning unit object path.
    #[zbus(out_args("unit"))]
    fn get_unit_by_control_group(
        &self,
        cgroup: String,
    ) -> Result<(zbus::zvariant::OwnedObjectPath,), CgroupLookupError> {
        if !is_normalized_absolute_cgroup_path(&cgroup) {
            let message = if cgroup.starts_with('/') {
                format!("Control group path is not normalized: {cgroup}")
            } else {
                format!("Control group path is not absolute: {cgroup}")
            };
            return Err(CgroupLookupError::InvalidArgs(message));
        }

        let snapshot = self.snapshot.read().map_err(|_| {
            CgroupLookupError::Failed("internal: unit snapshot lock poisoned".to_owned())
        })?;
        let unit = snapshot
            .iter()
            .filter(|unit| self.cgroup.has_unit_cgroup(&unit.name))
            .filter(|unit| {
                cgroup_is_within(
                    &self
                        .cgroup
                        .unit_cgroup_path_for_dbus(&unit.name)
                        .display()
                        .to_string(),
                    &cgroup,
                )
            })
            .max_by_key(|unit| {
                self.cgroup
                    .unit_cgroup_path_for_dbus(&unit.name)
                    .as_os_str()
                    .len()
            })
            .ok_or_else(|| {
                CgroupLookupError::NoSuchUnit(format!(
                    "Control group '{cgroup}' is not valid or not managed by this instance"
                ))
            })?;

        Ok(
            (unit_path(&unit.name)
                .map_err(|error| CgroupLookupError::Failed(error.to_string()))?,),
        )
    }

    /// `GetJob(id)` → canonical numeric job object path.
    #[zbus(out_args("job"))]
    fn get_job(&self, id: u32) -> Result<(zbus::zvariant::OwnedObjectPath,), JobMethodError> {
        if self.jobs.get(id).is_none() {
            return Err(no_such_job(id));
        }
        Ok((job_path(id).expect("numeric job identifiers always form valid D-Bus object paths"),))
    }

    /// `GetJobAfter(id)` → jobs whose execution is ordered after this job.
    #[zbus(out_args("jobs"))]
    fn get_job_after(&self, id: u32) -> Result<(Vec<JobListEntry>,), JobMethodError> {
        ensure_live_job(&self.jobs, id)?;
        Ok((self
            .jobs
            .get_after(id)
            .iter()
            .filter_map(job_list_entry)
            .collect(),))
    }

    /// `GetJobBefore(id)` → jobs that must execute before this job.
    #[zbus(out_args("jobs"))]
    fn get_job_before(&self, id: u32) -> Result<(Vec<JobListEntry>,), JobMethodError> {
        ensure_live_job(&self.jobs, id)?;
        Ok((self
            .jobs
            .get_before(id)
            .iter()
            .filter_map(job_list_entry)
            .collect(),))
    }

    /// `CancelJob(id)` — cancel a live job owned by this caller or an
    /// authorized manager caller.
    async fn cancel_job(
        &self,
        id: u32,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<(), JobMethodError> {
        ensure_live_job(&self.jobs, id)?;
        let sender = header.sender().map(ToString::to_string);
        let owner = sender
            .as_deref()
            .is_some_and(|sender| self.jobs.is_owner(id, sender));
        if !owner {
            authorize_privileged_caller(connection, &header)
                .await
                .map_err(job_method_authorization_error)?;
        }
        self.cancel_live_job(id)
    }

    /// `ClearJobs()` — cancel every live job after manager authorization.
    async fn clear_jobs(
        &self,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<(), JobMethodError> {
        authorize_privileged_caller(connection, &header)
            .await
            .map_err(job_method_authorization_error)?;
        self.clear_live_jobs()
    }

    /// `ListJobs()` → all live jobs in numeric identifier order.
    #[zbus(out_args("jobs"))]
    fn list_jobs(&self) -> (Vec<JobListEntry>,) {
        (self.jobs.list().iter().filter_map(job_list_entry).collect(),)
    }

    /// `Subscribe()` — register the caller for change signals.
    fn subscribe(&self, #[zbus(header)] hdr: zbus::MessageHeader<'_>) -> zbus::fdo::Result<()> {
        let sender = hdr.sender().map(ToString::to_string).unwrap_or_default();
        if !sender.is_empty() {
            if let Ok(mut set) = self.subscribers.lock() {
                set.insert(sender);
            }
        }
        Ok(())
    }

    /// `Unsubscribe()` — deregister the caller from change signals.
    fn unsubscribe(&self, #[zbus(header)] hdr: zbus::MessageHeader<'_>) -> zbus::fdo::Result<()> {
        let sender = hdr.sender().map(ToString::to_string).unwrap_or_default();
        if !sender.is_empty() {
            if let Ok(mut set) = self.subscribers.lock() {
                set.remove(&sender);
            }
        }
        Ok(())
    }

    // ── signals ───────────────────────────────────────────────────────

    /// `UnitNew(id, unit)` — emitted when a unit enters the registry.
    #[zbus(signal)]
    pub async fn unit_new(
        ctxt: &zbus::SignalContext<'_>,
        id: &str,
        unit: zbus::zvariant::ObjectPath<'_>,
    ) -> zbus::Result<()>;

    /// `UnitRemoved(id, unit)` — emitted when a unit leaves the registry.
    #[zbus(signal)]
    pub async fn unit_removed(
        ctxt: &zbus::SignalContext<'_>,
        id: &str,
        unit: zbus::zvariant::ObjectPath<'_>,
    ) -> zbus::Result<()>;

    /// `JobNew(id, job, unit)` — emitted when a job is queued.
    #[zbus(signal)]
    pub async fn job_new(
        ctxt: &zbus::SignalContext<'_>,
        id: u32,
        job: zbus::zvariant::ObjectPath<'_>,
        unit: &str,
    ) -> zbus::Result<()>;

    /// `JobRemoved(id, job, unit, result)` — emitted when a job completes.
    #[zbus(signal)]
    pub async fn job_removed(
        ctxt: &zbus::SignalContext<'_>,
        id: u32,
        job: zbus::zvariant::ObjectPath<'_>,
        unit: &str,
        result: &str,
    ) -> zbus::Result<()>;

    /// `Reloading(active)` — daemon-reload state transition.
    #[zbus(signal)]
    pub async fn reloading(ctxt: &zbus::SignalContext<'_>, active: bool) -> zbus::Result<()>;

    /// `UnitFilesChanged()` — unit-file metadata changed.
    #[zbus(signal)]
    pub async fn unit_files_changed(ctxt: &zbus::SignalContext<'_>) -> zbus::Result<()>;

    /// `StartupFinished(firmware, loader, kernel, initrd, userspace, total)`
    /// — initial manager startup completed.
    #[zbus(signal)]
    pub async fn startup_finished(
        ctxt: &zbus::SignalContext<'_>,
        firmware: u64,
        loader: u64,
        kernel: u64,
        initrd: u64,
        userspace: u64,
        total: u64,
    ) -> zbus::Result<()>;
}

fn manager_unit_file_control_dir(scope: ManagerScope, runtime: bool) -> PathBuf {
    match scope {
        ManagerScope::System => PathBuf::from(if runtime {
            "/run/systemd/system"
        } else {
            "/etc/systemd/system"
        }),
        ManagerScope::User => {
            if runtime {
                std::env::var_os("XDG_RUNTIME_DIR")
                    .map_or_else(|| PathBuf::from("."), PathBuf::from)
                    .join("systemd/user")
            } else {
                std::env::var_os("XDG_CONFIG_HOME")
                    .map_or_else(
                        || {
                            std::env::var_os("HOME")
                                .map_or_else(|| PathBuf::from("."), PathBuf::from)
                                .join(".config")
                        },
                        PathBuf::from,
                    )
                    .join("systemd/user")
            }
        }
    }
}

fn manager_unit_file_search_dirs(scope: ManagerScope) -> Vec<PathBuf> {
    match scope {
        ManagerScope::System => rooted_unit_search_dirs(Path::new("/")),
        ManagerScope::User => UnitLoader::user().search_dirs,
    }
}

fn manager_unit_file_preset_dirs(scope: ManagerScope) -> Vec<PathBuf> {
    let suffix = match scope {
        ManagerScope::System => "systemd/system-preset",
        ManagerScope::User => "systemd/user-preset",
    };
    ["/etc", "/run", "/usr/local/lib", "/usr/lib"]
        .into_iter()
        .map(|prefix| PathBuf::from(prefix).join(suffix))
        .collect()
}

impl ManagerInterface {
    #[allow(clippy::cast_possible_wrap)]
    fn get_unit_by_pid_for_pid(
        &self,
        pid: i32,
    ) -> Result<(zbus::zvariant::OwnedObjectPath,), PidLookupError> {
        if pid < 0 {
            return Err(PidLookupError::InvalidArgs(format!("Invalid PID {pid}")));
        }
        let unit = self
            .unit_name_for_pid(pid)
            .map_err(PidLookupError::Failed)?
            .ok_or_else(|| {
                PidLookupError::NoUnitForPid(format!(
                    "PID {pid} does not belong to any loaded unit."
                ))
            })?;
        unit_path(&unit)
            .map(|path| (path,))
            .map_err(|error| PidLookupError::Failed(error.to_string()))
    }

    fn get_unit_by_invocation_id_for_id(
        &self,
        invocation_id: [u8; 16],
    ) -> Result<(zbus::zvariant::OwnedObjectPath,), InvocationIdLookupError> {
        let known = self
            .snapshot
            .read()
            .map_err(|_| {
                InvocationIdLookupError::Failed("internal: unit snapshot lock poisoned".to_owned())
            })?
            .iter()
            .any(|unit| unit.service_runtime.invocation_id == Some(invocation_id));
        if !known {
            return Err(InvocationIdLookupError::NoUnitForInvocationId(format!(
                "No unit with the specified invocation ID {} known.",
                format_id128(&invocation_id)
            )));
        }
        invocation_id_path(&invocation_id)
            .map(|path| (path,))
            .map_err(|error| InvocationIdLookupError::Failed(error.to_string()))
    }

    fn get_unit_by_invocation_id_for_pid(
        &self,
        pid: i32,
    ) -> Result<(zbus::zvariant::OwnedObjectPath,), InvocationIdLookupError> {
        let snapshot = self.snapshot.read().map_err(|_| {
            InvocationIdLookupError::Failed("internal: unit snapshot lock poisoned".to_owned())
        })?;
        let unit = snapshot
            .iter()
            .find(|unit| {
                unit.main_pid == Some(pid)
                    || unit_cgroup_contains_pid(&self.cgroup, &unit.name, pid)
            })
            .ok_or_else(|| {
                InvocationIdLookupError::NoSuchUnit(
                    "Client PID does not belong to any unit.".to_owned(),
                )
            })?;
        let invocation_id = unit.service_runtime.invocation_id.ok_or_else(|| {
            InvocationIdLookupError::NoSuchUnit(
                "Client PID does not belong to any unit.".to_owned(),
            )
        })?;
        invocation_id_path(&invocation_id)
            .map(|path| (path,))
            .map_err(|error| InvocationIdLookupError::Failed(error.to_string()))
    }

    fn set_exit_code_value(&self, number: u8) {
        self.exit_code.store(number, Ordering::Release);
    }

    fn request_exit(&self) -> zbus::fdo::Result<()> {
        self.exit_requested.store(true, Ordering::Release);
        self.wake
            .wake()
            .map_err(|error| zbus::fdo::Error::Failed(error.to_string()))
    }

    fn request_reexecute(&self) -> zbus::fdo::Result<()> {
        self.reexecute_requested.store(true, Ordering::Release);
        self.wake
            .wake()
            .map_err(|error| zbus::fdo::Error::Failed(error.to_string()))
    }

    async fn request_system_shutdown(
        &self,
        operation: &str,
        action: u8,
        connection: &zbus::Connection,
        header: &zbus::MessageHeader<'_>,
    ) -> zbus::fdo::Result<()> {
        if self.scope != ManagerScope::System {
            return Err(zbus::fdo::Error::NotSupported(format!(
                "{operation} is only supported by system manager."
            )));
        }
        authorize_privileged_caller(connection, header).await?;
        if let Err(error) = shutdown_blocked_by_inhibitors(connection).await {
            return Err(error);
        }
        self.shutdown_action.store(action, Ordering::Release);
        self.wake
            .wake()
            .map_err(|error| zbus::fdo::Error::Failed(error.to_string()))
    }

    fn validate_freezer_unit(&self, name: &str, frozen: bool) -> Result<(), FreezerMethodError> {
        let snapshot = self.snapshot.read().map_err(|_| {
            FreezerMethodError::Failed("internal: unit snapshot lock poisoned".to_owned())
        })?;
        let unit = snapshot
            .iter()
            .find(|unit| unit.name == name)
            .ok_or_else(|| FreezerMethodError::NoSuchUnit(format!("Unit {name} not loaded.")))?;

        let supports_freezer = matches!(unit.unit_type.as_str(), "service" | "scope" | "slice")
            && unit.name != "-.slice"
            && unit.name != "init.scope";
        if !supports_freezer {
            return Err(FreezerMethodError::NotSupported(
                "Unit does not support freeze/thaw".to_owned(),
            ));
        }
        if self.jobs.for_unit(name).is_some() {
            return Err(FreezerMethodError::UnitBusy(
                "Unit has a pending job".to_owned(),
            ));
        }
        if unit.load_state != "loaded" {
            return Err(FreezerMethodError::NoSuchUnit(format!(
                "Unit {name} not found."
            )));
        }
        if unit.active_state != "active" {
            return Err(FreezerMethodError::UnitInactive(
                "Unit is not active".to_owned(),
            ));
        }
        drop(snapshot);

        if !frozen && self.cgroup.unit_frozen_by_parent(name) {
            return Err(FreezerMethodError::FrozenByParent(
                "Unit is frozen by a parent slice".to_owned(),
            ));
        }
        Ok(())
    }

    async fn apply_freezer_action(
        &self,
        name: &str,
        frozen: bool,
    ) -> Result<(), FreezerMethodError> {
        self.validate_freezer_unit(name, frozen)?;
        self.cgroup.set_unit_frozen(name, frozen).map_err(|error| {
            if error.downcast_ref::<std::io::Error>().is_some_and(|io| {
                io.kind() == std::io::ErrorKind::NotFound
                    || io.raw_os_error() == Some(libc::EOPNOTSUPP)
            }) {
                FreezerMethodError::NotSupported("Unit does not support freeze/thaw".to_owned())
            } else {
                FreezerMethodError::Failed(error.to_string())
            }
        })?;

        for _ in 0..500 {
            match self.cgroup.is_unit_frozen(name) {
                Ok(state) if state == frozen => return Ok(()),
                Ok(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                // cgroup.events is a kernel-generated text file.  A read can
                // transiently observe the file between updates (the same is
                // true for the regular-file fixture used by the replacement
                // oracle), in which case the `frozen` field is absent for one
                // poll.  Keep polling rather than turning that transient
                // observation into a spurious Failed reply.
                Err(error) if error.to_string().contains("has no valid frozen field") => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(error) => return Err(FreezerMethodError::Failed(error.to_string())),
            }
        }
        Err(FreezerMethodError::Failed(
            "Timed out waiting for cgroup freezer state".to_owned(),
        ))
    }

    async fn resolve_cgroup_unit(
        &self,
        requested: &str,
        connection: &zbus::Connection,
        header: &zbus::MessageHeader<'_>,
        load: bool,
    ) -> Result<UnitInfo, CgroupDelegationMethodError> {
        let name = if requested.is_empty() {
            let pid = caller_process_id(connection, header)
                .await
                .map_err(CgroupDelegationMethodError::Failed)?;
            self.unit_name_for_pid(pid)
                .map_err(CgroupDelegationMethodError::Failed)?
                .ok_or_else(|| {
                    CgroupDelegationMethodError::NoSuchUnit(
                        "Client not member of any unit.".to_owned(),
                    )
                })?
        } else {
            requested.to_owned()
        };
        if load && !valid_unit_name(&name) {
            return Err(CgroupDelegationMethodError::InvalidArgs(format!(
                "Unit name {name} is not valid."
            )));
        }

        let from_snapshot = self
            .snapshot
            .read()
            .map_err(|_| {
                CgroupDelegationMethodError::Failed(
                    "internal: unit snapshot lock poisoned".to_owned(),
                )
            })?
            .iter()
            .find(|unit| unit.name == name)
            .cloned();
        if let Some(unit) = from_snapshot {
            return Ok(unit);
        }
        if load {
            return self
                .request_unit_load(name.clone())
                .await
                .map_err(|error| CgroupDelegationMethodError::Failed(error.to_string()))?
                .ok_or_else(|| {
                    CgroupDelegationMethodError::NoSuchUnit(format!("Unit {name} not found."))
                });
        }
        Err(CgroupDelegationMethodError::NoSuchUnit(format!(
            "Unit {name} not loaded."
        )))
    }

    fn cgroup_unit_is_delegated(&self, name: &str) -> bool {
        matches!(
            UnitLoader::for_scope(self.scope).load(name),
            Ok(LoadedUnit::Service(service)) if service.specific.delegate
        )
    }

    fn cgroup_unit_reference_uid(&self, name: &str, unit: &UnitInfo) -> Option<u32> {
        if let Some(dynamic_user) = unit.service_runtime.dynamic_user.as_ref() {
            return Some(dynamic_user.uid);
        }
        let LoadedUnit::Service(service) = UnitLoader::for_scope(self.scope).load(name).ok()?
        else {
            return None;
        };
        let uid = resolve_user(&service.specific.user).ok()?;
        if uid == u32::MAX {
            Some(match self.scope {
                ManagerScope::System => 0,
                ManagerScope::User => crate::native::current_uid(),
            })
        } else {
            Some(uid)
        }
    }

    fn validate_kill_unit(
        &self,
        name: &str,
        whom: &str,
        signal: i32,
    ) -> Result<(), KillUnitMethodError> {
        let known = self
            .snapshot
            .read()
            .map_err(|_| {
                KillUnitMethodError::Failed("internal: unit snapshot lock poisoned".to_owned())
            })?
            .iter()
            .any(|unit| unit.name == name);
        if !known {
            return Err(KillUnitMethodError::NoSuchUnit(format!(
                "Unit {name} not loaded."
            )));
        }
        let _ = KillWhom::parse(whom)?;
        if signal <= 0 || signal > libc::SIGRTMAX() {
            return Err(KillUnitMethodError::InvalidArgs(
                "Signal number out of range.".to_owned(),
            ));
        }
        Ok(())
    }

    fn unit_is_known_or_realized(&self, name: &str) -> Result<bool, KillUnitMethodError> {
        let known = self
            .snapshot
            .read()
            .map_err(|_| {
                KillUnitMethodError::Failed("internal: unit snapshot lock poisoned".to_owned())
            })?
            .iter()
            .any(|unit| unit.name == name);
        Ok(known || self.cgroup.has_unit_cgroup(name))
    }

    fn validate_kill_unit_subgroup(
        &self,
        name: &str,
        whom: &str,
        subgroup: &str,
        signal: i32,
    ) -> Result<(), KillUnitMethodError> {
        if !self.unit_is_known_or_realized(name)? {
            return Err(KillUnitMethodError::NoSuchUnit(format!(
                "Unit {name} not loaded."
            )));
        }
        let whom = if whom.is_empty() {
            KillWhom::Cgroup
        } else {
            KillWhom::parse(whom)?
        };
        if !subgroup.is_empty() && !is_normalized_cgroup_subpath(subgroup) {
            return Err(KillUnitMethodError::InvalidArgs(
                "Specified cgroup sub-path is not valid.".to_owned(),
            ));
        }
        if !subgroup.is_empty() && !matches!(whom, KillWhom::Cgroup | KillWhom::CgroupFail) {
            return Err(KillUnitMethodError::InvalidArgs(
                "Subgroup can only be specified in combination with 'cgroup' or 'cgroup-fail'."
                    .to_owned(),
            ));
        }
        if !subgroup.is_empty() && !self.cgroup.has_unit_cgroup(name) {
            return Err(KillUnitMethodError::NotSupported(
                "Killing by subgroup is only available for units with control group delegation enabled."
                    .to_owned(),
            ));
        }
        validate_signal(signal)
    }

    fn validate_queue_signal_unit(
        &self,
        name: &str,
        whom: &str,
        signal: i32,
    ) -> Result<(), KillUnitMethodError> {
        if !self.unit_is_known_or_realized(name)? {
            return Err(KillUnitMethodError::NoSuchUnit(format!(
                "Unit {name} not loaded."
            )));
        }
        let _ = KillWhom::parse(whom)?;
        validate_signal(signal)?;
        if !(libc::SIGRTMIN()..=libc::SIGRTMAX()).contains(&signal) {
            return Err(KillUnitMethodError::InvalidArgs(format!(
                "Value parameter only accepted for realtime signals (SIGRTMIN…SIGRTMAX), refusing for signal SIG{}.",
                signal_name(signal)
            )));
        }
        Ok(())
    }

    fn kill_unit_for_request(
        &self,
        name: &str,
        whom: &str,
        signal: i32,
    ) -> Result<(), KillUnitMethodError> {
        self.validate_kill_unit(name, whom, signal)?;
        let whom = KillWhom::parse(whom)?;
        let unit = self
            .snapshot
            .read()
            .map_err(|_| {
                KillUnitMethodError::Failed("internal: unit snapshot lock poisoned".to_owned())
            })?
            .iter()
            .find(|unit| unit.name == name)
            .cloned()
            .expect("unit presence was validated above");
        let main_pid = unit.main_pid.filter(|pid| *pid > 0);
        let control_pid = unit.service_runtime.control_pid.filter(|pid| *pid > 0);
        let has_cgroup = self.cgroup.has_unit_cgroup(name);

        // Service units always have cgroup context in the candidate, even
        // before their cgroup directory has been realized. This matches the
        // v261 distinction between an unsupported unit type and a supported
        // unit that simply has no current processes.
        let supports_process_killing = unit.unit_type == "service" || has_cgroup;
        if !supports_process_killing && main_pid.is_none() && control_pid.is_none() {
            return Err(KillUnitMethodError::NotSupported(
                "Unit type does not support process killing.".to_owned(),
            ));
        }

        if matches!(whom, KillWhom::Main | KillWhom::MainFail) && main_pid.is_none() {
            return Err(KillUnitMethodError::NoSuchProcess(format!(
                "{} units have no main processes",
                unit.unit_type
            )));
        }
        if matches!(whom, KillWhom::Control | KillWhom::ControlFail) && control_pid.is_none() {
            return Err(KillUnitMethodError::NoSuchProcess(format!(
                "{} units have no control processes",
                unit.unit_type
            )));
        }

        let mut killed = false;
        if whom.includes_control() {
            killed |= signal_unit_process(control_pid, "control", signal)?;
        }
        if whom.includes_main() {
            killed |= signal_unit_process(main_pid, "main", signal)?;
        }
        if whom.includes_cgroup() && has_cgroup {
            let exclude: Vec<_> = if matches!(whom, KillWhom::All | KillWhom::AllFail) {
                [main_pid, control_pid].into_iter().flatten().collect()
            } else {
                Vec::new()
            };
            let sent = self
                .cgroup
                .signal_unit(name, signal, &exclude)
                .map_err(|error| KillUnitMethodError::Failed(error.to_string()))?;
            killed |= sent > 0;
        }
        if whom.is_fail() && !killed {
            return Err(KillUnitMethodError::NoSuchProcess(
                "No matching processes to kill".to_owned(),
            ));
        }
        Ok(())
    }

    fn kill_unit_subgroup_for_request(
        &self,
        name: &str,
        whom: &str,
        subgroup: &str,
        signal: i32,
    ) -> Result<(), KillUnitMethodError> {
        self.validate_kill_unit_subgroup(name, whom, subgroup, signal)?;
        let whom = if whom.is_empty() {
            KillWhom::Cgroup
        } else {
            KillWhom::parse(whom)?
        };
        let unit = self
            .snapshot
            .read()
            .map_err(|_| {
                KillUnitMethodError::Failed("internal: unit snapshot lock poisoned".to_owned())
            })?
            .iter()
            .find(|unit| unit.name == name)
            .cloned();
        let main_pid = unit
            .as_ref()
            .and_then(|unit| unit.main_pid)
            .filter(|pid| *pid > 0);
        let control_pid = unit
            .as_ref()
            .and_then(|unit| unit.service_runtime.control_pid)
            .filter(|pid| *pid > 0);
        let mut killed = false;
        if whom.includes_control() {
            killed |= signal_unit_process(control_pid, "control", signal)?;
        }
        if whom.includes_main() {
            killed |= signal_unit_process(main_pid, "main", signal)?;
        }
        if whom.includes_cgroup() {
            let exclude: Vec<_> = if matches!(whom, KillWhom::All | KillWhom::AllFail) {
                [main_pid, control_pid].into_iter().flatten().collect()
            } else {
                Vec::new()
            };
            let sent = if self.cgroup.has_unit_subgroup(name, subgroup) {
                self.cgroup
                    .signal_unit_subgroup(name, subgroup, signal, &exclude, None)
                    .map_err(|error| KillUnitMethodError::Failed(error.to_string()))?
            } else {
                0
            };
            killed |= sent > 0;
        }
        if whom.is_fail() && !killed {
            return Err(KillUnitMethodError::NoSuchProcess(
                "No matching processes to kill".to_owned(),
            ));
        }
        Ok(())
    }

    fn queue_signal_unit_for_request(
        &self,
        name: &str,
        whom: &str,
        signal: i32,
        value: i32,
    ) -> Result<(), KillUnitMethodError> {
        self.validate_queue_signal_unit(name, whom, signal)?;
        let whom = KillWhom::parse(whom)?;
        let unit = self
            .snapshot
            .read()
            .map_err(|_| {
                KillUnitMethodError::Failed("internal: unit snapshot lock poisoned".to_owned())
            })?
            .iter()
            .find(|unit| unit.name == name)
            .cloned();
        let main_pid = unit
            .as_ref()
            .and_then(|unit| unit.main_pid)
            .filter(|pid| *pid > 0);
        let control_pid = unit
            .as_ref()
            .and_then(|unit| unit.service_runtime.control_pid)
            .filter(|pid| *pid > 0);
        let mut queued = false;
        if whom.includes_control() {
            queued |= signal_unit_process_with_value(control_pid, "control", signal, Some(value))?;
        }
        if whom.includes_main() {
            queued |= signal_unit_process_with_value(main_pid, "main", signal, Some(value))?;
        }
        // v261 deliberately does not queue SI_QUEUE payloads through the
        // cgroup controller; only the main/control PID refs are targeted.
        // Normal cgroup requests therefore remain successful with no matching
        // process, while the *-fail variants report NoSuchProcess.
        if whom.is_fail() && !queued {
            return Err(KillUnitMethodError::NoSuchProcess(
                "No matching processes to kill".to_owned(),
            ));
        }
        Ok(())
    }

    fn ensure_dynamic_user_scope(&self) -> Result<(), DynamicUserMethodError> {
        if self.scope == ManagerScope::System {
            return Ok(());
        }
        Err(DynamicUserMethodError::NotSupported(
            "Dynamic users are only supported in the system instance.".to_owned(),
        ))
    }

    fn dynamic_user_entries(&self) -> Result<Vec<DynamicUserEntry>, DynamicUserMethodError> {
        self.ensure_dynamic_user_scope()?;
        let snapshot = self.snapshot.read().map_err(|_| {
            DynamicUserMethodError::Failed("internal: unit snapshot lock poisoned".to_owned())
        })?;
        let mut entries: Vec<DynamicUserEntry> = snapshot
            .iter()
            .filter_map(|unit| unit.service_runtime.dynamic_user.as_ref())
            .map(|identity| (identity.uid, identity.name.clone()))
            .collect();
        entries.sort_unstable();
        entries.dedup();
        Ok(entries)
    }

    fn dump_output(&self, patterns: Option<&[String]>) -> Result<String, DumpMethodError> {
        let patterns = patterns.unwrap_or_default();
        if patterns.len() > MAX_PATTERNS_PER_CALL {
            return Err(DumpMethodError::LimitsExceeded(
                "Too many patterns in a single query.".to_owned(),
            ));
        }

        let mut units = self
            .snapshot
            .read()
            .map_err(|_| {
                DumpMethodError::Failed("internal: unit snapshot lock poisoned".to_owned())
            })?
            .clone();
        units.sort_unstable_by(|left, right| left.name.cmp(&right.name));
        let mut jobs = self.jobs.list();
        jobs.sort_unstable_by_key(|job| job.id);

        let all_units = patterns.is_empty();
        let mut output = String::new();
        if all_units {
            output.push_str("Manager: rustd 261\n");
            output.push_str(&format!("Units: {}\n", units.len()));
            output.push_str(&format!("Jobs: {}\n", jobs.len()));
        }

        for unit in units.iter().filter(|unit| {
            all_units
                || patterns
                    .iter()
                    .any(|pattern| matches_no_escape(pattern, &unit.name))
        }) {
            append_unit_dump(&mut output, unit);
        }
        for job in jobs.iter().filter(|job| {
            all_units
                || patterns
                    .iter()
                    .any(|pattern| matches_no_escape(pattern, &job.unit_name))
        }) {
            append_job_dump(&mut output, job);
        }
        Ok(output)
    }

    async fn list_units_by_names_with_loader(
        &self,
        names: Vec<String>,
    ) -> zbus::fdo::Result<Vec<UnitListEntry>> {
        let snapshot = self
            .snapshot
            .read()
            .map_err(|_| zbus::fdo::Error::Failed("internal: unit snapshot lock poisoned".into()))?
            .clone();
        validate_unit_name_request_count(names.len(), snapshot.len())?;

        let mut entries = Vec::with_capacity(names.len());
        for name in names {
            if !valid_unit_name(&name) {
                continue;
            }
            if let Some(unit) = snapshot.iter().find(|unit| unit.name == name) {
                entries.push(self.unit_list_entry(unit));
                continue;
            }
            match self.request_unit_load(name.clone()).await? {
                Some(unit) => entries.push(self.unit_list_entry(&unit)),
                None => entries.push(not_found_unit_list_entry(&name)),
            }
        }
        Ok(entries)
    }

    async fn request_unit_load(&self, name: String) -> zbus::fdo::Result<Option<UnitInfo>> {
        let Some(requests) = &self.unit_load_requests else {
            return Ok(None);
        };
        let (reply, response) = oneshot::channel();
        requests
            .lock()
            .map_err(|_| {
                zbus::fdo::Error::Failed("internal: unit load queue lock poisoned".into())
            })?
            .push(UnitLoadRequest { name, reply });
        self.wake.wake().map_err(|error| {
            zbus::fdo::Error::Failed(format!("internal: event loop wake failed: {error}"))
        })?;

        match tokio::time::timeout(std::time::Duration::from_secs(5), response).await {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(_)) => Err(zbus::fdo::Error::Failed(
                "manager stopped before completing unit load".into(),
            )),
            Err(_) => Err(zbus::fdo::Error::Failed(
                "manager timed out while loading unit".into(),
            )),
        }
    }

    fn add_unit_reference(&self, sender: &str, unit: &str) -> Result<(), UnitReferenceMethodError> {
        let mut references = self.unit_references.lock().map_err(|_| {
            UnitReferenceMethodError::Failed("internal: unit reference lock poisoned".into())
        })?;
        let key = (sender.to_owned(), unit.to_owned());
        let count = references.entry(key).or_default();
        *count = count.checked_add(1).ok_or_else(|| {
            UnitReferenceMethodError::Failed("unit reference count overflow".into())
        })?;
        Ok(())
    }

    fn remove_unit_reference(
        &self,
        sender: &str,
        unit: &str,
    ) -> Result<(), UnitReferenceMethodError> {
        let mut references = self.unit_references.lock().map_err(|_| {
            UnitReferenceMethodError::Failed("internal: unit reference lock poisoned".into())
        })?;
        let key = (sender.to_owned(), unit.to_owned());
        let remove = match references.get_mut(&key) {
            None => {
                return Err(UnitReferenceMethodError::NotReferenced(
                    "Unit has not been referenced yet.".into(),
                ));
            }
            Some(count) if *count == 1 => true,
            Some(count) => {
                *count -= 1;
                false
            }
        };
        if remove {
            references.remove(&key);
        }
        Ok(())
    }

    fn list_units_matching(&self, states: &[String], patterns: &[String]) -> Vec<UnitListEntry> {
        let snap = match self.snapshot.read() {
            Ok(g) => g.clone(),
            Err(_) => return Vec::new(),
        };
        snap.into_iter()
            .filter(|unit| {
                (states.is_empty()
                    || states.iter().any(|state| {
                        state == &unit.load_state
                            || state == &unit.active_state
                            || state == &unit.sub_state
                    }))
                    && (patterns.is_empty()
                        || patterns
                            .iter()
                            .any(|pattern| matches_no_escape(pattern, &unit.name)))
            })
            .map(|unit| self.unit_list_entry(&unit))
            .collect()
    }

    fn unit_list_entry(&self, unit: &UnitInfo) -> UnitListEntry {
        let path = unit_path(&unit.name).unwrap_or_else(|_| dummy_path());
        let job = self.jobs.for_unit(&unit.name);
        let job_id = job.as_ref().map_or(0, |job| job.id);
        let job_type = job
            .as_ref()
            .map_or_else(String::new, |job| job.kind.as_str().to_owned());
        let job_object_path = job
            .as_ref()
            .and_then(|job| job_path(job.id).ok())
            .unwrap_or_else(dummy_path);
        (
            unit.name.clone(),
            unit.description.clone(),
            unit.load_state.clone(),
            unit.active_state.clone(),
            unit.sub_state.clone(),
            String::new(),
            path,
            job_id,
            job_type,
            job_object_path,
        )
    }
    fn enqueue(&self, kind: JobKind, name: &str, owner: Option<String>) -> zbus::fdo::Result<Job> {
        let job = {
            let mut queue = self.queue.lock().map_err(|_| {
                zbus::fdo::Error::Failed("internal: job queue lock poisoned".into())
            })?;
            queue.enqueue_owned(kind, name.to_owned(), owner)
        };
        self.wake.wake().map_err(|error| {
            zbus::fdo::Error::Failed(format!("internal: event loop wake failed: {error}"))
        })?;
        Ok(job)
    }

    /// Resolve a non-empty name only from the candidate's authoritative unit
    /// snapshot. This is the `manager_get_unit()` path used by v261
    /// `GetUnit`; unlike `LoadUnit`, it never attempts an on-demand load.
    fn get_explicit_unit(
        &self,
        name: &str,
    ) -> Result<zbus::zvariant::OwnedObjectPath, UnitLookupError> {
        let snapshot = self
            .snapshot
            .read()
            .map_err(|_| UnitLookupError::Failed("internal: unit snapshot lock poisoned".into()))?;
        if !snapshot.iter().any(|unit| unit.name == name) {
            return Err(UnitLookupError::NoSuchUnit(format!(
                "Unit {name} not loaded."
            )));
        }
        unit_path(name).map_err(|error| UnitLookupError::Failed(error.to_string()))
    }

    /// Look up a unit in the candidate's current snapshot/cgroup state.
    fn unit_name_for_pid(&self, pid: i32) -> Result<Option<String>, String> {
        let snapshot = self
            .snapshot
            .read()
            .map_err(|_| "internal: unit snapshot lock poisoned".to_owned())?;
        Ok(snapshot.iter().find_map(|unit| {
            (unit.main_pid == Some(pid) || unit_cgroup_contains_pid(&self.cgroup, &unit.name, pid))
                .then(|| unit.name.clone())
        }))
    }

    /// Validate and collapse one of the standard conditional job requests.
    ///
    /// v261 validates the unit name and job mode before authorization, so
    /// malformed calls retain their standard `InvalidArgs` diagnostics even
    /// for callers that would not otherwise be allowed to manage units.
    fn manager_job_kind(
        &self,
        request: ManagerJobRequest,
        name: &str,
        mode: &str,
    ) -> zbus::fdo::Result<JobKind> {
        if !valid_unit_name(name) {
            return Err(zbus::fdo::Error::InvalidArgs(format!(
                "Unit name {name} is not valid."
            )));
        }
        let mode = JobMode::parse(mode)
            .ok_or_else(|| zbus::fdo::Error::InvalidArgs(format!("Job mode {mode} invalid")))?;
        validate_job_mode_for_request(mode)?;

        let active_or_activating = self.unit_has_state(name, &["active", "activating"]);
        let active_or_reloading = self.unit_has_state(name, &["active", "reloading"]);
        let can_reload = self.unit_can_reload(name);

        Ok(collapse_manager_job_request(
            request,
            active_or_activating,
            active_or_reloading,
            can_reload,
        ))
    }

    fn unit_has_state(&self, name: &str, states: &[&str]) -> bool {
        self.snapshot.read().is_ok_and(|snapshot| {
            snapshot
                .iter()
                .find(|unit| unit.name == name)
                .is_some_and(|unit| states.contains(&unit.active_state.as_str()))
        })
    }

    fn unit_can_reload(&self, name: &str) -> bool {
        matches!(
            UnitLoader::for_scope(self.scope).load(name),
            Ok(LoadedUnit::Service(service)) if !service.specific.exec_reload.is_empty()
        )
    }

    fn cancel_live_job(&self, id: u32) -> Result<(), JobMethodError> {
        let canceled = self
            .queue
            .lock()
            .map_err(|_| JobMethodError::Failed("internal: job queue lock poisoned".to_owned()))?
            .cancel(id);
        if !canceled {
            return Err(no_such_job(id));
        }
        self.wake.wake().map_err(|error| {
            JobMethodError::Failed(format!("internal: event loop wake failed: {error}"))
        })
    }

    fn clear_live_jobs(&self) -> Result<(), JobMethodError> {
        let canceled = self
            .queue
            .lock()
            .map_err(|_| JobMethodError::Failed("internal: job queue lock poisoned".to_owned()))?
            .cancel_all();
        if canceled == 0 {
            return Ok(());
        }
        self.wake.wake().map_err(|error| {
            JobMethodError::Failed(format!("internal: event loop wake failed: {error}"))
        })
    }

    fn request_reload(&self) -> zbus::fdo::Result<()> {
        self.reload_requested.store(true, Ordering::Release);
        self.wake.wake().map_err(|error| {
            zbus::fdo::Error::Failed(format!("internal: event loop wake failed: {error}"))
        })
    }

    fn request_reset_failed(&self, units: Vec<String>) -> zbus::fdo::Result<()> {
        self.reset_failed_requests
            .lock()
            .map_err(|_| {
                zbus::fdo::Error::Failed("internal: reset-failed queue lock poisoned".into())
            })?
            .push(units);
        self.wake.wake().map_err(|error| {
            zbus::fdo::Error::Failed(format!("internal: event loop wake failed: {error}"))
        })
    }
}

/// Registered manager interface with stable `RustD` introspection.
///
/// zbus 4.0.1 derives an input argument's introspection name from the Rust
/// identifier. Rust requires the `type` argument in
/// `AddDependencyUnitFiles` to be written as `r#type`. This forwarding
/// interface keeps zbus's generated dispatch while exposing the API argument
/// as `type`.
pub struct ManagerInterfaceApi {
    inner: ManagerInterface,
}

impl ManagerInterfaceApi {
    /// Wrap a manager implementation for registration on the `RustD` D-Bus API.
    #[must_use]
    pub fn new(inner: ManagerInterface) -> Self {
        Self { inner }
    }
}

#[zbus::export::async_trait::async_trait]
impl zbus::object_server::Interface for ManagerInterfaceApi {
    fn name() -> zbus::names::InterfaceName<'static> {
        <ManagerInterface as zbus::object_server::Interface>::name()
    }

    async fn get(
        &self,
        property_name: &str,
    ) -> Option<zbus::fdo::Result<zbus::zvariant::OwnedValue>> {
        <ManagerInterface as zbus::object_server::Interface>::get(&self.inner, property_name).await
    }

    async fn get_all(
        &self,
    ) -> zbus::fdo::Result<std::collections::HashMap<String, zbus::zvariant::OwnedValue>> {
        <ManagerInterface as zbus::object_server::Interface>::get_all(&self.inner).await
    }

    fn set<'call>(
        &'call self,
        property_name: &'call str,
        value: &'call zbus::zvariant::Value<'_>,
        ctxt: &'call zbus::object_server::SignalContext<'_>,
    ) -> zbus::object_server::DispatchResult<'call> {
        <ManagerInterface as zbus::object_server::Interface>::set(
            &self.inner,
            property_name,
            value,
            ctxt,
        )
    }

    async fn set_mut(
        &mut self,
        property_name: &str,
        value: &zbus::zvariant::Value<'_>,
        ctxt: &zbus::object_server::SignalContext<'_>,
    ) -> Option<zbus::fdo::Result<()>> {
        <ManagerInterface as zbus::object_server::Interface>::set_mut(
            &mut self.inner,
            property_name,
            value,
            ctxt,
        )
        .await
    }

    fn call<'call>(
        &'call self,
        server: &'call zbus::ObjectServer,
        connection: &'call zbus::Connection,
        message: &'call zbus::message::Message,
        name: zbus::names::MemberName<'call>,
    ) -> zbus::object_server::DispatchResult<'call> {
        <ManagerInterface as zbus::object_server::Interface>::call(
            &self.inner,
            server,
            connection,
            message,
            name,
        )
    }

    fn call_mut<'call>(
        &'call mut self,
        server: &'call zbus::ObjectServer,
        connection: &'call zbus::Connection,
        message: &'call zbus::message::Message,
        name: zbus::names::MemberName<'call>,
    ) -> zbus::object_server::DispatchResult<'call> {
        <ManagerInterface as zbus::object_server::Interface>::call_mut(
            &mut self.inner,
            server,
            connection,
            message,
            name,
        )
    }

    fn introspect_to_writer(&self, writer: &mut dyn std::fmt::Write, level: usize) {
        let mut generated = String::new();
        <ManagerInterface as zbus::object_server::Interface>::introspect_to_writer(
            &self.inner,
            &mut generated,
            level,
        );
        let generated = generated.replace("name=\"r#type\"", "name=\"type\"");
        writer
            .write_str(&generated)
            .expect("writing D-Bus introspection XML cannot fail");
    }
}

fn validate_job_mode_for_request(mode: JobMode) -> zbus::fdo::Result<()> {
    match mode {
        JobMode::Isolate => Err(zbus::fdo::Error::InvalidArgs(
            "Isolate is only valid for start.".into(),
        )),
        JobMode::Triggering => Err(zbus::fdo::Error::InvalidArgs(
            "--job-mode=triggering is only valid for stop.".into(),
        )),
        JobMode::RestartDependencies => Err(zbus::fdo::Error::InvalidArgs(
            "--job-mode=restart-dependencies is only valid for start.".into(),
        )),
        JobMode::Fail
        | JobMode::Lenient
        | JobMode::Replace
        | JobMode::ReplaceIrreversibly
        | JobMode::Flush
        | JobMode::IgnoreDependencies
        | JobMode::IgnoreRequirements => Ok(()),
    }
}

fn parse_enqueued_job_type(value: &str) -> zbus::fdo::Result<JobKind> {
    match value {
        "nop" => Ok(JobKind::Nop),
        "start" => Ok(JobKind::Start),
        "stop" => Ok(JobKind::Stop),
        "reload" => Ok(JobKind::Reload),
        "restart" => Ok(JobKind::Restart),
        _ => Err(zbus::fdo::Error::InvalidArgs(format!(
            "Job type {value} invalid"
        ))),
    }
}

/// Parse the v261 `SetShowStatus` vocabulary and return the effective boolean
/// value exposed by the `ShowStatus` property.
fn parse_show_status_mode(mode: &str) -> zbus::fdo::Result<bool> {
    match mode {
        "" | "no" | "error" | "auto" => Ok(false),
        "temporary" | "yes" => Ok(true),
        _ => Err(zbus::fdo::Error::InvalidArgs(format!(
            "Invalid show status '{mode}'"
        ))),
    }
}

/// Validate the v261-only argument contract of `StartUnitWithFlags`.
///
/// The upstream interface has reserved the flags argument but v261 supports
/// no flags yet.  It still parses every valid `JobMode` accepted by a start
/// request, including the start-specific `isolate` and
/// `restart-dependencies` modes.
fn validate_start_unit_with_flags(mode: &str, flags: u64) -> zbus::fdo::Result<()> {
    JobMode::parse(mode)
        .ok_or_else(|| zbus::fdo::Error::InvalidArgs(format!("Job mode {mode} invalid")))?;
    if flags != 0 {
        return Err(zbus::fdo::Error::InvalidArgs(format!(
            "Invalid 'flags' parameter '{flags}'"
        )));
    }
    Ok(())
}

/// Follow v261's conditional `JobType` collapse rules after inspecting the
/// unit's live state and `ExecReload=` support.
const fn collapse_manager_job_request(
    request: ManagerJobRequest,
    active_or_activating: bool,
    active_or_reloading: bool,
    can_reload: bool,
) -> JobKind {
    match request {
        ManagerJobRequest::Reload => JobKind::Reload,
        ManagerJobRequest::TryRestart => {
            if active_or_activating {
                JobKind::Restart
            } else {
                JobKind::Nop
            }
        }
        ManagerJobRequest::ReloadOrRestart => {
            if can_reload {
                if active_or_reloading {
                    JobKind::Reload
                } else {
                    JobKind::Start
                }
            } else {
                JobKind::Restart
            }
        }
        ManagerJobRequest::ReloadOrTryRestart => {
            if can_reload {
                if active_or_reloading {
                    JobKind::Reload
                } else {
                    JobKind::Nop
                }
            } else if active_or_activating {
                JobKind::Restart
            } else {
                JobKind::Nop
            }
        }
    }
}

fn deduplicate_unit_search_paths(paths: impl IntoIterator<Item = PathBuf>) -> Vec<String> {
    let mut seen = HashSet::new();

    paths
        .into_iter()
        .filter(|path| seen.insert(std::fs::canonicalize(path).unwrap_or_else(|_| path.clone())))
        .filter_map(|path| path.into_os_string().into_string().ok())
        .collect()
}

fn manager_system_unit_search_paths(root: &Path) -> Vec<String> {
    deduplicate_unit_search_paths([
        root.join("etc/rustd/system.control"),
        root.join("run/rustd/system.control"),
        root.join("run/rustd/transient"),
        root.join("run/rustd/generator.early"),
        root.join("etc/rustd/system"),
        root.join("etc/rustd/system.attached"),
        root.join("run/rustd/system"),
        root.join("run/rustd/system.attached"),
        root.join("run/rustd/generator"),
        root.join("usr/local/lib/rustd/system"),
        root.join("usr/lib/rustd/system"),
        root.join("run/rustd/generator.late"),
    ])
}

fn manager_user_unit_search_paths() -> Vec<String> {
    deduplicate_unit_search_paths(UnitLoader::user().search_dirs)
}

fn validate_unit_list_filters(states: &[String], patterns: &[String]) -> zbus::fdo::Result<()> {
    if states.len() > MAX_STATES_PER_CALL {
        return Err(zbus::fdo::Error::LimitsExceeded(
            "Too many states in a single query.".into(),
        ));
    }
    if patterns.len() > MAX_PATTERNS_PER_CALL {
        return Err(zbus::fdo::Error::LimitsExceeded(
            "Too many patterns in a single query.".into(),
        ));
    }
    Ok(())
}

fn validate_unit_name_request_count(
    requested_names: usize,
    loaded_units: usize,
) -> zbus::fdo::Result<()> {
    if requested_names > loaded_units.max(MAX_NAMES_PER_CALL) {
        return Err(zbus::fdo::Error::LimitsExceeded(
            "Too many unit names requested.".into(),
        ));
    }
    Ok(())
}

fn list_system_unit_files() -> zbus::fdo::Result<Vec<UnitFileListEntry>> {
    list_root_unit_files(std::path::Path::new("/"))
        .map(|entries| {
            entries
                .into_iter()
                .map(|entry| {
                    (
                        entry.path.to_string_lossy().into_owned(),
                        entry.state.to_string(),
                    )
                })
                .collect()
        })
        .map_err(|error| zbus::fdo::Error::Failed(error.to_string()))
}

fn filter_unit_file_entries(
    entries: Vec<UnitFileListEntry>,
    states: &[String],
    patterns: &[String],
) -> Vec<UnitFileListEntry> {
    entries
        .into_iter()
        .filter(|(path, state)| {
            let name = std::path::Path::new(path)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default();
            (states.is_empty() || states.iter().any(|candidate| candidate == state))
                && (patterns.is_empty()
                    || patterns
                        .iter()
                        .any(|pattern| matches_no_escape(pattern, name)))
        })
        .collect()
}

fn valid_unit_name(name: &str) -> bool {
    if name.is_empty() || name.len() >= UNIT_NAME_MAX {
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
                | "target"
                | "device"
                | "mount"
                | "automount"
                | "swap"
                | "timer"
                | "path"
                | "slice"
                | "scope"
        )
    {
        return false;
    }

    let mut first_at = None;
    for (index, character) in prefix.char_indices() {
        if character == '@' && first_at.is_none() {
            first_at = Some(index);
        }
        if !(character.is_ascii_alphanumeric()
            || matches!(character, ':' | '-' | '_' | '.' | '\\' | '@'))
        {
            return false;
        }
    }
    first_at != Some(0)
}

fn invalid_property_value(name: &str) -> SetUnitPropertiesError {
    SetUnitPropertiesError::InvalidArgs(format!("Invalid value for property {name}."))
}

fn property_read_only(name: &str) -> SetUnitPropertiesError {
    SetUnitPropertiesError::PropertyReadOnly(format!(
        "Cannot set property {name}, or unknown property."
    ))
}

fn decode_bool_property(
    name: &str,
    value: zbus::zvariant::OwnedValue,
) -> Result<bool, SetUnitPropertiesError> {
    bool::try_from(value).map_err(|_| invalid_property_value(name))
}

fn decode_u64_property(
    name: &str,
    value: zbus::zvariant::OwnedValue,
) -> Result<u64, SetUnitPropertiesError> {
    u64::try_from(value).map_err(|_| invalid_property_value(name))
}

fn decode_limit_property(
    name: &str,
    value: zbus::zvariant::OwnedValue,
    tasks_max: bool,
) -> Result<LimitValue, SetUnitPropertiesError> {
    let value = decode_u64_property(name, value)?;
    if tasks_max && value == 0 {
        return Err(SetUnitPropertiesError::InvalidArgs(format!(
            "Value specified in {name} is out of range"
        )));
    }
    Ok(if value == u64::MAX {
        LimitValue::Max
    } else {
        LimitValue::Value(value)
    })
}

fn decode_weight_property(
    name: &str,
    value: zbus::zvariant::OwnedValue,
) -> Result<Option<u64>, SetUnitPropertiesError> {
    let value = decode_u64_property(name, value)?;
    if value == u64::MAX {
        return Ok(None);
    }
    if !(1..=10_000).contains(&value) {
        return Err(SetUnitPropertiesError::InvalidArgs(format!(
            "Value specified in {name} is out of range"
        )));
    }
    Ok(Some(value))
}

fn decode_cpu_weight(
    name: &str,
    value: zbus::zvariant::OwnedValue,
) -> Result<u64, SetUnitPropertiesError> {
    let value = decode_u64_property(name, value)?;
    if value != 0 && value != u64::MAX && !(1..=10_000).contains(&value) {
        return Err(SetUnitPropertiesError::InvalidArgs(format!(
            "Value specified in {name} is out of range"
        )));
    }
    Ok(value)
}

fn decode_cpu_quota(
    name: &str,
    value: zbus::zvariant::OwnedValue,
) -> Result<CpuQuota, SetUnitPropertiesError> {
    let value = decode_u64_property(name, value)?;
    if value == 0 {
        return Err(SetUnitPropertiesError::InvalidArgs(format!(
            "{name}= value out of range"
        )));
    }
    if value == u64::MAX {
        return Ok(CpuQuota::Max);
    }
    // The D-Bus property is usec of CPU time per one second.  The unit-file
    // representation and ResourceControl store hundredths of a percent.
    Ok(CpuQuota::PercentHundredths(value / 100))
}

fn decode_set_unit_properties(
    properties: Vec<(String, zbus::zvariant::OwnedValue)>,
) -> Result<Vec<SetUnitProperty>, SetUnitPropertiesError> {
    properties
        .into_iter()
        .map(|(name, value)| {
            let property = match name.as_str() {
                "Description" => {
                    let value =
                        String::try_from(value).map_err(|_| invalid_property_value(&name))?;
                    if value.contains(['\n', '\r', '\0']) {
                        return Err(invalid_property_value(&name));
                    }
                    SetUnitProperty::Description(value)
                }
                "IOAccounting" => {
                    SetUnitProperty::IoAccounting(decode_bool_property(&name, value)?)
                }
                "MemoryAccounting" => {
                    SetUnitProperty::MemoryAccounting(decode_bool_property(&name, value)?)
                }
                "TasksAccounting" => {
                    SetUnitProperty::TasksAccounting(decode_bool_property(&name, value)?)
                }
                "IPAccounting" => {
                    SetUnitProperty::IpAccounting(decode_bool_property(&name, value)?)
                }
                "CPUWeight" => SetUnitProperty::CpuWeight(decode_cpu_weight(&name, value)?),
                "CPUQuotaPerSecUSec" => SetUnitProperty::CpuQuota(decode_cpu_quota(&name, value)?),
                "IOWeight" | "BlockIOWeight" => {
                    SetUnitProperty::IoWeight(decode_weight_property(&name, value)?)
                }
                "MemoryMin" => {
                    SetUnitProperty::MemoryMin(decode_limit_property(&name, value, false)?)
                }
                "MemoryLow" => {
                    SetUnitProperty::MemoryLow(decode_limit_property(&name, value, false)?)
                }
                "MemoryHigh" => {
                    SetUnitProperty::MemoryHigh(decode_limit_property(&name, value, false)?)
                }
                "MemoryMax" => {
                    SetUnitProperty::MemoryMax(decode_limit_property(&name, value, false)?)
                }
                "MemorySwapMax" => {
                    SetUnitProperty::MemorySwapMax(decode_limit_property(&name, value, false)?)
                }
                "MemoryZSwapMax" => {
                    SetUnitProperty::MemoryZSwapMax(decode_limit_property(&name, value, false)?)
                }
                "MemoryZSwapWriteback" => {
                    SetUnitProperty::MemoryZSwapWriteback(decode_bool_property(&name, value)?)
                }
                "TasksMax" => SetUnitProperty::TasksMax(decode_limit_property(&name, value, true)?),
                _ => return Err(property_read_only(&name)),
            };
            Ok(property)
        })
        .collect()
}

fn set_property_assignment(property: &SetUnitProperty) -> (&'static str, &'static str, String) {
    match property {
        SetUnitProperty::Description(value) => ("Unit", "Description", value.clone()),
        SetUnitProperty::IoAccounting(value) => ("Service", "IOAccounting", value.to_string()),
        SetUnitProperty::MemoryAccounting(value) => {
            ("Service", "MemoryAccounting", value.to_string())
        }
        SetUnitProperty::TasksAccounting(value) => {
            ("Service", "TasksAccounting", value.to_string())
        }
        SetUnitProperty::IpAccounting(value) => ("Service", "IPAccounting", value.to_string()),
        SetUnitProperty::CpuWeight(value) => (
            "Service",
            "CPUWeight",
            match *value {
                0 => "idle".to_owned(),
                u64::MAX => String::new(),
                value => value.to_string(),
            },
        ),
        SetUnitProperty::CpuQuota(value) => ("Service", "CPUQuota", value.unit_value()),
        SetUnitProperty::IoWeight(value) => (
            "Service",
            "IOWeight",
            value.map_or_else(String::new, |value| value.to_string()),
        ),
        SetUnitProperty::MemoryMin(value) => ("Service", "MemoryMin", value.cgroup_value()),
        SetUnitProperty::MemoryLow(value) => ("Service", "MemoryLow", value.cgroup_value()),
        SetUnitProperty::MemoryHigh(value) => ("Service", "MemoryHigh", value.cgroup_value()),
        SetUnitProperty::MemoryMax(value) => ("Service", "MemoryMax", value.cgroup_value()),
        SetUnitProperty::MemorySwapMax(value) => ("Service", "MemorySwapMax", value.cgroup_value()),
        SetUnitProperty::MemoryZSwapMax(value) => {
            ("Service", "MemoryZSwapMax", value.cgroup_value())
        }
        SetUnitProperty::MemoryZSwapWriteback(value) => {
            ("Service", "MemoryZSwapWriteback", value.to_string())
        }
        SetUnitProperty::TasksMax(value) => ("Service", "TasksMax", value.cgroup_value()),
    }
}

/// Return the high-priority control root used by `SetUnitProperties`.
pub(crate) fn set_property_control_dir(scope: ManagerScope, runtime: bool) -> PathBuf {
    match scope {
        ManagerScope::System => {
            let variable = if runtime {
                "RUSTD_RUNTIME_CONTROL_PATH"
            } else {
                "RUSTD_SYSTEM_CONTROL_PATH"
            };
            std::env::var_os(variable).map_or_else(
                || {
                    PathBuf::from(if runtime {
                        "/run/systemd/system.control"
                    } else {
                        "/etc/systemd/system.control"
                    })
                },
                PathBuf::from,
            )
        }
        ManagerScope::User => {
            if runtime {
                std::env::var_os("RUSTD_RUNTIME_CONTROL_PATH").map_or_else(
                    || {
                        std::env::var_os("XDG_RUNTIME_DIR")
                            .map_or_else(|| PathBuf::from("."), PathBuf::from)
                            .join("systemd/user.control")
                    },
                    PathBuf::from,
                )
            } else {
                std::env::var_os("RUSTD_SYSTEM_CONTROL_PATH").map_or_else(
                    || {
                        std::env::var_os("XDG_CONFIG_HOME")
                            .map_or_else(
                                || {
                                    std::env::var_os("HOME")
                                        .map_or_else(|| PathBuf::from("."), PathBuf::from)
                                        .join(".config")
                                },
                                PathBuf::from,
                            )
                            .join("systemd/user.control")
                    },
                    PathBuf::from,
                )
            }
        }
    }
}

/// Write one atomically replaced Manager `SetUnitProperties` drop-in.
///
/// The manager loop calls this only after all wire values have been decoded
/// and unit applicability has been validated.  A dedicated file prevents a
/// D-Bus update from overwriting the CLI's `50-rustctl-set-property.conf`.
pub(crate) fn write_set_property_dropin(
    scope: ManagerScope,
    runtime: bool,
    unit: &str,
    properties: &[SetUnitProperty],
) -> std::io::Result<PathBuf> {
    let directory = set_property_control_dir(scope, runtime).join(format!("{unit}.d"));
    fs::create_dir_all(&directory)?;
    let path = directory.join("50-rustd-dbus-set-property.conf");
    let mut sections: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    if let Ok(content) = fs::read_to_string(&path) {
        let mut section = String::new();
        for line in content.lines().map(str::trim) {
            if line.starts_with('[') && line.ends_with(']') {
                line[1..line.len() - 1].clone_into(&mut section);
            } else if !line.is_empty() && !line.starts_with('#') && !line.starts_with(';') {
                if let Some((key, value)) = line.split_once('=') {
                    sections
                        .entry(section.clone())
                        .or_default()
                        .insert(key.trim().to_owned(), value.trim().to_owned());
                }
            }
        }
    }
    for property in properties {
        let (section, key, value) = set_property_assignment(property);
        sections
            .entry(section.to_owned())
            .or_default()
            .insert(key.to_owned(), value);
    }

    let mut content = String::new();
    for (section, values) in sections {
        if values.is_empty() {
            continue;
        }
        content.push('[');
        content.push_str(&section);
        content.push_str("]\n");
        for (key, value) in values {
            content.push_str(&key);
            content.push('=');
            content.push_str(&value);
            content.push('\n');
        }
        content.push('\n');
    }
    let temporary = directory.join(format!(
        ".50-rustd-dbus-set-property.conf.tmp.{}",
        std::process::id()
    ));
    fs::write(&temporary, content)?;
    if let Err(error) = fs::rename(&temporary, &path) {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    Ok(path)
}

fn sender_name(header: &zbus::MessageHeader<'_>) -> Result<String, UnitReferenceMethodError> {
    header.sender().map(ToString::to_string).ok_or_else(|| {
        UnitReferenceMethodError::AccessDenied("unable to determine D-Bus caller identity".into())
    })
}

fn unit_reference_lookup_error(error: UnitLookupError) -> UnitReferenceMethodError {
    match error {
        UnitLookupError::NoSuchUnit(message) => UnitReferenceMethodError::NoSuchUnit(message),
        UnitLookupError::Failed(message) => UnitReferenceMethodError::Failed(message),
    }
}

fn validate_reference_unit_load_state(
    name: &str,
    load_state: &str,
) -> Result<(), UnitReferenceMethodError> {
    match load_state {
        "loaded" => Ok(()),
        "not-found" => Err(UnitReferenceMethodError::NoSuchUnit(format!(
            "Unit {name} not found."
        ))),
        "masked" => Err(UnitReferenceMethodError::UnitMasked(format!(
            "Unit {name} is masked."
        ))),
        "bad-setting" => Err(UnitReferenceMethodError::BadUnitSetting(format!(
            "Unit {name} has a bad unit file setting."
        ))),
        other => Err(UnitReferenceMethodError::Failed(format!(
            "Unexpected load state of unit {name}: {other}"
        ))),
    }
}

fn validate_cgroup_unit_load_state(
    name: &str,
    load_state: &str,
) -> Result<(), CgroupDelegationMethodError> {
    match load_state {
        "loaded" => Ok(()),
        "not-found" => Err(CgroupDelegationMethodError::NoSuchUnit(format!(
            "Unit {name} not found."
        ))),
        "masked" => Err(CgroupDelegationMethodError::UnitMasked(format!(
            "Unit {name} is masked."
        ))),
        "bad-setting" => Err(CgroupDelegationMethodError::BadUnitSetting(format!(
            "Unit {name} has a bad unit file setting."
        ))),
        other => Err(CgroupDelegationMethodError::Failed(format!(
            "Unexpected load state of unit {name}: {other}"
        ))),
    }
}

fn validate_attachable_pid(pid: libc::pid_t) -> Result<(), CgroupDelegationMethodError> {
    if pid <= 0 {
        return Err(CgroupDelegationMethodError::InvalidArgs(
            "Process identifier is not valid.".to_owned(),
        ));
    }
    if pid == 1 || pid == unsafe { libc::getpid() } {
        return Err(CgroupDelegationMethodError::InvalidArgs(format!(
            "Process {pid} is a manager process, refusing."
        )));
    }

    let stat_path = PathBuf::from("/proc").join(pid.to_string()).join("stat");
    let stat = fs::read_to_string(stat_path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            CgroupDelegationMethodError::UnixProcessIdUnknown(format!(
                "Process with ID {pid} does not exist."
            ))
        } else {
            CgroupDelegationMethodError::Failed(format!(
                "Failed to determine whether process {pid} is a kernel thread: {error}"
            ))
        }
    })?;
    let Some(close) = stat.rfind(')') else {
        return Err(CgroupDelegationMethodError::Failed(format!(
            "Failed to determine whether process {pid} is a kernel thread: malformed stat"
        )));
    };
    let mut fields = stat[close + 1..].split_whitespace();
    let Some(flags) = fields.nth(6).and_then(|value| value.parse::<u64>().ok()) else {
        return Err(CgroupDelegationMethodError::Failed(format!(
            "Failed to determine whether process {pid} is a kernel thread: malformed stat"
        )));
    };
    #[allow(clippy::items_after_statements)]
    const PF_KTHREAD: u64 = 0x0020_0000;
    if flags & PF_KTHREAD != 0 {
        return Err(CgroupDelegationMethodError::InvalidArgs(format!(
            "Process {pid} is a kernel thread, refusing."
        )));
    }
    Ok(())
}

fn process_effective_uid(pid: libc::pid_t) -> Result<u32, String> {
    let status = fs::read_to_string(PathBuf::from("/proc").join(pid.to_string()).join("status"))
        .map_err(|error| error.to_string())?;
    let values = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .ok_or_else(|| "missing Uid field".to_owned())?
        .split_whitespace()
        .collect::<Vec<_>>();
    values
        .get(1)
        .ok_or_else(|| "missing effective UID".to_owned())?
        .parse::<u32>()
        .map_err(|error| error.to_string())
}

/// Remove all references owned by a sender whose unique name disappeared.
pub(crate) fn clear_unit_references_for_sender(references: &UnitReferences, sender: &str) {
    if let Ok(mut references) = references.lock() {
        references.retain(|(owner, _), _| owner != sender);
    }
}

fn not_found_unit_list_entry(name: &str) -> UnitListEntry {
    (
        name.to_owned(),
        name.to_owned(),
        "not-found".to_owned(),
        "inactive".to_owned(),
        "dead".to_owned(),
        String::new(),
        unit_path(name).expect("validated unit names always form valid D-Bus paths"),
        0,
        String::new(),
        dummy_path(),
    )
}

fn systemd_architecture() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x86-64",
        "x86" => "x86",
        "aarch64" => {
            if cfg!(target_endian = "little") {
                "arm64"
            } else {
                "arm64-be"
            }
        }
        "arm" => {
            if cfg!(target_endian = "little") {
                "arm"
            } else {
                "arm-be"
            }
        }
        "powerpc64" => {
            if cfg!(target_endian = "little") {
                "ppc64-le"
            } else {
                "ppc64"
            }
        }
        "powerpc" => {
            if cfg!(target_endian = "little") {
                "ppc-le"
            } else {
                "ppc"
            }
        }
        "mips64" | "mips64el" => {
            if cfg!(target_endian = "little") {
                "mips64-le"
            } else {
                "mips64"
            }
        }
        "mips" | "mipsel" => {
            if cfg!(target_endian = "little") {
                "mips-le"
            } else {
                "mips"
            }
        }
        "riscv64" => "riscv64",
        "riscv32" => "riscv32",
        "s390x" => "s390x",
        "sparc64" => "sparc64",
        "sparc" => "sparc",
        "loongarch64" => "loongarch64",
        "m68k" => "m68k",
        "s390" => "s390",
        other => other,
    }
}

// ── helpers ───────────────────────────────────────────────────────────────

/// Build the canonical D-Bus object path for a unit name.
///
/// Replaces non-alphanumeric chars with `_XX` percent-style encoding,
/// matching the upstream `bus_unit_path()` helper.
pub fn unit_path(name: &str) -> zbus::fdo::Result<zbus::zvariant::OwnedObjectPath> {
    let escaped = escape_unit_name(name);
    let path = format!("/io/rustd/Manager1/unit/{escaped}");
    zbus::zvariant::OwnedObjectPath::try_from(path)
        .map_err(|e| zbus::fdo::Error::InvalidArgs(e.to_string()))
}

/// Return the transient D-Bus object path keyed by a unit invocation ID.
///
/// v261 gives each active invocation an ID-specific alias in addition to the
/// stable name-based unit object path returned by `GetUnit` and listings.
pub fn invocation_id_path(
    invocation_id: &[u8; 16],
) -> zbus::fdo::Result<zbus::zvariant::OwnedObjectPath> {
    let path = format!("/io/rustd/Manager1/unit/_{}", format_id128(invocation_id));
    zbus::zvariant::OwnedObjectPath::try_from(path)
        .map_err(|error| zbus::fdo::Error::InvalidArgs(error.to_string()))
}

fn manager_control_group() -> String {
    fs::read_to_string("/proc/self/cgroup")
        .ok()
        .and_then(|contents| parse_unified_cgroup_path(&contents))
        .unwrap_or_default()
}

/// Return the candidate manager process's OOM adjustment.
///
/// v261 initializes the unconfigured default to zero, then replaces it with
/// the manager process's `oom_score_adj` when that procfs read succeeds.
fn current_oom_score_adjust() -> i32 {
    fs::read_to_string("/proc/self/oom_score_adj")
        .ok()
        .and_then(|contents| contents.trim().parse().ok())
        .unwrap_or_default()
}

fn parse_unified_cgroup_path(contents: &str) -> Option<String> {
    contents.lines().find_map(|line| {
        let mut fields = line.splitn(3, ':');
        let hierarchy = fields.next()?;
        let controllers = fields.next()?;
        let path = fields.next()?;
        (hierarchy == "0" && controllers.is_empty()).then(|| {
            if path != "/" {
                path.to_owned()
            } else {
                Default::default()
            }
        })
    })
}

fn validate_environment_assignments(assignments: &[String]) -> zbus::fdo::Result<()> {
    if assignments.len() > ENVIRONMENT_ASSIGNMENTS_MAX {
        return Err(zbus::fdo::Error::LimitsExceeded(
            "Too many environment assignments in a single query.".into(),
        ));
    }
    if !environment_assignments_are_valid(assignments) {
        return Err(zbus::fdo::Error::InvalidArgs(
            "Invalid environment assignments".into(),
        ));
    }
    Ok(())
}

fn validate_environment_unset_patterns(names: &[String]) -> zbus::fdo::Result<()> {
    if names.len() > ENVIRONMENT_ASSIGNMENTS_MAX {
        return Err(zbus::fdo::Error::LimitsExceeded(
            "Too many environment variable names in a single query.".into(),
        ));
    }
    if !environment_unset_patterns_are_valid(names) {
        return Err(zbus::fdo::Error::InvalidArgs(
            "Invalid environment variable names or assignments".into(),
        ));
    }
    Ok(())
}

fn validate_environment_unset_and_set(
    names: &[String],
    assignments: &[String],
) -> zbus::fdo::Result<()> {
    if names.len() > ENVIRONMENT_ASSIGNMENTS_MAX || assignments.len() > ENVIRONMENT_ASSIGNMENTS_MAX
    {
        return Err(zbus::fdo::Error::LimitsExceeded(
            "Too many environment variable names or assignments in a single query.".into(),
        ));
    }
    if !environment_unset_patterns_are_valid(names)
        || !environment_assignments_are_valid(assignments)
    {
        return Err(zbus::fdo::Error::InvalidArgs(
            "Invalid environment variable names or assignments".into(),
        ));
    }
    Ok(())
}

fn environment_arg_max() -> usize {
    let result = unsafe { libc::sysconf(libc::_SC_ARG_MAX) };
    usize::try_from(result).unwrap_or(131_072)
}

fn environment_name_is_valid(name: &str) -> bool {
    let bytes = name.as_bytes();
    let maximum = environment_arg_max().saturating_sub(2);
    !bytes.is_empty()
        && bytes.len() <= maximum
        && !bytes[0].is_ascii_digit()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
}

fn environment_assignment_is_valid(assignment: &str) -> bool {
    let Some((name, value)) = assignment.split_once('=') else {
        return false;
    };
    let arg_max = environment_arg_max();
    environment_name_is_valid(name)
        && value.len() <= arg_max.saturating_sub(3)
        && assignment.len() <= arg_max.saturating_sub(1)
}

fn environment_assignments_are_valid(assignments: &[String]) -> bool {
    let mut names = HashSet::with_capacity(assignments.len());
    assignments.iter().all(|assignment| {
        environment_assignment_is_valid(assignment)
            && names.insert(assignment.split_once('=').map_or("", |(name, _)| name))
    })
}

fn environment_unset_patterns_are_valid(patterns: &[String]) -> bool {
    let mut seen = HashSet::with_capacity(patterns.len());
    patterns.iter().all(|pattern| {
        (environment_assignment_is_valid(pattern) || environment_name_is_valid(pattern))
            && seen.insert(pattern)
    })
}

fn environment_key(entry: &str) -> &str {
    entry.split_once('=').map_or(entry, |(name, _)| name)
}

fn delete_environment_entries(entries: &mut Vec<String>, patterns: &[String]) {
    entries.retain(|entry| {
        !patterns.iter().any(|pattern| {
            entry == pattern
                || (!pattern.contains('=')
                    && entry
                        .strip_prefix(pattern)
                        .is_some_and(|suffix| suffix.starts_with('=')))
        })
    });
}

fn candidate_system_state(scope: ManagerScope, units: &[UnitInfo]) -> &'static str {
    let unit_is_active_or_pending = |name: &str| {
        units.iter().any(|unit| {
            unit.name == name
                && matches!(
                    unit.active_state.as_str(),
                    "active" | "activating" | "deactivating" | "reloading"
                )
        })
    };

    if unit_is_active_or_pending("shutdown.target") {
        return "stopping";
    }
    if scope == ManagerScope::System
        && (unit_is_active_or_pending("rescue.target")
            || unit_is_active_or_pending("emergency.target"))
    {
        return "maintenance";
    }
    if units.iter().any(|unit| unit.active_state == "failed") {
        return "degraded";
    }
    "running"
}

/// Return the PID represented by a Linux pidfd, matching the v261 fallback
/// through `/proc/self/fdinfo` when the newer pidfd info ioctl is unavailable.
fn pid_from_pidfd(fd: RawFd) -> std::io::Result<i32> {
    let contents = fs::read_to_string(format!("/proc/self/fdinfo/{fd}"))?;
    let pid = contents
        .lines()
        .find_map(|line| line.strip_prefix("Pid:\t"))
        .ok_or_else(|| std::io::Error::from_raw_os_error(libc::ENOTTY))?
        .parse::<i32>()
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    match pid {
        1.. => Ok(pid),
        0 => Err(std::io::Error::from_raw_os_error(libc::EREMOTE)),
        -1 => Err(std::io::Error::from_raw_os_error(libc::ESRCH)),
        _ => Err(std::io::Error::from_raw_os_error(libc::EINVAL)),
    }
}

fn pidfd_lookup_failed(error: std::io::Error) -> PidFdLookupError {
    let detail = error.raw_os_error().map_or_else(
        || error.to_string(),
        |errno| {
            // Safety: `strerror` returns a NUL-terminated static error string
            // for every errno accepted by the platform C library.
            unsafe { CStr::from_ptr(libc::strerror(errno)) }
                .to_string_lossy()
                .into_owned()
        },
    );
    PidFdLookupError::Failed(format!("Failed to get PID from PIDFD: {detail}"))
}

fn unit_cgroup_contains_pid(cgroup: &CgroupManager, name: &str, pid: i32) -> bool {
    let Ok(pid) = u32::try_from(pid) else {
        return false;
    };
    let cgroup_procs = cgroup.unit_procs_path(name);
    let Some(cgroup_root) = cgroup_procs.parent() else {
        return false;
    };
    cgroup_tree_contains_pid(cgroup_root, pid)
}

fn cgroup_tree_contains_pid(cgroup: &Path, pid: u32) -> bool {
    let owns_pid = fs::read_to_string(cgroup.join("cgroup.procs")).is_ok_and(|contents| {
        contents
            .split_whitespace()
            .any(|entry| entry.parse::<u32>().ok() == Some(pid))
    });
    owns_pid
        || fs::read_dir(cgroup).is_ok_and(|entries| {
            entries.flatten().any(|entry| {
                entry.file_type().is_ok_and(|kind| kind.is_dir())
                    && cgroup_tree_contains_pid(&entry.path(), pid)
            })
        })
}

fn append_unit_dump(output: &mut String, unit: &UnitInfo) {
    output.push_str(&format!("→ Unit {}:\n", unit.name));
    output.push_str(&format!("\tDescription: {}\n", unit.description));
    output.push_str(&format!("\tUnit Load State: {}\n", unit.load_state));
    output.push_str(&format!("\tUnit Active State: {}\n", unit.active_state));
    output.push_str(&format!("\tUnit Sub State: {}\n", unit.sub_state));
    output.push_str(&format!("\tType: {}\n", unit.unit_type));
    if let Some(pid) = unit.main_pid {
        output.push_str(&format!("\tMain PID: {pid}\n"));
    }
    if let Some(identity) = &unit.service_runtime.dynamic_user {
        output.push_str(&format!(
            "\tDynamic User: {} ({})\n",
            identity.name, identity.uid
        ));
    }
}

fn append_job_dump(output: &mut String, job: &JobInfo) {
    output.push_str(&format!("→ Job {}:\n", job.id));
    output.push_str(&format!("\tUnit: {}\n", job.unit_name));
    output.push_str(&format!("\tType: {}\n", job.kind.as_str()));
    output.push_str(&format!("\tState: {}\n", job.state.as_str()));
}

fn dump_to_memfd(output: &str) -> Result<zbus::zvariant::OwnedFd, String> {
    let raw_fd = unsafe {
        libc::memfd_create(
            b"dump\0".as_ptr().cast(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if raw_fd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    // Safety: `memfd_create` returned a new descriptor owned by this call.
    let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw_fd) };

    let mut remaining = output.as_bytes();
    while !remaining.is_empty() {
        let written =
            unsafe { libc::write(fd.as_raw_fd(), remaining.as_ptr().cast(), remaining.len()) };
        if written < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(error.to_string());
        }
        if written == 0 {
            return Err("short write while creating diagnostic dump".to_owned());
        }
        let written = usize::try_from(written).map_err(|error| error.to_string())?;
        remaining = &remaining[written..];
    }

    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_ADD_SEALS, seals) } < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    if unsafe { libc::lseek(fd.as_raw_fd(), 0, libc::SEEK_SET) } < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(zbus::zvariant::OwnedFd::from(fd))
}

/// Collect every still-live process in a managed unit's cgroup subtree.
///
/// Cgroup v2 exposes only direct membership through each `cgroup.procs` file,
/// so child cgroups must be walked as well. Processes that disappear while
/// this read-only query is in progress are omitted, matching the
/// best-effort nature of the host Manager query.
fn collect_unit_processes(cgroup_root: &Path, dbus_cgroup_root: &Path) -> Vec<UnitProcessEntry> {
    let mut entries = Vec::new();
    collect_unit_processes_at(cgroup_root, cgroup_root, dbus_cgroup_root, &mut entries);
    entries
}

fn collect_unit_processes_at(
    cgroup_root: &Path,
    cgroup: &Path,
    dbus_cgroup_root: &Path,
    entries: &mut Vec<UnitProcessEntry>,
) {
    let cgroup_path = match cgroup.strip_prefix(cgroup_root) {
        Ok(relative) if !relative.as_os_str().is_empty() => dbus_cgroup_root.join(relative),
        Ok(_) | Err(_) => dbus_cgroup_root.to_path_buf(),
    }
    .display()
    .to_string();

    let mut pids: Vec<u32> = std::fs::read_to_string(cgroup.join("cgroup.procs")).map_or_else(
        |_| Vec::new(),
        |contents| {
            contents
                .split_whitespace()
                .filter_map(|value| value.parse::<u32>().ok())
                .collect()
        },
    );
    pids.sort_unstable();
    pids.dedup();
    for pid in pids {
        if let Some(command_line) = process_command_line(pid) {
            entries.push((cgroup_path.clone(), pid, command_line));
        }
    }

    let mut children: Vec<PathBuf> = std::fs::read_dir(cgroup).map_or_else(
        |_| Vec::new(),
        |directory| {
            directory
                .flatten()
                .filter_map(|entry| {
                    entry
                        .file_type()
                        .ok()
                        .filter(std::fs::FileType::is_dir)
                        .map(|_| entry.path())
                })
                .collect()
        },
    );
    children.sort();
    for child in children {
        collect_unit_processes_at(cgroup_root, &child, dbus_cgroup_root, entries);
    }
}

/// Read a process command line in the same human-readable form used by the
/// Manager D-Bus API. Kernel threads have an empty `cmdline`; for those,
/// expose their task name instead.
fn process_command_line(pid: u32) -> Option<String> {
    let command_line = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let arguments: Vec<String> = command_line
        .split(|byte| *byte == 0)
        .filter(|argument| !argument.is_empty())
        .map(|argument| String::from_utf8_lossy(argument).into_owned())
        .collect();
    if !arguments.is_empty() {
        return Some(arguments.join(" "));
    }

    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|name| name.trim_end().to_owned())
        .filter(|name| !name.is_empty())
}

fn is_normalized_absolute_cgroup_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.as_bytes().contains(&0)
        && !path
            .split('/')
            .any(|component| component == "." || component == "..")
        && !path.contains("//")
}

fn cgroup_is_within(ancestor: &str, candidate: &str) -> bool {
    let candidate = candidate.trim_end_matches('/');
    candidate == ancestor
        || candidate
            .strip_prefix(ancestor)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

/// The v261 Manager accepts the relaxed system user/group-name form for
/// dynamic-user lookup. Path separators and empty names are the relevant
/// invalid inputs for this D-Bus boundary; the manager does not impose the
/// narrower `User=` parser here.
fn is_valid_dynamic_user_name(name: &str) -> bool {
    !name.is_empty() && !name.contains('/') && !name.as_bytes().contains(&0)
}

fn seconds_to_usec(seconds: u64) -> u64 {
    seconds.saturating_mul(USEC_PER_SEC)
}

fn nanoseconds_to_usec(nanoseconds: i64) -> u64 {
    u64::try_from(nanoseconds).map_or(0, |value| value / 1_000)
}

/// Build the canonical numeric D-Bus object path for a job.
pub fn job_path(id: u32) -> zbus::fdo::Result<zbus::zvariant::OwnedObjectPath> {
    let path = format!("/io/rustd/Manager1/job/{id}");
    zbus::zvariant::OwnedObjectPath::try_from(path)
        .map_err(|error| zbus::fdo::Error::InvalidArgs(error.to_string()))
}

/// Convert a live job into the canonical `a(usssoo)` wire tuple.
#[must_use]
pub fn job_list_entry(info: &JobInfo) -> Option<JobListEntry> {
    Some((
        info.id,
        info.unit_name.clone(),
        info.kind.as_str().to_owned(),
        info.state.as_str().to_owned(),
        job_path(info.id).ok()?,
        unit_path(&info.unit_name).ok()?,
    ))
}

fn no_such_job(id: u32) -> JobMethodError {
    JobMethodError::NoSuchJob(format!("Job {id} does not exist."))
}

fn job_method_authorization_error(error: zbus::fdo::Error) -> JobMethodError {
    JobMethodError::AccessDenied(error.to_string())
}

async fn shutdown_blocked_by_inhibitors(connection: &zbus::Connection) -> zbus::fdo::Result<()> {
    let reply = match connection
        .call_method(
            Some("org.freedesktop.login1"),
            "/org/freedesktop/login1",
            Some("org.freedesktop.login1.Manager"),
            "ListInhibitors",
            &(),
        )
        .await
    {
        Ok(reply) => reply,
        // Logind may be offline during early boot; do not hard-fail power ops.
        Err(_) => return Ok(()),
    };
    let inhibitors: Vec<(String, String, String, String, u32, u32)> = reply
        .body()
        .deserialize()
        .map_err(|error| zbus::fdo::Error::Failed(error.to_string()))?;
    let blockers: Vec<String> = inhibitors
        .into_iter()
        .filter(|(_, _, _, mode, _, _)| mode == "block")
        .filter(|(what, _, _, _, _, _)| {
            what.split(':')
                .any(|token| token == "shutdown" || token == "handle-power-key")
        })
        .map(|(what, who, why, _, _, _)| format!("{who}:{why} ({what})"))
        .collect();
    if blockers.is_empty() {
        Ok(())
    } else {
        Err(zbus::fdo::Error::Failed(format!(
            "operation inhibited by {}",
            blockers.join("; ")
        )))
    }
}

/// Resolve the PID of the sender of an incoming D-Bus request.
///
/// v261's `GetUnit("")` and `GetUnitByPID(0)` both route through
/// `bus_query_sender_pidref()` before consulting the manager's live unit
/// state. The bus daemon is the authority for that sender-to-PID mapping.
async fn caller_process_id(
    connection: &zbus::Connection,
    header: &zbus::MessageHeader<'_>,
) -> Result<i32, String> {
    let sender = header
        .sender()
        .cloned()
        .ok_or_else(|| "unable to determine D-Bus caller identity".to_owned())?;
    let proxy = zbus::fdo::DBusProxy::new(connection)
        .await
        .map_err(|error| error.to_string())?;
    let pid = proxy
        .get_connection_unix_process_id(sender.into())
        .await
        .map_err(|error| error.to_string())?;
    i32::try_from(pid).map_err(|_| format!("invalid D-Bus caller PID {pid}"))
}

/// Apply the v261 `GetUnitByPID` zero-PID convention.
///
/// A zero input means the PID supplied by the D-Bus daemon for the current
/// caller; every other wire value keeps the signed `pid_t` interpretation
/// used by v261's range validation.
#[allow(clippy::cast_possible_wrap)]
const fn pid_for_unit_lookup(pid: u32, caller_pid: Option<i32>) -> i32 {
    if pid == 0 {
        match caller_pid {
            Some(caller_pid) => caller_pid,
            None => 0,
        }
    } else {
        pid as i32
    }
}

/// Render one D-Bus ID128 argument in systemd's lowercase compact spelling.
fn format_id128(id: &[u8; 16]) -> String {
    let mut output = String::with_capacity(32);
    for byte in id {
        use std::fmt::Write;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn validate_signal(signal: i32) -> Result<(), KillUnitMethodError> {
    if signal <= 0 || signal > libc::SIGRTMAX() {
        return Err(KillUnitMethodError::InvalidArgs(
            "Signal number out of range.".to_owned(),
        ));
    }
    Ok(())
}

fn is_normalized_cgroup_subpath(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.ends_with('/')
        && !path.contains('\0')
        && path
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn signal_name(signal: i32) -> &'static str {
    match signal {
        libc::SIGHUP => "HUP",
        libc::SIGINT => "INT",
        libc::SIGQUIT => "QUIT",
        libc::SIGILL => "ILL",
        libc::SIGTRAP => "TRAP",
        libc::SIGABRT => "ABRT",
        libc::SIGBUS => "BUS",
        libc::SIGFPE => "FPE",
        libc::SIGKILL => "KILL",
        libc::SIGUSR1 => "USR1",
        libc::SIGSEGV => "SEGV",
        libc::SIGUSR2 => "USR2",
        libc::SIGPIPE => "PIPE",
        libc::SIGALRM => "ALRM",
        libc::SIGTERM => "TERM",
        libc::SIGCHLD => "CHLD",
        libc::SIGCONT => "CONT",
        libc::SIGSTOP => "STOP",
        libc::SIGTSTP => "TSTP",
        libc::SIGTTIN => "TTIN",
        libc::SIGTTOU => "TTOU",
        _ => "UNKNOWN",
    }
}

fn valid_log_level(value: &str) -> bool {
    matches!(
        value,
        "emerg" | "alert" | "crit" | "err" | "warning" | "notice" | "info" | "debug"
    )
}

fn valid_log_target(value: &str) -> bool {
    matches!(
        value,
        "console"
            | "journal"
            | "journal-or-kmsg"
            | "kmsg"
            | "null"
            | "syslog"
            | "syslog-or-kmsg"
            | "auto"
    )
}

fn signal_unit_process(
    pid: Option<i32>,
    process_kind: &str,
    signal: i32,
) -> Result<bool, KillUnitMethodError> {
    signal_unit_process_with_value(pid, process_kind, signal, None)
}

fn signal_unit_process_with_value(
    pid: Option<i32>,
    process_kind: &str,
    signal: i32,
    value: Option<i32>,
) -> Result<bool, KillUnitMethodError> {
    let Some(pid) = pid else {
        return Ok(false);
    };
    // Safety: the manager snapshot records this as a process owned by the
    // selected candidate unit.
    let result = if let Some(value) = value {
        unsafe {
            libc::sigqueue(
                pid,
                signal,
                libc::sigval {
                    sival_ptr: value as isize as *mut libc::c_void,
                },
            )
        }
    } else {
        unsafe { libc::kill(pid, signal) }
    };
    if result == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        return Ok(false);
    }
    Err(KillUnitMethodError::Failed(format!(
        "Failed to send signal to {process_kind} process: {error}"
    )))
}

fn ensure_live_job(jobs: &JobRegistry, id: u32) -> Result<(), JobMethodError> {
    if jobs.is_live(id) {
        Ok(())
    } else {
        Err(no_such_job(id))
    }
}

fn dummy_path() -> zbus::zvariant::OwnedObjectPath {
    zbus::zvariant::OwnedObjectPath::try_from("/").unwrap()
}

/// Escape a unit name for use as a D-Bus object path component.
///
/// Replaces characters not in `[A-Za-z0-9_]` with `_XX` where XX is the
/// hex byte value.  Matches upstream `bus_label_escape()`.
#[must_use]
pub fn escape_unit_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len() * 2);
    for b in name.bytes() {
        if b.is_ascii_alphanumeric() || b == b'_' {
            out.push(b as char);
        } else {
            use std::fmt::Write;
            let _ = write!(out, "_{b:02x}");
        }
    }
    // Object path components must not start with a digit.
    if out.starts_with(|c: char| c.is_ascii_digit()) {
        out.insert(0, '_');
    }
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_unit_properties_decodes_typed_v261_values() {
        let values = decode_set_unit_properties(vec![
            (
                "Description".to_owned(),
                zbus::zvariant::OwnedValue::try_from(zbus::zvariant::Value::from("updated"))
                    .unwrap(),
            ),
            (
                "CPUWeight".to_owned(),
                zbus::zvariant::OwnedValue::from(250_u64),
            ),
            (
                "CPUQuotaPerSecUSec".to_owned(),
                zbus::zvariant::OwnedValue::from(102_500_u64),
            ),
            (
                "MemoryMax".to_owned(),
                zbus::zvariant::OwnedValue::from(u64::MAX),
            ),
            (
                "TasksMax".to_owned(),
                zbus::zvariant::OwnedValue::from(512_u64),
            ),
        ])
        .unwrap();
        assert_eq!(
            values,
            vec![
                SetUnitProperty::Description("updated".to_owned()),
                SetUnitProperty::CpuWeight(250),
                SetUnitProperty::CpuQuota(CpuQuota::PercentHundredths(1025)),
                SetUnitProperty::MemoryMax(LimitValue::Max),
                SetUnitProperty::TasksMax(LimitValue::Value(512)),
            ]
        );
        assert!(matches!(
            decode_set_unit_properties(vec![(
                "TasksMax".to_owned(),
                zbus::zvariant::OwnedValue::from(0_u64),
            )]),
            Err(SetUnitPropertiesError::InvalidArgs(_))
        ));
        assert!(matches!(
            decode_set_unit_properties(vec![(
                "Unknown".to_owned(),
                zbus::zvariant::OwnedValue::from(1_u64),
            )]),
            Err(SetUnitPropertiesError::PropertyReadOnly(_))
        ));
    }

    #[test]
    fn set_unit_properties_exposes_exact_v261_signature() {
        let (interface, _, _, _) = test_interface();
        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        let method = xml
            .split(r#"<method name="SetUnitProperties">"#)
            .nth(1)
            .and_then(|rest| rest.split("</method>").next())
            .expect("SetUnitProperties introspection");
        for argument in [
            r#"<arg name="name" type="s" direction="in"/>"#,
            r#"<arg name="runtime" type="b" direction="in"/>"#,
            r#"<arg name="properties" type="a(sv)" direction="in"/>"#,
        ] {
            assert!(method.contains(argument), "missing argument: {argument}");
        }
        assert_eq!(method.matches("<arg ").count(), 3);
    }

    #[test]
    fn escape_simple() {
        assert_eq!(escape_unit_name("foo.service"), "foo_2eservice");
    }

    #[test]
    fn escape_dash() {
        assert_eq!(escape_unit_name("my-unit.service"), "my_2dunit_2eservice");
    }

    #[test]
    fn escape_at() {
        assert_eq!(
            escape_unit_name("getty@tty1.service"),
            "getty_40tty1_2eservice"
        );
    }

    #[test]
    fn architecture_uses_systemd_spelling() {
        #[cfg(target_arch = "x86_64")]
        assert_eq!(systemd_architecture(), "x86-64");
        #[cfg(target_arch = "aarch64")]
        assert_eq!(systemd_architecture(), "arm64");
    }

    #[test]
    fn virtualization_uses_live_candidate_detection_and_v261_empty_mapping() {
        let (interface, _, _, _) = test_interface();
        let detected = crate::unit::condition::detect_virtualization();
        let expected = (detected != "none").then_some(detected).unwrap_or_default();
        assert_eq!(interface.virtualization(), expected);

        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        let property = xml
            .split(r#"<property name="Virtualization" type="s" access="read">"#)
            .nth(1)
            .and_then(|rest| rest.split("</property>").next())
            .unwrap();
        assert!(property.contains(
            r#"<annotation name="org.freedesktop.DBus.Property.EmitsChangedSignal" value="const"/>"#
        ));
        let confidential = xml
            .split(r#"<property name="ConfidentialVirtualization" type="s" access="read">"#)
            .nth(1)
            .and_then(|rest| rest.split("</property>").next())
            .unwrap();
        assert!(confidential.contains(
            r#"<annotation name="org.freedesktop.DBus.Property.EmitsChangedSignal" value="const"/>"#
        ));
    }

    #[test]
    fn manager_default_limits_and_tasks_max_have_v261_wire_contract() {
        let (mut interface, _, _, _) = test_interface();
        let mut defaults = crate::config::UnitDefaults::default();
        defaults.apply_entry("DefaultLimitNOFILE", "123:456");
        defaults.apply_entry("DefaultTasksMax", "15%");
        interface.unit_defaults = Arc::new(RwLock::new(defaults));

        assert_eq!(interface.default_limit_nofile(), 456);
        assert_eq!(interface.default_limit_nofile_soft(), 123);
        assert_eq!(
            interface.default_tasks_max(),
            crate::limits::TasksMaxSpec::parse("15%").unwrap().resolve()
        );

        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        for name in [
            "CPU",
            "FSIZE",
            "DATA",
            "STACK",
            "CORE",
            "RSS",
            "NOFILE",
            "AS",
            "NPROC",
            "MEMLOCK",
            "LOCKS",
            "SIGPENDING",
            "MSGQUEUE",
            "NICE",
            "RTPRIO",
            "RTTIME",
        ] {
            for suffix in ["", "Soft"] {
                let property = format!("DefaultLimit{name}{suffix}");
                let fragment = xml
                    .split(&format!(
                        r#"<property name="{property}" type="t" access="read">"#
                    ))
                    .nth(1)
                    .and_then(|rest| rest.split("</property>").next())
                    .unwrap_or_else(|| panic!("missing {property}"));
                assert!(fragment.contains(
                    r#"<annotation name="org.freedesktop.DBus.Property.EmitsChangedSignal" value="const"/>"#
                ));
            }
        }
        let tasks = xml
            .split(r#"<property name="DefaultTasksMax" type="t" access="read">"#)
            .nth(1)
            .and_then(|rest| rest.split("</property>").next())
            .expect("missing DefaultTasksMax");
        assert!(tasks.contains(
            r#"<annotation name="org.freedesktop.DBus.Property.EmitsChangedSignal" value="false"/>"#
        ));
    }

    #[test]
    fn show_status_matches_v261_vocabulary_and_wire_contract() {
        let (interface, _, _, _) = test_interface();
        assert!(!interface.show_status());

        for (mode, expected) in [
            ("yes", true),
            ("temporary", true),
            ("error", false),
            ("no", false),
            ("auto", false),
            ("", false),
        ] {
            interface.set_show_status(mode.to_owned()).unwrap();
            assert_eq!(interface.show_status(), expected, "mode={mode:?}");
        }

        let invalid = interface.set_show_status("invalid".to_owned()).unwrap_err();
        assert_eq!(
            zbus::DBusError::name(&invalid).as_str(),
            "org.freedesktop.DBus.Error.InvalidArgs"
        );
        assert_eq!(
            zbus::DBusError::description(&invalid),
            Some("Invalid show status 'invalid'")
        );

        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        assert!(xml.contains(r#"<method name="SetShowStatus">"#));
        assert!(xml.contains(r#"<arg name="mode" type="s" direction="in"/>"#));
        assert!(xml.contains(r#"property name="ShowStatus" type="b" access="read""#));
    }

    #[test]
    fn log_properties_match_v261_values_validation_and_restore() {
        let (mut interface, _, _, _) = test_interface();
        assert_eq!(interface.log_level(), "info");
        assert_eq!(interface.log_target(), "journal-or-kmsg");
        interface.set_log_level("debug".into()).unwrap();
        interface.set_log_target("console".into()).unwrap();
        assert_eq!(interface.log_level(), "debug");
        assert_eq!(interface.log_target(), "console");
        interface.set_log_level(String::new()).unwrap();
        interface.set_log_target(String::new()).unwrap();
        assert_eq!(interface.log_level(), "info");
        assert_eq!(interface.log_target(), "journal-or-kmsg");
        let level = interface.set_log_level("invalid".into()).unwrap_err();
        assert_eq!(
            level.to_string(),
            "org.freedesktop.DBus.Error.InvalidArgs: Invalid log level 'invalid'"
        );
        let target = interface.set_log_target("invalid".into()).unwrap_err();
        assert_eq!(
            target.to_string(),
            "org.freedesktop.DBus.Error.InvalidArgs: Invalid log target 'invalid'"
        );

        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        for property in ["LogLevel", "LogTarget"] {
            assert!(xml.contains(&format!(
                r#"<property name="{property}" type="s" access="readwrite">"#
            )));
            assert!(xml.contains(
                r#"<annotation name="org.freedesktop.DBus.Property.EmitsChangedSignal" value="false"/>"#
            ));
        }
    }

    #[test]
    fn unit_path_produces_valid_path() {
        let p = unit_path("systemd-journald.service").unwrap();
        assert!(p.as_str().starts_with("/io/rustd/Manager1/unit/"));
    }

    fn test_interface() -> (
        ManagerInterface,
        Arc<Mutex<JobQueue>>,
        EventLoopWake,
        Arc<AtomicBool>,
    ) {
        let queue = Arc::new(Mutex::new(JobQueue::default()));
        let jobs = queue.lock().unwrap().registry();
        let wake = EventLoopWake::create().unwrap();
        let reload_requested = Arc::new(AtomicBool::new(false));
        let reload_count = Arc::new(AtomicU64::new(0));
        let exit_code = Arc::new(AtomicU8::new(0));
        let show_status = Arc::new(AtomicBool::new(false));
        let exit_requested = Arc::new(AtomicBool::new(false));
        let reexecute_requested = Arc::new(AtomicBool::new(false));
        let shutdown_action = Arc::new(AtomicU8::new(SHUTDOWN_NONE));
        let (signal_tx, _signal_rx) = tokio::sync::mpsc::unbounded_channel();
        let interface = ManagerInterface {
            scope: ManagerScope::System,
            cgroup: CgroupManager::with_root("/nonexistent/rustd-cgroup"),
            unit_defaults: Arc::new(RwLock::new(crate::config::UnitDefaults::default())),
            default_timeout_start_sec: 90,
            default_timeout_stop_sec: 90,
            snapshot: Arc::new(RwLock::new(Vec::new())),
            queue: Arc::clone(&queue),
            unit_load_requests: None,
            set_unit_property_requests: None,
            jobs,
            wake: wake.clone(),
            reload_requested: Arc::clone(&reload_requested),
            reload_count,
            exit_code,
            show_status,
            exit_requested,
            reexecute_requested,
            shutdown_action,
            shutdown_start_realtime_ns: Arc::new(AtomicI64::new(0)),
            shutdown_start_monotonic_ns: Arc::new(AtomicI64::new(0)),
            startup_realtime_ns: 0,
            startup_monotonic_ns: 0,
            finish_realtime_ns: Arc::new(AtomicI64::new(0)),
            finish_monotonic_ns: Arc::new(AtomicI64::new(0)),
            units_load_start_realtime_ns: Arc::new(AtomicI64::new(0)),
            units_load_start_monotonic_ns: Arc::new(AtomicI64::new(0)),
            units_load_finish_realtime_ns: Arc::new(AtomicI64::new(0)),
            units_load_finish_monotonic_ns: Arc::new(AtomicI64::new(0)),
            units_load_timestamp_realtime_ns: Arc::new(AtomicI64::new(0)),
            units_load_timestamp_monotonic_ns: Arc::new(AtomicI64::new(0)),
            environment: manager_environment_from_process(),
            log: manager_log_from_config("info".to_owned(), "journal-or-kmsg".to_owned()),
            reset_failed_requests: Arc::new(Mutex::new(Vec::new())),
            subscribers: Arc::new(Mutex::new(HashSet::new())),
            unit_references: Arc::new(Mutex::new(HashMap::new())),
            signal_tx,
        };
        (interface, queue, wake, reload_requested)
    }

    fn read_dump_fd(fd: libc::c_int) -> String {
        assert!(unsafe { libc::lseek(fd, 0, libc::SEEK_SET) } >= 0);
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let read = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
            assert!(read >= 0, "failed to read diagnostic memfd");
            if read == 0 {
                break;
            }
            let read = usize::try_from(read).unwrap();
            bytes.extend_from_slice(&buffer[..read]);
        }
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn reexecute_is_exported_and_internal_lookup_helpers_are_private() {
        let (interface, _, _, _) = test_interface();
        assert!(!interface.reexecute_requested.load(Ordering::Acquire));
        interface.request_reexecute().unwrap();
        assert!(interface.reexecute_requested.load(Ordering::Acquire));

        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        assert!(xml.contains(r#"<method name="Reexecute">"#));
        for helper in [
            "GetUnitByPidForPid",
            "GetUnitByInvocationIdForId",
            "GetUnitByInvocationIdForPid",
        ] {
            assert!(!xml.contains(&format!(r#"<method name="{helper}">"#)));
        }
    }

    #[test]
    fn enqueue_wakes_the_manager_event_loop() {
        let (interface, queue, wake, _) = test_interface();
        let job = interface
            .enqueue(JobKind::Start, "foo.service", Some(":1.9".to_owned()))
            .unwrap();
        assert_eq!(job.id, 1);
        assert!(interface.jobs.is_owner(job.id, ":1.9"));
        assert_eq!(queue.lock().unwrap().len(), 1);
        // Safety: the descriptor is owned by `wake` for this test.
        let counter = unsafe { crate::ffi::event::rustd_eventfd_read(wake.raw_fd()) };
        assert_eq!(counter, 1);
    }

    #[test]
    fn conditional_job_requests_follow_v261_collapse_rules() {
        assert_eq!(
            collapse_manager_job_request(ManagerJobRequest::Reload, false, false, false),
            JobKind::Reload
        );
        assert_eq!(
            collapse_manager_job_request(ManagerJobRequest::TryRestart, false, false, false),
            JobKind::Nop
        );
        assert_eq!(
            collapse_manager_job_request(ManagerJobRequest::TryRestart, true, false, false),
            JobKind::Restart
        );
        assert_eq!(
            collapse_manager_job_request(ManagerJobRequest::ReloadOrRestart, false, false, true),
            JobKind::Start
        );
        assert_eq!(
            collapse_manager_job_request(ManagerJobRequest::ReloadOrRestart, true, true, true),
            JobKind::Reload
        );
        assert_eq!(
            collapse_manager_job_request(ManagerJobRequest::ReloadOrTryRestart, false, false, true,),
            JobKind::Nop
        );
        assert_eq!(
            collapse_manager_job_request(ManagerJobRequest::ReloadOrTryRestart, false, true, true,),
            JobKind::Reload
        );
        assert_eq!(
            collapse_manager_job_request(ManagerJobRequest::ReloadOrTryRestart, true, false, false,),
            JobKind::Restart
        );
    }

    #[test]
    fn conditional_job_requests_accept_v261_job_modes() {
        for mode in [
            "fail",
            "lenient",
            "replace",
            "replace-irreversibly",
            "isolate",
            "flush",
            "ignore-dependencies",
            "ignore-requirements",
            "triggering",
            "restart-dependencies",
        ] {
            assert!(JobMode::parse(mode).is_some(), "missing mode {mode}");
        }
        assert!(JobMode::parse("not-a-mode").is_none());
    }

    #[test]
    fn freezer_methods_have_v261_introspection_signatures() {
        let (interface, _, _, _) = test_interface();
        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        for name in ["FreezeUnit", "ThawUnit"] {
            let method = xml
                .split(&format!(r#"<method name="{name}">"#))
                .nth(1)
                .and_then(|rest| rest.split("</method>").next())
                .expect("freezer method must be exported");
            assert!(method.contains(r#"name="name""#));
            assert!(method.contains(r#"type="s""#));
            assert!(method.contains(r#"direction="in""#));
            assert_eq!(method.matches("<arg ").count(), 1);
        }
    }

    #[test]
    fn conditional_job_requests_match_host_invalid_argument_errors() {
        let (interface, _, _, _) = test_interface();
        let invalid_name = interface
            .manager_job_kind(ManagerJobRequest::Reload, "bad", "replace")
            .unwrap_err();
        match invalid_name {
            zbus::fdo::Error::InvalidArgs(message) => {
                assert_eq!(message, "Unit name bad is not valid.");
            }
            other => panic!("unexpected error: {other}"),
        }

        let invalid_mode = interface
            .manager_job_kind(
                ManagerJobRequest::TryRestart,
                "rustd-conditional-test.service",
                "not-a-mode",
            )
            .unwrap_err();
        match invalid_mode {
            zbus::fdo::Error::InvalidArgs(message) => {
                assert_eq!(message, "Job mode not-a-mode invalid");
            }
            other => panic!("unexpected error: {other}"),
        }

        for (mode, expected) in [
            ("isolate", "Isolate is only valid for start."),
            (
                "triggering",
                "--job-mode=triggering is only valid for stop.",
            ),
            (
                "restart-dependencies",
                "--job-mode=restart-dependencies is only valid for start.",
            ),
        ] {
            let error = interface
                .manager_job_kind(
                    ManagerJobRequest::ReloadOrRestart,
                    "rustd-conditional-test.service",
                    mode,
                )
                .unwrap_err();
            match error {
                zbus::fdo::Error::InvalidArgs(message) => assert_eq!(message, expected),
                other => panic!("unexpected error: {other}"),
            }
        }
    }

    #[test]
    fn conditional_try_restart_queues_a_nop_job_when_inactive() {
        let (interface, queue, wake, _) = test_interface();
        let kind = interface
            .manager_job_kind(
                ManagerJobRequest::TryRestart,
                "rustd-conditional-test.service",
                "replace",
            )
            .unwrap();
        assert_eq!(kind, JobKind::Nop);

        let job = interface
            .enqueue(kind, "rustd-conditional-test.service", Some(":1.9".into()))
            .unwrap();
        assert_eq!(
            job_path(job.id).unwrap().as_str(),
            "/io/rustd/Manager1/job/1"
        );
        assert_eq!(
            queue.lock().unwrap().pop_front().unwrap().kind,
            JobKind::Nop
        );
        // Safety: the descriptor is owned by `wake` for this test.
        assert_eq!(
            unsafe { crate::ffi::event::rustd_eventfd_read(wake.raw_fd()) },
            1
        );
    }

    #[test]
    fn conditional_job_methods_have_v261_introspection_signatures() {
        let (interface, _, _, _) = test_interface();
        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        let xml: String = xml
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();

        for method in [
            "ReloadUnit",
            "TryRestartUnit",
            "ReloadOrRestartUnit",
            "ReloadOrTryRestartUnit",
        ] {
            let signature = format!(
                "<methodname=\"{method}\"><argname=\"name\"type=\"s\"direction=\"in\"/><argname=\"mode\"type=\"s\"direction=\"in\"/><argname=\"job\"type=\"o\"direction=\"out\"/></method>"
            );
            assert!(
                xml.contains(&signature),
                "missing signature for {method}: {xml}"
            );
        }
    }

    #[test]
    fn start_unit_with_flags_matches_v261_arguments_queue_and_introspection() {
        for mode in [
            "fail",
            "lenient",
            "replace",
            "replace-irreversibly",
            "isolate",
            "flush",
            "ignore-dependencies",
            "ignore-requirements",
            "triggering",
            "restart-dependencies",
        ] {
            assert!(
                validate_start_unit_with_flags(mode, 0).is_ok(),
                "v261 rejected start job mode {mode}"
            );
        }

        let invalid_mode = validate_start_unit_with_flags("not-a-mode", 0).unwrap_err();
        assert!(matches!(
            invalid_mode,
            zbus::fdo::Error::InvalidArgs(ref message) if message == "Job mode not-a-mode invalid"
        ));
        let invalid_flags = validate_start_unit_with_flags("replace", u64::MAX).unwrap_err();
        assert!(matches!(
            invalid_flags,
            zbus::fdo::Error::InvalidArgs(ref message)
                if message == "Invalid 'flags' parameter '18446744073709551615'"
        ));

        let (interface, queue, wake, _) = test_interface();
        let job = interface
            .enqueue(JobKind::Start, "flags.service", Some(":1.9".to_owned()))
            .unwrap();
        assert_eq!(
            job_path(job.id).unwrap().as_str(),
            "/io/rustd/Manager1/job/1"
        );
        assert_eq!(
            queue.lock().unwrap().pop_front().unwrap().kind,
            JobKind::Start
        );
        // Safety: the descriptor is owned by `wake` for this test.
        assert_eq!(
            unsafe { crate::ffi::event::rustd_eventfd_read(wake.raw_fd()) },
            1
        );

        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        let xml: String = xml
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        let signature = "<methodname=\"StartUnitWithFlags\"><argname=\"name\"type=\"s\"direction=\"in\"/><argname=\"mode\"type=\"s\"direction=\"in\"/><argname=\"flags\"type=\"t\"direction=\"in\"/><argname=\"job\"type=\"o\"direction=\"out\"/></method>";
        assert!(xml.contains(signature), "missing signature: {xml}");
    }

    #[test]
    fn get_job_returns_the_live_job_object_path() {
        let (interface, _, _, _) = test_interface();
        let job = interface
            .enqueue(JobKind::Start, "lookup.service", None)
            .unwrap();

        assert_eq!(
            interface.get_job(job.id).unwrap(),
            (job_path(job.id).unwrap(),)
        );
    }

    #[test]
    fn manager_count_properties_reflect_only_live_failed_units_and_jobs() {
        let (interface, _, _, _) = test_interface();
        interface.snapshot.write().unwrap().extend([
            UnitInfo {
                name: "failed.service".into(),
                description: "Failed unit".into(),
                load_state: "loaded".into(),
                active_state: "failed".into(),
                sub_state: "failed".into(),
                main_pid: None,
                unit_type: "service".into(),
                service_type: Some("simple".into()),
                restart_policy: Some("no".into()),
                service_runtime: Box::default(),
            },
            UnitInfo {
                name: "maintenance.service".into(),
                description: "Maintenance unit".into(),
                load_state: "loaded".into(),
                active_state: "maintenance".into(),
                sub_state: "auto-restart".into(),
                main_pid: None,
                unit_type: "service".into(),
                service_type: Some("simple".into()),
                restart_policy: Some("on-failure".into()),
                service_runtime: Box::default(),
            },
        ]);

        assert_eq!(interface.n_failed_units(), 1);
        assert_eq!(interface.n_names(), 2);
        assert_eq!(interface.n_jobs(), 0);
        assert_eq!(interface.n_installed_jobs(), 0);
        assert_eq!(interface.n_failed_jobs(), 0);

        let job = interface
            .enqueue(JobKind::Start, "queued.service", None)
            .unwrap();
        assert_eq!(interface.n_jobs(), 1);
        assert_eq!(interface.n_installed_jobs(), 1);
        assert!(interface
            .jobs
            .finish(job.id, crate::job::JobResult::Done)
            .is_some());
        assert_eq!(interface.n_jobs(), 0);
        assert_eq!(interface.n_failed_jobs(), 0);

        let failed = interface
            .enqueue(JobKind::Start, "failed-job.service", None)
            .unwrap();
        let timeout = interface
            .enqueue(JobKind::Start, "timeout-job.service", None)
            .unwrap();
        assert_eq!(interface.n_installed_jobs(), 3);
        assert!(interface
            .jobs
            .finish(timeout.id, crate::job::JobResult::Timeout)
            .is_some());
        assert_eq!(interface.n_failed_jobs(), 0);
        assert!(interface
            .jobs
            .finish(failed.id, crate::job::JobResult::Failed)
            .is_some());
        assert_eq!(interface.n_failed_jobs(), 1);

        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        assert!(xml.contains(r#"<property name="NNames" type="u" access="read"/>"#));
        assert!(xml.contains(r#"<property name="NFailedUnits" type="u" access="read"/>"#));
        assert!(xml.contains(r#"<property name="NJobs" type="u" access="read">"#));
        assert!(xml.contains(
            r#"<annotation name="org.freedesktop.DBus.Property.EmitsChangedSignal" value="false"/>"#
        ));
        for name in ["NInstalledJobs", "NFailedJobs"] {
            let property = xml
                .split(&format!(
                    r#"<property name="{name}" type="u" access="read">"#
                ))
                .nth(1)
                .and_then(|rest| rest.split("</property>").next())
                .unwrap();
            assert!(property.contains(
                r#"<annotation name="org.freedesktop.DBus.Property.EmitsChangedSignal" value="false"/>"#
            ));
        }
    }

    #[test]
    fn manager_progress_tracks_the_live_job_registry_and_v261_property_contract() {
        let (interface, _, _, _) = test_interface();
        assert!((interface.progress() - 1.0).abs() < f64::EPSILON);

        let first = interface
            .enqueue(JobKind::Start, "first.service", None)
            .unwrap();
        let second = interface
            .enqueue(JobKind::Start, "second.service", None)
            .unwrap();
        assert!(interface.progress().abs() < f64::EPSILON);

        assert!(interface
            .jobs
            .finish(first.id, crate::job::JobResult::Done)
            .is_some());
        assert!((interface.progress() - 0.5).abs() < f64::EPSILON);
        assert!(interface
            .jobs
            .finish(second.id, crate::job::JobResult::Failed)
            .is_some());
        assert!((interface.progress() - 1.0).abs() < f64::EPSILON);

        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        let property = xml
            .split(r#"<property name="Progress" type="d" access="read">"#)
            .nth(1)
            .and_then(|rest| rest.split("</property>").next())
            .unwrap();
        assert!(property.contains(
            r#"<annotation name="org.freedesktop.DBus.Property.EmitsChangedSignal" value="false"/>"#
        ));
    }

    #[test]
    fn manager_process_state_properties_follow_live_candidate_state_and_v261_contract() {
        fn unit(name: &str, active_state: &str) -> UnitInfo {
            UnitInfo {
                name: name.into(),
                description: name.into(),
                load_state: "loaded".into(),
                active_state: active_state.into(),
                sub_state: active_state.into(),
                main_pid: None,
                unit_type: "target".into(),
                service_type: None,
                restart_policy: None,
                service_runtime: Box::default(),
            }
        }

        assert_eq!(parse_unified_cgroup_path("0::/\n"), Some(String::new()));
        assert_eq!(
            parse_unified_cgroup_path("1:name=systemd:/legacy\n0::/user.slice/user-1000.slice\n"),
            Some("/user.slice/user-1000.slice".into())
        );
        assert_eq!(parse_unified_cgroup_path("1:cpu:/legacy\n"), None);

        let (interface, _, _, _) = test_interface();
        assert_eq!(interface.control_group(), manager_control_group());
        assert_eq!(interface.system_state(), "running");

        interface
            .snapshot
            .write()
            .unwrap()
            .push(unit("failed.service", "failed"));
        assert_eq!(interface.system_state(), "degraded");
        interface
            .snapshot
            .write()
            .unwrap()
            .push(unit("rescue.target", "active"));
        assert_eq!(interface.system_state(), "maintenance");
        interface
            .snapshot
            .write()
            .unwrap()
            .push(unit("shutdown.target", "activating"));
        assert_eq!(interface.system_state(), "stopping");

        let (mut user_interface, _, _, _) = test_interface();
        user_interface.scope = ManagerScope::User;
        user_interface
            .snapshot
            .write()
            .unwrap()
            .push(unit("rescue.target", "active"));
        assert_eq!(user_interface.system_state(), "running");

        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        for name in ["ControlGroup", "SystemState"] {
            let property = xml
                .split(&format!(
                    r#"<property name="{name}" type="s" access="read">"#
                ))
                .nth(1)
                .and_then(|rest| rest.split("</property>").next())
                .unwrap();
            assert!(property.contains(
                r#"<annotation name="org.freedesktop.DBus.Property.EmitsChangedSignal" value="false"/>"#
            ));
        }
    }

    #[test]
    fn exit_code_property_and_setter_share_live_candidate_state() {
        let (interface, _, _, _) = test_interface();
        assert_eq!(interface.exit_code(), 0);
        interface.set_exit_code(73).unwrap();
        assert_eq!(interface.exit_code(), 73);

        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        let property = xml
            .split(r#"<property name="ExitCode" type="y" access="read">"#)
            .nth(1)
            .and_then(|rest| rest.split("</property>").next())
            .unwrap();
        assert!(property.contains(
            r#"<annotation name="org.freedesktop.DBus.Property.EmitsChangedSignal" value="false"/>"#
        ));
        let method = xml
            .split(r#"<method name="SetExitCode">"#)
            .nth(1)
            .and_then(|rest| rest.split("</method>").next())
            .unwrap();
        assert!(method.contains(r#"<arg name="number" type="y" direction="in"/>"#));
    }

    #[test]
    fn exit_method_requests_manager_shutdown_and_has_v261_shape() {
        let (interface, _, _, _) = test_interface();
        assert!(!interface.exit_requested.load(Ordering::Acquire));
        interface.request_exit().unwrap();
        assert!(interface.exit_requested.load(Ordering::Acquire));

        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        let method = xml
            .split(r#"<method name="Exit">"#)
            .nth(1)
            .and_then(|rest| rest.split("</method>").next())
            .expect("Exit method must be exported");
        assert!(!method.contains("<arg "));
    }

    #[test]
    fn manager_spawn_default_properties_reflect_the_candidate_launcher_contract() {
        let (interface, _, _, _) = test_interface();
        let mut expected_environment: Vec<String> = std::env::vars()
            .map(|(name, value)| format!("{name}={value}"))
            .collect();
        expected_environment.sort_unstable();
        assert_eq!(interface.environment(), expected_environment);
        assert!(!interface.confirm_spawn());
        assert_eq!(interface.default_standard_output(), "inherit");
        assert_eq!(interface.default_standard_error(), "inherit");

        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        for (name, signature, emits_changed_signal) in [
            ("Environment", "as", "false"),
            ("ConfirmSpawn", "b", "const"),
            ("DefaultStandardOutput", "s", "const"),
            ("DefaultStandardError", "s", "const"),
        ] {
            let property = xml
                .split(&format!(
                    r#"<property name="{name}" type="{signature}" access="read">"#
                ))
                .nth(1)
                .and_then(|rest| rest.split("</property>").next())
                .unwrap();
            assert!(property.contains(&format!(
                r#"<annotation name="org.freedesktop.DBus.Property.EmitsChangedSignal" value="{emits_changed_signal}"/>"#
            )));
        }
    }

    #[test]
    fn manager_environment_lifecycle_matches_v261_merge_and_delete_contract() {
        let (mut interface, _, _, _) = test_interface();
        interface.environment =
            Arc::new(RwLock::new(ManagerEnvironmentState::with_baseline(vec![
                "BASE=one".into(),
                "OVERRIDE=baseline".into(),
            ])));

        manager_environment_modify(
            &interface.environment,
            &[],
            &[
                "OVERRIDE=client".into(),
                "ALPHA=one".into(),
                "BETA=two".into(),
            ],
        )
        .unwrap();
        assert_eq!(
            interface.environment(),
            ["BASE=one", "OVERRIDE=client", "ALPHA=one", "BETA=two"]
        );

        manager_environment_modify(
            &interface.environment,
            &["ALPHA".into()],
            &["BETA=updated".into(), "GAMMA=three".into()],
        )
        .unwrap();
        assert_eq!(
            interface.environment(),
            ["BASE=one", "OVERRIDE=client", "BETA=updated", "GAMMA=three"]
        );

        manager_environment_modify(&interface.environment, &["OVERRIDE".into()], &[]).unwrap();
        assert_eq!(
            interface.environment(),
            [
                "BASE=one",
                "OVERRIDE=baseline",
                "BETA=updated",
                "GAMMA=three"
            ]
        );

        manager_environment_modify(&interface.environment, &[], &["EXACT=value".into()]).unwrap();
        manager_environment_modify(&interface.environment, &["EXACT=value".into()], &[]).unwrap();
        assert!(!interface
            .environment()
            .iter()
            .any(|entry| entry == "EXACT=value"));
    }

    #[test]
    fn manager_environment_lifecycle_matches_v261_validation_and_introspection() {
        let invalid_assignments =
            validate_environment_assignments(&["BAD-NAME=value".into()]).unwrap_err();
        assert!(matches!(
            invalid_assignments,
            zbus::fdo::Error::InvalidArgs(ref message) if message == "Invalid environment assignments"
        ));

        let invalid_patterns =
            validate_environment_unset_patterns(&["BAD-NAME".into()]).unwrap_err();
        assert!(matches!(
            invalid_patterns,
            zbus::fdo::Error::InvalidArgs(ref message)
                if message == "Invalid environment variable names or assignments"
        ));

        let duplicate_assignments =
            validate_environment_assignments(&["DUPLICATE=one".into(), "DUPLICATE=two".into()])
                .unwrap_err();
        assert!(matches!(
            duplicate_assignments,
            zbus::fdo::Error::InvalidArgs(ref message) if message == "Invalid environment assignments"
        ));

        let too_many = vec!["LIMIT=value".to_owned(); ENVIRONMENT_ASSIGNMENTS_MAX + 1];
        let limit_error = validate_environment_assignments(&too_many).unwrap_err();
        assert!(matches!(
            limit_error,
            zbus::fdo::Error::LimitsExceeded(ref message)
                if message == "Too many environment assignments in a single query."
        ));

        let unset_limit_error = validate_environment_unset_patterns(&too_many).unwrap_err();
        assert!(matches!(
            unset_limit_error,
            zbus::fdo::Error::LimitsExceeded(ref message)
                if message == "Too many environment variable names in a single query."
        ));

        let combined_limit_error = validate_environment_unset_and_set(&too_many, &[]).unwrap_err();
        assert!(matches!(
            combined_limit_error,
            zbus::fdo::Error::LimitsExceeded(ref message)
                if message == "Too many environment variable names or assignments in a single query."
        ));

        let (interface, _, _, _) = test_interface();
        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        let xml: String = xml
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();

        for signature in [
            "<methodname=\"SetEnvironment\"><argname=\"assignments\"type=\"as\"direction=\"in\"/></method>",
            "<methodname=\"UnsetEnvironment\"><argname=\"names\"type=\"as\"direction=\"in\"/></method>",
            "<methodname=\"UnsetAndSetEnvironment\"><argname=\"names\"type=\"as\"direction=\"in\"/><argname=\"assignments\"type=\"as\"direction=\"in\"/></method>",
        ] {
            assert!(xml.contains(signature), "missing v261 signature: {signature}");
        }

        let property = xml
            .split(r#"<propertyname="Environment"type="as"access="read">"#)
            .nth(1)
            .and_then(|rest| rest.split("</property>").next())
            .unwrap();
        assert!(property.contains(
            r#"<annotationname="org.freedesktop.DBus.Property.EmitsChangedSignal"value="false"/>"#
        ));
    }

    #[test]
    fn manager_unit_path_uses_only_native_system_roots() {
        let (interface, _, _, _) = test_interface();

        assert_eq!(
            interface.unit_path(),
            vec![
                "/etc/rustd/system.control",
                "/run/rustd/system.control",
                "/run/rustd/transient",
                "/run/rustd/generator.early",
                "/etc/rustd/system",
                "/etc/rustd/system.attached",
                "/run/rustd/system",
                "/run/rustd/system.attached",
                "/run/rustd/generator",
                "/usr/local/lib/rustd/system",
                "/usr/lib/rustd/system",
                "/run/rustd/generator.late",
            ]
        );
    }

    #[test]
    fn load_unit_validates_names_and_exposes_v261_signature() {
        let (interface, _, _, _) = test_interface();
        assert!(valid_unit_name("example.service"));
        assert!(!valid_unit_name("bad"));
        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        let method = xml
            .split(r#"<method name="LoadUnit">"#)
            .nth(1)
            .and_then(|rest| rest.split("</method>").next())
            .expect("LoadUnit introspection");
        assert!(method.contains(r#"<arg name="name" type="s" direction="in"/>"#));
        assert!(method.contains(r#"<arg name="unit" type="o" direction="out"/>"#));
    }

    #[test]
    fn start_unit_replace_exposes_v261_signature() {
        let (interface, _, _, _) = test_interface();
        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        let method = xml
            .split(r#"<method name="StartUnitReplace">"#)
            .nth(1)
            .and_then(|rest| rest.split("</method>").next())
            .expect("StartUnitReplace introspection");
        assert!(method.contains(r#"<arg name="old_unit" type="s" direction="in"/>"#));
        assert!(method.contains(r#"<arg name="new_unit" type="s" direction="in"/>"#));
        assert!(method.contains(r#"<arg name="mode" type="s" direction="in"/>"#));
        assert!(method.contains(r#"<arg name="job" type="o" direction="out"/>"#));
    }

    #[test]
    fn manager_unit_path_deduplicates_equivalent_search_directories() {
        let root = tempfile::tempdir().unwrap();
        let user_lib = root.path().join("usr/lib/rustd/system");

        std::fs::create_dir_all(user_lib).unwrap();
        std::os::unix::fs::symlink("usr/lib", root.path().join("lib")).unwrap();

        let paths = manager_system_unit_search_paths(root.path());
        assert_eq!(paths.len(), 12);
        assert!(paths.contains(
            &root
                .path()
                .join("usr/lib/rustd/system")
                .display()
                .to_string()
        ));
        assert!(!paths.contains(&root.path().join("lib/rustd/system").display().to_string()));
    }

    #[test]
    fn manager_unit_path_uses_the_selected_manager_scope() {
        let (mut interface, _, _, _) = test_interface();

        interface.scope = ManagerScope::User;
        assert_eq!(interface.unit_path(), manager_user_unit_search_paths());
    }

    #[test]
    fn default_timeout_properties_use_manager_configuration_and_v261_annotations() {
        let (mut interface, _, _, _) = test_interface();
        interface.default_timeout_start_sec = 15;
        interface.default_timeout_stop_sec = 10;

        assert_eq!(interface.default_timeout_start_u_sec(), 15_000_000);
        assert_eq!(interface.default_timeout_stop_u_sec(), 10_000_000);
        assert_eq!(interface.default_timeout_abort_u_sec(), 10_000_000);
        assert_eq!(interface.default_restart_u_sec(), 100_000);
        assert_eq!(seconds_to_usec(u64::MAX), u64::MAX);

        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        for name in ["DefaultTimeoutStartUSec", "DefaultTimeoutStopUSec"] {
            let property = xml
                .split(&format!(
                    r#"<property name="{name}" type="t" access="read">"#
                ))
                .nth(1)
                .and_then(|rest| rest.split("</property>").next())
                .unwrap();
            assert!(property.contains(
                r#"<annotation name="org.freedesktop.DBus.Property.EmitsChangedSignal" value="const"/>"#
            ));
        }
        for (name, emits_changed_signal) in [
            ("DefaultTimeoutAbortUSec", "false"),
            ("DefaultRestartUSec", "const"),
        ] {
            let property = xml
                .split(&format!(
                    r#"<property name="{name}" type="t" access="read">"#
                ))
                .nth(1)
                .and_then(|rest| rest.split("</property>").next())
                .unwrap();
            assert!(property.contains(&format!(
                r#"<annotation name="org.freedesktop.DBus.Property.EmitsChangedSignal" value="{emits_changed_signal}"/>"#
            )));
        }
    }

    #[test]
    fn manager_immutable_default_policy_properties_match_v261_contract() {
        let (interface, _, _, _) = test_interface();

        assert_eq!(interface.default_timer_accuracy_u_sec(), 60_000_000);
        assert_eq!(interface.default_device_timeout_u_sec(), 90_000_000);
        assert_eq!(interface.default_start_limit_interval_u_sec(), 10_000_000);
        assert_eq!(interface.default_start_limit_burst(), 5);
        assert_eq!(interface.event_loop_rate_limit_interval_u_sec(), 1_000_000);
        assert_eq!(interface.event_loop_rate_limit_burst(), 50_000);
        assert!(interface.default_memory_accounting());
        assert!(interface.default_tasks_accounting());
        assert!(!interface.default_io_accounting());
        assert!(!interface.default_ip_accounting());
        assert!(interface.default_memory_z_swap_writeback());
        assert!(!interface.default_restrict_suid_sgid());
        assert_eq!(interface.default_oom_policy(), "stop");

        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        for (name, signature) in [
            ("DefaultTimerAccuracyUSec", "t"),
            ("DefaultDeviceTimeoutUSec", "t"),
            ("DefaultStartLimitIntervalUSec", "t"),
            ("DefaultStartLimitBurst", "u"),
            ("EventLoopRateLimitIntervalUSec", "t"),
            ("EventLoopRateLimitBurst", "u"),
            ("DefaultMemoryAccounting", "b"),
            ("DefaultTasksAccounting", "b"),
            ("DefaultIOAccounting", "b"),
            ("DefaultIPAccounting", "b"),
            ("DefaultMemoryZSwapWriteback", "b"),
            ("DefaultRestrictSUIDSGID", "b"),
            ("DefaultOOMPolicy", "s"),
        ] {
            let property = xml
                .split(&format!(
                    r#"<property name="{name}" type="{signature}" access="read">"#
                ))
                .nth(1)
                .and_then(|rest| rest.split("</property>").next())
                .unwrap();
            assert!(property.contains(
                r#"<annotation name="org.freedesktop.DBus.Property.EmitsChangedSignal" value="const"/>"#
            ));
        }
    }

    #[test]
    fn manager_timer_slack_nsec_matches_the_process_prctl_value() {
        let (interface, _, _, _) = test_interface();
        let expected = unsafe { libc::prctl(libc::PR_GET_TIMERSLACK) };

        assert!(expected >= 0);
        assert_eq!(interface.timer_slack_n_sec(), expected as u64);

        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        let property = xml
            .split(r#"<property name="TimerSlackNSec" type="t" access="read">"#)
            .nth(1)
            .and_then(|rest| rest.split("</property>").next())
            .unwrap();
        assert!(property.contains(
            r#"<annotation name="org.freedesktop.DBus.Property.EmitsChangedSignal" value="const"/>"#
        ));
    }

    #[test]
    fn default_oom_score_adjust_reads_the_candidate_process_and_v261_contract() {
        let (interface, _, _, _) = test_interface();
        let expected = fs::read_to_string("/proc/self/oom_score_adj")
            .unwrap()
            .trim()
            .parse::<i32>()
            .unwrap();

        assert_eq!(interface.default_oom_score_adjust(), expected);

        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        let property = xml
            .split(r#"<property name="DefaultOOMScoreAdjust" type="i" access="read">"#)
            .nth(1)
            .and_then(|rest| rest.split("</property>").next())
            .unwrap();
        assert!(property.contains(
            r#"<annotation name="org.freedesktop.DBus.Property.EmitsChangedSignal" value="const"/>"#
        ));
    }

    #[test]
    fn watchdog_properties_match_the_disabled_v261_contract() {
        let (interface, _, _, _) = test_interface();
        assert_eq!(interface.watchdog_device(), "");
        assert_eq!(
            interface.watchdog_last_ping_timestamp(),
            WATCHDOG_NEVER_PINGED_USEC
        );
        assert_eq!(
            interface.watchdog_last_ping_timestamp_monotonic(),
            WATCHDOG_NEVER_PINGED_USEC
        );

        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        for (name, signature, emits_changed) in [
            ("WatchdogDevice", "s", "const"),
            ("WatchdogLastPingTimestamp", "t", "false"),
            ("WatchdogLastPingTimestampMonotonic", "t", "false"),
        ] {
            let property = xml
                .split(&format!(
                    r#"<property name="{name}" type="{signature}" access="read">"#
                ))
                .nth(1)
                .and_then(|rest| rest.split("</property>").next())
                .unwrap();
            assert!(property.contains(&format!(
                r#"<annotation name="org.freedesktop.DBus.Property.EmitsChangedSignal" value="{emits_changed}"/>"#
            )));
        }
    }

    #[test]
    fn userspace_timestamp_properties_use_stable_dual_startup_clocks() {
        let (mut interface, _, _, _) = test_interface();
        interface.startup_realtime_ns = 1_234_567_890_123;
        interface.startup_monotonic_ns = 9_876_543_210;
        assert_eq!(interface.userspace_timestamp(), 1_234_567_890);
        assert_eq!(interface.userspace_timestamp_monotonic(), 9_876_543);
        assert_eq!(nanoseconds_to_usec(-1), 0);

        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        for name in ["UserspaceTimestamp", "UserspaceTimestampMonotonic"] {
            let property = xml
                .split(&format!(
                    r#"<property name="{name}" type="t" access="read">"#
                ))
                .nth(1)
                .and_then(|rest| rest.split("</property>").next())
                .unwrap();
            assert!(property.contains(
                r#"<annotation name="org.freedesktop.DBus.Property.EmitsChangedSignal" value="const"/>"#
            ));
        }
    }

    #[test]
    fn finish_timestamp_properties_reflect_one_shot_completion_state() {
        let (interface, _, _, _) = test_interface();
        assert_eq!(interface.finish_timestamp(), 0);
        assert_eq!(interface.finish_timestamp_monotonic(), 0);

        interface
            .finish_realtime_ns
            .store(2_345_678_901_234, Ordering::Release);
        interface
            .finish_monotonic_ns
            .store(8_765_432_109, Ordering::Release);
        assert_eq!(interface.finish_timestamp(), 2_345_678_901);
        assert_eq!(interface.finish_timestamp_monotonic(), 8_765_432);

        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        for name in ["FinishTimestamp", "FinishTimestampMonotonic"] {
            let property = xml
                .split(&format!(
                    r#"<property name="{name}" type="t" access="read">"#
                ))
                .nth(1)
                .and_then(|rest| rest.split("</property>").next())
                .unwrap();
            assert!(property.contains(
                r#"<annotation name="org.freedesktop.DBus.Property.EmitsChangedSignal" value="const"/>"#
            ));
        }
    }

    #[test]
    fn units_load_timestamp_properties_reflect_initial_dependency_load() {
        let (interface, _, _, _) = test_interface();
        assert_eq!(interface.units_load_start_timestamp(), 0);
        assert_eq!(interface.units_load_start_timestamp_monotonic(), 0);
        assert_eq!(interface.units_load_finish_timestamp(), 0);
        assert_eq!(interface.units_load_finish_timestamp_monotonic(), 0);

        interface
            .units_load_start_realtime_ns
            .store(1_234_567_890_123, Ordering::Release);
        interface
            .units_load_start_monotonic_ns
            .store(9_876_543_210, Ordering::Release);
        interface
            .units_load_finish_realtime_ns
            .store(1_234_567_891_234, Ordering::Release);
        interface
            .units_load_finish_monotonic_ns
            .store(9_876_544_321, Ordering::Release);
        assert_eq!(interface.units_load_start_timestamp(), 1_234_567_890);
        assert_eq!(interface.units_load_start_timestamp_monotonic(), 9_876_543);
        assert_eq!(interface.units_load_finish_timestamp(), 1_234_567_891);
        assert_eq!(interface.units_load_finish_timestamp_monotonic(), 9_876_544);

        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        for name in [
            "UnitsLoadStartTimestamp",
            "UnitsLoadStartTimestampMonotonic",
            "UnitsLoadFinishTimestamp",
            "UnitsLoadFinishTimestampMonotonic",
        ] {
            let property = xml
                .split(&format!(
                    r#"<property name="{name}" type="t" access="read">"#
                ))
                .nth(1)
                .and_then(|rest| rest.split("</property>").next())
                .unwrap();
            assert!(property.contains(
                r#"<annotation name="org.freedesktop.DBus.Property.EmitsChangedSignal" value="const"/>"#
            ));
        }
    }

    #[test]
    fn units_load_timestamp_properties_reflect_reload_state() {
        let (interface, _, _, _) = test_interface();
        assert_eq!(interface.units_load_timestamp(), 0);
        assert_eq!(interface.units_load_timestamp_monotonic(), 0);

        interface
            .units_load_timestamp_realtime_ns
            .store(1_111_222_333_444, Ordering::Release);
        interface
            .units_load_timestamp_monotonic_ns
            .store(7_777_888_999, Ordering::Release);
        assert_eq!(interface.units_load_timestamp(), 1_111_222_333);
        assert_eq!(interface.units_load_timestamp_monotonic(), 7_777_888);

        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        for name in ["UnitsLoadTimestamp", "UnitsLoadTimestampMonotonic"] {
            let property = xml
                .split(&format!(
                    r#"<property name="{name}" type="t" access="read">"#
                ))
                .nth(1)
                .and_then(|rest| rest.split("</property>").next())
                .unwrap();
            assert!(property.contains(
                r#"<annotation name="org.freedesktop.DBus.Property.EmitsChangedSignal" value="const"/>"#
            ));
        }
    }

    #[test]
    fn shutdown_start_timestamp_properties_reflect_one_shot_state() {
        let (interface, _, _, _) = test_interface();
        assert_eq!(interface.shutdown_start_timestamp(), 0);
        assert_eq!(interface.shutdown_start_timestamp_monotonic(), 0);

        interface
            .shutdown_start_realtime_ns
            .store(2_222_333_444_555, Ordering::Release);
        interface
            .shutdown_start_monotonic_ns
            .store(6_666_777_888, Ordering::Release);
        assert_eq!(interface.shutdown_start_timestamp(), 2_222_333_444);
        assert_eq!(interface.shutdown_start_timestamp_monotonic(), 6_666_777);

        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        for name in ["ShutdownStartTimestamp", "ShutdownStartTimestampMonotonic"] {
            let property = xml
                .split(&format!(
                    r#"<property name="{name}" type="t" access="read">"#
                ))
                .nth(1)
                .and_then(|rest| rest.split("</property>").next())
                .unwrap();
            assert!(property.contains(
                r#"<annotation name="org.freedesktop.DBus.Property.EmitsChangedSignal" value="const"/>"#
            ));
        }
    }

    #[test]
    fn reload_count_property_reads_live_saturating_manager_state() {
        let (interface, _, _, _) = test_interface();
        assert_eq!(interface.reload_count(), 0);
        interface.reload_count.store(u64::MAX, Ordering::Release);
        assert_eq!(interface.reload_count(), u64::MAX);

        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        let property = xml
            .split(r#"<property name="ReloadCount" type="t" access="read">"#)
            .nth(1)
            .and_then(|rest| rest.split("</property>").next())
            .unwrap();
        assert!(property.contains(
            r#"<annotation name="org.freedesktop.DBus.Property.EmitsChangedSignal" value="false"/>"#
        ));
    }

    #[test]
    fn job_lookup_methods_report_systemd_no_such_job() {
        let (interface, _, _, _) = test_interface();
        let id = 42;

        for error in [
            interface.get_job(id).unwrap_err(),
            interface.get_job_after(id).unwrap_err(),
            interface.get_job_before(id).unwrap_err(),
        ] {
            assert_eq!(
                zbus::DBusError::name(&error).as_str(),
                "io.rustd.Manager1.NoSuchJob"
            );
            assert_eq!(
                zbus::DBusError::description(&error),
                Some("Job 42 does not exist.")
            );
        }
    }

    #[test]
    fn manager_job_cancellation_matches_v261_errors_and_signatures() {
        let (interface, queue, _, _) = test_interface();
        let first = interface
            .enqueue(JobKind::Start, "first.service", Some(":1.3".to_owned()))
            .unwrap();
        let second = interface
            .enqueue(JobKind::Stop, "second.service", Some(":1.3".to_owned()))
            .unwrap();
        assert_eq!(queue.lock().unwrap().len(), 2);

        interface.cancel_live_job(first.id).unwrap();
        assert!(!interface.jobs.is_live(first.id));
        assert!(interface.jobs.is_live(second.id));
        assert_eq!(queue.lock().unwrap().len(), 1);

        interface.clear_live_jobs().unwrap();
        assert!(!interface.jobs.is_live(second.id));
        assert!(queue.lock().unwrap().is_empty());

        let missing = interface.cancel_live_job(42).unwrap_err();
        assert_eq!(
            zbus::DBusError::name(&missing).as_str(),
            "io.rustd.Manager1.NoSuchJob"
        );
        assert_eq!(
            zbus::DBusError::description(&missing),
            Some("Job 42 does not exist.")
        );

        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        assert!(xml.contains(r#"<method name="CancelJob">"#));
        assert!(xml.contains(r#"<arg name="id" type="u" direction="in"/>"#));
        assert!(xml.contains(r#"<method name="ClearJobs">"#));
    }

    #[test]
    fn job_ordering_methods_preserve_directions_and_wire_tuples() {
        let (interface, queue, _, _) = test_interface();
        let prerequisite = interface
            .enqueue(JobKind::Start, "prerequisite.service", None)
            .unwrap();
        let dependent = interface
            .enqueue(JobKind::Start, "dependent.service", None)
            .unwrap();
        queue
            .lock()
            .unwrap()
            .refresh_ordering(&std::collections::HashMap::from([(
                "dependent.service".to_owned(),
                vec!["prerequisite.service".to_owned()],
            )]));

        assert_eq!(
            interface.get_job_after(prerequisite.id).unwrap(),
            (vec![(
                dependent.id,
                "dependent.service".to_owned(),
                "start".to_owned(),
                "waiting".to_owned(),
                job_path(dependent.id).unwrap(),
                unit_path("dependent.service").unwrap(),
            )],)
        );
        assert_eq!(
            interface.get_job_before(dependent.id).unwrap(),
            (vec![(
                prerequisite.id,
                "prerequisite.service".to_owned(),
                "start".to_owned(),
                "waiting".to_owned(),
                job_path(prerequisite.id).unwrap(),
                unit_path("prerequisite.service").unwrap(),
            )],)
        );
        assert!(interface.get_job_after(dependent.id).unwrap().0.is_empty());
        assert!(interface
            .get_job_before(prerequisite.id)
            .unwrap()
            .0
            .is_empty());
    }

    #[test]
    fn get_unit_by_pid_returns_owning_unit() {
        let (interface, _, _, _) = test_interface();
        assert_eq!(pid_for_unit_lookup(0, Some(1234)), 1234);
        assert_eq!(pid_for_unit_lookup(1234, None), 1234);
        assert_eq!(pid_for_unit_lookup(u32::MAX, None), -1);
        interface.snapshot.write().unwrap().push(UnitInfo {
            name: "foo.service".into(),
            description: "Test service".into(),
            load_state: "loaded".into(),
            active_state: "active".into(),
            sub_state: "running".into(),
            main_pid: Some(1234),
            unit_type: "service".into(),
            service_type: Some("simple".into()),
            restart_policy: Some("no".into()),
            service_runtime: Box::default(),
        });

        assert_eq!(
            interface.get_unit_by_pid_for_pid(1234).unwrap(),
            (unit_path("foo.service").unwrap(),)
        );
        let missing = interface.get_unit_by_pid_for_pid(4321).unwrap_err();
        assert_eq!(
            zbus::DBusError::name(&missing).as_str(),
            "io.rustd.Manager1.NoUnitForPID"
        );
        assert_eq!(
            zbus::DBusError::description(&missing),
            Some("PID 4321 does not belong to any loaded unit.")
        );

        let temporary = tempfile::tempdir().unwrap();
        let mut cgroup_interface = interface;
        cgroup_interface.cgroup = CgroupManager::with_root(temporary.path());
        let cgroup_procs = cgroup_interface.cgroup.unit_procs_path("worker.service");
        std::fs::create_dir_all(cgroup_procs.parent().unwrap()).unwrap();
        std::fs::write(&cgroup_procs, "4567\n").unwrap();
        cgroup_interface.snapshot.write().unwrap().push(UnitInfo {
            name: "worker.service".into(),
            description: "Cgroup-owned service".into(),
            load_state: "loaded".into(),
            active_state: "active".into(),
            sub_state: "running".into(),
            main_pid: None,
            unit_type: "service".into(),
            service_type: Some("simple".into()),
            restart_policy: Some("no".into()),
            service_runtime: Box::default(),
        });
        assert_eq!(
            cgroup_interface.get_unit_by_pid_for_pid(4567).unwrap(),
            (unit_path("worker.service").unwrap(),)
        );

        let invalid = cgroup_interface.get_unit_by_pid_for_pid(-1).unwrap_err();
        assert_eq!(
            zbus::DBusError::name(&invalid).as_str(),
            "io.rustd.DBus.Error.InvalidArgs"
        );
        assert_eq!(
            zbus::DBusError::description(&invalid),
            Some("Invalid PID -1")
        );

        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&cgroup_interface, &mut xml, 0);
        let method = xml
            .split(r#"<method name="GetUnitByPID">"#)
            .nth(1)
            .and_then(|rest| rest.split("</method>").next())
            .unwrap();
        assert!(method.contains(r#"<arg name="pid" type="u" direction="in"/>"#));
        assert!(method.contains(r#"<arg name="unit" type="o" direction="out"/>"#));
    }

    #[allow(clippy::too_many_lines)]
    #[test]
    fn get_unit_by_pidfd_uses_a_live_pidfd_and_matches_v261_contract() {
        use std::os::fd::FromRawFd;

        fn self_pidfd() -> zbus::zvariant::OwnedFd {
            let raw = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_open,
                    i32::try_from(std::process::id()).unwrap(),
                    0,
                )
            };
            assert!(
                raw >= 0,
                "pidfd_open failed: {}",
                std::io::Error::last_os_error()
            );
            let raw = i32::try_from(raw).unwrap();
            let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
            fd.into()
        }

        let pid = i32::try_from(std::process::id()).unwrap();
        let (interface, _, _, _) = test_interface();
        let invocation_id = [
            0x4a, 0x8b, 0x81, 0x15, 0x50, 0xcb, 0x4f, 0xa4, 0x97, 0x7d, 0x47, 0x59, 0x0f, 0x57,
            0xad, 0x29,
        ];
        let runtime = crate::ipc::ServiceRuntimeInfo {
            invocation_id: Some(invocation_id),
            ..Default::default()
        };
        interface.snapshot.write().unwrap().push(UnitInfo {
            name: "pidfd.service".into(),
            description: "PIDFD service".into(),
            load_state: "loaded".into(),
            active_state: "active".into(),
            sub_state: "running".into(),
            main_pid: Some(pid),
            unit_type: "service".into(),
            service_type: Some("simple".into()),
            restart_policy: Some("no".into()),
            service_runtime: Box::new(runtime),
        });
        let (path, unit_id, invocation_id) = interface.get_unit_by_pidfd(self_pidfd()).unwrap();
        assert_eq!(path, unit_path("pidfd.service").unwrap());
        assert_eq!(unit_id, "pidfd.service");
        assert_eq!(
            invocation_id,
            vec![
                0x4a, 0x8b, 0x81, 0x15, 0x50, 0xcb, 0x4f, 0xa4, 0x97, 0x7d, 0x47, 0x59, 0x0f, 0x57,
                0xad, 0x29
            ]
        );

        let (mut cgroup_interface, _, _, _) = test_interface();
        let temporary = tempfile::tempdir().unwrap();
        cgroup_interface.cgroup = CgroupManager::with_root(temporary.path());
        let cgroup_procs = cgroup_interface
            .cgroup
            .unit_procs_path("cgroup-owned.service");
        std::fs::create_dir_all(cgroup_procs.parent().unwrap()).unwrap();
        std::fs::write(&cgroup_procs, format!("{pid}\n")).unwrap();
        cgroup_interface.snapshot.write().unwrap().push(UnitInfo {
            name: "cgroup-owned.service".into(),
            description: "Cgroup-owned service".into(),
            load_state: "loaded".into(),
            active_state: "active".into(),
            sub_state: "running".into(),
            main_pid: None,
            unit_type: "service".into(),
            service_type: Some("simple".into()),
            restart_policy: Some("no".into()),
            service_runtime: Box::default(),
        });
        let (path, unit_id, invocation_id) =
            cgroup_interface.get_unit_by_pidfd(self_pidfd()).unwrap();
        assert_eq!(path, unit_path("cgroup-owned.service").unwrap());
        assert_eq!(unit_id, "cgroup-owned.service");
        assert_eq!(invocation_id, vec![0; 16]);

        let (missing_interface, _, _, _) = test_interface();
        let missing = missing_interface
            .get_unit_by_pidfd(self_pidfd())
            .unwrap_err();
        assert_eq!(
            zbus::DBusError::name(&missing).as_str(),
            "io.rustd.Manager1.NoUnitForPID"
        );
        let expected_missing = format!("PID {pid} does not belong to any loaded unit.");
        assert_eq!(
            zbus::DBusError::description(&missing),
            Some(expected_missing.as_str())
        );

        let normal_fd = zbus::zvariant::OwnedFd::from(std::os::fd::OwnedFd::from(
            std::fs::File::open("/dev/null").unwrap(),
        ));
        let invalid = interface.get_unit_by_pidfd(normal_fd).unwrap_err();
        assert_eq!(
            zbus::DBusError::name(&invalid).as_str(),
            "io.rustd.DBus.Error.Failed"
        );
        assert_eq!(
            zbus::DBusError::description(&invalid),
            Some("Failed to get PID from PIDFD: Inappropriate ioctl for device")
        );

        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        let method = xml
            .split(r#"<method name="GetUnitByPIDFD">"#)
            .nth(1)
            .and_then(|rest| rest.split("</method>").next())
            .unwrap();
        assert!(method.contains(r#"<arg name="pidfd" type="h" direction="in"/>"#));
        assert!(method.contains(r#"<arg name="unit" type="o" direction="out"/>"#));
        assert!(method.contains(r#"<arg name="unit_id" type="s" direction="out"/>"#));
        assert!(method.contains(r#"<arg name="invocation_id" type="ay" direction="out"/>"#));
    }

    #[test]
    fn get_unit_by_invocation_id_uses_live_candidate_runtime_state() {
        let (interface, _, _, _) = test_interface();
        let invocation_id = [
            0x4a, 0x8b, 0x81, 0x15, 0x50, 0xcb, 0x4f, 0xa4, 0x97, 0x7d, 0x47, 0x59, 0x0f, 0x57,
            0xad, 0x29,
        ];
        interface.snapshot.write().unwrap().push(UnitInfo {
            name: "invocation.service".into(),
            description: "Invocation service".into(),
            load_state: "loaded".into(),
            active_state: "active".into(),
            sub_state: "running".into(),
            main_pid: None,
            unit_type: "service".into(),
            service_type: Some("simple".into()),
            restart_policy: Some("no".into()),
            service_runtime: Box::new(crate::ipc::ServiceRuntimeInfo {
                invocation_id: Some(invocation_id),
                ..Default::default()
            }),
        });

        assert_eq!(
            interface
                .get_unit_by_invocation_id_for_id(invocation_id)
                .unwrap()
                .0,
            invocation_id_path(&invocation_id).unwrap()
        );

        for invalid in [Vec::new(), vec![0; 15], vec![0; 17]] {
            let error = <[u8; 16]>::try_from(invalid)
                .map_err(|_| {
                    InvocationIdLookupError::InvalidArgs("Invalid invocation ID".to_owned())
                })
                .unwrap_err();
            assert_eq!(
                zbus::DBusError::name(&error).as_str(),
                "io.rustd.DBus.Error.InvalidArgs"
            );
            assert_eq!(
                zbus::DBusError::description(&error),
                Some("Invalid invocation ID")
            );
        }

        let unknown_id = [1u8; 16];
        let unknown = interface
            .get_unit_by_invocation_id_for_id(unknown_id)
            .unwrap_err();
        assert_eq!(
            zbus::DBusError::name(&unknown).as_str(),
            "io.rustd.Manager1.NoUnitForInvocationID"
        );
        assert_eq!(
            zbus::DBusError::description(&unknown),
            Some(
                "No unit with the specified invocation ID 01010101010101010101010101010101 known."
            )
        );

        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        let method = xml
            .split(r#"<method name="GetUnitByInvocationID">"#)
            .nth(1)
            .and_then(|rest| rest.split("</method>").next())
            .unwrap();
        assert!(method.contains(r#"<arg name="invocation_id" type="ay" direction="in"/>"#));
        assert!(method.contains(r#"<arg name="unit" type="o" direction="out"/>"#));

        let caller = interface.get_unit_by_invocation_id_for_pid(0).unwrap_err();
        assert_eq!(
            zbus::DBusError::name(&caller).as_str(),
            "io.rustd.Manager1.NoSuchUnit"
        );
        assert_eq!(
            zbus::DBusError::description(&caller),
            Some("Client PID does not belong to any unit.")
        );
    }

    #[allow(clippy::too_many_lines)]
    #[test]
    fn kill_unit_uses_candidate_pids_cgroup_and_v261_error_contract() {
        use std::os::unix::process::ExitStatusExt;
        use std::process::Command;

        let (mut interface, _, _, _) = test_interface();
        let temporary = tempfile::tempdir().unwrap();
        interface.cgroup = CgroupManager::with_root(temporary.path());
        interface.cgroup.setup_root().unwrap();
        interface
            .cgroup
            .create_unit_cgroup("killable.service")
            .unwrap();

        let mut child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let pid = i32::try_from(child.id()).unwrap();
        let procs = interface.cgroup.unit_procs_path("killable.service");
        std::fs::write(procs, format!("{pid}\n")).unwrap();
        interface.snapshot.write().unwrap().push(UnitInfo {
            name: "killable.service".into(),
            description: "Killable service".into(),
            load_state: "loaded".into(),
            active_state: "active".into(),
            sub_state: "running".into(),
            main_pid: Some(pid),
            unit_type: "service".into(),
            service_type: Some("simple".into()),
            restart_policy: Some("no".into()),
            service_runtime: Box::default(),
        });

        interface
            .kill_unit_for_request("killable.service", "all", libc::SIGTERM)
            .unwrap();
        assert_eq!(child.wait().unwrap().signal(), Some(libc::SIGTERM));

        for (name, whom, signal, expected_name, expected_description) in [
            (
                "missing.service",
                "all",
                libc::SIGTERM,
                "io.rustd.Manager1.NoSuchUnit",
                "Unit missing.service not loaded.",
            ),
            (
                "killable.service",
                "invalid",
                libc::SIGTERM,
                "io.rustd.DBus.Error.InvalidArgs",
                "Invalid whom argument: invalid",
            ),
            (
                "killable.service",
                "all",
                0,
                "io.rustd.DBus.Error.InvalidArgs",
                "Signal number out of range.",
            ),
        ] {
            let error = interface
                .kill_unit_for_request(name, whom, signal)
                .unwrap_err();
            assert_eq!(zbus::DBusError::name(&error).as_str(), expected_name);
            assert_eq!(
                zbus::DBusError::description(&error),
                Some(expected_description)
            );
        }

        interface
            .cgroup
            .create_unit_cgroup("empty.service")
            .unwrap();
        interface.snapshot.write().unwrap().push(UnitInfo {
            name: "empty.service".into(),
            description: "Empty service".into(),
            load_state: "loaded".into(),
            active_state: "inactive".into(),
            sub_state: "dead".into(),
            main_pid: None,
            unit_type: "service".into(),
            service_type: Some("oneshot".into()),
            restart_policy: Some("no".into()),
            service_runtime: Box::default(),
        });
        let no_process = interface
            .kill_unit_for_request("empty.service", "all-fail", libc::SIGTERM)
            .unwrap_err();
        assert_eq!(
            zbus::DBusError::name(&no_process).as_str(),
            "io.rustd.Manager1.NoSuchProcess"
        );
        assert_eq!(
            zbus::DBusError::description(&no_process),
            Some("No matching processes to kill")
        );

        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        let method = xml
            .split(r#"<method name="KillUnit">"#)
            .nth(1)
            .and_then(|rest| rest.split("</method>").next())
            .unwrap();
        for argument in [
            r#"<arg name="name" type="s" direction="in"/>"#,
            r#"<arg name="whom" type="s" direction="in"/>"#,
            r#"<arg name="signal" type="i" direction="in"/>"#,
        ] {
            assert!(method.contains(argument));
        }
    }

    #[allow(clippy::too_many_lines)]
    #[test]
    fn kill_subgroup_and_queue_signal_use_real_cgroup_and_pid_delivery() {
        use std::os::unix::process::ExitStatusExt;
        use std::process::Command;

        let (mut interface, _, _, _) = test_interface();
        let temporary = tempfile::tempdir().unwrap();
        interface.cgroup = CgroupManager::with_root(temporary.path());
        interface.cgroup.setup_root().unwrap();

        interface
            .cgroup
            .create_unit_cgroup("subgroup.service")
            .unwrap();
        let subgroup = interface
            .cgroup
            .unit_procs_path("subgroup.service")
            .parent()
            .unwrap()
            .join("worker");
        std::fs::create_dir_all(&subgroup).unwrap();
        let mut subgroup_child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let subgroup_pid = i32::try_from(subgroup_child.id()).unwrap();
        std::fs::write(subgroup.join("cgroup.procs"), format!("{subgroup_pid}\n")).unwrap();
        interface.snapshot.write().unwrap().push(UnitInfo {
            name: "subgroup.service".into(),
            description: "Subgroup service".into(),
            load_state: "loaded".into(),
            active_state: "active".into(),
            sub_state: "running".into(),
            main_pid: None,
            unit_type: "service".into(),
            service_type: Some("simple".into()),
            restart_policy: Some("no".into()),
            service_runtime: Box::default(),
        });

        interface
            .kill_unit_subgroup_for_request("subgroup.service", "", "worker", libc::SIGTERM)
            .unwrap();
        assert_eq!(subgroup_child.wait().unwrap().signal(), Some(libc::SIGTERM));

        interface
            .cgroup
            .create_unit_cgroup("queued.service")
            .unwrap();
        let mut queued_child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let queued_pid = i32::try_from(queued_child.id()).unwrap();
        interface.snapshot.write().unwrap().push(UnitInfo {
            name: "queued.service".into(),
            description: "Queued service".into(),
            load_state: "loaded".into(),
            active_state: "active".into(),
            sub_state: "running".into(),
            main_pid: Some(queued_pid),
            unit_type: "service".into(),
            service_type: Some("simple".into()),
            restart_policy: Some("no".into()),
            service_runtime: Box::default(),
        });
        interface
            .queue_signal_unit_for_request("queued.service", "main", libc::SIGRTMIN(), 42)
            .unwrap();
        assert_eq!(
            queued_child.wait().unwrap().signal(),
            Some(libc::SIGRTMIN())
        );

        let invalid_subgroup = interface
            .kill_unit_subgroup_for_request("queued.service", "cgroup", "../escape", libc::SIGTERM)
            .unwrap_err();
        assert_eq!(
            zbus::DBusError::description(&invalid_subgroup),
            Some("Specified cgroup sub-path is not valid.")
        );
        let invalid_value = interface
            .queue_signal_unit_for_request("queued.service", "main", libc::SIGTERM, 42)
            .unwrap_err();
        assert_eq!(
            zbus::DBusError::description(&invalid_value),
            Some("Value parameter only accepted for realtime signals (SIGRTMIN…SIGRTMAX), refusing for signal SIGTERM.")
        );

        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        for (name, args) in [
            (
                "KillUnitSubgroup",
                [
                    r#"<arg name="name" type="s" direction="in"/>"#,
                    r#"<arg name="whom" type="s" direction="in"/>"#,
                    r#"<arg name="subgroup" type="s" direction="in"/>"#,
                    r#"<arg name="signal" type="i" direction="in"/>"#,
                ],
            ),
            (
                "QueueSignalUnit",
                [
                    r#"<arg name="name" type="s" direction="in"/>"#,
                    r#"<arg name="whom" type="s" direction="in"/>"#,
                    r#"<arg name="signal" type="i" direction="in"/>"#,
                    r#"<arg name="value" type="i" direction="in"/>"#,
                ],
            ),
        ] {
            let method = xml
                .split(&format!(r#"<method name="{name}">"#))
                .nth(1)
                .and_then(|rest| rest.split("</method>").next())
                .unwrap();
            for arg in args {
                assert!(method.contains(arg), "{name} missing {arg}");
            }
        }
    }

    #[test]
    fn get_unit_processes_reads_the_live_managed_cgroup_tree() {
        let (mut interface, _, _, _) = test_interface();
        let temporary = tempfile::tempdir().unwrap();
        interface.cgroup = CgroupManager::with_root(temporary.path());
        let cgroup_procs = interface.cgroup.unit_procs_path("demo.service");
        let cgroup_root = cgroup_procs.parent().unwrap();
        let nested = cgroup_root.join("worker.scope");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(
            nested.join("cgroup.procs"),
            format!("{}\n", std::process::id()),
        )
        .unwrap();

        let (processes,) = interface.get_unit_processes("demo.service".into()).unwrap();
        assert_eq!(
            processes,
            vec![(
                "/system.slice/demo.service/worker.scope".to_owned(),
                std::process::id(),
                process_command_line(std::process::id()).unwrap(),
            )]
        );
    }

    #[test]
    fn get_unit_processes_matches_v261_error_and_introspection_contract() {
        let (interface, _, _, _) = test_interface();

        let missing = interface
            .get_unit_processes("no-such-unit-for-parity.service".into())
            .unwrap_err();
        assert_eq!(
            zbus::DBusError::name(&missing).as_str(),
            "io.rustd.Manager1.NoSuchUnit"
        );
        assert_eq!(
            zbus::DBusError::description(&missing),
            Some("Unit no-such-unit-for-parity.service not loaded.")
        );

        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        let method = xml
            .split(r#"<method name="GetUnitProcesses">"#)
            .nth(1)
            .and_then(|rest| rest.split("</method>").next())
            .unwrap();
        assert!(method.contains(r#"<arg name="name" type="s" direction="in"/>"#));
        assert!(method.contains(r#"<arg name="processes" type="a(sus)" direction="out"/>"#));
    }

    #[test]
    fn dynamic_user_queries_reflect_live_candidate_snapshot_allocations() {
        let (interface, _, _, _) = test_interface();
        let alpha_runtime = crate::ipc::ServiceRuntimeInfo {
            dynamic_user: Some(crate::ipc::DynamicUserInfo {
                uid: 61_184,
                name: "alpha.service".into(),
            }),
            ..Default::default()
        };
        let beta_runtime = crate::ipc::ServiceRuntimeInfo {
            dynamic_user: Some(crate::ipc::DynamicUserInfo {
                uid: 61_185,
                name: "beta.service".into(),
            }),
            ..Default::default()
        };
        interface.snapshot.write().unwrap().extend([
            UnitInfo {
                name: "alpha.service".into(),
                description: "Alpha dynamic user".into(),
                load_state: "loaded".into(),
                active_state: "active".into(),
                sub_state: "running".into(),
                main_pid: None,
                unit_type: "service".into(),
                service_type: Some("simple".into()),
                restart_policy: Some("no".into()),
                service_runtime: Box::new(alpha_runtime),
            },
            UnitInfo {
                name: "beta.service".into(),
                description: "Beta dynamic user".into(),
                load_state: "loaded".into(),
                active_state: "active".into(),
                sub_state: "running".into(),
                main_pid: None,
                unit_type: "service".into(),
                service_type: Some("simple".into()),
                restart_policy: Some("no".into()),
                service_runtime: Box::new(beta_runtime),
            },
        ]);

        assert_eq!(
            interface.get_dynamic_users().unwrap().0,
            vec![
                (61_184, "alpha.service".to_owned()),
                (61_185, "beta.service".to_owned()),
            ]
        );
        assert_eq!(
            interface
                .lookup_dynamic_user_by_name("beta.service".into())
                .unwrap(),
            (61_185,)
        );
        assert_eq!(
            interface.lookup_dynamic_user_by_uid(61_184).unwrap(),
            ("alpha.service".to_owned(),)
        );
    }

    #[test]
    fn dynamic_user_queries_match_v261_errors_and_introspection() {
        let (mut interface, _, _, _) = test_interface();

        let invalid_name = interface
            .lookup_dynamic_user_by_name(String::new())
            .unwrap_err();
        assert_eq!(
            zbus::DBusError::name(&invalid_name).as_str(),
            "io.rustd.DBus.Error.InvalidArgs"
        );
        assert_eq!(
            zbus::DBusError::description(&invalid_name),
            Some("User name invalid: ")
        );
        let invalid_path = interface
            .lookup_dynamic_user_by_name("../bad".into())
            .unwrap_err();
        assert_eq!(
            zbus::DBusError::name(&invalid_path).as_str(),
            "io.rustd.DBus.Error.InvalidArgs"
        );
        assert_eq!(
            zbus::DBusError::description(&invalid_path),
            Some("User name invalid: ../bad")
        );
        let unknown_name = interface
            .lookup_dynamic_user_by_name("no-such-user-for-parity".into())
            .unwrap_err();
        assert_eq!(
            zbus::DBusError::name(&unknown_name).as_str(),
            "io.rustd.Manager1.NoSuchDynamicUser"
        );
        assert_eq!(
            zbus::DBusError::description(&unknown_name),
            Some("Dynamic user no-such-user-for-parity does not exist.")
        );
        let invalid_uid = interface.lookup_dynamic_user_by_uid(u32::MAX).unwrap_err();
        assert_eq!(
            zbus::DBusError::name(&invalid_uid).as_str(),
            "io.rustd.DBus.Error.InvalidArgs"
        );
        assert_eq!(
            zbus::DBusError::description(&invalid_uid),
            Some("User ID invalid: 4294967295")
        );
        let unknown_uid = interface.lookup_dynamic_user_by_uid(61_234).unwrap_err();
        assert_eq!(
            zbus::DBusError::name(&unknown_uid).as_str(),
            "io.rustd.Manager1.NoSuchDynamicUser"
        );
        assert_eq!(
            zbus::DBusError::description(&unknown_uid),
            Some("Dynamic user ID 61234 does not exist.")
        );

        interface.scope = ManagerScope::User;
        for error in [
            interface.get_dynamic_users().unwrap_err(),
            interface
                .lookup_dynamic_user_by_name("alpha".into())
                .unwrap_err(),
            interface.lookup_dynamic_user_by_uid(61_184).unwrap_err(),
        ] {
            assert_eq!(
                zbus::DBusError::name(&error).as_str(),
                "io.rustd.DBus.Error.NotSupported"
            );
            assert_eq!(
                zbus::DBusError::description(&error),
                Some("Dynamic users are only supported in the system instance.")
            );
        }

        interface.scope = ManagerScope::System;
        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        for (name, input, output) in [
            (
                "LookupDynamicUserByName",
                "name=\"name\" type=\"s\"",
                "name=\"uid\" type=\"u\"",
            ),
            (
                "LookupDynamicUserByUID",
                "name=\"uid\" type=\"u\"",
                "name=\"name\" type=\"s\"",
            ),
            ("GetDynamicUsers", "", "name=\"users\" type=\"a(us)\""),
        ] {
            let method = xml
                .split(&format!(r#"<method name="{name}">"#))
                .nth(1)
                .and_then(|rest| rest.split("</method>").next())
                .unwrap();
            if !input.is_empty() {
                assert!(method.contains(&format!(r#"<arg {input} direction="in"/>"#)));
            }
            assert!(method.contains(&format!(r#"<arg {output} direction="out"/>"#)));
        }
    }

    #[test]
    fn descriptor_store_dump_reflects_live_candidate_service_configuration() {
        fn unit(name: &str, unit_type: &str, store_max: u32) -> UnitInfo {
            UnitInfo {
                name: name.into(),
                description: name.into(),
                load_state: "loaded".into(),
                active_state: "active".into(),
                sub_state: "running".into(),
                main_pid: None,
                unit_type: unit_type.into(),
                service_type: (unit_type == "service").then(|| "simple".into()),
                restart_policy: (unit_type == "service").then(|| "no".into()),
                service_runtime: Box::new(crate::ipc::ServiceRuntimeInfo {
                    file_descriptor_store_max: store_max,
                    ..Default::default()
                }),
            }
        }

        let (interface, _, _, _) = test_interface();
        interface.snapshot.write().unwrap().extend([
            unit("enabled.service", "service", 4),
            unit("disabled.service", "service", 0),
            unit("not-a-service.target", "target", 0),
        ]);
        assert_eq!(
            interface
                .dump_unit_file_descriptor_store("enabled.service".into())
                .unwrap(),
            (Vec::new(),)
        );

        let disabled = interface
            .dump_unit_file_descriptor_store("disabled.service".into())
            .unwrap_err();
        assert_eq!(
            zbus::DBusError::name(&disabled).as_str(),
            "io.rustd.Manager1.FileDescriptorStoreDisabled"
        );
        assert_eq!(
            zbus::DBusError::description(&disabled),
            Some("File descriptor store not enabled for disabled.service.")
        );

        let unsupported = interface
            .dump_unit_file_descriptor_store("not-a-service.target".into())
            .unwrap_err();
        assert_eq!(
            zbus::DBusError::name(&unsupported).as_str(),
            "io.rustd.DBus.Error.NotSupported"
        );
        assert_eq!(
            zbus::DBusError::description(&unsupported),
            Some("DumpUnitFileDescriptorStore operation is not supported for unit type 'target'")
        );

        let missing = interface
            .dump_unit_file_descriptor_store("missing.service".into())
            .unwrap_err();
        assert_eq!(
            zbus::DBusError::name(&missing).as_str(),
            "io.rustd.Manager1.NoSuchUnit"
        );
        assert_eq!(
            zbus::DBusError::description(&missing),
            Some("Unit missing.service not loaded.")
        );

        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        let method = xml
            .split(r#"<method name="DumpUnitFileDescriptorStore">"#)
            .nth(1)
            .and_then(|rest| rest.split("</method>").next())
            .unwrap();
        assert!(method.contains(r#"<arg name="name" type="s" direction="in"/>"#));
        assert!(method.contains(r#"<arg name="entries" type="a(suuutuusu)" direction="out"/>"#));
    }

    #[test]
    fn diagnostic_dumps_reflect_live_units_and_jobs() {
        let (interface, _, _, _) = test_interface();
        interface.snapshot.write().unwrap().extend([
            UnitInfo {
                name: "alpha.service".into(),
                description: "Alpha service".into(),
                load_state: "loaded".into(),
                active_state: "active".into(),
                sub_state: "running".into(),
                main_pid: Some(1234),
                unit_type: "service".into(),
                service_type: Some("simple".into()),
                restart_policy: Some("no".into()),
                service_runtime: Box::default(),
            },
            UnitInfo {
                name: "beta.service".into(),
                description: "Beta service".into(),
                load_state: "loaded".into(),
                active_state: "inactive".into(),
                sub_state: "dead".into(),
                main_pid: None,
                unit_type: "service".into(),
                service_type: Some("oneshot".into()),
                restart_policy: Some("no".into()),
                service_runtime: Box::default(),
            },
        ]);
        let job = interface
            .enqueue(JobKind::Start, "alpha.service", None)
            .unwrap();

        let (dump,) = interface.dump().unwrap();
        assert!(dump.starts_with("Manager: rustd 261\nUnits: 2\nJobs: 1\n"));
        assert!(dump.contains("→ Unit alpha.service:\n\tDescription: Alpha service\n"));
        assert!(dump.contains(
            "→ Unit beta.service:\n\tDescription: Beta service\n\tUnit Load State: loaded\n\tUnit Active State: inactive\n"
        ));
        assert!(dump.contains(&format!("→ Job {}:\n\tUnit: alpha.service\n", job.id)));

        let (empty_patterns,) = interface.dump_units_matching_patterns(Vec::new()).unwrap();
        assert_eq!(empty_patterns, dump);
        let (filtered,) = interface
            .dump_units_matching_patterns(vec!["alpha.*".into()])
            .unwrap();
        assert!(!filtered.contains("Manager: rustd"));
        assert!(filtered.contains("→ Unit alpha.service:"));
        assert!(filtered.contains(&format!("→ Job {}:", job.id)));
        assert!(!filtered.contains("beta.service"));
        assert_eq!(
            interface
                .dump_units_matching_patterns(vec!["no-such-unit-for-parity*".into()])
                .unwrap(),
            (String::new(),)
        );
    }

    #[test]
    fn diagnostic_dump_file_descriptors_match_string_output_and_are_sealed() {
        use std::os::fd::AsRawFd;

        let (interface, _, _, _) = test_interface();
        interface.snapshot.write().unwrap().push(UnitInfo {
            name: "alpha.service".into(),
            description: "Alpha service".into(),
            load_state: "loaded".into(),
            active_state: "active".into(),
            sub_state: "running".into(),
            main_pid: None,
            unit_type: "service".into(),
            service_type: Some("simple".into()),
            restart_policy: Some("no".into()),
            service_runtime: Box::default(),
        });

        let (string_dump,) = interface.dump().unwrap();
        let (fd,) = interface.dump_by_file_descriptor().unwrap();
        assert_eq!(read_dump_fd(fd.as_raw_fd()), string_dump);
        let expected_seals =
            libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
        assert_eq!(
            unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS) },
            expected_seals
        );

        let (filtered_string,) = interface
            .dump_units_matching_patterns(vec!["alpha.*".into()])
            .unwrap();
        let (filtered_fd,) = interface
            .dump_units_matching_patterns_by_file_descriptor(vec!["alpha.*".into()])
            .unwrap();
        assert_eq!(read_dump_fd(filtered_fd.as_raw_fd()), filtered_string);
    }

    #[test]
    fn diagnostic_dumps_match_v261_limit_error_and_introspection_contract() {
        let (interface, _, _, _) = test_interface();
        for error in [
            interface
                .dump_units_matching_patterns(vec![String::new(); MAX_PATTERNS_PER_CALL + 1])
                .unwrap_err(),
            interface
                .dump_units_matching_patterns_by_file_descriptor(vec![
                    String::new();
                    MAX_PATTERNS_PER_CALL + 1
                ])
                .unwrap_err(),
        ] {
            assert_eq!(
                zbus::DBusError::name(&error).as_str(),
                "io.rustd.DBus.Error.LimitsExceeded"
            );
            assert_eq!(
                zbus::DBusError::description(&error),
                Some("Too many patterns in a single query.")
            );
        }

        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        for (name, input, output) in [
            ("Dump", "", "name=\"output\" type=\"s\""),
            (
                "DumpUnitsMatchingPatterns",
                "name=\"patterns\" type=\"as\"",
                "name=\"output\" type=\"s\"",
            ),
            ("DumpByFileDescriptor", "", "name=\"fd\" type=\"h\""),
            (
                "DumpUnitsMatchingPatternsByFileDescriptor",
                "name=\"patterns\" type=\"as\"",
                "name=\"fd\" type=\"h\"",
            ),
        ] {
            let method = xml
                .split(&format!(r#"<method name="{name}">"#))
                .nth(1)
                .and_then(|rest| rest.split("</method>").next())
                .unwrap();
            if !input.is_empty() {
                assert!(method.contains(&format!(r#"<arg {input} direction="in"/>"#)));
            }
            assert!(method.contains(&format!(r#"<arg {output} direction="out"/>"#)));
        }
    }

    #[test]
    fn get_unit_by_control_group_uses_real_cgroups_and_closest_ancestor() {
        let (mut interface, _, _, _) = test_interface();
        let temporary = tempfile::tempdir().unwrap();
        interface.cgroup = CgroupManager::with_root(temporary.path());
        interface.cgroup.setup_root().unwrap();
        interface.cgroup.create_unit_cgroup("demo.service").unwrap();
        interface.snapshot.write().unwrap().extend([
            UnitInfo {
                name: "system.slice".into(),
                description: "System Slice".into(),
                load_state: "loaded".into(),
                active_state: "active".into(),
                sub_state: "active".into(),
                main_pid: None,
                unit_type: "slice".into(),
                service_type: None,
                restart_policy: None,
                service_runtime: Box::default(),
            },
            UnitInfo {
                name: "demo.service".into(),
                description: "Demo service".into(),
                load_state: "loaded".into(),
                active_state: "active".into(),
                sub_state: "running".into(),
                main_pid: None,
                unit_type: "service".into(),
                service_type: Some("simple".into()),
                restart_policy: Some("no".into()),
                service_runtime: Box::default(),
            },
            UnitInfo {
                name: "unmanaged.service".into(),
                description: "No cgroup".into(),
                load_state: "loaded".into(),
                active_state: "inactive".into(),
                sub_state: "dead".into(),
                main_pid: None,
                unit_type: "service".into(),
                service_type: Some("simple".into()),
                restart_policy: Some("no".into()),
                service_runtime: Box::default(),
            },
        ]);

        assert_eq!(
            interface
                .get_unit_by_control_group("/system.slice".into())
                .unwrap()
                .0,
            unit_path("system.slice").unwrap()
        );
        assert_eq!(
            interface
                .get_unit_by_control_group("/system.slice/demo.service/child".into())
                .unwrap()
                .0,
            unit_path("demo.service").unwrap()
        );
        assert_eq!(
            interface
                .get_unit_by_control_group("/system.slice/".into())
                .unwrap()
                .0,
            unit_path("system.slice").unwrap()
        );

        assert_eq!(
            interface
                .get_unit_by_control_group("/system.slice/unmanaged.service".into())
                .unwrap()
                .0,
            unit_path("system.slice").unwrap()
        );

        let missing = interface
            .get_unit_by_control_group("/unmanaged.slice".into())
            .unwrap_err();
        assert_eq!(
            zbus::DBusError::name(&missing).as_str(),
            "io.rustd.Manager1.NoSuchUnit"
        );
        assert_eq!(
            zbus::DBusError::description(&missing),
            Some("Control group '/unmanaged.slice' is not valid or not managed by this instance")
        );
    }

    #[test]
    fn get_unit_by_control_group_validates_paths_and_introspection() {
        let (interface, _, _, _) = test_interface();

        for (path, description) in [
            ("relative", "Control group path is not absolute: relative"),
            (
                "/system.slice/../system.slice",
                "Control group path is not normalized: /system.slice/../system.slice",
            ),
            (
                "/system.slice//demo.service",
                "Control group path is not normalized: /system.slice//demo.service",
            ),
            (
                "/system.slice/./demo.service",
                "Control group path is not normalized: /system.slice/./demo.service",
            ),
        ] {
            let error = interface
                .get_unit_by_control_group(path.into())
                .unwrap_err();
            assert_eq!(
                zbus::DBusError::name(&error).as_str(),
                "io.rustd.DBus.Error.InvalidArgs"
            );
            assert_eq!(zbus::DBusError::description(&error), Some(description));
        }

        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        let method = xml
            .split(r#"<method name="GetUnitByControlGroup">"#)
            .nth(1)
            .and_then(|rest| rest.split("</method>").next())
            .unwrap();
        assert!(method.contains(r#"<arg name="cgroup" type="s" direction="in"/>"#));
        assert!(method.contains(r#"<arg name="unit" type="o" direction="out"/>"#));
    }

    #[test]
    fn get_unit_requires_a_loaded_unit() {
        let (interface, _, _, _) = test_interface();
        interface.snapshot.write().unwrap().push(UnitInfo {
            name: "foo.service".into(),
            description: "Test service".into(),
            load_state: "loaded".into(),
            active_state: "inactive".into(),
            sub_state: "dead".into(),
            main_pid: None,
            unit_type: "service".into(),
            service_type: Some("simple".into()),
            restart_policy: Some("no".into()),
            service_runtime: Box::default(),
        });

        assert_eq!(
            interface.get_explicit_unit("foo.service").unwrap(),
            unit_path("foo.service").unwrap()
        );
        let missing = interface
            .get_explicit_unit("no-such-unit-for-parity.service")
            .unwrap_err();
        assert_eq!(
            zbus::DBusError::name(&missing).as_str(),
            "io.rustd.Manager1.NoSuchUnit"
        );
        assert_eq!(
            zbus::DBusError::description(&missing),
            Some("Unit no-such-unit-for-parity.service not loaded.")
        );

        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        let xml: String = xml
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        assert!(xml.contains(
            "<methodname=\"GetUnit\"><argname=\"name\"type=\"s\"direction=\"in\"/><argname=\"unit\"type=\"o\"direction=\"out\"/></method>"
        ));
    }

    #[test]
    fn ref_unit_tracks_recursive_sender_counts_and_v261_errors() {
        let (interface, _, _, _) = test_interface();
        interface.snapshot.write().unwrap().push(UnitInfo {
            name: "foo.service".into(),
            description: "Test service".into(),
            load_state: "loaded".into(),
            active_state: "inactive".into(),
            sub_state: "dead".into(),
            main_pid: None,
            unit_type: "service".into(),
            service_type: Some("simple".into()),
            restart_policy: Some("no".into()),
            service_runtime: Box::default(),
        });

        interface
            .add_unit_reference(":1.42", "foo.service")
            .unwrap();
        interface
            .add_unit_reference(":1.42", "foo.service")
            .unwrap();
        interface
            .add_unit_reference(":1.43", "foo.service")
            .unwrap();
        assert_eq!(
            interface
                .unit_references
                .lock()
                .unwrap()
                .get(&(":1.42".into(), "foo.service".into())),
            Some(&2)
        );

        interface
            .remove_unit_reference(":1.42", "foo.service")
            .unwrap();
        assert_eq!(
            interface
                .unit_references
                .lock()
                .unwrap()
                .get(&(":1.42".into(), "foo.service".into())),
            Some(&1)
        );
        interface
            .remove_unit_reference(":1.42", "foo.service")
            .unwrap();
        assert!(!interface
            .unit_references
            .lock()
            .unwrap()
            .contains_key(&(":1.42".into(), "foo.service".into())));

        let not_referenced = interface
            .remove_unit_reference(":1.42", "foo.service")
            .unwrap_err();
        assert_eq!(
            zbus::DBusError::name(&not_referenced).as_str(),
            "io.rustd.Manager1.NotReferenced"
        );
        assert_eq!(
            zbus::DBusError::description(&not_referenced),
            Some("Unit has not been referenced yet.")
        );

        clear_unit_references_for_sender(&interface.unit_references, ":1.43");
        assert!(interface.unit_references.lock().unwrap().is_empty());

        let masked = validate_reference_unit_load_state("foo.service", "masked").unwrap_err();
        assert_eq!(
            zbus::DBusError::name(&masked).as_str(),
            "io.rustd.Manager1.UnitMasked"
        );
        let invalid = validate_reference_unit_load_state("foo.service", "bad-setting").unwrap_err();
        assert_eq!(
            zbus::DBusError::name(&invalid).as_str(),
            "io.rustd.Manager1.BadUnitSetting"
        );

        let interface = ManagerInterfaceApi::new(interface);
        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        for method in ["RefUnit", "UnrefUnit"] {
            let method_xml = xml
                .split(&format!(r#"<method name="{method}">"#))
                .nth(1)
                .and_then(|rest| rest.split("</method>").next())
                .expect("unit reference method must be exported");
            assert!(method_xml.contains(r#"<arg name="name" type="s" direction="in"/>"#));
        }
    }

    #[test]
    fn unit_file_queries_preserve_lookup_error_classes() {
        let (interface, _, _, _) = test_interface();
        let host_state =
            query_root_enable_state_checked("systemd-journald.service", std::path::Path::new("/"))
                .unwrap()
                .to_string();
        assert_eq!(
            interface
                .get_unit_file_state("systemd-journald.service".into())
                .unwrap(),
            (host_state,)
        );
        assert_eq!(
            interface.get_default_target().unwrap(),
            (query_system_default_target().unwrap(),)
        );

        let missing = interface
            .get_unit_file_state("no-such-unit-for-parity.service".into())
            .unwrap_err();
        assert_eq!(
            zbus::DBusError::name(&missing).as_str(),
            "io.rustd.DBus.Error.FileNotFound"
        );
        assert_eq!(
            zbus::DBusError::description(&missing),
            Some("No such file or directory")
        );

        let invalid = interface
            .get_unit_file_state("../invalid.service".into())
            .unwrap_err();
        assert_eq!(
            zbus::DBusError::name(&invalid).as_str(),
            "io.rustd.DBus.Error.InvalidArgs"
        );
        assert_eq!(
            zbus::DBusError::description(&invalid),
            Some("Invalid argument")
        );

        let masked: UnitFileMethodError = UnitFileLookupError::DefaultTargetMasked.into();
        assert_eq!(
            zbus::DBusError::name(&masked).as_str(),
            "io.rustd.Manager1.UnitMasked"
        );
    }

    #[test]
    fn get_unit_file_links_matches_v261_signature_and_invalid_name_error() {
        let (interface, _, _, _) = test_interface();
        let (missing,) = interface
            .get_unit_file_links("no-such-unit-for-parity.service".into(), false)
            .unwrap();
        assert!(missing.is_empty());

        let invalid = interface
            .get_unit_file_links("../invalid.service".into(), false)
            .unwrap_err();
        assert_eq!(
            zbus::DBusError::name(&invalid).as_str(),
            "System.Error.EUCLEAN"
        );
        assert_eq!(
            zbus::DBusError::description(&invalid),
            Some("Structure needs cleaning")
        );

        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        assert!(xml.contains(r#"<method name="GetUnitFileLinks">"#));
        assert!(xml.contains(r#"<arg name="name" type="s" direction="in"/>"#));
        assert!(xml.contains(r#"<arg name="runtime" type="b" direction="in"/>"#));
        assert!(xml.contains(r#"<arg name="links" type="as" direction="out"/>"#));
    }

    #[test]
    fn revert_unit_files_matches_v261_signature() {
        let (interface, _, _, _) = test_interface();
        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        assert!(xml.contains(r#"<method name="RevertUnitFiles">"#));
        assert!(xml.contains(r#"<arg name="files" type="as" direction="in"/>"#));
        assert!(xml.contains(r#"<arg name="changes" type="a(sss)" direction="out"/>"#));
    }

    #[test]
    fn preset_unit_file_methods_match_v261_signatures() {
        let (interface, _, _, _) = test_interface();
        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);

        let preset = xml
            .split(r#"<method name="PresetUnitFiles">"#)
            .nth(1)
            .and_then(|rest| rest.split("</method>").next())
            .expect("PresetUnitFiles must be exported");
        for argument in [
            r#"<arg name="files" type="as" direction="in"/>"#,
            r#"<arg name="runtime" type="b" direction="in"/>"#,
            r#"<arg name="force" type="b" direction="in"/>"#,
            r#"<arg name="carries_install_info" type="b" direction="out"/>"#,
            r#"<arg name="changes" type="a(sss)" direction="out"/>"#,
        ] {
            assert!(preset.contains(argument), "missing {argument}");
        }

        let with_mode = xml
            .split(r#"<method name="PresetUnitFilesWithMode">"#)
            .nth(1)
            .and_then(|rest| rest.split("</method>").next())
            .expect("PresetUnitFilesWithMode must be exported");
        assert!(with_mode.contains(r#"<arg name="mode" type="s" direction="in"/>"#));

        let all = xml
            .split(r#"<method name="PresetAllUnitFiles">"#)
            .nth(1)
            .and_then(|rest| rest.split("</method>").next())
            .expect("PresetAllUnitFiles must be exported");
        assert!(all.contains(r#"<arg name="mode" type="s" direction="in"/>"#));
        assert!(all.contains(r#"<arg name="changes" type="a(sss)" direction="out"/>"#));
    }

    #[test]
    fn manager_output_argument_names_match_v261() {
        let (interface, _, _, _) = test_interface();
        let interface = ManagerInterfaceApi::new(interface);
        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);

        let method = |name: &str| {
            xml.split(&format!(r#"<method name="{name}">"#))
                .nth(1)
                .and_then(|rest| rest.split("</method>").next())
                .unwrap_or_else(|| panic!("{name} must be exported"))
        };
        for (name, argument) in [
            ("StartUnit", r#"<arg name="job" type="o" direction="out"/>"#),
            ("StopUnit", r#"<arg name="job" type="o" direction="out"/>"#),
            (
                "RestartUnit",
                r#"<arg name="job" type="o" direction="out"/>"#,
            ),
            (
                "GetDefaultTarget",
                r#"<arg name="name" type="s" direction="out"/>"#,
            ),
            ("GetJob", r#"<arg name="job" type="o" direction="out"/>"#),
            (
                "GetJobAfter",
                r#"<arg name="jobs" type="a(usssoo)" direction="out"/>"#,
            ),
            (
                "GetJobBefore",
                r#"<arg name="jobs" type="a(usssoo)" direction="out"/>"#,
            ),
            (
                "ListUnitFiles",
                r#"<arg name="unit_files" type="a(ss)" direction="out"/>"#,
            ),
            (
                "ListUnitFilesByPatterns",
                r#"<arg name="unit_files" type="a(ss)" direction="out"/>"#,
            ),
        ] {
            assert!(
                method(name).contains(argument),
                "missing {name}: {argument}"
            );
        }
        assert!(
            method("GetUnitFileState").contains(r#"<arg name="file" type="s" direction="in"/>"#)
        );
        assert!(
            method("GetUnitFileState").contains(r#"<arg name="state" type="s" direction="out"/>"#)
        );
    }

    #[test]
    fn add_dependency_unit_files_matches_v261_signature_and_errors() {
        let (interface, _, _, _) = test_interface();
        let interface = ManagerInterfaceApi::new(interface);
        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        let method = xml
            .split(r#"<method name="AddDependencyUnitFiles">"#)
            .nth(1)
            .and_then(|rest| rest.split("</method>").next())
            .expect("AddDependencyUnitFiles must be exported");
        for argument in [
            r#"<arg name="files" type="as" direction="in"/>"#,
            r#"<arg name="target" type="s" direction="in"/>"#,
            r#"<arg name="type" type="s" direction="in"/>"#,
            r#"<arg name="runtime" type="b" direction="in"/>"#,
            r#"<arg name="force" type="b" direction="in"/>"#,
            r#"<arg name="changes" type="a(sss)" direction="out"/>"#,
        ] {
            assert!(method.contains(argument), "missing {argument}");
        }

        let invalid_type = AddDependencyUnitFilesError::InvalidArgs("Invalid argument".into());
        assert_eq!(
            zbus::DBusError::name(&invalid_type).as_str(),
            "io.rustd.DBus.Error.InvalidArgs"
        );
        let bad_target = AddDependencyUnitFilesError::from_lookup(
            UnitFileLookupError::InvalidName("bad".into()),
            false,
        );
        assert_eq!(
            zbus::DBusError::name(&bad_target).as_str(),
            "io.rustd.Manager1.BadUnitSetting"
        );
        let invalid_file = AddDependencyUnitFilesError::from_lookup(
            UnitFileLookupError::InvalidName("../bad.service".into()),
            true,
        );
        assert_eq!(
            zbus::DBusError::description(&invalid_file),
            Some("File ../bad.service: Invalid argument")
        );
    }

    #[test]
    fn unit_file_flag_methods_match_v261_signatures() {
        let (interface, _, _, _) = test_interface();
        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        for method in [
            "EnableUnitFilesWithFlags",
            "DisableUnitFilesWithFlags",
            "DisableUnitFilesWithFlagsAndInstallInfo",
        ] {
            assert!(xml.contains(&format!(r#"<method name="{method}">"#)));
        }
        assert!(xml.contains(r#"<arg name="flags" type="t" direction="in"/>"#));
        assert!(xml.contains(r#"<arg name="carries_install_info" type="b" direction="out"/>"#));
    }

    #[test]
    fn enqueue_unit_job_matches_v261_signature() {
        let (interface, _, _, _) = test_interface();
        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        assert!(xml.contains(r#"<method name="EnqueueUnitJob">"#));
        for argument in [
            r#"<arg name="name" type="s" direction="in"/>"#,
            r#"<arg name="job_type" type="s" direction="in"/>"#,
            r#"<arg name="job_mode" type="s" direction="in"/>"#,
            r#"<arg name="job_id" type="u" direction="out"/>"#,
            r#"<arg name="job_path" type="o" direction="out"/>"#,
            r#"<arg name="unit_id" type="s" direction="out"/>"#,
            r#"<arg name="unit_path" type="o" direction="out"/>"#,
            r#"<arg name="affected_jobs" type="a(uosos)" direction="out"/>"#,
        ] {
            assert!(xml.contains(argument), "missing {argument}");
        }
    }

    #[test]
    fn list_unit_files_by_patterns_filters_names_and_states() {
        let entries = vec![
            (
                "/usr/lib/systemd/system/alpha.service".to_owned(),
                "enabled".to_owned(),
            ),
            (
                "/etc/systemd/system/alias.service".to_owned(),
                "alias".to_owned(),
            ),
            (
                "/run/systemd/generator/data.mount".to_owned(),
                "generated".to_owned(),
            ),
        ];

        assert_eq!(
            filter_unit_file_entries(
                entries.clone(),
                &["enabled".to_owned(), "generated".to_owned()],
                &["*.service".to_owned()],
            ),
            vec![(
                "/usr/lib/systemd/system/alpha.service".to_owned(),
                "enabled".to_owned(),
            )]
        );
        assert_eq!(
            filter_unit_file_entries(entries.clone(), &[], &["alpha.service".to_owned()],),
            vec![(
                "/usr/lib/systemd/system/alpha.service".to_owned(),
                "enabled".to_owned(),
            )]
        );
        assert!(filter_unit_file_entries(
            entries,
            &[],
            &["/usr/lib/systemd/system/alpha.service".to_owned()],
        )
        .is_empty());
    }

    #[test]
    fn list_units_filtered_matches_any_unit_state() {
        let (interface, _, _, _) = test_interface();
        interface.snapshot.write().unwrap().extend([
            UnitInfo {
                name: "active.service".into(),
                description: "Active service".into(),
                load_state: "loaded".into(),
                active_state: "active".into(),
                sub_state: "running".into(),
                main_pid: Some(1234),
                unit_type: "service".into(),
                service_type: Some("simple".into()),
                restart_policy: Some("no".into()),
                service_runtime: Box::default(),
            },
            UnitInfo {
                name: "failed.service".into(),
                description: "Failed service".into(),
                load_state: "loaded".into(),
                active_state: "failed".into(),
                sub_state: "failed".into(),
                main_pid: None,
                unit_type: "service".into(),
                service_type: Some("simple".into()),
                restart_policy: Some("no".into()),
                service_runtime: Box::default(),
            },
        ]);

        assert_eq!(interface.list_units().0.len(), 2);
        let (active,) = interface
            .list_units_filtered(vec!["active".into()])
            .unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].0, "active.service");
        assert_eq!(
            interface
                .list_units_filtered(vec!["running".into()])
                .unwrap()
                .0[0]
                .0,
            "active.service"
        );
        assert_eq!(
            interface
                .list_units_filtered(vec!["loaded".into()])
                .unwrap()
                .0
                .len(),
            2
        );
        assert!(interface
            .list_units_filtered(vec!["no-such-state".into()])
            .unwrap()
            .0
            .is_empty());
        let (matching,) = interface
            .list_units_by_patterns(vec!["loaded".into()], vec!["active*.service".into()])
            .unwrap();
        assert_eq!(matching.len(), 1);
        assert_eq!(matching[0].0, "active.service");
        assert!(interface
            .list_units_by_patterns(vec!["active".into()], vec!["failed-*.service".into()])
            .unwrap()
            .0
            .is_empty());
        assert!(matches!(
            interface.list_units_filtered(vec!["active".into(); MAX_STATES_PER_CALL + 1]),
            Err(zbus::fdo::Error::LimitsExceeded(_))
        ));
        assert!(matches!(
            interface.list_units_by_patterns(
                Vec::new(),
                vec!["*.service".into(); MAX_PATTERNS_PER_CALL + 1]
            ),
            Err(zbus::fdo::Error::LimitsExceeded(_))
        ));
    }

    #[test]
    fn core_listing_methods_have_v261_named_output_contracts() {
        let (interface, _, _, _) = test_interface();
        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        let xml: String = xml
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();

        for signature in [
            "<methodname=\"ListUnits\"><argname=\"units\"type=\"a(ssssssouso)\"direction=\"out\"/></method>",
            "<methodname=\"ListUnitsFiltered\"><argname=\"states\"type=\"as\"direction=\"in\"/><argname=\"units\"type=\"a(ssssssouso)\"direction=\"out\"/></method>",
            "<methodname=\"ListUnitsByPatterns\"><argname=\"states\"type=\"as\"direction=\"in\"/><argname=\"patterns\"type=\"as\"direction=\"in\"/><argname=\"units\"type=\"a(ssssssouso)\"direction=\"out\"/></method>",
            "<methodname=\"ListJobs\"><argname=\"jobs\"type=\"a(usssoo)\"direction=\"out\"/></method>",
        ] {
            assert!(xml.contains(signature), "missing v261 signature: {signature}");
        }
    }

    #[tokio::test]
    async fn list_units_by_names_preserves_request_order_and_host_missing_shape() {
        let (interface, _, _, _) = test_interface();
        interface.snapshot.write().unwrap().push(UnitInfo {
            name: "active.service".into(),
            description: "Active service".into(),
            load_state: "loaded".into(),
            active_state: "active".into(),
            sub_state: "running".into(),
            main_pid: Some(1234),
            unit_type: "service".into(),
            service_type: Some("simple".into()),
            restart_policy: Some("no".into()),
            service_runtime: Box::default(),
        });

        let (entries,) = interface
            .list_units_by_names(vec![
                "not-a-unit".into(),
                "missing.service".into(),
                "active.service".into(),
                "missing.service".into(),
                "@invalid.service".into(),
            ])
            .await
            .unwrap();

        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].0, "missing.service");
        assert_eq!(entries[0].1, "missing.service");
        assert_eq!(entries[0].2, "not-found");
        assert_eq!(entries[0].3, "inactive");
        assert_eq!(entries[0].4, "dead");
        assert_eq!(entries[0].5, "");
        assert_eq!(entries[0].6, unit_path("missing.service").unwrap());
        assert_eq!(entries[0].7, 0);
        assert_eq!(entries[0].8, "");
        assert_eq!(entries[0].9, dummy_path());
        assert_eq!(entries[1].0, "active.service");
        assert_eq!(entries[1].1, "Active service");
        assert_eq!(entries[1].2, "loaded");
        assert_eq!(entries[2], entries[0]);
    }

    #[tokio::test]
    async fn list_units_by_names_uses_v261_name_limit_and_wire_signature() {
        let (interface, _, _, _) = test_interface();
        let error = interface
            .list_units_by_names(vec!["missing.service".into(); MAX_NAMES_PER_CALL + 1])
            .await
            .unwrap_err();
        match error {
            zbus::fdo::Error::LimitsExceeded(message) => {
                assert_eq!(message, "Too many unit names requested.");
            }
            other => panic!("unexpected error: {other}"),
        }

        let mut xml = String::new();
        zbus::Interface::introspect_to_writer(&interface, &mut xml, 0);
        assert!(xml.contains(r#"<method name="ListUnitsByNames">"#));
        assert!(xml.contains(r#"<arg name="names" type="as" direction="in"/>"#));
        assert!(xml.contains(r#"<arg name="units" type="a(ssssssouso)" direction="out"/>"#));
    }

    #[tokio::test]
    async fn list_units_by_names_uses_manager_owned_load_replies() {
        let (mut interface, _, _, _) = test_interface();
        let requests: UnitLoadRequests = Arc::new(Mutex::new(Vec::new()));
        let worker_requests = Arc::clone(&requests);
        interface.unit_load_requests = Some(requests);

        let worker = std::thread::spawn(move || loop {
            let request = worker_requests.lock().unwrap().pop();
            if let Some(request) = request {
                let _ = request.reply.send(Some(UnitInfo {
                    name: request.name,
                    description: "Loaded on demand".into(),
                    load_state: "loaded".into(),
                    active_state: "inactive".into(),
                    sub_state: "dead".into(),
                    main_pid: None,
                    unit_type: "service".into(),
                    service_type: Some("oneshot".into()),
                    restart_policy: Some("no".into()),
                    service_runtime: Box::default(),
                }));
                break;
            }
            std::thread::yield_now();
        });

        let (entries,) = interface
            .list_units_by_names(vec!["on-demand.service".into()])
            .await
            .unwrap();
        worker.join().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "on-demand.service");
        assert_eq!(entries[0].1, "Loaded on demand");
        assert_eq!(entries[0].2, "loaded");
        assert_eq!(entries[0].3, "inactive");
        assert_eq!(entries[0].4, "dead");
    }

    #[test]
    fn get_and_list_jobs_use_numeric_paths() {
        let (interface, _, _, _) = test_interface();
        let job = interface
            .enqueue(JobKind::Start, "foo.service", None)
            .unwrap();
        assert_eq!(
            interface.get_job(job.id).unwrap(),
            (job_path(job.id).unwrap(),)
        );
        assert!(interface.get_job(job.id + 1).is_err());

        let (jobs,) = interface.list_jobs();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].0, job.id);
        assert_eq!(jobs[0].1, "foo.service");
        assert_eq!(jobs[0].2, "start");
        assert_eq!(jobs[0].3, "waiting");
        assert_eq!(jobs[0].4, job_path(job.id).unwrap());
    }

    #[test]
    fn reload_request_sets_flag_and_wakes_manager() {
        let (interface, _, wake, reload_requested) = test_interface();
        interface.request_reload().unwrap();
        assert!(reload_requested.load(Ordering::Acquire));
        // Safety: the descriptor is owned by `wake` for this test.
        let counter = unsafe { crate::ffi::event::rustd_eventfd_read(wake.raw_fd()) };
        assert_eq!(counter, 1);
    }

    #[test]
    fn reset_failed_requests_are_queued_and_wake_manager() {
        let (interface, _, wake, _) = test_interface();
        interface
            .request_reset_failed(vec!["failed.service".to_owned()])
            .unwrap();
        assert_eq!(
            *interface.reset_failed_requests.lock().unwrap(),
            vec![vec!["failed.service".to_owned()]]
        );
        // Safety: the descriptor is owned by `wake` for this test.
        let counter = unsafe { crate::ffi::event::rustd_eventfd_read(wake.raw_fd()) };
        assert_eq!(counter, 1);
    }
}
