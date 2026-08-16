// SPDX-License-Identifier: LGPL-2.1-or-later
//! Cgroup v2 tree management, empty notifications, and resource controls.
//!
//! Creates per-unit cgroup directories under `system.slice`, attaches
//! processes, monitors `cgroup.events`, and writes the controller files
//! represented by [`crate::resource_control::ResourceControl`].
//!
//! Upstream reference: `src/core/cgroup.c cg_create()`, `cg_attach()`,
//!   `cgroup_apply_unified_limit()` (v261)

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::config::ManagerScope;
use crate::event::loop_::IoHandler;
use crate::resource_control::{LimitValue, ResourceControl};

/// Root of the unified cgroup hierarchy.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Cgroup tree manager.
#[derive(Clone)]
pub struct CgroupManager {
    root: PathBuf,
    slice: PathBuf,
}

impl CgroupManager {
    /// Create a manager rooted at the default path or the test override in
    /// `RUSTD_CGROUP_ROOT`.
    #[must_use]
    pub fn new() -> Self {
        Self::for_scope(ManagerScope::System)
    }

    /// Create a cgroup manager for a system or per-user service manager.
    #[must_use]
    pub fn for_scope(scope: ManagerScope) -> Self {
        let root = std::env::var_os("RUSTD_CGROUP_ROOT")
            .map_or_else(|| PathBuf::from(CGROUP_ROOT), PathBuf::from);
        let slice = match scope {
            ManagerScope::System => PathBuf::from("system.slice"),
            ManagerScope::User => {
                let uid = unsafe { libc::getuid() };
                PathBuf::from("user.slice")
                    .join(format!("user-{uid}.slice"))
                    .join(format!("user@{uid}.service"))
                    .join("app.slice")
            }
        };
        Self { root, slice }
    }

    /// Create a manager rooted at a custom path (for testing).
    #[must_use]
    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            slice: PathBuf::from("system.slice"),
        }
    }

    /// Create the manager's `system.slice` directory and request the
    /// controllers used by the supported resource properties.
    ///
    /// # Errors
    /// Returns an error if the slice directory cannot be created.
    pub fn setup_root(&self) -> anyhow::Result<()> {
        fs::create_dir_all(self.root.join(&self.slice))?;
        let _ = fs::write(
            self.root.join("cgroup.subtree_control"),
            "+cpu +io +memory +pids\n",
        );
        Ok(())
    }

    /// Create the cgroup directory for `unit_name`.
    ///
    /// # Errors
    /// Returns an error if the directory cannot be created.
    pub fn create_unit_cgroup(&self, unit_name: &str) -> anyhow::Result<PathBuf> {
        let path = self.unit_path(unit_name);
        fs::create_dir_all(&path)?;
        Ok(path)
    }

    /// Attach `pid` to the cgroup for `unit_name`.
    ///
    /// # Errors
    /// Returns an error if the cgroup does not exist or the write fails.
    pub fn attach_pid(&self, unit_name: &str, pid: libc::pid_t) -> anyhow::Result<()> {
        fs::write(
            self.unit_path(unit_name).join("cgroup.procs"),
            format!("{pid}\n"),
        )?;
        Ok(())
    }

    /// Attach a set of processes to a unit or one of its delegated
    /// subgroups.
    ///
    /// `subgroup` is the absolute cgroup path supplied by the Manager D-Bus
    /// method. An empty path and "/" select the unit's own cgroup. The unit
    /// cgroup is realized before a non-empty process set is moved, matching
    /// `unit_attach_pids_to_cgroup()` in systemd v261. Processes already in
    /// the unit hierarchy are left in place; in particular, a requested
    /// subgroup has no effect for those processes.
    ///
    /// # Errors
    /// Returns an error if the unit cgroup or target subgroup cannot be
    /// created/opened, or if the kernel rejects a process migration.
    pub fn attach_pids_to_unit_subgroup(
        &self,
        unit_name: &str,
        subgroup: &str,
        pids: &[libc::pid_t],
    ) -> anyhow::Result<()> {
        if pids.is_empty() {
            return Ok(());
        }

        let unit_path = self.create_unit_cgroup(unit_name)?;
        let target = cgroup_subgroup_path(&unit_path, subgroup);
        let mut existing = HashSet::new();
        let _ = collect_cgroup_pids(&unit_path, &mut existing);

        for pid in pids {
            if existing.contains(pid) {
                continue;
            }
            fs::write(target.join("cgroup.procs"), format!("{pid}\n"))?;
            existing.insert(*pid);
        }
        Ok(())
    }

    /// Signal every positive PID in a unit cgroup hierarchy except exclusions.
    ///
    /// `ESRCH` races are ignored because processes may exit between enumeration
    /// and delivery. Other signal errors fail the operation.
    ///
    /// # Errors
    /// Returns an error if the cgroup hierarchy cannot be enumerated or a
    /// signal fails for a reason other than an exited-process race.
    pub fn signal_unit(
        &self,
        unit_name: &str,
        signal: libc::c_int,
        exclude: &[libc::pid_t],
    ) -> anyhow::Result<usize> {
        Self::signal_path(&self.unit_path(unit_name), signal, exclude, None)
    }

    /// Signal every positive PID in a unit cgroup subgroup hierarchy.
    ///
    /// An empty subgroup selects the unit's complete cgroup hierarchy. The
    /// caller validates the subgroup spelling before joining it to the unit
    /// path; this method deliberately treats it as a relative path only.
    ///
    /// # Errors
    /// Returns an error if the cgroup hierarchy cannot be enumerated or a
    /// signal fails for a reason other than an exited-process race.
    pub fn signal_unit_subgroup(
        &self,
        unit_name: &str,
        subgroup: &str,
        signal: libc::c_int,
        exclude: &[libc::pid_t],
        value: Option<i32>,
    ) -> anyhow::Result<usize> {
        let path = if subgroup.is_empty() {
            self.unit_path(unit_name)
        } else {
            self.unit_path(unit_name).join(subgroup)
        };
        Self::signal_path(&path, signal, exclude, value)
    }

    fn signal_path(
        path: &Path,
        signal: libc::c_int,
        exclude: &[libc::pid_t],
        value: Option<i32>,
    ) -> anyhow::Result<usize> {
        let mut pids = HashSet::new();
        collect_cgroup_pids(path, &mut pids)?;
        let excluded: HashSet<libc::pid_t> = exclude.iter().copied().collect();
        let mut sent = 0;
        for pid in pids {
            if pid <= 0 || excluded.contains(&pid) {
                continue;
            }
            // Safety: pid was read from this unit's cgroup.procs hierarchy.
            let result = if let Some(value) = value {
                // `sigqueue` carries the Manager.QueueSignalUnit payload;
                // Linux exposes the integer through the pointer-shaped union
                // member of `sigval`.
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
                sent += 1;
                continue;
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error.into());
            }
        }
        Ok(sent)
    }

    /// Open the unit's `cgroup.events` file and build its epoll handler.
    ///
    /// The returned source owns the open descriptor for as long as it is
    /// registered with the manager event loop.
    ///
    /// # Errors
    /// Returns an error if `cgroup.events` cannot be opened.
    pub fn event_source(
        &self,
        unit_name: &str,
        pending_empty: Arc<Mutex<Vec<String>>>,
    ) -> anyhow::Result<CgroupEventSource> {
        let file = File::open(self.unit_path(unit_name).join("cgroup.events"))?;
        Ok(CgroupEventSource {
            file,
            unit_name: unit_name.to_owned(),
            pending_empty,
        })
    }

    /// Return whether a unit cgroup currently contains any processes in its
    /// subtree, as reported by the unified hierarchy's `populated` field.
    ///
    /// # Errors
    /// Returns an error if `cgroup.events` cannot be read or has no valid
    /// `populated` field.
    pub fn is_unit_populated(&self, unit_name: &str) -> anyhow::Result<bool> {
        let contents = fs::read_to_string(self.unit_path(unit_name).join("cgroup.events"))?;
        parse_populated(&contents).ok_or_else(|| {
            anyhow::anyhow!(
                "{} has no valid populated field",
                self.unit_path(unit_name).join("cgroup.events").display()
            )
        })
    }

    /// Request the kernel cgroup-v2 freezer state for a managed unit.
    ///
    /// # Errors
    /// Returns an error when the unit cgroup has no freezer control or the
    /// kernel rejects the requested state.
    pub fn set_unit_frozen(&self, unit_name: &str, frozen: bool) -> anyhow::Result<()> {
        self.write_value(unit_name, "cgroup.freeze", if frozen { "1" } else { "0" })
    }

    /// Return the kernel-observed freezer state from `cgroup.events`.
    ///
    /// # Errors
    /// Returns an error when `cgroup.events` cannot be read or does not contain
    /// a valid `frozen` field.
    pub fn is_unit_frozen(&self, unit_name: &str) -> anyhow::Result<bool> {
        let events = self.unit_path(unit_name).join("cgroup.events");
        let contents = fs::read_to_string(&events)?;
        parse_frozen(&contents)
            .ok_or_else(|| anyhow::anyhow!("{} has no valid frozen field", events.display()))
    }

    /// Return whether any managed ancestor currently reports itself frozen.
    #[must_use]
    pub fn unit_frozen_by_parent(&self, unit_name: &str) -> bool {
        let unit_path = self.unit_path(unit_name);
        let mut parent = unit_path.parent();
        while let Some(path) = parent {
            if path == self.root || !path.starts_with(&self.root) {
                break;
            }
            let frozen = fs::read_to_string(path.join("cgroup.events"))
                .ok()
                .and_then(|contents| parse_frozen(&contents));
            if frozen == Some(true) {
                return true;
            }
            parent = path.parent();
        }
        false
    }

    /// Remove a unit cgroup directory after the hierarchy reports it empty.
    ///
    /// A missing directory is already clean and is treated as success.
    ///
    /// # Errors
    /// Returns an error if the kernel refuses to remove the cgroup.
    pub fn remove_unit_cgroup(&self, unit_name: &str) -> anyhow::Result<()> {
        match fs::remove_dir(self.unit_path(unit_name)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    /// Trim a delegated subgroup, removing the subgroup itself unless the
    /// supplied path selects the unit cgroup root.
    ///
    /// The kernel's rmdir(2) reports EBUSY when a subgroup still contains
    /// processes. The same check is performed for the filesystem-backed test
    /// hierarchy so candidate tests exercise the real failure contract rather
    /// than a fixture-only success path.
    ///
    /// # Errors
    /// Returns an error when the subgroup contains processes, cannot be
    /// enumerated, or cannot be removed. A missing subgroup is already clean
    /// and is treated as success, as in `cg_trim()`.
    pub fn remove_unit_subgroup(&self, unit_name: &str, subgroup: &str) -> anyhow::Result<()> {
        let unit_path = self.unit_path(unit_name);
        let target = cgroup_subgroup_path(&unit_path, subgroup);
        trim_cgroup(&target, target != unit_path)
    }

    /// Apply all configured cgroup-v2 resource controls for a unit.
    ///
    /// Settings left as `None` are not written, preserving the controller's
    /// inherited/default value.
    ///
    /// # Errors
    /// Returns the first control-file write failure.
    pub fn apply_resource_control(
        &self,
        unit_name: &str,
        control: &ResourceControl,
    ) -> anyhow::Result<()> {
        // `cpu.idle` is optional in cgroup-v2 kernels.  systemd treats a
        // missing controller attribute as a non-fatal best-effort write.
        let idle = self.unit_path(unit_name).join("cpu.idle");
        if idle.exists() {
            fs::write(idle, if control.cpu_idle { "1\n" } else { "0\n" })?;
        }
        if let Some(weight) = control.cpu_weight {
            self.write_value(
                unit_name,
                "cpu.weight",
                &weight.clamp(1, 10_000).to_string(),
            )?;
        }
        if let Some(quota) = control.cpu_quota {
            self.write_value(unit_name, "cpu.max", &quota.cgroup_value())?;
        }
        if let Some(weight) = control.io_weight {
            self.write_value(
                unit_name,
                "io.weight",
                &format!("default {}", weight.clamp(1, 10_000)),
            )?;
        }
        self.write_optional_limit(unit_name, "memory.min", control.memory_min)?;
        self.write_optional_limit(unit_name, "memory.low", control.memory_low)?;
        self.write_optional_limit(unit_name, "memory.high", control.memory_high)?;
        self.write_optional_limit(unit_name, "memory.max", control.memory_max)?;
        self.write_optional_limit(unit_name, "memory.swap.max", control.memory_swap_max)?;
        self.write_optional_limit(unit_name, "memory.zswap.max", control.memory_zswap_max)?;
        if let Some(writeback) = control.memory_zswap_writeback {
            self.write_value(
                unit_name,
                "memory.zswap.writeback",
                if writeback { "1" } else { "0" },
            )?;
        }
        self.write_optional_limit(unit_name, "pids.max", control.tasks_max)?;
        Ok(())
    }

    fn write_optional_limit(
        &self,
        unit_name: &str,
        file: &str,
        limit: Option<LimitValue>,
    ) -> anyhow::Result<()> {
        if let Some(limit) = limit {
            self.write_value(unit_name, file, &limit.cgroup_value())?;
        }
        Ok(())
    }

    fn write_value(&self, unit_name: &str, file: &str, value: &str) -> anyhow::Result<()> {
        fs::write(self.unit_path(unit_name).join(file), format!("{value}\n"))?;
        Ok(())
    }

    /// Return the host filesystem path for `unit_name`.
    fn unit_path(&self, unit_name: &str) -> PathBuf {
        self.root.join(self.unit_cgroup_path(unit_name))
    }

    /// Return the manager-relative cgroup path for `unit_name`.
    fn unit_cgroup_path(&self, unit_name: &str) -> PathBuf {
        if self
            .slice
            .file_name()
            .is_some_and(|slice_name| slice_name == unit_name)
        {
            self.slice.clone()
        } else {
            self.slice.join(unit_name)
        }
    }

    /// Return the absolute cgroup path reported over the Manager D-Bus API.
    #[must_use]
    pub fn unit_cgroup_path_for_dbus(&self, unit_name: &str) -> PathBuf {
        Path::new("/").join(self.unit_cgroup_path(unit_name))
    }

    /// Return whether the manager currently has a cgroup directory for a unit.
    #[must_use]
    pub fn has_unit_cgroup(&self, unit_name: &str) -> bool {
        self.unit_path(unit_name).is_dir()
    }

    /// Return whether a controller file is available in a realized unit.
    /// This lets inherited defaults remain best-effort when a host kernel has
    /// not delegated that controller to the manager hierarchy.
    #[must_use]
    pub fn unit_control_available(&self, unit_name: &str, file: &str) -> bool {
        self.unit_path(unit_name).join(file).exists()
    }

    /// Return whether a relative subgroup directory currently exists below a
    /// managed unit cgroup. An empty subgroup names the unit cgroup itself.
    #[must_use]
    pub fn has_unit_subgroup(&self, unit_name: &str, subgroup: &str) -> bool {
        if subgroup.is_empty() {
            self.has_unit_cgroup(unit_name)
        } else {
            self.unit_path(unit_name).join(subgroup).is_dir()
        }
    }

    /// Return the cgroup-v2 process-membership file for a unit.
    #[must_use]
    pub fn unit_procs_path(&self, unit_name: &str) -> PathBuf {
        self.unit_path(unit_name).join("cgroup.procs")
    }

    /// Return the cgroup path exposed by the Service D-Bus interface.
    #[must_use]
    pub fn service_control_group(&self, unit_name: &str) -> String {
        if self.has_unit_cgroup(unit_name) {
            self.unit_cgroup_path_for_dbus(unit_name)
                .display()
                .to_string()
        } else {
            String::new()
        }
    }

    /// Return the kernel cgroup identifier (the directory inode), or zero
    /// when the unit has no realized cgroup.
    #[must_use]
    pub fn service_control_group_id(&self, unit_name: &str) -> u64 {
        fs::metadata(self.unit_path(unit_name)).map_or(0, |metadata| metadata.ino())
    }

    /// Read a cgroup-v2 unsigned value, preserving systemd's infinity
    /// sentinel for a missing unit/file or a literal `max` value.
    #[must_use]
    pub fn service_cgroup_value(&self, unit_name: &str, file: &str) -> u64 {
        let Ok(value) = fs::read_to_string(self.unit_path(unit_name).join(file)) else {
            return u64::MAX;
        };
        let value = value.trim();
        if value == "max" {
            u64::MAX
        } else {
            value.parse().unwrap_or(u64::MAX)
        }
    }

    /// Read the cgroup CPU usage counter and convert microseconds to
    /// nanoseconds as required by `CPUUsageNSec`.
    #[must_use]
    pub fn service_cpu_usage_nsec(&self, unit_name: &str) -> u64 {
        let Ok(stat) = fs::read_to_string(self.unit_path(unit_name).join("cpu.stat")) else {
            return u64::MAX;
        };
        stat.lines()
            .find_map(|line| {
                let mut fields = line.split_whitespace();
                let key = fields.next()?;
                let value = fields.next()?;
                (key == "usage_usec")
                    .then(|| value.trim().parse::<u64>().ok())
                    .flatten()
            })
            .and_then(|usec| usec.checked_mul(1_000))
            .unwrap_or(u64::MAX)
    }

    /// Read a named counter from a cgroup-v2 key/value file, returning the
    /// systemd infinity sentinel when the file or key is unavailable.
    #[must_use]
    pub fn service_cgroup_counter(&self, unit_name: &str, file: &str, key: &str) -> u64 {
        let Ok(contents) = fs::read_to_string(self.unit_path(unit_name).join(file)) else {
            return u64::MAX;
        };
        contents
            .lines()
            .find_map(|line| {
                let mut fields = line.split_whitespace();
                let name = fields.next()?;
                let value = fields.next()?;
                (name == key)
                    .then(|| value.trim().parse::<u64>().ok())
                    .flatten()
            })
            .unwrap_or(u64::MAX)
    }

    /// Sum a cgroup-v2 `io.stat` counter across all devices. The kernel emits
    /// one `major:minor` row per device, while systemd exposes the aggregate
    /// unit value over D-Bus.
    #[must_use]
    pub fn service_io_counter(&self, unit_name: &str, key: &str) -> u64 {
        let Ok(contents) = fs::read_to_string(self.unit_path(unit_name).join("io.stat")) else {
            return u64::MAX;
        };
        let mut total = 0u64;
        let mut found = false;
        for line in contents.lines() {
            for field in line.split_whitespace().skip(1) {
                let Some((name, value)) = field.split_once('=') else {
                    continue;
                };
                if name != key {
                    continue;
                }
                let Ok(value) = value.parse::<u64>() else {
                    continue;
                };
                let Some(sum) = total.checked_add(value) else {
                    return u64::MAX;
                };
                total = sum;
                found = true;
            }
        }
        if found {
            total
        } else {
            u64::MAX
        }
    }

    /// Return the kernel's current `MemAvailable` estimate in bytes. The
    /// systemd Service property is host-wide rather than cgroup-local.
    #[must_use]
    pub fn service_memory_available(&self) -> u64 {
        let Ok(contents) = fs::read_to_string("/proc/meminfo") else {
            return u64::MAX;
        };
        contents
            .lines()
            .find_map(|line| {
                let mut fields = line.split_whitespace();
                (fields.next()? == "MemAvailable:")
                    .then(|| fields.next()?.parse::<u64>().ok())
                    .flatten()
            })
            .and_then(|kib| kib.checked_mul(1024))
            .unwrap_or(u64::MAX)
    }

    /// Return a cgroup-v2 cpuset file as a Linux CPU/memory-node bitmap.
    #[must_use]
    pub fn service_cpuset_bitmap(&self, unit_name: &str, file: &str) -> Vec<u8> {
        let Ok(contents) = fs::read_to_string(self.unit_path(unit_name).join(file)) else {
            return Vec::new();
        };
        expand_cpuset_bitmap(contents.trim())
    }

    /// Read the manager-wide effective cpuset when a service cgroup has not
    /// yet been realized, matching v261's inherited effective values.
    #[must_use]
    pub fn service_effective_cpuset_bitmap(&self, file: &str) -> Vec<u8> {
        let path = self.root.join(file);
        fs::read_to_string(path)
            .map(|contents| expand_cpuset_bitmap(contents.trim()))
            .unwrap_or_default()
    }
}

impl Default for CgroupManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Open `cgroup.events` source retained by the event loop.
pub struct CgroupEventSource {
    file: File,
    unit_name: String,
    pending_empty: Arc<Mutex<Vec<String>>>,
}

impl CgroupEventSource {
    /// Descriptor registered for priority-change notification.
    #[must_use]
    pub fn raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }

    fn read_populated(&mut self) -> anyhow::Result<bool> {
        self.file.seek(SeekFrom::Start(0))?;
        let mut contents = String::new();
        self.file.read_to_string(&mut contents)?;
        parse_populated(&contents).ok_or_else(|| anyhow::anyhow!("invalid cgroup.events data"))
    }
}

impl IoHandler for CgroupEventSource {
    fn on_io(&mut self, _fd: i32, _events: u32) {
        if !matches!(self.read_populated(), Ok(false)) {
            return;
        }
        let mut pending = self
            .pending_empty
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !pending.contains(&self.unit_name) {
            pending.push(self.unit_name.clone());
        }
    }
}

fn collect_cgroup_pids(path: &Path, pids: &mut HashSet<libc::pid_t>) -> anyhow::Result<()> {
    match fs::read_to_string(path.join("cgroup.procs")) {
        Ok(contents) => {
            for line in contents.lines() {
                if let Ok(pid) = line.trim().parse::<libc::pid_t>() {
                    if pid > 0 {
                        pids.insert(pid);
                    }
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            collect_cgroup_pids(&entry.path(), pids)?;
        }
    }
    Ok(())
}

fn cgroup_subgroup_path(unit_path: &Path, subgroup: &str) -> PathBuf {
    if subgroup.is_empty() || subgroup == "/" {
        unit_path.to_path_buf()
    } else {
        unit_path.join(subgroup.trim_start_matches('/'))
    }
}

fn trim_cgroup(path: &Path, delete_root: bool) -> anyhow::Result<()> {
    if !path.exists() {
        return Ok(());
    }

    if delete_root {
        let mut pids = HashSet::new();
        collect_cgroup_pids(path, &mut pids)?;
        if !pids.is_empty() {
            return Err(std::io::Error::from_raw_os_error(libc::EBUSY).into());
        }
    }

    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();
        if entry.file_type()?.is_dir() {
            trim_cgroup(&entry_path, true)?;
            continue;
        }

        // cgroup pseudo-files are controls, not children of the cgroup
        // hierarchy, and are never removed by cg_trim(). Keep them intact on
        // both a real cgroup2 mount and the filesystem-backed test tree.
        if delete_root {
            // Regular files in a test subgroup stand in for pseudo-files and
            // need removal before rmdir(2) can succeed. On a real cgroup2
            // mount all such unlink attempts are rejected and ignored.
            match fs::remove_file(&entry_path) {
                Ok(()) => {}
                Err(error)
                    if matches!(
                        error.raw_os_error(),
                        Some(libc::EPERM | libc::EOPNOTSUPP | libc::EROFS)
                    ) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
    }

    if delete_root {
        match fs::remove_dir(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn parse_populated(contents: &str) -> Option<bool> {
    contents.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        if fields.next()? != "populated" {
            return None;
        }
        match fields.next()? {
            "0" => Some(false),
            "1" => Some(true),
            _ => None,
        }
    })
}

fn parse_frozen(contents: &str) -> Option<bool> {
    contents.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        if fields.next()? != "frozen" {
            return None;
        }
        match fields.next()? {
            "0" => Some(false),
            "1" => Some(true),
            _ => None,
        }
    })
}

fn expand_cpuset_bitmap(value: &str) -> Vec<u8> {
    let mut cpus = Vec::new();
    for item in value.split(',') {
        let Some((first, last)) = item.split_once('-') else {
            if let Ok(cpu) = item.parse::<usize>() {
                cpus.push(cpu);
            }
            continue;
        };
        let (Ok(first), Ok(last)) = (first.parse::<usize>(), last.parse::<usize>()) else {
            continue;
        };
        cpus.extend(first..=last);
    }
    let Some(maximum) = cpus.iter().copied().max() else {
        return Vec::new();
    };
    let mut bitmap = vec![0; maximum / 8 + 1];
    for cpu in cpus {
        bitmap[cpu / 8] |= 1 << (cpu % 8);
    }
    bitmap
}

/// Return true if the cgroup filesystem is available.
#[must_use]
pub fn cgroup_available() -> bool {
    Path::new(CGROUP_ROOT).exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource_control::{CpuQuota, LimitValue};

    #[test]
    fn unit_path_correct() {
        let manager = CgroupManager::with_root("/tmp/test-cgroup");
        assert_eq!(
            manager.unit_path("foo.service"),
            PathBuf::from("/tmp/test-cgroup/system.slice/foo.service")
        );
    }

    #[test]
    fn dbus_paths_follow_the_managed_slice() {
        let manager = CgroupManager::with_root("/tmp/test-cgroup");
        assert_eq!(
            manager.unit_cgroup_path_for_dbus("foo.service"),
            PathBuf::from("/system.slice/foo.service")
        );
        assert_eq!(
            manager.unit_cgroup_path_for_dbus("system.slice"),
            PathBuf::from("/system.slice")
        );
    }

    #[test]
    fn cgroup_existence_reflects_the_filesystem() {
        let temporary = tempfile::tempdir().unwrap();
        let manager = CgroupManager::with_root(temporary.path());
        manager.setup_root().unwrap();

        assert!(!manager.has_unit_cgroup("foo.service"));
        manager.create_unit_cgroup("foo.service").unwrap();
        assert!(manager.has_unit_cgroup("foo.service"));
    }

    #[test]
    fn user_scope_uses_delegated_app_slice() {
        let temporary = tempfile::tempdir().unwrap();
        let old = std::env::var_os("RUSTD_CGROUP_ROOT");
        std::env::set_var("RUSTD_CGROUP_ROOT", temporary.path());
        let manager = CgroupManager::for_scope(ManagerScope::User);
        let uid = unsafe { libc::getuid() };
        assert_eq!(
            manager.unit_path("demo.service"),
            temporary
                .path()
                .join("user.slice")
                .join(format!("user-{uid}.slice"))
                .join(format!("user@{uid}.service"))
                .join("app.slice/demo.service")
        );
        assert_eq!(
            manager.unit_cgroup_path_for_dbus("demo.service"),
            PathBuf::from("/user.slice")
                .join(format!("user-{uid}.slice"))
                .join(format!("user@{uid}.service"))
                .join("app.slice/demo.service")
        );
        assert_eq!(
            manager.unit_cgroup_path_for_dbus("app.slice"),
            PathBuf::from("/user.slice")
                .join(format!("user-{uid}.slice"))
                .join(format!("user@{uid}.service"))
                .join("app.slice")
        );
        match old {
            Some(value) => std::env::set_var("RUSTD_CGROUP_ROOT", value),
            None => std::env::remove_var("RUSTD_CGROUP_ROOT"),
        }
    }

    #[test]
    fn setup_root_creates_dirs() {
        let temporary = tempfile::tempdir().unwrap();
        let manager = CgroupManager::with_root(temporary.path());
        manager.setup_root().unwrap();
        assert!(temporary.path().join("system.slice").is_dir());
    }

    #[test]
    fn create_and_attach_fake() {
        let temporary = tempfile::tempdir().unwrap();
        let manager = CgroupManager::with_root(temporary.path());
        manager.setup_root().unwrap();
        manager.create_unit_cgroup("foo.service").unwrap();
        manager.attach_pid("foo.service", 12345).unwrap();
        assert_eq!(
            fs::read_to_string(
                temporary
                    .path()
                    .join("system.slice/foo.service/cgroup.procs")
            )
            .unwrap(),
            "12345\n"
        );
    }

    #[test]
    fn delegated_subgroup_attach_and_trim_follow_cgroup_contract() {
        let temporary = tempfile::tempdir().unwrap();
        let manager = CgroupManager::with_root(temporary.path());
        manager.setup_root().unwrap();
        let unit = manager.create_unit_cgroup("foo.service").unwrap();
        fs::write(unit.join("cgroup.procs"), "100\n").unwrap();
        let subgroup = unit.join("workers");
        fs::create_dir(&subgroup).unwrap();
        fs::write(subgroup.join("cgroup.procs"), "sentinel\n").unwrap();

        // A process already in the unit hierarchy is not moved below the
        // requested subgroup, matching unit_attach_pids_to_cgroup().
        manager
            .attach_pids_to_unit_subgroup("foo.service", "/workers", &[100])
            .unwrap();
        assert_eq!(
            fs::read_to_string(subgroup.join("cgroup.procs")).unwrap(),
            "sentinel\n"
        );

        manager
            .attach_pids_to_unit_subgroup("foo.service", "/workers", &[200])
            .unwrap();
        assert_eq!(
            fs::read_to_string(subgroup.join("cgroup.procs")).unwrap(),
            "200\n"
        );

        let error = manager
            .remove_unit_subgroup("foo.service", "/workers")
            .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .and_then(std::io::Error::raw_os_error),
            Some(libc::EBUSY)
        );

        fs::write(subgroup.join("cgroup.procs"), "").unwrap();
        manager
            .remove_unit_subgroup("foo.service", "/workers")
            .unwrap();
        assert!(!subgroup.exists());
        manager
            .remove_unit_subgroup("foo.service", "/missing")
            .unwrap();
        manager.remove_unit_subgroup("foo.service", "/").unwrap();
        assert!(unit.exists());
    }

    #[test]
    fn reads_service_runtime_cgroup_contract() {
        let temporary = tempfile::tempdir().unwrap();
        let manager = CgroupManager::with_root(temporary.path());
        manager.setup_root().unwrap();
        let path = manager.create_unit_cgroup("foo.service").unwrap();
        fs::write(path.join("memory.current"), "1234\n").unwrap();
        fs::write(path.join("memory.peak"), "max\n").unwrap();
        fs::write(path.join("memory.max"), "4096\n").unwrap();
        fs::write(path.join("memory.high"), "2048\n").unwrap();
        fs::write(path.join("memory.swap.current"), "55\n").unwrap();
        fs::write(path.join("cpu.stat"), "usage_usec 77\nuser_usec 1\n").unwrap();
        fs::write(path.join("pids.current"), "3\n").unwrap();
        fs::write(path.join("pids.max"), "16\n").unwrap();
        fs::write(
            path.join("io.stat"),
            "8:0 rbytes=100 wbytes=20 rios=3 wios=4\n253:0 rbytes=7 wbytes=5 rios=2 wios=1\n",
        )
        .unwrap();
        fs::write(path.join("memory.events"), "oom_kill 2\noom_group_kill 1\n").unwrap();

        assert_eq!(
            manager.service_control_group("foo.service"),
            "/system.slice/foo.service"
        );
        assert_ne!(manager.service_control_group_id("foo.service"), 0);
        assert_eq!(
            manager.service_cgroup_value("foo.service", "memory.current"),
            1234
        );
        assert_eq!(
            manager.service_cgroup_value("foo.service", "memory.peak"),
            u64::MAX
        );
        assert_eq!(
            manager.service_cgroup_value("foo.service", "memory.max"),
            4096
        );
        assert_eq!(
            manager.service_cgroup_value("foo.service", "memory.high"),
            2048
        );
        assert_eq!(manager.service_cpu_usage_nsec("foo.service"), 77_000);
        assert_eq!(
            manager.service_cgroup_value("foo.service", "pids.current"),
            3
        );
        assert_eq!(manager.service_cgroup_value("foo.service", "pids.max"), 16);
        assert_eq!(manager.service_io_counter("foo.service", "rbytes"), 107);
        assert_eq!(manager.service_io_counter("foo.service", "wbytes"), 25);
        assert_eq!(manager.service_io_counter("foo.service", "rios"), 5);
        assert_eq!(manager.service_io_counter("foo.service", "wios"), 5);
        assert_eq!(
            manager.service_cgroup_counter("foo.service", "memory.events", "oom_kill"),
            2
        );
        assert_eq!(
            manager.service_cgroup_counter("foo.service", "memory.events", "oom_group_kill"),
            1
        );
    }

    #[test]
    fn parses_populated_state() {
        assert_eq!(parse_populated("populated 0\nfrozen 0\n"), Some(false));
        assert_eq!(parse_populated("populated 1\nfrozen 0\n"), Some(true));
        assert_eq!(parse_populated("frozen 0\n"), None);
    }

    #[test]
    fn freezer_controls_follow_kernel_event_state_and_parent_state() {
        let temporary = tempfile::tempdir().unwrap();
        let manager = CgroupManager::with_root(temporary.path());
        manager.setup_root().unwrap();
        let path = manager.create_unit_cgroup("foo.service").unwrap();
        fs::write(path.join("cgroup.freeze"), "0\n").unwrap();
        fs::write(path.join("cgroup.events"), "populated 1\nfrozen 0\n").unwrap();
        fs::write(
            temporary.path().join("system.slice/cgroup.events"),
            "populated 1\nfrozen 0\n",
        )
        .unwrap();

        assert!(!manager.is_unit_frozen("foo.service").unwrap());
        assert!(!manager.unit_frozen_by_parent("foo.service"));
        manager.set_unit_frozen("foo.service", true).unwrap();
        assert_eq!(
            fs::read_to_string(path.join("cgroup.freeze")).unwrap(),
            "1\n"
        );
        fs::write(path.join("cgroup.events"), "populated 1\nfrozen 1\n").unwrap();
        assert!(manager.is_unit_frozen("foo.service").unwrap());

        fs::write(
            temporary.path().join("system.slice/cgroup.events"),
            "populated 1\nfrozen 1\n",
        )
        .unwrap();
        assert!(manager.unit_frozen_by_parent("foo.service"));
        fs::write(
            temporary.path().join("system.slice/cgroup.events"),
            "populated 1\nfrozen 0\n",
        )
        .unwrap();
        assert!(!manager.unit_frozen_by_parent("foo.service"));

        manager.set_unit_frozen("foo.service", false).unwrap();
        assert_eq!(
            fs::read_to_string(path.join("cgroup.freeze")).unwrap(),
            "0\n"
        );
    }

    #[test]
    fn parses_frozen_state() {
        assert_eq!(parse_frozen("populated 0\nfrozen 0\n"), Some(false));
        assert_eq!(parse_frozen("populated 1\nfrozen 1\n"), Some(true));
        assert_eq!(parse_frozen("populated 1\n"), None);
    }

    #[test]
    fn empty_event_queues_unit_once() {
        let temporary = tempfile::tempdir().unwrap();
        let manager = CgroupManager::with_root(temporary.path());
        manager.setup_root().unwrap();
        let path = manager.create_unit_cgroup("foo.service").unwrap();
        fs::write(path.join("cgroup.events"), "populated 0\nfrozen 0\n").unwrap();
        let pending = Arc::new(Mutex::new(Vec::new()));
        let mut source = manager
            .event_source("foo.service", Arc::clone(&pending))
            .unwrap();

        source.on_io(source.raw_fd(), libc::EPOLLPRI as u32);
        source.on_io(source.raw_fd(), libc::EPOLLPRI as u32);

        let queued = pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert_eq!(queued, vec!["foo.service"]);
    }

    #[test]
    fn reads_populated_state_from_unit_file() {
        let temporary = tempfile::tempdir().unwrap();
        let manager = CgroupManager::with_root(temporary.path());
        manager.setup_root().unwrap();
        let path = manager.create_unit_cgroup("foo.service").unwrap();
        fs::write(path.join("cgroup.events"), "populated 1\nfrozen 0\n").unwrap();
        assert!(manager.is_unit_populated("foo.service").unwrap());
        fs::write(path.join("cgroup.events"), "populated 0\nfrozen 0\n").unwrap();
        assert!(!manager.is_unit_populated("foo.service").unwrap());
    }

    #[test]
    fn removes_unit_cgroup_directory() {
        let temporary = tempfile::tempdir().unwrap();
        let manager = CgroupManager::with_root(temporary.path());
        manager.setup_root().unwrap();
        let path = manager.create_unit_cgroup("foo.service").unwrap();
        manager.remove_unit_cgroup("foo.service").unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn applies_supported_resource_controls() {
        let temporary = tempfile::tempdir().unwrap();
        let manager = CgroupManager::with_root(temporary.path());
        manager.setup_root().unwrap();
        manager.create_unit_cgroup("foo.service").unwrap();
        let control = ResourceControl {
            cpu_weight: Some(250),
            cpu_quota: Some(CpuQuota::PercentHundredths(2_500)),
            io_weight: Some(300),
            memory_max: Some(LimitValue::Value(16_777_216)),
            memory_swap_max: Some(LimitValue::Max),
            memory_zswap_max: Some(LimitValue::Value(8_388_608)),
            memory_zswap_writeback: Some(false),
            tasks_max: Some(LimitValue::Value(32)),
            ..ResourceControl::default()
        };

        manager
            .apply_resource_control("foo.service", &control)
            .unwrap();
        let root = temporary.path().join("system.slice/foo.service");
        assert_eq!(
            fs::read_to_string(root.join("cpu.weight")).unwrap(),
            "250\n"
        );
        assert_eq!(
            fs::read_to_string(root.join("cpu.max")).unwrap(),
            "25000 100000\n"
        );
        assert_eq!(
            fs::read_to_string(root.join("io.weight")).unwrap(),
            "default 300\n"
        );
        assert_eq!(
            fs::read_to_string(root.join("memory.max")).unwrap(),
            "16777216\n"
        );
        assert_eq!(
            fs::read_to_string(root.join("memory.swap.max")).unwrap(),
            "max\n"
        );
        assert_eq!(
            fs::read_to_string(root.join("memory.zswap.max")).unwrap(),
            "8388608\n"
        );
        assert_eq!(
            fs::read_to_string(root.join("memory.zswap.writeback")).unwrap(),
            "0\n"
        );
        assert_eq!(fs::read_to_string(root.join("pids.max")).unwrap(), "32\n");
    }
}
