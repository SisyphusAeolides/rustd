// SPDX-License-Identifier: LGPL-2.1-or-later
//! Typed `[Service]` section and exec-context fields.
//!
//! Covers all keys from `systemd.service(5)` and `systemd.exec(5)` (v261).
//!
//! Upstream reference: `src/core/load-fragment.c` `[Service]` keys,
//! `src/core/service.c`, `src/core/execute.c` (v261)

use bitflags::bitflags;
use std::time::Duration;

use crate::limits::RlimitKind;
pub use crate::limits::{RlimitSpec, RlimitValue};
use crate::resource_control::ResourceControl;
use crate::unit::duration::parse_duration;

// ── Service type ──────────────────────────────────────────────────────────

/// `Type=` setting.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum ServiceType {
    /// Main process is the service. Ready when exec succeeds.
    #[default]
    Simple,
    /// Like Simple but waits for execve to succeed.
    Exec,
    /// Service forks and the parent exits. PID file used if set.
    Forking,
    /// Process runs to completion; considered active until it exits.
    Oneshot,
    /// Service acquires a D-Bus name.
    Dbus,
    /// Service sends `READY=1` via `rustd_notify`.
    Notify,
    /// Like Notify; also sends `RELOADING=1` during reload.
    NotifyReload,
    /// Started last, after all other jobs complete.
    Idle,
}

impl ServiceType {
    fn parse(s: &str) -> Self {
        match s {
            "exec" => Self::Exec,
            "forking" => Self::Forking,
            "oneshot" => Self::Oneshot,
            "dbus" => Self::Dbus,
            "notify" => Self::Notify,
            "notify-reload" => Self::NotifyReload,
            "idle" => Self::Idle,
            _ => Self::Simple,
        }
    }
}

// ── Restart policy ────────────────────────────────────────────────────────

/// `Restart=` setting.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum RestartPolicy {
    #[default]
    No,
    OnSuccess,
    OnFailure,
    OnAbnormal,
    OnWatchdog,
    OnAbort,
    Always,
}

impl RestartPolicy {
    fn parse(s: &str) -> Self {
        match s {
            "on-success" => Self::OnSuccess,
            "on-failure" => Self::OnFailure,
            "on-abnormal" => Self::OnAbnormal,
            "on-watchdog" => Self::OnWatchdog,
            "on-abort" => Self::OnAbort,
            "always" => Self::Always,
            _ => Self::No,
        }
    }
}

// ── NotifyAccess ──────────────────────────────────────────────────────────

/// `NotifyAccess=` setting.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum NotifyAccess {
    #[default]
    None,
    Main,
    Exec,
    All,
}

impl NotifyAccess {
    fn parse(s: &str) -> Self {
        match s {
            "main" => Self::Main,
            "exec" => Self::Exec,
            "all" => Self::All,
            _ => Self::None,
        }
    }
}

// ── Exec command ─────────────────────────────────────────────────────────

bitflags! {
    /// Prefix flags on an `Exec*=` command line.
    ///
    /// Upstream: `src/core/load-fragment.c config_parse_exec()` (v261)
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct ExecFlags: u8 {
        /// `-` — ignore non-zero exit code.
        const IGNORE_FAILURE      = 0b0000_0001;
        /// `+` — run with full privileges.
        const FULL_PRIVILEGES     = 0b0000_0010;
        /// `!` — keep sandboxing, but do not switch user/group credentials.
        const NO_SETUID           = 0b0000_0100;
        /// `@` — pass argv[0] as a separate argument.
        const ARGV0_SEPARATE      = 0b0000_1000;
        /// `:` — do not expand environment variables.
        const NO_ENV_EXPAND       = 0b0001_0000;
        /// `|` — invoke through the selected user's login shell.
        const VIA_SHELL           = 0b0010_0000;
    }
}

/// A single parsed exec command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecCommand {
    /// Executable path. This is deliberately distinct from `argv[0]` because
    /// the `@` prefix replaces `argv[0]` without changing the executable.
    pub path: String,
    /// Argument vector passed to the executable.
    pub argv: Vec<String>,
    /// Prefix flags.
    pub flags: ExecFlags,
}

impl ExecCommand {
    /// Parse a raw exec value into an `ExecCommand`.
    ///
    /// Handles `-`, `+`, `!`, `!!`, `@`, `:`, `|` prefix characters and
    /// simple argv splitting respecting single and double quotes.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        if raw.is_empty() {
            return None;
        }

        let mut words = split_argv(raw.trim_start());
        if words.is_empty() {
            return None;
        }

        let mut flags = ExecFlags::empty();
        let first = words.remove(0);
        let mut executable = first.as_str();
        let mut ambient_compat = false;

        // Prefixes apply to the executable token itself. In v261 `!!` is
        // retained solely as compatibility with the removed ambient-capability
        // hack and therefore resolves to no current execution flag.
        loop {
            let mut chars = executable.chars();
            let Some(prefix) = chars.next() else {
                break;
            };
            let rest = chars.as_str();
            let consumed = match prefix {
                '-' if !flags.contains(ExecFlags::IGNORE_FAILURE) => {
                    flags |= ExecFlags::IGNORE_FAILURE;
                    true
                }
                '@' if !flags.contains(ExecFlags::ARGV0_SEPARATE) => {
                    flags |= ExecFlags::ARGV0_SEPARATE;
                    true
                }
                ':' if !flags.contains(ExecFlags::NO_ENV_EXPAND) => {
                    flags |= ExecFlags::NO_ENV_EXPAND;
                    true
                }
                '|' if !flags.contains(ExecFlags::VIA_SHELL) => {
                    flags |= ExecFlags::VIA_SHELL;
                    true
                }
                '+' if !ambient_compat
                    && !flags.intersects(ExecFlags::FULL_PRIVILEGES | ExecFlags::NO_SETUID) =>
                {
                    flags |= ExecFlags::FULL_PRIVILEGES;
                    true
                }
                '!' if !ambient_compat
                    && !flags.intersects(ExecFlags::FULL_PRIVILEGES | ExecFlags::NO_SETUID) =>
                {
                    flags |= ExecFlags::NO_SETUID;
                    true
                }
                '!' if !ambient_compat && !flags.contains(ExecFlags::FULL_PRIVILEGES) => {
                    flags.remove(ExecFlags::NO_SETUID);
                    ambient_compat = true;
                    true
                }
                _ => false,
            };
            if !consumed {
                break;
            }
            executable = rest;
        }

        if flags.contains(ExecFlags::VIA_SHELL) {
            let mut argv = Vec::with_capacity(words.len() + 2);
            argv.push(
                if flags.contains(ExecFlags::ARGV0_SEPARATE) {
                    "-sh"
                } else {
                    "sh"
                }
                .to_owned(),
            );
            if !executable.is_empty() {
                argv.push(executable.to_owned());
            }
            argv.extend(words);
            return Some(Self {
                path: "/bin/sh".to_owned(),
                argv,
                flags,
            });
        }

        if executable.is_empty() {
            return None;
        }

        let path = executable.to_owned();
        let argv = if flags.contains(ExecFlags::ARGV0_SEPARATE) {
            if words.is_empty() {
                return None;
            }
            words
        } else {
            let mut argv = Vec::with_capacity(words.len() + 1);
            argv.push(path.clone());
            argv.extend(words);
            argv
        };

        Some(Self { path, argv, flags })
    }
}

/// Split an exec command line into argv, respecting single and double quotes.
fn split_argv(s: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut chars = s.chars().peekable();
    let mut in_single = false;
    let mut in_double = false;

    while let Some(c) = chars.next() {
        match c {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '\\' if in_double || !in_single => {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            ' ' | '\t' if !in_single && !in_double => {
                if !current.is_empty() {
                    args.push(current.clone());
                    current.clear();
                }
            }
            _ => current.push(c),
        }
    }
    if !current.is_empty() {
        args.push(current);
    }
    args
}

fn parse_mode(value: &str) -> Option<u32> {
    let value = value.trim().strip_prefix("0o").unwrap_or(value.trim());
    let value = value.trim_start_matches('0');
    if value.is_empty() {
        Some(0)
    } else {
        u32::from_str_radix(value, 8).ok()
    }
}

// ── Protect/Privacy enums ─────────────────────────────────────────────────

/// `ProtectSystem=` value.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum ProtectSystem {
    #[default]
    No,
    Yes,
    Full,
    Strict,
}

impl ProtectSystem {
    fn parse(s: &str) -> Self {
        match s {
            "yes" | "true" | "1" => Self::Yes,
            "full" => Self::Full,
            "strict" => Self::Strict,
            _ => Self::No,
        }
    }
}

/// `ProtectHome=` value.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum ProtectHome {
    #[default]
    No,
    Yes,
    ReadOnly,
    Tmpfs,
}

impl ProtectHome {
    fn parse(s: &str) -> Self {
        match s {
            "yes" | "true" | "1" => Self::Yes,
            "read-only" => Self::ReadOnly,
            "tmpfs" => Self::Tmpfs,
            _ => Self::No,
        }
    }
}

/// `KillMode=` setting.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum KillMode {
    #[default]
    ControlGroup,
    Process,
    Mixed,
    None,
}

impl KillMode {
    fn parse(value: &str) -> Self {
        match value {
            "process" => Self::Process,
            "mixed" => Self::Mixed,
            "none" => Self::None,
            _ => Self::ControlGroup,
        }
    }
}

pub(crate) fn parse_signal(value: &str) -> Option<libc::c_int> {
    let upper = value.trim().to_ascii_uppercase();
    if let Ok(number) = upper.parse::<libc::c_int>() {
        return (number > 0 && number <= libc::SIGRTMAX()).then_some(number);
    }
    let name = upper.strip_prefix("SIG").unwrap_or(&upper);
    let min = libc::SIGRTMIN();
    let max = libc::SIGRTMAX();
    if name == "RTMIN" {
        return Some(min);
    }
    if name == "RTMAX" {
        return Some(max);
    }
    if let Some(offset) = name
        .strip_prefix("RTMIN+")
        .and_then(|v| v.parse::<i32>().ok())
    {
        let signal = min.checked_add(offset)?;
        return (signal <= max).then_some(signal);
    }
    if let Some(offset) = name
        .strip_prefix("RTMAX-")
        .and_then(|v| v.parse::<i32>().ok())
    {
        let signal = max.checked_sub(offset)?;
        return (signal >= min).then_some(signal);
    }
    Some(match name {
        "HUP" => libc::SIGHUP,
        "INT" => libc::SIGINT,
        "QUIT" => libc::SIGQUIT,
        "ILL" => libc::SIGILL,
        "TRAP" => libc::SIGTRAP,
        "ABRT" | "IOT" => libc::SIGABRT,
        "BUS" => libc::SIGBUS,
        "FPE" => libc::SIGFPE,
        "KILL" => libc::SIGKILL,
        "USR1" => libc::SIGUSR1,
        "SEGV" => libc::SIGSEGV,
        "USR2" => libc::SIGUSR2,
        "PIPE" => libc::SIGPIPE,
        "ALRM" => libc::SIGALRM,
        "TERM" => libc::SIGTERM,
        "STKFLT" => libc::SIGSTKFLT,
        "CHLD" | "CLD" => libc::SIGCHLD,
        "CONT" => libc::SIGCONT,
        "STOP" => libc::SIGSTOP,
        "TSTP" => libc::SIGTSTP,
        "TTIN" => libc::SIGTTIN,
        "TTOU" => libc::SIGTTOU,
        "URG" => libc::SIGURG,
        "XCPU" => libc::SIGXCPU,
        "XFSZ" => libc::SIGXFSZ,
        "VTALRM" => libc::SIGVTALRM,
        "PROF" => libc::SIGPROF,
        "WINCH" => libc::SIGWINCH,
        "IO" | "POLL" => libc::SIGIO,
        "PWR" => libc::SIGPWR,
        "SYS" => libc::SIGSYS,
        _ => return None,
    })
}

pub(crate) fn exit_status_from_string(value: &str) -> Option<i32> {
    let value = value.trim();
    if let Ok(code) = value.parse::<u8>() {
        return Some(i32::from(code));
    }
    Some(match value {
        "SUCCESS" => 0,
        "FAILURE" => 1,
        "INVALIDARGUMENT" => 2,
        "NOTIMPLEMENTED" => 3,
        "NOPERMISSION" => 4,
        "NOTINSTALLED" => 5,
        "NOTCONFIGURED" => 6,
        "NOTRUNNING" => 7,
        "USAGE" => 64,
        "DATAERR" => 65,
        "NOINPUT" => 66,
        "NOUSER" => 67,
        "NOHOST" => 68,
        "UNAVAILABLE" => 69,
        "SOFTWARE" => 70,
        "OSERR" => 71,
        "OSFILE" => 72,
        "CANTCREAT" => 73,
        "IOERR" => 74,
        "TEMPFAIL" => 75,
        "PROTOCOL" => 76,
        "NOPERM" => 77,
        "CONFIG" => 78,
        "CHDIR" => 200,
        "NICE" => 201,
        "FDS" => 202,
        "EXEC" => 203,
        "MEMORY" => 204,
        "LIMITS" => 205,
        "OOM_ADJUST" => 206,
        "SIGNAL_MASK" => 207,
        "STDIN" => 208,
        "STDOUT" => 209,
        "CHROOT" => 210,
        "IOPRIO" => 211,
        "TIMERSLACK" => 212,
        "SECUREBITS" => 213,
        "SETSCHEDULER" => 214,
        "CPUAFFINITY" => 215,
        "GROUP" => 216,
        "USER" => 217,
        "CAPABILITIES" => 218,
        "CGROUP" => 219,
        "SETSID" => 220,
        "CONFIRM" => 221,
        "STDERR" => 222,
        "PAM" => 224,
        "NETWORK" => 225,
        "NAMESPACE" => 226,
        "NO_NEW_PRIVILEGES" => 227,
        "SECCOMP" => 228,
        "SELINUX_CONTEXT" => 229,
        "PERSONALITY" => 230,
        "APPARMOR" => 231,
        "ADDRESS_FAMILIES" => 232,
        "RUNTIME_DIRECTORY" => 233,
        "CHOWN" => 235,
        "SMACK_PROCESS_LABEL" => 236,
        "KEYRING" => 237,
        "STATE_DIRECTORY" => 238,
        "CACHE_DIRECTORY" => 239,
        "LOGS_DIRECTORY" => 240,
        "CONFIGURATION_DIRECTORY" => 241,
        "NUMA_POLICY" => 242,
        "CREDENTIALS" => 243,
        "BPF" => 244,
        "KSM" => 245,
        "MEMORY_THP" => 246,
        "EXCEPTION" => 255,
        _ => return None,
    })
}

pub(crate) fn exit_status_set_matches(values: &[String], code: i32, status: i32) -> bool {
    values.iter().any(|value| {
        if code == libc::CLD_EXITED {
            exit_status_from_string(value) == Some(status)
        } else if matches!(code, libc::CLD_KILLED | libc::CLD_DUMPED) {
            parse_signal(value) == Some(status)
        } else {
            false
        }
    })
}

fn apply_rlimit(target: &mut Option<RlimitSpec>, value: &str, kind: RlimitKind) {
    // config_parse_rlimit() ignores malformed assignments, including empty
    // strings, without discarding a value accepted earlier in the merge.
    if let Some(parsed) = RlimitSpec::parse(value, kind) {
        *target = Some(parsed);
    }
}

// ── ServiceSection ────────────────────────────────────────────────────────

fn parse_bool(s: &str) -> bool {
    matches!(s.to_ascii_lowercase().as_str(), "yes" | "true" | "1" | "on")
}

fn apply_exec_list(list: &mut Vec<ExecCommand>, value: &str) {
    if value.is_empty() {
        list.clear();
    } else if let Some(cmd) = ExecCommand::parse(value) {
        list.push(cmd);
    }
}

/// One `SystemCallFilter=` assignment, preserving whether it was inverted.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SystemCallFilterAssignment {
    pub invert: bool,
    pub items: Vec<String>,
}

/// Fully parsed `[Service]` section including exec-context fields.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Default, Clone)]
pub struct ServiceSection {
    // Service type
    pub service_type: ServiceType,
    pub exit_type: String,
    pub restart_mode: String,
    pub remain_after_exit: bool,
    pub guess_main_pid: bool,
    pub pid_file: String,
    pub bus_name: String,
    // Exec
    pub exec_condition: Vec<ExecCommand>,
    pub exec_start_pre: Vec<ExecCommand>,
    pub exec_start: Vec<ExecCommand>,
    pub exec_start_post: Vec<ExecCommand>,
    pub exec_reload: Vec<ExecCommand>,
    pub exec_reload_post: Vec<ExecCommand>,
    pub exec_stop: Vec<ExecCommand>,
    pub exec_stop_post: Vec<ExecCommand>,
    // Restart
    pub restart: RestartPolicy,
    pub restart_sec: Option<Duration>,
    pub restart_max_delay_sec: Option<Duration>,
    pub restart_steps: Option<u32>,
    // Timeouts
    pub timeout_start_sec: Option<Duration>,
    pub timeout_stop_sec: Option<Duration>,
    pub timeout_abort_sec: Option<Duration>,
    pub timeout_start_failure_mode: String,
    pub timeout_stop_failure_mode: String,
    pub runtime_max_sec: Option<Duration>,
    pub runtime_randomized_extra_sec: Option<Duration>,
    pub watchdog_sec: Option<Duration>,
    // Kill context
    pub kill_mode: KillMode,
    pub kill_signal: Option<libc::c_int>,
    pub restart_kill_signal: Option<libc::c_int>,
    pub final_kill_signal: Option<libc::c_int>,
    pub watchdog_signal: Option<libc::c_int>,
    pub send_sigkill: Option<bool>,
    pub send_sighup: bool,
    // Success/failure exit codes
    pub success_exit_status: Vec<String>,
    pub restart_prevent_exit_status: Vec<String>,
    pub restart_force_exit_status: Vec<String>,
    // Notify
    pub notify_access: NotifyAccess,
    pub sockets: Vec<String>,
    pub file_descriptor_store_max: u32,
    pub file_descriptor_store_preserve: String,
    pub refresh_on_reload: Vec<String>,
    // Exec context — identity
    pub user: String,
    pub group: String,
    pub dynamic_user: bool,
    pub supplementary_groups: Vec<String>,
    pub pam_name: String,
    // Exec context — environment
    pub working_directory: String,
    pub root_directory: String,
    pub environment: Vec<String>,
    pub environment_file: Vec<String>,
    pub pass_environment: Vec<String>,
    pub unset_environment: Vec<String>,
    // Exec context — capabilities / privileges
    pub capability_bounding_set: Vec<String>,
    pub ambient_capabilities: Vec<String>,
    pub no_new_privileges: bool,
    pub secure_bits: Vec<String>,
    // Exec context — stdio
    pub standard_input: String,
    pub standard_output: String,
    pub standard_error: String,
    pub tty_path: String,
    pub tty_reset: bool,
    pub tty_vhangup: bool,
    pub tty_vt_disallocate: bool,
    pub tty_rows: Option<u32>,
    pub tty_columns: Option<u32>,
    pub utmp_identifier: String,
    pub utmp_mode: String,
    // Exec context — logging
    pub syslog_identifier: String,
    pub syslog_facility: String,
    pub syslog_level: String,
    pub log_level_max: String,
    pub log_rate_limit_interval_sec: Option<Duration>,
    pub log_rate_limit_burst: Option<u32>,
    pub log_extra_fields: Vec<String>,
    pub log_namespace: String,
    // Exec context — scheduling
    pub nice: Option<i32>,
    pub oom_score_adjust: Option<i32>,
    pub io_scheduling_class: String,
    pub io_scheduling_priority: Option<i32>,
    pub cpu_scheduling_policy: String,
    pub cpu_scheduling_priority: Option<i32>,
    pub cpu_scheduling_reset_on_fork: bool,
    pub cpu_affinity: String,
    pub timer_slack_nsec: Option<Duration>,
    // Exec context — sandboxing
    pub private_tmp: bool,
    pub private_devices: bool,
    pub private_network: bool,
    pub private_users: bool,
    pub private_mounts: bool,
    pub private_ipc: bool,
    pub private_pids: String,
    pub protect_system: ProtectSystem,
    pub protect_home: ProtectHome,
    pub protect_hostname: bool,
    pub protect_proc: String,
    pub proc_subset: String,
    pub protect_kernel_tunables: bool,
    pub protect_kernel_modules: bool,
    pub protect_kernel_logs: bool,
    pub protect_clock: bool,
    pub protect_control_groups: bool,
    pub restrict_address_families: Vec<String>,
    pub restrict_filesystems: Vec<String>,
    pub restrict_namespaces: bool,
    pub restrict_realtime: bool,
    pub restrict_suid_sgid: bool,
    pub memory_deny_write_execute: bool,
    pub mount_api_vfs: bool,
    pub mount_flags: u64,
    pub bind_log_sockets: bool,
    pub memory_ksm: bool,
    pub memory_thp: String,
    pub user_namespace_path: String,
    pub network_namespace_path: String,
    pub ipc_namespace_path: String,
    pub lock_personality: bool,
    pub remove_ipc: bool,
    pub system_call_filter: Vec<SystemCallFilterAssignment>,
    pub system_call_architectures: Vec<String>,
    pub system_call_error_number: String,
    pub system_call_log: Vec<String>,
    pub personality: String,
    pub ignore_sigpipe: bool,
    pub keyring_mode: String,
    pub oom_policy: String,
    pub coredump_filter: String,
    pub delegate: bool,
    pub delegate_controllers: Vec<String>,
    pub delegate_subgroup: String,
    pub disable_controllers: Vec<String>,
    pub cpuset_partition: String,
    pub managed_oom_swap: String,
    pub managed_oom_memory_pressure: String,
    pub managed_oom_memory_pressure_limit: u32,
    pub managed_oom_memory_pressure_duration_sec: Option<Duration>,
    pub managed_oom_preference: String,
    pub same_process_group: bool,
    // Exec context — directories
    pub runtime_directory: Vec<String>,
    pub runtime_directory_mode: Option<u32>,
    pub runtime_directory_preserve: String,
    pub state_directory: Vec<String>,
    pub state_directory_mode: Option<u32>,
    pub cache_directory: Vec<String>,
    pub cache_directory_mode: Option<u32>,
    pub logs_directory: Vec<String>,
    pub logs_directory_mode: Option<u32>,
    pub configuration_directory: Vec<String>,
    pub configuration_directory_mode: Option<u32>,
    pub timeout_clean_sec: Option<Duration>,
    // Exec context — paths
    pub read_write_paths: Vec<String>,
    pub read_only_paths: Vec<String>,
    pub inaccessible_paths: Vec<String>,
    pub exec_paths: Vec<String>,
    pub no_exec_paths: Vec<String>,
    pub exec_search_path: Vec<String>,
    pub temporary_filesystem: Vec<String>,
    pub bind_paths: Vec<String>,
    pub bind_read_only_paths: Vec<String>,
    // Cgroup resource control
    pub resource_control: ResourceControl,
    // Process resource limits
    pub limit_cpu: Option<RlimitSpec>,
    pub limit_fsize: Option<RlimitSpec>,
    pub limit_data: Option<RlimitSpec>,
    pub limit_stack: Option<RlimitSpec>,
    pub limit_core: Option<RlimitSpec>,
    pub limit_rss: Option<RlimitSpec>,
    pub limit_nofile: Option<RlimitSpec>,
    pub limit_as: Option<RlimitSpec>,
    pub limit_nproc: Option<RlimitSpec>,
    pub limit_memlock: Option<RlimitSpec>,
    pub limit_locks: Option<RlimitSpec>,
    pub limit_sigpending: Option<RlimitSpec>,
    pub limit_msgqueue: Option<RlimitSpec>,
    pub limit_nice: Option<RlimitSpec>,
    pub limit_rtprio: Option<RlimitSpec>,
    pub limit_rttime: Option<RlimitSpec>,
    // Misc
    pub umask: String,
    pub se_linux_context: String,
    pub app_armor_profile: String,
    pub smack_process_label: String,
    pub import_credential: Vec<String>,
    pub ip_address_allow: Vec<String>,
    pub ip_address_deny: Vec<String>,
    pub device_allow: Vec<String>,
    pub device_policy: String,
    pub slice: String,
    pub open_file: Vec<String>,
    pub reload_signal: String,
    pub root_directory_start_only: bool,
    pub non_blocking: bool,
}

impl ServiceSection {
    /// Apply a single `(key, value)` pair from the `[Service]` section.
    #[allow(clippy::too_many_lines)]
    pub fn apply(&mut self, key: &str, value: &str) {
        if self.resource_control.apply(key, value) {
            return;
        }
        let bv = || parse_bool(value);
        let dv = || parse_duration(value);

        match key {
            "Type" => self.service_type = ServiceType::parse(value),
            "ExitType" if matches!(value, "main" | "cgroup") => {
                value.clone_into(&mut self.exit_type);
            }
            "RestartMode" if matches!(value, "normal" | "direct" | "debug") => {
                value.clone_into(&mut self.restart_mode);
            }
            "RemainAfterExit" => self.remain_after_exit = bv(),
            "GuessMainPID" => self.guess_main_pid = bv(),
            "PIDFile" => value.clone_into(&mut self.pid_file),
            "BusName" => value.clone_into(&mut self.bus_name),
            "ExecCondition" => apply_exec_list(&mut self.exec_condition, value),
            "ExecStartPre" => apply_exec_list(&mut self.exec_start_pre, value),
            "ExecStart" => apply_exec_list(&mut self.exec_start, value),
            "ExecStartPost" => apply_exec_list(&mut self.exec_start_post, value),
            "ExecReload" => apply_exec_list(&mut self.exec_reload, value),
            "ExecReloadPost" => apply_exec_list(&mut self.exec_reload_post, value),
            "ExecStop" => apply_exec_list(&mut self.exec_stop, value),
            "ExecStopPost" => apply_exec_list(&mut self.exec_stop_post, value),
            "Restart" => self.restart = RestartPolicy::parse(value),
            "RestartSec" => self.restart_sec = dv(),
            "RestartMaxDelaySec" => self.restart_max_delay_sec = dv(),
            "RestartSteps" => self.restart_steps = value.parse().ok(),
            "TimeoutStartSec" => self.timeout_start_sec = dv(),
            "TimeoutStopSec" => self.timeout_stop_sec = dv(),
            "TimeoutAbortSec" => self.timeout_abort_sec = dv(),
            "TimeoutSec" => {
                let d = dv();
                self.timeout_start_sec = d;
                self.timeout_stop_sec = d;
            }
            "TimeoutStartFailureMode" => value.clone_into(&mut self.timeout_start_failure_mode),
            "TimeoutStopFailureMode" => value.clone_into(&mut self.timeout_stop_failure_mode),
            "RuntimeMaxSec" => self.runtime_max_sec = dv(),
            "RuntimeRandomizedExtraSec" => self.runtime_randomized_extra_sec = dv(),
            "WatchdogSec" => self.watchdog_sec = dv(),
            "KillMode" => self.kill_mode = KillMode::parse(value),
            "KillSignal" => {
                if let Some(signal) = parse_signal(value) {
                    self.kill_signal = Some(signal);
                }
            }
            "RestartKillSignal" => {
                if let Some(signal) = parse_signal(value) {
                    self.restart_kill_signal = Some(signal);
                }
            }
            "FinalKillSignal" => {
                if let Some(signal) = parse_signal(value) {
                    self.final_kill_signal = Some(signal);
                }
            }
            "WatchdogSignal" => {
                if let Some(signal) = parse_signal(value) {
                    self.watchdog_signal = Some(signal);
                }
            }
            "SendSIGKILL" => self.send_sigkill = Some(bv()),
            "SendSIGHUP" => self.send_sighup = bv(),
            "SuccessExitStatus" => {
                if value.is_empty() {
                    self.success_exit_status.clear();
                } else {
                    self.success_exit_status
                        .extend(value.split_whitespace().map(str::to_owned));
                }
            }
            "RestartPreventExitStatus" => {
                if value.is_empty() {
                    self.restart_prevent_exit_status.clear();
                } else {
                    self.restart_prevent_exit_status
                        .extend(value.split_whitespace().map(str::to_owned));
                }
            }
            "RestartForceExitStatus" => {
                if value.is_empty() {
                    self.restart_force_exit_status.clear();
                } else {
                    self.restart_force_exit_status
                        .extend(value.split_whitespace().map(str::to_owned));
                }
            }
            "NotifyAccess" => self.notify_access = NotifyAccess::parse(value),
            "Sockets" => {
                if value.is_empty() {
                    self.sockets.clear();
                } else {
                    self.sockets
                        .extend(value.split_whitespace().map(str::to_owned));
                }
            }
            "FileDescriptorStoreMax" => self.file_descriptor_store_max = value.parse().unwrap_or(0),
            "FileDescriptorStorePreserve" => {
                value.clone_into(&mut self.file_descriptor_store_preserve);
            }
            "RefreshOnReload" => {
                if value.is_empty() {
                    self.refresh_on_reload.clear();
                } else {
                    self.refresh_on_reload
                        .extend(value.split_whitespace().map(str::to_owned));
                }
            }
            "User" => value.clone_into(&mut self.user),
            "Group" => value.clone_into(&mut self.group),
            "DynamicUser" => self.dynamic_user = bv(),
            "SupplementaryGroups" => {
                if value.is_empty() {
                    self.supplementary_groups.clear();
                } else {
                    self.supplementary_groups
                        .extend(value.split_whitespace().map(str::to_owned));
                }
            }
            "PAMName" => value.clone_into(&mut self.pam_name),
            "WorkingDirectory" => value.clone_into(&mut self.working_directory),
            "RootDirectory" => value.clone_into(&mut self.root_directory),
            "Environment" => {
                if value.is_empty() {
                    self.environment.clear();
                } else {
                    self.environment.push(value.to_owned());
                }
            }
            "EnvironmentFile" => {
                if value.is_empty() {
                    self.environment_file.clear();
                } else {
                    self.environment_file.push(value.to_owned());
                }
            }
            "PassEnvironment" => {
                if value.is_empty() {
                    self.pass_environment.clear();
                } else {
                    self.pass_environment
                        .extend(value.split_whitespace().map(str::to_owned));
                }
            }
            "UnsetEnvironment" => {
                if value.is_empty() {
                    self.unset_environment.clear();
                } else {
                    self.unset_environment
                        .extend(value.split_whitespace().map(str::to_owned));
                }
            }
            "CapabilityBoundingSet" => {
                if value.is_empty() {
                    self.capability_bounding_set.clear();
                } else {
                    let (inverted, names) = value
                        .strip_prefix('~')
                        .map_or((false, value), |names| (true, names));
                    self.capability_bounding_set
                        .extend(names.split_whitespace().map(|name| {
                            if inverted {
                                format!("~{name}")
                            } else {
                                name.to_owned()
                            }
                        }));
                }
            }
            "AmbientCapabilities" => {
                if value.is_empty() {
                    self.ambient_capabilities.clear();
                } else {
                    let (inverted, names) = value
                        .strip_prefix('~')
                        .map_or((false, value), |names| (true, names));
                    self.ambient_capabilities
                        .extend(names.split_whitespace().map(|name| {
                            if inverted {
                                format!("~{name}")
                            } else {
                                name.to_owned()
                            }
                        }));
                }
            }
            "NoNewPrivileges" => self.no_new_privileges = bv(),
            "SecureBits" => {
                if value.is_empty() {
                    self.secure_bits.clear();
                } else {
                    self.secure_bits
                        .extend(value.split_whitespace().map(str::to_owned));
                }
            }
            "StandardInput" => value.clone_into(&mut self.standard_input),
            "StandardOutput" => value.clone_into(&mut self.standard_output),
            "StandardError" => value.clone_into(&mut self.standard_error),
            "TTYPath" => value.clone_into(&mut self.tty_path),
            "TTYReset" => self.tty_reset = bv(),
            "TTYVHangup" => self.tty_vhangup = bv(),
            "TTYVTDisallocate" => self.tty_vt_disallocate = bv(),
            "TTYRows" => self.tty_rows = value.parse().ok(),
            "TTYColumns" => self.tty_columns = value.parse().ok(),
            "UtmpIdentifier" => value.clone_into(&mut self.utmp_identifier),
            "UtmpMode" => value.clone_into(&mut self.utmp_mode),
            "SyslogIdentifier" => value.clone_into(&mut self.syslog_identifier),
            "SyslogFacility" => value.clone_into(&mut self.syslog_facility),
            "SyslogLevel" => value.clone_into(&mut self.syslog_level),
            "LogLevelMax" => value.clone_into(&mut self.log_level_max),
            "LogRateLimitIntervalSec" => self.log_rate_limit_interval_sec = dv(),
            "LogRateLimitBurst" => self.log_rate_limit_burst = value.parse().ok(),
            "LogExtraFields" => {
                if value.is_empty() {
                    self.log_extra_fields.clear();
                } else {
                    self.log_extra_fields.push(value.to_owned());
                }
            }
            "LogNamespace" => value.clone_into(&mut self.log_namespace),
            "Nice" => self.nice = value.parse().ok(),
            "OOMScoreAdjust" => self.oom_score_adjust = value.parse().ok(),
            "IOSchedulingClass" => value.clone_into(&mut self.io_scheduling_class),
            "IOSchedulingPriority" => self.io_scheduling_priority = value.parse().ok(),
            "CPUSchedulingPolicy" => value.clone_into(&mut self.cpu_scheduling_policy),
            "CPUSchedulingPriority" => self.cpu_scheduling_priority = value.parse().ok(),
            "CPUSchedulingResetOnFork" => self.cpu_scheduling_reset_on_fork = bv(),
            "CPUAffinity" => value.clone_into(&mut self.cpu_affinity),
            "TimerSlackNSec" => self.timer_slack_nsec = dv(),
            "PrivateTmp" => self.private_tmp = bv(),
            "PrivateDevices" => self.private_devices = bv(),
            "PrivateNetwork" => self.private_network = bv(),
            "PrivateUsers" => self.private_users = bv(),
            "PrivateMounts" => self.private_mounts = bv(),
            "PrivateIPC" => self.private_ipc = bv(),
            "PrivatePIDs" => value.clone_into(&mut self.private_pids),
            "ProtectSystem" => self.protect_system = ProtectSystem::parse(value),
            "ProtectHome" => self.protect_home = ProtectHome::parse(value),
            "ProtectHostname" => self.protect_hostname = bv(),
            "ProtectProc" => value.clone_into(&mut self.protect_proc),
            "ProcSubset" => value.clone_into(&mut self.proc_subset),
            "ProtectKernelTunables" => self.protect_kernel_tunables = bv(),
            "ProtectKernelModules" => self.protect_kernel_modules = bv(),
            "ProtectKernelLogs" => self.protect_kernel_logs = bv(),
            "ProtectClock" => self.protect_clock = bv(),
            "ProtectControlGroups" => self.protect_control_groups = bv(),
            "RestrictAddressFamilies" => {
                if value.is_empty() {
                    self.restrict_address_families.clear();
                } else {
                    self.restrict_address_families
                        .extend(value.split_whitespace().map(str::to_owned));
                }
            }
            "RestrictFileSystems" => {
                if value.is_empty() {
                    self.restrict_filesystems.clear();
                } else {
                    self.restrict_filesystems
                        .extend(value.split_whitespace().map(str::to_owned));
                }
            }
            "RestrictNamespaces" => self.restrict_namespaces = bv(),
            "RestrictRealtime" => self.restrict_realtime = bv(),
            "RestrictSUIDSGID" => self.restrict_suid_sgid = bv(),
            "MemoryDenyWriteExecute" => self.memory_deny_write_execute = bv(),
            "MountAPIVFS" => self.mount_api_vfs = bv(),
            "MountFlags" => self.mount_flags = value.parse().unwrap_or_default(),
            "BindLogSockets" => self.bind_log_sockets = bv(),
            "MemoryKSM" => self.memory_ksm = bv(),
            "MemoryTHP" => value.clone_into(&mut self.memory_thp),
            "UserNamespacePath" => value.clone_into(&mut self.user_namespace_path),
            "NetworkNamespacePath" => value.clone_into(&mut self.network_namespace_path),
            "IPCNamespacePath" => value.clone_into(&mut self.ipc_namespace_path),
            "LockPersonality" => self.lock_personality = bv(),
            "RemoveIPC" => self.remove_ipc = bv(),
            "SystemCallFilter" => {
                if value.is_empty() {
                    self.system_call_filter.clear();
                } else {
                    let (invert, items) = value
                        .strip_prefix('~')
                        .map_or((false, value), |rest| (true, rest));
                    self.system_call_filter.push(SystemCallFilterAssignment {
                        invert,
                        items: items.split_whitespace().map(str::to_owned).collect(),
                    });
                }
            }
            "SystemCallArchitectures" => {
                if value.is_empty() {
                    self.system_call_architectures.clear();
                } else {
                    self.system_call_architectures
                        .extend(value.split_whitespace().map(str::to_owned));
                }
            }
            "SystemCallErrorNumber" => {
                if crate::seccomp_policy::valid_error_number(value) {
                    value.clone_into(&mut self.system_call_error_number);
                }
            }
            "SystemCallLog" => {
                if value.is_empty() {
                    self.system_call_log.clear();
                } else {
                    self.system_call_log
                        .extend(value.split_whitespace().map(str::to_owned));
                }
            }
            "Personality" => value.clone_into(&mut self.personality),
            "IgnoreSIGPIPE" => self.ignore_sigpipe = bv(),
            "KeyringMode" => value.clone_into(&mut self.keyring_mode),
            "OOMPolicy" => value.clone_into(&mut self.oom_policy),
            "CoredumpFilter" => value.clone_into(&mut self.coredump_filter),
            "Delegate" => self.delegate = bv(),
            "DelegateControllers" => {
                if value.is_empty() {
                    self.delegate_controllers.clear();
                } else {
                    self.delegate_controllers
                        .extend(value.split_whitespace().map(str::to_owned));
                }
            }
            "DelegateSubgroup" => value.clone_into(&mut self.delegate_subgroup),
            "DisableControllers" => {
                if value.is_empty() {
                    self.disable_controllers.clear();
                } else {
                    self.disable_controllers
                        .extend(value.split_whitespace().map(str::to_owned));
                }
            }
            "CPUSetPartition" => value.clone_into(&mut self.cpuset_partition),
            "ManagedOOMSwap" => value.clone_into(&mut self.managed_oom_swap),
            "ManagedOOMMemoryPressure" => value.clone_into(&mut self.managed_oom_memory_pressure),
            "ManagedOOMMemoryPressureLimit" => {
                self.managed_oom_memory_pressure_limit = value.parse().unwrap_or_default();
            }
            "ManagedOOMMemoryPressureDurationSec" => {
                self.managed_oom_memory_pressure_duration_sec = dv();
            }
            "ManagedOOMPreference" => value.clone_into(&mut self.managed_oom_preference),
            "SameProcessGroup" => self.same_process_group = bv(),
            "RuntimeDirectory" => {
                if value.is_empty() {
                    self.runtime_directory.clear();
                } else {
                    self.runtime_directory
                        .extend(value.split_whitespace().map(str::to_owned));
                }
            }
            "RuntimeDirectoryMode" => self.runtime_directory_mode = parse_mode(value),
            "RuntimeDirectoryPreserve" => value.clone_into(&mut self.runtime_directory_preserve),
            "StateDirectory" => {
                if value.is_empty() {
                    self.state_directory.clear();
                } else {
                    self.state_directory
                        .extend(value.split_whitespace().map(str::to_owned));
                }
            }
            "StateDirectoryMode" => self.state_directory_mode = parse_mode(value),
            "CacheDirectory" => {
                if value.is_empty() {
                    self.cache_directory.clear();
                } else {
                    self.cache_directory
                        .extend(value.split_whitespace().map(str::to_owned));
                }
            }
            "CacheDirectoryMode" => self.cache_directory_mode = parse_mode(value),
            "LogsDirectory" => {
                if value.is_empty() {
                    self.logs_directory.clear();
                } else {
                    self.logs_directory
                        .extend(value.split_whitespace().map(str::to_owned));
                }
            }
            "LogsDirectoryMode" => self.logs_directory_mode = parse_mode(value),
            "ConfigurationDirectory" => {
                if value.is_empty() {
                    self.configuration_directory.clear();
                } else {
                    self.configuration_directory
                        .extend(value.split_whitespace().map(str::to_owned));
                }
            }
            "ConfigurationDirectoryMode" => self.configuration_directory_mode = parse_mode(value),
            "TimeoutCleanSec" => self.timeout_clean_sec = dv(),
            "ReadWritePaths" => {
                if value.is_empty() {
                    self.read_write_paths.clear();
                } else {
                    self.read_write_paths
                        .extend(value.split_whitespace().map(str::to_owned));
                }
            }
            "ReadOnlyPaths" => {
                if value.is_empty() {
                    self.read_only_paths.clear();
                } else {
                    self.read_only_paths
                        .extend(value.split_whitespace().map(str::to_owned));
                }
            }
            "InaccessiblePaths" => {
                if value.is_empty() {
                    self.inaccessible_paths.clear();
                } else {
                    self.inaccessible_paths
                        .extend(value.split_whitespace().map(str::to_owned));
                }
            }
            "ExecPaths" => {
                if value.is_empty() {
                    self.exec_paths.clear();
                } else {
                    self.exec_paths
                        .extend(value.split_whitespace().map(str::to_owned));
                }
            }
            "NoExecPaths" => {
                if value.is_empty() {
                    self.no_exec_paths.clear();
                } else {
                    self.no_exec_paths
                        .extend(value.split_whitespace().map(str::to_owned));
                }
            }
            "ExecSearchPath" => {
                if value.is_empty() {
                    self.exec_search_path.clear();
                } else {
                    self.exec_search_path
                        .extend(value.split_whitespace().map(str::to_owned));
                }
            }
            "TemporaryFileSystem" => {
                if value.is_empty() {
                    self.temporary_filesystem.clear();
                } else {
                    self.temporary_filesystem.push(value.to_owned());
                }
            }
            "BindPaths" => {
                if value.is_empty() {
                    self.bind_paths.clear();
                } else {
                    self.bind_paths
                        .extend(value.split_whitespace().map(str::to_owned));
                }
            }
            "BindReadOnlyPaths" => {
                if value.is_empty() {
                    self.bind_read_only_paths.clear();
                } else {
                    self.bind_read_only_paths
                        .extend(value.split_whitespace().map(str::to_owned));
                }
            }
            "LimitCPU" => apply_rlimit(&mut self.limit_cpu, value, RlimitKind::Seconds),
            "LimitFSIZE" => apply_rlimit(&mut self.limit_fsize, value, RlimitKind::Size),
            "LimitDATA" => apply_rlimit(&mut self.limit_data, value, RlimitKind::Size),
            "LimitSTACK" => apply_rlimit(&mut self.limit_stack, value, RlimitKind::Size),
            "LimitCORE" => apply_rlimit(&mut self.limit_core, value, RlimitKind::Size),
            "LimitRSS" => apply_rlimit(&mut self.limit_rss, value, RlimitKind::Size),
            "LimitNOFILE" => apply_rlimit(&mut self.limit_nofile, value, RlimitKind::Count),
            "LimitAS" => apply_rlimit(&mut self.limit_as, value, RlimitKind::Size),
            "LimitNPROC" => apply_rlimit(&mut self.limit_nproc, value, RlimitKind::Count),
            "LimitMEMLOCK" => apply_rlimit(&mut self.limit_memlock, value, RlimitKind::Size),
            "LimitLOCKS" => apply_rlimit(&mut self.limit_locks, value, RlimitKind::Count),
            "LimitSIGPENDING" => {
                apply_rlimit(&mut self.limit_sigpending, value, RlimitKind::Count);
            }
            "LimitMSGQUEUE" => apply_rlimit(&mut self.limit_msgqueue, value, RlimitKind::Size),
            "LimitNICE" => apply_rlimit(&mut self.limit_nice, value, RlimitKind::Nice),
            "LimitRTPRIO" => apply_rlimit(&mut self.limit_rtprio, value, RlimitKind::Count),
            "LimitRTTIME" => {
                apply_rlimit(&mut self.limit_rttime, value, RlimitKind::Microseconds);
            }
            "UMask" => value.clone_into(&mut self.umask),
            "SELinuxContext" => value.clone_into(&mut self.se_linux_context),
            "AppArmorProfile" => value.clone_into(&mut self.app_armor_profile),
            "SmackProcessLabel" => value.clone_into(&mut self.smack_process_label),
            "ImportCredential" => {
                if value.is_empty() {
                    self.import_credential.clear();
                } else {
                    self.import_credential
                        .extend(value.split_whitespace().map(str::to_owned));
                }
            }
            "IPAddressAllow" => {
                if value.is_empty() {
                    self.ip_address_allow.clear();
                } else {
                    self.ip_address_allow
                        .extend(value.split_whitespace().map(str::to_owned));
                }
            }
            "IPAddressDeny" => {
                if value.is_empty() {
                    self.ip_address_deny.clear();
                } else {
                    self.ip_address_deny
                        .extend(value.split_whitespace().map(str::to_owned));
                }
            }
            "DeviceAllow" => {
                if value.is_empty() {
                    self.device_allow.clear();
                } else {
                    self.device_allow.push(value.to_owned());
                }
            }
            "DevicePolicy" => value.clone_into(&mut self.device_policy),
            "Slice" => value.clone_into(&mut self.slice),
            "OpenFile" => {
                if value.is_empty() {
                    self.open_file.clear();
                } else {
                    self.open_file.push(value.to_owned());
                }
            }
            "ReloadSignal" => value.clone_into(&mut self.reload_signal),
            "RootDirectoryStartOnly" => self.root_directory_start_only = bv(),
            "NonBlocking" => self.non_blocking = bv(),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unit::ini::parse_unit_text;

    fn load_journald() -> ServiceSection {
        let entries = parse_unit_text(include_str!(
            "../../tests/fixtures/systemd-journald.service"
        ));
        let mut s = ServiceSection::default();
        for e in entries.iter().filter(|e| e.section == "Service") {
            s.apply(&e.key, &e.value);
        }
        s
    }

    #[test]
    fn journald_type_notify_reload() {
        let s = load_journald();
        assert_eq!(s.service_type, ServiceType::NotifyReload);
    }

    #[test]
    fn exit_type_and_restart_mode_parse_v261_values() {
        let mut section = ServiceSection::default();
        assert_eq!(section.exit_type, "");
        assert_eq!(section.restart_mode, "");

        section.apply("ExitType", "cgroup");
        section.apply("RestartMode", "direct");
        assert_eq!(section.exit_type, "cgroup");
        assert_eq!(section.restart_mode, "direct");

        // Unknown values are rejected by the v261 parser and must not
        // overwrite the last valid setting.
        section.apply("ExitType", "invalid");
        section.apply("RestartMode", "invalid");
        assert_eq!(section.exit_type, "cgroup");
        assert_eq!(section.restart_mode, "direct");
    }

    #[test]
    fn journald_restart_always() {
        let s = load_journald();
        assert_eq!(s.restart, RestartPolicy::Always);
    }

    #[test]
    fn journald_exec_start() {
        let s = load_journald();
        assert!(!s.exec_start.is_empty(), "exec_start must not be empty");
        assert!(s.exec_start[0].argv[0].contains("journald"));
    }

    #[test]
    fn journald_watchdog() {
        let s = load_journald();
        assert!(s.watchdog_sec.is_some());
    }

    #[test]
    fn tty_and_utmp_properties_parse_v261_directives() {
        let mut section = ServiceSection::default();
        section.apply("TTYReset", "yes");
        section.apply("TTYVHangup", "true");
        section.apply("TTYVTDisallocate", "1");
        section.apply("TTYRows", "42");
        section.apply("TTYColumns", "80");
        section.apply("UtmpIdentifier", "console");
        section.apply("UtmpMode", "user");
        section.apply("ExecSearchPath", "/usr/local/bin /opt/bin");
        section.apply("RuntimeDirectoryMode", "0750");
        section.apply("RuntimeDirectoryPreserve", "restart");
        section.apply("StateDirectoryMode", "0o700");
        section.apply("CacheDirectoryMode", "0755");
        section.apply("LogsDirectoryMode", "0700");
        section.apply("ConfigurationDirectoryMode", "0750");
        section.apply("LogRateLimitIntervalSec", "2s");
        section.apply("LogRateLimitBurst", "15");
        assert!(section.tty_reset);
        assert!(section.tty_vhangup);
        assert!(section.tty_vt_disallocate);
        assert_eq!(section.tty_rows, Some(42));
        assert_eq!(section.tty_columns, Some(80));
        assert_eq!(section.utmp_identifier, "console");
        assert_eq!(section.utmp_mode, "user");
        assert_eq!(section.exec_search_path, ["/usr/local/bin", "/opt/bin"]);
        assert_eq!(section.runtime_directory_mode, Some(0o750));
        assert_eq!(section.runtime_directory_preserve, "restart");
        assert_eq!(section.state_directory_mode, Some(0o700));
        assert_eq!(section.cache_directory_mode, Some(0o755));
        assert_eq!(section.logs_directory_mode, Some(0o700));
        assert_eq!(section.configuration_directory_mode, Some(0o750));
        assert_eq!(
            section.log_rate_limit_interval_sec,
            Some(Duration::from_secs(2))
        );
        assert_eq!(section.log_rate_limit_burst, Some(15));
    }

    #[test]
    fn cgroup_delegation_properties_parse_v261_directives() {
        let mut section = ServiceSection::default();
        section.apply("DelegateControllers", "cpu memory");
        section.apply("DelegateSubgroup", "workers");
        section.apply("DisableControllers", "io pids");
        section.apply("CPUSetPartition", "root");
        assert_eq!(section.delegate_controllers, ["cpu", "memory"]);
        assert_eq!(section.delegate_subgroup, "workers");
        assert_eq!(section.disable_controllers, ["io", "pids"]);
        assert_eq!(section.cpuset_partition, "root");
        section.apply("DelegateControllers", "");
        section.apply("DisableControllers", "");
        assert_eq!(section.delegate_controllers, [] as [std::string::String; 0]);
        assert_eq!(section.disable_controllers, [] as [std::string::String; 0]);
    }

    #[test]
    fn managed_oom_properties_parse_v261_directives() {
        let mut section = ServiceSection::default();
        section.apply("ManagedOOMSwap", "kill");
        section.apply("ManagedOOMMemoryPressure", "omit");
        section.apply("ManagedOOMMemoryPressureLimit", "7500");
        section.apply("ManagedOOMMemoryPressureDurationSec", "5s");
        section.apply("ManagedOOMPreference", "avoid");
        assert_eq!(section.managed_oom_swap, "kill");
        assert_eq!(section.managed_oom_memory_pressure, "omit");
        assert_eq!(section.managed_oom_memory_pressure_limit, 7500);
        assert_eq!(
            section.managed_oom_memory_pressure_duration_sec,
            Some(Duration::from_secs(5))
        );
        assert_eq!(section.managed_oom_preference, "avoid");
    }

    #[test]
    fn exec_command_parse_flags() {
        let cmd = ExecCommand::parse("-/usr/bin/foo --flag").unwrap();
        assert!(cmd.flags.contains(ExecFlags::IGNORE_FAILURE));
        assert_eq!(cmd.path, "/usr/bin/foo");
        assert_eq!(cmd.argv[0], "/usr/bin/foo");
        assert_eq!(cmd.argv[1], "--flag");
    }

    #[test]
    fn exec_command_double_bang() {
        let cmd = ExecCommand::parse("!!/usr/bin/foo").unwrap();
        assert!(!cmd.flags.contains(ExecFlags::NO_SETUID));
        assert_eq!(cmd.path, "/usr/bin/foo");
    }

    #[test]
    fn exec_command_bang_skips_only_credentials() {
        let cmd = ExecCommand::parse("!/usr/bin/foo").unwrap();
        assert!(cmd.flags.contains(ExecFlags::NO_SETUID));
        assert!(!cmd.flags.contains(ExecFlags::FULL_PRIVILEGES));
    }

    #[test]
    fn exec_command_separates_executable_and_argv0() {
        let cmd = ExecCommand::parse("@/usr/bin/foo custom-name --flag").unwrap();
        assert_eq!(cmd.path, "/usr/bin/foo");
        assert_eq!(cmd.argv, ["custom-name", "--flag"]);
        assert!(cmd.flags.contains(ExecFlags::ARGV0_SEPARATE));
        assert!(ExecCommand::parse("@/usr/bin/foo").is_none());
    }

    #[test]
    fn exec_command_via_shell_matches_v261_shape() {
        let cmd = ExecCommand::parse("|echo hello").unwrap();
        assert_eq!(cmd.path, "/bin/sh");
        assert_eq!(cmd.argv, ["sh", "echo", "hello"]);
        assert!(cmd.flags.contains(ExecFlags::VIA_SHELL));

        let login = ExecCommand::parse("@|echo hello").unwrap();
        assert_eq!(login.path, "/bin/sh");
        assert_eq!(login.argv, ["-sh", "echo", "hello"]);
    }

    #[test]
    fn exec_command_quoted_args() {
        let cmd = ExecCommand::parse("/usr/bin/foo \"arg with spaces\" 'also quoted'").unwrap();
        assert_eq!(cmd.argv[1], "arg with spaces");
        assert_eq!(cmd.argv[2], "also quoted");
    }

    #[test]
    fn syscall_filter_preserves_assignment_mode_and_reset() {
        let mut section = ServiceSection::default();
        section.apply("SystemCallFilter", "@system-service");
        section.apply("SystemCallFilter", "~@mount getppid:EACCES");
        assert_eq!(section.system_call_filter.len(), 2);
        assert!(!section.system_call_filter[0].invert);
        assert_eq!(section.system_call_filter[0].items, ["@system-service"]);
        assert!(section.system_call_filter[1].invert);
        assert_eq!(
            section.system_call_filter[1].items,
            ["@mount", "getppid:EACCES"]
        );
        section.apply("SystemCallFilter", "");
        assert_eq!(section.system_call_filter.len(), 0);
    }

    #[test]
    fn resource_limits_parse_upstream_forms() {
        let mut section = ServiceSection::default();
        section.apply("LimitNOFILE", "4:5");
        assert_eq!(
            section.limit_nofile,
            Some(RlimitSpec {
                soft: RlimitValue::Value(4),
                hard: RlimitValue::Value(5),
            })
        );
        section.apply("LimitCPU", "25min:13h");
        assert_eq!(
            section.limit_cpu,
            Some(RlimitSpec {
                soft: RlimitValue::Value(1500),
                hard: RlimitValue::Value(46_800),
            })
        );
        section.apply("LimitRTTIME", "25min:13h");
        assert_eq!(
            section.limit_rttime,
            Some(RlimitSpec {
                soft: RlimitValue::Value(1_500_000_000),
                hard: RlimitValue::Value(46_800_000_000),
            })
        );
        section.apply("LimitNICE", "-7");
        assert_eq!(
            section.limit_nice,
            Some(RlimitSpec {
                soft: RlimitValue::Value(27),
                hard: RlimitValue::Value(27),
            })
        );
        section.apply("LimitAS", "1G:2G");
        assert_eq!(
            section.limit_as,
            Some(RlimitSpec {
                soft: RlimitValue::Value(1 << 30),
                hard: RlimitValue::Value(2 << 30),
            })
        );
    }

    #[test]
    fn resource_limits_reject_invalid_order() {
        let mut section = ServiceSection::default();
        section.apply("LimitNOFILE", "4:5");
        section.apply("LimitNOFILE", "5:4");
        section.apply("LimitNOFILE", "");
        assert_eq!(
            section.limit_nofile,
            Some(RlimitSpec {
                soft: RlimitValue::Value(4),
                hard: RlimitValue::Value(5),
            })
        );
        section.apply("LimitNICE", "+20");
        assert!(section.limit_nice.is_none());
    }

    #[test]
    fn kill_context_parses_signals_and_modes() {
        let mut section = ServiceSection::default();
        assert_eq!(section.kill_mode, KillMode::ControlGroup);
        section.apply("KillMode", "mixed");
        section.apply("KillSignal", "SIGUSR1");
        section.apply("RestartKillSignal", "USR2");
        section.apply("FinalKillSignal", "9");
        section.apply("WatchdogSignal", "RTMIN+1");
        section.apply("SendSIGKILL", "no");
        section.apply("SendSIGHUP", "yes");
        assert_eq!(section.kill_mode, KillMode::Mixed);
        assert_eq!(section.kill_signal, Some(libc::SIGUSR1));
        assert_eq!(section.restart_kill_signal, Some(libc::SIGUSR2));
        assert_eq!(section.final_kill_signal, Some(libc::SIGKILL));
        assert_eq!(section.watchdog_signal, Some(libc::SIGRTMIN() + 1));
        assert_eq!(section.send_sigkill, Some(false));
        assert!(section.send_sighup);
    }

    #[test]
    fn descriptor_store_preserve_keeps_v261_string_modes() {
        let mut section = ServiceSection::default();
        section.apply("FileDescriptorStorePreserve", "yes");
        assert_eq!(section.file_descriptor_store_preserve, "yes");
        section.apply("FileDescriptorStorePreserve", "restart");
        assert_eq!(section.file_descriptor_store_preserve, "restart");
    }

    #[test]
    fn invalid_system_call_errno_keeps_previous_value() {
        let mut section = ServiceSection::default();
        section.apply("SystemCallErrorNumber", "EPERM");
        section.apply("SystemCallErrorNumber", "not-an-errno");
        assert_eq!(section.system_call_error_number, "EPERM");
    }

    #[test]
    fn duration_90s() {
        assert_eq!(parse_duration("90s"), Some(Duration::from_secs(90)));
    }
}
