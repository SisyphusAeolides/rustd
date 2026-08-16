// SPDX-License-Identifier: LGPL-2.1-or-later
//! Condition and Assert evaluators for systemd unit files.
//!
//! `Condition*=` directives gate unit activation: a failing condition causes
//! the unit to be skipped (not failed). `Assert*=` directives cause the unit
//! to enter `failed` state when the assertion does not hold.
//!
//! Upstream reference: `src/shared/condition.c condition_test()` (v261)

use std::cmp::Ordering;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// The kind of condition, corresponding to a `Condition*=` / `Assert*=` key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConditionKind {
    // Path-based
    PathExists,
    PathExistsGlob,
    PathIsDirectory,
    PathIsSymbolicLink,
    PathIsMountPoint,
    PathIsReadWrite,
    PathIsEncrypted,
    DirectoryNotEmpty,
    // System properties
    Virtualization,
    Host,
    KernelCommandLine,
    KernelVersion,
    Credential,
    Environment,
    Security,
    Capability,
    ACPower,
    NeedsUpdate,
    FirstBoot,
    // Architecture / firmware
    Architecture,
    Firmware,
    // Version
    Version,
    // Memory / CPU
    Memory,
    CPUs,
    CPUFeature,
    // Catch-all for unknown condition types
    Unknown(String),
}

impl ConditionKind {
    /// Parse a `Condition*=` or `Assert*=` key name into a `ConditionKind`.
    ///
    /// Strips the leading `"Condition"` or `"Assert"` prefix before matching.
    #[must_use]
    pub fn from_key(key: &str) -> Self {
        let stripped = key
            .strip_prefix("Condition")
            .or_else(|| key.strip_prefix("Assert"))
            .unwrap_or(key);

        match stripped {
            "PathExists" => Self::PathExists,
            "PathExistsGlob" => Self::PathExistsGlob,
            "PathIsDirectory" => Self::PathIsDirectory,
            "PathIsSymbolicLink" => Self::PathIsSymbolicLink,
            "PathIsMountPoint" => Self::PathIsMountPoint,
            "PathIsReadWrite" => Self::PathIsReadWrite,
            "PathIsEncrypted" => Self::PathIsEncrypted,
            "DirectoryNotEmpty" => Self::DirectoryNotEmpty,
            "Virtualization" => Self::Virtualization,
            "Host" => Self::Host,
            "KernelCommandLine" => Self::KernelCommandLine,
            "KernelVersion" => Self::KernelVersion,
            "Credential" => Self::Credential,
            "Environment" => Self::Environment,
            "Security" => Self::Security,
            "Capability" => Self::Capability,
            "ACPower" => Self::ACPower,
            "NeedsUpdate" => Self::NeedsUpdate,
            "FirstBoot" => Self::FirstBoot,
            "Architecture" => Self::Architecture,
            "Firmware" => Self::Firmware,
            "Version" => Self::Version,
            "Memory" => Self::Memory,
            "CPUs" => Self::CPUs,
            "CPUFeature" => Self::CPUFeature,
            other => Self::Unknown(other.to_owned()),
        }
    }

    /// Return true if this key name is a condition or assert key.
    #[must_use]
    pub fn is_condition_key(key: &str) -> bool {
        key.starts_with("Condition") || key.starts_with("Assert")
    }
}

/// A parsed condition or assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Condition {
    /// The kind of check to perform.
    pub kind: ConditionKind,
    /// If true, invert the result (`!` prefix in the unit file).
    pub negate: bool,
    /// If true, this condition participates in the trigger/OR group (`|` prefix).
    pub trigger: bool,
    /// The value to check against (path, string, etc.).
    pub value: String,
    /// True if this was an `Assert*=` (vs `Condition*=`).
    pub is_assert: bool,
}

impl Condition {
    /// Return true if `key` is a `Condition*=` or `Assert*=` key.
    #[must_use]
    pub fn is_key(key: &str) -> bool {
        key.starts_with("Condition") || key.starts_with("Assert")
    }

    /// Evaluate a condition by reference (for use with iterators).
    #[must_use]
    pub fn evaluate_ref(cond: &Self) -> bool {
        evaluate(cond)
    }

    /// Parse a `Condition*=` or `Assert*=` key + value into a `Condition`.
    #[must_use]
    pub fn parse(key: &str, raw_value: &str) -> Self {
        let is_assert = key.starts_with("Assert");
        let kind = ConditionKind::from_key(key);

        let mut rest = raw_value;
        let mut negate = false;
        let mut trigger = false;
        loop {
            if let Some(next) = rest.strip_prefix('!') {
                negate = !negate;
                rest = next;
            } else if let Some(next) = rest.strip_prefix('|') {
                trigger = true;
                rest = next;
            } else {
                break;
            }
        }

        Self {
            kind,
            negate,
            trigger,
            value: rest.to_owned(),
            is_assert,
        }
    }
}

/// Evaluate a single condition against the live system.
///
/// Returns `true` if the condition passes (unit should proceed),
/// `false` if it fails (unit should be skipped or failed).
#[must_use]
pub fn evaluate(cond: &Condition) -> bool {
    let result = test_condition(cond);
    if cond.negate {
        !result
    } else {
        result
    }
}

/// Evaluate a systemd condition list, including the `|` trigger group.
#[must_use]
pub fn evaluate_list(conditions: &[Condition]) -> bool {
    let mut has_trigger = false;
    let mut trigger_passed = false;
    for condition in conditions {
        let passed = evaluate(condition);
        if condition.trigger {
            has_trigger = true;
            trigger_passed |= passed;
        } else if !passed {
            return false;
        }
    }
    !has_trigger || trigger_passed
}

#[allow(clippy::too_many_lines)]
fn test_condition(cond: &Condition) -> bool {
    match &cond.kind {
        ConditionKind::PathExists => Path::new(&cond.value).exists(),
        ConditionKind::PathExistsGlob => path_glob_exists(&cond.value),
        ConditionKind::PathIsDirectory => Path::new(&cond.value).is_dir(),
        ConditionKind::PathIsSymbolicLink => {
            fs::symlink_metadata(&cond.value).is_ok_and(|m| m.file_type().is_symlink())
        }
        ConditionKind::PathIsMountPoint => is_mount_point(&cond.value),
        ConditionKind::PathIsReadWrite => is_rw_filesystem(&cond.value),
        ConditionKind::PathIsEncrypted => path_is_encrypted(&cond.value),
        ConditionKind::DirectoryNotEmpty => directory_not_empty(&cond.value),
        ConditionKind::Virtualization => test_virtualization(&cond.value),
        ConditionKind::Host => test_host(&cond.value),
        ConditionKind::KernelCommandLine => {
            let cmdline = fs::read_to_string("/proc/cmdline").unwrap_or_default();
            let token = &cond.value;
            if token.contains('=') {
                cmdline.split_whitespace().any(|word| word == token)
            } else {
                cmdline.split_whitespace().any(|word| {
                    word == token || word.split_once('=').is_some_and(|(key, _)| key == token)
                })
            }
        }
        ConditionKind::KernelVersion => {
            kernel_release().is_some_and(|release| test_version_expression(&release, &cond.value))
        }
        ConditionKind::Credential => credential_exists(&cond.value),
        ConditionKind::Environment => {
            let (var, expected) = if let Some((key, value)) = cond.value.split_once('=') {
                (key, Some(value))
            } else {
                (cond.value.as_str(), None)
            };
            match (std::env::var(var), expected) {
                (Ok(_), None) => true,
                (Ok(actual), Some(expected)) => actual == expected,
                _ => false,
            }
        }
        ConditionKind::Security => test_security(&cond.value),
        ConditionKind::Capability => capability_in_bounding_set(&cond.value),
        ConditionKind::ACPower => {
            parse_boolean(&cond.value).is_some_and(|want_ac| detect_ac_power() == want_ac)
        }
        ConditionKind::NeedsUpdate => needs_update(&cond.value),
        ConditionKind::FirstBoot => parse_boolean(&cond.value).is_some_and(|want| {
            let first_boot = std::env::var("SYSTEMD_FIRST_BOOT")
                .ok()
                .as_deref()
                .and_then(parse_boolean)
                .unwrap_or_else(|| Path::new("/run/systemd/first-boot").exists());
            first_boot == want
        }),
        ConditionKind::Architecture => test_architecture(&cond.value),
        ConditionKind::Firmware => test_firmware(&cond.value),
        ConditionKind::Version => test_condition_version(&cond.value),
        ConditionKind::Memory => physical_memory_bytes()
            .is_some_and(|memory| compare_size_expression(memory, &cond.value)),
        ConditionKind::CPUs => std::thread::available_parallelism().is_ok_and(|cpus| {
            compare_count_expression(u64::try_from(cpus.get()).unwrap_or(u64::MAX), &cond.value)
        }),
        ConditionKind::CPUFeature => cpu_has_feature(&cond.value),
        ConditionKind::Unknown(_) => true,
    }
}

fn parse_boolean(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "yes" | "y" | "true" | "t" | "on" => Some(true),
        "0" | "no" | "n" | "false" | "f" | "off" => Some(false),
        _ => None,
    }
}

fn path_glob_exists(pattern: &str) -> bool {
    let path = Path::new(pattern);
    let mut components = Vec::new();
    for component in path.components() {
        components.push(component.as_os_str().to_string_lossy().into_owned());
    }

    let mut candidates = if path.is_absolute() {
        vec![PathBuf::from("/")]
    } else {
        vec![PathBuf::from(".")]
    };

    for component in components {
        if component == "/" || component == "." {
            continue;
        }
        let wildcard = has_glob_magic(&component);
        let mut next = Vec::new();
        for base in candidates {
            if wildcard {
                if let Ok(entries) = fs::read_dir(&base) {
                    for entry in entries.flatten() {
                        if glob_match(&component, &entry.file_name().to_string_lossy()) {
                            next.push(entry.path());
                        }
                    }
                }
            } else {
                let candidate = base.join(&component);
                if candidate.exists() {
                    next.push(candidate);
                }
            }
        }
        if next.is_empty() {
            return false;
        }
        candidates = next;
    }

    !candidates.is_empty()
}

fn directory_not_empty(path: &str) -> bool {
    fs::read_dir(path).is_ok_and(|entries| {
        entries.flatten().any(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            !name.starts_with('.') && !name.ends_with('~')
        })
    })
}

fn test_virtualization(value: &str) -> bool {
    let value = value.trim().to_ascii_lowercase();
    if value == "private-users" {
        return running_in_user_namespace();
    }

    let detected = detect_virtualization();
    if let Some(boolean) = parse_boolean(&value) {
        return boolean == (detected != "none");
    }
    if value == "none" {
        return detected == "none";
    }
    if value == "container" {
        return matches!(detected.as_str(), "docker" | "podman" | "lxc" | "container");
    }
    if value == "vm" {
        return detected != "none"
            && !matches!(detected.as_str(), "docker" | "podman" | "lxc" | "container");
    }
    detected == value
}

fn running_in_user_namespace() -> bool {
    let self_map = fs::read_to_string("/proc/self/uid_map").unwrap_or_default();
    let init_map = fs::read_to_string("/proc/1/uid_map").unwrap_or_default();
    !self_map.is_empty() && self_map != init_map
}

fn test_host(pattern: &str) -> bool {
    let normalized = normalize_id(pattern);
    if normalized.len() == 32 && normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        for path in [
            "/etc/machine-id",
            "/proc/sys/kernel/random/boot_id",
            "/sys/class/dmi/id/product_uuid",
        ] {
            if fs::read_to_string(path)
                .is_ok_and(|value| normalize_id(value.trim()).eq_ignore_ascii_case(&normalized))
            {
                return true;
            }
        }
    }

    kernel_hostname().is_some_and(|hostname| {
        glob_match(
            &pattern.to_ascii_lowercase(),
            &hostname.to_ascii_lowercase(),
        )
    })
}

fn normalize_id(value: &str) -> String {
    value
        .chars()
        .filter(|character| *character != '-')
        .collect()
}

fn kernel_hostname() -> Option<String> {
    fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn kernel_release() -> Option<String> {
    fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn credential_exists(name: &str) -> bool {
    if !credential_name_valid(name) {
        return false;
    }
    ["CREDENTIALS_DIRECTORY", "ENCRYPTED_CREDENTIALS_DIRECTORY"]
        .iter()
        .filter_map(std::env::var_os)
        .any(|directory| PathBuf::from(directory).join(name).exists())
}

fn credential_name_valid(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.chars().any(char::is_control)
}

fn test_security(value: &str) -> bool {
    match value {
        "selinux" => Path::new("/sys/fs/selinux").exists(),
        "apparmor" => Path::new("/sys/kernel/security/apparmor").exists(),
        "tomoyo" => Path::new("/sys/kernel/security/tomoyo").exists(),
        "smack" => Path::new("/sys/fs/smackfs").exists(),
        "ima" => Path::new("/sys/kernel/security/ima").exists(),
        "audit" => Path::new("/proc/sys/kernel/audit_enabled").exists(),
        "uefi-secureboot" => uefi_secure_boot(),
        "tpm2" => Path::new("/sys/class/tpm").exists() || Path::new("/sys/class/tpmrm").exists(),
        "cvm" => confidential_vm_detected(),
        "measured-uki" | "measured-os" => {
            Path::new("/sys/kernel/security/tpm0/binary_bios_measurements").exists()
                || Path::new("/sys/kernel/security/tpm0/ascii_bios_measurements").exists()
        }
        _ => false,
    }
}

fn uefi_secure_boot() -> bool {
    if !Path::new("/sys/firmware/efi/efivars").exists() {
        return false;
    }
    fs::read_dir("/sys/firmware/efi/efivars").is_ok_and(|entries| {
        entries.flatten().any(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.starts_with("SecureBoot-") {
                return false;
            }
            fs::read(entry.path())
                .ok()
                .and_then(|data| data.get(4).copied())
                == Some(1)
        })
    })
}

fn confidential_vm_detected() -> bool {
    [
        "/sys/firmware/sev",
        "/sys/firmware/tdx",
        "/sys/devices/platform/tdx_guest",
    ]
    .iter()
    .any(|path| Path::new(path).exists())
}

fn capability_in_bounding_set(name: &str) -> bool {
    let Some(bit) = capability_number(name) else {
        return false;
    };
    let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    let Some(value) = status
        .lines()
        .find_map(|line| line.strip_prefix("CapBnd:\t"))
    else {
        return false;
    };
    u64::from_str_radix(value.trim(), 16).is_ok_and(|mask| bit < 64 && mask & (1u64 << bit) != 0)
}

const CAPABILITY_NAMES: [&str; 41] = [
    "CHOWN",
    "DAC_OVERRIDE",
    "DAC_READ_SEARCH",
    "FOWNER",
    "FSETID",
    "KILL",
    "SETGID",
    "SETUID",
    "SETPCAP",
    "LINUX_IMMUTABLE",
    "NET_BIND_SERVICE",
    "NET_BROADCAST",
    "NET_ADMIN",
    "NET_RAW",
    "IPC_LOCK",
    "IPC_OWNER",
    "SYS_MODULE",
    "SYS_RAWIO",
    "SYS_CHROOT",
    "SYS_PTRACE",
    "SYS_PACCT",
    "SYS_ADMIN",
    "SYS_BOOT",
    "SYS_NICE",
    "SYS_RESOURCE",
    "SYS_TIME",
    "SYS_TTY_CONFIG",
    "MKNOD",
    "LEASE",
    "AUDIT_WRITE",
    "AUDIT_CONTROL",
    "SETFCAP",
    "MAC_OVERRIDE",
    "MAC_ADMIN",
    "SYSLOG",
    "WAKE_ALARM",
    "BLOCK_SUSPEND",
    "AUDIT_READ",
    "PERFMON",
    "BPF",
    "CHECKPOINT_RESTORE",
];

fn capability_number(name: &str) -> Option<u32> {
    let canonical = name.trim().to_ascii_uppercase();
    let canonical = canonical.strip_prefix("CAP_").unwrap_or(&canonical);
    CAPABILITY_NAMES
        .iter()
        .position(|candidate| *candidate == canonical)
        .and_then(|index| u32::try_from(index).ok())
}

fn detect_ac_power() -> bool {
    fs::read_dir("/sys/class/power_supply").map_or(true, |entries| {
        let mut saw_mains = false;
        let mut online = false;
        for entry in entries.flatten() {
            let kind = fs::read_to_string(entry.path().join("type")).unwrap_or_default();
            if kind.trim() != "Mains" {
                continue;
            }
            saw_mains = true;
            if fs::read_to_string(entry.path().join("online"))
                .is_ok_and(|value| value.trim() == "1")
            {
                online = true;
            }
        }
        !saw_mains || online
    })
}

fn needs_update(path: &str) -> bool {
    if kernel_cmdline_boolean("systemd.condition_needs_update").is_some_and(|value| value) {
        return true;
    }
    if kernel_cmdline_boolean("systemd.condition_needs_update") == Some(false) {
        return false;
    }
    if Path::new("/etc/initrd-release").exists()
        || Path::new("/run/systemd/initrd-release").exists()
    {
        return false;
    }
    if !Path::new(path).is_absolute() {
        return true;
    }
    if !is_rw_filesystem(path) {
        return false;
    }

    let marker = Path::new(path).join(".updated");
    let Ok(marker_meta) = fs::symlink_metadata(marker) else {
        return true;
    };
    let Ok(usr_meta) = fs::symlink_metadata("/usr") else {
        return true;
    };

    if usr_meta.mtime() != marker_meta.mtime() {
        return usr_meta.mtime() > marker_meta.mtime();
    }
    if usr_meta.mtime_nsec() == 0 || marker_meta.mtime_nsec() > 0 {
        return usr_meta.mtime_nsec() > marker_meta.mtime_nsec();
    }

    fs::read_to_string(Path::new(path).join(".updated"))
        .ok()
        .and_then(|contents| {
            contents.lines().find_map(|line| {
                line.strip_prefix("TIMESTAMP_NSEC=")
                    .and_then(|value| value.trim_matches('"').parse::<i128>().ok())
            })
        })
        .map_or(true, |timestamp| {
            i128::from(usr_meta.mtime()) * 1_000_000_000 + i128::from(usr_meta.mtime_nsec())
                > timestamp
        })
}

fn kernel_cmdline_boolean(key: &str) -> Option<bool> {
    let cmdline = fs::read_to_string("/proc/cmdline").ok()?;
    cmdline.split_whitespace().find_map(|word| {
        let (name, value) = word.split_once('=')?;
        (name == key).then_some(value).and_then(parse_boolean)
    })
}

fn test_architecture(value: &str) -> bool {
    let architecture = match std::env::consts::ARCH {
        "x86_64" => "x86-64",
        "x86" | "i686" | "i386" => "x86",
        "aarch64" => "arm64",
        "arm" => "arm",
        "riscv64" => "riscv64",
        other => other,
    };
    value == architecture || value == "native"
}

fn test_firmware(value: &str) -> bool {
    if value == "device-tree" {
        return Path::new("/sys/firmware/devicetree").exists();
    }
    if value == "uefi" {
        return Path::new("/sys/firmware/efi").exists();
    }
    if let Some(compatible) = value
        .strip_prefix("device-tree-compatible(")
        .and_then(|value| value.strip_suffix(')'))
    {
        return fs::read("/proc/device-tree/compatible").is_ok_and(|contents| {
            contents
                .split(|byte| *byte == 0)
                .any(|entry| entry == compatible.as_bytes())
        });
    }
    if let Some(expression) = value
        .strip_prefix("smbios-field(")
        .and_then(|value| value.strip_suffix(')'))
    {
        return test_smbios_expression(expression);
    }
    false
}

fn test_smbios_expression(expression: &str) -> bool {
    let Some((field, operator, expected)) = split_string_expression(expression) else {
        return false;
    };
    if field.is_empty()
        || field.contains('/')
        || field == "."
        || field == ".."
        || !field
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return false;
    }
    fs::read_to_string(Path::new("/sys/class/dmi/id").join(field))
        .is_ok_and(|actual| compare_strings(actual.trim(), expected.trim_matches('"'), operator))
}

fn split_string_expression(expression: &str) -> Option<(&str, CompareOp, &str)> {
    for (token, operator) in [
        ("!=", CompareOp::NotEqual),
        (">=", CompareOp::GreaterOrEqual),
        ("<=", CompareOp::LessOrEqual),
        ("==", CompareOp::Equal),
        ("=", CompareOp::Equal),
        (">", CompareOp::Greater),
        ("<", CompareOp::Less),
    ] {
        if let Some((left, right)) = expression.split_once(token) {
            return Some((left.trim(), operator, right.trim()));
        }
    }
    None
}

fn test_condition_version(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty() {
        return true;
    }

    let (subject, expression) =
        value
            .split_once(char::is_whitespace)
            .map_or(("kernel", value), |(subject, expression)| {
                if matches!(subject, "kernel" | "systemd" | "glibc") {
                    (subject, expression.trim())
                } else {
                    ("kernel", value)
                }
            });

    let actual = match subject {
        "kernel" => kernel_release(),
        "systemd" => Some("261".to_owned()),
        "glibc" => glibc_version(),
        _ => None,
    };
    actual.is_some_and(|actual| test_version_expression(&actual, expression))
}

fn glibc_version() -> Option<String> {
    for path in [
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/lib/aarch64-linux-gnu/libc.so.6",
        "/lib64/libc.so.6",
        "/lib/libc.so.6",
    ] {
        let Ok(canonical) = fs::canonicalize(path) else {
            continue;
        };
        let Some(name) = canonical.file_name() else {
            continue;
        };
        let name = name.to_string_lossy();
        if let Some(version) = name
            .strip_prefix("libc-")
            .and_then(|value| value.strip_suffix(".so"))
        {
            return Some(version.to_owned());
        }
    }
    None
}

fn physical_memory_bytes() -> Option<u64> {
    let meminfo = fs::read_to_string("/proc/meminfo").ok()?;
    let kilobytes = meminfo.lines().find_map(|line| {
        line.strip_prefix("MemTotal:")?
            .split_whitespace()
            .next()?
            .parse::<u64>()
            .ok()
    })?;
    kilobytes.checked_mul(1024)
}

fn compare_size_expression(actual: u64, expression: &str) -> bool {
    let (operator, value) = parse_compare_prefix(expression, CompareOp::GreaterOrEqual);
    parse_size_bytes(value).is_some_and(|expected| compare_order(actual.cmp(&expected), operator))
}

fn compare_count_expression(actual: u64, expression: &str) -> bool {
    let (operator, value) = parse_compare_prefix(expression, CompareOp::GreaterOrEqual);
    value
        .trim()
        .parse::<u64>()
        .is_ok_and(|expected| compare_order(actual.cmp(&expected), operator))
}

fn parse_size_bytes(value: &str) -> Option<u64> {
    let value = value.trim();
    let split = value
        .find(|character: char| !character.is_ascii_digit() && character != '.')
        .unwrap_or(value.len());
    let (number, suffix) = value.split_at(split);
    if number.is_empty() {
        return None;
    }
    let multiplier = match suffix.trim().to_ascii_uppercase().as_str() {
        "" | "B" => 1u128,
        "K" | "KB" | "KIB" => 1u128 << 10,
        "M" | "MB" | "MIB" => 1u128 << 20,
        "G" | "GB" | "GIB" => 1u128 << 30,
        "T" | "TB" | "TIB" => 1u128 << 40,
        "P" | "PB" | "PIB" => 1u128 << 50,
        "E" | "EB" | "EIB" => 1u128 << 60,
        _ => return None,
    };
    let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
    let whole = whole.parse::<u128>().ok()?;
    let fraction_value = if fraction.is_empty() {
        0
    } else {
        fraction.parse::<u128>().ok()?
    };
    let scale = if fraction.is_empty() {
        1
    } else {
        10u128.checked_pow(u32::try_from(fraction.len()).ok()?)?
    };
    let total = whole
        .checked_mul(multiplier)?
        .checked_add(fraction_value.checked_mul(multiplier)? / scale)?;
    u64::try_from(total).ok()
}

fn cpu_has_feature(feature: &str) -> bool {
    let feature = feature.trim().to_ascii_lowercase();
    if feature.is_empty() {
        return false;
    }
    fs::read_to_string("/proc/cpuinfo").is_ok_and(|cpuinfo| {
        cpuinfo.lines().any(|line| {
            let Some((key, values)) = line.split_once(':') else {
                return false;
            };
            matches!(key.trim(), "flags" | "Features")
                && values
                    .split_whitespace()
                    .any(|candidate| candidate.eq_ignore_ascii_case(&feature))
        })
    })
}

#[derive(Clone, Copy)]
enum CompareOp {
    Equal,
    NotEqual,
    Less,
    LessOrEqual,
    Greater,
    GreaterOrEqual,
    Pattern,
}

fn parse_compare_prefix(value: &str, default: CompareOp) -> (CompareOp, &str) {
    let value = value.trim();
    for (prefix, operator) in [
        (">=", CompareOp::GreaterOrEqual),
        ("<=", CompareOp::LessOrEqual),
        ("!=", CompareOp::NotEqual),
        ("==", CompareOp::Equal),
        ("=", CompareOp::Equal),
        (">", CompareOp::Greater),
        ("<", CompareOp::Less),
    ] {
        if let Some(rest) = value.strip_prefix(prefix) {
            return (operator, rest.trim());
        }
    }
    (default, value)
}

fn compare_order(ordering: Ordering, operator: CompareOp) -> bool {
    match operator {
        CompareOp::Equal => ordering == Ordering::Equal,
        CompareOp::NotEqual => ordering != Ordering::Equal,
        CompareOp::Less => ordering == Ordering::Less,
        CompareOp::LessOrEqual => ordering != Ordering::Greater,
        CompareOp::Greater => ordering == Ordering::Greater,
        CompareOp::GreaterOrEqual => ordering != Ordering::Less,
        CompareOp::Pattern => false,
    }
}

fn compare_strings(actual: &str, expected: &str, operator: CompareOp) -> bool {
    if matches!(operator, CompareOp::Equal | CompareOp::NotEqual) && has_glob_magic(expected) {
        let matched = glob_match(expected, actual);
        return if matches!(operator, CompareOp::NotEqual) {
            !matched
        } else {
            matched
        };
    }
    compare_order(version_cmp(actual, expected), operator)
}

fn test_version_expression(actual: &str, expression: &str) -> bool {
    for token in expression.split_whitespace() {
        let (operator, expected) = parse_compare_prefix(token, CompareOp::Pattern);
        let matched = if matches!(operator, CompareOp::Pattern) {
            if has_glob_magic(expected) {
                glob_match(expected, actual)
            } else {
                version_cmp(actual, expected) == Ordering::Equal
            }
        } else {
            compare_strings(actual, expected, operator)
        };
        if !matched {
            return false;
        }
    }
    true
}

fn has_glob_magic(value: &str) -> bool {
    value.bytes().any(|byte| matches!(byte, b'*' | b'?' | b'['))
}

fn version_cmp(left: &str, right: &str) -> Ordering {
    let left = version_tokens(left);
    let right = version_tokens(right);
    let length = left.len().max(right.len());
    for index in 0..length {
        match (left.get(index), right.get(index)) {
            (Some(VersionToken::Number(a)), Some(VersionToken::Number(b))) => {
                let ordering = a.cmp(b);
                if ordering != Ordering::Equal {
                    return ordering;
                }
            }
            (Some(VersionToken::Text(a)), Some(VersionToken::Text(b))) => {
                let ordering = a.cmp(b);
                if ordering != Ordering::Equal {
                    return ordering;
                }
            }
            (Some(VersionToken::Number(_)), Some(VersionToken::Text(_))) | (Some(_), None) => {
                return Ordering::Greater
            }
            (Some(VersionToken::Text(_)), Some(VersionToken::Number(_))) | (None, Some(_)) => {
                return Ordering::Less
            }
            (None, None) => break,
        }
    }
    Ordering::Equal
}

#[derive(Debug, PartialEq, Eq)]
enum VersionToken {
    Number(u128),
    Text(String),
}

fn version_tokens(value: &str) -> Vec<VersionToken> {
    let mut output = Vec::new();
    let mut current = String::new();
    let mut numeric = None;
    for character in value.chars() {
        if !character.is_ascii_alphanumeric() {
            flush_version_token(&mut output, &mut current, numeric);
            numeric = None;
            continue;
        }
        let is_numeric = character.is_ascii_digit();
        if numeric.is_some_and(|kind| kind != is_numeric) {
            flush_version_token(&mut output, &mut current, numeric);
        }
        numeric = Some(is_numeric);
        current.push(character.to_ascii_lowercase());
    }
    flush_version_token(&mut output, &mut current, numeric);
    output
}

fn flush_version_token(
    output: &mut Vec<VersionToken>,
    current: &mut String,
    numeric: Option<bool>,
) {
    if current.is_empty() {
        return;
    }
    if numeric == Some(true) {
        output.push(VersionToken::Number(current.parse().unwrap_or(u128::MAX)));
    } else {
        output.push(VersionToken::Text(std::mem::take(current)));
        return;
    }
    current.clear();
}

/// Glob matching used by host, firmware, version, and path conditions.
fn glob_match(pattern: &str, name: &str) -> bool {
    glob_match_bytes(pattern.as_bytes(), name.as_bytes())
}

fn glob_match_bytes(pattern: &[u8], text: &[u8]) -> bool {
    match pattern {
        [] => text.is_empty(),
        [b'*', rest @ ..] => {
            glob_match_bytes(rest, text)
                || (!text.is_empty() && glob_match_bytes(pattern, &text[1..]))
        }
        [b'?', rest @ ..] => !text.is_empty() && glob_match_bytes(rest, &text[1..]),
        [b'[', rest @ ..] => match_bracket(rest, text),
        [literal, rest @ ..] => text.first() == Some(literal) && glob_match_bytes(rest, &text[1..]),
    }
}

fn match_bracket(pattern: &[u8], text: &[u8]) -> bool {
    let Some(value) = text.first().copied() else {
        return false;
    };
    let Some(end) = pattern.iter().position(|byte| *byte == b']') else {
        return value == b'[' && glob_match_bytes(pattern, &text[1..]);
    };
    let class = &pattern[..end];
    let negate = class
        .first()
        .is_some_and(|byte| matches!(byte, b'!' | b'^'));
    let class = if negate { &class[1..] } else { class };
    let mut matched = false;
    let mut index = 0;
    while index < class.len() {
        if index + 2 < class.len() && class[index + 1] == b'-' {
            matched |= (class[index]..=class[index + 2]).contains(&value);
            index += 3;
        } else {
            matched |= class[index] == value;
            index += 1;
        }
    }
    matched ^= negate;
    matched && glob_match_bytes(&pattern[end + 1..], &text[1..])
}

/// Detect virtualisation from container markers and DMI data.
///
/// This is shared by `ConditionVirtualization=` and the Manager D-Bus
/// `Virtualization` property so both report the candidate's same live host
/// view.
#[must_use]
pub fn detect_virtualization() -> String {
    if Path::new("/.dockerenv").exists() {
        return "docker".to_owned();
    }
    if let Ok(environment) = fs::read_to_string("/proc/1/environ") {
        if environment.contains("container=podman") {
            return "podman".to_owned();
        }
        if environment.contains("container=lxc") {
            return "lxc".to_owned();
        }
        if environment.contains("container=") {
            return "container".to_owned();
        }
    }
    if let Ok(vendor) = fs::read_to_string("/sys/class/dmi/id/sys_vendor") {
        let vendor = vendor.trim().to_ascii_lowercase();
        if vendor.contains("vmware") {
            return "vmware".to_owned();
        }
        if vendor.contains("virtualbox") || vendor.contains("innotek") {
            return "oracle".to_owned();
        }
        if vendor.contains("microsoft") {
            return "microsoft".to_owned();
        }
        if vendor.contains("qemu") || vendor.contains("bochs") {
            return "qemu".to_owned();
        }
        if vendor.contains("xen") {
            return "xen".to_owned();
        }
    }
    "none".to_owned()
}

fn is_mount_point(path: &str) -> bool {
    let canonical = fs::canonicalize(path).unwrap_or_else(|_| PathBuf::from(path));
    mount_entries()
        .iter()
        .any(|entry| entry.mount_point == canonical)
}

/// Check whether the filesystem containing `path` is mounted read-write.
fn is_rw_filesystem(path: &str) -> bool {
    let canonical = fs::canonicalize(path).unwrap_or_else(|_| PathBuf::from(path));
    mount_entries()
        .into_iter()
        .filter(|entry| path_is_beneath(&canonical, &entry.mount_point))
        .max_by_key(|entry| entry.mount_point.as_os_str().len())
        .map_or(true, |entry| {
            entry.options.split(',').any(|option| option == "rw")
        })
}

fn path_is_encrypted(path: &str) -> bool {
    let canonical = fs::canonicalize(path).unwrap_or_else(|_| PathBuf::from(path));
    let Some(entry) = mount_entries()
        .into_iter()
        .filter(|entry| path_is_beneath(&canonical, &entry.mount_point))
        .max_by_key(|entry| entry.mount_point.as_os_str().len())
    else {
        return false;
    };
    block_device_encrypted(&entry.device, 0)
}

fn path_is_beneath(path: &Path, parent: &Path) -> bool {
    path == parent || path.starts_with(parent)
}

struct MountEntry {
    device: String,
    mount_point: PathBuf,
    options: String,
}

fn mount_entries() -> Vec<MountEntry> {
    let contents = fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    contents
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 6 {
                return None;
            }
            Some(MountEntry {
                device: fields[2].to_owned(),
                mount_point: PathBuf::from(unescape_mount_field(fields[4])),
                options: fields[5].to_owned(),
            })
        })
        .collect()
}

fn unescape_mount_field(value: &str) -> String {
    value
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

fn block_device_encrypted(device: &str, depth: usize) -> bool {
    if depth > 16 || !device.contains(':') {
        return false;
    }
    let root = PathBuf::from("/sys/dev/block").join(device);
    if fs::read_to_string(root.join("dm/uuid"))
        .is_ok_and(|uuid| uuid.trim_start().starts_with("CRYPT-"))
    {
        return true;
    }
    fs::read_dir(root.join("slaves")).is_ok_and(|entries| {
        entries.flatten().any(|entry| {
            fs::read_to_string(entry.path().join("dev"))
                .is_ok_and(|slave| block_device_encrypted(slave.trim(), depth + 1))
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_exists_true() {
        let condition = Condition::parse("ConditionPathExists", "/etc/hostname");
        assert!(evaluate(&condition));
    }

    #[test]
    fn path_exists_false() {
        let condition = Condition::parse("ConditionPathExists", "/nonexistent_path_xyz");
        assert!(!evaluate(&condition));
    }

    #[test]
    fn path_exists_negated() {
        let condition = Condition::parse("ConditionPathExists", "!/nonexistent_path_xyz");
        assert!(evaluate(&condition));
    }

    #[test]
    fn path_is_directory() {
        let condition = Condition::parse("ConditionPathIsDirectory", "/etc");
        assert!(evaluate(&condition));
    }

    #[test]
    fn virtualization_none() {
        let condition = Condition::parse("ConditionVirtualization", "none");
        let _ = evaluate(&condition);
    }

    #[test]
    fn kernel_cmdline_present() {
        let condition = Condition::parse("ConditionKernelCommandLine", "ro");
        let _ = evaluate(&condition);
    }

    #[test]
    fn assert_parse() {
        let condition = Condition::parse("AssertPathExists", "/etc");
        assert!(condition.is_assert);
        assert!(!condition.negate);
        assert!(!condition.trigger);
        assert_eq!(condition.value, "/etc");
    }

    #[test]
    fn trigger_and_negation_prefixes_parse() {
        let condition = Condition::parse("ConditionPathExists", "|!/missing");
        assert!(condition.trigger);
        assert!(condition.negate);
        assert_eq!(condition.value, "/missing");
    }

    #[test]
    fn condition_trigger_group_is_orred() {
        let conditions = vec![
            Condition::parse("ConditionPathExists", "|/definitely-missing-a"),
            Condition::parse("ConditionPathExists", "|!/definitely-missing-b"),
            Condition::parse("ConditionPathExists", "/"),
        ];
        assert!(evaluate_list(&conditions));
        let failing = vec![
            Condition::parse("ConditionPathExists", "|/definitely-missing-a"),
            Condition::parse("ConditionPathExists", "|/definitely-missing-b"),
            Condition::parse("ConditionPathExists", "/"),
        ];
        assert!(!evaluate_list(&failing));
    }

    #[test]
    fn glob_patterns() {
        assert!(glob_match("*.service", "foo.service"));
        assert!(!glob_match("*.service", "foo.socket"));
        assert!(glob_match("foo?", "fooa"));
        assert!(glob_match("[ab]ar", "bar"));
        assert!(glob_match("*", "anything"));
    }

    #[test]
    fn count_comparison_defaults_to_greater_equal() {
        assert!(compare_count_expression(8, "4"));
        assert!(compare_count_expression(8, ">=8"));
        assert!(!compare_count_expression(8, ">8"));
    }

    #[test]
    fn size_comparison_uses_binary_suffixes() {
        assert!(compare_size_expression(2 * 1024 * 1024, "1M"));
        assert!(!compare_size_expression(1024, ">2K"));
    }

    #[test]
    fn version_predicates_compare_numeric_segments() {
        assert!(test_version_expression("6.8.12", ">=6.8"));
        assert!(!test_version_expression("6.8.12", ">7"));
        assert!(test_version_expression("6.8.12-generic", "6.8.*"));
    }

    #[test]
    fn capability_names_map_to_linux_numbers() {
        assert_eq!(capability_number("CAP_SYS_ADMIN"), Some(21));
        assert_eq!(capability_number("bpf"), Some(39));
        assert_eq!(capability_number("invalid"), None);
    }

    #[test]
    fn credential_names_reject_paths() {
        assert!(credential_name_valid("network.key"));
        assert!(!credential_name_valid("../network.key"));
        assert!(!credential_name_valid("nested/key"));
    }
}
