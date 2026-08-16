// SPDX-License-Identifier: LGPL-2.1-or-later
//! Shared process-resource-limit parsing and manager-default helpers.
//!
//! The same rlimit grammar is used by `[Manager] DefaultLimit*=` and
//! `[Service] Limit*=`.  Keeping it in one module prevents the two parsers
//! from drifting apart at the boundary where manager defaults are inherited
//! by a unit's execution context.

use crate::unit::duration::parse_duration;

/// One numeric side of a process resource limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RlimitValue {
    /// A finite kernel rlimit value.
    Value(u64),
    /// `RLIM_INFINITY`.
    Infinity,
}

/// Parsed soft and hard resource limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RlimitSpec {
    /// The soft (`rlim_cur`) value.
    pub soft: RlimitValue,
    /// The hard (`rlim_max`) value.
    pub hard: RlimitValue,
}

/// Grammar used by a `Limit*=` assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RlimitKind {
    /// CPU time in seconds, rounded up from sub-second values.
    Seconds,
    /// Byte quantities.
    Size,
    /// Unsigned counter values.
    Count,
    /// Nice priority resource encoding.
    Nice,
    /// Real-time CPU time in microseconds.
    Microseconds,
}

impl RlimitSpec {
    /// Parse `soft[:hard]` using the resource-specific systemd grammar.
    #[must_use]
    pub fn parse(s: &str, kind: RlimitKind) -> Option<Self> {
        let mut fields = s.split(':');
        let soft = parse_rlimit_value(fields.next()?, kind)?;
        let hard = match fields.next() {
            Some(value) => parse_rlimit_value(value, kind)?,
            None => soft,
        };
        if fields.next().is_some() || rlimit_ord(soft) > rlimit_ord(hard) {
            return None;
        }
        Some(Self { soft, hard })
    }
}

fn rlimit_ord(value: RlimitValue) -> u128 {
    match value {
        RlimitValue::Value(value) => u128::from(value),
        RlimitValue::Infinity => u128::MAX,
    }
}

fn parse_rlimit_value(value: &str, kind: RlimitKind) -> Option<RlimitValue> {
    if value == "infinity" && !matches!(kind, RlimitKind::Nice) {
        return Some(RlimitValue::Infinity);
    }
    let raw = match kind {
        RlimitKind::Count => value.parse().ok()?,
        RlimitKind::Size => parse_rlimit_size(value)?,
        RlimitKind::Seconds => {
            let duration = parse_duration(value)?;
            let micros = duration.as_micros();
            let seconds = micros.saturating_add(999_999) / 1_000_000;
            u64::try_from(seconds).ok()?
        }
        RlimitKind::Microseconds => {
            let duration = parse_duration(value)?;
            u64::try_from(duration.as_micros()).ok()?
        }
        RlimitKind::Nice => parse_rlimit_nice(value)?,
    };
    (raw < u64::MAX).then_some(RlimitValue::Value(raw))
}

fn parse_rlimit_nice(value: &str) -> Option<u64> {
    if let Some(raw) = value.strip_prefix('+') {
        let nice: u64 = raw.parse().ok()?;
        (nice < 20).then_some(20 - nice)
    } else if let Some(raw) = value.strip_prefix('-') {
        let magnitude: u64 = raw.parse().ok()?;
        (magnitude <= 20).then_some(20 + magnitude)
    } else {
        let raw: u64 = value.parse().ok()?;
        (raw <= 40).then_some(raw)
    }
}

#[allow(clippy::cast_precision_loss)]
fn parse_rlimit_size(value: &str) -> Option<u64> {
    let mut total = 0f64;
    let mut input = value.trim();
    if input.is_empty() {
        return None;
    }
    while !input.is_empty() {
        input = input.trim_start();
        let number_end = input
            .find(|character: char| !character.is_ascii_digit() && character != '.')
            .unwrap_or(input.len());
        if number_end == 0 {
            return None;
        }
        let number: f64 = input[..number_end].parse().ok()?;
        if !number.is_finite() || number < 0.0 {
            return None;
        }
        input = &input[number_end..];
        let suffix_end = input
            .find(|character: char| !character.is_ascii_alphabetic())
            .unwrap_or(input.len());
        let suffix = input[..suffix_end].to_ascii_uppercase();
        let factor = match suffix.as_str() {
            "" | "B" => 1u64,
            "K" | "KB" | "KIB" => 1u64 << 10,
            "M" | "MB" | "MIB" => 1u64 << 20,
            "G" | "GB" | "GIB" => 1u64 << 30,
            "T" | "TB" | "TIB" => 1u64 << 40,
            "P" | "PB" | "PIB" => 1u64 << 50,
            "E" | "EB" | "EIB" => 1u64 << 60,
            _ => return None,
        };
        total += number * factor as f64;
        if total >= u64::MAX as f64 {
            return None;
        }
        input = &input[suffix_end..];
        if !input.is_empty() && !input.starts_with(char::is_whitespace) {
            return None;
        }
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Some(total as u64)
}

/// The 16 rlimit resources exposed by the Manager D-Bus interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RlimitResource {
    /// `RLIMIT_CPU` / `DefaultLimitCPU`.
    Cpu,
    /// `RLIMIT_FSIZE` / `DefaultLimitFSIZE`.
    Fsize,
    /// `RLIMIT_DATA` / `DefaultLimitDATA`.
    Data,
    /// `RLIMIT_STACK` / `DefaultLimitSTACK`.
    Stack,
    /// `RLIMIT_CORE` / `DefaultLimitCORE`.
    Core,
    /// `RLIMIT_RSS` / `DefaultLimitRSS`.
    Rss,
    /// `RLIMIT_NOFILE` / `DefaultLimitNOFILE`.
    Nofile,
    /// `RLIMIT_AS` / `DefaultLimitAS`.
    As,
    /// `RLIMIT_NPROC` / `DefaultLimitNPROC`.
    Nproc,
    /// `RLIMIT_MEMLOCK` / `DefaultLimitMEMLOCK`.
    Memlock,
    /// `RLIMIT_LOCKS` / `DefaultLimitLOCKS`.
    Locks,
    /// `RLIMIT_SIGPENDING` / `DefaultLimitSIGPENDING`.
    Sigpending,
    /// `RLIMIT_MSGQUEUE` / `DefaultLimitMSGQUEUE`.
    Msgqueue,
    /// `RLIMIT_NICE` / `DefaultLimitNICE`.
    Nice,
    /// `RLIMIT_RTPRIO` / `DefaultLimitRTPRIO`.
    Rtprio,
    /// `RLIMIT_RTTIME` / `DefaultLimitRTTIME`.
    Rttime,
}

impl RlimitResource {
    /// All resources in the v261 Manager property/configuration order.
    pub const ALL: [Self; 16] = [
        Self::Cpu,
        Self::Fsize,
        Self::Data,
        Self::Stack,
        Self::Core,
        Self::Rss,
        Self::Nofile,
        Self::As,
        Self::Nproc,
        Self::Memlock,
        Self::Locks,
        Self::Sigpending,
        Self::Msgqueue,
        Self::Nice,
        Self::Rtprio,
        Self::Rttime,
    ];

    /// Array index used by `UnitDefaults`.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::Cpu => 0,
            Self::Fsize => 1,
            Self::Data => 2,
            Self::Stack => 3,
            Self::Core => 4,
            Self::Rss => 5,
            Self::Nofile => 6,
            Self::As => 7,
            Self::Nproc => 8,
            Self::Memlock => 9,
            Self::Locks => 10,
            Self::Sigpending => 11,
            Self::Msgqueue => 12,
            Self::Nice => 13,
            Self::Rtprio => 14,
            Self::Rttime => 15,
        }
    }

    /// Configuration key suffix without the `DefaultLimit` prefix.
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::Cpu => "CPU",
            Self::Fsize => "FSIZE",
            Self::Data => "DATA",
            Self::Stack => "STACK",
            Self::Core => "CORE",
            Self::Rss => "RSS",
            Self::Nofile => "NOFILE",
            Self::As => "AS",
            Self::Nproc => "NPROC",
            Self::Memlock => "MEMLOCK",
            Self::Locks => "LOCKS",
            Self::Sigpending => "SIGPENDING",
            Self::Msgqueue => "MSGQUEUE",
            Self::Nice => "NICE",
            Self::Rtprio => "RTPRIO",
            Self::Rttime => "RTTIME",
        }
    }

    /// Grammar used by this resource's configuration value.
    #[must_use]
    pub const fn kind(self) -> RlimitKind {
        match self {
            Self::Cpu => RlimitKind::Seconds,
            Self::Fsize | Self::Data | Self::Stack | Self::Core | Self::Rss | Self::As => {
                RlimitKind::Size
            }
            Self::Nofile | Self::Nproc | Self::Locks | Self::Sigpending | Self::Rtprio => {
                RlimitKind::Count
            }
            Self::Memlock | Self::Msgqueue => RlimitKind::Size,
            Self::Nice => RlimitKind::Nice,
            Self::Rttime => RlimitKind::Microseconds,
        }
    }

    /// libc resource identifier used by the fallback D-Bus getter.
    #[must_use]
    pub const fn libc_resource(self) -> libc::__rlimit_resource_t {
        match self {
            Self::Cpu => libc::RLIMIT_CPU,
            Self::Fsize => libc::RLIMIT_FSIZE,
            Self::Data => libc::RLIMIT_DATA,
            Self::Stack => libc::RLIMIT_STACK,
            Self::Core => libc::RLIMIT_CORE,
            Self::Rss => libc::RLIMIT_RSS,
            Self::Nofile => libc::RLIMIT_NOFILE,
            Self::As => libc::RLIMIT_AS,
            Self::Nproc => libc::RLIMIT_NPROC,
            Self::Memlock => libc::RLIMIT_MEMLOCK,
            Self::Locks => libc::RLIMIT_LOCKS,
            Self::Sigpending => libc::RLIMIT_SIGPENDING,
            Self::Msgqueue => libc::RLIMIT_MSGQUEUE,
            Self::Nice => libc::RLIMIT_NICE,
            Self::Rtprio => libc::RLIMIT_RTPRIO,
            Self::Rttime => libc::RLIMIT_RTTIME,
        }
    }
}

/// Manager `DefaultTasksMax=` value. `scale == 0` means an absolute value;
/// `u64::MAX, 0` is the v261 unlimited sentinel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TasksMaxSpec {
    /// Absolute value or percentage numerator.
    pub value: u64,
    /// Percentage denominator, or zero for an absolute value.
    pub scale: u64,
}

impl Default for TasksMaxSpec {
    fn default() -> Self {
        Self {
            value: 15,
            scale: 100,
        }
    }
}

impl TasksMaxSpec {
    /// The unlimited `TasksMax` value.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            value: u64::MAX,
            scale: 0,
        }
    }

    /// Parse the manager/unit `TasksMax` grammar.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let value = value.trim();
        if value.is_empty() || value == "infinity" {
            return Some(Self::unlimited());
        }
        if let Some(numerator) = parse_permyriad(value) {
            return Some(Self {
                value: numerator,
                scale: 10_000,
            });
        }
        let absolute = value.parse::<u64>().ok()?;
        (absolute > 0 && absolute < u64::MAX).then_some(Self {
            value: absolute,
            scale: 0,
        })
    }

    /// Resolve this value against the host's system task capacity.
    #[must_use]
    pub fn resolve(self) -> u64 {
        if self.scale == 0 {
            return self.value;
        }
        let capacity = system_tasks_max();
        u64::try_from(
            u128::from(capacity)
                .saturating_mul(u128::from(self.value))
                .checked_div(u128::from(self.scale))
                .unwrap_or(u128::from(u64::MAX)),
        )
        .unwrap_or(u64::MAX)
    }
}

fn parse_permyriad(value: &str) -> Option<u64> {
    let (number, multiplier, precision) = if let Some(number) = value.strip_suffix('‱') {
        (number, 1, 0)
    } else if let Some(number) = value.strip_suffix('‰') {
        (number, 10, 1)
    } else {
        let number = value.strip_suffix('%')?;
        (number, 100, 2)
    };

    let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
    if whole.is_empty()
        || !whole.chars().all(|character| character.is_ascii_digit())
        || (number.contains('.') && fraction.is_empty())
        || fraction.len() > precision
        || !fraction.chars().all(|character| character.is_ascii_digit())
    {
        return None;
    }
    let whole = whole.parse::<u64>().ok()?;
    let fraction = if fraction.is_empty() {
        0
    } else {
        fraction.parse::<u64>().ok()?
            * 10u64.checked_pow(u32::try_from(precision - fraction.len()).ok()?)?
    };
    let result = whole.checked_mul(multiplier)?.checked_add(fraction)?;
    (result <= 10_000).then_some(result)
}

/// Resolve the kernel's system-wide task capacity used by `DefaultTasksMax`.
#[must_use]
pub fn system_tasks_max() -> u64 {
    let threads = read_u64("/proc/sys/kernel/threads-max").unwrap_or(u64::MAX);
    let pids = read_u64("/proc/sys/kernel/pid_max")
        .unwrap_or(u64::MAX)
        .saturating_sub(1);
    let root_pids = std::fs::read_to_string("/sys/fs/cgroup/pids.max")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(u64::MAX);
    threads.min(pids).min(root_pids)
}

fn read_u64(path: &str) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Convert an rlimit value into the D-Bus representation.
#[must_use]
pub const fn rlimit_value(value: RlimitValue) -> u64 {
    match value {
        RlimitValue::Value(value) => value,
        RlimitValue::Infinity => u64::MAX,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_rlimit_parser_matches_unit_grammar() {
        assert_eq!(
            RlimitSpec::parse("55:66", RlimitKind::Count),
            Some(RlimitSpec {
                soft: RlimitValue::Value(55),
                hard: RlimitValue::Value(66),
            })
        );
        assert_eq!(
            RlimitSpec::parse("40s:1m", RlimitKind::Seconds),
            Some(RlimitSpec {
                soft: RlimitValue::Value(40),
                hard: RlimitValue::Value(60),
            })
        );
        assert_eq!(RlimitSpec::parse("200:100", RlimitKind::Count), None);
        assert_eq!(
            RlimitSpec::parse("infinity", RlimitKind::Count),
            Some(RlimitSpec {
                soft: RlimitValue::Infinity,
                hard: RlimitValue::Infinity,
            })
        );
    }

    #[test]
    fn tasks_max_supports_absolute_percentage_and_unlimited() {
        assert_eq!(
            TasksMaxSpec::parse("32"),
            Some(TasksMaxSpec {
                value: 32,
                scale: 0
            })
        );
        assert_eq!(
            TasksMaxSpec::parse("15%"),
            Some(TasksMaxSpec {
                value: 1500,
                scale: 10_000,
            })
        );
        assert_eq!(
            TasksMaxSpec::parse("infinity"),
            Some(TasksMaxSpec::unlimited())
        );
        assert_eq!(TasksMaxSpec::parse("0"), None);
    }

    #[test]
    fn permyriad_parser_matches_v261_vectors() {
        for (value, numerator) in [
            ("0‱", 0),
            ("555‱", 555),
            ("1000‱", 1000),
            ("0‰", 0),
            ("555.5‰", 5555),
            ("1000.0‰", 10_000),
            ("0%", 0),
            ("55%", 5500),
            ("55.5%", 5550),
            ("55.50%", 5550),
            ("55.53%", 5553),
            ("100%", 10_000),
        ] {
            assert_eq!(parse_permyriad(value), Some(numerator), "{value}");
        }
        for value in [
            "", "foo", "0", "50", "100", "-1", "-7‱", "10007‱", "‱", "‱‱", "‱1", "1‱‱", "3.2‱",
            "-7‰", "1007‰", "‰", "‰‰", "‰1", "1‰‰", "3.22‰", "-7%", "107%", "%", "%%", "%1", "1%%",
            "3.212%",
        ] {
            assert_eq!(parse_permyriad(value), None, "{value}");
        }
    }

    #[test]
    fn tasks_max_rejects_non_v261_unlimited_spellings_and_precision() {
        for value in ["3.212%", "3.22‰", "3.2‱", "max", "Infinity"] {
            assert_eq!(TasksMaxSpec::parse(value), None, "{value}");
        }
    }
}
