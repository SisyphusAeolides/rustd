// SPDX-License-Identifier: LGPL-2.1-or-later
//! Cgroup-v2 resource-control property parsing and normalization.
//!
//! The manager stores the canonical unit-file properties here so the unit
//! parser, `rustctl set-property`, and cgroup writer share one definition.

use crate::limits::TasksMaxSpec;

/// A cgroup numeric limit or the controller's unlimited value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitValue {
    /// A concrete controller value.
    Value(u64),
    /// No configured upper bound (`max` in cgroup v2 files).
    Max,
}

impl LimitValue {
    /// Return the value accepted by a cgroup v2 control file.
    #[must_use]
    pub fn cgroup_value(self) -> String {
        match self {
            Self::Value(value) => value.to_string(),
            Self::Max => "max".to_owned(),
        }
    }
}

/// `CPUQuota=` represented in hundredths of one percent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuQuota {
    /// A quota percentage, where 10.25% is stored as 1025.
    PercentHundredths(u64),
    /// Disable the CPU quota.
    Max,
}

impl CpuQuota {
    /// Render the canonical unit-file value used by `rustctl set-property`.
    #[must_use]
    pub fn unit_value(self) -> String {
        match self {
            Self::PercentHundredths(value) => {
                format!("{}.{:02}%", value / 100, value % 100)
            }
            Self::Max => "infinity".to_owned(),
        }
    }

    /// Render `cpu.max` using systemd's 100 ms default period.
    #[must_use]
    pub fn cgroup_value(self) -> String {
        const PERIOD_USEC: u64 = 100_000;
        match self {
            Self::Max => format!("max {PERIOD_USEC}"),
            Self::PercentHundredths(value) => {
                let quota =
                    u64::try_from((u128::from(PERIOD_USEC) * u128::from(value)).div_ceil(10_000))
                        .unwrap_or(u64::MAX)
                        .max(1_000);
                format!("{quota} {PERIOD_USEC}")
            }
        }
    }
}

/// Resource controls currently enforced on service cgroups.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ResourceControl {
    pub io_accounting: bool,
    pub memory_accounting: bool,
    pub tasks_accounting: bool,
    pub ip_accounting: bool,
    pub cpu_weight: Option<u64>,
    pub cpu_quota: Option<CpuQuota>,
    pub io_weight: Option<u64>,
    pub memory_min: Option<LimitValue>,
    pub memory_low: Option<LimitValue>,
    pub memory_high: Option<LimitValue>,
    pub memory_max: Option<LimitValue>,
    pub memory_swap_max: Option<LimitValue>,
    pub memory_zswap_max: Option<LimitValue>,
    pub memory_zswap_writeback: Option<bool>,
    pub tasks_max: Option<LimitValue>,
    /// True when `tasks_max` came from the manager default rather than an
    /// explicit unit property. This keeps unavailable pids controllers
    /// non-fatal while retaining the inherited D-Bus value.
    pub tasks_max_default: bool,
    /// Whether CPU idle scheduling is requested (`CPUWeight=idle`).
    pub cpu_idle: bool,
}

impl ResourceControl {
    /// Return whether at least one resource-control property is configured.
    #[must_use]
    pub fn is_configured(&self) -> bool {
        self.io_accounting
            || self.memory_accounting
            || self.tasks_accounting
            || self.ip_accounting
            || self.cpu_weight.is_some()
            || self.cpu_idle
            || self.cpu_quota.is_some()
            || self.io_weight.is_some()
            || self.memory_min.is_some()
            || self.memory_low.is_some()
            || self.memory_high.is_some()
            || self.memory_max.is_some()
            || self.memory_swap_max.is_some()
            || self.memory_zswap_max.is_some()
            || self.memory_zswap_writeback.is_some()
            || self.tasks_max.is_some() && !self.tasks_max_default
    }

    /// Apply one unit-file key. Returns true when the key is a supported
    /// resource-control setting, even if its value is invalid.
    pub fn apply(&mut self, key: &str, value: &str) -> bool {
        match key {
            "IOAccounting" => self.io_accounting = parse_bool(value),
            "MemoryAccounting" => self.memory_accounting = parse_bool(value),
            "TasksAccounting" => self.tasks_accounting = parse_bool(value),
            "IPAccounting" => self.ip_accounting = parse_bool(value),
            "CPUWeight" => {
                if value.trim().eq_ignore_ascii_case("idle") {
                    self.cpu_weight = None;
                    self.cpu_idle = true;
                } else {
                    self.cpu_idle = false;
                    self.cpu_weight = parse_weight(value);
                }
            }
            "CPUShares" => {
                self.cpu_idle = false;
                self.cpu_weight = parse_cpu_shares(value);
            }
            "CPUQuota" => self.cpu_quota = parse_cpu_quota(value),
            "IOWeight" => self.io_weight = parse_weight(value),
            "BlockIOWeight" => self.io_weight = parse_block_io_weight(value),
            "MemoryMin" => self.memory_min = parse_size_limit(value),
            "MemoryLow" => self.memory_low = parse_size_limit(value),
            "MemoryHigh" => self.memory_high = parse_size_limit(value),
            "MemoryMax" | "MemoryLimit" => self.memory_max = parse_size_limit(value),
            "MemorySwapMax" => self.memory_swap_max = parse_size_limit(value),
            "MemoryZSwapMax" => self.memory_zswap_max = parse_size_limit(value),
            "MemoryZSwapWriteback" => self.memory_zswap_writeback = Some(parse_bool(value)),
            "TasksMax" => {
                if value.trim().is_empty() {
                    // An empty unit assignment restores the manager default
                    // when the unit contexts are patched after parsing.
                    self.tasks_max = None;
                    self.tasks_max_default = false;
                } else if let Some(parsed) = parse_count_limit(value) {
                    self.tasks_max = Some(parsed);
                    self.tasks_max_default = false;
                }
            }
            _ => return false,
        }
        true
    }
}

fn parse_bool(value: &str) -> bool {
    matches!(value.trim(), "1" | "yes" | "true" | "on")
}

/// A validated, canonical unit-file assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedProperty {
    pub key: &'static str,
    pub value: String,
}

/// Validate a `rustctl set-property` assignment and normalize aliases.
///
/// # Errors
/// Returns a user-facing error for unsupported properties or invalid values.
pub fn normalize_property(key: &str, value: &str) -> Result<NormalizedProperty, String> {
    let value = value.trim();
    match key {
        "CPUWeight" if value.eq_ignore_ascii_case("idle") => Ok(NormalizedProperty {
            key: "CPUWeight",
            value: "idle".to_owned(),
        }),
        "CPUWeight" => normalize_weight("CPUWeight", value, parse_weight),
        "CPUShares" => normalize_weight("CPUWeight", value, parse_cpu_shares),
        "CPUQuota" => parse_cpu_quota(value)
            .map(|quota| NormalizedProperty {
                key: "CPUQuota",
                value: quota.unit_value(),
            })
            .ok_or_else(|| "CPUQuota must be a positive percentage or infinity".to_owned()),
        "IOWeight" => normalize_weight("IOWeight", value, parse_weight),
        "BlockIOWeight" => normalize_weight("IOWeight", value, parse_block_io_weight),
        "MemoryMin" => normalize_size("MemoryMin", value),
        "MemoryLow" => normalize_size("MemoryLow", value),
        "MemoryHigh" => normalize_size("MemoryHigh", value),
        "MemoryMax" | "MemoryLimit" => normalize_size("MemoryMax", value),
        "MemorySwapMax" => normalize_size("MemorySwapMax", value),
        "MemoryZSwapMax" => normalize_size("MemoryZSwapMax", value),
        "MemoryZSwapWriteback" => parse_bool_value("MemoryZSwapWriteback", value),
        "TasksMax" if value.is_empty() => Ok(NormalizedProperty {
            key: "TasksMax",
            value: String::new(),
        }),
        "TasksMax" => parse_count_limit(value)
            .map(|limit| NormalizedProperty {
                key: "TasksMax",
                value: unit_limit_value(limit),
            })
            .ok_or_else(|| {
                "TasksMax must be a positive integer, percentage, or infinity".to_owned()
            }),
        _ => Err(format!("unsupported property '{key}'")),
    }
}

fn parse_bool_value(key: &'static str, value: &str) -> Result<NormalizedProperty, String> {
    let normalized = match value.trim().to_ascii_lowercase().as_str() {
        "1" | "yes" | "true" | "on" => "yes",
        "0" | "no" | "false" | "off" => "no",
        _ => return Err(format!("{key} must be a boolean")),
    };
    Ok(NormalizedProperty {
        key,
        value: normalized.to_owned(),
    })
}

fn normalize_weight(
    key: &'static str,
    value: &str,
    parser: fn(&str) -> Option<u64>,
) -> Result<NormalizedProperty, String> {
    parser(value)
        .map(|weight| NormalizedProperty {
            key,
            value: weight.to_string(),
        })
        .ok_or_else(|| format!("{key} must resolve to an integer in the range 1..=10000"))
}

fn normalize_size(key: &'static str, value: &str) -> Result<NormalizedProperty, String> {
    parse_size_limit(value)
        .map(|limit| NormalizedProperty {
            key,
            value: unit_limit_value(limit),
        })
        .ok_or_else(|| {
            format!("{key} must be a byte count with an optional K/M/G/T/P suffix, or infinity")
        })
}

fn unit_limit_value(limit: LimitValue) -> String {
    match limit {
        LimitValue::Value(value) => value.to_string(),
        LimitValue::Max => "infinity".to_owned(),
    }
}

fn parse_weight(value: &str) -> Option<u64> {
    value
        .trim()
        .parse::<u64>()
        .ok()
        .filter(|weight| (1..=10_000).contains(weight))
}

fn parse_cpu_shares(value: &str) -> Option<u64> {
    let shares = value.trim().parse::<u64>().ok()?;
    if !(2..=262_144).contains(&shares) {
        return None;
    }
    Some(1 + ((shares - 2) * 9_999) / 262_142)
}

fn parse_block_io_weight(value: &str) -> Option<u64> {
    let weight = value.trim().parse::<u64>().ok()?;
    if !(10..=1_000).contains(&weight) {
        return None;
    }
    Some(1 + ((weight - 10) * 9_999) / 990)
}

fn parse_count_limit(value: &str) -> Option<LimitValue> {
    TasksMaxSpec::parse(value).map(|spec| match spec.resolve() {
        value if value == u64::MAX => LimitValue::Max,
        value => LimitValue::Value(value),
    })
}

fn parse_size_limit(value: &str) -> Option<LimitValue> {
    if is_unlimited(value) {
        return Some(LimitValue::Max);
    }
    parse_size_bytes(value).map(LimitValue::Value)
}

fn is_unlimited(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "infinity" | "max"
    )
}

fn parse_size_bytes(value: &str) -> Option<u64> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

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

    let (whole, fractional, scale) = parse_decimal(number)?;
    let scaled = u128::from(whole)
        .checked_mul(multiplier)?
        .checked_add(u128::from(fractional).checked_mul(multiplier)? / u128::from(scale))?;
    u64::try_from(scaled).ok()
}

fn parse_cpu_quota(value: &str) -> Option<CpuQuota> {
    if is_unlimited(value) {
        return Some(CpuQuota::Max);
    }
    let number = value.trim().strip_suffix('%')?;
    let (whole, fractional, scale) = parse_decimal(number)?;
    let hundredths = u128::from(whole)
        .checked_mul(100)?
        .checked_add((u128::from(fractional) * 100).div_ceil(u128::from(scale)))?;
    let hundredths = u64::try_from(hundredths).ok()?;
    (hundredths > 0).then_some(CpuQuota::PercentHundredths(hundredths))
}

fn parse_decimal(value: &str) -> Option<(u64, u64, u64)> {
    let mut parts = value.split('.');
    let whole = parts.next()?.parse::<u64>().ok()?;
    let fraction_text = parts.next().unwrap_or("");
    if parts.next().is_some()
        || !fraction_text
            .chars()
            .all(|character| character.is_ascii_digit())
        || fraction_text.len() > 6
    {
        return None;
    }
    if fraction_text.is_empty() {
        return Some((whole, 0, 1));
    }
    let fractional = fraction_text.parse::<u64>().ok()?;
    let scale = 10u64.checked_pow(u32::try_from(fraction_text.len()).ok()?)?;
    Some((whole, fractional, scale))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_suffixes_are_binary() {
        assert_eq!(parse_size_limit("16M"), Some(LimitValue::Value(16_777_216)));
        assert_eq!(
            parse_size_limit("1.5G"),
            Some(LimitValue::Value(1_610_612_736))
        );
        assert_eq!(parse_size_limit("infinity"), Some(LimitValue::Max));
    }

    #[test]
    fn legacy_weights_are_normalized() {
        assert_eq!(normalize_property("CPUShares", "2").unwrap().value, "1");
        assert_eq!(
            normalize_property("CPUShares", "262144").unwrap().value,
            "10000"
        );
        assert_eq!(
            normalize_property("BlockIOWeight", "1000").unwrap().value,
            "10000"
        );
    }

    #[test]
    fn cpu_quota_is_canonical_and_writable() {
        let property = normalize_property("CPUQuota", "10%").unwrap();
        assert_eq!(property.value, "10.00%");
        assert_eq!(
            parse_cpu_quota(&property.value).unwrap().cgroup_value(),
            "10000 100000"
        );
    }

    #[test]
    fn unsupported_property_is_rejected() {
        assert!(normalize_property("Description", "changed").is_err());
    }
    #[test]
    fn configured_detection_tracks_requested_limits() {
        let mut control = ResourceControl::default();
        assert!(!control.is_configured());
        control.cpu_weight = Some(200);
        assert!(control.is_configured());
    }

    #[test]
    fn tasks_max_percentage_resolves_to_kernel_capacity() {
        let mut control = ResourceControl::default();
        assert!(control.apply("TasksMax", "15%"));
        let expected = crate::limits::TasksMaxSpec::parse("15%").unwrap().resolve();
        assert_eq!(control.tasks_max, Some(LimitValue::Value(expected)));
        assert!(control.is_configured());
    }

    #[test]
    fn tasks_max_empty_resets_but_invalid_assignment_preserves() {
        let mut control = ResourceControl::default();
        assert!(control.apply("TasksMax", "12"));
        assert!(control.apply("TasksMax", "invalid"));
        assert_eq!(control.tasks_max, Some(LimitValue::Value(12)));
        assert!(control.apply("TasksMax", ""));
        assert_eq!(control.tasks_max, None);
        assert_eq!(normalize_property("TasksMax", "").unwrap().value, "");
        assert!(normalize_property("TasksMax", "Infinity").is_err());
        assert!(normalize_property("TasksMax", "max").is_err());
    }

    #[test]
    fn accounting_directives_are_parsed_and_mark_control_configured() {
        let mut control = ResourceControl::default();
        assert!(control.apply("IOAccounting", "yes"));
        assert!(control.apply("MemoryAccounting", "true"));
        assert!(control.apply("TasksAccounting", "1"));
        assert!(control.apply("IPAccounting", "on"));
        assert!(control.io_accounting);
        assert!(control.memory_accounting);
        assert!(control.tasks_accounting);
        assert!(control.ip_accounting);
        assert!(control.is_configured());
    }

    #[test]
    fn zswap_directives_are_parsed_and_normalized() {
        let mut control = ResourceControl::default();
        assert!(control.apply("MemoryZSwapMax", "2M"));
        assert!(control.apply("MemoryZSwapWriteback", "no"));
        assert_eq!(control.memory_zswap_max, Some(LimitValue::Value(2 << 20)));
        assert_eq!(control.memory_zswap_writeback, Some(false));
        assert!(control.is_configured());
        assert_eq!(
            normalize_property("MemoryZSwapMax", "2M").unwrap().value,
            (2 << 20).to_string()
        );
        assert_eq!(
            normalize_property("MemoryZSwapWriteback", "off")
                .unwrap()
                .value,
            "no"
        );
    }
}
