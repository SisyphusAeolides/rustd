// SPDX-License-Identifier: LGPL-2.1-or-later
//! Duration string parser matching systemd's `parse_time()`.
//!
//! Upstream reference: `src/basic/time-util.c parse_time()` (v261)
//!
//! Supported units: `us`, `ms`, `s`, `sec`, `m`, `min`, `h`, `hr`,
//! `d`, `day`, `w`, `week`, `month`, `y`, `year`.
//! The value `infinity` maps to `None` (no timeout).
//! A bare number is treated as seconds.

use std::time::Duration;

/// Parse a systemd duration string into a `Duration`.
///
/// Returns `None` for `"infinity"` or unparseable values.
#[must_use]
pub fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s.is_empty() || s == "infinity" {
        return None;
    }

    let mut total_us: u64 = 0;
    let mut remaining = s;

    while !remaining.is_empty() {
        remaining = remaining.trim_start();
        if remaining.is_empty() {
            break;
        }

        // Parse leading number (integer or float for sub-second precision).
        let num_end = remaining
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(remaining.len());
        if num_end == 0 {
            return None;
        }
        let num_str = &remaining[..num_end];
        let num: f64 = num_str.parse().ok()?;
        remaining = remaining[num_end..].trim_start();

        // Parse optional unit suffix.
        let (unit_us, unit_len) = parse_unit_suffix(remaining);
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss
        )]
        let chunk = (num * unit_us as f64) as u64;
        total_us = total_us.saturating_add(chunk);
        remaining = &remaining[unit_len..];
    }

    Some(Duration::from_micros(total_us))
}

/// Return `(microseconds_per_unit, suffix_len)` for the leading unit string.
/// Defaults to seconds (`1_000_000` µs) with `suffix_len` 0 if no unit matches.
fn parse_unit_suffix(s: &str) -> (u64, usize) {
    // Ordered longest-first so "min" beats "m", "week" beats "w", etc.
    let units: &[(&str, u64)] = &[
        ("usec", 1),
        ("us", 1),
        ("msec", 1_000),
        ("ms", 1_000),
        ("minutes", 60_000_000),
        ("minute", 60_000_000),
        ("months", 2_592_000_000_000),
        ("month", 2_592_000_000_000),
        ("years", 31_536_000_000_000),
        ("year", 31_536_000_000_000),
        ("weeks", 604_800_000_000),
        ("week", 604_800_000_000),
        ("days", 86_400_000_000),
        ("day", 86_400_000_000),
        ("hours", 3_600_000_000),
        ("hour", 3_600_000_000),
        ("min", 60_000_000),
        ("sec", 1_000_000),
        ("hr", 3_600_000_000),
        ("h", 3_600_000_000),
        ("d", 86_400_000_000),
        ("w", 604_800_000_000),
        ("s", 1_000_000),
        ("m", 60_000_000),
    ];

    let lower = s.to_ascii_lowercase();
    for (suffix, factor) in units {
        if lower.starts_with(suffix) {
            // Make sure the suffix is not followed by another letter (e.g. "min" vs "minutes").
            let next_char = s.chars().nth(suffix.len());
            if next_char.map_or(true, |c| !c.is_alphabetic()) {
                return (*factor, suffix.len());
            }
        }
    }

    // No unit — treat as seconds.
    (1_000_000, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seconds() {
        assert_eq!(parse_duration("90s"), Some(Duration::from_secs(90)));
        assert_eq!(parse_duration("90"), Some(Duration::from_secs(90)));
        assert_eq!(parse_duration("1sec"), Some(Duration::from_secs(1)));
    }

    #[test]
    fn minutes() {
        assert_eq!(parse_duration("1min"), Some(Duration::from_secs(60)));
        assert_eq!(parse_duration("5m"), Some(Duration::from_secs(300)));
    }

    #[test]
    fn compound() {
        assert_eq!(parse_duration("1min 30s"), Some(Duration::from_secs(90)));
        assert_eq!(parse_duration("1h 5min"), Some(Duration::from_secs(3900)));
    }

    #[test]
    fn millis() {
        assert_eq!(parse_duration("500ms"), Some(Duration::from_millis(500)));
    }

    #[test]
    fn infinity_returns_none() {
        assert_eq!(parse_duration("infinity"), None);
    }

    #[test]
    fn watchdog_3min() {
        assert_eq!(parse_duration("3min"), Some(Duration::from_secs(180)));
    }
}
