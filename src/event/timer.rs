// SPDX-License-Identifier: LGPL-2.1-or-later
//! Timer source — timerfd wrappers and clock types.
//!
//! Upstream reference: src/libsystemd/sd-event/sd-event.c
//!   `rustd_event_add_time()`, `source_set_pending()` (v261)

use std::os::unix::io::FromRawFd;
use std::os::unix::io::OwnedFd;

/// Which kernel clock backs a timer source.
///
/// Values match the Linux `CLOCK_*` constants used by `timerfd_create(2)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ClockId {
    /// Wall-clock time.  Jumps on NTP/adjtime.
    Realtime = 0,
    /// Monotonic time since boot.  Never jumps.
    Monotonic = 1,
    /// Like `CLOCK_MONOTONIC` but includes suspend time.
    Boottime = 7,
}

/// A timer specification: first-fire time and optional repeat interval,
/// both in nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimerSpec {
    /// When the timer first fires (nanoseconds).  Relative to clock epoch
    /// unless `absolute` is set.
    pub value_ns: i64,
    /// Repeat interval in nanoseconds; 0 = one-shot.
    pub interval_ns: i64,
    /// If true, `value_ns` is an absolute timestamp on the clock.
    pub absolute: bool,
}

impl TimerSpec {
    /// One-shot timer firing `delay_ns` nanoseconds from now (relative).
    #[must_use]
    pub fn once(delay_ns: i64) -> Self {
        Self {
            value_ns: delay_ns,
            interval_ns: 0,
            absolute: false,
        }
    }

    /// Repeating timer: first fire after `delay_ns`, then every `interval_ns`.
    #[must_use]
    pub fn repeating(delay_ns: i64, interval_ns: i64) -> Self {
        Self {
            value_ns: delay_ns,
            interval_ns,
            absolute: false,
        }
    }
}

/// Return the current time in nanoseconds for `clock`.
///
/// # Errors
/// Returns an error if `clock_gettime(2)` fails.
pub fn clock_now(clock: ClockId) -> anyhow::Result<i64> {
    // Safety: rustd_clock_now_nsec reads the kernel clock; no side effects.
    let ns = unsafe { crate::ffi::event::rustd_clock_now_nsec(clock as i32) };
    if ns < 0 {
        Err(anyhow::anyhow!("clock_gettime failed: errno {}", -ns))
    } else {
        Ok(ns)
    }
}

/// An owned timerfd file descriptor.  Closed on drop.
#[derive(Debug)]
pub(crate) struct TimerFd(pub(crate) OwnedFd);

impl TimerFd {
    /// Create a new timerfd for the given clock.
    pub(crate) fn create(clock: ClockId) -> anyhow::Result<Self> {
        // Safety: rustd_timerfd_create returns a valid fd or -errno.
        let fd = unsafe { crate::ffi::event::rustd_timerfd_create(clock as i32) };
        if fd < 0 {
            return Err(anyhow::anyhow!("timerfd_create failed: errno {}", -fd));
        }
        // Safety: fd is a valid, owned file descriptor returned by the kernel.
        Ok(Self(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    /// Arm the timer.
    pub(crate) fn set(&self, spec: &TimerSpec) -> anyhow::Result<()> {
        use std::os::unix::io::AsRawFd;
        let flags = i32::from(spec.absolute);
        let value_seconds = spec.value_ns / 1_000_000_000;
        let value_nanoseconds = spec.value_ns % 1_000_000_000;
        let interval_seconds = spec.interval_ns / 1_000_000_000;
        let interval_nanoseconds = spec.interval_ns % 1_000_000_000;
        let r = unsafe {
            crate::ffi::event::rustd_timerfd_settime(
                self.0.as_raw_fd(),
                flags,
                value_seconds,
                value_nanoseconds,
                interval_seconds,
                interval_nanoseconds,
            )
        };
        if r < 0 {
            return Err(anyhow::anyhow!("timerfd_settime failed: errno {}", -r));
        }
        Ok(())
    }

    /// Disarm (cancel) the timer.
    #[allow(dead_code)]
    pub(crate) fn disarm(&self) -> anyhow::Result<()> {
        use std::os::unix::io::AsRawFd;
        let r = unsafe { crate::ffi::event::rustd_timerfd_disarm(self.0.as_raw_fd()) };
        if r < 0 {
            return Err(anyhow::anyhow!("timerfd_disarm failed: errno {}", -r));
        }
        Ok(())
    }

    /// Drain the timerfd after it fires.  Returns the number of expirations.
    pub(crate) fn drain(&self) -> i64 {
        use std::os::unix::io::AsRawFd;
        unsafe { crate::ffi::event::rustd_timerfd_read(self.0.as_raw_fd()) }
    }
}
