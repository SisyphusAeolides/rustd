// SPDX-License-Identifier: LGPL-2.1-or-later
//! Safe wrappers for native C and Fortran helpers in `ffi/`.
//!
//! The notification and socket-activation interfaces mirror the public
//! `sd-daemon` behavior implemented by systemd v261.

use std::os::fd::RawFd;
use std::time::Duration;

use anyhow::anyhow;

use crate::event::loop_::{EventLoop, TimerHandler};
use crate::event::timer::{ClockId, TimerSpec};
use crate::event::SourceId;

/// Restore the default dispositions for signals managed by the service manager.
///
/// # Errors
/// Returns an error when `sigaction(2)` fails.
pub fn install_signal_handlers() -> anyhow::Result<()> {
    errno_unit(
        "installing signal handlers",
        // Safety: the native helper only changes process signal dispositions.
        unsafe { crate::ffi::native::rustd_install_signal_handlers() },
    )
}

/// Send `READY=1` to the socket named by `RUSTD_NOTIFY_SOCKET`.
///
/// Returns `false` when `RUSTD_NOTIFY_SOCKET` is not set.
///
/// # Errors
/// Returns an error when the socket address is invalid or the datagram cannot
/// be sent.
pub fn notify_ready() -> anyhow::Result<bool> {
    notification_result(
        "sending READY notification",
        // Safety: the native helper reads `RUSTD_NOTIFY_SOCKET` and sends one datagram.
        unsafe { crate::ffi::native::rustd_notify_ready() },
    )
}

/// Send `STOPPING=1` to the socket named by `RUSTD_NOTIFY_SOCKET`.
///
/// Returns `false` when `RUSTD_NOTIFY_SOCKET` is not set.
///
/// # Errors
/// Returns an error when the socket address is invalid or the datagram cannot
/// be sent.
pub fn notify_stopping() -> anyhow::Result<bool> {
    notification_result(
        "sending STOPPING notification",
        // Safety: the native helper reads `RUSTD_NOTIFY_SOCKET` and sends one datagram.
        unsafe { crate::ffi::native::rustd_notify_stopping() },
    )
}

/// Send `WATCHDOG=1` to the socket named by `RUSTD_NOTIFY_SOCKET`.
///
/// Returns `false` when `RUSTD_NOTIFY_SOCKET` is not set.
///
/// # Errors
/// Returns an error when the socket address is invalid or the datagram cannot
/// be sent.
pub fn notify_watchdog() -> anyhow::Result<bool> {
    notification_result(
        "sending watchdog notification",
        // Safety: the native helper reads `RUSTD_NOTIFY_SOCKET` and sends one datagram.
        unsafe { crate::ffi::native::rustd_notify_watchdog() },
    )
}

/// Parse `RUSTD_WATCHDOG_USEC` and `RUSTD_WATCHDOG_PID` for the current process.
///
/// Returns `None` when no watchdog is configured or when `RUSTD_WATCHDOG_PID` names
/// a different process. When `unset_environment` is true, both watchdog
/// variables are removed before the function returns.
///
/// # Errors
/// Returns an error when either environment variable is malformed.
pub fn watchdog_enabled(unset_environment: bool) -> anyhow::Result<Option<Duration>> {
    let mut microseconds = 0u64;
    // Safety: `microseconds` is a valid writable pointer for the duration of
    // the call. The helper does not retain it.
    let result = unsafe {
        crate::ffi::native::rustd_watchdog_enabled(
            libc::c_int::from(unset_environment),
            std::ptr::addr_of_mut!(microseconds),
        )
    };
    if result < 0 {
        return Err(errno_error("reading watchdog configuration", result));
    }
    if result == 0 {
        return Ok(None);
    }
    Ok(Some(Duration::from_micros(microseconds)))
}

/// Register an event-loop timer that sends watchdog keepalives at half of the
/// configured watchdog interval.
///
/// The timer runs on the manager's event loop rather than a helper thread, so
/// a stalled manager stops emitting keepalives and its supervisor can detect
/// the failure.
///
/// # Errors
/// Returns an error when the watchdog duration is zero or the timer source
/// cannot be created or armed.
pub fn install_watchdog(
    event_loop: &mut EventLoop,
    watchdog_timeout: Duration,
) -> anyhow::Result<SourceId> {
    let period_ns = watchdog_period_ns(watchdog_timeout)?;
    event_loop.add_timer(
        ClockId::Monotonic,
        TimerSpec::repeating(period_ns, period_ns),
        Box::new(WatchdogHandler),
    )
}

/// Return the real UID of the manager process.
#[must_use]
pub fn current_uid() -> libc::uid_t {
    // Safety: the native helper wraps getuid(2), has no inputs, and cannot fail.
    unsafe { crate::ffi::native::rustd_current_uid() }
}

/// Return the peer UID for an `AF_UNIX` socket.
///
/// # Errors
/// Returns an error when `fd` is invalid or peer credentials are unavailable.
pub fn peer_uid(fd: RawFd) -> anyhow::Result<libc::uid_t> {
    let mut uid = 0;
    // Safety: `uid` is a valid output pointer and is not retained.
    let result = unsafe { crate::ffi::native::rustd_peer_uid(fd, std::ptr::addr_of_mut!(uid)) };
    if result < 0 {
        Err(errno_error("reading peer UID", result))
    } else {
        Ok(uid)
    }
}

/// Return the peer PID for an `AF_UNIX` socket.
///
/// # Errors
/// Returns an error when `fd` is invalid or peer credentials are unavailable.
pub fn peer_pid(fd: RawFd) -> anyhow::Result<libc::pid_t> {
    let mut pid = 0;
    // Safety: `pid` is a valid output pointer and is not retained.
    let result = unsafe { crate::ffi::native::rustd_peer_pid(fd, std::ptr::addr_of_mut!(pid)) };
    if result < 0 {
        Err(errno_error("reading peer PID", result))
    } else {
        Ok(pid)
    }
}

/// Return the number of socket-activation descriptors inherited at fd 3.
///
/// When `unset_environment` is true, all `LISTEN_*` variables are removed
/// before the function returns.
///
/// # Errors
/// Returns an error when the environment is malformed or an inherited
/// descriptor cannot be marked close-on-exec.
pub fn listen_fds(unset_environment: bool) -> anyhow::Result<usize> {
    // Safety: the helper reads process environment and descriptor flags only.
    let result =
        unsafe { crate::ffi::native::rustd_listen_fds(libc::c_int::from(unset_environment)) };
    if result < 0 {
        return Err(errno_error("reading socket-activation descriptors", result));
    }
    usize::try_from(result).map_err(anyhow::Error::from)
}

/// Test whether `fd` is a socket with the requested family, type, and listen
/// state.
///
/// A family or socket type of zero accepts any value. `listening = None`
/// skips the `SO_ACCEPTCONN` check.
///
/// # Errors
/// Returns an error when descriptor metadata cannot be read.
pub fn is_socket(
    fd: RawFd,
    family: libc::c_int,
    socket_type: libc::c_int,
    listening: Option<bool>,
) -> anyhow::Result<bool> {
    let listening = listening.map_or(-1, libc::c_int::from);
    // Safety: the helper only inspects descriptor metadata.
    let result = unsafe { crate::ffi::native::rustd_is_socket(fd, family, socket_type, listening) };
    if result < 0 {
        Err(errno_error("inspecting socket descriptor", result))
    } else {
        Ok(result > 0)
    }
}

struct WatchdogHandler;

impl TimerHandler for WatchdogHandler {
    fn on_timer(&mut self, _id: SourceId, _expirations: i64) {
        if let Err(error) = notify_watchdog() {
            eprintln!("rustd: watchdog notification failed: {error}");
        }
    }
}

fn watchdog_period_ns(timeout: Duration) -> anyhow::Result<i64> {
    if timeout.is_zero() {
        return Err(anyhow!("watchdog timeout must be greater than zero"));
    }
    let timeout_ns = i64::try_from(timeout.as_nanos()).unwrap_or(i64::MAX);
    Ok((timeout_ns / 2).max(1))
}

fn notification_result(operation: &str, result: libc::c_int) -> anyhow::Result<bool> {
    if result < 0 {
        Err(errno_error(operation, result))
    } else {
        Ok(result > 0)
    }
}

fn errno_unit(operation: &str, result: libc::c_int) -> anyhow::Result<()> {
    if result < 0 {
        Err(errno_error(operation, result))
    } else {
        Ok(())
    }
}

fn errno_error(operation: &str, result: libc::c_int) -> anyhow::Error {
    let errno = result.checked_neg().unwrap_or(libc::EIO);
    anyhow!(
        "{operation} failed: {}",
        std::io::Error::from_raw_os_error(errno)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notification_results_preserve_not_configured() {
        assert!(!notification_result("test", 0).unwrap());
        assert!(notification_result("test", 1).unwrap());
        assert!(notification_result("test", -libc::EINVAL).is_err());
    }

    #[test]
    fn watchdog_uses_half_interval() {
        assert_eq!(
            watchdog_period_ns(Duration::from_secs(2)).unwrap(),
            1_000_000_000
        );
        assert_eq!(watchdog_period_ns(Duration::from_nanos(1)).unwrap(), 1);
        assert!(watchdog_period_ns(Duration::ZERO).is_err());
    }
}
