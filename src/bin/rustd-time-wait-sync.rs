// SPDX-License-Identifier: LGPL-2.1-or-later
//! Native RustD time synchronization wait helper.

use std::collections::VecDeque;
use std::env;
use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rustd::native::{notify_watchdog, watchdog_enabled};

const TIME_ERROR: i32 = 5;
const STA_NANO: i32 = 0x2000;
const INOTIFY_BUFFER_SIZE: usize = 4096;
static TERMINATE: AtomicBool = AtomicBool::new(false);

struct State {
    inotify: OwnedFd,
    rustd_watch: i32,
    timesync_watch: i32,
    timer: Option<OwnedFd>,
    has_watchfile: bool,
    timesync_dir: PathBuf,
    synchronized: PathBuf,
    fixture_states: VecDeque<i32>,
}

enum Update {
    Exit,
    Wait,
}

fn main() {
    // This internal service helper deliberately ignores argv.
    if let Err(error) = run() {
        log(&error);
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    install_signals()?;
    let run_root = env::var_os("RUSTD_TIME_WAIT_SYNC_RUN_ROOT")
        .map_or_else(|| PathBuf::from("/run/rustd"), PathBuf::from);
    let timesync_dir = run_root.join("timesync");
    let synchronized = timesync_dir.join("synchronized");
    let inotify = inotify_create()?;
    let rustd_watch = add_watch(inotify.as_raw_fd(), &run_root, libc::IN_CREATE)
        .map_err(|error| format!("Failed to add watch for {}: {error}", run_root.display()))?;
    let timesync_watch = add_watch(
        inotify.as_raw_fd(),
        &timesync_dir,
        libc::IN_CREATE | libc::IN_DELETE_SELF,
    )
    .unwrap_or(-1);
    let fixture_states = env::var("RUSTD_TIME_WAIT_SYNC_ADJTIMEX_STATES")
        .ok()
        .map(|value| {
            value
                .split(',')
                .filter_map(|part| part.parse::<i32>().ok())
                .collect()
        })
        .unwrap_or_default();
    let mut state = State {
        inotify,
        rustd_watch,
        timesync_watch,
        timer: None,
        has_watchfile: false,
        timesync_dir,
        synchronized,
        fixture_states,
    };

    let watchdog = watchdog_enabled(false)
        .map_err(|error| format!("Failed to create watchdog event source: {error}"))?;
    let mut next_watchdog = watchdog.map(|period| {
        let _ = notify_watchdog();
        Instant::now() + half_period(period)
    });

    if matches!(state.update()?, Update::Exit) {
        return Ok(());
    }
    loop {
        if TERMINATE.load(Ordering::Relaxed) {
            return Ok(());
        }
        let timeout = next_watchdog.map_or(-1, |deadline| {
            let remaining = deadline.saturating_duration_since(Instant::now());
            i32::try_from(remaining.as_millis().max(1)).unwrap_or(i32::MAX)
        });
        let timer_fd = state.timer.as_ref().map_or(-1, AsRawFd::as_raw_fd);
        let mut descriptors = [
            libc::pollfd {
                fd: state.inotify.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: timer_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: both pollfd entries are initialized and live for this call.
        let result =
            unsafe { libc::poll(descriptors.as_mut_ptr(), descriptors.len() as _, timeout) };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("Failed in event loop: {error}"));
        }
        if next_watchdog.is_some_and(|deadline| Instant::now() >= deadline) {
            let _ = notify_watchdog();
            next_watchdog = watchdog.map(|period| Instant::now() + half_period(period));
        }
        if descriptors[0].revents & libc::POLLIN != 0
            && state.process_inotify()?
            && matches!(state.update()?, Update::Exit)
        {
            return Ok(());
        }
        if descriptors[1].revents & (libc::POLLIN | libc::POLLERR) != 0
            && matches!(state.update()?, Update::Exit)
        {
            return Ok(());
        }
    }
}

impl State {
    fn update(&mut self) -> Result<Update, String> {
        self.timer = Some(time_change_fd()?);
        let (state, status) = self.adjtimex()?;
        trace(&format!("adjtimex={state} status={status:#x}"));
        self.has_watchfile = self.synchronized.exists();
        if self.has_watchfile || state != TIME_ERROR {
            self.timer = None;
            if self.has_watchfile {
                trace("exit=watchfile");
            } else {
                trace("exit=adjtimex");
            }
            return Ok(Update::Exit);
        }
        Ok(Update::Wait)
    }

    fn adjtimex(&mut self) -> Result<(i32, i32), String> {
        if let Some(state) = self.fixture_states.pop_front() {
            return Ok((state, 0));
        }
        // SAFETY: zero is a valid initial representation for an adjtimex query.
        let mut value: libc::timex = unsafe { std::mem::zeroed() };
        // SAFETY: `value` is writable and adjtimex does not retain the pointer.
        let result = unsafe { libc::adjtimex(std::ptr::addr_of_mut!(value)) };
        if result < 0 {
            return Err(format!(
                "Failed to read adjtimex state: {}",
                io::Error::last_os_error()
            ));
        }
        let mut micros = value.time.tv_usec;
        if value.status & STA_NANO != 0 {
            micros /= 1000;
        }
        trace(&format!("time={}.{:06}", value.time.tv_sec, micros));
        Ok((result, value.status))
    }

    fn process_inotify(&mut self) -> Result<bool, String> {
        let mut buffer = [0_u8; INOTIFY_BUFFER_SIZE];
        let mut file = std::mem::ManuallyDrop::new(unsafe {
            // SAFETY: ManuallyDrop prevents ownership of the state's descriptor.
            fs::File::from_raw_fd(self.inotify.as_raw_fd())
        });
        let length = match file.read(&mut buffer) {
            Ok(length) => length,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) => return Err(format!("Lost access to inotify: {error}")),
        };
        let mut offset = 0;
        let mut update = false;
        while offset + std::mem::size_of::<libc::inotify_event>() <= length {
            // SAFETY: the kernel returned a complete fixed header at this offset.
            let event = unsafe {
                std::ptr::read_unaligned(buffer[offset..].as_ptr().cast::<libc::inotify_event>())
            };
            offset += std::mem::size_of::<libc::inotify_event>()
                + usize::try_from(event.len).unwrap_or(0);
            if event.wd == self.rustd_watch && self.timesync_watch < 0 {
                self.timesync_watch = add_watch(
                    self.inotify.as_raw_fd(),
                    &self.timesync_dir,
                    libc::IN_CREATE | libc::IN_DELETE_SELF,
                )
                .unwrap_or(-1);
            } else if event.wd == self.timesync_watch {
                if event.mask & libc::IN_DELETE_SELF != 0 {
                    // SAFETY: the watch belongs to this inotify descriptor.
                    unsafe {
                        libc::inotify_rm_watch(self.inotify.as_raw_fd(), self.timesync_watch)
                    };
                    self.timesync_watch = -1;
                } else {
                    update = true;
                }
            }
        }
        Ok(update)
    }
}

fn time_change_fd() -> Result<OwnedFd, String> {
    let fixture = env::var("RUSTD_TIME_WAIT_SYNC_TIMER_USEC")
        .ok()
        .and_then(|value| value.parse::<i64>().ok());
    let clock = if fixture.is_some() {
        libc::CLOCK_MONOTONIC
    } else {
        libc::CLOCK_REALTIME
    };
    // SAFETY: timerfd_create has no pointer arguments.
    let raw = unsafe { libc::timerfd_create(clock, libc::TFD_NONBLOCK | libc::TFD_CLOEXEC) };
    if raw < 0 {
        return Err(format!(
            "Failed to create timerfd: {}",
            io::Error::last_os_error()
        ));
    }
    // SAFETY: raw is a newly created owned descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut timer: libc::itimerspec = unsafe { std::mem::zeroed() };
    let flags;
    if let Some(microseconds) = fixture {
        timer.it_value.tv_sec = microseconds / 1_000_000;
        timer.it_value.tv_nsec = (microseconds % 1_000_000) * 1000;
        flags = 0;
    } else {
        timer.it_value.tv_sec = libc::time_t::MAX;
        flags = libc::TFD_TIMER_ABSTIME | libc::TFD_TIMER_CANCEL_ON_SET;
    }
    trace(&format!("timerfd clock={clock} flags={flags:#x}"));
    // SAFETY: timer points to a valid itimerspec and the fd is a timerfd.
    if unsafe { libc::timerfd_settime(fd.as_raw_fd(), flags, &timer, std::ptr::null_mut()) } < 0 {
        return Err(format!(
            "Failed to create timerfd: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(fd)
}

fn inotify_create() -> Result<OwnedFd, String> {
    // SAFETY: inotify_init1 has no pointer arguments.
    let raw = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
    if raw < 0 {
        return Err(format!(
            "Failed to create inotify descriptor: {}",
            io::Error::last_os_error()
        ));
    }
    // SAFETY: raw is a newly created owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn add_watch(fd: RawFd, path: &Path, mask: u32) -> io::Result<i32> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: path is a valid NUL-terminated string for this call.
    let watch = unsafe { libc::inotify_add_watch(fd, path.as_ptr(), mask) };
    if watch < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(watch)
    }
}

fn half_period(period: Duration) -> Duration {
    period.checked_div(2).unwrap_or(Duration::from_micros(1))
}

extern "C" fn signal_handler(_: i32) {
    TERMINATE.store(true, Ordering::Relaxed);
}

fn install_signals() -> Result<(), String> {
    // SAFETY: signal_handler has the required async-signal-safe signature.
    let handler = signal_handler as *const () as libc::sighandler_t;
    if unsafe { libc::signal(libc::SIGTERM, handler) } == libc::SIG_ERR
        || unsafe { libc::signal(libc::SIGINT, handler) } == libc::SIG_ERR
    {
        return Err(format!(
            "Failed to enable SIGTERM/SIGINT handling: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn trace(message: &str) {
    if let Some(path) = env::var_os("RUSTD_TIME_WAIT_SYNC_TRACE") {
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(file, "{message}");
        }
    }
}

fn log(message: &str) {
    if env::var_os("RUSTD_LOG_TARGET").as_deref() != Some(std::ffi::OsStr::new("null")) {
        eprintln!("{message}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watchdog_period_is_halved() {
        assert_eq!(
            half_period(Duration::from_micros(9)),
            Duration::from_nanos(4_500)
        );
    }
}
