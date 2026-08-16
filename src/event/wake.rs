// SPDX-License-Identifier: LGPL-2.1-or-later
//! Cross-thread event-loop wakeups backed by `eventfd(2)`.
//!
//! Producers such as the IPC server write to the eventfd after queueing work.
//! The manager's epoll loop drains the counter and immediately starts another
//! dispatch iteration instead of sleeping until the poll timeout expires.

use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;

use crate::event::loop_::IoHandler;

/// A cloneable handle that wakes the manager event loop.
#[derive(Clone, Debug)]
pub struct EventLoopWake {
    fd: Arc<OwnedFd>,
}

impl EventLoopWake {
    /// Create a non-blocking eventfd wake source.
    ///
    /// # Errors
    /// Returns an error if `eventfd(2)` cannot be created.
    pub fn create() -> anyhow::Result<Self> {
        // Safety: the wrapper creates a new eventfd and returns either its
        // descriptor or a negative errno value.
        let raw_fd = unsafe { crate::ffi::event::rustd_eventfd_create() };
        if raw_fd < 0 {
            return Err(anyhow::anyhow!(
                "eventfd wake source creation failed: errno {}",
                -raw_fd
            ));
        }

        // Safety: `raw_fd` is a newly created descriptor owned by this object.
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        Ok(Self { fd: Arc::new(fd) })
    }

    /// Return the descriptor registered with epoll.
    #[must_use]
    pub fn raw_fd(&self) -> libc::c_int {
        self.fd.as_raw_fd()
    }

    /// Notify the event loop that cross-thread work is ready.
    ///
    /// # Errors
    /// Returns an error if writing to the eventfd fails. A saturated eventfd
    /// is already readable, so `EAGAIN` is treated as a successful wakeup.
    pub fn wake(&self) -> anyhow::Result<()> {
        // Safety: `raw_fd` remains owned by this wake handle.
        let result = unsafe { crate::ffi::event::rustd_eventfd_write(self.raw_fd(), 1) };
        if result < 0 && result != -libc::EAGAIN {
            return Err(anyhow::anyhow!(
                "eventfd wake write failed: errno {}",
                -result
            ));
        }
        Ok(())
    }

    /// Build the epoll handler that drains this wake source.
    #[must_use]
    pub fn io_handler(&self) -> Box<dyn IoHandler> {
        Box::new(Self {
            fd: Arc::clone(&self.fd),
        })
    }
}

impl IoHandler for EventLoopWake {
    fn on_io(&mut self, fd: i32, _events: u32) {
        // Safety: `fd` is the eventfd registered for this handler.
        while unsafe { crate::ffi::event::rustd_eventfd_read(fd) } > 0 {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wake_counter_is_readable() {
        let wake = EventLoopWake::create().unwrap();
        wake.wake().unwrap();
        // Safety: the descriptor is owned by `wake` for this test.
        let value = unsafe { crate::ffi::event::rustd_eventfd_read(wake.raw_fd()) };
        assert_eq!(value, 1);
    }
}
