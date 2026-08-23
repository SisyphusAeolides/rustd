// SPDX-License-Identifier: LGPL-2.1-or-later
//! The epoll-driven event loop.
//!
//! `EventLoop` owns the epoll fd, the signalfd, all registered timerfds, and
//! the inotify fd.  Callers register sources, then call `run_once` or `run`
//! to dispatch events.
//!
//! Design matches `rustd_event` from upstream (v261):
//!   src/libsystemd/sd-event/sd-event.c
//!
//! The loop operates in three phases per iteration:
//!   1. Prepare  — arm or update timerfd expiries, run defer callbacks.
//!   2. Poll     — call `epoll_wait` with the nearest timer deadline.
//!   3. Dispatch — call registered handlers for each ready source.

use std::collections::HashMap;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};

use crate::event::child::{reap_children, ChildExit};
use crate::event::inotify::InotifyFd;
use crate::event::signal::{signal_to_action, SignalAction, SignalFd};
use crate::event::source::{SourceId, SourceIdAlloc, SourceKind, SourceToken};
use crate::event::timer::{ClockId, TimerFd, TimerSpec};

/// Maximum events returned by a single `epoll_wait` call.
const MAX_EVENTS: usize = 64;

/// What the event loop should do after dispatching all pending events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopResult {
    /// Keep running.
    Continue,
    /// A clean exit was requested (SIGTERM / SIGINT on user manager).
    Exit,
    /// A system reboot was requested.
    Reboot,
    /// A system poweroff was requested.
    Poweroff,
    /// A system halt was requested.
    Halt,
    /// A kexec transition was requested.
    Kexec,
    /// Re-execute the manager binary in-place (SIGUSR2).
    Reexecute,
}

// ── Handler trait ──────────────────────────────────────────────────────────

/// Callback for an IO source becoming readable or writable.
pub trait IoHandler: Send {
    fn on_io(&mut self, fd: i32, events: u32);
}

/// Callback for a timer expiry.
pub trait TimerHandler: Send {
    fn on_timer(&mut self, id: SourceId, expirations: i64);
}

/// Callback for an inotify event.
pub trait InotifyHandler: Send {
    fn on_inotify(&mut self, wd: i32, mask: u32, path: Option<&str>);
}

/// Callback invoked once per loop iteration, before `epoll_wait`.
pub trait DeferHandler: Send {
    /// Returns true if the source should be kept alive for the next iteration.
    fn on_defer(&mut self) -> bool;
}

// ── Registered source storage ─────────────────────────────────────────────

struct IoSource {
    fd: i32,
    events: u32,
    enabled: bool,
    handler: Box<dyn IoHandler>,
}

struct TimerSource {
    tfd: TimerFd,
    #[allow(dead_code)]
    spec: TimerSpec,
    handler: Box<dyn TimerHandler>,
}

struct InotifySource {
    ifd: InotifyFd,
    handler: Box<dyn InotifyHandler>,
}

// ── EventLoop ─────────────────────────────────────────────────────────────

/// The PID 1 / manager event loop.
pub struct EventLoop {
    epfd: OwnedFd,
    sfd: SignalFd,
    alloc: SourceIdAlloc,

    io_sources: HashMap<SourceId, IoSource>,
    timer_sources: HashMap<SourceId, TimerSource>,
    inotify_sources: HashMap<SourceId, InotifySource>,
    defer_handlers: Vec<Box<dyn DeferHandler>>,

    #[allow(dead_code)]
    signal_source_id: SourceId,
    result: LoopResult,

    /// Child exits collected by `dispatch_signal`; drained by the manager
    /// after each `run_once` call so state transitions are applied correctly.
    pending_child_exits: Vec<ChildExit>,
}

impl EventLoop {
    /// Create the event loop.
    ///
    /// - Creates the epoll fd.
    /// - Creates and registers the signalfd (blocks all signals in the mask).
    ///
    /// # Errors
    /// Returns an error if any kernel call fails.
    pub fn new() -> anyhow::Result<Self> {
        // epoll
        let epfd_raw = unsafe { crate::ffi::event::rustd_epoll_create1() };
        if epfd_raw < 0 {
            return Err(anyhow::anyhow!("epoll_create1 failed: errno {}", -epfd_raw));
        }
        // Safety: epfd_raw is a valid owned fd.
        let epfd = unsafe { OwnedFd::from_raw_fd(epfd_raw) };

        // signalfd — blocks all signals and returns readable fd
        let sfd = SignalFd::create()?;

        let mut alloc = SourceIdAlloc::default();
        let signal_source_id = alloc.next();
        let signal_token = SourceToken::encode(SourceKind::Signal, signal_source_id);

        // Register signalfd with epoll EPOLLIN
        let r = unsafe {
            crate::ffi::event::rustd_epoll_add_fd(
                epfd.as_raw_fd(),
                sfd.0.as_raw_fd(),
                libc::EPOLLIN as u32,
                signal_token.0,
            )
        };
        if r < 0 {
            return Err(anyhow::anyhow!("epoll_add signalfd failed: errno {}", -r));
        }

        Ok(Self {
            epfd,
            sfd,
            alloc,
            io_sources: HashMap::new(),
            timer_sources: HashMap::new(),
            inotify_sources: HashMap::new(),
            defer_handlers: Vec::new(),
            signal_source_id,
            result: LoopResult::Continue,
            pending_child_exits: Vec::new(),
        })
    }

    /// Drain all child exits that were collected during the last `run_once` call.
    ///
    /// The manager calls this immediately after `run_once` returns so that
    /// child state transitions are applied without waiting for the next
    /// iteration.
    pub fn drain_child_exits(&mut self) -> Vec<ChildExit> {
        std::mem::take(&mut self.pending_child_exits)
    }

    // ── Source registration ────────────────────────────────────────────────

    /// Register an IO fd for EPOLLIN.  Returns the source id.
    ///
    /// # Errors
    /// Returns an error if `epoll_ctl(ADD)` fails.
    pub fn add_io(
        &mut self,
        fd: i32,
        events: u32,
        handler: Box<dyn IoHandler>,
    ) -> anyhow::Result<SourceId> {
        let id = self.alloc.next();
        let token = SourceToken::encode(SourceKind::Io, id);
        let r = unsafe {
            crate::ffi::event::rustd_epoll_add_fd(self.epfd.as_raw_fd(), fd, events, token.0)
        };
        if r < 0 {
            return Err(anyhow::anyhow!("epoll_add_fd({fd}) failed: errno {}", -r));
        }
        self.io_sources.insert(
            id,
            IoSource {
                fd,
                events,
                enabled: true,
                handler,
            },
        );
        Ok(id)
    }

    /// Enable or disable readiness delivery while retaining the IO handler.
    ///
    /// Socket units use this to stop level-triggered listener readiness from
    /// repeatedly starting a service that already owns the activation fd.
    ///
    /// # Errors
    /// Returns an error if the source is unknown or `epoll_ctl(MOD)` fails.
    pub fn set_io_enabled(&mut self, id: SourceId, enabled: bool) -> anyhow::Result<()> {
        let source = self
            .io_sources
            .get_mut(&id)
            .ok_or_else(|| anyhow::anyhow!("unknown IO source {}", id.get()))?;
        if source.enabled == enabled {
            return Ok(());
        }
        let token = SourceToken::encode(SourceKind::Io, id);
        let events = if enabled { source.events } else { 0 };
        let result = unsafe {
            crate::ffi::event::rustd_epoll_mod_fd(self.epfd.as_raw_fd(), source.fd, events, token.0)
        };
        if result < 0 {
            return Err(anyhow::anyhow!(
                "epoll_mod_fd({}) failed: errno {}",
                source.fd,
                -result
            ));
        }
        source.enabled = enabled;
        Ok(())
    }

    /// Register a timerfd source.  Returns the source id.
    ///
    /// # Errors
    /// Returns an error if `timerfd_create` or `epoll_ctl(ADD)` fails.
    pub fn add_timer(
        &mut self,
        clock: ClockId,
        spec: TimerSpec,
        handler: Box<dyn TimerHandler>,
    ) -> anyhow::Result<SourceId> {
        let tfd = TimerFd::create(clock)?;
        tfd.set(&spec)?;

        let id = self.alloc.next();
        let token = SourceToken::encode(SourceKind::Timer, id);
        let r = unsafe {
            crate::ffi::event::rustd_epoll_add_fd(
                self.epfd.as_raw_fd(),
                tfd.0.as_raw_fd(),
                libc::EPOLLIN as u32,
                token.0,
            )
        };
        if r < 0 {
            return Err(anyhow::anyhow!(
                "epoll_add_fd(timerfd) failed: errno {}",
                -r
            ));
        }
        self.timer_sources
            .insert(id, TimerSource { tfd, spec, handler });
        Ok(id)
    }

    /// Register an inotify source.  Returns the source id.
    ///
    /// The caller adds individual path watches via `inotify_add_watch` on the
    /// returned id after registration.
    ///
    /// # Errors
    /// Returns an error if `inotify_init1` or `epoll_ctl(ADD)` fails.
    pub fn add_inotify(&mut self, handler: Box<dyn InotifyHandler>) -> anyhow::Result<SourceId> {
        let ifd = InotifyFd::create()?;
        let id = self.alloc.next();
        let token = SourceToken::encode(SourceKind::Inotify, id);
        let r = unsafe {
            crate::ffi::event::rustd_epoll_add_fd(
                self.epfd.as_raw_fd(),
                ifd.as_raw_fd(),
                libc::EPOLLIN as u32,
                token.0,
            )
        };
        if r < 0 {
            return Err(anyhow::anyhow!(
                "epoll_add_fd(inotify) failed: errno {}",
                -r
            ));
        }
        self.inotify_sources
            .insert(id, InotifySource { ifd, handler });
        Ok(id)
    }

    /// Add a watch path to an existing inotify source.
    ///
    /// # Errors
    /// Returns an error if the source id is unknown or `inotify_add_watch` fails.
    pub fn inotify_add_watch(
        &mut self,
        id: SourceId,
        path: &str,
        mask: u32,
    ) -> anyhow::Result<i32> {
        let src = self
            .inotify_sources
            .get_mut(&id)
            .ok_or_else(|| anyhow::anyhow!("unknown inotify source {id:?}"))?;
        src.ifd.add_watch(path, mask)
    }

    /// Register a defer callback — called once per loop iteration before
    /// `epoll_wait`.
    pub fn add_defer(&mut self, handler: Box<dyn DeferHandler>) {
        self.defer_handlers.push(handler);
    }

    /// Remove an IO source.
    ///
    /// # Errors
    /// Returns an error if `epoll_ctl(DEL)` fails.
    pub fn remove_io(&mut self, id: SourceId) -> anyhow::Result<()> {
        if let Some(src) = self.io_sources.remove(&id) {
            let r = unsafe { crate::ffi::event::rustd_epoll_del_fd(self.epfd.as_raw_fd(), src.fd) };
            if r < 0 {
                return Err(anyhow::anyhow!("epoll_del_fd failed: errno {}", -r));
            }
        }
        Ok(())
    }

    /// Remove a timer source and close its timerfd.
    ///
    /// # Errors
    /// Returns an error if `epoll_ctl(DEL)` fails.
    pub fn remove_timer(&mut self, id: SourceId) -> anyhow::Result<()> {
        if let Some(source) = self.timer_sources.remove(&id) {
            let result = unsafe {
                crate::ffi::event::rustd_epoll_del_fd(
                    self.epfd.as_raw_fd(),
                    source.tfd.0.as_raw_fd(),
                )
            };
            if result < 0 {
                return Err(anyhow::anyhow!(
                    "epoll_del timerfd failed: errno {}",
                    -result
                ));
            }
        }
        Ok(())
    }

    /// Remove an inotify source and all watches owned by it.
    ///
    /// # Errors
    /// Returns an error if removing the descriptor from epoll fails.
    pub fn remove_inotify(&mut self, id: SourceId) -> anyhow::Result<()> {
        if let Some(source) = self.inotify_sources.remove(&id) {
            let result = unsafe {
                crate::ffi::event::rustd_epoll_del_fd(self.epfd.as_raw_fd(), source.ifd.as_raw_fd())
            };
            if result < 0 {
                return Err(anyhow::anyhow!(
                    "epoll_del inotify failed: errno {}",
                    -result
                ));
            }
        }
        Ok(())
    }

    /// Signal that the loop should exit with the given result on the next
    /// iteration boundary.
    pub fn request_exit(&mut self, result: LoopResult) {
        self.result = result;
    }

    // ── Dispatch ──────────────────────────────────────────────────────────

    /// Run one iteration with the default 30-second polling ceiling.
    ///
    /// # Errors
    /// Returns an error only if `epoll_wait` itself fails with a hard error.
    pub fn run_once(&mut self) -> anyhow::Result<LoopResult> {
        self.run_once_timeout(30_000)
    }

    /// Run one iteration with a caller-selected polling timeout.
    ///
    /// The timeout is clamped to the manager's 30-second ceiling. This lets
    /// the service manager wake at the nearest watchdog deadline.
    ///
    /// # Errors
    /// Returns an error only if `epoll_wait` itself fails with a hard error.
    pub fn run_once_timeout(&mut self, timeout_ms: i32) -> anyhow::Result<LoopResult> {
        // Phase 1: defer callbacks
        self.defer_handlers.retain_mut(|h| h.on_defer());

        if self.result != LoopResult::Continue {
            return Ok(self.result);
        }

        // Phase 2: poll with the caller's bounded timeout.
        let timeout_ms = timeout_ms.clamp(0, 30_000);
        let mut raw_events = [crate::ffi::event::SdEpollEvent {
            events: 0,
            token: 0,
        }; MAX_EVENTS];
        // MAX_EVENTS = 64, which fits in i32 on all targets.
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        let max_ev = MAX_EVENTS as i32;
        let n = unsafe {
            crate::ffi::event::rustd_epoll_wait(
                self.epfd.as_raw_fd(),
                raw_events.as_mut_ptr(),
                max_ev,
                timeout_ms,
            )
        };
        if n < 0 {
            return Err(anyhow::anyhow!("epoll_wait failed: errno {}", -n));
        }

        // Phase 3: dispatch
        // n >= 0 is guaranteed by the epoll_wait check above.
        #[allow(clippy::cast_sign_loss)]
        for ev in &raw_events[..n as usize] {
            let token = SourceToken(ev.token);
            let kind = token.kind();
            let id_raw = token.id();

            match kind {
                Some(SourceKind::Signal) => {
                    self.dispatch_signal()?;
                }
                Some(SourceKind::Timer) => {
                    if let Some(id) = SourceId::new(id_raw) {
                        self.dispatch_timer(id);
                    }
                }
                Some(SourceKind::Io) => {
                    if let Some(id) = SourceId::new(id_raw) {
                        self.dispatch_io(id, ev.events);
                    }
                }
                Some(SourceKind::Inotify) => {
                    if let Some(id) = SourceId::new(id_raw) {
                        self.dispatch_inotify(id);
                    }
                }
                Some(SourceKind::Child | SourceKind::Defer) | None => {}
            }
        }

        Ok(self.result)
    }

    /// Consume a terminal result after the service manager has translated it
    /// into an orderly unit transaction.
    pub fn take_result(&mut self) -> LoopResult {
        std::mem::replace(&mut self.result, LoopResult::Continue)
    }

    /// Run the event loop until a non-`Continue` result is returned.
    ///
    /// # Errors
    /// Propagates errors from `run_once`.
    pub fn run(&mut self) -> anyhow::Result<LoopResult> {
        loop {
            let r = self.run_once()?;
            if r != LoopResult::Continue {
                return Ok(r);
            }
        }
    }

    // ── Internal dispatch helpers ─────────────────────────────────────────

    fn dispatch_signal(&mut self) -> anyhow::Result<()> {
        // Drain all pending signals from the signalfd.
        loop {
            match self.sfd.read_one()? {
                None => break,
                Some(signo) => {
                    let action = signal_to_action(signo);
                    match action {
                        SignalAction::ReapChildren => {
                            // Collect exits into pending_child_exits so the
                            // manager can apply state transitions after run_once.
                            self.pending_child_exits.extend(reap_children());
                        }
                        SignalAction::Terminate => {
                            self.result = LoopResult::Exit;
                        }
                        SignalAction::CtrlAltDelete => {
                            // On PID 1, Ctrl-Alt-Delete → clean reboot.
                            self.result = LoopResult::Reboot;
                        }
                        SignalAction::Reexecute => {
                            self.result = LoopResult::Reexecute;
                        }
                        SignalAction::Realtime(sig) => {
                            self.dispatch_realtime_signal(sig);
                        }
                        SignalAction::Reload
                        | SignalAction::DumpStatus
                        | SignalAction::WindowResize
                        | SignalAction::PowerFailure
                        | SignalAction::Ignore => {
                            // Handled by higher layers once implemented.
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn dispatch_realtime_signal(&mut self, sig: libc::c_int) {
        // RT signals in [SIGRTMIN, SIGRTMIN+29] carry systemd-specific
        // semantics.  Map them to LoopResult actions where appropriate.
        // Remaining RT signals are forwarded to the unit state machine.
        // SIGRTMIN() is safe to call (reads a kernel constant, no side effects).
        let min = libc::SIGRTMIN();
        match sig - min {
            2 | 13 => self.result = LoopResult::Poweroff,
            3 | 15 => self.result = LoopResult::Halt,
            4 | 14 => self.result = LoopResult::Reboot,
            _ => {}
        }
    }

    fn dispatch_timer(&mut self, id: SourceId) {
        if let Some(src) = self.timer_sources.get_mut(&id) {
            let exp = src.tfd.drain();
            if exp > 0 {
                src.handler.on_timer(id, exp);
            }
        }
    }

    fn dispatch_io(&mut self, id: SourceId, events: u32) {
        if let Some(src) = self.io_sources.get_mut(&id) {
            src.handler.on_io(src.fd, events);
        }
    }

    fn dispatch_inotify(&mut self, id: SourceId) {
        // Read all pending inotify events from the fd.
        // Each inotify_event is variable-length due to the name field.
        let Some(src) = self.inotify_sources.get_mut(&id) else {
            return;
        };

        let mut buf = [0u8; 4096];
        loop {
            // Safety: read into a valid byte buffer owned by this scope.
            let n = unsafe { libc::read(src.ifd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                break;
            }
            // n > 0, so cast to usize is safe.
            #[allow(clippy::cast_sign_loss)]
            let nbytes = n as usize;
            let mut offset = 0usize;
            while offset + std::mem::size_of::<libc::inotify_event>() <= nbytes {
                // Safety: buf has at least sizeof(inotify_event) bytes remaining
                // starting at offset; the kernel guarantees correct alignment.
                #[allow(clippy::cast_ptr_alignment)]
                let ev = unsafe { &*buf.as_ptr().add(offset).cast::<libc::inotify_event>() };
                let path = src.ifd.path_for(ev.wd);
                src.handler.on_inotify(ev.wd, ev.mask, path);
                offset += std::mem::size_of::<libc::inotify_event>() + ev.len as usize;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{EventLoop, IoHandler};
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    struct CountingIo(Arc<AtomicUsize>);

    impl IoHandler for CountingIo {
        fn on_io(&mut self, fd: i32, _events: u32) {
            let mut byte = 0_u8;
            // Safety: the event loop invokes this handler only while the
            // registered UnixStream descriptor remains open.
            let _ = unsafe { libc::read(fd, std::ptr::addr_of_mut!(byte).cast(), 1) };
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn disabled_io_source_retains_pending_readiness_until_reenabled() {
        let (reader, mut writer) = UnixStream::pair().expect("socketpair");
        reader.set_nonblocking(true).expect("nonblocking reader");
        let calls = Arc::new(AtomicUsize::new(0));
        let mut event_loop = EventLoop::new().expect("event loop");
        let source = event_loop
            .add_io(
                reader.as_raw_fd(),
                libc::EPOLLIN as u32,
                Box::new(CountingIo(Arc::clone(&calls))),
            )
            .expect("register IO source");

        event_loop
            .set_io_enabled(source, false)
            .expect("disable IO source");
        writer.write_all(b"x").expect("make source readable");
        event_loop.run_once_timeout(0).expect("disabled poll");
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        event_loop
            .set_io_enabled(source, true)
            .expect("reenable IO source");
        event_loop.run_once_timeout(100).expect("enabled poll");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
