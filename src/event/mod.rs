// SPDX-License-Identifier: LGPL-2.1-or-later
//! Event loop — epoll-driven I/O, signal, timer, inotify, child, and defer
//! sources.
//!
//! This is the Rust side of the rustd event loop, mirroring the role of
//! `sd-event` in upstream systemd (src/libsystemd/sd-event/sd-event.c).  All
//! Linux kernel calls go through `ffi/event.c`; this module provides safe
//! typed wrappers and the dispatch engine used by the service manager.
//!
//! Upstream reference: src/libsystemd/sd-event/sd-event.c (v261)

pub mod child;
pub mod inotify;
pub mod loop_;
pub mod signal;
pub mod source;
pub mod timer;
pub mod wake;

pub use loop_::{EventLoop, LoopResult};
pub use source::{SourceId, SourceToken};
pub use timer::{ClockId, TimerSpec};
pub use wake::EventLoopWake;
