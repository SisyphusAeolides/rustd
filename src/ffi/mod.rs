// SPDX-License-Identifier: LGPL-2.1-or-later
//! FFI module — raw C binding declarations.
//!
//! Each sub-module corresponds to one `ffi/*.c` source file.
//! No logic lives here; all safe wrappers live in `src/event/`,
//! `src/native/`, etc.

pub mod capability;
pub mod event;
pub mod journal;
pub mod kexec;
pub mod mute_console;
pub mod native;
pub mod notify;
pub mod sandbox;
pub mod seccomp;
pub mod socket_activation;
pub mod spawn;
