// SPDX-License-Identifier: LGPL-2.1-or-later
//! D-Bus server — `org.freedesktop.systemd1`.
//!
//! Runs a zbus `Connection` on a dedicated tokio thread pool.  The main
//! epoll loop is unaffected; D-Bus calls enqueue jobs into the shared
//! `JobQueue` which is drained each manager loop iteration.
//!
//! Upstream reference: `src/core/dbus-manager.c`,
//!   `src/core/dbus-unit.c` (v261)

pub mod auth;
pub mod introspection;
pub mod job_iface;
pub mod manager_iface;
pub mod server;
pub mod service_iface;
pub mod unit_iface;
