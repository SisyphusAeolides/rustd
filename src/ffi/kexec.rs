// SPDX-License-Identifier: LGPL-2.1-or-later
//! FFI bindings for `ffi/kexec.c` — Linux `reboot(2)` wrappers.
//!
//! Upstream reference: `src/core/reboot-util.c` (v261)

extern "C" {
    /// Invoke `reboot(2)` with the given command magic.
    ///
    /// Returns 0 on success, -errno on failure.
    pub fn rustd_sys_reboot(cmd: libc::c_uint) -> libc::c_int;

    /// Trigger a clean system reboot.
    ///
    /// Returns 0 on success, -errno on failure.  On success does not return.
    pub fn rustd_reboot() -> libc::c_int;

    /// Trigger a clean system poweroff.
    ///
    /// Returns 0 on success, -errno on failure.  On success does not return.
    pub fn rustd_poweroff() -> libc::c_int;

    /// Trigger a clean system halt.
    ///
    /// Returns 0 on success, -errno on failure.  On success does not return.
    pub fn rustd_halt() -> libc::c_int;

    /// Jump into a pre-loaded kexec kernel.
    ///
    /// Returns 0 on success, -errno on failure.  On success does not return.
    pub fn rustd_kexec() -> libc::c_int;
}
