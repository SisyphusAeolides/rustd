// SPDX-License-Identifier: LGPL-2.1-or-later
//! FFI bindings for `ffi/capability.c` — Linux capability helpers.
//!
//! Upstream reference: `src/shared/capability-util.c` (v261)

extern "C" {
    /// Map a capability name (lowercase, with or without `CAP_`/`cap_` prefix)
    /// to its kernel number.
    ///
    /// Returns the capability number on success, or `-1` if unrecognised.
    ///
    /// # Safety
    /// `name` must be a valid NUL-terminated C string.
    pub fn rustd_capability_name_to_num(name: *const libc::c_char) -> libc::c_int;

    /// Drop every capability not set in `keep_mask` from the bounding set.
    /// `keep_mask = 0` drops all; `u64::MAX` keeps all (no-op).
    ///
    /// Returns 0 on success; negative errno on failure.
    ///
    /// # Safety
    /// Must be called from a single-threaded child process after `fork()`,
    /// before changing the process identity.
    pub fn rustd_capability_bounding_set_drop(keep_mask: u64) -> libc::c_int;

    /// Add the requested ambient capabilities to the permitted, inheritable,
    /// and effective sets required by `PR_CAP_AMBIENT_RAISE`.
    ///
    /// Returns 0 on success; negative errno on failure.
    ///
    /// # Safety
    /// Must be called from a single-threaded child after changing UID/GID and
    /// before clearing `PR_SET_KEEPCAPS`.
    pub fn rustd_capability_ambient_prepare(ambient_mask: u64) -> libc::c_int;

    /// Clear all ambient capabilities, then raise the requested mask.
    ///
    /// Returns 0 on success; negative errno on failure.
    ///
    /// # Safety
    /// Must be called from a single-threaded child after capability-set
    /// preparation and before `execve()`.
    pub fn rustd_capability_ambient_apply(ambient_mask: u64) -> libc::c_int;
}
