// SPDX-License-Identifier: LGPL-2.1-or-later
//! Raw FFI declarations for ffi/journal.c.
//!
//! Upstream reference: `src/journald/journald-server.c`,
//!   `src/journal/journal-file.c` (v261).
//!
//! All `extern "C"` items correspond 1-for-1 to declarations in
//! `ffi/journal.c`.  No logic lives here — only types and `extern` blocks.
//! All calls are `unsafe`; safe wrappers live in `src/journal/`.

/// Receive-buffer size: 128 KiB, matching upstream `ENTRY_SIZE_MAX`.
pub const JOURNAL_RECV_BUF: usize = 128 * 1024;

/// A single field passed to `rustd_journal_file_append`.
///
/// Mirrors `rustd_journal_field` in `ffi/journal.h`.
#[repr(C)]
pub struct SdJournalField {
    /// NUL-terminated field name (e.g. `b"MESSAGE\0"`).
    pub key: *const libc::c_char,
    /// Raw value bytes (not NUL-terminated).
    pub value: *const u8,
    /// Length of `value` in bytes.
    pub value_len: libc::size_t,
}

// Safety: SdJournalField contains raw pointers that are only used for the
// duration of the FFI call; the caller guarantees validity.
unsafe impl Send for SdJournalField {}

extern "C" {
    // ── Datagram receiver ─────────────────────────────────────────────────

    /// Bind the journal datagram socket (`/run/rustd/journal/socket`).
    ///
    /// Returns the bound `SOCK_DGRAM` fd, or a negative errno on failure.
    pub fn rustd_journal_socket_bind() -> libc::c_int;

    /// Non-blocking `recvmsg` on the journal datagram socket.
    ///
    /// When `SO_PASSCRED` is enabled, peer credentials are written through the
    /// optional `pid`/`uid`/`gid` out-parameters. Returns the number of bytes
    /// received, 0 on EOF, or a negative errno.
    pub fn rustd_journal_socket_recv(
        fd: libc::c_int,
        buf: *mut libc::c_void,
        len: libc::size_t,
        pid: *mut libc::pid_t,
        uid: *mut libc::uid_t,
        gid: *mut libc::gid_t,
    ) -> libc::ssize_t;

    // ── stdout stream server ──────────────────────────────────────────────

    /// Bind the journal stdout stream socket (`/run/rustd/journal/stdout`).
    ///
    /// Returns the bound `SOCK_STREAM` listening fd, or a negative errno.
    pub fn rustd_journal_stdout_bind() -> libc::c_int;

    // ── Compressed DATA payloads ───────────────────────────────────────────

    /// Decode an upstream compressed journal DATA payload.
    ///
    /// Object compression flag values are 1=XZ, 2=LZ4, and 4=ZSTD.
    pub fn rustd_journal_decompress_payload(
        flags: u8,
        source: *const u8,
        source_size: libc::size_t,
        destination: *mut u8,
        destination_size: libc::size_t,
    ) -> libc::ssize_t;

    // ── Journal file I/O ──────────────────────────────────────────────────

    /// Open (or create) a journal file at `path`.
    ///
    /// Returns a file descriptor used as a handle, or a negative errno.
    pub fn rustd_journal_file_open(path: *const libc::c_char) -> libc::c_int;

    /// Append an entry consisting of `n` fields to the open journal file.
    ///
    /// `realtime_usec` is the wall-clock timestamp; `seqnum` is the
    /// monotonic sequence number.  Returns 0 on success or a negative errno.
    pub fn rustd_journal_file_append(
        fd: libc::c_int,
        fields: *const SdJournalField,
        n: libc::size_t,
        realtime_usec: u64,
        seqnum: u64,
    ) -> libc::c_int;

    /// Flush and close a journal file handle opened by `rustd_journal_file_open`.
    ///
    /// Returns 0 on success or a negative errno.
    pub fn rustd_journal_file_close(fd: libc::c_int) -> libc::c_int;
}
