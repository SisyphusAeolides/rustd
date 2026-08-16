# Phase E — Journal

## Overview

Implement `systemd-journald`: a socket receiver at
`/run/systemd/journal/socket`, a binary journal file writer matching the
upstream on-disk format, log capture from service stdout/stderr via
`/run/systemd/journal/stdout`, and a fully functional `journalctl` binary.

Upstream reference: `src/journal/`, `src/journal-remote/`,
`src/journald/` in systemd v261
(`de9dbc37ad4aa637e200ac02a0545095997055df`).

Language boundaries:
- **Rust** — receiver, in-memory ring, journal writer, journalctl
- **C** (`ffi/journal.c`) — `writev` journal entry, mmap journal file header
- **Fortran** — no new modules
- **Idris / Agda** — formal spec of journal entry ordering (Phase J)

---

## Sub-tasks

### E1 — Journal entry types and in-memory ring (`src/journal/entry.rs`)

**Intent**
Define the in-memory representation of a journal entry: a set of
`KEY=VALUE` fields, a monotonic timestamp, a realtime timestamp, a
boot ID, a machine ID, and a sequence number.  Provide the ring buffer
that holds entries before they are flushed to disk.

**Expected outcomes**
- `src/journal/entry.rs` — `JournalEntry`, `JournalFields`, `EntryRing`.
- `JournalEntry::new(fields)` stamps timestamps automatically.
- `EntryRing::push` / `EntryRing::drain_since` for cursor-based reads.
- Unit tests: push 3 entries, drain returns them in order.

**Status:** [x] done

---

### E2 — Journal socket receiver (`ffi/journal.c` + `src/journal/receiver.rs`)

**Intent**
Bind the datagram socket at `/run/systemd/journal/socket`, receive
`sd_journal_sendv`-style messages (newline-separated `KEY=VALUE` pairs
or binary large-field frames), parse them into `JournalEntry` values,
and push them into the ring.

The C helper exposes:
- `sd_journal_socket_bind()` — create and bind the socket.
- `sd_journal_socket_recv(fd, buf, len)` — `recvmsg` one datagram.

**Expected outcomes**
- `ffi/journal.c` implements `sd_journal_socket_bind` and
  `sd_journal_socket_recv`.
- `src/journal/receiver.rs` — `JournalReceiver` wrapping the fd,
  registered with `EventLoop::add_io`; `on_io` parses datagrams.
- `PRIORITY`, `MESSAGE`, `_PID`, `_COMM`, `_SYSTEMD_UNIT` fields
  extracted correctly.
- Unit test: send a datagram to the socket; confirm entry appears in ring.

**Status:** [x] done

---

### E3 — Binary journal file writer (`ffi/journal.c` + `src/journal/writer.rs`)

**Intent**
Write journal entries to binary journal files under
`/var/log/journal/<machine-id>/system.journal`, matching the upstream
on-disk format well enough that `journalctl --file` from the real
systemd can read them.

The upstream format:
- File header (256 bytes): magic, file flags, header size, arena size,
  data hash table offset, field hash table offset, tail object offset,
  head object offset, tail entry offset, entry array offset, etc.
- Objects: `ObjectHeader` (type, flags, size) followed by payload.
  Object types: DATA (0), FIELD (1), ENTRY (2), DATA_HASH_TABLE (3),
  FIELD_HASH_TABLE (4), ENTRY_ARRAY (5), TAG (6).
- Entry object: realtime_usec, monotonic_usec, boot_id, xor_hash,
  array of `EntryItem { object_offset, hash }`.

The C helper exposes:
- `sd_journal_file_open(path)` — open/create, write header, return fd.
- `sd_journal_append_entry(fd, fields, n)` — append one entry object.
- `sd_journal_file_close(fd)` — flush and close.

**Expected outcomes**
- Journal files are readable by `journalctl --file <path>`.
- Unit test: write 10 entries, open file with `journalctl --file`,
  confirm output matches.

**Status:** [x] done

---

### E4 — stdout/stderr capture (`src/journal/stdout.rs`)

**Intent**
When the manager spawns a service, redirect its stdout and stderr to a
Unix stream socket at `/run/systemd/journal/stdout`.  Each connection
carries a header (service name, priority, identifier) followed by
line-buffered log lines that are injected into the journal as
`MESSAGE=` entries.

**Expected outcomes**
- `src/journal/stdout.rs` — `StdoutServer` bound to the socket,
  registered with the event loop.
- `spawn.c` connects a child's stdout/stderr to the socket before exec.
- Lines arrive as `MESSAGE=<line>`, `PRIORITY=<n>`, `SYSLOG_IDENTIFIER=<name>`.
- Unit test: spawn a service that writes to stdout; confirm entry in ring.

**Status:** [x] done

---

### E5 — Journal rotation and vacuum (`src/journal/rotation.rs`)

**Intent**
When the active journal file exceeds 128 MiB (or the configured
`SystemMaxFileSize=`), close it, rename it to a timestamped archive
name, and open a fresh file.  Vacuum removes archived files when total
disk use exceeds `SystemMaxUse=` or files are older than
`MaxRetentionSec=`.

**Expected outcomes**
- `src/journal/rotation.rs` — `rotate_if_needed`, `vacuum`.
- Rotation triggers automatically in `JournalWriter::append`.
- Unit test: write entries until rotation triggers; confirm two files.

**Status:** [x] done

---

### E6 — `journalctl` binary (`src/bin/journalctl.rs`)

**Intent**
Implement the `journalctl` command that reads journal files from
`/var/log/journal/` (and optionally a file given by `--file`) and
prints entries in the requested format.

**Expected outcomes**
- `journalctl` with no args: print all entries, short format.
- `journalctl -u <unit>`: filter by `_SYSTEMD_UNIT=`.
- `journalctl -b`: filter by current boot ID.
- `journalctl -f`: follow mode (poll for new entries).
- `journalctl -n <N>`: last N lines.
- `journalctl -o json`: JSON output.
- `journalctl -o short` (default), `verbose`, `cat`, `export`.
- Exit code 0 on success, 1 on error.

**Status:** [x] done

---

### E7 — Manager integration

**Intent**
Wire the journal receiver, stdout server, and writer into `Manager::new`
and `Manager::run`.

**Expected outcomes**
- `Manager::new` starts `JournalReceiver` and `StdoutServer`, registers
  them with the event loop.
- `Manager::run` flushes the entry ring to the writer each loop.
- Services spawned by `activate()` have stdout/stderr connected to the
  stdout socket.
- `SYSLOG_IDENTIFIER` and `_SYSTEMD_UNIT` fields are set correctly.

**Status:** [x] done

---

### E8 — Full validation, docs, commit

**Expected outcomes**
- `make check-native && cargo fmt --all -- --check &&
  cargo clippy --all-targets --all-features -- -D warnings &&
  cargo test --all-targets --all-features` all pass.
- `journalctl --file <test.journal>` from real systemd reads our files.
- `docs/PLAN-phase-e.md` all sub-tasks `[x] done`.
- `docs/COMPATIBILITY.md` journal items checked off.
- Signed commit `journal: implement journald and journalctl — Phase E`.

**Status:** [x] done

---

## New / modified files

| File | Role |
|---|---|
| `ffi/journal.c` | Socket bind/recv, binary journal file I/O |
| `ffi/journal.h` | C declarations |
| `src/journal/mod.rs` | Module root |
| `src/journal/entry.rs` | `JournalEntry`, `EntryRing` |
| `src/journal/receiver.rs` | Datagram socket receiver |
| `src/journal/writer.rs` | Binary journal file writer |
| `src/journal/stdout.rs` | stdout/stderr capture socket |
| `src/journal/rotation.rs` | File rotation and vacuum |
| `src/bin/journalctl.rs` | Full `journalctl` CLI |
| `src/manager.rs` | Wire journal into startup and run loop |

## Dependency order

```
E1 (entry types + ring)
  └─ E2 (socket receiver)
       └─ E3 (binary writer)
            ├─ E4 (stdout capture)
            ├─ E5 (rotation)
            └─ E6 (journalctl)
                 └─ E7 (manager integration)
                      └─ E8 (validation + commit)
```
