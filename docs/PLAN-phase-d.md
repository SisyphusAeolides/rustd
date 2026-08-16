# Phase D — systemctl CLI

## Overview

Implement a `systemctl` binary that communicates with the running manager over
a private Unix datagram socket.  The interface is intentionally minimal and
sufficient for the commands listed below; a D-Bus implementation is a later
phase.

Upstream reference: `src/systemctl/systemctl.c`,
`src/core/dbus-manager.c` (v261,
`de9dbc37ad4aa637e200ac02a0545095997055df`).

Language boundaries:
- **Rust** — all IPC types, manager-side server, systemctl client
- **C / Fortran / Idris / Agda** — no new modules required for Phase D

---

## IPC design

The manager creates a Unix **SOCK_SEQPACKET** socket at
`/run/rustd/ctl.sock` when it starts.  Each request is a single
`\n`-terminated JSON frame; each response is a single JSON frame.  Frame size
is capped at 64 KiB.

```
Request  → { "cmd": "<verb>", "args": [...] }
Response → { "ok": true/false, "data": <value>, "error": "<msg>" }
```

Verbs: `list-units`, `status`, `start`, `stop`, `restart`,
       `enable`, `disable`, `is-enabled`, `is-active`, `is-failed`,
       `daemon-reload`.

The wire types live in `src/ipc.rs` (lib crate) and are shared by both the
manager and the `systemctl` binary.

---

## Sub-tasks

### D1 — Wire protocol (`src/ipc.rs`)

**Intent**
Define `IpcRequest`, `IpcResponse`, and `UnitInfo` types.  Derive `serde`
`Serialize`/`Deserialize` for JSON encoding.  Provide a `send_request` /
`recv_response` helper that writes/reads a single frame over a
`SOCK_SEQPACKET` fd.

**Expected outcomes**
- `src/ipc.rs` compiles; all types derive `Serialize`, `Deserialize`, `Debug`.
- `IpcRequest::to_json()` and `IpcResponse::from_json()` helpers.
- `const SOCKET_PATH: &str = "/run/rustd/ctl.sock"`.
- Unit test: round-trip `IpcRequest` → JSON → `IpcRequest`.

**Status:** [x] done

---

### D2 — Manager IPC server (`src/manager.rs` extension)

**Intent**
On startup the manager binds `SOCKET_PATH` and spawns a dedicated thread that
`accept`s connections and dispatches requests.  Responses are formed from a
snapshot of `Manager::units` held behind an `Arc<RwLock<…>>` so the server
thread can read without blocking the event loop.

**Expected outcomes**
- `Manager::new()` calls `IpcServer::start()` which binds the socket and
  spawns a thread.
- The thread loop: `accept` → read frame → dispatch → write response.
- Dispatch table covers all eleven verbs; unknown verbs return
  `IpcResponse::err("unknown command")`.
- `daemon-reload` sends a signal to the main thread via an `Arc<AtomicBool>`
  flag polled in `Manager::run()`.
- `start`/`stop`/`restart` enqueue jobs into the `Arc<Mutex<JobQueue>>`
  shared queue (already exists from Phase C timers).
- The socket file is removed in `Drop` of `IpcServer`.
- Unit test: `IpcServer::start()` succeeds; a client can send
  `list-units` and get back a valid JSON response.

**Status:** [x] done

---

### D3 — `systemctl list-units`

**Intent**
Print a table of all loaded units with columns: `UNIT`, `LOAD`, `ACTIVE`,
`SUB`, `DESCRIPTION`.

**Expected outcomes**
- `systemctl list-units` connects to `SOCKET_PATH`, sends
  `{"cmd":"list-units","args":[]}`, prints a table.
- Output format matches upstream column widths (unit name left-padded to 45
  chars, state columns 8 chars each).
- `systemctl list-units --state=active` filters by `ACTIVE` column.
- Exit code 0 on success, 1 on connection failure.

**Status:** [x] done

---

### D4 — `systemctl status <unit>`

**Intent**
Print detailed status for one or more units including PID, cgroup path,
recent log lines (stub — full journal integration is Phase E), and the
`●` / `○` / `✗` glyph.

**Expected outcomes**
- `systemctl status foo.service` sends `{"cmd":"status","args":["foo.service"]}`.
- Response includes `UnitInfo` with all fields.
- Output mirrors upstream `systemctl status` layout (name line, loaded/active
  lines, docs, main PID, cgroup, recent log stub).
- Non-existent unit prints an error and exits 4 (upstream convention).

**Status:** [x] done

---

### D5 — `systemctl start / stop / restart`

**Intent**
Enqueue activation or deactivation jobs on the running manager and wait
for the unit to reach the expected state.

**Expected outcomes**
- `systemctl start foo.service` sends `{"cmd":"start","args":["foo.service"]}`.
- Client polls `status` every 100 ms until state is `active` or timeout
  (default 90 s).
- `systemctl stop` waits for `inactive`.
- `systemctl restart` sends `stop` then `start`.
- Exit code 0 on success, 1 on timeout, 5 on "unit not found".

**Status:** [x] done

---

### D6 — `systemctl enable / disable / is-enabled`

**Intent**
Create or remove `[Install]` symlinks in `/etc/systemd/system/` without
requiring a running manager (operates on files directly, like upstream).

**Expected outcomes**
- `systemctl enable foo.service` reads `WantedBy=` from `[Install]`,
  creates `.wants/` symlinks.
- `systemctl disable foo.service` removes those symlinks.
- `systemctl is-enabled foo.service` checks symlink existence; exits 0
  (enabled) or 1 (disabled).
- All three subcommands work without a running manager.

**Status:** [x] done

---

### D7 — `systemctl is-active / is-failed / daemon-reload`

**Intent**
Thin wrappers around the IPC protocol.

**Expected outcomes**
- `systemctl is-active <unit>` → exit 0 if `Active`, else 3.
- `systemctl is-failed <unit>` → exit 0 if `Failed`, else 1.
- `systemctl daemon-reload` → sends `{"cmd":"daemon-reload","args":[]}`;
  manager re-scans unit directories and reloads changed units; exits 0.

**Status:** [x] done

---

### D8 — Full validation, docs, commit

**Expected outcomes**
- `make check-native && cargo fmt --all -- --check &&
  cargo clippy --all-targets --all-features -- -D warnings &&
  cargo test --all-targets --all-features` all pass.
- `docs/PLAN-phase-d.md` all sub-tasks `[x] done`.
- `docs/COMPATIBILITY.md` systemctl items checked off.
- Signed commit `systemctl: add CLI frontend — Phase D` pushed to `main`.

**Status:** [x] done

---

## New / modified files summary

| File | Role |
|---|---|
| `src/ipc.rs` | Wire protocol types, JSON helpers, socket path constant |
| `src/manager.rs` | `IpcServer` field, server thread, command dispatch |
| `src/bin/systemctl.rs` | Full CLI: arg parse, connect, format, exit codes |
| `docs/PLAN-phase-d.md` | This file |

## Dependency order

```
D1 (ipc.rs wire types)
  └─ D2 (manager IPC server)
       ├─ D3 (list-units)
       ├─ D4 (status)
       ├─ D5 (start/stop/restart)
       └─ D7 (is-active/is-failed/daemon-reload)
D6 (enable/disable/is-enabled — file-only, no server dep)
D8 (validation + commit)
```
