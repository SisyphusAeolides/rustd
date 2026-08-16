# Phase C — Service Lifecycle Manager

## Overview

Implement the core service manager: the unit registry, dependency resolver,
job queue, process spawner, service state machine, notification socket,
watchdog, restart logic, cgroup tree, and timeout escalation.

At the end of Phase C the binary (`src/main.rs`) must be able to load a real
`.service` file, fork/exec the process, transition through
`Inactive → Activating → Active`, handle process exit, and apply the correct
restart policy — all driven by the existing `EventLoop`.

Upstream reference: `src/core/manager.c`, `src/core/service.c`,
`src/core/job.c`, `src/core/unit.c`, `src/core/execute.c`,
`src/core/cgroup.c` in systemd v261
(`de9dbc37ad4aa637e200ac02a0545095997055df`).

Language boundaries:
- **Rust** — all state machine logic, job queue, registry, orchestration
- **C** (`ffi/spawn.c`) — `fork`/`execve` with uid/gid/cwd/capabilities setup
- **Fortran** (`ffi/sched.f90`) — cgroup weight normalization (already built)
- **Idris / Agda** — formal specs; no new modules required for Phase C

---

## Sub-tasks

### C1 — Process spawn FFI (`ffi/spawn.c` + `src/ffi/spawn.rs`)

**Intent**
All `fork`/`execve` work goes through a C helper so unsafe Rust stays
confined to `src/ffi/`. The helper sets the working directory, applies
uid/gid credential switching, constructs the child environment vector,
installs the standard file descriptors (stdin/stdout/stderr), and closes
all inherited fds except those explicitly kept. Full Linux namespace setup
(`clone` flags, `pivot_root`, `mount`) is **not** in scope for C1; it is
added in C8.

**Expected outcomes**
- `ffi/spawn.c` exports one function `sd_spawn` with the signature below.
- `src/ffi/spawn.rs` declares the matching `extern "C"` binding.
- `ffi/test_spawn.c` smoke-tests: spawn `/bin/true` returns pid > 0;
  spawn `/nonexistent` returns `-ENOENT`; working directory is set
  correctly; environment is inherited when `envp` is null.
- `make check-native` passes with the new smoke tests.

```c
/* ffi/spawn.h */
typedef struct {
    const char * const *argv;   /* NULL-terminated, argv[0] is exec path  */
    const char * const *envp;   /* NULL-terminated; NULL = inherit parent  */
    const char         *cwd;    /* NULL = inherit parent cwd               */
    uid_t               uid;    /* (uid_t)-1 = do not switch               */
    gid_t               gid;    /* (gid_t)-1 = do not switch               */
    int                 stdin_fd;   /* -1 = /dev/null                      */
    int                 stdout_fd;  /* -1 = inherit                        */
    int                 stderr_fd;  /* -1 = inherit                        */
    int                 notify_fd;  /* -1 = not passed; else set NOTIFY_SOCKET */
} sd_spawn_params;

/* Returns pid on success, negative errno on failure. */
pid_t sd_spawn(const sd_spawn_params *p);
```

**Status:** [x] done

---

### C2 — Unit registry and manager skeleton (`src/manager.rs`)

**Intent**
`Manager` is the central object that owns the unit registry, the event loop,
and the job queue. In C2 only the skeleton is built: a `HashMap` from unit
name to `UnitRecord`, the ability to load a unit on demand via `UnitLoader`,
and a stub run loop. No activation yet.

**Expected outcomes**
- `src/manager.rs` compiles with `Manager::new()`, `Manager::load_unit()`,
  and `Manager::run()` (stubs).
- `Manager` owns an `EventLoop` and a `HashMap<String, UnitRecord>`.
- `UnitRecord` wraps `LoadedUnit` and adds runtime state:
  `state: UnitState`, `active_pid: Option<Pid>`, `restart_count: u32`,
  and `job: Option<Job>` (Job defined in C3).
- Unit tests: `Manager::new()` succeeds; `load_unit("systemd-journald.service")`
  populates the registry.
- `src/lib.rs` declares `pub mod manager`.

**Status:** [x] done

---

### C3 — Job queue (`src/job.rs`)

**Intent**
A `Job` is a pending activation or deactivation request for a unit. Jobs
form an ordered queue; the manager drains the queue each event-loop cycle.
Phase C needs only two job types: `Start` and `Stop`. `Reload` and
`Restart` are added in C6.

**Expected outcomes**
- `src/job.rs` exports `Job`, `JobKind` (`Start`, `Stop`), and `JobQueue`.
- `JobQueue::enqueue()` appends; `JobQueue::drain()` returns jobs whose
  dependency prerequisites are met (all `After=` units are `Active` or
  `Inactive`, depending on direction).
- Unit tests: enqueue `Start(a)` where `a` has `After=b`; `b` is `Inactive`;
  `drain()` first yields `Start(b)`, then `Start(a)` after `b` reaches
  `Active`.

**Status:** [x] done

---

### C4 — Dependency resolver (`src/deps.rs`)

**Intent**
Given a target unit name and the loaded unit registry, compute the full
transitive closure of units that must be started, in the correct order,
respecting `After=`/`Before=` edges. Detect cycles. Return an ordered
`Vec<String>` that the manager feeds to the job queue.

**Expected outcomes**
- `src/deps.rs` exports `fn resolve_start_order(target: &str, units: &HashMap<String, UnitRecord>) -> anyhow::Result<Vec<String>>`.
- `resolve_start_order` returns units in topological order: dependencies
  before dependents.
- Returns `Err` if a cycle is detected.
- `Wants=` units that are not loadable are silently skipped (matching
  upstream `Wants=` semantics); `Requires=` failures propagate.
- Unit tests: diamond dependency graph resolves correctly; cycle returns `Err`.

**Status:** [x] done

---

### C5 — Service state machine (`src/service.rs`)

**Intent**
Implement the `Inactive → Activating → Active → Deactivating → Inactive/Failed`
lifecycle for `Type=simple`, `Type=exec`, `Type=oneshot`, and `Type=forking`.
`Type=notify` and `Type=dbus` require the notification socket (C7) and D-Bus
(Phase D) respectively; stub them as `NotYet` errors for now.

State transitions are driven by:
- `activate(unit, manager)` — called by the job runner
- `deactivate(unit, manager)` — called by the job runner
- `on_child_exit(pid, exit_info, manager)` — called by SIGCHLD handler

**Expected outcomes**
- `src/service.rs` exports `fn activate`, `fn deactivate`,
  `fn on_child_exit`.
- `activate` for `Type=simple`: calls `sd_spawn`, records pid, transitions
  state to `Active`.
- `activate` for `Type=oneshot`: calls `sd_spawn`, transitions to
  `Activating`; `on_child_exit` transitions to `Active` (if
  `RemainAfterExit=yes`) or `Inactive` on clean exit.
- `activate` for `Type=forking`: calls `sd_spawn`, waits for parent exit,
  reads `PIDFile=` to get the daemon pid, transitions to `Active`.
- `on_child_exit` for all types: if pid matches active pid, evaluate exit
  code against `SuccessExitStatus=` / `RestartPreventExitStatus=`, apply
  restart policy (defer to C6 for actual restart), transition state.
- Conditions (`all_conditions_pass`) are checked before any spawn.
- Unit tests (no real fork): state transitions from `Inactive` to
  `Activating`, `Active`, `Failed` are exercised via mock `sd_spawn` return
  values.

**Status:** [x] done

---

### C6 — Restart policy and timeout escalation (`src/restart.rs`)

**Intent**
After a service exits, the restart policy (`Restart=`, `RestartSec=`,
`RestartSteps=`) determines whether and when to re-activate it. Timeouts
(`TimeoutStartSec=`, `TimeoutStopSec=`, `TimeoutAbortSec=`) escalate from
`SIGTERM` to `SIGKILL`. Both use the existing `EventLoop` timer API.

**Expected outcomes**
- `src/restart.rs` exports `fn schedule_restart` and `fn arm_start_timeout` /
  `fn arm_stop_timeout`.
- `schedule_restart`: if `RestartPolicy` allows restart given the exit reason,
  arm a one-shot `TimerSpec::once(restart_sec_ns)` on the event loop; the
  timer callback calls `activate()`.
- `arm_start_timeout`: arm `timeout_start_sec` monotonic timer; on expiry send
  `SIGTERM`; arm `timeout_abort_sec` (or `TimeoutStopSec`) secondary timer for
  `SIGKILL`.
- `arm_stop_timeout`: same pattern for stop.
- Start-limit burst tracking: after `start_limit_burst` activations within
  `start_limit_interval_sec`, transition to `Failed` and run
  `StartLimitAction=`.
- Unit tests: RestartPolicy matching for `no`, `on-failure`, `always`; timer
  arms correct delay.

**Status:** [x] done

---

### C7 — Notification socket and watchdog (`src/notify.rs`)

**Intent**
`Type=notify` services signal readiness by writing `READY=1` to the
`$NOTIFY_SOCKET` abstract Unix domain socket. The manager creates this
socket, registers it with the event loop as an I/O source, and parses
incoming datagrams. The watchdog heartbeat (`WATCHDOG=1`) resets a per-unit
watchdog timer; if the timer expires the service is killed.

**Expected outcomes**
- `src/notify.rs` exports `NotifyServer` with `new()`, `socket_path()`,
  and a `notify_fd()` suitable for passing to `sd_spawn_params.notify_fd`.
- `NotifyServer` implements `IoHandler`; registered on the event loop.
- On `READY=1`: transitions matching unit from `Activating` to `Active`.
- On `WATCHDOG=1`: resets the watchdog timer for that unit.
- On `STOPPING=1`: notes impending shutdown.
- Watchdog timer (`WatchdogSec=`) is armed in `activate()` for notify-type
  services; expiry kills the service with `SIGABRT`.
- `sd_spawn_params.notify_fd` is set so the socket fd is kept open across
  `exec` and `NOTIFY_SOCKET` env var is set to the socket path.
- Unit tests: write `READY=1` datagram to socket; confirm state transition.

**Status:** [x] done

---

### C8 — Cgroup tree (`src/cgroup.rs` + `ffi/cgroup.c` extension)

**Intent**
Every unit runs in its own cgroup under `system.slice`. The cgroup tree is:
```
/sys/fs/cgroup/systemd/
  system.slice/
    <unit-name>.service/
```
The Fortran `sd_sched_score_weight` kernel normalizes `CPUWeight=` values
across siblings before writing to `cpu.weight`. Phase C implements tree
creation, process attachment, and CPU/memory limits. IO limits and nested
slices are deferred.

**Expected outcomes**
- `src/cgroup.rs` exports `CgroupManager` with `setup_root()`,
  `create_unit_cgroup(name)`, `attach_pid(name, pid)`,
  `apply_cpu_weight(name, weight, siblings)`,
  `apply_memory_max(name, bytes)`.
- `setup_root()` creates `/sys/fs/cgroup/systemd/system.slice/` if absent.
- `create_unit_cgroup(name)` creates the leaf directory for a unit.
- `attach_pid(name, pid)` writes pid to `<cgroup>/cgroup.procs`.
- `apply_cpu_weight` calls Fortran `sd_sched_score_weight`, then writes
  the normalized value to `cpu.weight`.
- `apply_memory_max` writes `memory.max`.
- `ffi/cgroup.c` already has helpers; extend with `sd_cgroup_write_cpu_weight`
  and `sd_cgroup_write_memory_max`.
- Unit tests run only if `/sys/fs/cgroup` is writable (skip otherwise).

**Status:** [x] done

---

### C9 — Target and timer unit activation

**Intent**
Target units are synchronization points: activating a target means all its
`Wants=`/`Requires=` deps are activated and the target itself is marked
`Active` when they are all `Active`. Timer units arm a timerfd when activated
and enqueue a `Start` job for their `Unit=` service when the timer fires.

**Expected outcomes**
- `src/target.rs` exports `fn activate_target(record, manager)` — sets state
  to `Active` once all deps are `Active`.
- `src/timer_unit.rs` exports `fn activate_timer(record, loop_)` — arms a
  `timerfd` via `EventLoop::add_timer` for `OnBootSec=`, `OnActiveSec=`, etc.
- When the timer fires, a `Start` job is enqueued for the timer's `Unit=`.
- `Manager::run()` dispatches `LoadedUnit::Target` and `LoadedUnit::Timer`
  through these handlers.
- Unit test: synthetic timer unit with `OnBootSec=50ms` fires after ≥50 ms
  in a real event loop.

**Status:** [x] done

---

### C10 — Manager startup, `src/main.rs`, integration test

**Intent**
Wire everything together into a runnable binary. `main.rs` sets up the
manager, loads `default.target` (or a test target), resolves the dependency
closure, feeds jobs to the queue, and enters the event loop. An integration
test activates a real local `.service` file (e.g. a sleep script) and
verifies it reaches `Active`, then exits and reaches `Inactive`.

**Expected outcomes**
- `src/main.rs` initialises `Manager`, loads `default.target` or a named
  unit from argv, calls `resolve_start_order`, enqueues `Start` jobs, calls
  `manager.run()`.
- `make check-native && cargo test --all-targets --all-features` pass.
- Integration test in `src/manager.rs` (behind `#[cfg(test)]`):
  - Creates a temp `.service` file with `ExecStart=/bin/sleep 0.1`.
  - Loads it via `UnitLoader::with_dirs`.
  - Activates it; asserts state reaches `Active`.
  - Waits for child exit; asserts state reaches `Inactive`.
- `docs/PLAN-phase-c.md` all sub-tasks marked `[x] done`.
- `docs/COMPATIBILITY.md` service lifecycle items checked off.
- Signed commit pushed to `main`.

**Status:** [x] done

---

## New files summary

| File | Role |
|---|---|
| `ffi/spawn.h` | C header for `sd_spawn_params` and `sd_spawn` |
| `ffi/spawn.c` | fork/exec with uid/gid/cwd setup |
| `ffi/test_spawn.c` | C smoke tests for spawn |
| `src/ffi/spawn.rs` | `extern "C"` binding for `sd_spawn` |
| `src/manager.rs` | `Manager`, `UnitRecord`, central orchestrator |
| `src/job.rs` | `Job`, `JobKind`, `JobQueue` |
| `src/deps.rs` | Topological dependency resolver |
| `src/service.rs` | Service state machine: activate/deactivate/on_child_exit |
| `src/restart.rs` | Restart policy, timeout escalation |
| `src/notify.rs` | sd_notify socket server and watchdog |
| `src/cgroup.rs` | Cgroup tree management |
| `src/target.rs` | Target unit activation |
| `src/timer_unit.rs` | Timer unit arm/fire |

## Dependency order

```
C1 (spawn FFI)
  └─ C2 (manager skeleton)
       ├─ C3 (job queue)
       │    └─ C4 (dependency resolver)
       └─ C5 (service state machine)  ← needs C1, C3
            ├─ C6 (restart + timeouts)
            ├─ C7 (notify socket)
            └─ C8 (cgroup tree)
                 └─ C9 (target + timer units)
                      └─ C10 (main.rs + integration test)
```
