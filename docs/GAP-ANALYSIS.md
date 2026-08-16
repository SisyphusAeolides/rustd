<!-- SPDX-License-Identifier: LGPL-2.1-or-later -->
# rustd Gap Analysis — v261 Parity

Upstream baseline: `de9dbc37ad4aa637e200ac02a0545095997055df`

## Quick scorecard

| Area | Done | Open | Complexity |
|---|---|---|---|
| seccomp filters | RestrictRealtime only | SystemCallFilter, RestrictNamespaces, MemoryDenyWriteExecute, RestrictArchitectures | XL |
| capabilities | — | CapabilityBoundingSet, AmbientCapabilities, capset(2) | M |
| D-Bus signals | Subscribe/Unsubscribe stubs | UnitNew, UnitRemoved, JobNew, JobRemoved | M |
| D-Bus Service object | — | ~80 service-specific properties | L |
| polkit | allow-all implicit | CheckAuthorization async flow | M |
| watchdog | parse only | keepalive timer, WATCHDOG_USEC env, hardware ioctl | M |
| cgroup empty | inotify infra | cgroup.events watch + populated state trigger | S |
| systemctl | 12 commands | list-unit-files, isolate, show, set-property | M |
| journalctl -b | flag parsed | boot ID lookup, offset, filtering | M |
| journal catalog | — | binary format, MESSAGE_ID lookup, locale chain | M |

---

## 1. seccomp — `src/shared/seccomp-util.c`

### What upstream does

| Function | Purpose |
|---|---|
| `seccomp_load_syscall_filter()` | Compile + load allow/block list BPF via `prctl(PR_SET_SECCOMP)` |
| `seccomp_restrict_archs()` | Block non-native arches (`SystemCallArchitectures=`) |
| `seccomp_restrict_namespaces()` | Block `unshare(2)` / `clone(CLONE_NEW*)` args |
| `seccomp_memory_deny_write_execute()` | Block `mmap(PROT_WRITE|PROT_EXEC)` and `mprotect()` to PROT_EXEC |
| `seccomp_restrict_realtime_full()` | Kill on `sched_setscheduler(SCHED_FIFO/RR)` |

BPF program structure: load arch → check arch → load syscall nr → jump table per syscall → check args → `SECCOMP_RET_KILL_PROCESS` or `SECCOMP_RET_ERRNO(EPERM)` or `SECCOMP_RET_ALLOW`.

### What we have

`ffi/sandbox.c:sd_sandbox_restrict_realtime()` — 13-instruction hand-coded BPF for SCHED_FIFO/RR. Fully working.

### What is missing

- `SystemCallFilter=` allow/block list → arbitrary syscall BPF filter
- `SystemCallArchitectures=` → arch restriction filter
- `RestrictNamespaces=` → block `unshare` + `clone` with CLONE_NEW* args
- `MemoryDenyWriteExecute=` → block simultaneous PROT_WRITE+PROT_EXEC mmap/mprotect

### Implementation plan

New C file `ffi/seccomp.c` + header `ffi/seccomp.h`. No libseccomp dependency — hand-coded BPF using Linux `<linux/filter.h>` and `<linux/seccomp.h>`.

```c
int sd_seccomp_restrict_namespaces(uint64_t allowed_mask);
int sd_seccomp_memory_deny_write_execute(void);
int sd_seccomp_syscall_filter(const char *const *allow, const char *const *deny, int errno_num);
int sd_seccomp_restrict_archs(uint32_t native_arch);
```

Rust bindings in `src/ffi/seccomp.rs`. Enforcement wired in `src/sandbox.rs::apply_in_child()`.

**Complexity: XL** (~1 200 lines C + 200 lines Rust)

---

## 2. capabilities — `src/shared/capability-util.c`

### What upstream does

Exec-child sequence (after fork, before execve):
1. `prctl(PR_CAPBSET_DROP, cap)` for each cap not in `CapabilityBoundingSet=`
2. `setuid()` / `setgid()` (privilege drop)
3. `capset(hdr, data)` to set effective/permitted/inheritable sets
4. `prctl(PR_CAP_AMBIENT_RAISE, cap)` for each cap in `AmbientCapabilities=`

ABI: `capset(2)` requires `_LINUX_CAPABILITY_VERSION_3` header + two `cap_user_data_t` structs (64-bit bitmask split across two 32-bit words).

### What we have

`ffi/spawn.c` does `setuid()`/`setgid()`. `src/unit/section_service.rs` parses `CapabilityBoundingSet=` and `AmbientCapabilities=` into `Vec<String>`. Neither is applied.

### What is missing

- C function `sd_spawn_apply_capabilities(uint64_t bounding, uint64_t ambient)` in `ffi/spawn.c`
- Cap name → number mapping (CAP_CHOWN=0 … CAP_LAST_CAP; we own the table, no libcap)
- `src/sandbox.rs`: resolve string list → bitmask, pass to spawn params
- `SdSpawnParams`: new fields `cap_bounding_set: u64`, `ambient_caps: u64`

**Complexity: M** (~300 lines C + 150 lines Rust)

---

## 3. D-Bus signals — `src/core/dbus-manager.c`

### What upstream does

```c
bus_manager_send_unit_new(manager, unit);        // signal UnitNew(ss)
bus_manager_send_unit_removed(manager, unit);    // signal UnitRemoved(ss)
bus_manager_send_job_new(manager, job, unit);    // signal JobNew(uos)
bus_manager_send_job_removed(manager, job, ...); // signal JobRemoved(uosss)
```

Emission is via `sd_bus_emit_signal(bus, path, iface, signal, sig, args...)`. Sent to all subscribed connections.

### What we have

`Subscribe()`/`Unsubscribe()` are no-ops. No signal emission.

### What is missing

- zbus signal emission: `ObjectServer::emit_signal(path, iface, signal, args)`
- `ManagerInterface` gains subscriber set `Arc<Mutex<HashSet<String>>>`
- `publish_snapshot()` in manager triggers signal emission on state delta
- `JobQueue` completion callback fires `JobRemoved`

**Complexity: M** (~300 lines Rust)

---

## 4. D-Bus Service object — `src/core/dbus-service.c`

### What upstream does

Exposes `org.freedesktop.systemd1.Service` on each service unit's object path with ~80 properties:

Config: `Type`, `Restart`, `TimeoutStartUSec`, `TimeoutStopUSec`, `WatchdogUSec`, `RemainAfterExit`, `ExecStart` (`a(sasb)`), `ExecStop`, `User`, `Group`, `DynamicUser`, `NoNewPrivileges`, `CapabilityBoundingSet`, `AmbientCapabilities`, `MemoryDenyWriteExecute`, `RestrictNamespaces`, `RestrictRealtime`, `PrivateTmp`, `PrivateNetwork`, `ProtectSystem`, `ProtectHome`, `NotifyAccess`, `OOMPolicy`, `FailureAction`, `SuccessAction` …

Runtime: `MainPID`, `ControlPID`, `StatusText`, `StatusErrno`, `Result`, `NRestarts`, `ExecMainExitCode`, `ExecMainExitStatus`, `USec`.

### What we have

`UnitInterface` in `src/dbus/unit_iface.rs` covers the base Unit properties only. No Service-specific object.

### What is missing

`src/dbus/service_iface.rs` — new `ServiceInterface` struct with zbus `#[interface(name="org.freedesktop.systemd1.Service")]`. Registered alongside `UnitInterface` for service units. Reads directly from `UnitRecord` / `ServiceSection` snapshot.

**Complexity: L** (~700 lines Rust)

---

## 5. polkit — `src/core/dbus-manager.c`

### What upstream does

Before executing any privileged method, calls `bus_verify_polkit_async(msg, "org.freedesktop.systemd1.manage-units", ...)` which:
1. Gets caller UID/PID from D-Bus connection credentials
2. Calls `org.freedesktop.PolicyKit1.Authority.CheckAuthorization` async
3. Blocks method reply until polkit returns Allow/Deny/Challenge

Action IDs: `org.freedesktop.systemd1.manage-units`, `.manage-unit-files`, `.reboot-system`, `.power-off-system`, `.reload-daemon`, `.manage-environment`.

### What we have

All methods execute immediately without any authorization check. Implicitly allow-all.

### What is missing

`src/dbus/auth.rs` — async `check_polkit(conn, action_id, details)` function. Call before each privileged method body. On non-root system bus reject without polkit query.

**Complexity: M** (~250 lines Rust)

---

## 6. watchdog — `src/core/watchdog.c`

### What upstream does

1. Parse `WatchdogSec=` from unit file → `watchdog_usec`
2. Set `WATCHDOG_USEC=<usec>` in child environment
3. Install half-period timer in epoll loop
4. On timer: `sd_notify(0, "WATCHDOG=1")` (notify socket) or `ioctl(wd_fd, WDIOC_KEEPALIVE)` (hardware)
5. Track last WATCHDOG=1 from child; kill+restart if overdue

### What we have

`NotifyMessage::watchdog` bool parsed. Timer infra exists. `WATCHDOG_USEC` not set in child env.

### What is missing

- `section_service.rs`: parse `WatchdogSec=` → `Duration`
- `ffi/spawn.c`: add `WATCHDOG_USEC=<usec>` to child environment when non-zero
- `manager.rs`: install per-unit watchdog timer; on expiry send `WATCHDOG=1` or kill
- `notify.rs`: `NotifyServer` tracks last watchdog ping time per PID

**Complexity: M** (~300 lines Rust + 30 lines C)

---

## 7. cgroup empty notification — `src/core/cgroup.c`

### What upstream does

Watch `<cgroup_path>/cgroup.events` via `inotify_add_watch(..., IN_MODIFY)`. On change: read file, check `populated 0` → trigger service deactivation.

### What we have

`EventLoop::add_inotify()` fully works. `CgroupManager::create_unit_cgroup()` returns the path.

### What is missing

- After `attach_pid()`: call `event_loop.inotify_add_watch(id, "<path>/cgroup.events", IN_MODIFY)`
- `InotifyHandler` impl: read file, parse `populated N`, if `N==0` push deactivation job
- Wire into manager's `run_job()` Start path

**Complexity: S** (~120 lines Rust)

---

## 8. systemctl gaps

### list-unit-files

Scan unit dirs, detect enabled/disabled/static/masked/alias state per file. Output table with `STATE` + `VENDOR PRESET` columns.

`src/unit/enable_state.rs` already has `UnitFileState` and `query_system_enable_state()`. Need: directory traversal + sorting + tabular output.

**Complexity: M** (~250 lines Rust)

### isolate

Job mode `"isolate"` passed to `StartUnit()`: compute dependency closure of target, enqueue Stop for every active unit not in closure. Integrates with existing `src/deps.rs` resolver.

**Complexity: M** (~200 lines Rust)

### show

Query all D-Bus properties via `org.freedesktop.DBus.Properties.GetAll`, format as `Property=Value` lines. `-p Name,…` filter. `--value` prints values only.

**Complexity: M** (~200 lines Rust)

### set-property

Call `org.freedesktop.DBus.Properties.Set` per property. Parse `Key=Value` args. Persist to `/run/systemd/system.control/<unit>.d/` (runtime) or `/etc/systemd/system/` (permanent).

**Complexity: M** (~200 lines Rust)

---

## 9. journalctl -b

Read boot ID from `/proc/sys/kernel/random/boot_id`. For offset (`-b -1`): list journal dir sorted by mtime, pick nth file, extract `_BOOT_ID` from first entry. Filter entries by `_BOOT_ID` field match.

**Complexity: M** (~200 lines Rust)

---

## 10. journal catalog — `src/journal/catalog.c`

Binary database at `/var/lib/systemd/catalog/systemd.catalog`. Index: sorted array of (MESSAGE_ID u128, text_offset u64, text_len u64). Text: `<lang_code>\n<message>\n\n`. Lookup: binary search by MESSAGE_ID, locale fallback chain.

**Complexity: M** (~300 lines Rust)

---

## Formal verification additions needed

| Gap | Idris2 proof | Agda proof |
|---|---|---|
| seccomp filter correctness | BPF instruction list terminates | `Systemd/Seccomp/Filter.agda` — filter safety invariant |
| capability bitmask | cap set ⊆ bounding set | `Systemd/Capability/Bound.agda` |
| watchdog monotonicity | ping timestamps strictly increase | Extend `Systemd/Unit/State.agda` |
| cgroup empty ↔ deactivation | empty → ¬Active | Extend `Systemd/Unit/Transition.agda` |

---

## Total remaining work estimate

| Phase | Items | Est. lines | Est. time |
|---|---|---|---|
| L — seccomp + capabilities | 2 | ~1 900 | 2 weeks |
| M — D-Bus signals + Service obj + polkit | 3 | ~1 250 | 2 weeks |
| N — systemctl (4 commands) | 4 | ~850 | 1 week |
| O — journal (-b, catalog) | 2 | ~500 | 1 week |
| P — watchdog + cgroup empty | 2 | ~450 | 1 week |
| Q — release gates (diff tests, live boot) | 6 | tests | ongoing |

**Grand total: ~5 000 lines of new code across 7 weeks of focused work.**
