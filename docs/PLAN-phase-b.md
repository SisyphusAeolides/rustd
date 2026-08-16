# Phase B — Unit File Parser

## Overview

Implement a complete, parity-correct parser for all systemd unit file types.
The parser reads `.service`, `.socket`, `.timer`, `.target`, `.path`, `.mount`,
`.swap`, `.slice`, and `.scope` files from disk, applies drop-in overlays, expands
specifiers, and produces typed in-memory unit descriptors that the service manager
(Phase C) will activate.

Upstream reference: `src/core/load-fragment.c`, `src/core/unit.c`,
`src/core/unit-file.c`, `src/shared/specifier.c` in systemd v261
(`de9dbc37ad4aa637e200ac02a0545095997055df`).

---

## Sub-tasks

### B1 — INI tokeniser and section/key/value extractor

**Intent**
All systemd unit files are INI-style text. Before any typed parsing can happen,
raw text must be turned into a stream of `(section, key, value)` triples. The
tokeniser must handle comments (`#`, `;`), line continuations (`\` at end of
line), multi-value keys (repeated key = value appends), empty-value keys
(resets a list to empty), and the `[Install]` section. It must reject unknown
sections with a warning but not a hard error, matching upstream behaviour.

**Expected outcomes**
- `src/unit/ini.rs` exports `parse_unit_text(input: &str) -> Vec<RawEntry>`
  where `RawEntry` holds `(section: String, key: String, value: String)`.
- Line continuations are joined before the entry is emitted.
- Empty value (`Key=`) is represented as `value: ""` — callers decide semantics.
- Round-trip test: all 312 installed `.service` files parse without error.

**Todo**
1. Create `src/unit/ini.rs` with the tokeniser.
2. Handle `#`/`;` comment lines, blank lines, `[Section]` headers.
3. Handle `\`-continuation: join lines, strip the backslash.
4. Emit `RawEntry { section, key, value }` for each key-value line.
5. Write unit tests covering comments, continuations, empty values, and
   multi-value keys.

**Relevant context**
- `ffi/event.h` pattern: C does I/O, Rust does logic. Here Rust does all of it
  — unit files are text, no syscall wrappers needed.
- `src/event/source.rs`: follow the same doc-comment style.
- Installed unit files to test against: `/usr/lib/systemd/system/*.service`.

**Status:** [x] done

---

### B2 — Specifier expansion

**Intent**
Systemd replaces `%`-prefixed tokens in unit file values before use. All 30+
specifiers from the v261 `man systemd.unit` SPECIFIERS section must be handled.
The most critical for parity are: `%n` (unit name), `%N` (unescaped name),
`%p` (prefix), `%i` (instance), `%I` (unescaped instance), `%f` (filename),
`%t` (runtime dir), `%S` (state dir), `%C` (cache dir), `%L` (logs dir),
`%E` (config dir), `%h` (home dir), `%s` (shell), `%m` (machine ID),
`%b` (boot ID), `%H` (hostname), `%v` (kernel release), `%u` (user name),
`%U` (UID), `%g` (group name), `%G` (GID), `%%` (literal `%`).

**Expected outcomes**
- `src/unit/specifier.rs` exports `expand(value: &str, ctx: &SpecifierContext) -> String`.
- `SpecifierContext` holds unit name, instance, machine ID, hostname, uid, gid,
  runtime/state/cache/logs/config dirs.
- All specifiers from the v261 man page are handled; unknown `%x` passes through
  unchanged (matching upstream behaviour).
- Unit tests for template instance expansion (`getty@tty1.service` → `%i` = `tty1`).

**Todo**
1. Create `src/unit/specifier.rs`.
2. Define `SpecifierContext` struct with all required fields.
3. Implement `expand()` scanning for `%` and replacing each known token.
4. Handle `%%` → `%` last to avoid double-expansion.
5. Parse unit name into prefix, instance, suffix for `%p`/`%i`/`%I`.
6. Write tests covering all specifiers, including `%%` and unknown `%x`.

**Relevant context**
- Upstream: `src/shared/specifier.c specifier_printf()`.
- Template units: `getty@.service` with instance `tty1` → `getty@tty1.service`.
- Machine ID lives in `/etc/machine-id`; boot ID in `/proc/sys/kernel/random/boot_id`.

**Status:** [x] done

---

### B3 — Condition and Assert evaluators

**Intent**
Unit files carry `Condition*=` and `Assert*=` directives that gate activation.
Conditions that fail cause the unit to be skipped (not failed). Assertions that
fail cause the unit to enter `failed` state. All 25+ condition types from v261
must be evaluated correctly. The most commonly used:
`ConditionPathExists=`, `ConditionPathIsDirectory=`, `ConditionPathIsSymbolicLink=`,
`ConditionPathIsMountPoint=`, `ConditionDirectoryNotEmpty=`,
`ConditionVirtualization=`, `ConditionKernelCommandLine=`,
`ConditionACPower=`, `ConditionFirstBoot=`, `ConditionHost=`,
`ConditionSecurity=`, `ConditionCapability=`, `ConditionEnvironment=`.
Negation via `!` prefix must work for all types.

**Expected outcomes**
- `src/unit/condition.rs` exports `Condition`, `ConditionKind`, and
  `fn evaluate(cond: &Condition) -> bool`.
- Negation (`!`) is handled uniformly.
- `ConditionPathExists=` works on the live filesystem.
- Unit tests for path conditions, negation, and `ConditionVirtualization=none`.

**Todo**
1. Create `src/unit/condition.rs`.
2. Define `ConditionKind` enum covering all 25+ types.
3. Define `Condition { kind, negate, value }`.
4. Implement `evaluate()` dispatching on `ConditionKind`.
5. Implement path-based conditions using `std::fs`.
6. Implement `ConditionVirtualization=` by reading `/proc/1/environ` or
   `/sys/class/dmi/id/sys_vendor`.
7. Implement `ConditionKernelCommandLine=` from `/proc/cmdline`.
8. Write tests for path conditions and negation.

**Relevant context**
- Upstream: `src/core/condition.c condition_test()`.
- All conditions support `!` prefix (negate) and `|` prefix (trigger, not yet
  required for Phase B).

**Status:** [x] done

---

### B4 — Typed [Unit] section

**Intent**
Parse the `[Unit]` section into a typed `UnitSection` struct covering all
dependency edges (`Wants=`, `Requires=`, `Requisite=`, `BindsTo=`, `PartOf=`,
`Upholds=`, `Conflicts=`, `Before=`, `After=`, `OnFailure=`, `OnSuccess=`,
`PropagatesReloadTo=`, `ReloadPropagatedFrom=`, `PropagatesStopTo=`,
`StopPropagatedFrom=`, `JoinsNamespaceOf=`, `RequiresMountsFor=`), behaviour
flags (`DefaultDependencies=`, `IgnoreOnIsolate=`, `StopWhenUnneeded=`,
`RefuseManualStart=`, `RefuseManualStop=`, `AllowIsolate=`, `CollectMode=`),
failure/success actions, job timeout settings, start-limit settings, and all
`Condition*=`/`Assert*=` entries.

**Expected outcomes**
- `src/unit/section_unit.rs` exports `UnitSection` with every field from the
  v261 `systemd.unit(5)` `[Unit]` section.
- All dependency list fields hold `Vec<String>` (unit names, specifier-expanded).
- Conditions and asserts hold `Vec<Condition>`.
- Parsing `systemd-journald.service` produces the correct `After=`, `Requires=`,
  and `Before=` lists.

**Todo**
1. Create `src/unit/section_unit.rs`.
2. Define `UnitSection` with all fields, deriving `Default`.
3. Implement `UnitSection::apply(key, value)` consuming `RawEntry` triples.
4. Parse space-separated unit name lists for dependency fields.
5. Wire `ConditionKind` parsing into `apply()` for `Condition*=`/`Assert*=`.
6. Write tests parsing `systemd-journald.service` and checking dep lists.

**Relevant context**
- Upstream: `src/core/load-fragment.c config_parse_unit_deps()`.
- Dependency lists are space-separated and accumulate across repeated keys.

**Status:** [x] done

---

### B5 — Typed [Service] section

**Intent**
Parse the `[Service]` section into a typed `ServiceSection` struct covering
`Type=` (simple, exec, forking, oneshot, dbus, notify, notify-reload, idle),
all `Exec*=` fields, `Restart=`, all timeout fields, `WatchdogSec=`,
`NotifyAccess=`, `PIDFile=`, `BusName=`, `Sockets=`, `FileDescriptorStoreMax=`,
`RemainAfterExit=`, `SuccessExitStatus=`, `RestartPreventExitStatus=`, and all
sandboxing/exec-context keys from `systemd.exec(5)` (`User=`, `Group=`,
`WorkingDirectory=`, `Environment=`, `EnvironmentFile=`, `CapabilityBoundingSet=`,
`NoNewPrivileges=`, `PrivateTmp=`, `ProtectSystem=`, `ProtectHome=`,
`SystemCallFilter=`, all `Limit*=` fields, all `*Directory=` fields, etc.).

**Expected outcomes**
- `src/unit/section_service.rs` exports `ServiceSection` with every field from
  the v261 `systemd.service(5)` and `systemd.exec(5)` man pages.
- `ExecStart=`, `ExecStartPre=`, etc. are parsed into `Vec<ExecCommand>` where
  `ExecCommand` holds the argv, and prefix flags (`-`, `+`, `!`, `!!`, `@`).
- Parsing `systemd-journald.service` produces `Type::NotifyReload`,
  correct `ExecStart=`, `WatchdogSec=`, and `Restart=Always`.

**Todo**
1. Create `src/unit/section_service.rs`.
2. Define `ServiceType` enum for all 8 types.
3. Define `ExecCommand { argv, flags }` and `ExecFlags` bitflags.
4. Define `RestartPolicy` enum.
5. Define `ServiceSection` with all fields.
6. Implement `ServiceSection::apply(key, value)`.
7. Parse exec command lines: handle `@`, `-`, `+`, `!`, `!!` prefixes, argv
   splitting respecting quotes.
8. Parse duration strings (`90s`, `1min 30s`, `infinity`) into `Option<Duration>`.
9. Write tests parsing `systemd-journald.service`.

**Relevant context**
- Upstream: `src/core/load-fragment.c config_parse_exec()`,
  `config_parse_service_type()`.
- Duration parsing: `src/basic/time-util.c parse_time()`.
- Exec prefix flags: `-` = ignore failure, `+` = full privileges, `!` = no
  new privs, `!!` = deny supplementary groups, `@` = pass argv[0] separately.

**Status:** [x] done

---

### B6 — Typed [Socket], [Timer], [Path], [Mount], [Swap] sections

**Intent**
Parse the remaining unit-type-specific sections. Each maps to a typed struct:
`SocketSection` (all `Listen*=`, `Accept=`, `PassCredentials=`, `SocketMode=`,
`Service=`, etc.), `TimerSection` (`OnBootSec=`, `OnUnitActiveSec=`,
`OnCalendar=`, `AccuracySec=`, `Persistent=`, etc.), `PathSection`
(`PathExists=`, `PathChanged=`, `PathModified=`, `DirectoryNotEmpty=`,
`MakeDirectory=`, `Unit=`), `MountSection` (`What=`, `Where=`, `Type=`,
`Options=`, `TimeoutSec=`), `SwapSection` (`What=`, `Priority=`, `Options=`,
`TimeoutSec=`).

**Expected outcomes**
- One `src/unit/section_*.rs` file per unit type.
- Parsing `systemd-journald.socket` produces `ListenDatagram=`,
  `ListenStream=`, `Service=`, `PassCredentials=` fields correctly.
- Parsing `systemd-tmpfiles-clean.timer` produces `OnBootSec=` and
  `OnUnitActiveSec=` as `Duration` values.

**Todo**
1. Create `src/unit/section_socket.rs` — all `systemd.socket(5)` fields.
2. Create `src/unit/section_timer.rs` — all `systemd.timer(5)` fields.
3. Create `src/unit/section_path.rs` — all `systemd.path(5)` fields.
4. Create `src/unit/section_mount.rs` — all `systemd.mount(5)` fields.
5. Create `src/unit/section_swap.rs` — all `systemd.swap(5)` fields.
6. Write apply() for each, reusing `parse_duration()` from B5.
7. Write tests parsing installed socket and timer units.

**Relevant context**
- Upstream: `src/core/socket.c`, `src/core/timer.c`, `src/core/path.c`.
- Timer calendar expressions (`OnCalendar=`) are complex; stub with a string
  field for now — full calendar parsing is a separate gate.

**Status:** [x] done

---

### B7 — [Install] section and enable/disable state

**Intent**
The `[Install]` section (`WantedBy=`, `RequiredBy=`, `UpheldBy=`, `Also=`,
`Alias=`, `DefaultInstance=`) drives `systemctl enable/disable`. Parse it into
`InstallSection` and implement the symlink-state reader that checks
`/etc/systemd/system/*.wants/` and `*.requires/` to determine if a unit is
enabled, disabled, static, masked, or linked.

**Expected outcomes**
- `src/unit/section_install.rs` exports `InstallSection`.
- `src/unit/enable_state.rs` exports `EnableState` enum and
  `fn query_enable_state(unit_name: &str, search_dirs: &[&Path]) -> EnableState`.
- Querying `ssh.service` on this system returns `Enabled`.

**Todo**
1. Create `src/unit/section_install.rs`.
2. Define `InstallSection` with `wanted_by`, `required_by`, `also`, `alias`,
   `default_instance` fields.
3. Create `src/unit/enable_state.rs`.
4. Define `EnableState` enum: `Enabled`, `EnabledRuntime`, `Linked`,
   `LinkedRuntime`, `Alias`, `Masked`, `MaskedRuntime`, `Static`, `Indirect`,
   `Disabled`, `Bad`, `Generated`, `Transient`.
5. Implement `query_enable_state()` scanning symlinks under search directories.
6. Write test checking `ssh.service` enable state matches `systemctl is-enabled`.

**Relevant context**
- Upstream: `src/core/unit-file.c unit_file_get_state()`.
- Masked units are symlinks to `/dev/null`.

**Status:** [x] done

---

### B8 — Unit loader: search paths, drop-ins, template instantiation

**Intent**
Bring all the above together in a `UnitLoader` that:
1. Searches the standard unit file directories in priority order
   (`/etc/systemd/system/` → `/run/systemd/system/` → `/usr/lib/systemd/system/`).
2. Reads drop-in directories (`<name>.d/*.conf`).
3. Applies drop-in entries over the base unit in order.
4. Instantiates template units (`foo@.service` + instance `bar` →
   `foo@bar.service`) by loading the template and substituting specifiers.
5. Returns a fully resolved `LoadedUnit` enum covering all unit types.

**Expected outcomes**
- `src/unit/loader.rs` exports `UnitLoader` and `LoadedUnit`.
- `UnitLoader::load("systemd-journald.service")` returns a correctly populated
  `LoadedUnit::Service(...)` on this system.
- `UnitLoader::load("getty@tty1.service")` resolves the `getty@.service` template
  with `%i` = `tty1`.
- Drop-in files in `/etc/systemd/system/systemd-journald.service.d/` are applied.

**Todo**
1. Create `src/unit/loader.rs`.
2. Define `UnitLoader { search_dirs: Vec<PathBuf> }`.
3. Implement `find_unit_file(name)` scanning dirs in priority order.
4. Implement `find_dropin_dirs(name)` for `<name>.d/` at each search level.
5. Implement template resolution: strip `@instance` from name, find `foo@.service`,
   build `SpecifierContext` with instance set.
6. Implement `load(name)` calling tokeniser → typed sections → specifier expansion
   → drop-in overlay → `LoadedUnit`.
7. Define `LoadedUnit` enum with variants for all 9 unit types.
8. Write integration test loading `systemd-journald.service` from the live system.

**Relevant context**
- Upstream: `src/core/unit.c unit_load_fragment()`,
  `src/core/unit-file.c unit_file_find_fragment()`.
- Search dir priority: `/etc` > `/run` > `/usr/lib`. Higher priority wins.
- Drop-ins: applied in filename-sort order within each `.d/` directory.

**Status:** [x] done

---

### B9 — Module wiring, COMPATIBILITY.md update, tests, commit

**Intent**
Wire all `src/unit/` modules into `src/lib.rs`, run the full validation suite
(`make check-native`, `cargo fmt`, `cargo clippy -D warnings`, `cargo test`),
update `docs/COMPATIBILITY.md` to check off the unit-parser items, and commit.

**Expected outcomes**
- `cargo test` passes with all new unit tests green.
- `docs/COMPATIBILITY.md` unit-file-parsing items are checked.
- Signed commit pushed to `main`.

**Todo**
1. Add `pub mod unit` sub-modules to `src/lib.rs`.
2. Run `cargo fmt --all` and fix any formatting issues.
3. Run `cargo clippy --all-targets --all-features -D warnings` and fix all lints.
4. Run `cargo test --all-targets --all-features`.
5. Update `docs/COMPATIBILITY.md` unit-parser ledger entries.
6. `git add -A && git commit -S && git push`.

**Status:** [x] done

---

## Dependency order

```
B1 (tokeniser)
  └─ B2 (specifiers)
       └─ B3 (conditions)
            └─ B4 ([Unit])
                 └─ B5 ([Service])
                 └─ B6 ([Socket/Timer/Path/Mount/Swap])
                 └─ B7 ([Install] + enable state)
                      └─ B8 (loader)
                           └─ B9 (wire + commit)
```
