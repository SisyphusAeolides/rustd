# RustD interoperability and release ledger

RustD is an independent Linux init system and service manager. This ledger
tracks native RustD behavior and the small interoperability surface that may be
retained for applications that speak established Linux or freedesktop
protocols. Upstream implementation parity is not a RustD release criterion.

## Native identity

- [x] Cargo package name is `rustd`.
- [x] Rust library crate name is `rustd`.
- [x] PID 1 executable is `rustd`.
- [x] Manager CLI is `rustctl`.
- [x] Private C/Rust FFI symbols use the `rustd_*` namespace.
- [x] Native configuration roots are `/etc/rustd`, `/run/rustd`, and
  `/usr/lib/rustd`.
- [x] Native system unit roots are `/etc/rustd/system`, `/run/rustd/system`,
  `/usr/local/lib/rustd/system`, and `/usr/lib/rustd/system`.
- [x] Native journal and control-plane runtime state belongs under `/run/rustd`.
- [x] The shipped executable surface uses RustD names rather than compatibility
  executable aliases.

## Build integrity

- [x] Rust package paths have concrete library and binary sources.
- [x] C and Fortran ABI declarations agree at the repository boundary.
- [x] Rust 1.75 is the minimum supported Rust version for the RustD manager.
- [x] Stable `rustfmt` is an authoritative CI gate.
- [x] Rust 1.75 Clippy, all-target/all-feature tests, release builds, native ABI,
  packaging, and lockfile reproducibility are authoritative CI gates.
- [x] The `rustd-logind` D-Bus compatibility target is covered by the same
  strict stable-Clippy source policy as the manager.
- [x] Idris and Agda models are checked by the formal-verification workflow.
- [x] GitHub Actions used by the production CI are pinned to immutable commits.

## PID 1 and service manager

- [x] Kernel command-line parsing and explicit target selection.
- [x] cgroup v2 root setup and per-unit resource hierarchy.
- [x] epoll event loop with signal, socket, timer, and inotify sources.
- [x] native RustD unit loading and dependency transactions.
- [x] service lifecycle and `ExecStart*`, `ExecStop`, and `ExecReload` handling.
- [x] simple, forking, oneshot, notify, D-Bus, and idle service modes.
- [x] restart policy and start/stop timeout handling.
- [x] socket, timer, path, mount, swap, and target activation/tracking.
- [x] cgroup-v2 CPU, IO, memory, and task resource controls.
- [x] emergency, rescue, and normal boot target selection.
- [x] reboot, poweroff, halt, kexec, and in-place re-execution transitions.
- [x] PID 1 child reaping and service supervision paths are covered by native
  tests.

## RustD control plane

- [x] `rustctl list-units`, `list-jobs`, `status`, and `show`.
- [x] `rustctl start`, `stop`, `restart`, and `reload`.
- [x] `rustctl enable --now` and `disable --now`.
- [x] `rustctl mask`, `unmask`, `is-enabled`, `is-active`, and `is-failed`.
- [x] `rustctl reset-failed`, `daemon-reload`, `isolate`, and `cancel`.
- [x] bounded job completion waits rather than unbounded CLI blocking.
- [x] alternate-root enablement safety prevents `--root` from mutating the live
  manager with `--now`.

## Activation, logging, and recovery

- [x] RustD-owned journald component and runtime sockets.
- [x] structured journal ingestion and persistent journal storage.
- [x] journal rotation, vacuuming, filtering, follow, and catalog handling.
- [x] native socket, timer, path, and mount activation paths.
- [x] RustD-owned rescue and emergency console-shell services.
- [x] native boot graph, getty templates, boot accounting, random seed, time,
  and boot-health units are shipped from `/usr/lib/rustd/system`.

## Security boundaries

- [x] user/group and dynamic-user handling.
- [x] `NoNewPrivileges`, private temporary/device namespaces, and filesystem
  protection controls.
- [x] capability bounding and ambient capabilities.
- [x] namespace restrictions and seccomp filters.
- [x] SELinux/AppArmor context assignment where available.
- [x] cgroup and privilege-boundary failures propagate as hard manager errors
  rather than being silently ignored at the production PID 1 boundary.

## Companion resolver

- [x] `rustd-resolved` is a separate native RustD daemon.
- [x] native resolver runtime paths live under `/run/rustd/resolve`.
- [x] native resolver CLI is `rustd-resolvectl`.
- [x] native Varlink namespace is `io.rustd.Resolve`.
- [x] RustD-resolved maintains compatibility adapters only at explicitly tested
  protocol boundaries; they do not define the native RustD identity.

## Interoperability boundary

RustD may implement established Linux/freedesktop interfaces when doing so lets
existing software communicate with RustD without making another init system the
reference architecture. Such adapters must be isolated from RustD's native
package names, executable names, private symbols, configuration roots, runtime
paths, and internal module namespace.

A compatibility adapter is acceptable only when all of these are true:

- the native RustD interface remains authoritative;
- the adapter is covered by a regression test;
- disabling or removing the adapter does not change RustD's internal model;
- the adapter does not install compatibility executables or compatibility
  libraries as the primary RustD interface;
- user-facing RustD diagnostics and documentation continue to identify the
  running component as RustD.

Source-tree compatibility libraries are validation and application-interoperability
surfaces; the native `make install` target continues to install RustD libraries
and executables rather than those compatibility SONAMEs. Current regression
coverage includes:

- [x] compatibility SONAME and required-symbol checks against development
  headers;
- [x] journal stream creation and bidirectional journal cursor traversal;
- [x] pidfd session and owner-UID lookup with pidfd identity validation;
- [x] device property iteration across the complete native property list;
- [x] writable device sysattrs with bounded values, trailing newline trimming,
  real errno propagation, no-write `NULL` behavior, and path traversal
  rejection.

## Production-release gates

Source/build readiness requires every authoritative CI and formal gate to pass
from the same committed tree. Installed-system readiness additionally requires a
snapshot-backed or otherwise recoverable machine running RustD as PID 1.

Before a release is called production-ready, the project requires:

- [ ] native ABI, formatting, Clippy, tests, release build, packaging, lockfile,
  and formal-model CI gates pass from the same candidate commit;
- [ ] repeated clean cold boots with RustD as the sole PID 1;
- [ ] repeated reboot, poweroff, halt, rescue, emergency, and re-exec campaigns;
- [ ] crash-loop, timeout-escalation, signal-storm, dependency-failure, and
  resource-pressure campaigns;
- [ ] activation concurrency and manager-reload stress campaigns;
- [ ] installed `rustd-resolved` restart/reconfiguration and network recovery
  campaigns on the same RustD boot stack;
- [ ] malformed-input, privilege-boundary, filesystem-pressure, and
  resource-exhaustion fault campaigns;
- [ ] reproducible release artifacts and long-running soak results archived for
  the candidate release;
- [ ] `make certify` passes on the installed candidate while `/proc/1/exe`
  resolves to the RustD PID 1 binary.

The source tree must not claim that passing a normal-process unit test or build
alone proves PID 1 production readiness. The installed-system campaign is the
final safety boundary for an init system.
