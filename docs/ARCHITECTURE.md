# RustD architecture

RustD is one independent Linux init system assembled from Rust, C, Fortran,
Idris, and Agda. Language boundaries are narrow and explicit. Runtime policy is
owned by RustD; native-language helpers expose only the Linux operations needed
by that policy.

## Rust

Rust owns PID 1 lifecycle, kernel-command-line parsing, unit loading, dependency
transactions, service supervision, cgroup management, activation, journal
coordination, manager IPC, recovery transitions, and the command-line programs.
The Cargo package and library crate are both named `rustd`, and internal Rust
code imports the project through the `rustd::...` namespace.

## C

C owns narrow Linux ABI operations that benefit from direct C bindings:
signal/signalfd setup, epoll, timerfd, inotify, eventfd, waitid, cgroup file
descriptors, capabilities, namespaces, seccomp, Unix peer credentials,
notification datagrams, inherited descriptors, kexec, and selected filesystem
operations. The private static archive is `librustd_native.a`; its functions and
constants use the `rustd_*` and `RUSTD_*` namespaces. These symbols are an
internal RustD ABI, not an installed compatibility library.

Rust wrappers around this boundary live under `src/ffi` and `src/native.rs`.
Unsafe operations are kept at this explicit boundary rather than spread through
the service-manager state machine.

## Fortran

Fortran provides deterministic scheduling-weight and resource-score functions
through a private C ABI. It handles CPU and IO weight normalization and stable
tie-breaking used by RustD policy code.

## Idris

Idris defines total models for unit states and dependency/job ordering. The
formal workflow checks legal lifecycle transitions, ordering constraints, and
activation-sequence properties against the RustD model.

## Agda

Agda carries proof-oriented lifecycle, resource-bound, and job-ordering
invariants. These proofs are checked as an independent source-tree gate and are
not substituted for runtime fault testing.

## Native runtime flow

1. `rustd` enters as PID 1 and parses the kernel command line and RustD manager
   configuration.
2. RustD establishes its cgroup-v2 hierarchy and native runtime state under
   `/run/rustd`.
3. The manager installs its signalfd/epoll event sources and PID 1 child-reaping
   path through the private `rustd_*` native ABI.
4. RustD loads the selected target and its dependency closure from native RustD
   unit roots.
5. The transaction engine orders and activates units while enforcing dependency
   and ordering edges.
6. Socket, timer, path, mount, swap, and service events share the manager event
   loop and cgroup tree.
7. `rustctl` communicates with the manager through the RustD control plane.
8. Service readiness, watchdog, and stopping notifications are consumed by the
   RustD notification path.
9. `rustd-journald` receives and persists RustD journal traffic through native
   runtime sockets.
10. PID 1 performs reload, re-exec, rescue, emergency, reboot, halt, poweroff,
    and kexec transitions through RustD-owned state and native Linux APIs.

## Unit and control-plane identity

Native system configuration belongs under `/etc/rustd`, `/run/rustd`, and
`/usr/lib/rustd`. Native system units are loaded from `/etc/rustd/system`,
`/run/rustd/system`, `/usr/local/lib/rustd/system`, and `/usr/lib/rustd/system`.
The shipped manager CLI is `rustctl`; the authoritative PID 1 binary is `rustd`.
Compatibility executable aliases are not part of the native installation
contract.

Familiar administration syntax is an ergonomic choice rather than an internal
architecture dependency. For example, `rustctl enable --now UNIT` is implemented
by RustD's own enablement and job machinery.

## Interoperability boundary

Existing Linux applications may rely on established kernel, freedesktop,
notification, D-Bus, or service-manager conventions. RustD can implement
explicit adapters for those contracts where useful, but adapters must terminate
at a boundary. They do not define RustD's package name, internal crate name,
private C ABI, configuration roots, runtime paths, unit model, or manager state
machine.

The companion `rustd-resolved` follows the same rule: `io.rustd.*` and
`/run/rustd/resolve` are native; legacy protocol names may exist only as tested
translation surfaces for external clients.

## Production boundary

Source-tree CI proves build integrity, formatting, native ABI consistency,
Clippy policy, tests, release builds, packaging, lockfile reproducibility, and
formal models. Those gates do not by themselves prove that an init system is
safe as the only PID 1 on a machine.

The installed-system boundary is `make certify` plus repeated recoverable-machine
campaigns covering cold boot, reboot, halt, poweroff, rescue, emergency, re-exec,
crash loops, signal storms, timeout escalation, dependency failures, activation
concurrency, filesystem pressure, and cgroup/resource pressure. A production
release is complete only when the source/build gates and those installed PID 1
campaigns pass on the same release candidate.
