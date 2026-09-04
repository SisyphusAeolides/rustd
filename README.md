# RustD

RustD is an independent Linux init system and service manager built around a
native `rustd` PID 1 and the `rustctl` control plane. RustD defines its own
process lifecycle, unit model, IPC, logging, activation, cgroup, recovery, boot,
and administration contracts while keeping familiar service-management command
ergonomics.

RustD is built from Rust, C, Fortran, Idris, Agda, and direct Linux interfaces.
Linux kernel ABIs and useful freedesktop/Linux application protocols may be
supported where they make sense, but another init system is not RustD's
reference architecture and implementation parity is not a release gate.

For ArachOS, RustD is the measured PID 1 payload loaded by GRUB into Arach
Kernel. ArachOS owns the release, pacman repository, ArchISO image, and
Calamares installer. That path is release-qualified only when Arach Kernel
provides the complete Linux process, filesystem, cgroup, device, IPC, and
networking contracts exercised by the packaged RustD service graph.

The default manager scheduler includes a bounded nonlinear policy weave using
Lorenz and Mandelbrot features plus Rössler, logistic-map, Lyapunov, and
Duffing signals. These signals rank only jobs that are already dependency-ready;
they cannot bypass transaction ordering or configured critical operations.
Their boundedness and ordering invariants are covered by unit tests, while any
performance claim still requires boot and workload benchmarks.

> **Current status (2026-09-04):** RustD's native, build, packaging, and
> compatibility-library gates are passing, including 107 native targets and
> complete validation of the 336-entry compatibility surface. The bounded
> nonlinear scheduler passes its ordering and bounds tests. The pinned RustD
> and RustD-resolved revisions also pass the ArachOS pacman package build and
> candidate-repository validation. The final Arach-Kernel image and
> installed-system runtime certificate remain open gates.
>
> **Production boundary:** this is not a claim that RustD is a 100% certified,
> drop-in replacement for systemd. Repeated installed-system VM campaigns as
> sole PID 1—covering cold boot, reboot, shutdown, rescue/emergency paths,
> re-exec, crash/fault recovery, networking, login, DNS, package management,
> SELinux, and initramfs behavior—remain required for the exact release image.
> Until those gates pass, retain a known-good recovery path and use a
> snapshot-backed VM or equivalent recoverable environment before making RustD
> the only boot path.

## Native architecture

RustD is built around a small authoritative core:

- the Cargo package and library crate are both named `rustd`;
- `rustd` owns PID 1 duties, child reaping, shutdown/reboot, signal handling,
  service supervision, dependency transactions, activation, and recovery;
- `rustctl` is the authoritative manager CLI;
- private native FFI symbols use the `rustd_*` namespace;
- configuration belongs under `/etc/rustd`, `/run/rustd`, and `/usr/lib/rustd`;
- native system unit roots are `/etc/rustd/system`, `/run/rustd/system`,
  `/usr/local/lib/rustd/system`, and `/usr/lib/rustd/system`;
- per-user unit/config roots use the RustD namespace beneath the XDG paths;
- cgroup v2, Linux capabilities, seccomp, namespaces, sockets, timers, paths,
  mounts, credentials, and process supervision are handled directly through
  Linux APIs;
- `rustd-journald` and the logging layer are RustD components;
- `rustd-resolved` is the companion native RustD name resolver in its own
  repository.

## Familiar administration, native implementation

RustD keeps common service-management workflows familiar while using RustD
names, paths, IPC, and runtime semantics:

```sh
rustctl enable --now sshd.service
rustctl disable --now example.service
rustctl start example.service
rustctl stop example.service
rustctl restart example.service
rustctl reload example.service
rustctl status example.service
rustctl is-active example.service
rustctl is-enabled example.service
rustctl mask example.service
rustctl unmask example.service
rustctl daemon-reload
```

`rustctl enable --now UNIT` creates native RustD enablement links and starts the
unit through the RustD manager. `rustctl disable --now UNIT` removes native
enablement links and stops the unit. `--now` is deliberately rejected with
`--root` so an offline-root operation cannot mutate the live manager.

The supported manager command contract includes `list-units`, `list-jobs`,
`status`, `show`, `start`, `stop`, `restart`, `reload`, `enable`, `disable`,
`mask`, `unmask`, `is-enabled`, `is-active`, `is-failed`, `reset-failed`,
`daemon-reload`, `isolate`, and `cancel`.

## Native conversion status

The repository now uses RustD identity through its compiled and packaged core:

- Cargo package and library crate names are `rustd`;
- internal Rust imports use `rustd::...`;
- private C/Rust FFI helpers use `rustd_*` names;
- the installer ships native RustD executable names as the authoritative
  interfaces;
- the supported build surface is native RustD targets;
- Legacy package capabilities, selected compatibility pathnames, and
  compatibility SONAMEs are isolated external boundaries backed by RustD code;
  they are not a second implementation and do not permit foreign init-system
  executables in a certified cutover;
- native C/Fortran objects and the static ABI archive use RustD names and
  `librustd_native.a`;
- manager configuration uses `RUSTD_MANAGER_CONFIG`,
  `RUSTD_MANAGER_DROPIN_DIRS`, and RustD-owned roots;
- the unit loader uses `RUSTD_UNIT_PATH`, RustD control paths, RustD system unit
  directories, and RustD XDG user directories;
- native runtime state is rooted under `/run/rustd`;
- `make install` ships the native unit graph to `/usr/lib/rustd/system`;
- the boot graph includes default, multi-user, basic, sysinit, local-filesystem,
  socket, path, timer, network-readiness, shutdown, and recovery targets plus
  RustD-owned getty templates;
- emergency and rescue modes use RustD-owned console-shell services;
- RustD generators use RustD controls, credentials, runtime state, and vendor
  unit paths;
- `rustbootctl` uses the RustD EFI image path `EFI/RustD/rustd-bootx64.efi`
  while retaining the standards-defined `EFI/BOOT/BOOTX64.EFI` fallback;
- PID 1 terminal transitions are testable without destructive syscalls through
  a recording transition backend;
- `rustctl enable --now` and `disable --now` use bounded job completion waits
  and alternate-root safety.

Remaining work is release hardening, not an internal crate-name migration. The
largest unresolved production boundary is repeated sole-PID1 installed-system
certification on the exact ArachOS image together with Arach Kernel ABI closure
and the paired RustD-Resolved release certificate.

## Supported platform

ArachOS is the current integration and release-certification target. Its final
gate uses Arach Kernel, GRUB, RustD PID 1, RustD-resolved, pacman packages,
ArchISO, and graphical Calamares. Arch Linux and compatible distributions are
also supported build environments, but they do not substitute for the ArachOS
installed-system gate.

## ArachOS integration

ArachOS builds RustD and RustD-resolved from revisions pinned in
`sources.lock`. The Podman build creates the pacman repository and ArchISO
image. Disposable QEMU disks are then used to test BIOS and UEFI installer
boots, installation, cold boot, reboot, shutdown, rescue and emergency modes,
networking, login, DNS, package transactions, udev settling, and service
control. A release remains blocked until the exact installed image passes the
complete campaign with RustD as its only PID 1.

## Language boundaries

| Language | Responsibility |
| --- | --- |
| Rust | PID 1, manager, journal, activation, IPC, unit model, cgroups, CLIs |
| C | narrow Linux ABI boundaries and low-level kernel interfaces |
| Fortran | deterministic scheduling and resource-weight scoring |
| Idris | total unit-state and dependency-ordering model |
| Agda | proof-oriented lifecycle, resource-bound, and ordering invariants |

See `docs/ARCHITECTURE.md` and `docs/COMPATIBILITY.md` for the native boundary
and release contracts.

## Build and test

On Arch Linux, install the build and formal-check dependencies with:

```sh
sudo pacman -S --needed base-devel rust cargo gcc-fortran idris2 agda
```

The manager's minimum supported Rust version is 1.75. The native boundary also
requires a C17 compiler, GNU Fortran with Fortran 2018 support, and `ar`.

```sh
make check-native
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --all-features --locked -- --test-threads=1
cargo build --release --all-features --locked
make check-packaging
make check-formal
make release
```

Stable `rustfmt` is a hard CI gate. Lockfile reproducibility, Rust 1.75 Clippy,
all-target/all-feature tests, release builds, native C/Fortran checks, packaging,
and formal models are authoritative source-tree gates.

`make release` runs the source/build release gate. On a snapshot-backed VM or
other recoverable machine with the candidate installed and RustD actually
running as PID 1, run:

```sh
make certify
```

`make certify` reruns the release gate and executes the live boot certificate.
The certificate requires `/proc/1/exe` to resolve to `rustd`, the native manager
control socket and journal sockets to exist, normal boot targets and
`rustd-journald` to be active, recovery targets to be inactive, and `rustctl` to
return live manager state. A successful normal-process development run cannot
satisfy this gate.

## Native installation contract

The authoritative names and roots are RustD names:

- `/usr/lib/rustd/rustd`
- `/usr/bin/rustctl`
- `/usr/bin/rustjournalctl`
- `/usr/lib/rustd/rustd-journald`
- `/usr/lib/rustd/` for RustD-managed helpers
- `/etc/rustd/` for system configuration
- `/run/rustd/` for runtime state
- `/etc/rustd/system/`, `/run/rustd/system/`, and `/usr/lib/rustd/system/` for
  native system units

The package includes RustD-owned base targets, recovery shells, console/getty
templates, journald, hostname/locale services, boot accounting, random-seed,
time, boot-health, mute-console activation, and debug-breakpoint units. The
package contract rejects shipped RustD units that point at foreign init-system
installation or runtime roots.

## RustD Resolved

The resolver is developed separately as `rustd-resolved`. The native stack uses
`rustd-resolved`, `rustd-resolvectl`, `/run/rustd/resolve`, RustD-owned service
definitions, and the public `io.rustd.Resolve` Varlink namespace.

Compatibility adapters may remain at explicitly tested external protocol
boundaries when existing applications need them. They do not define the native
resolver identity: RustD names, paths, diagnostics, and the native Varlink
transport remain authoritative.

## Production-release gates

A RustD release is judged by native guarantees. Source/build readiness and
installed-system readiness are separate boundaries. A production candidate must
ultimately demonstrate all of the following:

1. boot a clean supported VM as PID 1 repeatedly, including cold boot, reboot,
   shutdown, emergency, rescue, and failed-service paths;
2. reliably reap orphaned children and supervise services under crash loops,
   timeout escalation, signal storms, dependency failures, and resource
   pressure;
3. preserve deterministic dependency transactions and socket/timer/path/mount
   activation under concurrency;
4. pass cgroup-v2, namespace, capability, seccomp, credential, IPC, filesystem,
   privilege-boundary, malformed-input, and resource-exhaustion tests;
5. keep `rustctl` lifecycle commands deterministic and bounded, including
   `enable --now`, `disable --now`, restart, reload, isolate, cancellation, and
   manager reload;
6. integrate `rustd-resolved` through native RustD service/runtime paths and
   survive resolver/network restart and reconfiguration;
7. keep native RustD interfaces authoritative while limiting compatibility
   pathnames, package capabilities, and SONAMEs to measured external
   boundaries implemented by RustD code;
8. reproduce release artifacts from the locked source tree and pass long-running
   soak/fault-injection tests;
9. pass `make certify` on the installed candidate while RustD is PID 1;
10. pass the ArachOS full-VM zero-systemd certificate with zero `systemd*`
    packages, no foreign init-system implementation code in the rebuilt
    initramfs, SELinux enforcing, and the required
    networking/login/DNS/package-management stack operational.

Passing source CI, a package dependency solve, or a compatibility symbol count
alone is deliberately not represented as proof that PID 1 is
production-certified.

## Performance contract

Performance claims require repeatable measurements. Release benchmarking records
cold-boot time, manager startup, unit start/stop/restart latency,
dependency-transaction latency, steady-state memory, CPU wakeups, and
control-plane throughput. Resolver benchmarking records cached and uncached DNS
latency, concurrent-query throughput, transport fallback, DNSSEC overhead, and
p50/p95/p99 tail latency.

Comparative runs may use other stacks as baselines, but RustD's release gate is
an explicit native regression budget using the same hardware or VM image, fixed
workload, warm-up and measured iterations, raw result artifacts, and failure on
material regressions. No release should claim a comparative speed advantage
without benchmark artifacts supporting it.

## License

GNU Lesser General Public License 2.1 or later.
