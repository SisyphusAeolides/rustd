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

> **Safety status:** the source/build gates are extensive, but PID 1 production
> certification still requires repeated installed-system boot, reboot, shutdown,
> rescue, emergency, re-exec, crash/fault, recovery, and Fedora zero-systemd
> cutover campaigns. Until the installed-system gates have passed for a release
> candidate, keep a known-good recovery path and validate RustD in a
> snapshot-backed VM or equivalent recoverable environment before making it the
> only boot path.

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
- Fedora compatibility RPM capabilities, selected legacy executable pathnames,
  and compatibility SONAMEs are isolated external boundaries backed by RustD
  code; they are not a second implementation and do not permit systemd RPMs or
  systemd executable code in a certified cutover;
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
certification on the exact Fedora cutover image together with final ABI closure
and the paired RustD-Resolved release certificate.

## Supported platform

Fedora 44 is the current zero-systemd cutover certification target. The release
gate uses the official Fedora Cloud base image and must prove that the machine
continues to boot and operate after the Fedora systemd package stack is removed.
Arch Linux and compatible Arch-based distributions remain supported build and
native-install targets, but they do not substitute for the Fedora cutover gate.

## Fedora zero-systemd cutover

The Fedora target is deliberately stronger than an installroot dependency
solver. A release candidate is not Fedora-certified until
`certification/fedora-full-vm-latest.txt` records `status=pass` for the exact
RustD SHA and its pinned RustD-Resolved SHA.

The Fedora campaign performs a destructive conversion of a disposable Fedora
44 VM and requires all of the following:

- build RustD, RustD-Resolved, compatibility libraries, Fedora transaction
  frontends, and SELinux policy from one pinned source pair;
- bind the replacement RPM capabilities to the exact Fedora `systemd`,
  `systemd-libs`, and `systemd-udev` EVR measured in the build environment;
- stage only `rustd-cutover-tools` and `rustd-resolved-nss` first, with no
  `--allowerasing`, and prove that no pre-existing package was removed or
  replaced while systemd remains installed and continues to own PID 1;
- migrate authselect-managed PAM and NSS configuration while the original stack
  is still present, preserving the selected profile/features and creating a
  rollback backup;
- require the final `rustd-fedora-compat` RPM transaction to repeat the PAM,
  NSS, authselect, and file checks in a fail-closed `%pretrans` guard before it
  is allowed to erase the old stack;
- reject unsupported `systemd-homed` and `pam_systemd_loadkey` configurations
  before the destructive phase rather than silently dropping their semantics;
- remove every installed RPM whose name is `systemd` or begins `systemd-` and
  pass `dnf check` afterward;
- require `/usr/sbin/init` and the legacy Fedora transaction entry points to be
  owned by `rustd-fedora-compat`, compatibility SONAMEs to be owned by
  `rustd-compat-libs`, the PAM migration helper and module to be owned by
  `rustd-cutover-tools`, and the DNS NSS module to be owned by
  `rustd-resolved-nss`;
- require `/usr/sbin/init` to resolve to `/usr/lib/rustd/rustd` and the legacy
  udev daemon pathname to resolve to RustD's native `rustd-udevd`;
- rebuild the Fedora initramfs without systemd implementation modules or
  executables, while allowing only explicitly tested compatibility pathnames
  that resolve to RustD code;
- cold-boot the converted filesystem three times with RustD as PID 1;
- keep SELinux enforcing and prove D-Bus, NetworkManager, OpenSSH,
  RustD-Resolved, NSS/DNS, DNF, udev settling, service control, and RustD
  poweroff remain functional.

The cutover helper is installed as `/usr/sbin/rustd-fedora-cutover` by the
nonconflicting `rustd-cutover-tools` package. It is a fail-closed migration tool
for the disposable certification machine and for administrators who deliberately
choose the same conversion path; it is not a reason to perform an unverified
in-place conversion on an irreplaceable host.

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
   pathnames, RPM capabilities, and SONAMEs to measured external boundaries
   implemented by RustD code;
8. reproduce release artifacts from the locked source tree and pass long-running
   soak/fault-injection tests;
9. pass `make certify` on the installed candidate while RustD is PID 1;
10. pass the Fedora 44 full-VM zero-systemd certificate with zero `systemd*`
    RPMs, no systemd implementation code in the rebuilt initramfs, SELinux
    enforcing, and the required networking/login/DNS/package-management stack
    operational.

Passing source CI, an RPM dependency solve, or a compatibility symbol count
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
