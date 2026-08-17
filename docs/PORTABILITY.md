# RustD / RustD-Resolved Portability Contract

This document defines what “compatible with any Linux distro and any Linux-capable hardware” means for RustD and RustD-Resolved.

## Portable upstream

These artifacts must remain distro-neutral:

- PID1 / manager runtime under `/run/rustd`
- Native shared libraries: `librustd_{service,journal,device,login,manager}.so.1`
- Preview compatibility shims: `libsystemd.so.0`, `libudev.so.1` (must not claim full `systemd-libs` replacement until host ABI closure is green)
- Resolver runtime under `/run/rustd/resolve`
- NSS module: `libnss_rustd_dns.so.2`
- Environment: `RUSTD_*` (with optional dual-set of classic `NOTIFY_SOCKET` / `LISTEN_*` for third-party clients)

Core source under `src/`, `ffi/`, `libs/`, and `nss/` must not hard-code:

- package managers (`pacman`, `dnf`, `apt`)
- bootloader families beyond optional adapters
- initramfs generators beyond optional adapters
- SELinux/AppArmor policy specifics

## Distro adapters

Thin packaging and migration assets live outside the portable runtime contract:

| Family | Adapter location |
|---|---|
| Arch / CachyOS | `Sisyphus-Repo/rustd`, `Sisyphus-Repo/rustd-resolved` |
| Fedora / RHEL | `packaging/rpm` (planned) |
| Debian / Ubuntu | `packaging/debian` (resolver already has stubs) |

Adapters own:

- package metadata and replacement identities
- initramfs hooks
- bootloader rewrite / rollback
- policy modules
- display-manager presets

## Hardware / architecture matrix

First-class build targets:

1. `x86_64-unknown-linux-gnu`
2. `aarch64-unknown-linux-gnu`

Next:

3. `riscv64gc-unknown-linux-gnu`

Rules:

- no architecture-specific assembly in portable paths without a fallback
- no fixed page-size assumptions beyond `sysconf(_SC_PAGESIZE)`
- endian-sensitive wire formats must use explicit conversions

## Production readiness tiers

| Tier | Promise |
|---|---|
| A | Builds and unit/smoke tests pass on the architecture |
| B | Preview/compat ABI covers the audited host profile (or certified client libraries are retained) |
| C | Exclusive PID1 + resolver ownership boots with reversible rollback |

Exclusive cutover (Tier C) may retain `systemd-libs` until `make check-compat-closure` reports zero missing versioned symbols for the target host profile **and** those symbols are backed by a real native bus/JSON/Varlink implementation (not ENOSYS stubs). Symbol closure with fail-closed stubs is necessary but not sufficient to Provide/Replace `systemd-libs`.

## Required gates

- `make check-native check-compat check-packaging`
- `make check-compat-closure REPORT=<host-audit.json>` before promoting `rustd-compat` to Provide/Replace `systemd-libs`
- resolver: `make check-native check-packaging check-nss`
- packaging: `Sisyphus-Repo/scripts/check-side-by-side-packaging.sh`
- exclusive: `scripts/exclusive-cutover-gate.sh --release` only after Tier C evidence

## Compat ABI status (host profile)

Host closure audit (`check-compat-closure`) is green for the current CachyOS profile with fail-closed `sd_bus`/`sd_json`/`sd_varlink` stubs in `libs/compat/sd_bus_stubs.c`. These stubs return `-ENOSYS`/`NULL` and do **not** implement D-Bus. Exclusive Tier C cutover still retains `systemd-libs` until a real native bus stack replaces the stubs and runtime certification passes.
