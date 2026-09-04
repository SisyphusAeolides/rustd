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

Thin packaging and migration assets live outside the portable runtime contract.
The authoritative production adapter is the ArachOS ArchISO package set:

| Family | Adapter location | Release status |
|---|---|---|
| Arch / CachyOS | `ArachOS/packaging/pkgbuild/rustd` and `rustd-resolved` | Production path |
| Fedora / RHEL | `dist/fedora` and compatibility metadata | Legacy compatibility only |
| Debian / Ubuntu | `packaging/debian` compatibility metadata | Legacy compatibility only |

The ArachOS release does not run DNF, RPM, or Debian package transactions.
Legacy adapters remain isolated for downstream interoperability and are not
part of the RustD PID 1 or RustD-resolved production cutover.

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

Exclusive cutover (Tier C) may retain `systemd-libs` until `make check-compat-closure` reports zero missing versioned symbols for the target host profile and the installed-image campaign passes. The compatibility library now uses native bus/JSON/Varlink implementations; symbol presence and source tests still do not replace target-host runtime certification.

## Required gates

- `make check-native check-compat check-packaging`
- `make check-compat-closure REPORT=<host-audit.json>` before promoting `rustd-compat` to Provide/Replace `systemd-libs`
- resolver: `make check-native check-packaging check-nss`
- packaging: `Sisyphus-Repo/scripts/check-side-by-side-packaging.sh`
- exclusive: `scripts/exclusive-cutover-gate.sh --release` only after Tier C evidence

## Compat ABI status (host profile)

The measured compatibility surface is green at source level (`184/184`) and
`make check-compat` exercises the native D-Bus, JSON/Varlink, and journal
implementations. Exclusive Tier C cutover still retains `systemd-libs` until a
host-specific closure report and the complete installed-image runtime campaign
pass.
