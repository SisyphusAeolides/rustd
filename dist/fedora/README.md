# Legacy Fedora compatibility adapter

ArachOS is released through its Arch Linux package set, ArchISO profile, and
Calamares installer. Nothing in this directory is part of that release path or
is required to build the ArachOS image.

The Fedora/RHEL files remain as a separately tested compatibility adapter for
downstream users who still need an RPM transaction to hand control to RustD.
They are migration tooling, not a second service manager and not a claim that
the Fedora path is an ArachOS production target.

The compatibility entry points preserve the conventional transaction command
names while all service-manager actions are executed by RustD (`rustctl`,
`rustd-tmpfiles`, `rustd-sysusers`, `rustd-sysctl`, `rustd-binfmt`, and
`rustudevadm`).

This adapter remains fail-closed until its own validation is complete:

- the RustD `libsystemd.so.0` / `libudev.so.1` compatibility ABI and native
  behavioral tests pass;
- package dependency capabilities are satisfied by RustD-owned libraries;
- the transaction compatibility certificate passes;
- RustD-Resolved's exact candidate passes its installed and resolver gates;
- boot, fault, soak, rollback, suspend/resume, graphical, and performance
  evidence passes the adapter's validators.

Third-party unit files are mirrored into RustD's native unit roots by the
transaction frontend. RustD's authoritative roots remain `/etc/rustd`,
`/run/rustd`, and `/usr/lib/rustd`.
