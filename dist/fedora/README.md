# Fedora RustD Cutover

This directory contains Fedora-specific compatibility and packaging surfaces for
an exclusive RustD installation.

The compatibility entry points are **not systemd implementations**. They exist
so already-built Fedora RPM scriptlets can continue to invoke the conventional
transaction command names while all service-manager actions are executed by
RustD (`rustctl`, `rustd-tmpfiles`, `rustd-sysusers`, `rustd-sysctl`,
`rustd-binfmt`, and `rustudevadm`).

Production cutover remains fail-closed until:

- the RustD `libsystemd.so.0` / `libudev.so.1` compatibility ABI is complete;
- Fedora RPM dependency capabilities are satisfied by RustD-owned libraries;
- the Fedora transaction compatibility certificate passes;
- RustD-Resolved's exact candidate passes its installed and resolver gates;
- exact-stack boot, fault, soak, rollback, suspend/resume, graphical and
  performance evidence passes the release validators.

Third-party unit files installed under Fedora's conventional unit directories
are mirrored into RustD runtime-native unit roots by the transaction frontend;
RustD's authoritative static unit roots remain `/etc/rustd`, `/run/rustd`, and
`/usr/lib/rustd`.
