# RPM/DNF RustD Cutover

This directory contains the RPM/DNF compatibility and packaging surfaces used
by the exclusive ArachOS RustD installation. The source path is retained for
the existing compatibility build layout.

The compatibility entry points are **not systemd implementations**. They exist
so already-built bootstrap RPM scriptlets can continue to invoke the conventional
transaction command names while all service-manager actions are executed by
RustD (`rustctl`, `rustd-tmpfiles`, `rustd-sysusers`, `rustd-sysctl`,
`rustd-binfmt`, and `rustudevadm`).

Production cutover remains fail-closed until the ArachOS release gates pass:

- the RustD `libsystemd.so.0` / `libudev.so.1` compatibility ABI and its native
  behavioral tests pass;
- RPM dependency capabilities are satisfied by RustD-owned libraries;
- the RPM transaction compatibility certificate passes;
- RustD-Resolved's exact candidate passes its installed and resolver gates;
- exact-stack boot, fault, soak, rollback, suspend/resume, graphical and
  performance evidence passes the release validators.

Third-party unit files installed under the conventional unit directories
are mirrored into RustD runtime-native unit roots by the transaction frontend;
RustD's authoritative static unit roots remain `/etc/rustd`, `/run/rustd`, and
`/usr/lib/rustd`.
