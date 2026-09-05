# Executable surfaces

RustD publishes one native executable surface from the RustD source tree. The
surface currently contains 110 names, including `rustd`, `rustctl`,
`rustjournalctl`, and the `rustd-*` helper programs. Native libexec programs are
installed under `/usr/lib/rustd`; native public programs are installed under
`/usr/bin`.

Arch package transactions also need a small compatibility entry point at
`/usr/bin/systemctl`. It is a RustD-owned shell frontend that delegates to the
native `rustctl` client for unit-file operations such as `enable`, `disable`,
`reenable`, `mask`, and `is-enabled`. It is not a second systemd executable
surface and does not provide a systemd daemon or systemd ABI.

The Fedora compatibility files under `dist/fedora/` remain separate migration
artifacts for the legacy Fedora packaging path. They are not installed by the
Arch packages or the ArachOS image.

`Cargo.toml` declares every native target so release builds prove that each
entry point is buildable. `scripts/executable_contract.py` is the single
inventory source used by the package validator and staging installer.

Providing the complete declared name set does not by itself establish drop-in
parity. Replacement remains prohibited until the source-bound release
certificate passes every behavioral, boot, security, D-Bus, journal, command
output, installation, and rollback gate against the pinned systemd v261
baseline.
