# Executable surfaces

RustD publishes two executable name sets from the same source implementations.

The native surface contains 83 RustD names, including `rustd`, `rustctl`,
`rustjournalctl`, and the `rustd-*` helper programs. Native libexec programs are
installed under `/usr/lib/rustd`; native public programs are installed under
`/usr/bin`.

The compatibility surface contains 78 systemd v261 names, including `systemd`,
`systemctl`, `journalctl`, and the corresponding `systemd-*` helpers. Public
compatibility names are relative symbolic links to their RustD-native twins.
Compatibility libexec names are installed under `/usr/lib/systemd` as relative
symbolic links to `/usr/lib/rustd`.

`Cargo.toml` declares both names so release builds prove that every entry point
is buildable. `scripts/executable_contract.py` is the single inventory and
mapping source used by the package validator and staging installer.

Providing the complete declared name set does not by itself establish drop-in
parity. Replacement remains prohibited until the source-bound release
certificate passes every behavioral, boot, security, D-Bus, journal, command
output, installation, and rollback gate against the pinned systemd v261
baseline.
