# RustD native environment contract

RustD-owned runtime and test controls use the `RUSTD_*` environment namespace.
These variables configure RustD components directly; they are not compatibility
aliases for another init system.

The manager control socket defaults to `/run/rustd/ctl.sock`. User managers use
an XDG runtime path beneath `rustd/ctl.sock`. `RUSTD_CONTROL_SOCKET` may override
that path for user managers, containers, integration tests, and other isolated
environments.

RustD's private native helpers and test harnesses likewise use `RUSTD_*` names
for RustD-specific overrides such as notification endpoints, cgroup roots, and
fixture paths. Installed production defaults remain rooted in RustD-owned paths
under `/etc/rustd`, `/run/rustd`, and `/usr/lib/rustd`.

Established application-facing environment variables are separate from this
private namespace. For example, when RustD implements an existing notification
protocol for service compatibility, the protocol-defined variables presented to
the application are part of that external interoperability boundary. They do
not rename or control RustD's internal implementation.

A source-tree change must not introduce `SYSTEMD_RS_*` as a RustD private
configuration namespace. New RustD-owned controls belong under `RUSTD_*` and
should be covered by the component's unit or integration tests.
