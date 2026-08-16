# Security

This project inherits the security model of the upstream systemd v261 baseline
at `de9dbc37ad4aa637e200ac02a0545095997055df`.

## Threat model scope

- PID 1 runs as root; all privilege separation boundaries match upstream.
- Per-unit sandboxing directives (`PrivateTmp=`, `CapabilityBoundingSet=`,
  `SystemCallFilter=`, etc.) must match upstream semantics exactly before
  the project claims parity.
- D-Bus method authorization is mediated by polkit; the authorization policy
  must match the pinned upstream baseline.

## Reporting

Security issues should be reported privately before public disclosure.
Follow the same coordinated disclosure timeline as upstream systemd.

## Known deviations

No security-relevant behavior is implemented yet. All items in the security
section of `docs/COMPATIBILITY.md` are unchecked. Do not deploy in any
security-sensitive context.
