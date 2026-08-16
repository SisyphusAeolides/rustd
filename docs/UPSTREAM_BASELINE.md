# Upstream baseline

The compatibility target is the `systemd` implementation in
`systemd/systemd` at commit:

```
de9dbc37ad4aa637e200ac02a0545095997055df
```

That snapshot is the official `v261` release. Compatibility work must be
compared against that exact tree before moving the baseline.

Primary reference surfaces:

- `src/core/`          — PID 1 service manager
- `src/journal/`       — journald and journalctl
- `src/login/`         — logind
- `src/network/`       — networkd
- `src/resolve/`       — resolved
- `src/shared/`        — shared library used across components
- `src/basic/`         — low-level utilities and ABI helpers
- `man/systemd.xml`
- `man/systemctl.xml`
- `man/journalctl.xml`
- `man/org.freedesktop.systemd1.xml`
- `test/units/`
