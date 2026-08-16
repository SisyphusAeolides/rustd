// SPDX-License-Identifier: LGPL-2.1-or-later
macro_rules! env {
    ("CARGO_BIN_EXE_systemd-journald") => {
        std::env!("CARGO_BIN_EXE_rustd-journald")
    };
    ("CARGO_BIN_EXE_journalctl") => {
        std::env!("CARGO_BIN_EXE_rustjournalctl")
    };
}
include!("compat_oracles/rustd_journald_daemon.rs");
