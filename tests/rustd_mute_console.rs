// SPDX-License-Identifier: LGPL-2.1-or-later
macro_rules! env {
    ("CARGO_BIN_EXE_systemd-mute-console") => {
        std::env!("CARGO_BIN_EXE_rustd-mute-console")
    };
}
include!("compat_oracles/rustd_mute_console.rs");
