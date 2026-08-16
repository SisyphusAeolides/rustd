// SPDX-License-Identifier: LGPL-2.1-or-later
macro_rules! env {
    ("CARGO_BIN_EXE_systemd-update-utmp") => {
        std::env!("CARGO_BIN_EXE_rustd-update-utmp")
    };
}
include!("compat_oracles/rustd_update_utmp.rs");
