// SPDX-License-Identifier: LGPL-2.1-or-later
macro_rules! env {
    ("CARGO_BIN_EXE_systemd-update-done") => {
        std::env!("CARGO_BIN_EXE_rustd-update-done")
    };
}
include!("compat_oracles/rustd_update_done.rs");
