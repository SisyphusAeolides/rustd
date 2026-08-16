// SPDX-License-Identifier: LGPL-2.1-or-later
macro_rules! env {
    ("CARGO_BIN_EXE_systemd-xdg-autostart-condition") => {
        std::env!("CARGO_BIN_EXE_rustd-xdg-autostart-condition")
    };
}
include!("compat_oracles/rustd_xdg_autostart_condition.rs");
