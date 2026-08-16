// SPDX-License-Identifier: LGPL-2.1-or-later
macro_rules! env {
    ("CARGO_BIN_EXE_systemd-battery-check") => {
        std::env!("CARGO_BIN_EXE_rustd-battery-check")
    };
}
include!("compat_oracles/rustd_battery_check.rs");
