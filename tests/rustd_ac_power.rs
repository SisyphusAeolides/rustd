// SPDX-License-Identifier: LGPL-2.1-or-later
macro_rules! env {
    ("CARGO_BIN_EXE_systemd-ac-power") => {
        std::env!("CARGO_BIN_EXE_rustd-ac-power")
    };
}
include!("compat_oracles/rustd_ac_power.rs");
