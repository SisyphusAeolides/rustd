// SPDX-License-Identifier: LGPL-2.1-or-later
macro_rules! env {
    ("CARGO_BIN_EXE_systemd-delta") => {
        std::env!("CARGO_BIN_EXE_rustd-delta")
    };
}
include!("compat_oracles/rustd_delta.rs");
