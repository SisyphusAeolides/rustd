// SPDX-License-Identifier: LGPL-2.1-or-later
macro_rules! env {
    ("CARGO_BIN_EXE_systemd-path") => {
        std::env!("CARGO_BIN_EXE_rustd-path")
    };
}
include!("compat_oracles/rustd_path.rs");
