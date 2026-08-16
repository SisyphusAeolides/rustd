// SPDX-License-Identifier: LGPL-2.1-or-later
macro_rules! env {
    ("CARGO_BIN_EXE_systemd-escape") => {
        std::env!("CARGO_BIN_EXE_rustd-escape")
    };
}
include!("compat_oracles/rustd_escape.rs");
