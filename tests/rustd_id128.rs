// SPDX-License-Identifier: LGPL-2.1-or-later
macro_rules! env {
    ("CARGO_BIN_EXE_systemd-id128") => {
        std::env!("CARGO_BIN_EXE_rustd-id128")
    };
}
include!("compat_oracles/rustd_id128.rs");
