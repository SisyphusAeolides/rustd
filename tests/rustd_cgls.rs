// SPDX-License-Identifier: LGPL-2.1-or-later
macro_rules! env {
    ("CARGO_BIN_EXE_systemd-cgls") => {
        std::env!("CARGO_BIN_EXE_rustd-cgls")
    };
}
include!("compat_oracles/rustd_cgls.rs");
