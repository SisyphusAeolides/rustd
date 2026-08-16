// SPDX-License-Identifier: LGPL-2.1-or-later
macro_rules! env {
    ("CARGO_BIN_EXE_systemd-notify") => {
        std::env!("CARGO_BIN_EXE_rustd-notify")
    };
}
include!("compat_oracles/rustd_notify.rs");
