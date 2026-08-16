// SPDX-License-Identifier: LGPL-2.1-or-later
macro_rules! env {
    ("CARGO_BIN_EXE_systemd-reply-password") => {
        std::env!("CARGO_BIN_EXE_rustd-reply-password")
    };
}
include!("compat_oracles/rustd_reply_password.rs");
