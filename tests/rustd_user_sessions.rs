// SPDX-License-Identifier: LGPL-2.1-or-later
macro_rules! env {
    ("CARGO_BIN_EXE_systemd-user-sessions") => {
        std::env!("CARGO_BIN_EXE_rustd-user-sessions")
    };
}
include!("compat_oracles/rustd_user_sessions.rs");
