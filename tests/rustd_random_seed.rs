// SPDX-License-Identifier: LGPL-2.1-or-later
macro_rules! env {
    ("CARGO_BIN_EXE_systemd-random-seed") => {
        std::env!("CARGO_BIN_EXE_rustd-random-seed")
    };
}
include!("compat_oracles/rustd_random_seed.rs");
