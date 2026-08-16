// SPDX-License-Identifier: LGPL-2.1-or-later

macro_rules! env {
    ("CARGO_BIN_EXE_systemd-vpick") => {{
        match option_env!("CARGO_BIN_EXE_rustd-vpick") {
            Some(path) => path,
            None => panic!("CARGO_BIN_EXE_rustd-vpick is not set"),
        }
    }};
}

include!("compat_oracles/rustd_vpick.rs");
