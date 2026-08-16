// SPDX-License-Identifier: LGPL-2.1-or-later
macro_rules! env {
    ("CARGO_BIN_EXE_systemd-detect-virt") => {
        std::env!("CARGO_BIN_EXE_rustd-detect-virt")
    };
}
include!("compat_oracles/rustd_detect_virt.rs");
