// SPDX-License-Identifier: LGPL-2.1-or-later
macro_rules! env {
    ("CARGO_BIN_EXE_systemd-ssh-issue") => {
        std::env!("CARGO_BIN_EXE_rustd-ssh-issue")
    };
}
include!("compat_oracles/rustd_ssh_issue.rs");
