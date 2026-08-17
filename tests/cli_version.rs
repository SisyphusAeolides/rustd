// SPDX-License-Identifier: LGPL-2.1-or-later

use std::process::Command;

const VERSION_OUTPUT: &str = concat!("RustD ", env!("CARGO_PKG_VERSION"), "\n");

fn assert_version(binary: &str, extra_arg: Option<&str>) {
    let mut command = Command::new(binary);
    command.arg("--version");
    if let Some(arg) = extra_arg {
        command.arg(arg);
    }
    let output = command.output().expect("run RustD CLI version command");

    assert!(output.status.success());
    assert_eq!(output.stdout, VERSION_OUTPUT.as_bytes());
    assert_eq!(output.stderr, [] as [u8; 0]);
}

#[test]
fn native_version_output_is_rustd() {
    assert_version(env!("CARGO_BIN_EXE_rustd"), None);
    assert_version(env!("CARGO_BIN_EXE_rustctl"), None);
    assert_version(env!("CARGO_BIN_EXE_rustjournalctl"), None);
}

#[test]
fn version_takes_precedence_over_other_arguments() {
    assert_version(env!("CARGO_BIN_EXE_rustd"), Some("--user"));
    assert_version(env!("CARGO_BIN_EXE_rustctl"), Some("list-units"));
    assert_version(env!("CARGO_BIN_EXE_rustjournalctl"), Some("-n"));
}
