// SPDX-License-Identifier: LGPL-2.1-or-later

use std::process::{Command, Output};

fn fixture(count: &str, log_level: Option<&str>, log_target: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rustd-boot-check-no-failures"));
    command
        .env("LC_ALL", "C")
        .env("RUSTD_BOOT_CHECK_FAILED_UNITS", count);
    if let Some(level) = log_level {
        command.env("RUSTD_LOG_LEVEL", level);
    } else {
        command.env_remove("RUSTD_LOG_LEVEL");
    }
    if let Some(target) = log_target {
        command.env("RUSTD_LOG_TARGET", target);
    } else {
        command.env_remove("RUSTD_LOG_TARGET");
    }
    command.output().expect("execute RustD boot health check")
}

#[test]
fn native_help_and_version_identify_rustd() {
    let binary = env!("CARGO_BIN_EXE_rustd-boot-check-no-failures");
    let help = Command::new(binary).arg("--help").output().unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).starts_with("rustd-boot-check-no-failures"));

    let version = Command::new(binary).arg("--version").output().unwrap();
    assert!(version.status.success());
    assert_eq!(
        String::from_utf8_lossy(&version.stdout),
        "rustd-boot-check-no-failures 0.1.0\n"
    );
}

#[test]
fn deterministic_failed_count_exit_and_logging_contract() {
    for (count, level, target, code, stderr) in [
        ("0", None, None, 0, "Health check: no failed units.\n"),
        ("1", None, None, 1, "Health check: 1 units have failed.\n"),
        ("17", None, None, 1, "Health check: 17 units have failed.\n"),
        ("0", Some("notice"), None, 0, ""),
        (
            "1",
            Some("notice"),
            None,
            1,
            "Health check: 1 units have failed.\n",
        ),
        ("1", Some("warning"), None, 1, ""),
        ("0", None, Some("null"), 0, ""),
    ] {
        let output = fixture(count, level, target);
        assert_eq!(output.status.code(), Some(code), "count={count}");
        assert!(output.stdout.is_empty(), "count={count}");
        assert_eq!(output.stderr, stderr.as_bytes(), "count={count}");
    }
}
