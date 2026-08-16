// SPDX-License-Identifier: LGPL-2.1-or-later

use std::process::{Command, Output};

fn run(binary: &str, args: &[&str]) -> Output {
    Command::new(binary)
        .args(args)
        .output()
        .expect("run escape CLI")
}

fn pinned_host_available() -> bool {
    let output = run("/usr/bin/systemd-escape", &["--version"]);
    output.status.success() && output.stdout.starts_with(b"systemd 261 (261.2-1-arch)\n")
}

#[test]
fn representative_v261_outputs_match_host() {
    let candidate = env!("CARGO_BIN_EXE_systemd-escape");
    let cases: &[&[&str]] = &[
        &["foo/bar", ".foo", "foo-bar", "föo"],
        &["--path", "/", "/foo//bar/"],
        &["--unescape", "foo-bar", "foo\\x2dbar"],
        &["--unescape", "--path", "foo-bar", "-"],
        &["--mangle", "/dev/sda", "/srv/data", "foo", "foo bar"],
        &["--suffix=service", "hello"],
        &["--template=foo@.service", "hello/world"],
        &["--unescape", "--instance", "foo@bar\\x2dbaz.service"],
    ];

    for args in cases {
        let ours = run(candidate, args);
        assert!(ours.status.success(), "args={args:?}");
        assert!(ours.stderr.is_empty(), "args={args:?}");
        if pinned_host_available() {
            let host = run("/usr/bin/systemd-escape", args);
            assert_eq!(ours.status.code(), host.status.code(), "args={args:?}");
            assert_eq!(ours.stdout, host.stdout, "args={args:?}");
            assert_eq!(ours.stderr, host.stderr, "args={args:?}");
        }
    }
}

#[test]
fn representative_v261_errors_match_host() {
    let candidate = env!("CARGO_BIN_EXE_systemd-escape");
    let cases: &[(&[&str], &str)] = &[
        (&[], "Not enough arguments.\n"),
        (
            &["--path", "/foo/../bar"],
            "Input '/foo/../bar' is not a normalized file system path, failed to escape.\n",
        ),
        (
            &["--unescape", "--path", "foo/"],
            "Failed to unescape string: Invalid argument\n",
        ),
        (
            &["--suffix=invalid", "foo"],
            "Invalid unit suffix type \"invalid\".\n",
        ),
        (
            &["--suffix=service", "--template=foo@.service", "foo"],
            "--suffix= and --template= may not be combined.\n",
        ),
    ];

    for (args, expected_error) in cases {
        let ours = run(candidate, args);
        assert!(!ours.status.success(), "args={args:?}");
        assert!(ours.stdout.is_empty(), "args={args:?}");
        assert_eq!(ours.stderr, expected_error.as_bytes(), "args={args:?}");
        if pinned_host_available() {
            let host = run("/usr/bin/systemd-escape", args);
            assert_eq!(ours.status.code(), host.status.code(), "args={args:?}");
            assert_eq!(ours.stdout, host.stdout, "args={args:?}");
            assert_eq!(ours.stderr, host.stderr, "args={args:?}");
        }
    }
}
