// SPDX-License-Identifier: LGPL-2.1-or-later

use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{symlink, MetadataExt};
use std::path::Path;
use std::process::{Command, Output};

const HOST: &str = "/usr/lib/systemd/systemd-ssh-issue";

fn host_is_pinned_v261() -> bool {
    Path::new(HOST).is_file()
        && Command::new(HOST)
            .arg("--version")
            .output()
            .is_ok_and(|output| output.stdout.starts_with(b"systemd 261 "))
}

fn command(binary: &str) -> Command {
    let mut command = Command::new(binary);
    command
        .env("LC_ALL", "C")
        .env("SYSTEMD_COLORS", "0")
        .env("SYSTEMD_URLIFY", "0")
        .env("SYSTEMD_LOG_COLOR", "0")
        .env("SYSTEMD_LOG_TARGET", "console")
        .env("SYSTEMD_LOG_LEVEL", "err");
    command
}

fn run(binary: &str, arguments: &[OsString]) -> Output {
    command(binary)
        .args(arguments)
        .output()
        .expect("run systemd-ssh-issue")
}

fn assert_same(host: &Output, candidate: &Output, context: &str) {
    assert_eq!(
        candidate.status.code(),
        host.status.code(),
        "status: {context}"
    );
    assert_eq!(candidate.stdout, host.stdout, "stdout: {context}");
    assert_eq!(candidate.stderr, host.stderr, "stderr: {context}");
}

#[test]
#[allow(clippy::too_many_lines)]
fn cli_help_and_logging_surface_matches_v261() {
    if !host_is_pinned_v261() {
        eprintln!("skipping live comparison: systemd-ssh-issue is not v261");
        return;
    }
    let candidate = env!("CARGO_BIN_EXE_systemd-ssh-issue");
    let cases: Vec<Vec<OsString>> = vec![
        vec![],
        vec!["-h".into()],
        vec!["--help".into()],
        vec!["--version".into()],
        vec!["--ver".into()],
        vec!["--vers=x".into()],
        vec!["--".into()],
        vec!["-".into()],
        vec!["make-vsock".into()],
        vec!["rm-vsock".into()],
        vec!["bogus".into()],
        vec!["bogus".into(), "extra".into()],
        vec!["make-vsock".into(), "extra".into()],
        vec!["--make-vsock".into()],
        vec!["--rm-vsock".into()],
        vec!["--make-vsock".into(), "make-vsock".into()],
        vec!["--issue-path=-".into(), "rm-vsock".into()],
        vec!["--issue-path=".into(), "rm-vsock".into()],
        vec!["--issue-path".into(), "-".into(), "rm-vsock".into()],
        vec!["--issue-path".into()],
        vec!["--issue".into()],
        vec!["--issue=relative".into(), "rm-vsock".into()],
        vec!["--make".into()],
        vec!["--rm".into()],
        vec!["--m".into()],
        vec!["--r".into()],
        vec!["-x".into()],
        vec!["-hh".into()],
        vec!["--help=x".into()],
        vec!["rm-vsock".into(), "--issue-path=-".into()],
        vec!["".into()],
        vec!["m".into()],
        vec!["make-vsoc".into()],
        vec!["make-vsockk".into()],
        vec!["x".into()],
        vec!["--make-vsock".into(), "--rm-vsock".into()],
        vec!["--version".into(), "bogus".into()],
        vec!["bogus".into(), "--help".into()],
        vec!["--i=x".into(), "rm-vsock".into()],
        vec!["--ma=x".into()],
        vec!["--bad=x".into()],
        vec!["--=x".into()],
        vec![OsString::from_vec(vec![b'-', b'-', 0xff])],
        vec![OsString::from_vec(vec![0xff])],
    ];
    for arguments in cases {
        assert_same(
            &run(HOST, &arguments),
            &run(candidate, &arguments),
            &format!("CLI {arguments:?}"),
        );
    }

    for target in [
        "console",
        "console-prefixed",
        "null",
        "kmsg",
        "journal",
        "journal-or-kmsg",
        "invalid",
    ] {
        for level in [
            "emerg",
            "err",
            "notice",
            "debug",
            "bogus",
            "console:emerg",
            "kmsg:emerg",
            "console-prefixed:emerg",
        ] {
            let mut host = command(HOST);
            let mut ours = command(candidate);
            for process in [&mut host, &mut ours] {
                process
                    .env("SYSTEMD_LOG_TARGET", target)
                    .env("SYSTEMD_LOG_LEVEL", level)
                    .args(["--issue-path=-", "rm-vsock"]);
            }
            assert_same(
                &host.output().expect("run host logging case"),
                &ours.output().expect("run candidate logging case"),
                &format!("logging target={target} level={level}"),
            );
        }
    }

    for (colors, urlify, no_color) in [
        ("1", "0", None),
        ("0", "1", None),
        ("1", "1", None),
        ("1", "1", Some("1")),
        ("bogus", "bogus", None),
    ] {
        let mut host = command(HOST);
        let mut ours = command(candidate);
        for process in [&mut host, &mut ours] {
            process
                .env("SYSTEMD_COLORS", colors)
                .env("SYSTEMD_URLIFY", urlify)
                .env_remove("NO_COLOR")
                .arg("--help");
            if let Some(value) = no_color {
                process.env("NO_COLOR", value);
            }
        }
        assert_same(
            &host.output().expect("run host help case"),
            &ours.output().expect("run candidate help case"),
            &format!("help colors={colors} urlify={urlify} no_color={no_color:?}"),
        );
    }
}

fn run_debug(binary: &str, arguments: &[OsString], directory: Option<&Path>) -> Output {
    let mut process = command(binary);
    process.env("SYSTEMD_LOG_LEVEL", "debug").args(arguments);
    if let Some(directory) = directory {
        process.current_dir(directory);
    }
    process.output().expect("run debug filesystem case")
}

#[test]
fn removal_and_path_normalization_match_v261() {
    if !host_is_pinned_v261() {
        eprintln!("skipping live comparison: systemd-ssh-issue is not v261");
        return;
    }
    let candidate = env!("CARGO_BIN_EXE_systemd-ssh-issue");
    let fixture = tempfile::tempdir().expect("create removal fixture");
    fs::create_dir(fixture.path().join("foo")).expect("create foo directory");
    fs::create_dir(fixture.path().join("bar")).expect("create bar directory");

    for (arguments, directory) in [
        (
            vec![
                OsString::from(format!(
                    "--issue-path={}",
                    fixture.path().join("missing").display()
                )),
                OsString::from("rm-vsock"),
            ],
            None,
        ),
        (
            vec![
                OsString::from(format!(
                    "--issue-path={}",
                    fixture.path().join("bar").display()
                )),
                OsString::from("rm-vsock"),
            ],
            None,
        ),
        (
            vec![
                OsString::from("--issue-path=foo//.././bar"),
                OsString::from("rm-vsock"),
            ],
            Some(fixture.path()),
        ),
        (
            vec![
                OsString::from("--issue-path=./bar"),
                OsString::from("rm-vsock"),
            ],
            Some(fixture.path()),
        ),
    ] {
        assert_same(
            &run_debug(HOST, &arguments, directory),
            &run_debug(candidate, &arguments, directory),
            &format!("filesystem {arguments:?}"),
        );
    }

    let target = fixture.path().join("target");
    fs::write(&target, b"target").expect("write symlink target");
    for symlink_case in [false, true] {
        let path = fixture.path().join(if symlink_case {
            "remove-symlink"
        } else {
            "remove-file"
        });
        let create = || {
            if symlink_case {
                symlink(&target, &path).expect("create removal symlink");
            } else {
                fs::write(&path, b"remove").expect("create removal file");
            }
        };
        let arguments = vec![
            OsString::from(format!("--issue-path={}", path.display())),
            OsString::from("rm-vsock"),
        ];
        create();
        let host = run_debug(HOST, &arguments, None);
        assert!(!path.exists() && !path.is_symlink());
        create();
        let ours = run_debug(candidate, &arguments, None);
        assert!(!path.exists() && !path.is_symlink());
        assert_same(&host, &ours, "existing issue removal");
        assert_eq!(fs::read(&target).expect("read symlink target"), b"target");
    }
}

#[test]
fn live_vsock_generation_branch_matches_v261() {
    if !host_is_pinned_v261() {
        eprintln!("skipping live comparison: systemd-ssh-issue is not v261");
        return;
    }
    let candidate = env!("CARGO_BIN_EXE_systemd-ssh-issue");
    let stdout_arguments = [
        OsString::from("--issue-path=-"),
        OsString::from("make-vsock"),
    ];
    assert_same(
        &run(HOST, &stdout_arguments),
        &run(candidate, &stdout_arguments),
        "live VSOCK stdout generation or non-VM skip",
    );

    let fixture = tempfile::tempdir().expect("create generation fixture");
    let path = fixture.path().join("nested/issue");
    let arguments = [
        OsString::from(format!("--issue-path={}", path.display())),
        OsString::from("make-vsock"),
    ];
    let host = run(HOST, &arguments);
    let host_state = path.exists().then(|| {
        (
            fs::read(&path).expect("read host issue"),
            fs::metadata(&path).expect("stat host issue").mode() & 0o7777,
        )
    });
    if path.exists() {
        fs::remove_file(&path).expect("remove host issue fixture");
    }
    let ours = run(candidate, &arguments);
    let our_state = path.exists().then(|| {
        (
            fs::read(&path).expect("read candidate issue"),
            fs::metadata(&path).expect("stat candidate issue").mode() & 0o7777,
        )
    });
    assert_same(&host, &ours, "live VSOCK file generation or non-VM skip");
    assert_eq!(our_state, host_state, "live VSOCK issue contents and mode");
}
