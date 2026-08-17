// SPDX-License-Identifier: LGPL-2.1-or-later

use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, UNIX_EPOCH};

const HOST: &str = "/usr/lib/systemd/systemd-update-done";
const EXPECTED_NANOS: u64 = 1_700_000_000_123_456_789;

fn live_oracle_enabled() -> bool {
    // Exclusive RustD keeps native branding/IPC. Opt into live systemd byte-parity
    // oracles only when explicitly certifying against a pinned host binary.
    host_is_pinned_v261() && std::env::var_os("RUSTD_LIVE_SYSTEMD_ORACLE").is_some()
}

fn host_is_pinned_v261() -> bool {
    Path::new(HOST).is_file()
        && Command::new(HOST)
            .arg("--version")
            .output()
            .is_ok_and(|output| output.stdout.starts_with(b"systemd 261 "))
}

fn run(binary: &str, arguments: &[&OsStr]) -> Output {
    Command::new(binary)
        .args(arguments)
        .env("LC_ALL", "C")
        .env("SYSTEMD_COLORS", "0")
        .output()
        .expect("execute systemd-update-done")
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

fn set_usr_timestamp(path: &Path) {
    let timestamp = UNIX_EPOCH + Duration::from_nanos(EXPECTED_NANOS);
    let file = fs::File::open(path).expect("open usr directory");
    file.set_times(
        fs::FileTimes::new()
            .set_accessed(timestamp)
            .set_modified(timestamp),
    )
    .expect("set usr timestamp");
}

fn prepare_root(parent: &Path, with_directories: bool) -> PathBuf {
    let root = parent.join("root");
    fs::create_dir_all(root.join("usr")).expect("create usr fixture");
    if with_directories {
        fs::create_dir(root.join("etc")).expect("create etc fixture");
        fs::create_dir(root.join("var")).expect("create var fixture");
    }
    set_usr_timestamp(&root.join("usr"));
    root
}

fn marker_snapshot(root: &Path, directory: &str) -> (Vec<u8>, u32, i64, i64) {
    let path = root.join(directory).join(".updated");
    let metadata = fs::metadata(&path).expect("stat marker");
    (
        fs::read(path).expect("read marker"),
        metadata.permissions().mode() & 0o777,
        metadata.mtime(),
        metadata.mtime_nsec(),
    )
}

#[test]
fn complete_option_help_version_and_error_surface_matches_live_v261() {
    if !live_oracle_enabled() {
        eprintln!("skipping live comparison: systemd package is not v261");
        return;
    }
    let candidate = env!("CARGO_BIN_EXE_systemd-update-done");
    let cases: Vec<Vec<OsString>> = vec![
        vec![OsString::from("--help")],
        vec![OsString::from("--version")],
        vec![OsString::from("--h")],
        vec![OsString::from("--v")],
        vec![OsString::from("-h")],
        vec![OsString::from("-hx")],
        vec![OsString::from("-x")],
        vec![OsString::from("--help=x")],
        vec![OsString::from("--version=x")],
        vec![OsString::from("--root")],
        vec![OsString::from("--bogus")],
        vec![OsString::from("--=x")],
        vec![OsString::from("operand")],
        vec![OsString::from("--"), OsString::from("--help")],
        vec![OsString::from_vec(vec![b'-', b'-', 0xff])],
        vec![OsString::from_vec(vec![0xff])],
    ];
    for arguments in cases {
        let references: Vec<&OsStr> = arguments.iter().map(OsString::as_os_str).collect();
        assert_same(
            &run(HOST, &references),
            &run(candidate, &references),
            &format!("{arguments:?}"),
        );
    }
}

#[test]
fn isolated_atomic_timestamp_content_creation_and_symlink_contract_matches_v261() {
    if !live_oracle_enabled() {
        eprintln!("skipping live comparison: systemd package is not v261");
        return;
    }
    let candidate = env!("CARGO_BIN_EXE_systemd-update-done");

    for with_directories in [true, false] {
        let host_temp = tempfile::tempdir().expect("create host root parent");
        let ours_temp = tempfile::tempdir().expect("create candidate root parent");
        let host_root = prepare_root(host_temp.path(), with_directories);
        let ours_root = prepare_root(ours_temp.path(), with_directories);
        let host = run(HOST, &[OsStr::new("--root"), host_root.as_os_str()]);
        let ours = run(candidate, &[OsStr::new("--root"), ours_root.as_os_str()]);
        assert_eq!(host.status.code(), Some(0));
        assert_eq!(ours.status.code(), Some(0));
        assert!(host.stdout.is_empty() && host.stderr.is_empty());
        assert!(ours.stdout.is_empty() && ours.stderr.is_empty());
        for directory in ["etc", "var"] {
            assert_eq!(
                marker_snapshot(&ours_root, directory),
                marker_snapshot(&host_root, directory),
                "marker snapshot for {directory}"
            );
            let snapshot = marker_snapshot(&ours_root, directory);
            assert_eq!(snapshot.1, 0o644);
            assert_eq!(snapshot.2, 1_700_000_000);
            assert_eq!(snapshot.3, 123_456_789);
        }
    }

    for binary in [HOST, candidate] {
        let temporary = tempfile::tempdir().expect("create symlink fixture");
        let root = prepare_root(temporary.path(), false);
        fs::create_dir(root.join("real-etc")).expect("create real etc");
        symlink("real-etc", root.join("etc")).expect("link etc within root");
        fs::create_dir(root.join("var")).expect("create var");
        let protected = root.join("protected");
        fs::write(&protected, b"preserve\n").expect("seed protected file");
        symlink(&protected, root.join("real-etc/.updated")).expect("seed marker symlink");
        let result = run(binary, &[OsStr::new("--root"), root.as_os_str()]);
        assert_eq!(result.status.code(), Some(0), "symlink run with {binary}");
        assert_eq!(fs::read(&protected).expect("read protected"), b"preserve\n");
        assert!(!fs::symlink_metadata(root.join("real-etc/.updated"))
            .expect("stat replaced marker")
            .file_type()
            .is_symlink());
    }
}

#[test]
fn rooted_filesystem_failures_match_live_v261() {
    if !live_oracle_enabled() {
        eprintln!("skipping live comparison: systemd package is not v261");
        return;
    }
    let candidate = env!("CARGO_BIN_EXE_systemd-update-done");
    let missing = tempfile::tempdir().expect("create missing usr root");
    let root = missing.path().join("does-not-exist");
    assert_same(
        &run(HOST, &[OsStr::new("--root"), root.as_os_str()]),
        &run(candidate, &[OsStr::new("--root"), root.as_os_str()]),
        "missing rooted usr",
    );

    let temporary = tempfile::tempdir().expect("create non-directory fixture");
    let root = prepare_root(temporary.path(), false);
    fs::write(root.join("etc"), b"not a directory").expect("create etc file");
    fs::create_dir(root.join("var")).expect("create var");
    let host = run(HOST, &[OsStr::new("--root"), root.as_os_str()]);
    fs::remove_file(root.join("var/.updated")).expect("reset host var marker");
    let ours = run(candidate, &[OsStr::new("--root"), root.as_os_str()]);
    assert_same(&host, &ours, "etc is not a directory");
    assert!(
        root.join("var/.updated").is_file(),
        "var update still attempted"
    );
}
