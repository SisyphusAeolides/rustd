// SPDX-License-Identifier: LGPL-2.1-or-later

use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;
use std::process::{Command, Output};

const HOST: &str = "/usr/lib/systemd/systemd-user-sessions";
const MESSAGE: &[u8] = b"System is going down. Unprivileged users are not permitted to log in anymore. For technical details, see pam_nologin(8).\n";

fn host_is_pinned_v261() -> bool {
    Path::new(HOST).is_file()
        && Command::new("/usr/bin/systemd-ac-power")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.stdout.starts_with(b"systemd 261 "))
}

fn plain(binary: &str, arguments: &[&OsStr]) -> Output {
    Command::new(binary)
        .args(arguments)
        .env("LC_ALL", "C")
        .env("SYSTEMD_COLORS", "0")
        .env_remove("RUSTD_USER_SESSIONS_NOLOGIN")
        .output()
        .expect("execute systemd-user-sessions")
}

fn fixture(binary: &str, path: &Path, verb: &str) -> Output {
    Command::new(binary)
        .arg(verb)
        .env("LC_ALL", "C")
        .env("SYSTEMD_COLORS", "0")
        .env("RUSTD_USER_SESSIONS_NOLOGIN", path)
        .output()
        .expect("execute fixture systemd-user-sessions")
}

fn namespace_supported() -> bool {
    Command::new("unshare")
        .args(["--user", "--map-root-user", "--mount", "true"])
        .status()
        .is_ok_and(|status| status.success())
}

fn namespace_run(binary: &str, run: &Path, verb: &str, read_only: bool) -> Output {
    let script = if read_only {
        "set -eu; mount --bind \"$1\" /run; mount -o remount,bind,ro /run; exec \"$2\" \"$3\""
    } else {
        "set -eu; mount --bind \"$1\" /run; exec \"$2\" \"$3\""
    };
    Command::new("unshare")
        .args(["--user", "--map-root-user", "--mount", "sh", "-c"])
        .arg(script)
        .arg("systemd-user-sessions-oracle")
        .arg(run)
        .arg(binary)
        .arg(verb)
        .env("LC_ALL", "C")
        .env("SYSTEMD_COLORS", "0")
        .env_remove("RUSTD_USER_SESSIONS_NOLOGIN")
        .output()
        .expect("execute mount namespace oracle")
}

fn assert_same(host: &Output, candidate: &Output, context: &str) {
    assert_eq!(candidate.status.code(), host.status.code(), "{context}");
    assert_eq!(candidate.stdout, host.stdout, "stdout: {context}");
    assert_eq!(candidate.stderr, host.stderr, "stderr: {context}");
}

#[test]
fn complete_argument_and_error_surface_matches_live_v261() {
    if !host_is_pinned_v261() {
        eprintln!("skipping live comparison: systemd package is not v261");
        return;
    }
    let candidate = env!("CARGO_BIN_EXE_systemd-user-sessions");
    let cases: Vec<Vec<OsString>> = vec![
        vec![],
        vec![OsString::from("--help")],
        vec![OsString::from("--version")],
        vec![OsString::from("bogus")],
        vec![OsString::from("START")],
        vec![OsString::from_vec(vec![0xff])],
        vec![OsString::from("start"), OsString::from("extra")],
    ];
    for arguments in cases {
        let references: Vec<&OsStr> = arguments.iter().map(OsString::as_os_str).collect();
        let host = plain(HOST, &references);
        let ours = plain(candidate, &references);
        assert_same(&host, &ours, &format!("{arguments:?}"));
    }
}

#[test]
fn deterministic_stop_start_atomic_mode_and_symlink_contract() {
    let candidate = env!("CARGO_BIN_EXE_systemd-user-sessions");
    let temporary = tempfile::tempdir().expect("create nologin fixture");
    let nologin = temporary.path().join("nologin");

    let stop = fixture(candidate, &nologin, "stop");
    assert_eq!(stop.status.code(), Some(0));
    assert!(stop.stdout.is_empty());
    assert!(stop.stderr.is_empty());
    assert_eq!(fs::read(&nologin).expect("read nologin"), MESSAGE);
    assert_eq!(
        fs::metadata(&nologin)
            .expect("stat nologin")
            .permissions()
            .mode()
            & 0o777,
        0o644
    );

    let target = temporary.path().join("administrator-file");
    fs::write(&target, b"preserve\n").expect("seed symlink target");
    fs::remove_file(&nologin).expect("remove first nologin");
    symlink(&target, &nologin).expect("create nologin symlink");
    assert!(fixture(candidate, &nologin, "stop").status.success());
    assert!(!fs::symlink_metadata(&nologin)
        .expect("stat replacement")
        .file_type()
        .is_symlink());
    assert_eq!(fs::read(&nologin).expect("read replacement"), MESSAGE);
    assert_eq!(fs::read(&target).expect("read target"), b"preserve\n");

    assert!(fixture(candidate, &nologin, "start").status.success());
    assert!(!nologin.exists());
    assert!(fixture(candidate, &nologin, "start").status.success());
}

#[test]
fn isolated_real_run_lifecycle_and_filesystem_errors_match_live_v261() {
    if !host_is_pinned_v261() || !namespace_supported() {
        eprintln!("skipping isolated live comparison: v261 or user namespaces unavailable");
        return;
    }
    let candidate = env!("CARGO_BIN_EXE_systemd-user-sessions");

    for binary in [HOST, candidate] {
        let run = tempfile::tempdir().expect("create isolated run");
        let stop = namespace_run(binary, run.path(), "stop", false);
        assert_eq!(stop.status.code(), Some(0), "stop with {binary}");
        assert!(stop.stdout.is_empty());
        assert!(stop.stderr.is_empty());
        let nologin = run.path().join("nologin");
        assert_eq!(fs::read(&nologin).expect("read isolated nologin"), MESSAGE);
        assert_eq!(
            fs::metadata(&nologin)
                .expect("stat isolated nologin")
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
        let start = namespace_run(binary, run.path(), "start", false);
        assert_eq!(start.status.code(), Some(0), "start with {binary}");
        assert!(!nologin.exists());
    }

    let host_run = tempfile::tempdir().expect("create host error run");
    let our_run = tempfile::tempdir().expect("create candidate error run");
    fs::create_dir(host_run.path().join("nologin")).expect("create host nologin directory");
    fs::create_dir(our_run.path().join("nologin")).expect("create candidate nologin directory");
    let host = namespace_run(HOST, host_run.path(), "start", false);
    let ours = namespace_run(candidate, our_run.path(), "start", false);
    assert_same(&host, &ours, "unlink directory error");

    let host_ro = tempfile::tempdir().expect("create host read-only run");
    let our_ro = tempfile::tempdir().expect("create candidate read-only run");
    let host = namespace_run(HOST, host_ro.path(), "stop", true);
    let ours = namespace_run(candidate, our_ro.path(), "stop", true);
    assert_same(&host, &ours, "read-only create error");
}
