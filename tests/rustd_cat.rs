// SPDX-License-Identifier: LGPL-2.1-or-later

use std::fs;
use std::io::{Read, Write as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Command, Stdio};
use std::thread;

fn read_connection(mut stream: UnixStream) -> Vec<u8> {
    let mut contents = Vec::new();
    stream
        .read_to_end(&mut contents)
        .expect("read RustD journal stream");
    contents
}

#[test]
fn native_identity_and_help_are_rustd_only() {
    let candidate = env!("CARGO_BIN_EXE_rustd-cat");
    let version = Command::new(candidate)
        .arg("--version")
        .output()
        .expect("run rustd-cat --version");
    assert!(version.status.success());
    assert!(version.stdout.starts_with(b"RustD "));
    assert!(!version.stdout.windows(7).any(|window| window == b"systemd"));

    let help = Command::new(candidate)
        .arg("--help")
        .output()
        .expect("run rustd-cat --help");
    assert!(help.status.success());
    assert!(help.stdout.starts_with(b"rustd-cat "));
    assert!(help
        .stdout
        .windows(13)
        .any(|window| window == b"RustD journal"));
}

#[test]
fn stream_handshake_priorities_and_native_stream_id_work() {
    let fixture = tempfile::tempdir().expect("create stream fixture");
    let runtime = fixture.path().join("run/rustd");
    fs::create_dir_all(runtime.join("journal")).expect("create journal directory");
    let listener = UnixListener::bind(runtime.join("journal/stdout")).expect("bind journal stream");
    let candidate = env!("CARGO_BIN_EXE_rustd-cat");
    let mut child = Command::new(candidate)
        .args([
            "--identifier=fixture",
            "--priority=notice",
            "--stderr-priority=debug",
            "--level-prefix=no",
            "sh",
            "-c",
            "test -n \"$RUSTD_JOURNAL_STREAM\" || exit 9; printf stdout-payload; printf stderr-payload >&2",
        ])
        .env("LC_ALL", "C")
        .env("PATH", "/usr/bin:/bin")
        .env("RUSTD_CAT_RUNTIME_DIR", &runtime)
        .spawn()
        .expect("spawn rustd-cat");
    let stdout_stream = listener.accept().expect("accept stdout stream").0;
    let stderr_stream = listener.accept().expect("accept stderr stream").0;
    let stdout_reader = thread::spawn(move || read_connection(stdout_stream));
    let stderr_reader = thread::spawn(move || read_connection(stderr_stream));
    assert_eq!(child.wait().expect("wait rustd-cat").code(), Some(0));
    assert_eq!(
        stdout_reader.join().expect("join stdout reader"),
        b"fixture\n\n5\n0\n0\n0\n0\nstdout-payload"
    );
    assert_eq!(
        stderr_reader.join().expect("join stderr reader"),
        b"fixture\n\n7\n0\n0\n0\n0\nstderr-payload"
    );
}

#[test]
fn namespace_routing_and_stdin_use_rustd_runtime() {
    let fixture = tempfile::tempdir().expect("create namespace fixture");
    let runtime = fixture.path().join("run/rustd");
    fs::create_dir_all(runtime.join("journal.demo")).expect("create namespace directory");
    let listener =
        UnixListener::bind(runtime.join("journal.demo/stdout")).expect("bind namespace stream");
    let candidate = env!("CARGO_BIN_EXE_rustd-cat");
    let mut child = Command::new(candidate)
        .arg("--namespace=demo")
        .env("RUSTD_CAT_RUNTIME_DIR", &runtime)
        .stdin(Stdio::piped())
        .spawn()
        .expect("spawn default cat");
    let stream = listener.accept().expect("accept namespace stream").0;
    let reader = thread::spawn(move || read_connection(stream));
    child
        .stdin
        .take()
        .expect("cat stdin")
        .write_all(b"stdin-payload")
        .expect("write cat stdin");
    assert_eq!(child.wait().expect("wait default cat").code(), Some(0));
    assert_eq!(
        reader.join().expect("join namespace reader"),
        b"\n\n6\n1\n0\n0\n0\nstdin-payload"
    );
}

#[test]
fn active_namespace_must_match_requested_namespace() {
    let fixture = tempfile::tempdir().expect("create namespace fixture");
    let runtime = fixture.path().join("run/rustd");
    fs::create_dir_all(runtime.join("journal.demo")).expect("create namespace directory");
    let candidate = env!("CARGO_BIN_EXE_rustd-cat");
    let mismatch = Command::new(candidate)
        .args(["--namespace=demo", "true"])
        .env("RUSTD_LOG_NAMESPACE", "other")
        .env("RUSTD_CAT_RUNTIME_DIR", &runtime)
        .output()
        .expect("run active namespace mismatch");
    assert_eq!(mismatch.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&mismatch.stderr).contains("Object is remote"));
}
