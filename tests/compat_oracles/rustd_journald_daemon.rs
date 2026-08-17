// SPDX-License-Identifier: LGPL-2.1-or-later
// End-to-end coverage for the native rustd-journald executable.

use std::io::Write as _;
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::path::Path;
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, Instant};

use tempfile::TempDir;

const WAIT: Duration = Duration::from_secs(5);

#[test]
fn isolated_daemon_persists_datagram_and_stdout_entries_then_exits_on_sigterm() {
    let temporary = TempDir::new().expect("temporary journal root");
    let runtime_directory = temporary.path().join("runtime");
    let journal_directory = temporary.path().join("journal");
    let journal_file = journal_directory.join("system.journal");

    let mut daemon = start_daemon(&runtime_directory, &journal_directory);

    let datagram_path = runtime_directory.join("socket");
    let stdout_path = runtime_directory.join("stdout");
    wait_for_path(&datagram_path);
    wait_for_path(&stdout_path);

    let client = UnixDatagram::unbound().expect("create datagram client");
    client
        .send_to(b"MESSAGE=datagram message\nPRIORITY=5\n", &datagram_path)
        .expect("send journal datagram");

    let mut stdout = UnixStream::connect(&stdout_path).expect("connect journal stdout");
    stdout
        .write_all(b"integration-test\nexample.service\n4\n0\n0\n\n0\nstdout message\n")
        .expect("write journal stdout stream");
    drop(stdout);

    wait_for_file_bytes(&journal_file, b"datagram message");
    wait_for_file_bytes(&journal_file, b"stdout message");

    // Safety: daemon.id() is the PID returned by this test's own child spawn.
    #[allow(clippy::cast_possible_wrap)]
    let signal_result = unsafe { libc::kill(daemon.id() as libc::pid_t, libc::SIGTERM) };
    assert_eq!(signal_result, 0, "send SIGTERM to journald");
    wait_for_successful_exit(&mut daemon);
    wait_for_absent(&datagram_path);
    wait_for_absent(&stdout_path);

    let mut restarted = start_daemon(&runtime_directory, &journal_directory);
    wait_for_path(&datagram_path);
    wait_for_path(&stdout_path);
    client
        .send_to(b"MESSAGE=restart message\nPRIORITY=6\n", &datagram_path)
        .expect("send journal datagram after restart");
    wait_for_file_bytes(&journal_file, b"restart message");

    // Safety: restarted.id() is the PID returned by this test's own child spawn.
    #[allow(clippy::cast_possible_wrap)]
    let signal_result = unsafe { libc::kill(restarted.id() as libc::pid_t, libc::SIGTERM) };
    assert_eq!(signal_result, 0, "send SIGTERM to restarted journald");
    wait_for_successful_exit(&mut restarted);
    wait_for_absent(&datagram_path);
    wait_for_absent(&stdout_path);

    let rendered = Command::new(env!("CARGO_BIN_EXE_journalctl"))
        .arg("--file")
        .arg(&journal_file)
        .arg("--output")
        .arg("cat")
        .output()
        .expect("read persisted journal");
    assert!(
        rendered.status.success(),
        "journalctl failed: {}",
        String::from_utf8_lossy(&rendered.stderr)
    );
    let rendered = String::from_utf8_lossy(&rendered.stdout);
    assert!(rendered.contains("datagram message"));
    assert!(rendered.contains("stdout message"));
    assert!(rendered.contains("restart message"));

    assert!(
        datagram_path.starts_with(temporary.path()) && stdout_path.starts_with(temporary.path()),
        "the test sockets must remain inside the temporary directory"
    );
}

#[test]
fn failed_second_socket_bind_cleans_up_the_first_socket() {
    let temporary = TempDir::new().expect("temporary journal root");
    let runtime_directory = temporary.path().join("runtime");
    let journal_directory = temporary.path().join("journal");
    std::fs::create_dir_all(&runtime_directory).expect("create runtime directory");
    let stdout_path = runtime_directory.join("stdout");
    std::fs::write(&stdout_path, b"not a socket").expect("create conflicting stdout path");

    let output = Command::new(env!("CARGO_BIN_EXE_systemd-journald"))
        .arg("--runtime-directory")
        .arg(&runtime_directory)
        .arg("--journal-directory")
        .arg(&journal_directory)
        .output()
        .expect("run journald with a conflicting stdout path");
    assert!(!output.status.success(), "conflicting startup must fail");
    assert!(
        !runtime_directory.join("socket").exists(),
        "receiver socket must be cleaned after stdout setup fails"
    );
    assert_eq!(std::fs::read(&stdout_path).unwrap(), b"not a socket");
}

fn start_daemon(runtime_directory: &Path, journal_directory: &Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_systemd-journald"))
        .arg("--runtime-directory")
        .arg(runtime_directory)
        .arg("--journal-directory")
        .arg(journal_directory)
        .spawn()
        .expect("start isolated journald")
}

fn wait_for_path(path: &Path) {
    let deadline = Instant::now() + WAIT;
    while Instant::now() < deadline {
        if path.exists() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for {}", path.display());
}

fn wait_for_absent(path: &Path) {
    let deadline = Instant::now() + WAIT;
    while Instant::now() < deadline {
        if !path.exists() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for {} to be removed", path.display());
}

fn wait_for_file_bytes(path: &Path, expected: &[u8]) {
    let deadline = Instant::now() + WAIT;
    while Instant::now() < deadline {
        if std::fs::read(path)
            .is_ok_and(|contents| {
                contents
                    .windows(expected.len())
                    .any(|window| window == expected)
            })
        {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!(
        "timed out waiting for journal {} to contain {:?}",
        path.display(),
        String::from_utf8_lossy(expected)
    );
}

fn wait_for_successful_exit(child: &mut Child) {
    let deadline = Instant::now() + WAIT;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("poll journald") {
            assert!(status.success(), "journald exited with {status}");
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("timed out waiting for journald to exit after SIGTERM");
}
