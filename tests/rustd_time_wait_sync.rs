// SPDX-License-Identifier: LGPL-2.1-or-later

use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

fn fixture_root(parent: &Path, marker: bool) -> PathBuf {
    let root = parent.join("run").join("rustd");
    fs::create_dir_all(root.join("timesync")).expect("create run fixture");
    if marker {
        fs::write(root.join("timesync/synchronized"), b"").expect("create synchronized marker");
    }
    root
}

fn run_candidate(root: &Path, states: Option<&str>, timer_usec: Option<&str>) -> Child {
    run_candidate_with_args(root, states, timer_usec, &[])
}

fn run_candidate_with_args(
    root: &Path,
    states: Option<&str>,
    timer_usec: Option<&str>,
    arguments: &[OsString],
) -> Child {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rustd-time-wait-sync"));
    command
        .args(arguments)
        .env("RUSTD_LOG_TARGET", "null")
        .env("RUSTD_TIME_WAIT_SYNC_RUN_ROOT", root)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(states) = states {
        command.env("RUSTD_TIME_WAIT_SYNC_ADJTIMEX_STATES", states);
    }
    if let Some(timer_usec) = timer_usec {
        command.env("RUSTD_TIME_WAIT_SYNC_TIMER_USEC", timer_usec);
    }
    command.spawn().expect("spawn RustD time-wait-sync")
}

fn wait_for_success(child: &mut Child, context: &str) {
    for _ in 0..40 {
        if let Some(status) = child.try_wait().expect("poll child") {
            assert!(status.success(), "{context}: {status}");
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    let _ = child.kill();
    let status = child.wait().expect("reap timed-out child");
    panic!("{context}: child did not exit successfully ({status})");
}

#[test]
fn marker_path_exits_without_mutating_the_fixture() {
    let temporary = tempfile::tempdir().expect("create marker fixture");
    let root = fixture_root(temporary.path(), true);
    let marker = root.join("timesync/synchronized");
    let before = fs::metadata(&marker).expect("stat marker").len();
    let mut child = run_candidate(&root, None, None);
    wait_for_success(&mut child, "marker path");
    assert_eq!(fs::metadata(marker).expect("restat marker").len(), before);
}

#[test]
fn unsynchronized_state_waits_and_inotify_marker_releases_it() {
    let temporary = tempfile::tempdir().expect("create wait fixture");
    let root = fixture_root(temporary.path(), false);
    let marker = root.join("timesync/synchronized");
    let mut child = run_candidate(&root, Some("5"), Some("5000000"));
    thread::sleep(Duration::from_millis(150));
    assert!(child.try_wait().expect("poll waiting helper").is_none());
    fs::write(marker, b"").expect("create synchronized marker");
    wait_for_success(&mut child, "inotify marker release");
}

#[test]
fn term_signal_releases_the_waiter_cleanly() {
    let temporary = tempfile::tempdir().expect("create signal fixture");
    let root = fixture_root(temporary.path(), false);
    let mut child = run_candidate(&root, Some("5"), Some("5000000"));
    thread::sleep(Duration::from_millis(150));
    assert!(child.try_wait().expect("poll signal helper").is_none());
    // SAFETY: the child PID was returned by std::process::Command and is still
    // alive as established by try_wait above.
    let result = unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
    assert_eq!(result, 0, "send SIGTERM");
    wait_for_success(&mut child, "SIGTERM release");
}

#[test]
fn arbitrary_arguments_are_ignored_by_the_internal_service_helper() {
    let arguments = vec![
        OsString::from("--help"),
        OsString::from("--version"),
        OsString::from_vec(vec![0xff, 0xfe]),
    ];
    let temporary = tempfile::tempdir().expect("create argv fixture");
    let root = fixture_root(temporary.path(), true);
    let mut child = run_candidate_with_args(&root, None, None, &arguments);
    wait_for_success(&mut child, "native argv surface");
}

#[test]
fn watchdog_socket_receives_keepalive_payload_while_waiting() {
    let temporary = tempfile::tempdir().expect("create watchdog fixture");
    let root = fixture_root(temporary.path(), false);
    let socket_path = temporary.path().join("notify.sock");
    let receiver = UnixDatagram::bind(&socket_path).expect("bind watchdog socket");
    receiver
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("set watchdog receive timeout");

    let mut child = Command::new(env!("CARGO_BIN_EXE_rustd-time-wait-sync"))
        .env("RUSTD_LOG_TARGET", "null")
        .env("RUSTD_TIME_WAIT_SYNC_RUN_ROOT", &root)
        .env("RUSTD_TIME_WAIT_SYNC_ADJTIMEX_STATES", "5")
        .env("RUSTD_TIME_WAIT_SYNC_TIMER_USEC", "5000000")
        .env("WATCHDOG_USEC", "100000")
        .env("NOTIFY_SOCKET", &socket_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn watchdog helper");
    let mut payload = [0_u8; 64];
    let length = receiver
        .recv(&mut payload)
        .expect("receive watchdog payload");
    assert_eq!(&payload[..length], b"WATCHDOG=1\n");
    assert!(child.try_wait().expect("poll watchdog helper").is_none());
    // SAFETY: the child is alive and was returned by Command.
    assert_eq!(
        unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) },
        0
    );
    wait_for_success(&mut child, "watchdog SIGTERM cleanup");
}

#[test]
fn timer_rearms_until_adjtimex_reports_synchronization() {
    let temporary = tempfile::tempdir().expect("create timer fixture");
    let root = fixture_root(temporary.path(), false);
    let trace = temporary.path().join("trace");
    let mut child = Command::new(env!("CARGO_BIN_EXE_rustd-time-wait-sync"))
        .env("RUSTD_LOG_TARGET", "null")
        .env("RUSTD_TIME_WAIT_SYNC_RUN_ROOT", &root)
        .env("RUSTD_TIME_WAIT_SYNC_ADJTIMEX_STATES", "5,5,0")
        .env("RUSTD_TIME_WAIT_SYNC_TIMER_USEC", "10000")
        .env("RUSTD_TIME_WAIT_SYNC_TRACE", &trace)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn timer rearm helper");
    wait_for_success(&mut child, "timer rearm");
    let trace = fs::read_to_string(trace).expect("read timer trace");
    assert_eq!(trace.matches("adjtimex=").count(), 3);
    assert!(trace.contains("exit=adjtimex"));
}

#[test]
fn missing_run_directory_fails_closed_before_event_loop() {
    let temporary = tempfile::tempdir().expect("create missing run fixture");
    let root = temporary.path().join("missing/rustd");
    let output = Command::new(env!("CARGO_BIN_EXE_rustd-time-wait-sync"))
        .env("RUSTD_TIME_WAIT_SYNC_RUN_ROOT", &root)
        .output()
        .expect("execute missing-run helper");
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Failed to add watch"));
}

#[test]
fn packaged_unit_preserves_native_runtime_contract() {
    let unit = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("packaging/rustd/rustd-time-wait-sync.service"),
    )
    .expect("read packaged unit");
    for required in [
        "Description=RustD Time Synchronization Wait",
        "DefaultDependencies=no",
        "ConditionCapability=CAP_SYS_TIME",
        "ConditionVirtualization=!container",
        "After=local-fs.target",
        "Before=time-sync.target shutdown.target",
        "Wants=time-sync.target",
        "Conflicts=shutdown.target",
        "Type=oneshot",
        "ExecStart=/usr/lib/rustd/rustd-time-wait-sync",
        "TimeoutStartSec=infinity",
        "RemainAfterExit=yes",
        "WantedBy=sysinit.target",
    ] {
        assert!(unit.contains(required), "missing unit contract: {required}");
    }
}
