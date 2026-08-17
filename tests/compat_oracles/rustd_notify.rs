// SPDX-License-Identifier: LGPL-2.1-or-later

use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixDatagram;
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use rustd::ffi::notify::{rustd_notify_enable_passcred, rustd_notify_recv};

#[derive(Debug, Eq, PartialEq)]
struct Message {
    payload: Vec<u8>,
    uid: u32,
    gid: u32,
    fds: Vec<Vec<u8>>,
}

fn host_is_pinned_v261() -> bool {
    Command::new("/usr/bin/systemd-notify")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.stdout.starts_with(b"systemd 261 "))
}

fn live_systemd_notify_oracle_enabled() -> bool {
    // Exclusive RustD uses RUSTD_NOTIFY_SOCKET / native field names. Live
    // byte-for-byte comparison against /usr/bin/systemd-notify is only valid
    // when explicitly requested for compatibility archaeology.
    host_is_pinned_v261() && std::env::var_os("RUSTD_LIVE_SYSTEMD_NOTIFY_ORACLE").is_some()
}

fn plain(binary: &str, arguments: &[&str]) -> Output {
    Command::new(binary)
        .args(arguments)
        .env("LC_ALL", "C")
        .env("SYSTEMD_COLORS", "0")
        .env("PATH", "/usr/bin:/bin")
        .env_remove("RUSTD_NOTIFY_SOCKET")
        .env_remove("MANAGERPID")
        .env_remove("MANAGERPIDFDID")
        .output()
        .expect("execute systemd-notify")
}

#[allow(clippy::similar_names)] // PID/UID/GID are the canonical SCM_CREDENTIALS field names.
fn receive(socket: &UnixDatagram) -> Message {
    let mut buffer = [0_u8; 65_536];
    let mut pid = 0_i32;
    let mut uid = u32::MAX;
    let mut gid = u32::MAX;
    let mut raw_fds = [-1_i32; 253];
    let mut n_fds = 0_usize;
    // SAFETY: all buffers and output pointers are valid for this call.
    let length = unsafe {
        rustd_notify_recv(
            socket.as_raw_fd(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut pid,
            &mut uid,
            &mut gid,
            raw_fds.as_mut_ptr(),
            raw_fds.len(),
            &mut n_fds,
        )
    };
    assert!(length >= 0, "receive notification: {length}");
    let mut fds = Vec::new();
    for raw_fd in raw_fds.iter().copied().take(n_fds) {
        // SAFETY: SCM_RIGHTS transferred ownership of each descriptor.
        let mut file = unsafe { File::from_raw_fd(raw_fd) };
        let mut contents = Vec::new();
        if file.read_to_end(&mut contents).is_err() {
            contents = b"<write-only>".to_vec();
        }
        fds.push(contents);
    }
    Message {
        payload: buffer[..usize::try_from(length).expect("non-negative length")].to_vec(),
        uid,
        gid,
        fds,
    }
}

fn capture(binary: &str, arguments: &[&str], stdin: Option<File>) -> (Output, Vec<Message>) {
    let fixture = tempfile::tempdir().expect("create notification fixture");
    let socket_path = fixture.path().join("notify.sock");
    let socket = UnixDatagram::bind(&socket_path).expect("bind notify receiver");
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set receiver timeout");
    // SAFETY: this is a valid AF_UNIX datagram socket.
    assert_eq!(
        unsafe { rustd_notify_enable_passcred(socket.as_raw_fd()) },
        0
    );
    let mut command = Command::new(binary);
    command
        .args(arguments)
        .env("LC_ALL", "C")
        .env("SYSTEMD_COLORS", "0")
        .env("PATH", "/usr/bin:/bin")
        .env("RUSTD_NOTIFY_SOCKET", &socket_path)
        .env("NOTIFY_SOCKET", &socket_path)
        .env_remove("MANAGERPID")
        .env_remove("MANAGERPIDFDID")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(file) = stdin {
        command.stdin(Stdio::from(file));
    }
    let child = command.spawn().expect("spawn systemd-notify");
    let mut messages = vec![receive(&socket)];
    if !arguments.contains(&"--no-block") {
        messages.push(receive(&socket));
    }
    let output = child.wait_with_output().expect("wait for systemd-notify");
    (output, messages)
}

fn normalize_dynamic_fields(payload: &[u8]) -> Vec<u8> {
    String::from_utf8_lossy(payload)
        .lines()
        .map(|line| {
            if line.starts_with("MAINPID=") {
                "MAINPID=<pid>".to_owned()
            } else if line.starts_with("MAINPIDFDID=") {
                "MAINPIDFDID=<id>".to_owned()
            } else if line.starts_with("MONOTONIC_USEC=") {
                "MONOTONIC_USEC=<time>".to_owned()
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes()
}

#[test]
fn complete_option_and_error_surface_matches_live_v261() {
    if !live_systemd_notify_oracle_enabled() {
        eprintln!(
            "skipping live systemd-notify comparison: exclusive RustD notify naming is intentional"
        );
        return;
    }
    let candidate = env!("CARGO_BIN_EXE_systemd-notify");
    let cases: &[&[&str]] = &[
        &[],
        &["--help"],
        &["--version"],
        &["--ready"],
        &["--pid"],
        &["--pid="],
        &["--pid=999999999"],
        &["--uid=no-such-systemd-notify-user"],
        &["--booted"],
        &["--booted", "parameter"],
        &["--booted", "--ready"],
        &["--exec", "READY=1"],
        &["--exec", "READY=1", ";"],
        &["--exec", ";", "true"],
        &["--fdname=name", "READY=1"],
        &["--fd=-1"],
        &["--fd=9999"],
        &["--fdname=a:b"],
        &["--fork"],
        &["-q"],
        &["--unknown"],
        &["--r"],
        &["--ready=value"],
        &["--uid"],
        &["--status"],
        &["--fd"],
    ];
    for arguments in cases {
        let host = plain("/usr/bin/systemd-notify", arguments);
        let ours = plain(candidate, arguments);
        assert_eq!(ours.status.code(), host.status.code(), "{arguments:?}");
        assert_eq!(ours.stdout, host.stdout, "stdout for {arguments:?}");
        assert_eq!(ours.stderr, host.stderr, "stderr for {arguments:?}");
    }
}

#[test]
fn datagrams_credentials_barrier_and_all_protocol_fields_match_v261() {
    if !live_systemd_notify_oracle_enabled() {
        eprintln!(
            "skipping live systemd-notify comparison: exclusive RustD notify naming is intentional"
        );
        return;
    }
    let candidate = env!("CARGO_BIN_EXE_systemd-notify");
    let cases: &[&[&str]] = &[
        &["--ready"],
        &["--ready", "READY=0", "STATUS=override"],
        &["--reloading"],
        &[
            "--ready",
            "--reloading",
            "--stopping",
            "--status=working",
            "ERRNO=5",
            "BUSERROR=org.example.Error",
            "MAINPID=9",
            "MONOTONIC_USEC=7",
            "FDSTOREREMOVE=1",
            "EXTEND_TIMEOUT_USEC=8",
            "WATCHDOG=1",
            "RUSTD_WATCHDOG_USEC=4",
            "FDNAME=manual",
            "WATCHDOG_TRIGGER=1",
            "NOTIFYACCESS=all",
            "UUID=0123456789abcdef",
        ],
        &["--pid=self", "X=1"],
        &["--pid=parent", "X=1"],
        &["A=first", "A=last"],
        &["--no-block", "READY=1"],
    ];
    for arguments in cases {
        let (host_output, mut host) = capture("/usr/bin/systemd-notify", arguments, None);
        let (our_output, mut ours) = capture(candidate, arguments, None);
        assert_eq!(
            our_output.status.code(),
            host_output.status.code(),
            "{arguments:?}"
        );
        assert_eq!(our_output.stdout, host_output.stdout, "{arguments:?}");
        assert_eq!(our_output.stderr, host_output.stderr, "{arguments:?}");
        assert_eq!(ours.len(), host.len(), "{arguments:?}");
        for (our_message, host_message) in ours.iter_mut().zip(host.iter_mut()) {
            our_message.payload = normalize_dynamic_fields(&our_message.payload);
            host_message.payload = normalize_dynamic_fields(&host_message.payload);
        }
        assert_eq!(ours, host, "{arguments:?}");
    }
}

#[test]
fn descriptor_store_sends_scm_rights_and_fdname_then_closes_barrier() {
    let candidate = env!("CARGO_BIN_EXE_systemd-notify");
    let fixture = tempfile::tempdir().expect("create descriptor fixture");
    let path = fixture.path().join("payload");
    std::fs::write(&path, b"descriptor-payload").expect("write descriptor payload");
    let input = File::open(&path).expect("open descriptor payload");
    let (output, messages) = capture(
        candidate,
        &["--fd=0", "--fdname=demo", "UUID=fixture"],
        Some(input),
    );
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(messages[0].payload, b"FDSTORE=1\nFDNAME=demo\nUUID=fixture");
    assert_eq!(messages[0].fds, vec![b"descriptor-payload".to_vec()]);
    assert_eq!(messages[1].payload, b"BARRIER=1");
    assert_eq!(messages[1].fds, vec![b"<write-only>".to_vec()]);
}

#[test]
fn uid_mode_sends_the_requested_real_credentials() {
    let candidate = env!("CARGO_BIN_EXE_systemd-notify");
    let metadata = std::fs::metadata("/proc/self").expect("stat self process");
    let user = format!("--uid={}", metadata.uid());
    let (output, messages) = capture(candidate, &[&user, "--no-block", "READY=1"], None);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(messages[0].uid, metadata.uid());
    assert_eq!(messages[0].gid, metadata.gid());
}

#[test]
fn exec_and_fork_modes_match_v261_lifecycle_contracts() {
    let candidate = env!("CARGO_BIN_EXE_systemd-notify");
    let (output, messages) = capture(
        candidate,
        &[
            "--no-block",
            "--exec",
            "READY=1",
            ";",
            "--",
            "sh",
            "-c",
            "printf exec-ok",
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"exec-ok");
    assert_eq!(messages[0].payload, b"READY=1");

    let success = plain(candidate, &["--fork", "--", "true"]);
    assert_eq!(success.status.code(), Some(0));
    assert!(success.stdout.ends_with(b"\n"));

    let failure = plain(candidate, &["--fork", "--", "false"]);
    assert_eq!(failure.status.code(), Some(1));

    let ready = plain(
        candidate,
        &[
            "--fork",
            "--",
            candidate,
            "--no-block",
            "--ready",
        ],
    );
    assert_eq!(ready.status.code(), Some(0));
    assert_eq!(ready.stderr, [] as [u8; 0]);

    let quiet = plain(candidate, &["--quiet", "--fork", "--", "true"]);
    assert_eq!(quiet.status.code(), Some(0));
    assert_eq!(quiet.stdout, [] as [u8; 0]);

    let abstract_socket = plain(
        candidate,
        &[
            "--quiet",
            "--fork",
            "--",
            "sh",
            "-c",
            "case $RUSTD_NOTIFY_SOCKET in @*) exit 0;; *) exit 2;; esac",
        ],
    );
    assert_eq!(abstract_socket.status.code(), Some(0));
}

#[test]
fn fork_forwards_the_v261_signal_set_to_the_child() {
    let candidate = env!("CARGO_BIN_EXE_systemd-notify");
    let mut process = Command::new(candidate)
        .args([
            "--quiet",
            "--fork",
            "--",
            "sh",
            "-c",
            "trap 'exit 7' USR1; while :; do sleep 1; done",
        ])
        .env("LC_ALL", "C")
        .env("PATH", "/usr/bin:/bin")
        .spawn()
        .expect("spawn forwarding oracle");
    std::thread::sleep(Duration::from_millis(150));
    let signal = Command::new("kill")
        .args(["-USR1", &process.id().to_string()])
        .status()
        .expect("signal systemd-notify");
    assert!(signal.success());
    assert_eq!(
        process.wait().expect("wait forwarding oracle").code(),
        Some(7)
    );
}
