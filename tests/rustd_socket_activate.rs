// SPDX-License-Identifier: LGPL-2.1-or-later

use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const HOST: &str = "/usr/bin/systemd-socket-activate";

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
        .env("SYSTEMD_LOG_COLOR", "0")
        .env("SYSTEMD_LOG_TARGET", "console")
        .env("SYSTEMD_LOG_LEVEL", "err");
    command
}

fn run(binary: &str, arguments: &[OsString]) -> Output {
    command(binary)
        .args(arguments)
        .output()
        .expect("run rustd-socket-activate")
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

fn wait_for_path(path: &Path, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < deadline {
        if path.exists() {
            return;
        }
        assert!(
            child.try_wait().expect("poll activation helper").is_none(),
            "activation helper exited before creating {}",
            path.display()
        );
        thread::sleep(Duration::from_millis(10));
    }
    panic!("activation socket did not appear: {}", path.display());
}

fn wait_with_output(mut child: Child) -> Output {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if child.try_wait().expect("poll activation child").is_some() {
            return child.wait_with_output().expect("collect activation output");
        }
        thread::sleep(Duration::from_millis(10));
    }
    child.kill().expect("kill timed out activation child");
    panic!("activation child timed out");
}

fn spawn_accept(binary: &str, path: &Path, inetd: bool, raised_limit: bool) -> Child {
    let response = concat!(
        "import os,resource,socket\n",
        "s=socket.socket(fileno=3)\n",
        "v=(os.environ.get('LISTEN_FDS'),os.environ.get('LISTEN_FDNAMES'),",
        "os.getpid()==int(os.environ['LISTEN_PID']),",
        "os.environ.get('LISTEN_PIDFDID','').isdigit(),",
        "resource.getrlimit(resource.RLIMIT_NOFILE))\n",
        "s.sendall(repr(v).encode())\n",
    );
    let mut process = if raised_limit {
        let mut process = command("/usr/bin/prlimit");
        process.args(["--nofile=65536:1048576", "--", binary]);
        process
    } else {
        command(binary)
    };
    process
        .arg("--accept")
        .arg("-l")
        .arg(path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    if inetd {
        process.args(["--inetd", "/bin/cat"]);
    } else {
        process.args(["--fdname=accepted", "/usr/bin/python3", "-c", response]);
    }
    process.spawn().expect("spawn accept-mode helper")
}

fn stop_group(child: &mut Child) {
    let pid = i32::try_from(child.id()).expect("child PID fits pid_t");
    // SAFETY: the child was placed in a fresh process group whose id is its PID.
    unsafe { libc::kill(-pid, libc::SIGTERM) };
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if child
            .try_wait()
            .expect("poll stopped accept helper")
            .is_some()
        {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    // SAFETY: the target remains the exact process group created above.
    unsafe { libc::kill(-pid, libc::SIGKILL) };
    let _ = child.wait();
}

fn accept_response(binary: &str, inetd: bool, raised_limit: bool) -> Vec<u8> {
    let fixture = tempfile::tempdir().expect("create accept fixture");
    let path = fixture.path().join("accept.sock");
    let mut child = spawn_accept(binary, &path, inetd, raised_limit);
    wait_for_path(&path, &mut child);
    let mut client = UnixStream::connect(&path).expect("connect accept socket");
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set accept timeout");
    if inetd {
        client
            .write_all(b"inetd-echo")
            .expect("write inetd request");
        client
            .shutdown(std::net::Shutdown::Write)
            .expect("finish inetd request");
    }
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .expect("read accept response");
    stop_group(&mut child);
    response
}

fn assert_logging_environment_matches_v261(candidate: &str) {
    for level in ["emerg", "err", "debug", "bogus", "console:emerg"] {
        let mut host = command(HOST);
        let mut ours = command(candidate);
        host.env("SYSTEMD_LOG_LEVEL", level).arg("/bin/true");
        ours.env("SYSTEMD_LOG_LEVEL", level).arg("/bin/true");
        assert_same(
            &host.output().expect("run host log-level case"),
            &ours.output().expect("run candidate log-level case"),
            &format!("log level {level}"),
        );
    }

    for target in ["console", "console-prefixed", "null", "kmsg", "invalid"] {
        let mut host = command(HOST);
        let mut ours = command(candidate);
        host.env("SYSTEMD_LOG_TARGET", target);
        ours.env("SYSTEMD_LOG_TARGET", target);
        assert_same(
            &host.output().expect("run host log-target case"),
            &ours.output().expect("run candidate log-target case"),
            &format!("log target {target}"),
        );
    }

    for (colors, urlify, no_color) in [("1", "0", None), ("0", "1", None), ("1", "1", Some("1"))] {
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
            &host.output().expect("run host decorated help"),
            &ours.output().expect("run candidate decorated help"),
            &format!("help colors={colors} urlify={urlify} no_color={no_color:?}"),
        );
    }
}

fn send_seqpacket(path: &Path) {
    let output = Command::new("/usr/bin/python3")
        .args([
            "-c",
            concat!(
                "import socket,sys\n",
                "s=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)\n",
                "s.connect(sys.argv[1])\n",
                "s.sendall(b'mode-payload')\n",
            ),
        ])
        .arg(path)
        .output()
        .expect("run seqpacket client");
    assert!(
        output.status.success(),
        "seqpacket client failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn complete_getopt_address_environment_and_logging_surface_matches_v261() {
    if !host_is_pinned_v261() {
        eprintln!("skipping live comparison: systemd-socket-activate is not v261");
        return;
    }
    let candidate = env!("CARGO_BIN_EXE_rustd-socket-activate");
    let cases: Vec<Vec<OsString>> = vec![
        vec!["--help".into()],
        vec!["--version".into()],
        vec![],
        vec!["--definitely-unknown".into()],
        vec!["--listen".into()],
        vec!["-l".into()],
        vec!["--help=x".into()],
        vec!["--s".into()],
        vec!["-adx".into()],
        vec!["-E".into(), "=x".into(), "/bin/true".into()],
        vec![
            "--datagram".into(),
            "--seqpacket".into(),
            "/bin/true".into(),
        ],
        vec!["--datagram".into(), "--accept".into(), "/bin/true".into()],
        vec!["--accept".into(), "--now".into(), "/bin/true".into()],
        vec!["--listen=".into(), "/bin/true".into()],
        vec!["--listen=0".into(), "/bin/true".into()],
        vec!["--listen=65536".into(), "/bin/true".into()],
        vec!["--listen=+65536".into(), "--now".into(), "/bin/true".into()],
        vec!["--listen=045972".into(), "--now".into(), "/bin/true".into()],
        vec![
            "--seqpacket".into(),
            "--listen=127.0.0.1:45973".into(),
            "--now".into(),
            "/bin/true".into(),
        ],
        vec!["--fdname=a::b".into(), "/bin/true".into()],
        vec![OsString::from_vec(vec![b'-', b'-', 0xff])],
    ];
    for arguments in cases {
        assert_same(
            &run(HOST, &arguments),
            &run(candidate, &arguments),
            &format!("CLI {arguments:?}"),
        );
    }

    let path_case: Vec<OsString> = vec![
        "--now".into(),
        "-l".into(),
        "@rustd-path-lookup".into(),
        "-E".into(),
        "PATH=/definitely/missing".into(),
        "true".into(),
    ];
    let mut host = command(HOST);
    let mut ours = command(candidate);
    host.env("PATH", "/usr/bin:/bin").args(&path_case);
    ours.env("PATH", "/usr/bin:/bin").args(&path_case);
    assert_same(
        &host.output().expect("run host PATH lookup"),
        &ours.output().expect("run candidate PATH lookup"),
        "execvpe uses caller PATH",
    );

    assert_logging_environment_matches_v261(candidate);
}

#[test]
#[allow(clippy::too_many_lines)]
fn stream_datagram_seqpacket_and_activation_environment_match_v261() {
    if !host_is_pinned_v261() {
        eprintln!("skipping live comparison: systemd-socket-activate is not v261");
        return;
    }
    let candidate = env!("CARGO_BIN_EXE_rustd-socket-activate");
    let now_code = concat!(
        "import fcntl,os,socket\n",
        "rows=[]\n",
        "for fd in range(3,3+int(os.environ['LISTEN_FDS'])):\n",
        " s=socket.socket(fileno=os.dup(fd)); rows.append((s.family,s.type,",
        "bool(fcntl.fcntl(fd,fcntl.F_GETFD)&fcntl.FD_CLOEXEC)))\n",
        "print(repr((os.environ.get('LISTEN_FDS'),os.environ.get('LISTEN_FDNAMES'),",
        "os.getpid()==int(os.environ['LISTEN_PID']),",
        "os.environ.get('LISTEN_PIDFDID','').isdigit(),os.environ.get('X'),",
        "os.environ.get('SHOULD_DROP'),rows)))\n",
    );
    let arguments: Vec<OsString> = vec![
        "--now".into(),
        "--fdname=only".into(),
        "-E".into(),
        "X=value".into(),
        "-l".into(),
        "@rustd-now-one".into(),
        "-l".into(),
        "@rustd-now-two".into(),
        "/usr/bin/python3".into(),
        "-c".into(),
        now_code.into(),
    ];
    let mut host = command(HOST);
    let mut ours = command(candidate);
    host.env("SHOULD_DROP", "yes").args(&arguments);
    ours.env("SHOULD_DROP", "yes").args(&arguments);
    assert_same(
        &host.output().expect("run host immediate activation"),
        &ours.output().expect("run candidate immediate activation"),
        "immediate multi-socket environment",
    );

    for (mode, socket_name, python) in [
        (
            "stream",
            "stream.sock",
            "import os,socket;s=socket.socket(fileno=os.dup(3));c,_=s.accept();print(c.recv(32))",
        ),
        (
            "datagram",
            "datagram.sock",
            "import os,socket;s=socket.socket(fileno=os.dup(3));print(s.recv(32))",
        ),
        (
            "seqpacket",
            "seqpacket.sock",
            "import os,socket;s=socket.socket(fileno=os.dup(3));c,_=s.accept();print(c.recv(32))",
        ),
    ] {
        let fixture = tempfile::tempdir().expect("create activation fixture");
        let path = fixture.path().join(socket_name);
        let mut arguments = Vec::<OsString>::new();
        if mode == "datagram" {
            arguments.push("--datagram".into());
        } else if mode == "seqpacket" {
            arguments.push("--seqpacket".into());
        }
        let path_index = arguments.len() + 1;
        arguments.extend([
            "-l".into(),
            path.as_os_str().to_owned(),
            "/usr/bin/python3".into(),
            "-c".into(),
            python.into(),
        ]);
        let mut child = command(candidate)
            .args(&arguments)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn candidate activation mode");
        wait_for_path(&path, &mut child);
        if mode == "stream" {
            let mut client = UnixStream::connect(&path).expect("connect stream activation");
            client
                .write_all(b"mode-payload")
                .expect("write stream payload");
        } else if mode == "datagram" {
            let client = UnixDatagram::unbound().expect("create datagram client");
            client
                .send_to(b"mode-payload", &path)
                .expect("write datagram payload");
        } else {
            send_seqpacket(&path);
        }
        let candidate_output = wait_with_output(child);

        let host_fixture = tempfile::tempdir().expect("create host activation fixture");
        let host_path = host_fixture.path().join(socket_name);
        arguments[path_index] = host_path.as_os_str().to_owned();
        let mut child = command(HOST)
            .args(&arguments)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn host activation mode");
        wait_for_path(&host_path, &mut child);
        if mode == "stream" {
            let mut client = UnixStream::connect(&host_path).expect("connect host stream");
            client
                .write_all(b"mode-payload")
                .expect("write host stream payload");
        } else if mode == "datagram" {
            let client = UnixDatagram::unbound().expect("create datagram client");
            client
                .send_to(b"mode-payload", &host_path)
                .expect("write host datagram payload");
        } else {
            send_seqpacket(&host_path);
        }
        let host_output = wait_with_output(child);
        assert_same(&host_output, &candidate_output, mode);
    }
}

#[test]
fn accept_inetd_and_safe_child_limit_match_v261() {
    if !host_is_pinned_v261() {
        eprintln!("skipping live comparison: systemd-socket-activate is not v261");
        return;
    }
    let candidate = env!("CARGO_BIN_EXE_rustd-socket-activate");
    assert_eq!(
        accept_response(candidate, false, false),
        accept_response(HOST, false, false),
        "accept-mode activation environment"
    );
    assert_eq!(
        accept_response(candidate, true, false),
        accept_response(HOST, true, false),
        "inetd descriptor protocol"
    );
    assert_eq!(
        accept_response(candidate, false, true),
        accept_response(HOST, false, true),
        "accept child RLIMIT_NOFILE"
    );
}

fn notification_messages(binary: &str, arguments: &[&str]) -> (Output, Vec<Vec<u8>>) {
    let fixture = tempfile::tempdir().expect("create notification fixture");
    let path = fixture.path().join("notify.sock");
    let receiver = UnixDatagram::bind(&path).expect("bind notification receiver");
    receiver
        .set_read_timeout(Some(Duration::from_millis(80)))
        .expect("set notification timeout");
    let output = command(binary)
        .env("NOTIFY_SOCKET", &path)
        .args(arguments)
        .output()
        .expect("run notification case");
    let mut messages = Vec::new();
    loop {
        let mut packet = vec![0_u8; 4096];
        match receiver.recv(&mut packet) {
            Ok(length) => {
                packet.truncate(length);
                messages.push(packet);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                break;
            }
            Err(error) => panic!("receive notification: {error}"),
        }
    }
    (output, messages)
}

fn filesystem_result(binary: &str) -> (Output, u32, bool, u32, u32) {
    let fixture = tempfile::tempdir().expect("create filesystem socket fixture");
    let first = fixture.path().join("first");
    let parent = first.join("second");
    let path = parent.join("activate.sock");
    let code = "import os; old=os.umask(0); os.umask(old); print(oct(old))";
    let mut process = command(binary);
    process.args([OsString::from("--now"), OsString::from("-l")]);
    process.arg(&path).args(["/usr/bin/python3", "-c", code]);
    // SAFETY: pre_exec runs in the single-threaded fork child and umask has
    // no pointer arguments. The activation program must restore this value.
    unsafe {
        process.pre_exec(|| {
            libc::umask(0o077);
            Ok(())
        });
    }
    let output = process.output().expect("run filesystem socket case");
    let socket = fs::symlink_metadata(&path).expect("stat socket node");
    let first = fs::metadata(first).expect("stat first parent");
    let second = fs::metadata(parent).expect("stat second parent");
    (
        output,
        socket.mode() & 0o7777,
        socket.file_type().is_socket(),
        first.mode() & 0o7777,
        second.mode() & 0o7777,
    )
}

#[test]
fn notification_and_filesystem_socket_lifecycle_match_v261() {
    if !host_is_pinned_v261() {
        eprintln!("skipping live comparison: systemd-socket-activate is not v261");
        return;
    }
    let candidate = env!("CARGO_BIN_EXE_rustd-socket-activate");
    for arguments in [
        vec!["--help"],
        vec!["/bin/true"],
        vec!["--now", "-l", "@rustd-notify", "/definitely/missing"],
    ] {
        let (host_output, host_messages) = notification_messages(HOST, &arguments);
        let (our_output, our_messages) = notification_messages(candidate, &arguments);
        assert_same(
            &host_output,
            &our_output,
            &format!("notification {arguments:?}"),
        );
        assert_eq!(our_messages, host_messages, "notification {arguments:?}");
    }

    let host = filesystem_result(HOST);
    let ours = filesystem_result(candidate);
    assert_same(&host.0, &ours.0, "filesystem socket output and umask");
    assert_eq!(
        (&ours.1, &ours.2, &ours.3, &ours.4),
        (&host.1, &host.2, &host.3, &host.4)
    );
}
