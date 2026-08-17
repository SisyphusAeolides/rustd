// SPDX-License-Identifier: LGPL-2.1-or-later
//! Native `RustD` socket-activation contract tests.
//!
//! These assert `RUSTD_LISTEN_*` / `RUSTD_NOTIFY_*` behavior only. They do not
//! compare against `systemd-socket-activate`.

use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_rustd-socket-activate")
}

fn command() -> Command {
    let mut command = Command::new(binary());
    command.env("LC_ALL", "C").env_remove("RUSTD_NOTIFY_SOCKET");
    command
}

fn run(arguments: &[OsString]) -> Output {
    command()
        .args(arguments)
        .output()
        .expect("run rustd-socket-activate")
}

fn wait_for_path(path: &Path, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < deadline {
        if path.exists() {
            return;
        }
        if let Some(status) = child.try_wait().expect("poll activation helper") {
            let mut stderr = String::new();
            if let Some(mut pipe) = child.stderr.take() {
                pipe.read_to_string(&mut stderr)
                    .expect("read activation helper stderr");
            }
            panic!(
                "activation helper exited before creating {}: status={status}, stderr={stderr}",
                path.display()
            );
        }
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

fn spawn_accept(path: &Path, inetd: bool, raised_limit: bool) -> Child {
    let response = concat!(
        "import os,resource,socket\n",
        "s=socket.socket(fileno=3)\n",
        "assert 'LISTEN_FDS' not in os.environ\n",
        "assert 'LISTEN_PID' not in os.environ\n",
        "v=(os.environ['RUSTD_LISTEN_FDS'],os.environ.get('RUSTD_LISTEN_FDNAMES'),",
        "os.getpid()==int(os.environ['RUSTD_LISTEN_PID']),",
        "os.environ.get('RUSTD_LISTEN_PIDFDID','').isdigit(),",
        "resource.getrlimit(resource.RLIMIT_NOFILE))\n",
        "s.sendall(repr(v).encode())\n",
    );
    let mut process = command();
    if raised_limit {
        // SAFETY: this closure runs after fork and before exec, performs only
        // libc rlimit calls, captures no parent state, and preserves the
        // runner's hard limit.
        unsafe {
            process.pre_exec(|| {
                let mut limit = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if limit.rlim_max <= 1024 {
                    return Err(std::io::Error::other(
                        "RLIMIT_NOFILE hard limit is too low for the clamp test",
                    ));
                }
                limit.rlim_cur = std::cmp::min(limit.rlim_max, 65_536);
                if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    process
        .arg("--accept")
        .arg("-l")
        .arg(path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
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

fn accept_response(inetd: bool, raised_limit: bool) -> Vec<u8> {
    let fixture = tempfile::tempdir().expect("create accept fixture");
    let path = fixture.path().join("accept.sock");
    let mut child = spawn_accept(&path, inetd, raised_limit);
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

fn notification_messages(arguments: &[&str]) -> (Output, Vec<Vec<u8>>) {
    let fixture = tempfile::tempdir().expect("create notification fixture");
    let path = fixture.path().join("notify.sock");
    let receiver = UnixDatagram::bind(&path).expect("bind notification receiver");
    receiver
        .set_read_timeout(Some(Duration::from_millis(80)))
        .expect("set notification timeout");
    let output = command()
        .env("RUSTD_NOTIFY_SOCKET", &path)
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

#[test]
fn cli_rejects_invalid_option_combinations() {
    let cases: &[(&[&str], i32)] = &[
        (&[], 1),
        (&["--definitely-unknown"], 1),
        (&["--listen"], 1),
        (&["-l"], 1),
        (&["--datagram", "--seqpacket", "/bin/true"], 1),
        (&["--datagram", "--accept", "/bin/true"], 1),
        (&["--accept", "--now", "/bin/true"], 1),
        (&["--fdname=a::b", "/bin/true"], 1),
    ];
    for (arguments, expected) in cases {
        let output = run(&arguments
            .iter()
            .map(|argument| OsString::from(*argument))
            .collect::<Vec<_>>());
        assert_eq!(
            output.status.code(),
            Some(*expected),
            "CLI {arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let help = run(&[OsString::from("--help")]);
    assert_eq!(help.status.code(), Some(0));
    assert!(
        help.stdout.windows(b"rustd".len()).any(|w| w == b"rustd")
            || help.stderr.windows(b"rustd".len()).any(|w| w == b"rustd")
            || help
                .stdout
                .windows(b"OPTIONS".len())
                .any(|w| w == b"OPTIONS")
    );
}

#[test]
fn immediate_activation_exports_only_rustd_listen_environment() {
    let code = concat!(
        "import fcntl,os,socket,sys\n",
        "assert 'LISTEN_FDS' not in os.environ\n",
        "assert 'LISTEN_PID' not in os.environ\n",
        "assert 'LISTEN_FDNAMES' not in os.environ\n",
        "fds=int(os.environ['RUSTD_LISTEN_FDS'])\n",
        "assert fds==2\n",
        "assert os.environ['RUSTD_LISTEN_FDNAMES']=='only:only'\n",
        "assert os.getpid()==int(os.environ['RUSTD_LISTEN_PID'])\n",
        "assert os.environ.get('RUSTD_LISTEN_PIDFDID','').isdigit()\n",
        "assert os.environ['X']=='value'\n",
        "assert 'SHOULD_DROP' not in os.environ\n",
        "for fd in range(3,5):\n",
        " s=socket.socket(fileno=os.dup(fd))\n",
        " assert s.family==socket.AF_UNIX and s.type==socket.SOCK_STREAM\n",
        " assert not (fcntl.fcntl(fd,fcntl.F_GETFD)&fcntl.FD_CLOEXEC)\n",
        "print('ok')\n",
    );
    let output = command()
        .env("SHOULD_DROP", "yes")
        .args([
            OsString::from("--now"),
            OsString::from("--fdname=only"),
            OsString::from("-E"),
            OsString::from("X=value"),
            OsString::from("-l"),
            OsString::from("@rustd-native-now-one"),
            OsString::from("-l"),
            OsString::from("@rustd-native-now-two"),
            OsString::from("/usr/bin/python3"),
            OsString::from("-c"),
            OsString::from(code),
        ])
        .output()
        .expect("run immediate activation");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"ok\n");
}

#[test]
fn stream_datagram_and_seqpacket_activation_deliver_payload() {
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
            arguments.push(OsString::from("--datagram"));
        } else if mode == "seqpacket" {
            arguments.push(OsString::from("--seqpacket"));
        }
        arguments.extend([
            OsString::from("-l"),
            path.as_os_str().to_owned(),
            OsString::from("/usr/bin/python3"),
            OsString::from("-c"),
            OsString::from(python),
        ]);
        let mut child = command()
            .args(&arguments)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn activation mode");
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
        let output = wait_with_output(child);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{mode}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"b'mode-payload'\n", "{mode}");
    }
}

#[test]
fn accept_inetd_and_safe_child_limit_use_rustd_listen_contract() {
    let response = accept_response(false, false);
    let text = String::from_utf8(response).expect("accept env utf8");
    assert!(
        text.contains("'1'") && text.contains("'accepted'") && text.contains("True"),
        "accept-mode activation environment: {text}"
    );

    assert_eq!(accept_response(true, false), b"inetd-echo");

    let raised = String::from_utf8(accept_response(false, true)).expect("raised limit utf8");
    // Accept children keep a safe soft NOFILE ceiling of 1024 even when the
    // activator itself was launched with a higher soft limit.
    assert!(
        raised.contains("(1024, "),
        "accept child RLIMIT_NOFILE: {raised}"
    );
}

#[test]
fn notification_and_filesystem_socket_lifecycle_are_native() {
    for arguments in [
        vec!["--help"],
        vec!["/bin/true"],
        vec!["--now", "-l", "@rustd-native-notify", "/definitely/missing"],
    ] {
        let (output, messages) = notification_messages(&arguments);
        assert!(
            messages.iter().any(|message| message == b"EXIT_STATUS=0"
                || message
                    .windows(b"EXIT_STATUS=".len())
                    .any(|w| w == b"EXIT_STATUS=")),
            "notification {arguments:?} messages={messages:?} status={:?}",
            output.status.code()
        );
    }

    let fixture = tempfile::tempdir().expect("create filesystem socket fixture");
    let first = fixture.path().join("first");
    let parent = first.join("second");
    let path = parent.join("activate.sock");
    let code = "import os; old=os.umask(0); os.umask(old); print(oct(old))";
    let mut process = command();
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
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"0o77\n");
    let socket = fs::symlink_metadata(&path).expect("stat socket node");
    assert!(socket.file_type().is_socket());
    // Bind temporarily applies umask 0133 so filesystem sockets land as 0644.
    assert_eq!(socket.mode() & 0o777, 0o644);
    assert_eq!(
        fs::metadata(&first).expect("stat first").mode() & 0o777,
        0o755
    );
    assert_eq!(
        fs::metadata(&parent).expect("stat second").mode() & 0o777,
        0o755
    );
}
