// SPDX-License-Identifier: LGPL-2.1-or-later

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

fn host_is_pinned_v261() -> bool {
    Command::new("/usr/bin/systemd-mute-console")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.stdout.starts_with(b"systemd 261 "))
}

fn plain(binary: &str, arguments: &[&str]) -> Output {
    Command::new(binary)
        .args(arguments)
        .env("LC_ALL", "C")
        .env("SYSTEMD_COLORS", "0")
        .env_remove("SYSTEMD_VARLINK_LISTEN")
        .env_remove("LISTEN_FDS")
        .env_remove("LISTEN_PID")
        .env_remove("LISTEN_FDNAMES")
        .output()
        .expect("execute systemd-mute-console")
}

fn wait_for_path(path: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while !path.exists() {
        assert!(Instant::now() < deadline, "timed out waiting for {path:?}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn signal(child: &Child, name: &str) {
    assert!(Command::new("kill")
        .args([name, &child.id().to_string()])
        .status()
        .expect("signal child")
        .success());
}

fn read_notify(socket: &UnixDatagram) -> Vec<u8> {
    let mut buffer = [0_u8; 4096];
    let length = socket.recv(&mut buffer).expect("receive notification");
    buffer[..length].to_vec()
}

fn varlink_call(
    stream: &mut UnixStream,
    reader: &mut BufReader<UnixStream>,
    request: &Value,
) -> Value {
    serde_json::to_writer(&mut *stream, request).expect("write Varlink request");
    stream.write_all(&[0]).expect("terminate Varlink request");
    stream.flush().expect("flush Varlink request");
    let mut response = Vec::new();
    reader
        .read_until(0, &mut response)
        .expect("read Varlink response");
    assert_eq!(response.pop(), Some(0));
    serde_json::from_slice(&response).expect("parse Varlink response")
}

fn start_varlink(binary: &str, fixture: &tempfile::TempDir) -> (Child, UnixStream) {
    let socket = fixture.path().join("mute-console.sock");
    let child = Command::new(binary)
        .env("LC_ALL", "C")
        .env("SYSTEMD_VARLINK_LISTEN", &socket)
        .env("RUSTD_MUTE_CONSOLE_CONTAINER", "no")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn Varlink server");
    wait_for_path(&socket);
    let stream = UnixStream::connect(socket).expect("connect Varlink server");
    (child, stream)
}

fn capture_varlink(binary: &str, requests: &[Value]) -> Vec<Value> {
    let fixture = tempfile::tempdir().expect("create Varlink capture fixture");
    let (mut child, mut stream) = start_varlink(binary, &fixture);
    let mut reader = BufReader::new(stream.try_clone().expect("clone Varlink stream"));
    let replies = requests
        .iter()
        .map(|request| varlink_call(&mut stream, &mut reader, request))
        .collect();
    drop(reader);
    drop(stream);
    assert_eq!(child.wait().expect("wait Varlink server").code(), Some(0));
    replies
}

#[test]
fn complete_option_help_version_and_error_surface_matches_live_v261() {
    if !host_is_pinned_v261() {
        eprintln!("skipping live comparison: systemd-mute-console is not v261");
        return;
    }
    let candidate = env!("CARGO_BIN_EXE_systemd-mute-console");
    let cases: &[&[&str]] = &[
        &["--help"],
        &["-h"],
        &["--he"],
        &["--version"],
        &["--ver"],
        &["--kernel"],
        &["--pid1"],
        &["--kernel=x"],
        &["--pid1=x"],
        &["--kernel=no", "--pid1=no"],
        &["--k=no", "--p=no"],
        &["--kernel=no", "--pid1=no", "extra"],
        &["extra", "--kernel=no", "--pid1=no"],
        &["-hh"],
        &["-hx"],
        &["--kernel=no", "--pid1=no", "-"],
        &["-xh", "--kernel=no", "--pid1=no"],
        &["--unknown"],
        &["-x"],
        &["--help=x"],
    ];
    for arguments in cases {
        let host = plain("/usr/bin/systemd-mute-console", arguments);
        let ours = plain(candidate, arguments);
        assert_eq!(ours.status.code(), host.status.code(), "{arguments:?}");
        assert_eq!(ours.stdout, host.stdout, "stdout {arguments:?}");
        assert_eq!(ours.stderr, host.stderr, "stderr {arguments:?}");
    }
}

#[test]
fn mute_lifecycle_changes_and_restores_pid1_printk_and_notify_state() {
    let fixture = tempfile::tempdir().expect("create mute fixture");
    let printk = fixture.path().join("printk");
    let pid1 = fixture.path().join("pid1.log");
    let notify_path = fixture.path().join("notify.sock");
    fs::write(&printk, "3\t3\t3\t3\n").expect("seed printk");
    let notify = UnixDatagram::bind(&notify_path).expect("bind notify socket");
    notify
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set notify timeout");
    let mut child = Command::new(env!("CARGO_BIN_EXE_systemd-mute-console"))
        .env("LC_ALL", "C")
        .env("NOTIFY_SOCKET", &notify_path)
        .env("RUSTD_MUTE_CONSOLE_PRINTK", &printk)
        .env("RUSTD_MUTE_CONSOLE_PID1_LOG", &pid1)
        .env("RUSTD_MUTE_CONSOLE_CONTAINER", "no")
        .spawn()
        .expect("spawn mute lifecycle");
    assert_eq!(
        read_notify(&notify),
        b"READY=1\nSTATUS=Console status output muted temporarily."
    );
    assert_eq!(
        fs::read_to_string(&printk).expect("read muted printk"),
        "0\n"
    );
    assert_eq!(fs::read_to_string(&pid1).expect("read pid1 log"), "no\n");
    signal(&child, "-TERM");
    assert_eq!(
        read_notify(&notify),
        b"STOPPING=1\nSTATUS=Console status output unmuted."
    );
    assert_eq!(child.wait().expect("wait mute lifecycle").code(), Some(0));
    assert_eq!(
        fs::read_to_string(&printk).expect("read restored printk"),
        "3\n"
    );
    assert_eq!(
        fs::read_to_string(&pid1).expect("read restored pid1 log"),
        "no\n<empty>\n"
    );
}

#[test]
fn externally_changed_printk_is_not_restored_and_container_skips_it() {
    let fixture = tempfile::tempdir().expect("create external fixture");
    let printk = fixture.path().join("printk");
    let notify_path = fixture.path().join("notify.sock");
    fs::write(&printk, "5\n").expect("seed printk");
    let notify = UnixDatagram::bind(&notify_path).expect("bind notify socket");
    notify
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set notify timeout");
    let mut child = Command::new(env!("CARGO_BIN_EXE_systemd-mute-console"))
        .args(["--pid1=no"])
        .env("NOTIFY_SOCKET", &notify_path)
        .env("RUSTD_MUTE_CONSOLE_PRINTK", &printk)
        .env("RUSTD_MUTE_CONSOLE_CONTAINER", "no")
        .spawn()
        .expect("spawn external-change lifecycle");
    let _ = read_notify(&notify);
    fs::write(&printk, "4\n").expect("externally change printk");
    signal(&child, "-TERM");
    let _ = read_notify(&notify);
    assert_eq!(
        child.wait().expect("wait external lifecycle").code(),
        Some(0)
    );
    assert_eq!(
        fs::read_to_string(&printk).expect("read external printk"),
        "4\n"
    );

    fs::write(&printk, "6\n").expect("seed container printk");
    let mut container = Command::new(env!("CARGO_BIN_EXE_systemd-mute-console"))
        .args(["--pid1=no"])
        .env("NOTIFY_SOCKET", &notify_path)
        .env("RUSTD_MUTE_CONSOLE_PRINTK", &printk)
        .env("RUSTD_MUTE_CONSOLE_CONTAINER", "yes")
        .spawn()
        .expect("spawn container lifecycle");
    let _ = read_notify(&notify);
    assert_eq!(
        fs::read_to_string(&printk).expect("read container printk"),
        "6\n"
    );
    signal(&container, "-TERM");
    let _ = read_notify(&notify);
    assert_eq!(
        container.wait().expect("wait container lifecycle").code(),
        Some(0)
    );
    assert_eq!(
        fs::read_to_string(&printk).expect("read skipped printk"),
        "6\n"
    );
}

#[test]
fn varlink_service_metadata_errors_and_harmless_mute_match_live_v261() {
    if !host_is_pinned_v261() {
        return;
    }
    let requests = [
        json!({"method":"org.varlink.service.GetInfo","parameters":{}}),
        json!({"method":"org.varlink.service.GetInterfaceDescription","parameters":{"interface":"io.systemd.MuteConsole"}}),
        json!({"method":"org.varlink.service.GetInterfaceDescription","parameters":{"interface":"no.such"}}),
        json!({"method":"io.systemd.MuteConsole.NoSuch","parameters":{}}),
        json!({"method":"io.systemd.MuteConsole.Mute","parameters":{"kernel":false,"pid1":false}}),
        json!({"method":"io.systemd.MuteConsole.Mute","parameters":{"kernel":false,"pid1":false},"more":true}),
    ];

    let host = capture_varlink("/usr/bin/systemd-mute-console", &requests);
    let ours = capture_varlink(env!("CARGO_BIN_EXE_systemd-mute-console"), &requests);
    assert_eq!(ours, host);
}

#[test]
fn varlink_mute_lifetime_restores_resources_on_disconnect() {
    let fixture = tempfile::tempdir().expect("create Varlink lifetime fixture");
    let printk = fixture.path().join("printk");
    let pid1 = fixture.path().join("pid1.log");
    fs::write(&printk, "7\n").expect("seed Varlink printk");
    let socket = fixture.path().join("mute.sock");
    let mut child = Command::new(env!("CARGO_BIN_EXE_systemd-mute-console"))
        .env("SYSTEMD_VARLINK_LISTEN", &socket)
        .env("RUSTD_MUTE_CONSOLE_PRINTK", &printk)
        .env("RUSTD_MUTE_CONSOLE_PID1_LOG", &pid1)
        .env("RUSTD_MUTE_CONSOLE_CONTAINER", "no")
        .spawn()
        .expect("spawn Varlink lifetime server");
    wait_for_path(&socket);
    let mut stream = UnixStream::connect(socket).expect("connect lifetime server");
    let mut reader = BufReader::new(stream.try_clone().expect("clone lifetime stream"));
    assert_eq!(
        varlink_call(
            &mut stream,
            &mut reader,
            &json!({"method":"io.systemd.MuteConsole.Mute","parameters":{},"more":true}),
        ),
        json!({"continues":true})
    );
    assert_eq!(
        fs::read_to_string(&printk).expect("read muted printk"),
        "0\n"
    );
    assert_eq!(fs::read_to_string(&pid1).expect("read muted pid1"), "no\n");
    drop(reader);
    drop(stream);
    assert_eq!(child.wait().expect("wait lifetime server").code(), Some(0));
    assert_eq!(
        fs::read_to_string(&printk).expect("read restored printk"),
        "7\n"
    );
    assert_eq!(
        fs::read_to_string(&pid1).expect("read restored pid1"),
        "no\n<empty>\n"
    );
}

#[test]
fn accepted_socket_activation_descriptor_runs_the_same_varlink_service() {
    let (mut parent, child_socket) = UnixStream::pair().expect("create activation socket pair");
    let child_socket: OwnedFd = child_socket.into();
    let candidate = env!("CARGO_BIN_EXE_systemd-mute-console");
    let mut child = Command::new("sh")
        .args([
            "-c",
            "exec 3<&0; export LISTEN_PID=$$ LISTEN_FDS=1 LISTEN_FDNAMES=varlink; exec \"$1\"",
            "sh",
            candidate,
        ])
        .stdin(Stdio::from(child_socket))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn socket-activated server");
    let mut reader = BufReader::new(parent.try_clone().expect("clone activated stream"));
    let info = varlink_call(
        &mut parent,
        &mut reader,
        &json!({"method":"org.varlink.service.GetInfo","parameters":{}}),
    );
    assert_eq!(
        info["parameters"]["interfaces"],
        json!([
            "io.systemd",
            "io.systemd.MuteConsole",
            "org.varlink.service"
        ])
    );
    assert_eq!(
        varlink_call(
            &mut parent,
            &mut reader,
            &json!({"method":"io.systemd.MuteConsole.Mute","parameters":{"kernel":false,"pid1":false},"more":true}),
        ),
        json!({"continues":true})
    );
    drop(reader);
    drop(parent);
    assert_eq!(child.wait().expect("wait activated server").code(), Some(0));
}
