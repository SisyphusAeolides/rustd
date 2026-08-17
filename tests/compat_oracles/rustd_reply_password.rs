// SPDX-License-Identifier: LGPL-2.1-or-later

use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const HOST: &str = "/usr/lib/systemd/systemd-reply-password";
static ABSTRACT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn live_oracle_enabled() -> bool {
    // Exclusive RustD keeps native branding/IPC. Opt into live systemd byte-parity
    // oracles only when explicitly certifying against a pinned host binary.
    host_is_pinned_v261() && std::env::var_os("RUSTD_LIVE_SYSTEMD_ORACLE").is_some()
}

fn host_is_pinned_v261() -> bool {
    Path::new(HOST).is_file()
        && Command::new("/usr/bin/systemd-ac-power")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.stdout.starts_with(b"systemd 261 "))
}

fn execute(binary: &str, arguments: &[&OsStr], input: &[u8]) -> Output {
    let mut child = Command::new(binary)
        .args(arguments)
        .env("LC_ALL", "C")
        .env("SYSTEMD_COLORS", "0")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn systemd-reply-password");
    child
        .stdin
        .take()
        .expect("capture stdin")
        .write_all(input)
        .expect("write password input");
    child.wait_with_output().expect("wait for reply helper")
}

fn capture_filesystem(binary: &str, mode: &str, input: &[u8]) -> (Output, Vec<u8>) {
    let fixture = tempfile::tempdir().expect("create reply fixture");
    let path = fixture.path().join("reply.sock");
    let receiver = UnixDatagram::bind(&path).expect("bind reply receiver");
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set reply timeout");
    let output = execute(binary, &[OsStr::new(mode), path.as_os_str()], input);
    let mut packet = vec![0_u8; 4096];
    let length = receiver.recv(&mut packet).expect("receive reply packet");
    packet.truncate(length);
    (output, packet)
}

fn capture_abstract(binary: &str, input: &[u8]) -> (Output, Vec<u8>) {
    let sequence = ABSTRACT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let name = format!("rustd-reply-password-{}-{sequence}", std::process::id());
    let address = SocketAddr::from_abstract_name(name.as_bytes()).expect("form abstract address");
    let receiver = UnixDatagram::bind_addr(&address).expect("bind abstract reply receiver");
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set reply timeout");
    let argument = OsString::from_vec([b"@".as_slice(), name.as_bytes()].concat());
    let output = execute(binary, &[OsStr::new("1"), argument.as_os_str()], input);
    let mut packet = vec![0_u8; 4096];
    let length = receiver.recv(&mut packet).expect("receive abstract reply");
    packet.truncate(length);
    (output, packet)
}

fn assert_output_same(host: &Output, candidate: &Output, context: &str) {
    assert_eq!(candidate.status.code(), host.status.code(), "{context}");
    assert_eq!(candidate.stdout, host.stdout, "stdout: {context}");
    assert_eq!(candidate.stderr, host.stderr, "stderr: {context}");
}

#[test]
fn success_cancel_line_framing_and_abstract_delivery_match_live_v261() {
    if !live_oracle_enabled() {
        eprintln!("skipping live comparison: systemd package is not v261");
        return;
    }
    let candidate = env!("CARGO_BIN_EXE_systemd-reply-password");
    for (mode, input, expected) in [
        ("1", b"secret\n".as_slice(), b"+secret\0".as_slice()),
        ("1", b"\n", b"+\0"),
        ("1", b"windows\r\nignored", b"+windows\0"),
        ("1", b"old-mac\rignored", b"+old-mac\0"),
        ("1", b"nul\0ignored", b"+nul\0"),
        ("1", b"no-delimiter", b"+no-delimiter\0"),
        ("1", b"raw-\xff\n", b"+raw-\xff\0"),
        ("0", b"ignored\n", b"-"),
    ] {
        let (host_output, host_packet) = capture_filesystem(HOST, mode, input);
        let (our_output, our_packet) = capture_filesystem(candidate, mode, input);
        assert_output_same(&host_output, &our_output, &format!("{mode} {input:?}"));
        assert_eq!(host_packet, expected);
        assert_eq!(our_packet, host_packet);
    }

    let (host_output, host_packet) = capture_abstract(HOST, b"abstract\n");
    let (our_output, our_packet) = capture_abstract(candidate, b"abstract\n");
    assert_output_same(&host_output, &our_output, "abstract socket");
    assert_eq!(our_packet, host_packet);
    assert_eq!(our_packet, b"+abstract\0");
}

#[test]
fn complete_argument_path_eof_and_line_limit_errors_match_live_v261() {
    if !live_oracle_enabled() {
        eprintln!("skipping live comparison: systemd package is not v261");
        return;
    }
    let candidate = env!("CARGO_BIN_EXE_systemd-reply-password");
    let cases: Vec<(Vec<OsString>, Vec<u8>)> = vec![
        (vec![], vec![]),
        (vec![OsString::from("--help")], vec![]),
        (vec![OsString::from("1")], vec![]),
        (vec![OsString::from("x"), OsString::from("/unused")], vec![]),
        (vec![OsString::from("1"), OsString::from("/unused")], vec![]),
        (
            vec![OsString::from("0"), OsString::from("relative")],
            vec![],
        ),
        (vec![OsString::from("0"), OsString::from("@")], vec![]),
        (
            vec![
                OsString::from("0"),
                OsString::from("/definitely/missing/reply-password.sock"),
            ],
            vec![],
        ),
        (
            vec![
                OsString::from("0"),
                OsString::from(format!("/{}", "x".repeat(107))),
            ],
            vec![],
        ),
        (
            vec![OsString::from("1"), OsString::from("/unused")],
            vec![b'x'; 1024 * 1024],
        ),
    ];

    for (arguments, input) in cases {
        let references: Vec<&OsStr> = arguments.iter().map(OsString::as_os_str).collect();
        let host = execute(HOST, &references, &input);
        let ours = execute(candidate, &references, &input);
        assert_output_same(&host, &ours, &format!("{arguments:?}"));
    }
}
