// SPDX-License-Identifier: LGPL-2.1-or-later

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Read;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const HOST: &str = "/usr/lib/systemd/systemd-battery-check";
const LOW_MESSAGE: &str =
    "Battery level critically low. Please connect your charger or the system will power off in 10 seconds.";

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

fn plain(binary: &str, arguments: &[&OsStr]) -> Output {
    Command::new(binary)
        .args(arguments)
        .env("LC_ALL", "C")
        .env("SYSTEMD_COLORS", "0")
        .env_remove("RUSTD_BATTERY_CHECK_CMDLINE")
        .env_remove("RUSTD_BATTERY_CHECK_SYSFS_ROOT")
        .env_remove("RUSTD_BATTERY_CHECK_DELAY_MS")
        .env_remove("RUSTD_BATTERY_CHECK_CONSOLE")
        .env_remove("RUSTD_BATTERY_CHECK_PLYMOUTH")
        .output()
        .expect("execute systemd-battery-check")
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

struct Fixture {
    root: tempfile::TempDir,
}

impl Fixture {
    fn new(capacity: &str) -> Self {
        let root = tempfile::tempdir().expect("create battery fixture");
        let class = root.path().join("class");
        let battery = class.join("power_supply/BAT0");
        fs::create_dir_all(&battery).expect("create battery");
        fs::create_dir_all(class.join("typec")).expect("create type-c class");
        for (name, value) in [
            ("type", "Battery"),
            ("present", "1"),
            ("status", "Discharging"),
            ("capacity", capacity),
        ] {
            fs::write(battery.join(name), format!("{value}\n")).expect("write attribute");
        }
        Self { root }
    }

    fn class(&self) -> PathBuf {
        self.root.path().join("class")
    }

    fn capacity(&self) -> PathBuf {
        self.class().join("power_supply/BAT0/capacity")
    }
}

fn fixture_command(fixture: &Fixture, console: &Path, plymouth: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_systemd-battery-check"));
    command
        .env("LC_ALL", "C")
        .env("SYSTEMD_COLORS", "0")
        .env("SYSTEMD_LOG_TARGET", "null")
        .env("RUSTD_BATTERY_CHECK_CMDLINE", "quiet")
        .env("RUSTD_BATTERY_CHECK_SYSFS_ROOT", fixture.class())
        .env("RUSTD_BATTERY_CHECK_DELAY_MS", "200")
        .env("RUSTD_BATTERY_CHECK_CONSOLE", console)
        .env("RUSTD_BATTERY_CHECK_PLYMOUTH", plymouth);
    command
}

fn receive(listener: &UnixListener) -> Vec<u8> {
    let (mut stream, _) = listener.accept().expect("accept Plymouth message");
    let mut bytes = Vec::new();
    stream
        .read_to_end(&mut bytes)
        .expect("read Plymouth message");
    bytes
}

fn plymouth_payload(mode: &str, message: &str) -> Vec<u8> {
    let mut bytes = vec![b'C', 2, u8::try_from(mode.len() + 1).expect("mode length")];
    bytes.extend_from_slice(mode.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&[
        b'M',
        2,
        u8::try_from(message.len() + 1).expect("message length"),
    ]);
    bytes.extend_from_slice(message.as_bytes());
    bytes.push(0);
    bytes
}

#[test]
fn complete_option_and_default_runtime_matches_live_v261() {
    if !live_oracle_enabled() {
        eprintln!("skipping live comparison: systemd package is not v261");
        return;
    }
    let candidate = env!("CARGO_BIN_EXE_systemd-battery-check");
    let cases: Vec<Vec<OsString>> = vec![
        vec![],
        vec![OsString::from("--help")],
        vec![OsString::from("--version")],
        vec![OsString::from("--h")],
        vec![OsString::from("--v")],
        vec![OsString::from("-h")],
        vec![OsString::from("-hx")],
        vec![OsString::from("-x")],
        vec![OsString::from("--help=x")],
        vec![OsString::from("--=x")],
        vec![OsString::from("argument")],
        vec![OsString::from("--"), OsString::from("argument")],
        vec![OsString::from_vec(vec![b'-', b'-', 0xff])],
        vec![OsString::from_vec(vec![0xff])],
    ];
    for arguments in cases {
        let references: Vec<&OsStr> = arguments.iter().map(OsString::as_os_str).collect();
        assert_same(
            &plain(HOST, &references),
            &plain(candidate, &references),
            &format!("{arguments:?}"),
        );
    }
}

#[test]
fn kernel_command_line_disable_and_invalid_value_contract() {
    let binary = env!("CARGO_BIN_EXE_systemd-battery-check");
    for cmdline in [
        "systemd.battery_check=0",
        "rd.systemd.battery_check=no",
        "systemd.battery_check=1 systemd.battery_check=off",
    ] {
        let output = Command::new(binary)
            .env("RUSTD_BATTERY_CHECK_CMDLINE", cmdline)
            .env("SYSTEMD_LOG_TARGET", "null")
            .output()
            .expect("run disabled battery check");
        assert_eq!(output.status.code(), Some(0), "{cmdline}");
        assert!(output.stdout.is_empty() && output.stderr.is_empty());
    }
    let output = Command::new(binary)
        .env(
            "RUSTD_BATTERY_CHECK_CMDLINE",
            "systemd.battery_check=invalid",
        )
        .env("SYSTEMD_LOG_TARGET", "null")
        .output()
        .expect("run invalid battery option");
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn charged_unreadable_and_ac_power_states_skip_the_warning_path() {
    let binary = env!("CARGO_BIN_EXE_systemd-battery-check");
    for (capacity, with_ac) in [("6", false), ("invalid", false), ("1", true)] {
        let fixture = Fixture::new(capacity);
        if with_ac {
            let mains = fixture.class().join("power_supply/AC");
            fs::create_dir(&mains).expect("create AC supply");
            fs::write(mains.join("type"), "Mains\n").expect("write AC type");
            fs::write(mains.join("online"), "1\n").expect("write AC state");
        }
        let output = Command::new(binary)
            .env("RUSTD_BATTERY_CHECK_CMDLINE", "quiet")
            .env("RUSTD_BATTERY_CHECK_SYSFS_ROOT", fixture.class())
            .env("SYSTEMD_LOG_TARGET", "null")
            .output()
            .expect("run non-low battery check");
        assert_eq!(output.status.code(), Some(0), "{capacity}, AC={with_ac}");
        assert!(output.stdout.is_empty() && output.stderr.is_empty());
    }
}

#[test]
fn low_battery_console_plymouth_delay_and_positive_failure_contract() {
    let fixture = Fixture::new("5");
    let temporary = tempfile::tempdir().expect("create output fixture");
    let console = temporary.path().join("console");
    let socket = temporary.path().join("plymouth.sock");
    let listener = UnixListener::bind(&socket).expect("bind Plymouth socket");
    let mut child = fixture_command(&fixture, &console, &socket)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn low battery check");
    let shutdown = receive(&listener);
    assert!(
        child
            .try_wait()
            .expect("query sleeping battery check")
            .is_none(),
        "the deterministic delay seam must retain the recheck wait"
    );
    let output = child.wait_with_output().expect("wait for battery check");
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    assert_eq!(
        shutdown,
        plymouth_payload("shutdown", &format!("🪫 {LOW_MESSAGE}"))
    );
    assert_eq!(
        fs::read(console).expect("read console"),
        format!("\x1b[0;1;31m! {LOW_MESSAGE}\x1b[0m\n").as_bytes()
    );
}

#[test]
fn restored_power_sends_exact_second_console_and_plymouth_messages() {
    let fixture = Fixture::new("3");
    let temporary = tempfile::tempdir().expect("create output fixture");
    let console = temporary.path().join("console");
    let socket = temporary.path().join("plymouth.sock");
    let listener = UnixListener::bind(&socket).expect("bind Plymouth socket");
    let child = fixture_command(&fixture, &console, &socket)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn restoring battery check");
    let shutdown = receive(&listener);
    fs::write(fixture.capacity(), "90\n").expect("restore battery capacity");
    let restored = receive(&listener);
    let output = child.wait_with_output().expect("wait for battery check");
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    assert_eq!(
        shutdown,
        plymouth_payload("shutdown", &format!("🪫 {LOW_MESSAGE}"))
    );
    assert_eq!(
        restored,
        plymouth_payload("boot-up", "A.C. power restored, continuing.")
    );
    assert_eq!(
        fs::read(console).expect("read console"),
        format!("\x1b[0;1;31m! {LOW_MESSAGE}\x1b[0m\nA.C. power restored, continuing.\n")
            .as_bytes()
    );
}
