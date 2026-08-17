// SPDX-License-Identifier: LGPL-2.1-or-later

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SYSFS_OVERRIDE: &str = "SYSTEMD_AC_POWER_SYSFS_ROOT";

fn run(binary: &Path, arguments: &[&str]) -> Output {
    Command::new(binary)
        .args(arguments)
        .env("LC_ALL", "C")
        .env("SYSTEMD_COLORS", "0")
        .env_remove(SYSFS_OVERRIDE)
        .output()
        .expect("execute systemd-ac-power")
}

fn run_fixture(binary: &Path, arguments: &[&str], sysfs: &Path) -> Output {
    Command::new(binary)
        .args(arguments)
        .env("LC_ALL", "C")
        .env("SYSTEMD_COLORS", "0")
        .env(SYSFS_OVERRIDE, sysfs)
        .output()
        .expect("execute candidate systemd-ac-power")
}

fn live_oracle_enabled() -> bool {
    // Exclusive RustD keeps native branding/IPC. Opt into live systemd byte-parity
    // oracles only when explicitly certifying against a pinned host binary.
    host_is_pinned_v261() && std::env::var_os("RUSTD_LIVE_SYSTEMD_ORACLE").is_some()
}

fn host_is_pinned_v261() -> bool {
    Command::new("/usr/bin/systemd-ac-power")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.stdout.starts_with(b"systemd 261 "))
}

fn assert_same(host: &Output, candidate: &Output, arguments: &[&str]) {
    assert_eq!(candidate.status.code(), host.status.code(), "{arguments:?}");
    assert_eq!(candidate.stdout, host.stdout, "stdout for {arguments:?}");
    assert_eq!(candidate.stderr, host.stderr, "stderr for {arguments:?}");
}

#[test]
fn option_and_output_contracts_match_the_live_pinned_host() {
    if !live_oracle_enabled() {
        eprintln!("skipping live comparison: /usr/bin/systemd-ac-power is not v261");
        return;
    }
    let candidate = Path::new(env!("CARGO_BIN_EXE_systemd-ac-power"));
    let cases: &[&[&str]] = &[
        &[],
        &["--verbose"],
        &["--low"],
        &["--low", "--verbose"],
        &["-vv"],
        &["--help"],
        &["--version"],
        &["--v"],
        &["--ve"],
        &["--verb"],
        &["--unknown"],
        &["-x"],
        &["--verbose=value"],
        &["--low=value"],
        &["argument"],
        &["--", "argument"],
        &["--version", "--unknown"],
        &["--unknown", "--version"],
        &["-vh"],
    ];
    for arguments in cases {
        let host = run(Path::new("/usr/bin/systemd-ac-power"), arguments);
        let ours = run(candidate, arguments);
        assert_same(&host, &ours, arguments);
    }
}

struct Fixture {
    root: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("create sysfs fixture");
        fs::create_dir_all(root.path().join("class/power_supply"))
            .expect("create power supply class");
        fs::create_dir_all(root.path().join("class/typec")).expect("create type-c class");
        Self { root }
    }

    fn sysfs(&self) -> PathBuf {
        self.root.path().join("class")
    }

    fn power_supply(&self, name: &str, attributes: &[(&str, &str)]) -> PathBuf {
        let device = self.sysfs().join("power_supply").join(name);
        fs::create_dir_all(&device).expect("create synthetic power supply");
        for (attribute, value) in attributes {
            fs::write(device.join(attribute), format!("{value}\n"))
                .expect("write power supply attribute");
        }
        device
    }

    fn usb_with_role(&self, role: &str) {
        let controller = self.root.path().join("devices/controller");
        let usb = controller.join("power_supply/USB0");
        let port = controller.join("typec/port0");
        fs::create_dir_all(&usb).expect("create USB power supply device");
        fs::create_dir_all(&port).expect("create type-c port device");
        fs::write(usb.join("type"), "USB\n").expect("write USB type");
        fs::write(usb.join("online"), "1\n").expect("write USB online state");
        fs::write(port.join("power_role"), format!("{role}\n")).expect("write power role");
        symlink(&usb, self.sysfs().join("power_supply/USB0"))
            .expect("link USB power supply into class");
        symlink(&port, self.sysfs().join("typec/port0")).expect("link port into class");
    }
}

fn assert_state(sysfs: &Path, arguments: &[&str], code: i32, stdout: &[u8]) {
    let output = run_fixture(
        Path::new(env!("CARGO_BIN_EXE_systemd-ac-power")),
        arguments,
        sysfs,
    );
    assert_eq!(output.status.code(), Some(code), "{arguments:?}");
    assert_eq!(output.stdout, stdout, "stdout for {arguments:?}");
    assert!(output.stderr.is_empty(), "stderr for {arguments:?}");
}

#[test]
fn synthetic_sysfs_matches_v261_ac_and_battery_rules() {
    let empty = Fixture::new();
    assert_state(&empty.sysfs(), &["--verbose"], 0, b"yes\n");
    assert_state(&empty.sysfs(), &["--low", "--verbose"], 1, b"no\n");

    let discharging = Fixture::new();
    discharging.power_supply(
        "BAT0",
        &[
            ("type", "Battery"),
            ("present", "1"),
            ("status", "Discharging"),
            ("capacity", "5"),
        ],
    );
    assert_state(&discharging.sysfs(), &["--verbose"], 1, b"no\n");
    assert_state(&discharging.sysfs(), &["--low", "--verbose"], 0, b"yes\n");

    let online = Fixture::new();
    online.power_supply(
        "BAT0",
        &[
            ("type", "Battery"),
            ("present", "1"),
            ("status", "Discharging"),
            ("capacity", "1"),
        ],
    );
    online.power_supply("AC", &[("type", "Mains"), ("online", "2")]);
    assert_state(&online.sysfs(), &["--verbose"], 0, b"yes\n");
    assert_state(&online.sysfs(), &["--low", "--verbose"], 1, b"no\n");

    let device_battery = Fixture::new();
    device_battery.power_supply(
        "peripheral",
        &[
            ("type", "Battery"),
            ("scope", "Device"),
            ("present", "1"),
            ("status", "Discharging"),
            ("capacity", "1"),
        ],
    );
    assert_state(&device_battery.sysfs(), &["--verbose"], 0, b"yes\n");
}

#[test]
fn low_requires_every_enumerated_battery_to_be_readable_and_at_most_five_percent() {
    let charged = Fixture::new();
    charged.power_supply(
        "BAT0",
        &[
            ("type", "Battery"),
            ("present", "1"),
            ("status", "Discharging"),
            ("capacity", "4"),
        ],
    );
    charged.power_supply(
        "BAT1",
        &[
            ("type", "Battery"),
            ("present", "1"),
            ("status", "Discharging"),
            ("capacity", "6"),
        ],
    );
    assert_state(&charged.sysfs(), &["--low", "-v"], 1, b"no\n");

    let unreadable = Fixture::new();
    unreadable.power_supply(
        "BAT0",
        &[
            ("type", "Battery"),
            ("present", "1"),
            ("status", "Discharging"),
            ("capacity", "4"),
        ],
    );
    unreadable.power_supply(
        "BAT1",
        &[
            ("type", "Battery"),
            ("present", "1"),
            ("status", "Discharging"),
            ("capacity", "invalid"),
        ],
    );
    assert_state(&unreadable.sysfs(), &["--low", "-v"], 1, b"no\n");
}

#[test]
fn usb_type_c_source_is_ignored_and_sink_is_external_power() {
    let source = Fixture::new();
    source.power_supply(
        "BAT0",
        &[
            ("type", "Battery"),
            ("present", "1"),
            ("status", "Discharging"),
            ("capacity", "50"),
        ],
    );
    source.usb_with_role("[source] sink");
    assert_state(&source.sysfs(), &["--verbose"], 1, b"no\n");

    let sink = Fixture::new();
    sink.power_supply(
        "BAT0",
        &[
            ("type", "Battery"),
            ("present", "1"),
            ("status", "Discharging"),
            ("capacity", "50"),
        ],
    );
    sink.usb_with_role("source [sink]");
    assert_state(&sink.sysfs(), &["--verbose"], 0, b"yes\n");
}
