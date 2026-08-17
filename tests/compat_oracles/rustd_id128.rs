// SPDX-License-Identifier: LGPL-2.1-or-later

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

const MACHINE_OVERRIDE: &str = "SYSTEMD_ID128_MACHINE_ID_PATH";
const BOOT_OVERRIDE: &str = "SYSTEMD_ID128_BOOT_ID_PATH";
const RANDOM_OVERRIDE: &str = "SYSTEMD_ID128_RANDOM_PATH";

fn run(binary: &Path, arguments: &[&str], invocation: Option<&str>) -> Output {
    let mut command = Command::new(binary);
    command
        .args(arguments)
        .env("LC_ALL", "C")
        .env("SYSTEMD_COLORS", "0")
        .env("SYSTEMD_PAGER", "cat")
        .env_remove(MACHINE_OVERRIDE)
        .env_remove(BOOT_OVERRIDE)
        .env_remove(RANDOM_OVERRIDE);
    if let Some(value) = invocation {
        command.env("INVOCATION_ID", value);
    } else {
        command.env_remove("INVOCATION_ID");
    }
    command.output().expect("execute systemd-id128")
}

fn assert_same(arguments: &[&str], invocation: Option<&str>) {
    let host = run(Path::new("/usr/bin/systemd-id128"), arguments, invocation);
    let ours = run(
        Path::new(env!("CARGO_BIN_EXE_systemd-id128")),
        arguments,
        invocation,
    );
    assert_eq!(ours.status.code(), host.status.code(), "{arguments:?}");
    assert_eq!(ours.stdout, host.stdout, "stdout for {arguments:?}");
    assert_eq!(ours.stderr, host.stderr, "stderr for {arguments:?}");
}

fn live_oracle_enabled() -> bool {
    // Exclusive RustD keeps native branding/IPC. Opt into live systemd byte-parity
    // oracles only when explicitly certifying against a pinned host binary.
    host_is_pinned_v261() && std::env::var_os("RUSTD_LIVE_SYSTEMD_ORACLE").is_some()
}

fn host_is_pinned_v261() -> bool {
    Command::new("/usr/bin/systemd-id128")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.stdout.starts_with(b"systemd 261 "))
}

#[test]
fn complete_option_verb_and_error_surface_matches_live_v261() {
    if !live_oracle_enabled() {
        eprintln!("skipping live comparison: /usr/bin/systemd-id128 is not v261");
        return;
    }
    let cases: &[&[&str]] = &[
        &[],
        &["help"],
        &["--help"],
        &["--version"],
        &["machine-id"],
        &["-u", "machine-id"],
        &["boot-id"],
        &["-u", "boot-id"],
        &["var-partition-uuid"],
        &["show", "user-home"],
        &["show", "773f91ef-66d4-49b5-bd83-d683bf40ad16"],
        &["show", "11111111111111111111111111111111"],
        &["-Pu", "show", "user-home"],
        &["--no-legend", "show", "user-home", "swap"],
        &["--json=short", "show", "user-home", "swap"],
        &["--json=pretty", "--uuid", "show", "user-home"],
        &["--json=off", "show", "user-home"],
        &["--json=help", "show"],
        &["-jP", "show", "user-home"],
        &["-p", "show", "user-home", "swap"],
        &["-P", "-p", "show", "user-home"],
        &["-p", "-P", "show", "user-home"],
        &["-p", "-u", "show", "user-home"],
        &[
            "--app-specific=f0e0d0c0b0a090807060504030201000",
            "show",
            "user-home",
        ],
        &[
            "--app-specific=00000000000000000000000000000000",
            "machine-id",
        ],
        &["--app-specific=x", "machine-id"],
        &["--app-specific=f0e0d0c0b0a090807060504030201000", "new"],
        &[
            "--app-specific=f0e0d0c0b0a090807060504030201000",
            "invocation-id",
        ],
        &[
            "--app-specific=f0e0d0c0b0a090807060504030201000",
            "var-partition-uuid",
        ],
        &["--app-specific=f0e0d0c0b0a090807060504030201000", "show"],
        &["--json=short", "--pretty", "show", "user-home"],
        &["--json=short", "--value", "show", "user-home", "swap"],
        &["show", "unknown"],
        &["new", "extra"],
        &["unknown"],
        &["--unknown"],
        &["--app-specific"],
        &["-a"],
    ];
    for arguments in cases {
        assert_same(arguments, Some("000102030405060708090a0b0c0d0e0f"));
    }
    assert_same(&["invocation-id"], Some("000102030405060708090a0b0c0d0e0f"));
    assert_same(
        &["-u", "invocation-id"],
        Some("000102030405060708090a0b0c0d0e0f"),
    );
}

#[test]
fn full_gpt_inventory_matches_live_v261_in_table_value_and_json_modes() {
    if !live_oracle_enabled() {
        eprintln!("skipping live comparison: /usr/bin/systemd-id128 is not v261");
        return;
    }
    for arguments in [
        &["--no-pager", "show"][..],
        &["--no-pager", "--no-legend", "--uuid", "show"][..],
        &["--no-pager", "--value", "show"][..],
        &["--no-pager", "--json=short", "show"][..],
    ] {
        assert_same(arguments, None);
    }
}

#[test]
fn deterministic_fixture_seams_cover_all_dynamic_identifier_sources() {
    let root = tempfile::tempdir().expect("create ID fixture");
    let machine = root.path().join("machine-id");
    let boot_id_path = root.path().join("boot-id");
    let random = root.path().join("random");
    fs::write(&machine, "000102030405060708090a0b0c0d0e0f\n").expect("write machine ID");
    fs::write(&boot_id_path, "10213243-5465-4768-899a-abbccddeeff0\n").expect("write boot ID");
    fs::write(&random, (0_u8..16).collect::<Vec<_>>()).expect("write random fixture");

    let binary = Path::new(env!("CARGO_BIN_EXE_systemd-id128"));
    let run_fixture = |arguments: &[&str]| {
        Command::new(binary)
            .args(arguments)
            .env("LC_ALL", "C")
            .env("SYSTEMD_COLORS", "0")
            .env(MACHINE_OVERRIDE, &machine)
            .env(BOOT_OVERRIDE, &boot_id_path)
            .env(RANDOM_OVERRIDE, &random)
            .env("INVOCATION_ID", "ffeeddccbbaa49888776655443322110")
            .output()
            .expect("execute fixture candidate")
    };

    for (arguments, expected) in [
        (&["machine-id"][..], "000102030405060708090a0b0c0d0e0f\n"),
        (&["boot-id"][..], "1021324354654768899aabbccddeeff0\n"),
        (&["invocation-id"][..], "ffeeddccbbaa49888776655443322110\n"),
        (&["new"][..], "000102030405460788090a0b0c0d0e0f\n"),
        (
            &[
                "--app-specific=f0e0d0c0b0a090807060504030201000",
                "machine-id",
            ][..],
            "1a3c2557f70642cfa12514db12ae2a1d\n",
        ),
        (
            &["var-partition-uuid"][..],
            "6538a1706db6418d9483627aeed2ae32\n",
        ),
    ] {
        let output = run_fixture(arguments);
        assert!(output.status.success(), "{arguments:?}");
        assert_eq!(String::from_utf8(output.stdout).unwrap(), expected);
        assert_eq!(output.stderr, [] as [u8; 0]);
    }
}

#[test]
fn generated_id_has_uuid_v4_shape() {
    let output = run(
        Path::new(env!("CARGO_BIN_EXE_systemd-id128")),
        &["new"],
        None,
    );
    assert!(output.status.success());
    let value = String::from_utf8(output.stdout).unwrap();
    assert_eq!(value.len(), 33);
    assert_eq!(value.as_bytes()[12], b'4');
    assert!(matches!(value.as_bytes()[16], b'8' | b'9' | b'a' | b'b'));
}
