// SPDX-License-Identifier: LGPL-2.1-or-later

use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::path::Path;
use std::process::{Command, Output};

const HOST: &str = "/usr/lib/systemd/systemd-update-utmp";
const RECORD_SIZE: usize = 384;

fn host_is_pinned_v261() -> bool {
    Path::new(HOST).is_file()
        && Command::new("/usr/bin/systemd-ac-power")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.stdout.starts_with(b"systemd 261 "))
}

fn plain(binary: &str, arguments: &[&OsStr]) -> Output {
    Command::new(binary)
        .args(arguments)
        .env("LC_ALL", "C")
        .env("SYSTEMD_COLORS", "0")
        .env_remove("RUSTD_UPDATE_UTMP_UTMP")
        .env_remove("RUSTD_UPDATE_UTMP_WTMP")
        .env_remove("RUSTD_UPDATE_UTMP_TIMESTAMP_USEC")
        .env_remove("RUSTD_UPDATE_UTMP_REBOOT_USEC")
        .env_remove("RUSTD_UPDATE_UTMP_AUDIT_LOG")
        .env_remove("RUSTD_UPDATE_UTMP_MANAGER_ERROR")
        .env_remove("RUSTD_UPDATE_UTMP_MONOTONIC_NOW_USEC")
        .env_remove("RUSTD_UPDATE_UTMP_REALTIME_NOW_USEC")
        .output()
        .expect("execute systemd-update-utmp")
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

fn empty_file(path: &Path) {
    fs::File::create(path).expect("create empty accounting file");
}

fn run_host_isolated(verb: &str, accounting: &Path, history: &Path) -> Output {
    Command::new("unshare")
        .args(["--user", "--map-root-user", "--mount", "sh", "-ceu"])
        .arg("mount --bind \"$1\" /run/utmp; mount --bind \"$2\" /var/log/wtmp; exec \"$3\" \"$4\"")
        .arg("systemd-update-utmp-oracle")
        .arg(accounting)
        .arg(history)
        .arg(HOST)
        .arg(verb)
        .env("LC_ALL", "C")
        .env("SYSTEMD_COLORS", "0")
        .output()
        .expect("execute isolated host update-utmp")
}

fn record_timestamp(record: &[u8]) -> u64 {
    assert_eq!(record.len(), RECORD_SIZE);
    let seconds = i32::from_ne_bytes(record[340..344].try_into().expect("seconds field"));
    let micros = i32::from_ne_bytes(record[344..348].try_into().expect("micros field"));
    u64::try_from(seconds).expect("positive seconds") * 1_000_000
        + u64::try_from(micros).expect("positive micros")
}

fn run_candidate(
    verb: &str,
    accounting: &Path,
    history: &Path,
    timestamp: u64,
    audit: &Path,
) -> Output {
    Command::new(env!("CARGO_BIN_EXE_systemd-update-utmp"))
        .arg(verb)
        .env("LC_ALL", "C")
        .env("SYSTEMD_COLORS", "0")
        .env("SYSTEMD_LOG_TARGET", "null")
        .env("RUSTD_UPDATE_UTMP_UTMP", accounting)
        .env("RUSTD_UPDATE_UTMP_WTMP", history)
        .env(
            "RUSTD_UPDATE_UTMP_TIMESTAMP_USEC",
            timestamp.to_string(),
        )
        .env("RUSTD_UPDATE_UTMP_AUDIT_LOG", audit)
        .output()
        .expect("execute candidate update-utmp")
}

#[test]
fn complete_verb_error_and_raw_byte_surface_matches_live_v261() {
    if !host_is_pinned_v261() {
        eprintln!("skipping live comparison: systemd package is not v261");
        return;
    }
    let candidate = env!("CARGO_BIN_EXE_systemd-update-utmp");
    let cases: Vec<Vec<OsString>> = vec![
        vec![],
        vec![OsString::from("foo")],
        vec![OsString::from("reboo")],
        vec![OsString::from("shutdow")],
        vec![OsString::from("poweroff")],
        vec![OsString::from("--help")],
        vec![OsString::from("--version")],
        vec![OsString::from("REBOOT")],
        vec![OsString::from("reboot"), OsString::from("extra")],
        vec![OsString::from("shutdown"), OsString::from("extra")],
        vec![OsString::from_vec(vec![0xff])],
        vec![OsString::from_vec(vec![b'r', 0xff])],
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
fn isolated_reboot_and_shutdown_records_match_live_v261_byte_for_byte() {
    if !host_is_pinned_v261() {
        eprintln!("skipping live comparison: systemd package is not v261");
        return;
    }
    for verb in ["reboot", "shutdown"] {
        let host_temp = tempfile::tempdir().expect("create host accounting fixture");
        let host_accounting = host_temp.path().join("utmp");
        let host_history = host_temp.path().join("wtmp");
        empty_file(&host_accounting);
        empty_file(&host_history);
        let host_output = run_host_isolated(verb, &host_accounting, &host_history);
        assert_eq!(host_output.status.code(), Some(0), "host {verb}");
        let host_record = fs::read(&host_accounting).expect("read host accounting record");
        assert_eq!(host_record.len(), RECORD_SIZE);
        assert_eq!(
            fs::read(&host_history).expect("read host history"),
            host_record
        );

        let candidate_temp = tempfile::tempdir().expect("create candidate accounting fixture");
        let candidate_accounting = candidate_temp.path().join("utmp");
        let candidate_history = candidate_temp.path().join("wtmp");
        let audit = candidate_temp.path().join("audit");
        empty_file(&candidate_accounting);
        empty_file(&candidate_history);
        let candidate_output = run_candidate(
            verb,
            &candidate_accounting,
            &candidate_history,
            record_timestamp(&host_record),
            &audit,
        );
        assert_eq!(candidate_output.status.code(), Some(0), "candidate {verb}");
        assert!(candidate_output.stdout.is_empty() && candidate_output.stderr.is_empty());
        assert_eq!(
            fs::read(&candidate_accounting).expect("read candidate accounting"),
            host_record,
            "accounting record for {verb}"
        );
        assert_eq!(
            fs::read(&candidate_history).expect("read candidate history"),
            host_record,
            "history record for {verb}"
        );
        assert_eq!(
            fs::read_to_string(&audit).expect("read audit seam"),
            if verb == "reboot" {
                "AUDIT_SYSTEM_BOOT systemd-update-utmp success=1\n"
            } else {
                "AUDIT_SYSTEM_SHUTDOWN systemd-update-utmp success=1\n"
            }
        );
    }
}

#[test]
fn absent_accounting_files_and_reboot_timestamp_seam_are_nonfatal() {
    let temporary = tempfile::tempdir().expect("create absent accounting fixture");
    let audit = temporary.path().join("audit");
    let output = Command::new(env!("CARGO_BIN_EXE_systemd-update-utmp"))
        .arg("reboot")
        .env("SYSTEMD_LOG_TARGET", "null")
        .env(
            "RUSTD_UPDATE_UTMP_UTMP",
            temporary.path().join("missing-utmp"),
        )
        .env(
            "RUSTD_UPDATE_UTMP_WTMP",
            temporary.path().join("missing-wtmp"),
        )
        .env("RUSTD_UPDATE_UTMP_REBOOT_USEC", "1700000000123456")
        .env("RUSTD_UPDATE_UTMP_AUDIT_LOG", &audit)
        .output()
        .expect("execute absent accounting case");
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    assert_eq!(
        fs::read_to_string(audit).expect("read audit seam"),
        "AUDIT_SYSTEM_BOOT systemd-update-utmp success=1\n"
    );
}

#[test]
fn dbus_failure_uses_v261_zero_monotonic_fallback_before_clock_mapping() {
    let temporary = tempfile::tempdir().expect("create D-Bus failure fixture");
    let accounting = temporary.path().join("utmp");
    let history = temporary.path().join("wtmp");
    empty_file(&accounting);
    empty_file(&history);
    let output = Command::new(env!("CARGO_BIN_EXE_systemd-update-utmp"))
        .arg("reboot")
        .env("RUSTD_UPDATE_UTMP_UTMP", &accounting)
        .env("RUSTD_UPDATE_UTMP_WTMP", &history)
        .env("RUSTD_UPDATE_UTMP_MANAGER_ERROR", "connection")
        .env("RUSTD_UPDATE_UTMP_MONOTONIC_NOW_USEC", "20000000")
        .env(
            "RUSTD_UPDATE_UTMP_REALTIME_NOW_USEC",
            "1700000020000000",
        )
        .output()
        .expect("execute D-Bus failure fixture");
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        output.stderr,
        b"Failed to get D-Bus connection, ignoring: fixture connection failure\n"
    );
    let record = fs::read(accounting).expect("read failure-fallback record");
    assert_eq!(record_timestamp(&record), 1_700_000_000_000_000);
    assert_eq!(fs::read(history).expect("read failure history"), record);
}
