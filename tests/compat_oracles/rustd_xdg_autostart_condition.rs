// SPDX-License-Identifier: LGPL-2.1-or-later

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStringExt;
use std::path::Path;
use std::process::{Command, Output};

const HOST: &str = "/usr/lib/systemd/systemd-xdg-autostart-condition";

fn host_is_pinned_v261() -> bool {
    Path::new(HOST).is_file()
        && Command::new("/usr/bin/systemd-ac-power")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.stdout.starts_with(b"systemd 261 "))
}

fn execute(binary: &str, arguments: &[&OsStr], desktop: Option<&OsStr>) -> Output {
    let mut command = Command::new(binary);
    command
        .args(arguments)
        .env("LC_ALL", "C")
        .env("SYSTEMD_COLORS", "0");
    if let Some(desktop) = desktop {
        command.env("XDG_CURRENT_DESKTOP", desktop);
    } else {
        command.env_remove("XDG_CURRENT_DESKTOP");
    }
    command
        .output()
        .expect("execute systemd-xdg-autostart-condition")
}

fn assert_same(host: &Output, candidate: &Output, context: &str) {
    assert_eq!(candidate.status.code(), host.status.code(), "{context}");
    assert_eq!(candidate.stdout, host.stdout, "stdout: {context}");
    assert_eq!(candidate.stderr, host.stderr, "stderr: {context}");
}

#[test]
fn full_colon_set_order_precedence_and_default_contract_matches_live_v261() {
    if !host_is_pinned_v261() {
        eprintln!("skipping live comparison: systemd package is not v261");
        return;
    }
    let candidate = env!("CARGO_BIN_EXE_systemd-xdg-autostart-condition");
    let desktops = [
        None,
        Some(""),
        Some("GNOME"),
        Some("GNOME:KDE"),
        Some("KDE:GNOME"),
        Some(":GNOME"),
        Some("GNOME:"),
        Some("GNOME::KDE"),
        Some("gnome"),
    ];
    let sets = [
        ("", ""),
        ("GNOME", ""),
        ("", "GNOME"),
        ("GNOME", "GNOME"),
        ("GNOME", "KDE"),
        ("KDE", "GNOME"),
        ("KDE:GNOME", ""),
        ("", "KDE:GNOME"),
        (":", "GNOME"),
        ("::", ""),
    ];

    for desktop in desktops {
        for (only, not) in sets {
            let arguments = [OsStr::new(only), OsStr::new(not)];
            let desktop = desktop.map(OsStr::new);
            let host = execute(HOST, &arguments, desktop);
            let ours = execute(candidate, &arguments, desktop);
            assert_same(
                &host,
                &ours,
                &format!("desktop={desktop:?}, only={only:?}, not={not:?}"),
            );
        }
    }
}

#[test]
fn exact_argument_errors_and_non_utf8_matching_match_live_v261() {
    if !host_is_pinned_v261() {
        eprintln!("skipping live comparison: systemd package is not v261");
        return;
    }
    let candidate = env!("CARGO_BIN_EXE_systemd-xdg-autostart-condition");
    let cases: Vec<Vec<OsString>> = vec![
        vec![],
        vec![OsString::from("")],
        vec![OsString::from("--help")],
        vec![OsString::from("--version")],
        vec![
            OsString::from(""),
            OsString::from(""),
            OsString::from("extra"),
        ],
    ];
    for arguments in cases {
        let references: Vec<&OsStr> = arguments.iter().map(OsString::as_os_str).collect();
        let host = execute(HOST, &references, None);
        let ours = execute(candidate, &references, None);
        assert_same(&host, &ours, &format!("{arguments:?}"));
    }

    let raw = OsString::from_vec(vec![0xff]);
    let desktop = OsString::from_vec(vec![0xff, b':', b'X']);
    let arguments = [raw.as_os_str(), OsStr::new("X")];
    let host = execute(HOST, &arguments, Some(desktop.as_os_str()));
    let ours = execute(candidate, &arguments, Some(desktop.as_os_str()));
    assert_same(&host, &ours, "non-UTF8 desktop and set");
    assert_eq!(ours.status.code(), Some(0));
}
