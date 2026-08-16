// SPDX-License-Identifier: LGPL-2.1-or-later

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

const KEYS: &[&str] = &[
    "temporary",
    "temporary-large",
    "system-search-configuration",
    "system-binaries",
    "system-include",
    "system-library-private",
    "system-library-arch",
    "system-shared",
    "system-configuration-factory",
    "system-state-factory",
    "system-configuration",
    "system-runtime",
    "system-runtime-logs",
    "system-state-private",
    "system-state-logs",
    "system-state-cache",
    "system-state-spool",
    "user-binaries",
    "user-library-private",
    "user-library-arch",
    "user-shared",
    "user-configuration",
    "user-runtime",
    "user-state-cache",
    "user-state-private",
    "user",
    "user-documents",
    "user-music",
    "user-pictures",
    "user-videos",
    "user-download",
    "user-public",
    "user-templates",
    "user-desktop",
    "user-projects",
    "search-binaries",
    "search-binaries-default",
    "search-library-private",
    "search-library-arch",
    "search-shared",
    "search-configuration-factory",
    "search-state-factory",
    "search-configuration",
    "systemd-util",
    "systemd-system-unit",
    "systemd-system-preset",
    "systemd-system-conf",
    "systemd-user-unit",
    "systemd-user-preset",
    "systemd-user-conf",
    "systemd-initrd-preset",
    "systemd-search-system-unit",
    "systemd-search-user-unit",
    "systemd-system-generator",
    "systemd-user-generator",
    "systemd-search-system-generator",
    "systemd-search-user-generator",
    "systemd-sleep",
    "systemd-shutdown",
    "tmpfiles",
    "sysusers",
    "sysctl",
    "binfmt",
    "modules-load",
    "catalog",
    "systemd-search-network",
    "systemd-system-environment-generator",
    "systemd-user-environment-generator",
    "systemd-search-system-environment-generator",
    "systemd-search-user-environment-generator",
    "system-credential-store",
    "system-search-credential-store",
    "system-credential-store-encrypted",
    "system-search-credential-store-encrypted",
    "user-credential-store",
    "user-search-credential-store",
    "user-credential-store-encrypted",
    "user-search-credential-store-encrypted",
];

fn run(binary: &Path, arguments: &[&str], root: &Path) -> Output {
    Command::new(binary)
        .args(arguments)
        .env_clear()
        .env("LC_ALL", "C")
        .env("SYSTEMD_COLORS", "0")
        .env("SYSTEMD_PAGER", "cat")
        .env("HOME", root.join("home"))
        .env("TMPDIR", root.join("tmp"))
        .env("XDG_RUNTIME_DIR", root.join("run"))
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("XDG_CONFIG_DIRS", "/configuration/one::/configuration/two:")
        .env("XDG_DATA_HOME", root.join("data"))
        .env("XDG_DATA_DIRS", "/data/one::/data/two:")
        .env("XDG_CACHE_HOME", root.join("cache"))
        .env("XDG_STATE_HOME", root.join("state"))
        .env("PATH", "/binary/one::/binary/two:")
        .env("LD_LIBRARY_PATH", "/library/one::/library/two:")
        .env("SYSTEMD_UNIT_PATH", "/unit/one::/unit/two:")
        .env("SYSTEMD_GENERATOR_PATH", "/generator/one::/generator/two:")
        .env(
            "SYSTEMD_ENVIRONMENT_GENERATOR_PATH",
            "/environment-generator/one::/environment-generator/two:",
        )
        .output()
        .expect("execute systemd-path")
}

fn fixture() -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("create path fixture");
    fs::create_dir_all(root.path().join("config")).expect("create XDG config home");
    fs::create_dir_all(root.path().join("tmp")).expect("create temporary directory");
    fs::write(
        root.path().join("config/user-dirs.dirs"),
        concat!(
            "XDG_DESKTOP_DIR=\"$HOME/Desk\"\n",
            "XDG_DOCUMENTS_DIR=\"/srv/Documents\"\n",
            "XDG_DOWNLOAD_DIR=\"$HOME\"\n",
            "XDG_MUSIC_DIR=\"relative-is-ignored\"\n",
            "XDG_PROJECTS_DIR=\"$HOME/Source\"\n",
        ),
    )
    .expect("write user directory fixture");
    root
}

fn host_is_pinned_v261() -> bool {
    Command::new("/usr/bin/systemd-path")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.stdout.starts_with(b"systemd 261 "))
}

#[test]
fn all_v261_keys_match_the_live_pinned_host() {
    if !host_is_pinned_v261() {
        eprintln!("skipping live comparison: /usr/bin/systemd-path is not v261");
        return;
    }

    let candidate = Path::new(env!("CARGO_BIN_EXE_systemd-path"));
    let root = fixture();
    let host = run(Path::new("/usr/bin/systemd-path"), KEYS, root.path());
    let ours = run(candidate, KEYS, root.path());
    assert_eq!(ours.status.code(), host.status.code());
    assert_eq!(ours.stdout, host.stdout);
    assert_eq!(ours.stderr, host.stderr);

    let host = run(
        Path::new("/usr/bin/systemd-path"),
        &["--no-pager"],
        root.path(),
    );
    let ours = run(candidate, &["--no-pager"], root.path());
    assert_eq!(ours.status.code(), host.status.code());
    assert_eq!(ours.stdout, host.stdout);
    assert_eq!(ours.stderr, host.stderr);
}

#[test]
fn suffix_and_option_contracts_match_the_live_pinned_host() {
    if !host_is_pinned_v261() {
        eprintln!("skipping live comparison: /usr/bin/systemd-path is not v261");
        return;
    }

    let candidate = Path::new(env!("CARGO_BIN_EXE_systemd-path"));
    let root = fixture();
    let cases: &[&[&str]] = &[
        &["--suffix=/one//./two/", "temporary", "search-binaries"],
        &["temporary", "--suffix=../leaf"],
        &["--suffix", "-x", "temporary"],
        &["--suff=leaf", "temporary"],
        &["--user"],
        &["--system"],
        &["--global"],
        &["--suffix"],
        &["--no-pager=value"],
        &["unknown", "temporary"],
        &["--", "-x"],
        &["-hx"],
        &["--version", "--unknown"],
        &["--unknown", "--version"],
    ];

    for arguments in cases {
        let host = run(Path::new("/usr/bin/systemd-path"), arguments, root.path());
        let ours = run(candidate, arguments, root.path());
        assert_eq!(
            ours.status.code(),
            host.status.code(),
            "arguments={arguments:?}"
        );
        assert_eq!(ours.stdout, host.stdout, "arguments={arguments:?}");
        assert_eq!(ours.stderr, host.stderr, "arguments={arguments:?}");
    }
}

#[test]
fn deterministic_clean_environment_contract() {
    let candidate = Path::new(env!("CARGO_BIN_EXE_systemd-path"));
    let root = fixture();
    let output = run(
        candidate,
        &[
            "--suffix=leaf",
            "temporary",
            "search-binaries",
            "search-library-arch",
            "user-desktop",
            "user-projects",
        ],
        root.path(),
    );
    let expected = format!(
        "{}/tmp/leaf\n/binary/one/leaf:/binary/two/leaf\n/library/one/leaf:/library/two/leaf\n{}/home/Desk/leaf\n{}/home/Source/leaf\n",
        root.path().display(),
        root.path().display(),
        root.path().display(),
    );
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).expect("UTF-8 output"),
        expected
    );
    assert!(output.stderr.is_empty());
}
