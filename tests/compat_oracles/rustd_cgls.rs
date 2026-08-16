// SPDX-License-Identifier: LGPL-2.1-or-later

use std::ffi::{CString, OsString};
use std::fs;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::Path;
use std::process::{Command, Output};

const HOST: &str = "/usr/bin/systemd-cgls";

fn host_is_pinned_v261() -> bool {
    Path::new(HOST).is_file()
        && Command::new("/usr/bin/systemd-ac-power")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.stdout.starts_with(b"systemd 261 "))
}

fn command(binary: &str) -> Command {
    let mut command = Command::new(binary);
    command
        .env("LC_ALL", "C")
        .env("SYSTEMD_COLORS", "0")
        .env("SYSTEMD_PAGER", "cat")
        .env("COLUMNS", "80")
        .env_remove("RUSTD_CGROUP_ROOT");
    command
}

fn plain(binary: &str, arguments: &[OsString]) -> Output {
    command(binary)
        .args(arguments)
        .output()
        .expect("execute systemd-cgls")
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

#[test]
fn complete_cli_error_and_live_unit_surface_matches_v261() {
    if !host_is_pinned_v261() {
        eprintln!("skipping live comparison: systemd package is not v261");
        return;
    }
    let candidate = env!("CARGO_BIN_EXE_systemd-cgls");
    let cases = vec![
        vec![OsString::from("--help")],
        vec![OsString::from("--version")],
        vec![OsString::from("--xattr=maybe")],
        vec![OsString::from("--cgroup-id=maybe")],
        vec![OsString::from("--unit"), OsString::from("--user-unit")],
        vec![
            OsString::from("--unit"),
            OsString::from("-M"),
            OsString::from("machine"),
        ],
        vec![OsString::from("--machine=")],
        vec![OsString::from("--machine=definitely-missing-cgls")],
        vec![OsString::from("--unknown")],
        vec![OsString::from("-z")],
        vec![OsString::from("--all=x")],
        vec![OsString::from("-M")],
        vec![OsString::from("/../../etc")],
        vec![OsString::from("/foo/../bar")],
        vec![OsString::from("cpu:/definitely-missing")],
        vec![
            OsString::from("--unit"),
            OsString::from("definitely-missing-cgls.service"),
        ],
        vec![OsString::from("--unit"), OsString::from("init.scope")],
        vec![
            OsString::from("--xattr=false"),
            OsString::from("/sys/fs/cgroup/init.scope"),
        ],
        vec![OsString::from_vec(vec![b'-', b'-', 0xff])],
    ];
    for arguments in cases {
        assert_same(
            &plain(HOST, &arguments),
            &plain(candidate, &arguments),
            &format!("{arguments:?}"),
        );
    }
}

fn write_fixture(root: &Path) {
    let alpha = root.join("alpha.slice");
    let child = alpha.join("child.scope");
    let escaped = root.join("_escaped.scope");
    fs::create_dir_all(&child).expect("create nested fixture");
    fs::create_dir(&escaped).expect("create escaped fixture");
    fs::write(root.join("cgroup.procs"), "1\n1\n0\n").expect("write root pids");
    fs::write(alpha.join("cgroup.procs"), "1\n").expect("write alpha pids");
    fs::write(child.join("cgroup.procs"), "").expect("write child pids");
    fs::write(escaped.join("cgroup.procs"), "").expect("write escaped pids");
    fs::write(alpha.join("cgroup.events"), "populated 1\nfrozen 0\n").expect("write alpha events");
    fs::write(child.join("cgroup.events"), "populated 0\nfrozen 0\n").expect("write child events");
    fs::write(escaped.join("cgroup.events"), "populated 0\nfrozen 0\n")
        .expect("write escaped events");
    set_xattr(&alpha, "user.delegate", b"1");
    set_xattr(&alpha, "user.demo", b"hello world");
}

fn set_xattr(path: &Path, name: &str, value: &[u8]) {
    let path = CString::new(path.as_os_str().as_bytes()).expect("fixture path without NUL");
    let name = CString::new(name).expect("xattr name without NUL");
    // SAFETY: path/name are NUL terminated and value is readable for its length.
    let result = unsafe {
        libc::setxattr(
            path.as_ptr(),
            name.as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
        )
    };
    assert_eq!(result, 0, "set fixture xattr");
}

fn isolated_host(root: &Path, arguments: &[&str], locale: &str, columns: &str) -> Output {
    Command::new("unshare")
        .args(["--user", "--map-root-user", "--mount", "sh", "-ceu"])
        .arg("mount --bind \"$1\" /sys/fs/cgroup; shift; exec \"$@\"")
        .arg("systemd-cgls-oracle")
        .arg(root)
        .arg(HOST)
        .args(arguments)
        .arg("/sys/fs/cgroup")
        .env("LC_ALL", locale)
        .env("SYSTEMD_COLORS", "0")
        .env("SYSTEMD_PAGER", "cat")
        .env("COLUMNS", columns)
        .output()
        .expect("execute isolated host systemd-cgls")
}

fn fixture_candidate(root: &Path, arguments: &[&str], locale: &str, columns: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_systemd-cgls"))
        .args(arguments)
        .arg("/sys/fs/cgroup")
        .env("RUSTD_CGROUP_ROOT", root)
        .env("LC_ALL", locale)
        .env("SYSTEMD_COLORS", "0")
        .env("SYSTEMD_PAGER", "cat")
        .env("COLUMNS", columns)
        .output()
        .expect("execute fixture candidate systemd-cgls")
}

#[test]
fn isolated_hierarchy_display_matches_v261_exactly() {
    if !host_is_pinned_v261() {
        eprintln!("skipping live comparison: systemd package is not v261");
        return;
    }
    let temporary = tempfile::tempdir().expect("create hierarchy fixture");
    write_fixture(temporary.path());
    let cases = [
        (&["--no-pager", "--all"][..], "C.UTF-8", "80"),
        (&["--no-pager", "--all", "--xattr"][..], "C.UTF-8", "80"),
        (&["--no-pager", "--all", "--cgroup-id"][..], "C.UTF-8", "80"),
        (&["--no-pager", "--xattr"][..], "C.UTF-8", "80"),
        (&["--no-pager", "--all", "--full"][..], "C.UTF-8", "24"),
        (&["--no-pager", "--all"][..], "C", "80"),
    ];
    for (arguments, locale, columns) in cases {
        assert_same(
            &isolated_host(temporary.path(), arguments, locale, columns),
            &fixture_candidate(temporary.path(), arguments, locale, columns),
            &format!("fixture {arguments:?} {locale} {columns}"),
        );
    }
}

#[test]
fn deterministic_fixture_never_requires_the_real_cgroup_tree() {
    let temporary = tempfile::tempdir().expect("create hierarchy fixture");
    write_fixture(temporary.path());
    let output = fixture_candidate(
        temporary.path(),
        &["--no-pager", "--all", "--xattr"],
        "C.UTF-8",
        "80",
    );
    assert!(output.status.success());
    assert!(output
        .stdout
        .windows(b"alpha.slice".len())
        .any(|w| w == b"alpha.slice"));
    assert!(output
        .stdout
        .windows(b"user.demo: hello world".len())
        .any(|w| { w == b"user.demo: hello world" }));
}

#[test]
fn raw_positional_path_is_byte_preserving() {
    let temporary = tempfile::tempdir().expect("create fixture");
    let name = OsString::from_vec(vec![b'_', 0xff]);
    let group = temporary.path().join(name);
    fs::create_dir(&group).expect("create non-UTF8 group");
    fs::write(temporary.path().join("cgroup.procs"), "").expect("write root pids");
    fs::write(group.join("cgroup.procs"), "").expect("write group pids");
    let output = fixture_candidate(temporary.path(), &["--no-pager", "--all"], "C", "80");
    assert!(output.status.success());
    assert!(output
        .stdout
        .windows(3)
        .any(|window| window == [b'`', b'-', 0xff]));
}
