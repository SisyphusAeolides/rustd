// SPDX-License-Identifier: LGPL-2.1-or-later

use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::process::{Command, Output};

const HOST: &str = "/usr/bin/systemd-delta";
const SUFFIXES: [&str; 10] = [
    "sysctl.d",
    "tmpfiles.d",
    "modules-load.d",
    "binfmt.d",
    "systemd/system",
    "systemd/user",
    "systemd/system-preset",
    "systemd/user-preset",
    "udev/rules.d",
    "modprobe.d",
];

const NAMESPACE_RUNNER: &str = r#"
root=$1
binary=$2
shift 2
mount --bind "$root/etc" /etc
mount --bind "$root/run" /run
mount --bind "$root/usr/local" /usr/local
mount --bind "$root/usr/share" /usr/share
for suffix in sysctl.d tmpfiles.d modules-load.d binfmt.d systemd/system systemd/user systemd/system-preset systemd/user-preset udev/rules.d modprobe.d; do
    mount --bind "$root/usr/lib/$suffix" "/usr/lib/$suffix"
done
exec "$binary" "$@"
"#;

fn host_is_pinned_v261() -> bool {
    Path::new(HOST).is_file()
        && Command::new(HOST)
            .arg("--version")
            .output()
            .is_ok_and(|output| output.stdout.starts_with(b"systemd 261 "))
}

fn unshare_supported() -> bool {
    Command::new("unshare")
        .args(["--user", "--map-root-user", "--mount", "true"])
        .status()
        .is_ok_and(|status| status.success())
}

fn plain(binary: &str, arguments: &[OsString]) -> Output {
    Command::new(binary)
        .args(arguments)
        .env("LC_ALL", "C")
        .env("SYSTEMD_COLORS", "0")
        .env("SYSTEMD_PAGER", "cat")
        .output()
        .expect("run systemd-delta CLI case")
}

fn isolated(
    root: &Path,
    binary: &str,
    arguments: &[OsString],
    locale: &str,
    colors: &str,
) -> Output {
    Command::new("unshare")
        .args(["--user", "--map-root-user", "--mount", "sh", "-ceu"])
        .arg(NAMESPACE_RUNNER)
        .arg("systemd-delta-oracle")
        .arg(root)
        .arg(binary)
        .args(arguments)
        .env("LC_ALL", locale)
        .env("SYSTEMD_COLORS", colors)
        .env("SYSTEMD_PAGER", "cat")
        .env("SYSTEMD_URLIFY", "0")
        .output()
        .expect("run isolated systemd-delta")
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

fn create_layout(root: &Path) {
    for prefix in ["etc", "run", "usr/local", "usr/share"] {
        fs::create_dir_all(root.join(prefix)).expect("create prefix fixture");
    }
    for suffix in SUFFIXES {
        fs::create_dir_all(root.join("usr/lib").join(suffix)).expect("create suffix fixture");
    }

    let etc = root.join("etc/sysctl.d");
    let run = root.join("run/sysctl.d");
    let vendor = root.join("usr/lib/sysctl.d");
    fs::create_dir_all(&etc).expect("create etc sysctl fixture");
    fs::create_dir_all(&run).expect("create run sysctl fixture");

    fs::write(vendor.join("10-masked.conf"), b"vendor\n").expect("write masked vendor");
    fs::write(etc.join("10-masked.conf"), b"").expect("write empty mask");

    fs::write(vendor.join("20-equivalent.conf"), b"vendor\n").expect("write equivalent vendor");
    symlink(
        "/usr/lib/sysctl.d/20-equivalent.conf",
        etc.join("20-equivalent.conf"),
    )
    .expect("write equivalent symlink");

    fs::write(vendor.join("30-redirected.conf"), b"vendor\n").expect("write redirect vendor");
    fs::write(vendor.join("redirect-target.conf"), b"target\n").expect("write redirect target");
    symlink(
        "/usr/lib/sysctl.d/redirect-target.conf",
        etc.join("30-redirected.conf"),
    )
    .expect("write redirected symlink");

    fs::write(vendor.join("40-overridden.conf"), b"vendor\n").expect("write override vendor");
    fs::write(etc.join("40-overridden.conf"), b"local\n").expect("write override local");
    fs::write(vendor.join("41-identical.conf"), b"same\n").expect("write identical vendor");
    fs::write(etc.join("41-identical.conf"), b"same\n").expect("write identical local");
    fs::write(vendor.join("50-unchanged.conf"), b"vendor\n").expect("write unchanged");

    fs::write(vendor.join("60-layered.conf"), b"vendor\n").expect("write layered vendor");
    fs::write(run.join("60-layered.conf"), b"runtime\n").expect("write layered runtime");
    fs::write(etc.join("60-layered.conf"), b"local\n").expect("write layered local");

    fs::write(vendor.join("70-relative.conf"), b"vendor\n").expect("write relative vendor");
    symlink(
        "../../usr/lib/sysctl.d/70-relative.conf",
        etc.join("70-relative.conf"),
    )
    .expect("write relative symlink");

    let raw = OsString::from_vec(vec![b'8', b'0', b'-', 0xff, b'.', b'c', b'o', b'n', b'f']);
    fs::write(vendor.join(&raw), b"vendor\n").expect("write raw vendor");
    fs::write(etc.join(&raw), b"local\n").expect("write raw local");

    let vendor_units = root.join("usr/lib/systemd/system");
    let etc_units = root.join("etc/systemd/system");
    let run_units = root.join("run/systemd/system");
    fs::create_dir_all(&etc_units).expect("create etc unit fixture");
    fs::create_dir_all(&run_units).expect("create run unit fixture");
    fs::write(
        vendor_units.join("demo.service"),
        b"[Service]\nExecStart=true\n",
    )
    .expect("write vendor unit");
    fs::create_dir_all(vendor_units.join("demo.service.d")).expect("create vendor dropin");
    fs::create_dir_all(etc_units.join("demo.service.d")).expect("create etc dropin");
    fs::create_dir_all(run_units.join("demo.service.d")).expect("create run dropin");
    fs::write(
        vendor_units.join("demo.service.d/10-shared.conf"),
        b"vendor\n",
    )
    .expect("write vendor dropin");
    fs::write(etc_units.join("demo.service.d/10-shared.conf"), b"local\n")
        .expect("write local dropin");
    fs::write(
        run_units.join("demo.service.d/20-runtime.conf"),
        b"runtime\n",
    )
    .expect("write runtime dropin");
}

#[test]
fn complete_getopt_help_version_and_error_surface_matches_v261() {
    if !host_is_pinned_v261() {
        eprintln!("skipping live comparison: systemd-delta is not v261");
        return;
    }
    let candidate = env!("CARGO_BIN_EXE_systemd-delta");
    let cases = vec![
        vec![OsString::from("--help")],
        vec![OsString::from("-hfoo")],
        vec![OsString::from("--version")],
        vec![OsString::from("--bogus")],
        vec![OsString::from("-xh")],
        vec![OsString::from("--no-pager=yes")],
        vec![OsString::from("-t")],
        vec![OsString::from("-t=default")],
        vec![OsString::from("--type=")],
        vec![OsString::from("--diff=maybe")],
        vec![OsString::from("--=x")],
        vec![OsString::from_vec(vec![b'-', b'-', 0xff])],
    ];
    for arguments in cases {
        assert_same(
            &plain(HOST, &arguments),
            &plain(candidate, &arguments),
            &format!("CLI {arguments:?}"),
        );
    }
}

#[test]
fn isolated_scanner_classification_order_selectors_color_and_diff_match_v261() {
    if !host_is_pinned_v261() || !unshare_supported() {
        eprintln!("skipping isolated comparison: v261 host or user namespace unavailable");
        return;
    }
    let temporary = tempfile::tempdir().expect("create delta fixture");
    create_layout(temporary.path());
    let candidate = env!("CARGO_BIN_EXE_systemd-delta");
    let cases: Vec<(Vec<OsString>, &str, &str)> = vec![
        (
            vec![
                OsString::from("--no-pager"),
                OsString::from("--type=masked,equivalent,redirected,overridden,unchanged"),
                OsString::from("--diff=no"),
                OsString::from("sysctl.d"),
            ],
            "C.UTF-8",
            "0",
        ),
        (
            vec![OsString::from("--no-pager"), OsString::from("sysctl.d")],
            "C.UTF-8",
            "0",
        ),
        (
            vec![
                OsString::from("--no-pager"),
                OsString::from("--type=default,unchanged"),
                OsString::from("--diff=no"),
                OsString::from("systemd/system"),
            ],
            "C",
            "0",
        ),
        (
            vec![
                OsString::from("--no-pager"),
                OsString::from("--diff=no"),
                OsString::from("/usr/lib/sysctl.d"),
            ],
            "C.UTF-8",
            "1",
        ),
        (
            vec![
                OsString::from("--no-pager"),
                OsString::from("--type=masked"),
                OsString::from("--type=unchanged"),
                OsString::from("--diff=no"),
                OsString::from("sysctl.d"),
            ],
            "C",
            "0",
        ),
        (
            vec![OsString::from("--no-pager"), OsString::from("--diff=no")],
            "C.UTF-8",
            "0",
        ),
    ];

    for (arguments, locale, colors) in cases {
        assert_same(
            &isolated(temporary.path(), HOST, &arguments, locale, colors),
            &isolated(temporary.path(), candidate, &arguments, locale, colors),
            &format!("fixture {arguments:?}, locale={locale}, colors={colors}"),
        );
    }
}

#[test]
fn invalid_absolute_selector_matches_inside_isolated_tree() {
    if !host_is_pinned_v261() || !unshare_supported() {
        return;
    }
    let temporary = tempfile::tempdir().expect("create delta fixture");
    create_layout(temporary.path());
    let arguments = vec![OsString::from("/opt/not-a-delta-prefix")];
    assert_same(
        &isolated(temporary.path(), HOST, &arguments, "C", "0"),
        &isolated(
            temporary.path(),
            env!("CARGO_BIN_EXE_systemd-delta"),
            &arguments,
            "C",
            "0",
        ),
        "invalid absolute selector",
    );
}

#[test]
fn positional_dash_is_not_treated_as_an_option() {
    let output = plain(
        env!("CARGO_BIN_EXE_systemd-delta"),
        &[OsString::from("--"), OsString::from("-")],
    );
    assert!(output.status.success());
    assert_eq!(output.stdout, b"0 overridden configuration files found.\n");
    assert!(output.stderr.is_empty());
}
