// SPDX-License-Identifier: LGPL-2.1-or-later

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const ROOT_OVERRIDE: &str = "SYSTEMD_DETECT_VIRT_ROOT";

fn run(binary: &Path, arguments: &[&str]) -> Output {
    Command::new(binary)
        .args(arguments)
        .env("LC_ALL", "C")
        .env("SYSTEMD_COLORS", "0")
        .env_remove(ROOT_OVERRIDE)
        .output()
        .expect("execute systemd-detect-virt")
}

fn run_fixture(binary: &Path, arguments: &[&str], root: &Path) -> Output {
    Command::new(binary)
        .args(arguments)
        .env("LC_ALL", "C")
        .env("SYSTEMD_COLORS", "0")
        .env(ROOT_OVERRIDE, root)
        .env_remove("SYSTEMD_IN_CHROOT")
        .env_remove("SYSTEMD_IGNORE_CHROOT")
        .output()
        .expect("execute fixture systemd-detect-virt")
}

fn live_oracle_enabled() -> bool {
    // Exclusive RustD keeps native branding/IPC. Opt into live systemd byte-parity
    // oracles only when explicitly certifying against a pinned host binary.
    host_is_pinned_v261() && std::env::var_os("RUSTD_LIVE_SYSTEMD_ORACLE").is_some()
}

fn host_is_pinned_v261() -> bool {
    Command::new("/usr/bin/systemd-detect-virt")
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
fn option_output_and_live_detection_contracts_match_pinned_v261() {
    if !live_oracle_enabled() {
        eprintln!("skipping live comparison: /usr/bin/systemd-detect-virt is not v261");
        return;
    }
    let candidate = Path::new(env!("CARGO_BIN_EXE_systemd-detect-virt"));
    let cases: &[&[&str]] = &[
        &[],
        &["--quiet"],
        &["--container"],
        &["--vm"],
        &["--chroot"],
        &["--private-users"],
        &["--cvm"],
        &["--list"],
        &["--list-cvm"],
        &["--help"],
        &["--version"],
        &["--c"],
        &["--l"],
        &["--v"],
        &["--p"],
        &["--list-c"],
        &["--list=value"],
        &["--private-users=value"],
        &["--unknown"],
        &["-x"],
        &["argument"],
        &["--", "argument"],
        &["-qcv"],
        &["--container", "--vm"],
        &["--vm", "--container"],
        &["--list", "ignored"],
        &["--cvm", "--unknown"],
        &["--unknown", "--cvm"],
        &["-hunknown"],
    ];
    for arguments in cases {
        assert_same(
            &run(Path::new("/usr/bin/systemd-detect-virt"), arguments),
            &run(candidate, arguments),
            arguments,
        );
    }
}

struct Fixture {
    root: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("create detect-virt fixture");
        let fixture = Self { root };
        fixture.write("/proc/sys/kernel/osrelease", "Linux fixture\n");
        fixture.write("/proc/self/status", "TracerPid:\t0\n");
        fixture.write("/run/systemd/detect-virt/pid-namespace", "init\n");
        fixture.write("/run/systemd/detect-virt/user-namespace", "init\n");
        fixture.write("/run/systemd/detect-virt/cpuid", "none\n");
        fixture
    }

    fn path(&self) -> &Path {
        self.root.path()
    }

    fn rooted(&self, absolute: &str) -> PathBuf {
        self.path().join(absolute.trim_start_matches('/'))
    }

    fn write(&self, absolute: &str, contents: &str) {
        let path = self.rooted(absolute);
        fs::create_dir_all(path.parent().expect("fixture parent")).expect("create fixture path");
        fs::write(path, contents).expect("write fixture file");
    }

    fn touch(&self, absolute: &str) {
        self.write(absolute, "");
    }
}

fn assert_detect(fixture: &Fixture, arguments: &[&str], code: i32, stdout: &str) {
    let output = run_fixture(
        Path::new(env!("CARGO_BIN_EXE_systemd-detect-virt")),
        arguments,
        fixture.path(),
    );
    assert_eq!(output.status.code(), Some(code), "{arguments:?}");
    assert_eq!(output.stdout, stdout.as_bytes(), "stdout for {arguments:?}");
    assert!(
        output.stderr.is_empty(),
        "stderr for {arguments:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn synthetic_container_detection_preserves_v261_order_and_names() {
    let openvz = Fixture::new();
    openvz.touch("/proc/vz");
    assert_detect(&openvz, &["--container"], 0, "openvz\n");

    let wsl = Fixture::new();
    wsl.write(
        "/proc/sys/kernel/osrelease",
        "6.6.0-microsoft-standard-WSL2\n",
    );
    wsl.write("/run/systemd/container", "docker\n");
    assert_detect(&wsl, &["--container"], 0, "wsl\n");

    let proot = Fixture::new();
    proot.write("/proc/self/status", "TracerPid:\t42\n");
    proot.write("/proc/42/comm", "proot-loader\n");
    assert_detect(&proot, &["--container"], 0, "proot\n");

    let manager = Fixture::new();
    manager.write("/run/host/container-manager", "systemd-nspawn\n");
    manager.write("/run/systemd/container", "docker\n");
    assert_detect(&manager, &["--container"], 0, "systemd-nspawn\n");

    let pid1 = Fixture::new();
    pid1.write("/proc/1/environ", "PATH=/usr/bin\0container=lxc-libvirt\0");
    assert_detect(&pid1, &["--container"], 0, "lxc-libvirt\n");

    let oci = Fixture::new();
    oci.write("/run/systemd/container", "oci\n");
    oci.touch("/run/.containerenv");
    oci.touch("/.dockerenv");
    assert_detect(&oci, &["--container"], 0, "podman\n");

    let unknown = Fixture::new();
    unknown.write("/run/systemd/container", "home-grown\n");
    assert_detect(&unknown, &["--container"], 0, "container-other\n");

    let namespace = Fixture::new();
    namespace.write("/run/systemd/detect-virt/pid-namespace", "nested\n");
    assert_detect(&namespace, &["--container"], 0, "container-other\n");
}

#[test]
fn synthetic_vm_detection_preserves_v261_probe_precedence() {
    let oracle = Fixture::new();
    oracle.write("/sys/class/dmi/id/product_name", "VirtualBox\n");
    oracle.write("/run/systemd/detect-virt/cpuid", "KVMKVMKVM\n");
    assert_detect(&oracle, &["--vm"], 0, "oracle\n");

    let gce = Fixture::new();
    gce.write("/sys/class/dmi/id/product_name", "Google Compute Engine\n");
    gce.write("/run/systemd/detect-virt/cpuid", "KVMKVMKVM\n");
    assert_detect(&gce, &["--vm"], 0, "google\n");

    let hyperv = Fixture::new();
    hyperv.write("/run/systemd/detect-virt/cpuid", "Microsoft Hv\n");
    hyperv.write("/sys/class/dmi/id/product_name", "QEMU Standard PC\n");
    assert_detect(&hyperv, &["--vm"], 0, "qemu\n");

    let uml = Fixture::new();
    uml.write("/proc/cpuinfo", "vendor_id\t: User Mode Linux\n");
    assert_detect(&uml, &["--vm"], 0, "uml\n");

    let xen_guest = Fixture::new();
    fs::create_dir_all(xen_guest.rooted("/proc/xen")).expect("create Xen fixture");
    assert_detect(&xen_guest, &["--vm"], 0, "xen\n");

    let signatures = [
        ("TCGTCGTCGTCG", "qemu"),
        ("VMwareVMware", "vmware"),
        ("bhyve bhyve ", "bhyve"),
        ("QNXQVMBSQG", "qnx"),
        ("ACRNACRNACRN", "acrn"),
        ("SRESRESRESRE", "sre"),
        ("unexpected", "vm-other"),
    ];
    for (signature, identifier) in signatures {
        let fixture = Fixture::new();
        fixture.write("/run/systemd/detect-virt/cpuid", signature);
        assert_detect(&fixture, &["--vm"], 0, &format!("{identifier}\n"));
    }
}

#[test]
fn any_mode_prefers_inner_container_and_quiet_only_changes_output() {
    let fixture = Fixture::new();
    fixture.write("/run/systemd/container", "docker\n");
    fixture.write("/run/systemd/detect-virt/cpuid", "KVMKVMKVM\n");
    assert_detect(&fixture, &[], 0, "docker\n");
    assert_detect(&fixture, &["--quiet"], 0, "");

    let physical = Fixture::new();
    assert_detect(&physical, &[], 1, "none\n");
    assert_detect(&physical, &["--quiet"], 1, "");
}

#[test]
fn synthetic_namespace_chroot_and_confidential_modes_are_deterministic() {
    let fixture = Fixture::new();
    fixture.write("/run/systemd/detect-virt/user-namespace", "nested\n");
    fixture.write("/run/systemd/detect-virt/chroot", "yes\n");
    assert_detect(&fixture, &["--private-users"], 0, "");
    assert_detect(&fixture, &["--chroot"], 0, "");

    for identifier in ["sev", "sev-es", "sev-snp", "tdx", "protvirt", "cca"] {
        let cvm = Fixture::new();
        cvm.write("/run/systemd/detect-virt/cvm", identifier);
        assert_detect(&cvm, &["--cvm"], 0, &format!("{identifier}\n"));
        assert_detect(&cvm, &["--quiet", "--cvm", "--bad"], 0, "");
    }
}

#[test]
fn list_inventory_is_the_exact_v261_enum_surface() {
    let binary = Path::new(env!("CARGO_BIN_EXE_systemd-detect-virt"));
    let listed = run(binary, &["--list"]);
    assert_eq!(listed.status.code(), Some(0));
    assert_eq!(
        listed.stdout,
        b"none\nkvm\namazon\nqemu\nbochs\nxen\numl\nvmware\noracle\nmicrosoft\nzvm\nparallels\nbhyve\nqnx\nacrn\npowervm\napple\nsre\ngoogle\nvm-other\nsystemd-nspawn\nlxc-libvirt\nlxc\nopenvz\ndocker\npodman\nrkt\nwsl\nproot\npouch\ncontainer-other\n"
    );
    assert_eq!(
        run(binary, &["--list-cvm"]).stdout,
        b"none\nsev\nsev-es\nsev-snp\ntdx\nprotvirt\ncca\n"
    );
}
