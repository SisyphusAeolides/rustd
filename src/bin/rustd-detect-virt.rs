// SPDX-License-Identifier: LGPL-2.1-or-later
//! `systemd-detect-virt` compatibility utility.
//!
//! Upstream reference: systemd v261 `src/detect-virt/detect-virt.c`,
//! `src/basic/virt.c`, and `src/basic/confidential-virt.c`.

use std::env;
use std::fs::{self, File};
use std::io::{self, Write};
#[cfg(target_arch = "x86_64")]
use std::os::unix::fs::FileExt;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

const VERSION_OUTPUT: &str = concat!(
    "systemd 261 (261.2-1-arch)\n",
    "+PAM +AUDIT -SELINUX +APPARMOR -IMA +IPE +SMACK +SECCOMP +GCRYPT +GNUTLS +OPENSSL +ACL ",
    "+BLKID +CURL +ELFUTILS +FIDO2 +IDN2 +KMOD +LIBCRYPTSETUP +LIBCRYPTSETUP_PLUGINS +LIBFDISK ",
    "+PCRE2 +PWQUALITY +P11KIT +QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB +ZSTD +BPF_FRAMEWORK +BTF ",
    "+XKBCOMMON +UTMP +LIBARCHIVE\n"
);

const HELP: &str = concat!(
    "systemd-detect-virt [OPTIONS...]\n\n",
    "Detect execution in a virtualized environment.\n\n",
    "Options:\n",
    "  -h --help          Show this help\n",
    "     --version       Show package version\n",
    "  -q --quiet         Don't output anything, just set return value\n",
    "  -c --container     Only detect whether we are run in a container\n",
    "     --private-users Only detect whether we are running in a user namespace\n",
    "  -v --vm            Only detect whether we are run in a VM\n",
    "  -r --chroot        Detect whether we are run in a chroot() environment\n",
    "     --list          List all known and detectable types of virtualization\n",
    "     --cvm           Only detect whether we are run in a confidential VM\n",
    "     --list-cvm      List all known and detectable types of confidential\n",
    "                     virtualization\n\n",
    "See the systemd-detect-virt(1) man page for details.\n"
);

const VIRTUALIZATIONS: &[&str] = &[
    "none",
    "kvm",
    "amazon",
    "qemu",
    "bochs",
    "xen",
    "uml",
    "vmware",
    "oracle",
    "microsoft",
    "zvm",
    "parallels",
    "bhyve",
    "qnx",
    "acrn",
    "powervm",
    "apple",
    "sre",
    "google",
    "vm-other",
    "systemd-nspawn",
    "lxc-libvirt",
    "lxc",
    "openvz",
    "docker",
    "podman",
    "rkt",
    "wsl",
    "proot",
    "pouch",
    "container-other",
];
const CONFIDENTIAL_VIRTUALIZATIONS: &[&str] =
    &["none", "sev", "sev-es", "sev-snp", "tdx", "protvirt", "cca"];
const ROOT_OVERRIDE: &str = "SYSTEMD_DETECT_VIRT_ROOT";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Any,
    Vm,
    Container,
    Chroot,
    PrivateUsers,
    Cvm,
}

#[derive(Debug, Eq, PartialEq)]
struct Options {
    mode: Mode,
    quiet: bool,
}

enum ParseResult {
    Run(Options),
    Exit(&'static str),
}

fn main() {
    let arguments: Vec<String> = env::args().skip(1).collect();
    let result = match parse_options(&arguments) {
        Ok(ParseResult::Exit(output)) => write_stdout(output.as_bytes()).map(|()| true),
        Ok(ParseResult::Run(options)) => run(&options),
        Err(error) => {
            eprintln!("{error}");
            Err(())
        }
    };
    match result {
        Ok(true) => {}
        Ok(false) | Err(()) => std::process::exit(1),
    }
}

fn write_stdout(bytes: &[u8]) -> Result<(), ()> {
    io::stdout().lock().write_all(bytes).map_err(|_| ())
}

fn list(values: &[&str]) -> &'static str {
    if values.len() == VIRTUALIZATIONS.len() {
        concat!(
            "none\nkvm\namazon\nqemu\nbochs\nxen\numl\nvmware\noracle\nmicrosoft\nzvm\n",
            "parallels\nbhyve\nqnx\nacrn\npowervm\napple\nsre\ngoogle\nvm-other\n",
            "systemd-nspawn\nlxc-libvirt\nlxc\nopenvz\ndocker\npodman\nrkt\nwsl\nproot\npouch\n",
            "container-other\n"
        )
    } else {
        "none\nsev\nsev-es\nsev-snp\ntdx\nprotvirt\ncca\n"
    }
}

fn parse_options(arguments: &[String]) -> Result<ParseResult, String> {
    let mut options = Options {
        mode: Mode::Any,
        quiet: false,
    };
    let mut positional = false;
    let mut positional_only = false;
    for argument in arguments {
        if positional_only || argument == "-" || !argument.starts_with('-') {
            positional = true;
            continue;
        }
        if argument == "--" {
            positional_only = true;
            continue;
        }
        if let Some(long) = argument.strip_prefix("--") {
            let (name, attached) = long
                .split_once('=')
                .map_or((long, None), |(name, value)| (name, Some(value)));
            let option = resolve_long_option(name)?;
            reject_attached_argument(option, attached)?;
            match option {
                "help" => return Ok(ParseResult::Exit(HELP)),
                "version" => return Ok(ParseResult::Exit(VERSION_OUTPUT)),
                "quiet" => options.quiet = true,
                "container" => options.mode = Mode::Container,
                "private-users" => options.mode = Mode::PrivateUsers,
                "vm" => options.mode = Mode::Vm,
                "chroot" => options.mode = Mode::Chroot,
                "list" => return Ok(ParseResult::Exit(list(VIRTUALIZATIONS))),
                // v261 returns directly from parse_argv() for these modes.
                "cvm" => {
                    return Ok(ParseResult::Run(Options {
                        mode: Mode::Cvm,
                        ..options
                    }))
                }
                "list-cvm" => {
                    return Ok(ParseResult::Exit(list(CONFIDENTIAL_VIRTUALIZATIONS)));
                }
                _ => unreachable!("complete long-option match"),
            }
            continue;
        }
        for short in argument[1..].chars() {
            match short {
                'h' => return Ok(ParseResult::Exit(HELP)),
                'q' => options.quiet = true,
                'c' => options.mode = Mode::Container,
                'v' => options.mode = Mode::Vm,
                'r' => options.mode = Mode::Chroot,
                _ => {
                    return Err(format!(
                        "systemd-detect-virt: unrecognized option '-{short}'"
                    ));
                }
            }
        }
    }
    if positional {
        return Err("systemd-detect-virt takes no arguments.".to_owned());
    }
    Ok(ParseResult::Run(options))
}

fn resolve_long_option(value: &str) -> Result<&'static str, String> {
    const OPTIONS: &[&str] = &[
        "help",
        "version",
        "quiet",
        "container",
        "private-users",
        "vm",
        "chroot",
        "list",
        "cvm",
        "list-cvm",
    ];
    if let Some(exact) = OPTIONS.iter().copied().find(|option| *option == value) {
        return Ok(exact);
    }
    let matches: Vec<&str> = OPTIONS
        .iter()
        .copied()
        .filter(|option| option.starts_with(value))
        .collect();
    match matches.as_slice() {
        [single] => Ok(single),
        [] => Err(format!(
            "systemd-detect-virt: unrecognized option '--{value}'"
        )),
        _ => Err(format!(
            "systemd-detect-virt: option '--{value}' is ambiguous; possibilities: {}",
            matches
                .iter()
                .map(|option| format!("--{option}"))
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

fn reject_attached_argument(name: &str, attached: Option<&str>) -> Result<(), String> {
    if attached.is_some() {
        return Err(format!(
            "systemd-detect-virt: option '--{name}' doesn't allow an argument"
        ));
    }
    Ok(())
}

struct Detector {
    root: Option<PathBuf>,
}

impl Detector {
    fn new() -> Self {
        Self {
            root: env::var_os(ROOT_OVERRIDE).map(PathBuf::from),
        }
    }

    fn path(&self, absolute: &str) -> PathBuf {
        self.root.as_ref().map_or_else(
            || PathBuf::from(absolute),
            |root| root.join(absolute.trim_start_matches('/')),
        )
    }

    fn exists(&self, absolute: &str) -> bool {
        self.path(absolute).exists()
    }

    fn read(&self, absolute: &str) -> io::Result<String> {
        fs::read_to_string(self.path(absolute))
            .map(|text| text.trim_end_matches(['\n', '\r', '\0']).to_owned())
    }

    fn fixture_value(&self, name: &str) -> Option<String> {
        self.root.as_ref()?;
        self.read(&format!("/run/systemd/detect-virt/{name}")).ok()
    }

    fn detect_container_files(&self) -> Option<&'static str> {
        if self.exists("/run/.containerenv") {
            Some("podman")
        } else if self.exists("/.dockerenv") {
            Some("docker")
        } else {
            None
        }
    }

    fn translate_container(&self, name: &str) -> &'static str {
        if name == "oci" {
            return self.detect_container_files().unwrap_or("container-other");
        }
        match name {
            "lxc" => "lxc",
            "lxc-libvirt" => "lxc-libvirt",
            "systemd-nspawn" => "systemd-nspawn",
            "docker" => "docker",
            "podman" => "podman",
            "rkt" => "rkt",
            "wsl" => "wsl",
            "proot" => "proot",
            "pouch" => "pouch",
            _ => "container-other",
        }
    }

    fn detect_container(&self) -> &'static str {
        if self.exists("/proc/vz") && !self.exists("/proc/bc") {
            return "openvz";
        }
        if self
            .read("/proc/sys/kernel/osrelease")
            .is_ok_and(|value| value.contains("Microsoft") || value.contains("WSL"))
        {
            return "wsl";
        }
        if let Ok(status) = self.read("/proc/self/status") {
            if let Some(pid) = status.lines().find_map(|line| {
                line.strip_prefix("TracerPid:")
                    .map(str::trim)
                    .filter(|pid| *pid != "0")
            }) {
                if self
                    .read(&format!("/proc/{pid}/comm"))
                    .is_ok_and(|comm| comm.starts_with("proot"))
                {
                    return "proot";
                }
            }
        }
        if let Ok(manager) = self.read("/run/host/container-manager") {
            if !manager.is_empty() {
                return self.translate_container(&manager);
            }
        }
        if let Ok(manager) = self.read("/run/systemd/container") {
            if !manager.is_empty() {
                return self.translate_container(&manager);
            }
        }
        if let Ok(environ) = fs::read(self.path("/proc/1/environ")) {
            if let Some(value) = environ.split(|byte| *byte == 0).find_map(|item| {
                item.strip_prefix(b"container=")
                    .and_then(|value| std::str::from_utf8(value).ok())
            }) {
                if !value.is_empty() {
                    return self.translate_container(value);
                }
            }
        }
        if let Some(container) = self.detect_container_files() {
            return container;
        }
        if self.namespace_is_init("pid", 0xEFFF_FFFC) == Some(false) {
            return "container-other";
        }
        "none"
    }

    fn detect_dmi(&self) -> &'static str {
        let paths = [
            "/sys/class/dmi/id/product_name",
            "/sys/class/dmi/id/sys_vendor",
            "/sys/class/dmi/id/board_vendor",
            "/sys/class/dmi/id/bios_vendor",
            "/sys/class/dmi/id/product_version",
        ];
        for path in paths {
            let Ok(value) = self.read(path) else { continue };
            let result = [
                ("KVM", "kvm"),
                ("OpenStack", "kvm"),
                ("KubeVirt", "kvm"),
                ("Amazon EC2", "amazon"),
                ("QEMU", "qemu"),
                ("VMware", "vmware"),
                ("VMW", "vmware"),
                ("innotek GmbH", "oracle"),
                ("VirtualBox", "oracle"),
                ("Oracle Corporation", "oracle"),
                ("Xen", "xen"),
                ("Bochs", "bochs"),
                ("Parallels", "parallels"),
                ("BHYVE", "bhyve"),
                ("Hyper-V", "microsoft"),
                ("Apple Virtualization", "apple"),
                ("Google Compute Engine", "google"),
            ]
            .into_iter()
            .find_map(|(prefix, id)| value.starts_with(prefix).then_some(id));
            if let Some(id) = result {
                if id == "amazon" {
                    return self.amazon_dmi_result();
                }
                return id;
            }
        }
        if self.smbios_vm_bit() == Some(true) {
            "vm-other"
        } else {
            "none"
        }
    }

    fn smbios_vm_bit(&self) -> Option<bool> {
        let bytes = fs::read(self.path("/sys/firmware/dmi/entries/0-0/raw")).ok()?;
        if bytes.len() < 20 || usize::from(bytes[1]) < 20 {
            return None;
        }
        Some(bytes[19] & (1 << 4) != 0)
    }

    fn amazon_dmi_result(&self) -> &'static str {
        match self.smbios_vm_bit() {
            Some(true) => "amazon",
            Some(false) => "none",
            None => self
                .read("/sys/class/dmi/id/product_name")
                .map_or("amazon", |name| {
                    let metal = name.find(".metal").is_some_and(|at| {
                        name.as_bytes()
                            .get(at + 6)
                            .map_or(true, |byte| *byte == b'-')
                    });
                    if metal {
                        "none"
                    } else {
                        "amazon"
                    }
                }),
        }
    }

    fn detect_uml(&self) -> bool {
        self.read("/proc/cpuinfo").is_ok_and(|cpuinfo| {
            cpuinfo.lines().any(|line| {
                line.strip_prefix("vendor_id\t: ")
                    .is_some_and(|vendor| vendor.starts_with("User Mode Linux"))
            })
        })
    }

    #[cfg(any(
        target_arch = "arm",
        target_arch = "aarch64",
        target_arch = "powerpc",
        target_arch = "powerpc64",
        target_arch = "riscv32",
        target_arch = "riscv64"
    ))]
    fn detect_device_tree(&self) -> &'static str {
        if let Ok(kind) = self.read("/proc/device-tree/hypervisor/compatible") {
            if kind == "linux,kvm" {
                return "kvm";
            }
            if kind.contains("xen") {
                return "xen";
            }
            if kind.contains("vmware") {
                return "vmware";
            }
            return "vm-other";
        }
        if self.exists("/proc/device-tree/ibm,partition-name")
            && self.exists("/proc/device-tree/hmc-managed?")
            && !self.exists("/proc/device-tree/chosen/qemu,graphic-width")
        {
            return "powervm";
        }
        if fs::read_dir(self.path("/proc/device-tree")).is_ok_and(|entries| {
            entries
                .filter_map(Result::ok)
                .any(|entry| entry.file_name().to_string_lossy().contains("fw-cfg"))
        }) {
            return "qemu";
        }
        match self.read("/proc/device-tree/compatible").as_deref() {
            Ok("qemu,pseries") => "qemu",
            Ok("linux,dummy-virt") => "vm-other",
            _ => "none",
        }
    }

    #[cfg(not(any(
        target_arch = "arm",
        target_arch = "aarch64",
        target_arch = "powerpc",
        target_arch = "powerpc64",
        target_arch = "riscv32",
        target_arch = "riscv64"
    )))]
    #[allow(clippy::unused_self)]
    fn detect_device_tree(&self) -> &'static str {
        "none"
    }

    #[cfg(target_arch = "s390x")]
    fn detect_zvm(&self) -> &'static str {
        self.read("/proc/sysinfo").map_or("none", |sysinfo| {
            sysinfo
                .lines()
                .find_map(|line| line.strip_prefix("VM00 Control Program:"))
                .map_or(
                    "none",
                    |value| {
                        if value.trim() == "z/VM" {
                            "zvm"
                        } else {
                            "kvm"
                        }
                    },
                )
        })
    }

    #[cfg(not(target_arch = "s390x"))]
    #[allow(clippy::unused_self)]
    fn detect_zvm(&self) -> &'static str {
        "none"
    }

    fn cpuid_vm(&self) -> &'static str {
        if let Some(value) = self.fixture_value("cpuid") {
            return cpuid_signature_to_vm(&value);
        }
        if self.root.is_some() {
            return "none";
        }
        native_cpuid_vm()
    }

    fn xen_dom0(&self) -> bool {
        if let Ok(features) = self.read("/sys/hypervisor/properties/features") {
            if let Ok(bits) = u64::from_str_radix(features.trim_start_matches("0x"), 16) {
                return bits & (1 << 11) != 0;
            }
        }
        self.read("/proc/xen/capabilities").is_ok_and(|caps| {
            caps.split(',')
                .any(|capability| capability.trim() == "control_d")
        })
    }

    fn detect_vm(&self) -> &'static str {
        let dmi = self.detect_dmi();
        if matches!(dmi, "oracle" | "xen" | "amazon" | "parallels") {
            return dmi;
        }
        if self.detect_uml() {
            return "uml";
        }
        let xen = self.exists("/proc/xen");
        if xen && !self.xen_dom0() {
            return "xen";
        }
        let cpuid = self.cpuid_vm();
        let hyperv = cpuid == "microsoft";
        let mut other = cpuid == "vm-other" || dmi == "vm-other";
        if cpuid == "kvm" && dmi == "google" {
            return "google";
        }
        if !matches!(cpuid, "none" | "microsoft" | "vm-other") {
            return cpuid;
        }
        if xen && self.xen_dom0() {
            return if hyperv {
                "microsoft"
            } else if other {
                "vm-other"
            } else {
                "none"
            };
        }
        if !matches!(dmi, "none" | "google" | "vm-other") {
            return dmi;
        }
        if let Ok(kind) = self.read("/sys/hypervisor/type") {
            if kind == "xen" {
                return "xen";
            }
            other = true;
        }
        let device_tree = self.detect_device_tree();
        if device_tree == "vm-other" {
            other = true;
        } else if device_tree != "none" {
            return device_tree;
        }
        let zvm = self.detect_zvm();
        if zvm != "none" {
            return zvm;
        }
        if hyperv {
            "microsoft"
        } else if other {
            "vm-other"
        } else {
            "none"
        }
    }

    fn namespace_is_init(&self, kind: &str, init_inode: u64) -> Option<bool> {
        if let Some(value) = self.fixture_value(&format!("{kind}-namespace")) {
            return Some(value == "init");
        }
        fs::metadata(self.path(&format!("/proc/self/ns/{kind}")))
            .ok()
            .map(|metadata| metadata.ino() == init_inode)
    }

    fn in_user_namespace(&self) -> io::Result<bool> {
        Ok(!self
            .namespace_is_init("user", 0xEFFF_FFFD)
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?)
    }

    fn in_chroot(&self) -> io::Result<bool> {
        if let Ok(value) = env::var("SYSTEMD_IN_CHROOT") {
            if let Some(boolean) = parse_boolean(&value) {
                return Ok(boolean);
            }
        }
        if env::var("SYSTEMD_IGNORE_CHROOT")
            .ok()
            .and_then(|value| parse_boolean(&value))
            == Some(true)
        {
            return Ok(false);
        }
        if let Some(value) = self.fixture_value("chroot") {
            return Ok(value == "yes");
        }
        let root = fs::metadata(self.path("/"))?;
        let pid1_root = fs::metadata(self.path("/proc/1/root"))?;
        Ok(root.dev() != pid1_root.dev() || root.ino() != pid1_root.ino())
    }

    fn detect_cvm(&self) -> &'static str {
        if let Some(value) = self.fixture_value("cvm") {
            return CONFIDENTIAL_VIRTUALIZATIONS
                .iter()
                .copied()
                .find(|known| *known == value)
                .unwrap_or("none");
        }
        if self.root.is_some() {
            return "none";
        }
        native_cvm()
    }
}

fn parse_boolean(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "yes" | "y" | "true" | "t" | "on" => Some(true),
        "0" | "no" | "n" | "false" | "f" | "off" => Some(false),
        _ => None,
    }
}

fn run(options: &Options) -> Result<bool, ()> {
    let detector = Detector::new();
    match options.mode {
        Mode::Chroot => detector.in_chroot().map_err(|error| {
            eprintln!(
                "Failed to check for chroot() environment: {}",
                concise_io_error(&error)
            );
        }),
        Mode::PrivateUsers => detector.in_user_namespace().map_err(|error| {
            eprintln!(
                "Failed to check for user namespace: {}",
                concise_io_error(&error)
            );
        }),
        Mode::Vm | Mode::Container | Mode::Cvm | Mode::Any => {
            let detected = match options.mode {
                Mode::Vm => detector.detect_vm(),
                Mode::Container => detector.detect_container(),
                Mode::Cvm => detector.detect_cvm(),
                Mode::Any => {
                    let container = detector.detect_container();
                    if container == "none" {
                        detector.detect_vm()
                    } else {
                        container
                    }
                }
                Mode::Chroot | Mode::PrivateUsers => unreachable!(),
            };
            if !options.quiet {
                write_stdout(format!("{detected}\n").as_bytes())?;
            }
            Ok(detected != "none")
        }
    }
}

fn concise_io_error(error: &io::Error) -> String {
    let rendered = error.to_string();
    // `io::Error` adds this suffix, while systemd's `%m` renders strerror(3).
    rendered
        .split(" (os error ")
        .next()
        .unwrap_or(&rendered)
        .to_owned()
}

fn cpuid_signature_to_vm(signature: &str) -> &'static str {
    match signature.trim_end_matches('\0') {
        "XenVMMXenVMM" => "xen",
        "KVMKVMKVM" | "Linux KVM Hv" => "kvm",
        "TCGTCGTCGTCG" => "qemu",
        "VMwareVMware" => "vmware",
        "Microsoft Hv" => "microsoft",
        "bhyve bhyve " => "bhyve",
        "QNXQVMBSQG" => "qnx",
        "ACRNACRNACRN" => "acrn",
        "SRESRESRESRE" => "sre",
        "Apple VZ" => "apple",
        "none" | "" => "none",
        _ => "vm-other",
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[allow(unused_unsafe)] // Rust 1.75 declares this intrinsic unsafe; newer compilers do not.
fn native_cpuid_vm() -> &'static str {
    #[cfg(target_arch = "x86")]
    use std::arch::x86::__cpuid;
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::__cpuid;
    // SAFETY: CPUID is supported on the x86 targets accepted by this crate.
    let features = unsafe { __cpuid(1) };
    if features.ecx & (1 << 31) == 0 {
        return "none";
    }
    // SAFETY: querying a CPUID leaf is side-effect free.
    let vendor = unsafe { __cpuid(0x4000_0000) };
    let mut bytes = Vec::with_capacity(12);
    bytes.extend_from_slice(&vendor.ebx.to_le_bytes());
    bytes.extend_from_slice(&vendor.ecx.to_le_bytes());
    bytes.extend_from_slice(&vendor.edx.to_le_bytes());
    cpuid_signature_to_vm(std::str::from_utf8(&bytes).unwrap_or("unknown"))
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn native_cpuid_vm() -> &'static str {
    "none"
}

#[cfg(target_arch = "x86_64")]
#[allow(unused_unsafe)] // Rust 1.75 declares this intrinsic unsafe; newer compilers do not.
fn native_cvm() -> &'static str {
    use std::arch::x86_64::__cpuid;
    // SAFETY: CPUID is supported on x86_64.
    if unsafe { __cpuid(1) }.ecx & (1 << 31) == 0 {
        return "none";
    }
    // SAFETY: querying a CPUID leaf is side-effect free.
    let vendor = unsafe { __cpuid(0) };
    let mut signature = Vec::with_capacity(12);
    signature.extend_from_slice(&vendor.ebx.to_le_bytes());
    signature.extend_from_slice(&vendor.edx.to_le_bytes());
    signature.extend_from_slice(&vendor.ecx.to_le_bytes());
    if signature == b"AuthenticAMD" {
        // SAFETY: querying supported-leaf information is side-effect free.
        if unsafe { __cpuid(0x8000_0000) }.eax < 0x8000_001f {
            return "none";
        }
        // SAFETY: the maximum-leaf check above establishes leaf availability.
        let encrypted = unsafe { __cpuid(0x8000_001f) };
        if encrypted.eax & 2 == 0 {
            return if hyperv_isolation_type(2) {
                "sev-snp"
            } else {
                "none"
            };
        }
        let mut bytes = [0_u8; 8];
        if File::open("/dev/cpu/0/msr")
            .and_then(|file| file.read_exact_at(&mut bytes, 0xc001_0131))
            .is_ok()
        {
            let state = u64::from_ne_bytes(bytes);
            if state & 4 != 0 {
                return "sev-snp";
            }
            if state & 2 != 0 {
                return "sev-es";
            }
            if state & 1 != 0 {
                return "sev";
            }
        }
        return "none";
    } else if signature == b"GenuineIntel" {
        // SAFETY: CPUID leaf zero reports the maximum standard leaf.
        if vendor.eax < 0x21 {
            return "none";
        }
        // SAFETY: the maximum-leaf check above establishes leaf availability.
        let tdx = unsafe { __cpuid(0x21) };
        let mut bytes = Vec::with_capacity(12);
        bytes.extend_from_slice(&tdx.ebx.to_le_bytes());
        bytes.extend_from_slice(&tdx.edx.to_le_bytes());
        bytes.extend_from_slice(&tdx.ecx.to_le_bytes());
        if bytes == b"IntelTDX    " {
            return "tdx";
        }
        return if hyperv_isolation_type(3) {
            "tdx"
        } else {
            "none"
        };
    }
    "none"
}

#[cfg(target_arch = "x86_64")]
#[allow(unused_unsafe)] // Rust 1.75 declares this intrinsic unsafe; newer compilers do not.
fn hyperv_isolation_type(expected: u32) -> bool {
    use std::arch::x86_64::__cpuid;
    // SAFETY: CPUID is supported on x86_64.
    let vendor = unsafe { __cpuid(0x4000_0000) };
    if !(0x4000_0005..=0x4000_ffff).contains(&vendor.eax) {
        return false;
    }
    let mut signature = Vec::with_capacity(12);
    signature.extend_from_slice(&vendor.ebx.to_le_bytes());
    signature.extend_from_slice(&vendor.ecx.to_le_bytes());
    signature.extend_from_slice(&vendor.edx.to_le_bytes());
    if signature != b"Microsoft Hv" {
        return false;
    }
    // SAFETY: Hyper-V's reported maximum leaf covers this feature leaf.
    let features = unsafe { __cpuid(0x4000_0003) };
    if features.ebx & (1 << 22) == 0 || features.ebx & (1 << 12) != 0 {
        return false;
    }
    // SAFETY: Hyper-V's reported maximum leaf covers this isolation leaf.
    unsafe { __cpuid(0x4000_000c) }.ebx & 0xf == expected
}

#[cfg(target_arch = "s390x")]
fn native_cvm() -> &'static str {
    fs::read_to_string("/sys/firmware/uv/prot_virt_guest")
        .ok()
        .filter(|value| value.starts_with('1'))
        .map_or("none", |_| "protvirt")
}

#[cfg(target_arch = "aarch64")]
fn native_cvm() -> &'static str {
    if std::path::Path::new("/sys/devices/platform/arm-cca-dev").exists() {
        "cca"
    } else {
        "none"
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "s390x", target_arch = "aarch64")))]
fn native_cvm() -> &'static str {
    "none"
}
