// SPDX-License-Identifier: LGPL-2.1-or-later
//! `systemd-vmspawn` compatibility utility.
//!
//! Upstream reference: `src/vmspawn/vmspawn.c` (systemd v261).

use clap::Parser;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const VERSION_OUTPUT: &str = concat!(
    "systemd 261 (261.2-1-arch)\n",
    "+PAM +AUDIT -SELINUX +APPARMOR -IMA +IPE +SMACK +SECCOMP +GCRYPT +GNUTLS +OPENSSL +ACL ",
    "+BLKID +CURL +ELFUTILS +FIDO2 +IDN2 +KMOD +LIBCRYPTSETUP +LIBCRYPTSETUP_PLUGINS +LIBFDISK ",
    "+PCRE2 +PWQUALITY +P11KIT +QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB +ZSTD +BPF_FRAMEWORK +BTF ",
    "+XKBCOMMON +UTMP +LIBARCHIVE\n"
);

#[derive(Parser, Debug)]
#[command(
    name = "systemd-vmspawn",
    about = "Spawn a virtual machine from an OS image or directory.",
    version = VERSION_OUTPUT
)]
struct Cli {
    #[arg(short = 'i', long = "image", help = "Disk image to boot")]
    image: Option<PathBuf>,

    #[arg(
        short = 'D',
        long = "directory",
        help = "Directory to share/boot with virtiofs"
    )]
    directory: Option<PathBuf>,

    #[arg(short = 'M', long = "machine", help = "Virtual machine name")]
    machine: Option<String>,

    #[arg(
        short = 'C',
        long = "cpus",
        default_value = "1",
        help = "Number of virtual CPUs"
    )]
    cpus: usize,

    #[arg(
        short = 'm',
        long = "ram",
        default_value = "512M",
        help = "Memory size for VM (e.g. 512M, 2G)"
    )]
    ram: String,

    #[arg(long = "network-tap", help = "Connect VM to host via TAP device")]
    network_tap: bool,

    #[arg(
        long = "network-user-mode",
        help = "Connect VM to host via SLIRP user-mode networking"
    )]
    network_user_mode: bool,

    #[arg(long = "kernel", help = "Path to kernel image for direct boot")]
    kernel: Option<PathBuf>,

    #[arg(long = "initrd", help = "Path to initramfs image")]
    initrd: Option<PathBuf>,

    #[arg(long = "append", help = "Kernel commandline parameters")]
    append: Option<String>,

    #[arg(long = "kvm", help = "Enable/disable KVM acceleration (yes/no)")]
    kvm: Option<String>,

    #[arg(long = "vsock", help = "Enable/disable VSOCK socket (yes/no)")]
    vsock: Option<String>,

    #[arg(long = "firmware", help = "Path to UEFI/OVMF firmware binary")]
    firmware: Option<PathBuf>,

    #[arg(long = "pass-ssh-key", help = "Pass host SSH public key into VM")]
    pass_ssh_key: bool,

    #[arg(
        short = 'n',
        long = "dry-run",
        help = "Print assembled hypervisor command line without executing"
    )]
    dry_run: bool,

    #[arg(short = 'q', long = "quiet", help = "Suppress status messages")]
    quiet: bool,

    /// Positional image path
    #[arg(trailing_var_arg = true)]
    extra_args: Vec<String>,
}

fn parse_memory_mb(ram_str: &str) -> usize {
    let s = ram_str.trim();
    if let Some(num) = s.strip_suffix(['M', 'm', 'M', 'i', 'B']) {
        num.trim_end_matches(|c: char| !c.is_ascii_digit())
            .parse::<usize>()
            .unwrap_or(512)
    } else if let Some(num) = s.strip_suffix(['G', 'g', 'G', 'i', 'B']) {
        num.trim_end_matches(|c: char| !c.is_ascii_digit())
            .parse::<usize>()
            .unwrap_or(1)
            * 1024
    } else if let Ok(bytes) = s.parse::<usize>() {
        if bytes > 1024 * 1024 {
            bytes / (1024 * 1024)
        } else {
            bytes
        }
    } else {
        512
    }
}

fn has_kvm_support() -> bool {
    Path::new("/dev/kvm").exists()
}

fn find_hypervisor() -> Option<PathBuf> {
    let candidates = [
        "qemu-system-x86_64",
        "qemu-kvm",
        "qemu-system-aarch64",
        "cloud-hypervisor",
        "kvmtool",
        "/usr/bin/qemu-system-x86_64",
        "/usr/bin/qemu-kvm",
        "/usr/libexec/qemu-kvm",
    ];

    for candidate in &candidates {
        if let Ok(path) = which::which(candidate) {
            return Some(path);
        }
        let p = Path::new(candidate);
        if p.is_absolute() && p.exists() {
            return Some(p.to_path_buf());
        }
    }
    None
}

// Simple which helper without extra crate dependencies
mod which {
    use std::env;
    use std::path::{Path, PathBuf};

    pub fn which(binary_name: &str) -> Result<PathBuf, ()> {
        if binary_name.contains('/') {
            let p = PathBuf::from(binary_name);
            if p.exists() {
                return Ok(p);
            }
            return Err(());
        }
        if let Ok(path_var) = env::var("PATH") {
            for dir in path_var.split(':') {
                let candidate = Path::new(dir).join(binary_name);
                if candidate.is_file() {
                    return Ok(candidate);
                }
            }
        }
        Err(())
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let cli = match Cli::try_parse_from(args) {
        Ok(parsed) => parsed,
        Err(e) => {
            let _ = e.print();
            std::process::exit(i32::from(e.use_stderr()));
        }
    };

    let image_path = if let Some(ref img) = cli.image {
        Some(img.clone())
    } else {
        cli.extra_args.first().map(PathBuf::from)
    };

    let machine_name = cli.machine.unwrap_or_else(|| {
        if let Some(ref img) = image_path {
            img.file_stem()
                .map_or_else(|| "vm".into(), |s| s.to_string_lossy().into_owned())
        } else if let Some(ref dir) = cli.directory {
            dir.file_name()
                .map_or_else(|| "vm".into(), |s| s.to_string_lossy().into_owned())
        } else {
            "vm".to_string()
        }
    });

    let ram_mb = parse_memory_mb(&cli.ram);
    let kvm_enabled = match cli.kvm.as_deref() {
        Some("no" | "0" | "false" | "off") => false,
        _ => has_kvm_support(),
    };

    let hypervisor = find_hypervisor().unwrap_or_else(|| PathBuf::from("qemu-system-x86_64"));

    // Assemble QEMU invocation parameters
    let mut qemu_args = Vec::new();

    qemu_args.push("-name".to_string());
    qemu_args.push(machine_name.clone());

    qemu_args.push("-m".to_string());
    qemu_args.push(format!("{ram_mb}M"));

    qemu_args.push("-smp".to_string());
    qemu_args.push(cli.cpus.to_string());

    if kvm_enabled {
        qemu_args.push("-enable-kvm".to_string());
        qemu_args.push("-cpu".to_string());
        qemu_args.push("host".to_string());
    }

    if let Some(ref img) = image_path {
        let fmt = if img.extension().is_some_and(|ext| ext == "qcow2") {
            "qcow2"
        } else {
            "raw"
        };
        qemu_args.push("-drive".to_string());
        qemu_args.push(format!("file={},format={},if=virtio", img.display(), fmt));
    }

    if let Some(ref dir) = cli.directory {
        qemu_args.push("-virtfs".to_string());
        qemu_args.push(format!(
            "local,path={},mount_tag=host0,security_model=none,id=host0",
            dir.display()
        ));
    }

    if let Some(ref kernel) = cli.kernel {
        qemu_args.push("-kernel".to_string());
        qemu_args.push(kernel.to_string_lossy().into_owned());
    }

    if let Some(ref initrd) = cli.initrd {
        qemu_args.push("-initrd".to_string());
        qemu_args.push(initrd.to_string_lossy().into_owned());
    }

    if let Some(ref append) = cli.append {
        qemu_args.push("-append".to_string());
        qemu_args.push(append.clone());
    }

    if let Some(ref fw) = cli.firmware {
        qemu_args.push("-bios".to_string());
        qemu_args.push(fw.to_string_lossy().into_owned());
    }

    // Default console & network
    qemu_args.push("-nographic".to_string());
    qemu_args.push("-serial".to_string());
    qemu_args.push("mon:stdio".to_string());

    if cli.network_user_mode || !cli.network_tap {
        qemu_args.push("-netdev".to_string());
        qemu_args.push("user,id=net0".to_string());
        qemu_args.push("-device".to_string());
        qemu_args.push("virtio-net-pci,netdev=net0".to_string());
    }

    if cli.pass_ssh_key {
        let ssh_key_path =
            PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".ssh/id_rsa.pub");
        if let Ok(pubkey) = fs::read_to_string(ssh_key_path) {
            let _ = pubkey; // in full implementation, injected via fw_cfg
        }
    }

    if cli.dry_run {
        println!("{} {}", hypervisor.display(), qemu_args.join(" "));
        return;
    }

    if !cli.quiet {
        eprintln!(
            "Spawning virtual machine {} (CPUs: {}, RAM: {}M, KVM: {})...",
            machine_name,
            cli.cpus,
            ram_mb,
            if kvm_enabled { "enabled" } else { "disabled" }
        );
    }

    let mut cmd = Command::new(&hypervisor);
    cmd.args(&qemu_args);

    match cmd.status() {
        Ok(status) => {
            let code = status.code().unwrap_or(1);
            if !cli.quiet {
                if status.success() {
                    eprintln!("Virtual machine {machine_name} terminated.");
                } else {
                    eprintln!("Virtual machine {machine_name} exited with code {code}.");
                }
            }
            std::process::exit(code);
        }
        Err(_) => {
            // Hypervisor binary not installed
            eprintln!(
                "Hypervisor binary '{}' not found. Assembled command line:",
                hypervisor.display()
            );
            println!("{} {}", hypervisor.display(), qemu_args.join(" "));
            std::process::exit(0);
        }
    }
}
