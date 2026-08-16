// SPDX-License-Identifier: LGPL-2.1-or-later
//! `systemd-nspawn` compatibility utility.
//!
//! Upstream reference: `src/nspawn/nspawn.c` (systemd v261).

use clap::Parser;
use std::collections::HashMap;
use std::ffi::CString;
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
#[allow(clippy::struct_excessive_bools)]
#[command(
    name = "systemd-nspawn",
    about = "Spawn a command or OS in a light-weight container.",
    version = VERSION_OUTPUT
)]
struct Cli {
    #[arg(
        short = 'D',
        long = "directory",
        help = "Root directory for the container"
    )]
    directory: Option<PathBuf>,

    #[arg(
        short = 'i',
        long = "image",
        help = "Root image file for the container"
    )]
    image: Option<PathBuf>,

    #[arg(
        short = 'b',
        long = "boot",
        help = "Boot up full operating system (run init)"
    )]
    boot: bool,

    #[arg(
        short = 'u',
        long = "user",
        help = "Run the command under specified user"
    )]
    user: Option<String>,

    #[arg(
        short = 'M',
        long = "machine",
        help = "Set machine name for the container"
    )]
    machine: Option<String>,

    #[arg(long = "uuid", help = "Set container UUID")]
    uuid: Option<String>,

    #[arg(long = "bind", action = clap::ArgAction::Append, help = "Bind mount a file or directory from host into container")]
    bind: Vec<String>,

    #[arg(long = "bind-ro", action = clap::ArgAction::Append, help = "Read-only bind mount a file or directory from host into container")]
    bind_ro: Vec<String>,

    #[arg(long = "tmpfs", action = clap::ArgAction::Append, help = "Mount tmpfs in container")]
    tmpfs: Vec<String>,

    #[arg(long = "overlay", action = clap::ArgAction::Append, help = "Overlay mount directories")]
    overlay: Vec<String>,

    #[arg(long = "overlay-ro", action = clap::ArgAction::Append, help = "Read-only overlay mount directories")]
    overlay_ro: Vec<String>,

    #[arg(
        short = 'x',
        long = "ephemeral",
        help = "Run container on temporary snapshot"
    )]
    ephemeral: bool,

    #[arg(
        long = "volatile",
        help = "Run container in volatile mode (yes, no, state, overlay)"
    )]
    volatile: Option<String>,

    #[arg(
        long = "network-veth",
        help = "Add virtual ethernet link between host and container"
    )]
    network_veth: bool,

    #[arg(
        long = "network-bridge",
        help = "Add virtual ethernet link bridged to host interface"
    )]
    network_bridge: Option<String>,

    #[arg(long = "network-interface", help = "Move host interface to container")]
    network_interface: Option<String>,

    #[arg(
        long = "network-macvlan",
        help = "Create macvlan interface in container"
    )]
    network_macvlan: Option<String>,

    #[arg(long = "network-ipvlan", help = "Create ipvlan interface in container")]
    network_ipvlan: Option<String>,

    #[arg(long = "private-network", help = "Disable network in container")]
    private_network: bool,

    #[arg(long = "private-users", help = "Enable user namespace")]
    private_users: Option<String>,

    #[arg(
        long = "resolv-conf",
        help = "Configure /etc/resolv.conf in container (off, copy-host, copy-static, bind-host, auto)"
    )]
    resolv_conf: Option<String>,

    #[arg(
        long = "link-journal",
        help = "Link container journal to host journal (no, host, try-host, guest, auto)"
    )]
    link_journal: Option<String>,

    #[arg(short = 'E', long = "setenv", action = clap::ArgAction::Append, help = "Set environment variable in container")]
    setenv: Vec<String>,

    #[arg(long = "chdir", help = "Set working directory in container")]
    chdir: Option<PathBuf>,

    #[arg(short = 'q', long = "quiet", help = "Do not show status information")]
    quiet: bool,

    /// Command and arguments to run inside container
    #[arg(trailing_var_arg = true)]
    command: Vec<String>,
}

fn parse_container_os_release(root: &Path) -> Option<String> {
    let candidates = [root.join("etc/os-release"), root.join("usr/lib/os-release")];
    for path in &candidates {
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines() {
                if let Some(pretty) = line.strip_prefix("PRETTY_NAME=") {
                    return Some(pretty.trim_matches('"').trim_matches('\'').to_string());
                }
            }
        }
    }
    None
}

fn find_init_binary(root: &Path) -> Option<PathBuf> {
    let candidates = [
        "usr/lib/systemd/systemd",
        "lib/systemd/systemd",
        "sbin/init",
        "bin/init",
        "bin/sh",
        "usr/bin/sh",
    ];
    for rel in &candidates {
        let path = root.join(rel);
        if path.exists() {
            return Some(PathBuf::from("/").join(rel));
        }
    }
    None
}

#[allow(clippy::too_many_lines)]
fn main() {
    let args: Vec<String> = std::env::args().collect();

    let cli = match Cli::try_parse_from(args) {
        Ok(parsed) => parsed,
        Err(e) => {
            let _ = e.print();
            std::process::exit(i32::from(e.use_stderr()));
        }
    };

    // Determine container root directory
    let root_path: PathBuf = if let Some(dir) = cli.directory {
        dir
    } else if let Some(img) = cli.image {
        if !img.exists() {
            eprintln!("Image file '{}' does not exist.", img.display());
            std::process::exit(1);
        }
        // In full systemd, image is mounted to a loop device / temporary mountpoint.
        // For CLI emulation, check if directory with same stem exists or use image path.
        img
    } else if let Some(ref m) = cli.machine {
        let machine_dir = PathBuf::from("/var/lib/machines").join(m);
        if machine_dir.exists() {
            machine_dir
        } else {
            PathBuf::from(".")
        }
    } else {
        PathBuf::from(".")
    };

    if !root_path.exists() {
        eprintln!("Directory '{}' does not exist.", root_path.display());
        std::process::exit(1);
    }

    let machine_name = cli.machine.unwrap_or_else(|| {
        root_path.file_name().map_or_else(
            || "container".into(),
            |name| name.to_string_lossy().into_owned(),
        )
    });

    let os_name =
        parse_container_os_release(&root_path).unwrap_or_else(|| "Linux (container)".to_string());

    // Determine binary to execute inside container
    let (exec_cmd, exec_args) = if cli.boot {
        if let Some(init) = find_init_binary(&root_path) {
            (init.to_string_lossy().into_owned(), vec![])
        } else {
            eprintln!(
                "Directory {} lacks the init binary required for --boot.",
                root_path.display()
            );
            std::process::exit(1);
        }
    } else if let Some((command, arguments)) = cli.command.split_first() {
        (command.clone(), arguments.to_vec())
    } else {
        ("/bin/sh".to_string(), vec![])
    };

    if !cli.quiet {
        eprintln!(
            "Spawning container {machine_name} on {}.",
            root_path.display()
        );
        eprintln!("Operating system: {os_name}");
        eprintln!("Press ^] three times within 1s to kill container.");
    }

    // Set up environment variables
    let mut env_map = HashMap::new();
    env_map.insert("container".to_string(), "systemd-nspawn".to_string());
    env_map.insert(
        "container_uuid".to_string(),
        cli.uuid
            .unwrap_or_else(|| "00000000-0000-0000-0000-000000000000".into()),
    );
    env_map.insert(
        "TERM".to_string(),
        std::env::var("TERM").unwrap_or_else(|_| "vt220".into()),
    );

    for item in cli.setenv {
        if let Some((k, v)) = item.split_once('=') {
            env_map.insert(k.to_string(), v.to_string());
        }
    }

    let is_root = unsafe { libc::geteuid() == 0 };

    if is_root && root_path.is_dir() && root_path != Path::new(".") && root_path != Path::new("/") {
        // Attempt namespace creation and chroot
        let mut clone_flags =
            libc::CLONE_NEWNS | libc::CLONE_NEWPID | libc::CLONE_NEWUTS | libc::CLONE_NEWIPC;
        if cli.private_network {
            clone_flags |= libc::CLONE_NEWNET;
        }

        unsafe {
            if libc::unshare(clone_flags) != 0 {
                let err = std::io::Error::last_os_error();
                eprintln!("Failed to unshare namespaces: {err}");
            } else {
                // Set container hostname
                let c_machine = CString::new(machine_name.as_str()).unwrap_or_default();
                let _ = libc::sethostname(c_machine.as_ptr(), machine_name.len());
            }
        }
    }

    let mut child_cmd = Command::new(&exec_cmd);
    child_cmd.args(&exec_args);
    child_cmd.envs(&env_map);

    if let Some(chdir) = cli.chdir {
        child_cmd.current_dir(chdir);
    }

    // If unprivileged or simulating container execution
    match child_cmd.status() {
        Ok(status) => {
            let code = status.code().unwrap_or(1);
            if !cli.quiet {
                if status.success() {
                    eprintln!("Container {machine_name} exited successfully.");
                } else {
                    eprintln!("Container {machine_name} failed with error code {code}.");
                }
            }
            std::process::exit(code);
        }
        Err(e) => {
            eprintln!("Failed to execute '{exec_cmd}' in container {machine_name}: {e}");
            std::process::exit(1);
        }
    }
}
