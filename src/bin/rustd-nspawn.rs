// SPDX-License-Identifier: LGPL-2.1-or-later
//! RustD lightweight container launcher.
//!
//! The supported execution core is deliberately fail-closed: a requested
//! isolation feature must either be applied successfully or the container is
//! not started.

use clap::Parser;
use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::ptr;

const VERSION_OUTPUT: &str = concat!(
    "RustD nspawn 0.1.0\n",
    "native Linux namespace container launcher\n"
);

#[derive(Parser, Debug)]
#[allow(clippy::struct_excessive_bools)]
#[command(
    name = "rustd-nspawn",
    about = "Spawn a command or OS in a lightweight RustD container.",
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

    #[arg(long = "volatile", help = "Run container in volatile mode")]
    volatile: Option<String>,

    #[arg(
        long = "network-veth",
        help = "Add virtual ethernet link between host and container"
    )]
    network_veth: bool,

    #[arg(
        long = "network-bridge",
        help = "Bridge a virtual ethernet link to a host interface"
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

    #[arg(long = "private-network", help = "Create a private network namespace")]
    private_network: bool,

    #[arg(long = "private-users", help = "Enable a mapped user namespace")]
    private_users: Option<String>,

    #[arg(long = "resolv-conf", help = "Configure /etc/resolv.conf in container")]
    resolv_conf: Option<String>,

    #[arg(long = "link-journal", help = "Link container journal to host journal")]
    link_journal: Option<String>,

    #[arg(short = 'E', long = "setenv", action = clap::ArgAction::Append, help = "Set environment variable in container")]
    setenv: Vec<String>,

    #[arg(long = "chdir", help = "Set working directory in container")]
    chdir: Option<PathBuf>,

    #[arg(short = 'q', long = "quiet", help = "Do not show status information")]
    quiet: bool,

    /// Command and arguments to run inside container.
    #[arg(trailing_var_arg = true)]
    command: Vec<String>,
}

fn fail(message: impl std::fmt::Display) -> ! {
    eprintln!("rustd-nspawn: {message}");
    std::process::exit(1);
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
        "usr/lib/rustd/rustd",
        "sbin/rustd",
        "sbin/init",
        "bin/init",
        "bin/sh",
        "usr/bin/sh",
    ];
    for rel in &candidates {
        if root.join(rel).exists() {
            return Some(PathBuf::from("/").join(rel));
        }
    }
    None
}

fn cstring_path(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path contains an embedded NUL byte: {}", path.display()),
        )
    })
}

fn unshare(flags: libc::c_int, description: &str) -> io::Result<()> {
    if unsafe { libc::unshare(flags) } == 0 {
        Ok(())
    } else {
        Err(io::Error::new(
            io::Error::last_os_error().kind(),
            format!(
                "failed to create {description}: {}",
                io::Error::last_os_error()
            ),
        ))
    }
}

fn configure_user_namespace() -> io::Result<()> {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    unshare(libc::CLONE_NEWUSER, "user namespace")?;

    let setgroups = Path::new("/proc/self/setgroups");
    if setgroups.exists() {
        fs::write(setgroups, "deny\n")?;
    }
    fs::write("/proc/self/uid_map", format!("0 {uid} 1\n"))?;
    fs::write("/proc/self/gid_map", format!("0 {gid} 1\n"))?;
    Ok(())
}

fn make_mount_namespace_private() -> io::Result<()> {
    let slash = CString::new("/").expect("static path has no NUL");
    let flags = (libc::MS_REC | libc::MS_PRIVATE) as libc::c_ulong;
    if unsafe { libc::mount(ptr::null(), slash.as_ptr(), ptr::null(), flags, ptr::null()) } == 0 {
        Ok(())
    } else {
        Err(io::Error::new(
            io::Error::last_os_error().kind(),
            format!(
                "failed to make mount namespace private: {}",
                io::Error::last_os_error()
            ),
        ))
    }
}

fn set_container_hostname(machine_name: &str) -> io::Result<()> {
    let hostname = CString::new(machine_name).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "machine name contains an embedded NUL byte",
        )
    })?;
    if unsafe { libc::sethostname(hostname.as_ptr(), machine_name.len()) } == 0 {
        Ok(())
    } else {
        Err(io::Error::new(
            io::Error::last_os_error().kind(),
            format!(
                "failed to set container hostname: {}",
                io::Error::last_os_error()
            ),
        ))
    }
}

fn reject_unimplemented_features(cli: &Cli) {
    let mut unsupported = Vec::new();
    if cli.image.is_some() {
        unsupported.push("--image");
    }
    if cli.user.is_some() {
        unsupported.push("--user");
    }
    if !cli.bind.is_empty() {
        unsupported.push("--bind");
    }
    if !cli.bind_ro.is_empty() {
        unsupported.push("--bind-ro");
    }
    if !cli.tmpfs.is_empty() {
        unsupported.push("--tmpfs");
    }
    if !cli.overlay.is_empty() {
        unsupported.push("--overlay");
    }
    if !cli.overlay_ro.is_empty() {
        unsupported.push("--overlay-ro");
    }
    if cli.ephemeral {
        unsupported.push("--ephemeral");
    }
    if cli.volatile.is_some() {
        unsupported.push("--volatile");
    }
    if cli.network_veth {
        unsupported.push("--network-veth");
    }
    if cli.network_bridge.is_some() {
        unsupported.push("--network-bridge");
    }
    if cli.network_interface.is_some() {
        unsupported.push("--network-interface");
    }
    if cli.network_macvlan.is_some() {
        unsupported.push("--network-macvlan");
    }
    if cli.network_ipvlan.is_some() {
        unsupported.push("--network-ipvlan");
    }
    if cli.resolv_conf.is_some() {
        unsupported.push("--resolv-conf");
    }
    if cli.link_journal.is_some() {
        unsupported.push("--link-journal");
    }
    if !unsupported.is_empty() {
        fail(format!(
            "requested feature is not implemented safely yet: {}",
            unsupported.join(", ")
        ));
    }
}

#[allow(clippy::too_many_lines)]
fn main() {
    let cli = match Cli::try_parse() {
        Ok(parsed) => parsed,
        Err(error) => {
            let _ = error.print();
            std::process::exit(i32::from(error.use_stderr()));
        }
    };

    reject_unimplemented_features(&cli);

    let root_path = if let Some(directory) = cli.directory.as_ref() {
        directory.clone()
    } else if let Some(machine) = cli.machine.as_ref() {
        let machine_dir = PathBuf::from("/var/lib/machines").join(machine);
        if !machine_dir.is_dir() {
            fail(format!(
                "machine root does not exist: {}",
                machine_dir.display()
            ));
        }
        machine_dir
    } else {
        PathBuf::from(".")
    };

    if !root_path.is_dir() {
        fail(format!(
            "container root is not a directory: {}",
            root_path.display()
        ));
    }
    let root_path = root_path
        .canonicalize()
        .unwrap_or_else(|error| fail(format!("cannot resolve container root: {error}")));
    if root_path == Path::new("/") {
        fail("refusing to use the host root filesystem as a container root");
    }

    let machine_name = cli.machine.clone().unwrap_or_else(|| {
        root_path.file_name().map_or_else(
            || "rustd-container".into(),
            |name| name.to_string_lossy().into_owned(),
        )
    });
    if machine_name.is_empty() || machine_name.len() > 64 || machine_name.contains('/') {
        fail("machine name must contain 1..64 non-path characters");
    }

    let os_name =
        parse_container_os_release(&root_path).unwrap_or_else(|| "Linux (container)".to_string());

    let (exec_cmd, exec_args) = if cli.boot {
        if let Some(init) = find_init_binary(&root_path) {
            (init.to_string_lossy().into_owned(), Vec::new())
        } else {
            fail(format!(
                "{} lacks a RustD/init binary required for --boot",
                root_path.display()
            ));
        }
    } else if let Some((command, arguments)) = cli.command.split_first() {
        (command.clone(), arguments.to_vec())
    } else {
        ("/bin/sh".to_string(), Vec::new())
    };

    if !cli.quiet {
        eprintln!(
            "Spawning RustD container {machine_name} on {}.",
            root_path.display()
        );
        eprintln!("Operating system: {os_name}");
    }

    let mut env_map = HashMap::new();
    env_map.insert("container".to_string(), "rustd-nspawn".to_string());
    env_map.insert(
        "container_uuid".to_string(),
        cli.uuid
            .clone()
            .unwrap_or_else(|| "00000000-0000-0000-0000-000000000000".into()),
    );
    env_map.insert(
        "TERM".to_string(),
        std::env::var("TERM").unwrap_or_else(|_| "vt220".into()),
    );
    for item in &cli.setenv {
        let Some((key, value)) = item.split_once('=') else {
            fail(format!(
                "invalid --setenv value (expected KEY=VALUE): {item}"
            ));
        };
        if key.is_empty() {
            fail("environment variable name may not be empty");
        }
        env_map.insert(key.to_string(), value.to_string());
    }

    let is_root = unsafe { libc::geteuid() == 0 };
    if !is_root || cli.private_users.is_some() {
        configure_user_namespace().unwrap_or_else(|error| fail(error));
    }

    let mut clone_flags =
        libc::CLONE_NEWNS | libc::CLONE_NEWPID | libc::CLONE_NEWUTS | libc::CLONE_NEWIPC;
    if cli.private_network {
        clone_flags |= libc::CLONE_NEWNET;
    }
    unshare(clone_flags, "mount/PID/UTS/IPC namespaces").unwrap_or_else(|error| fail(error));
    make_mount_namespace_private().unwrap_or_else(|error| fail(error));
    set_container_hostname(&machine_name).unwrap_or_else(|error| fail(error));

    let proc_path = root_path.join("proc");
    fs::create_dir_all(&proc_path)
        .unwrap_or_else(|error| fail(format!("cannot create container /proc: {error}")));

    let root_c = cstring_path(&root_path).unwrap_or_else(|error| fail(error));
    let slash_c = CString::new("/").expect("static path has no NUL");
    let proc_target_c = CString::new("/proc").expect("static path has no NUL");
    let proc_source_c = CString::new("proc").expect("static path has no NUL");
    let proc_type_c = CString::new("proc").expect("static path has no NUL");
    let chdir_c = cli
        .chdir
        .as_ref()
        .map(|path| cstring_path(path).unwrap_or_else(|error| fail(error)));

    let mut child_cmd = Command::new(&exec_cmd);
    child_cmd.args(&exec_args);
    child_cmd.envs(&env_map);

    unsafe {
        child_cmd.pre_exec(move || {
            if libc::chroot(root_c.as_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::chdir(slash_c.as_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }

            let proc_flags = (libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV) as libc::c_ulong;
            if libc::mount(
                proc_source_c.as_ptr(),
                proc_target_c.as_ptr(),
                proc_type_c.as_ptr(),
                proc_flags,
                ptr::null(),
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }

            if let Some(directory) = chdir_c.as_ref() {
                if libc::chdir(directory.as_ptr()) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }

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
        Err(error) => fail(format!(
            "failed to execute '{exec_cmd}' inside container {machine_name}: {error}"
        )),
    }
}
