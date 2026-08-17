// SPDX-License-Identifier: LGPL-2.1-or-later
//! `machinectl` compatibility utility for rustd / systemd.
//!
//! Control and query the virtual machine and container registration manager.
//! Upstream reference: `src/machine/machinectl.c` (systemd v261).

use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;
use zbus::Connection;
use zvariant::OwnedObjectPath;

const VERSION_OUTPUT: &str = concat!(
    "systemd 261 (261.2-1-arch)\n",
    "+PAM +AUDIT -SELINUX +APPARMOR -IMA +IPE +SMACK +SECCOMP +GCRYPT +GNUTLS +OPENSSL +ACL ",
    "+BLKID +CURL +ELFUTILS +FIDO2 +IDN2 +KMOD +LIBCRYPTSETUP +LIBCRYPTSETUP_PLUGINS +LIBFDISK ",
    "+PCRE2 +PWQUALITY +P11KIT +QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB +ZSTD +BPF_FRAMEWORK +BTF ",
    "+XKBCOMMON +UTMP +LIBARCHIVE\n"
);

static RUNNING: AtomicBool = AtomicBool::new(true);

#[derive(Parser, Debug)]
#[command(
    name = "machinectl",
    about = "Send control commands to or query the virtual machine and container registration manager.",
    version = VERSION_OUTPUT,
    long_about = "Send control commands to or query the virtual machine and container registration manager."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Do not pipe output into a pager
    #[arg(long, global = true)]
    no_pager: bool,

    /// Do not show table headers or footers
    #[arg(long, global = true)]
    no_legend: bool,

    /// Do not prompt for password
    #[arg(long, global = true)]
    no_ask_password: bool,

    /// Operate on remote host
    #[arg(short = 'H', long = "host", global = true)]
    host: Option<String>,

    /// Operate on local container
    #[arg(short = 'M', long = "machine", global = true)]
    machine: Option<String>,

    /// Suppress output
    #[arg(short = 'q', long = "quiet", global = true)]
    quiet: bool,

    /// Show all properties or machines
    #[arg(short = 'a', long = "all", global = true)]
    all: bool,

    /// Do not ellipsize output
    #[arg(short = 'l', long = "full", global = true)]
    full: bool,

    /// When showing properties, only print the value
    #[arg(long, global = true)]
    value: bool,

    /// Show only properties with specified names
    #[arg(short = 'p', long = "property", global = true)]
    properties: Vec<String>,

    /// Equivalent to --value --property=NAME
    #[arg(short = 'P', global = true)]
    print_property: Option<String>,

    /// Output as JSON (pretty, short, off)
    #[arg(
        short = 'j',
        long = "json",
        value_enum,
        default_missing_value = "pretty",
        num_args = 0..=1,
        global = true
    )]
    json: Option<JsonMode>,

    /// Signal to send
    #[arg(short = 's', long = "signal", default_value = "SIGTERM", global = true)]
    signal: String,

    /// Whom to send signal to ('leader' or 'all')
    #[arg(
        long = "kill-whom",
        alias = "kill-who",
        default_value = "all",
        global = true
    )]
    kill_whom: String,

    /// Specify user ID / name to invoke shell as
    #[arg(long = "uid", global = true)]
    uid: Option<String>,

    /// Add an environment variable for shell
    #[arg(short = 'E', long = "setenv", global = true)]
    setenv: Vec<String>,

    /// Create read-only bind mount or clone
    #[arg(long = "read-only", global = true)]
    read_only: bool,

    /// Create directory before bind mounting, if missing
    #[arg(long = "mkdir", global = true)]
    mkdir: bool,

    /// Replace target file when copying, if necessary
    #[arg(long = "force", global = true)]
    force: bool,

    /// Start or power off container after enabling or disabling it
    #[arg(long = "now", global = true)]
    now: bool,

    /// Number of journal entries to show
    #[arg(short = 'n', long = "lines", global = true)]
    lines: Option<usize>,

    /// Number of internet addresses to show at most
    #[arg(long = "max-addresses", global = true)]
    max_addresses: Option<usize>,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum JsonMode {
    Pretty,
    Short,
    Off,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// List running VMs and containers (default)
    #[command(name = "list", alias = "list-machines")]
    List,

    /// List available VM and container images
    #[command(name = "list-images")]
    ListImages,

    /// Show VM/container details
    #[command(name = "status")]
    Status {
        /// Machines to inspect
        names: Vec<String>,
    },

    /// Show properties of one or more VMs/containers or manager
    #[command(name = "show")]
    Show {
        /// Machines to inspect (if empty, shows manager properties)
        names: Vec<String>,
    },

    /// Start container as a service
    #[command(name = "start")]
    Start { names: Vec<String> },

    /// Stop container/machine
    #[command(name = "stop")]
    Stop { names: Vec<String> },

    /// Terminate one or more machines
    #[command(name = "terminate")]
    Terminate { names: Vec<String> },

    /// Send signal to processes of a machine
    #[command(name = "kill")]
    Kill { names: Vec<String> },

    /// Reboot one or more machines
    #[command(name = "reboot")]
    Reboot { names: Vec<String> },

    /// Power off one or more machines
    #[command(name = "poweroff")]
    Poweroff { names: Vec<String> },

    /// Pause one or more machines
    #[command(name = "pause")]
    Pause { names: Vec<String> },

    /// Resume one or more paused machines
    #[command(name = "resume")]
    Resume { names: Vec<String> },

    /// Invoke a shell (or other command) in a container or on local host
    #[command(name = "shell")]
    Shell {
        /// [USER@]NAME of machine (defaults to .host)
        target: Option<String>,
        /// Command and arguments to execute
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// Get a login prompt in a container or on local host
    #[command(name = "login")]
    Login {
        /// Machine name (defaults to .host)
        name: Option<String>,
    },

    /// Bind mount a path from the host into a container
    #[command(name = "bind")]
    Bind {
        name: String,
        source: PathBuf,
        destination: Option<PathBuf>,
    },

    /// Copy files from the host to a container
    #[command(name = "copy-to")]
    CopyTo {
        name: String,
        source: PathBuf,
        destination: Option<PathBuf>,
    },

    /// Copy files from a container to the host
    #[command(name = "copy-from")]
    CopyFrom {
        name: String,
        source: PathBuf,
        destination: Option<PathBuf>,
    },

    /// Mark or unmark image or machine read-only
    #[command(name = "read-only")]
    ReadOnly {
        name: String,
        #[arg(id = "read_only_mode", value_name = "READ_ONLY")]
        mode: Option<String>,
    },

    /// Show image details
    #[command(name = "image-status")]
    ImageStatus { names: Vec<String> },

    /// Show properties of image
    #[command(name = "show-image")]
    ShowImage { names: Vec<String> },

    /// Clone an image
    #[command(name = "clone", alias = "clone-image")]
    Clone { source: String, destination: String },

    /// Rename an image
    #[command(name = "rename", alias = "rename-image")]
    Rename { source: String, destination: String },

    /// Remove an image
    #[command(name = "remove", alias = "remove-image", alias = "rm")]
    Remove { names: Vec<String> },

    /// Set image or pool size limit
    #[command(name = "set-limit")]
    SetLimit {
        name_or_bytes: String,
        bytes: Option<String>,
    },

    /// Remove hidden (or all) images
    #[command(name = "clean", alias = "clean-images")]
    Clean,

    /// Enable automatic container start at boot
    #[command(name = "enable")]
    Enable { names: Vec<String> },

    /// Disable automatic container start at boot
    #[command(name = "disable")]
    Disable { names: Vec<String> },

    /// Show settings of one or more VMs/containers
    #[command(name = "cat")]
    Cat { names: Vec<String> },

    /// Edit settings of one or more VMs/containers
    #[command(name = "edit")]
    Edit { names: Vec<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MachineRecord {
    name: String,
    class: String,
    service: String,
    os: String,
    version: String,
    addresses: Vec<String>,
    leader: u32,
    unit: String,
    root_directory: String,
    state: String,
    id: String,
    timestamp_usec: u64,
    raw_props: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ImageRecord {
    name: String,
    image_type: String,
    read_only: bool,
    usage_bytes: u64,
    limit_bytes: u64,
    created: String,
    modified: String,
    path: String,
    raw_props: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ManagerRecord {
    pool_path: String,
    pool_usage: u64,
    pool_limit: u64,
}

// ── Utility Formatting & Helpers ──────────────────────────────────────────

fn format_bytes(bytes: u64) -> String {
    if bytes == u64::MAX {
        return "n/a".to_string();
    }
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    const TIB: u64 = 1024 * GIB;

    if bytes >= TIB {
        format!("{:.1}T", bytes as f64 / TIB as f64)
    } else if bytes >= GIB {
        format!("{:.1}G", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1}M", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1}K", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes}B")
    }
}

fn parse_bytes(s: &str) -> Option<u64> {
    let s = s.trim();
    if s == "infinity" || s == "max" || s == "n/a" {
        return Some(u64::MAX);
    }
    if let Ok(num) = s.parse::<u64>() {
        return Some(num);
    }
    let (num_part, unit_part) = if let Some(idx) = s.find(|c: char| c.is_alphabetic()) {
        (&s[..idx], &s[idx..])
    } else {
        (s, "")
    };
    let num: f64 = num_part.parse().ok()?;
    let mult: f64 = match unit_part.to_uppercase().as_str() {
        "B" | "" => 1.0,
        "K" | "KB" | "KIB" => 1024.0,
        "M" | "MB" | "MIB" => 1024.0 * 1024.0,
        "G" | "GB" | "GIB" => 1024.0 * 1024.0 * 1024.0,
        "T" | "TB" | "TIB" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        _ => return None,
    };
    Some((num * mult) as u64)
}

fn format_timestamp(usec: u64) -> String {
    if usec == 0 {
        return "---".to_string();
    }
    let secs = (usec / 1_000_000) as libc::time_t;
    let mut tm_local: libc::tm = unsafe { std::mem::zeroed() };
    unsafe {
        libc::localtime_r(&secs, &mut tm_local);
    }
    let mut local_buf = [0i8; 128];
    unsafe {
        libc::strftime(
            local_buf.as_mut_ptr(),
            local_buf.len(),
            b"%a %Y-%m-%d %H:%M:%S %Z\0".as_ptr().cast::<i8>(),
            &tm_local,
        );
        std::ffi::CStr::from_ptr(local_buf.as_ptr())
            .to_string_lossy()
            .into_owned()
    }
}

fn format_since(usec: u64) -> String {
    if usec == 0 {
        return "---".to_string();
    }
    let formatted = format_timestamp(usec);
    let now_secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let past_secs = usec / 1_000_000;
    let diff = now_secs.saturating_sub(past_secs);

    let duration_str = if diff < 60 {
        format!("{diff}s ago")
    } else if diff < 3600 {
        format!("{}min ago", diff / 60)
    } else if diff < 86400 {
        format!("{}h ago", diff / 3600)
    } else {
        format!("{} days ago", diff / 86400)
    };
    format!("{formatted}; {duration_str}")
}

fn signal_from_name(sig: &str) -> i32 {
    let s = sig.trim_start_matches("SIG").to_uppercase();
    match s.as_str() {
        "HUP" | "1" => libc::SIGHUP,
        "INT" | "2" => libc::SIGINT,
        "QUIT" | "3" => libc::SIGQUIT,
        "KILL" | "9" => libc::SIGKILL,
        "USR1" | "10" => libc::SIGUSR1,
        "USR2" | "12" => libc::SIGUSR2,
        "PIPE" | "13" => libc::SIGPIPE,
        "ALRM" | "14" => libc::SIGALRM,
        "TERM" | "15" => libc::SIGTERM,
        "STOP" | "19" => libc::SIGSTOP,
        "CONT" | "18" => libc::SIGCONT,
        "PWR" | "30" => libc::SIGPWR,
        _ => libc::SIGTERM,
    }
}

fn parse_key_value_file(path: &Path) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    if let Ok(content) = fs::read_to_string(path) {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                let key = k.trim().to_string();
                let val = v.trim().trim_matches('"').to_string();
                map.insert(key, val);
            }
        }
    }
    map
}

fn get_os_release_from_root(root: &Path) -> (String, String) {
    let candidates = [
        root.join("etc/os-release"),
        root.join("usr/lib/os-release"),
        PathBuf::from("/etc/os-release"),
        PathBuf::from("/usr/lib/os-release"),
    ];

    for path in &candidates {
        if path.exists() {
            let props = parse_key_value_file(path);
            let os_name = props
                .get("PRETTY_NAME")
                .or_else(|| props.get("NAME"))
                .cloned()
                .unwrap_or_else(|| "Linux".to_string());
            let version = props
                .get("VERSION_ID")
                .or_else(|| props.get("VERSION"))
                .cloned()
                .unwrap_or_else(|| "-".to_string());
            return (os_name, version);
        }
    }
    ("Linux".to_string(), "-".to_string())
}

fn get_host_machine_id() -> String {
    if let Ok(id) = fs::read_to_string("/etc/machine-id") {
        let trimmed = id.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    if let Ok(id) = fs::read_to_string("/var/lib/dbus/machine-id") {
        let trimmed = id.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    "00000000000000000000000000000000".to_string()
}

fn get_host_ip_addresses() -> Vec<String> {
    let mut addrs = Vec::new();
    let mut seen = HashSet::new();

    unsafe {
        let mut ifaddrs_ptr: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifaddrs_ptr) == 0 && !ifaddrs_ptr.is_null() {
            let mut cur = ifaddrs_ptr;
            while !cur.is_null() {
                let ifa = *cur;
                if !ifa.ifa_addr.is_null() {
                    let family = i32::from((*ifa.ifa_addr).sa_family);
                    if family == libc::AF_INET {
                        let sin = *(ifa.ifa_addr.cast::<libc::sockaddr_in>());
                        let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                        if !ip.is_loopback() {
                            let ip_str = ip.to_string();
                            if !seen.contains(&ip_str) {
                                seen.insert(ip_str.clone());
                                addrs.push(ip_str);
                            }
                        }
                    } else if family == libc::AF_INET6 {
                        let sin6 = *(ifa.ifa_addr.cast::<libc::sockaddr_in6>());
                        let ip6 = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                        if !ip6.is_loopback() {
                            let ip_str = ip6.to_string();
                            if !seen.contains(&ip_str) {
                                seen.insert(ip_str.clone());
                                addrs.push(ip_str);
                            }
                        }
                    }
                }
                cur = ifa.ifa_next;
            }
            libc::freeifaddrs(ifaddrs_ptr);
        }
    }

    addrs
}

fn get_process_name(pid: u32) -> String {
    if let Ok(comm) = fs::read_to_string(format!("/proc/{pid}/comm")) {
        let trimmed = comm.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    if let Ok(cmdline) = fs::read_to_string(format!("/proc/{pid}/cmdline")) {
        if let Some(first) = cmdline.split('\0').next() {
            if let Some(name) = Path::new(first).file_name() {
                return name.to_string_lossy().into_owned();
            }
        }
    }
    "systemd".to_string()
}

fn get_cgroup_processes(unit_or_slice: &str) -> Vec<(u32, String)> {
    let mut procs = Vec::new();
    let cgroup_candidates = [
        format!("/sys/fs/cgroup/machine.slice/{unit_or_slice}/cgroup.procs"),
        format!("/sys/fs/cgroup/{unit_or_slice}/cgroup.procs"),
        format!("/sys/fs/cgroup/machine.slice/machine-{unit_or_slice}.scope/cgroup.procs"),
    ];

    for path in &cgroup_candidates {
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines() {
                if let Ok(pid) = line.trim().parse::<u32>() {
                    let cmd =
                        if let Ok(cmdline) = fs::read_to_string(format!("/proc/{pid}/cmdline")) {
                            let parts: Vec<&str> =
                                cmdline.split('\0').filter(|s| !s.is_empty()).collect();
                            if !parts.is_empty() {
                                parts.join(" ")
                            } else {
                                get_process_name(pid)
                            }
                        } else {
                            get_process_name(pid)
                        };
                    procs.push((pid, cmd));
                }
            }
            if !procs.is_empty() {
                break;
            }
        }
    }
    procs
}

fn collect_host_machine() -> MachineRecord {
    let id = get_host_machine_id();
    let (os, version) = get_os_release_from_root(Path::new("/"));
    let addresses = get_host_ip_addresses();

    let boot_time_usec = if let Ok(stat) = fs::read_to_string("/proc/stat") {
        let btime = stat
            .lines()
            .find(|l| l.starts_with("btime "))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or_else(|| {
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            });
        btime * 1_000_000
    } else {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64
    };

    let mut raw_props = BTreeMap::new();
    raw_props.insert("Name".to_string(), ".host".to_string());
    raw_props.insert("Id".to_string(), id.clone());
    raw_props.insert("Timestamp".to_string(), format_timestamp(boot_time_usec));
    raw_props.insert("TimestampMonotonic".to_string(), "0".to_string());
    raw_props.insert("Unit".to_string(), "-.slice".to_string());
    raw_props.insert("Leader".to_string(), "1".to_string());
    raw_props.insert("LeaderPIDFDId".to_string(), "1".to_string());
    raw_props.insert("Supervisor".to_string(), "0".to_string());
    raw_props.insert("SupervisorPIDFDId".to_string(), "0".to_string());
    raw_props.insert("Class".to_string(), "host".to_string());
    raw_props.insert("RootDirectory".to_string(), "/".to_string());
    raw_props.insert("VSockCID".to_string(), "4294967295".to_string());
    raw_props.insert("State".to_string(), "running".to_string());
    raw_props.insert("UID".to_string(), "0".to_string());
    raw_props.insert("OS".to_string(), os.clone());
    raw_props.insert("Version".to_string(), version.clone());

    MachineRecord {
        name: ".host".to_string(),
        class: "host".to_string(),
        service: "systemd".to_string(),
        os,
        version,
        addresses,
        leader: 1,
        unit: "-.slice".to_string(),
        root_directory: "/".to_string(),
        state: "running".to_string(),
        id,
        timestamp_usec: boot_time_usec,
        raw_props,
    }
}

// ── Fallback Discovery (Procfs, Cgroups, /var/lib/machines) ───────────────

fn scan_run_machines() -> Vec<MachineRecord> {
    let mut machines = Vec::new();
    let run_dir = Path::new("/run/systemd/machines");
    if run_dir.is_dir() {
        if let Ok(entries) = fs::read_dir(run_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let name = path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .into_owned();
                    let props = parse_key_value_file(&path);
                    let class = props
                        .get("CLASS")
                        .cloned()
                        .unwrap_or_else(|| "container".to_string());
                    let service = props
                        .get("SERVICE")
                        .cloned()
                        .unwrap_or_else(|| "systemd-nspawn".to_string());
                    let leader = props
                        .get("LEADER")
                        .and_then(|l| l.parse::<u32>().ok())
                        .unwrap_or(0);
                    let unit = props
                        .get("SCOPE")
                        .or_else(|| props.get("UNIT"))
                        .cloned()
                        .unwrap_or_else(|| format!("machine-{name}.scope"));
                    let root_dir = props
                        .get("ROOT")
                        .cloned()
                        .unwrap_or_else(|| format!("/var/lib/machines/{name}"));
                    let state = props
                        .get("STATE")
                        .cloned()
                        .unwrap_or_else(|| "running".to_string());
                    let id = props.get("ID").cloned().unwrap_or_default();
                    let (os, version) = get_os_release_from_root(Path::new(&root_dir));

                    machines.push(MachineRecord {
                        name,
                        class,
                        service,
                        os,
                        version,
                        addresses: Vec::new(),
                        leader,
                        unit,
                        root_directory: root_dir,
                        state,
                        id,
                        timestamp_usec: 0,
                        raw_props: props,
                    });
                }
            }
        }
    }
    machines
}

fn scan_cgroup_machines() -> Vec<MachineRecord> {
    let mut machines = Vec::new();
    let cgroup_dir = Path::new("/sys/fs/cgroup/machine.slice");
    if cgroup_dir.is_dir() {
        if let Ok(entries) = fs::read_dir(cgroup_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let dir_name = path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .into_owned();
                    if dir_name.ends_with(".scope") || dir_name.ends_with(".service") {
                        let name = dir_name
                            .trim_start_matches("machine-")
                            .trim_end_matches(".scope")
                            .trim_end_matches(".service")
                            .replace("\\x2d", "-");
                        let procs_file = path.join("cgroup.procs");
                        let leader = if let Ok(content) = fs::read_to_string(&procs_file) {
                            content
                                .lines()
                                .next()
                                .and_then(|l| l.trim().parse::<u32>().ok())
                                .unwrap_or(0)
                        } else {
                            0
                        };

                        let (service, class) = if leader > 0 {
                            let comm = get_process_name(leader);
                            if comm.contains("qemu") || comm.contains("kvm") {
                                ("qemu".to_string(), "vm".to_string())
                            } else {
                                ("systemd-nspawn".to_string(), "container".to_string())
                            }
                        } else {
                            ("systemd-nspawn".to_string(), "container".to_string())
                        };

                        let root_dir = format!("/var/lib/machines/{name}");
                        let (os, version) = get_os_release_from_root(Path::new(&root_dir));

                        let mut raw_props = BTreeMap::new();
                        raw_props.insert("Name".to_string(), name.clone());
                        raw_props.insert("Class".to_string(), class.clone());
                        raw_props.insert("Service".to_string(), service.clone());
                        raw_props.insert("Leader".to_string(), leader.to_string());
                        raw_props.insert("Unit".to_string(), dir_name.clone());
                        raw_props.insert("RootDirectory".to_string(), root_dir.clone());
                        raw_props.insert("State".to_string(), "running".to_string());

                        machines.push(MachineRecord {
                            name,
                            class,
                            service,
                            os,
                            version,
                            addresses: Vec::new(),
                            leader,
                            unit: dir_name,
                            root_directory: root_dir,
                            state: "running".to_string(),
                            id: String::new(),
                            timestamp_usec: 0,
                            raw_props,
                        });
                    }
                }
            }
        }
    }
    machines
}

fn discover_images_local() -> Vec<ImageRecord> {
    let mut images = Vec::new();
    let search_dirs = [
        PathBuf::from("/var/lib/machines"),
        PathBuf::from("/var/lib/portables"),
        PathBuf::from("/var/lib/extensions"),
        PathBuf::from("/var/lib/confexts"),
    ];

    let mut seen_paths = HashSet::new();

    for dir in &search_dirs {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if seen_paths.contains(&path) {
                    continue;
                }
                seen_paths.insert(path.clone());

                let file_name = entry.file_name().to_string_lossy().into_owned();
                if file_name.starts_with('.') {
                    continue;
                }

                let meta = match entry.metadata() {
                    Ok(m) => m,
                    Err(_) => continue,
                };

                let is_dir = meta.is_dir();
                let is_raw = file_name.ends_with(".raw") || file_name.ends_with(".img");
                let is_qcow2 = file_name.ends_with(".qcow2");
                let is_tar = file_name.ends_with(".tar")
                    || file_name.ends_with(".tar.gz")
                    || file_name.ends_with(".tar.xz")
                    || file_name.ends_with(".tar.zst");

                if !is_dir && !is_raw && !is_qcow2 && !is_tar {
                    continue;
                }

                let image_type = if is_dir {
                    "directory".to_string()
                } else if is_raw {
                    "raw".to_string()
                } else if is_qcow2 {
                    "qcow2".to_string()
                } else {
                    "tar".to_string()
                };

                let name = file_name
                    .trim_end_matches(".raw")
                    .trim_end_matches(".img")
                    .trim_end_matches(".qcow2")
                    .trim_end_matches(".tar.zst")
                    .trim_end_matches(".tar.xz")
                    .trim_end_matches(".tar.gz")
                    .trim_end_matches(".tar")
                    .to_string();

                let size = if is_dir { 0 } else { meta.len() };
                let read_only = meta.permissions().readonly();

                let created_str = meta
                    .created()
                    .ok()
                    .or_else(|| meta.modified().ok())
                    .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                    .map_or_else(
                        || "---".to_string(),
                        |d| format_timestamp(d.as_micros() as u64),
                    );

                let modified_str = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                    .map_or_else(
                        || "---".to_string(),
                        |d| format_timestamp(d.as_micros() as u64),
                    );

                let mut raw_props = BTreeMap::new();
                raw_props.insert("Name".to_string(), name.clone());
                raw_props.insert("Path".to_string(), path.to_string_lossy().into_owned());
                raw_props.insert("Type".to_string(), image_type.clone());
                raw_props.insert(
                    "ReadOnly".to_string(),
                    if read_only { "yes" } else { "no" }.to_string(),
                );
                raw_props.insert("CreationTimestamp".to_string(), created_str.clone());
                raw_props.insert("ModificationTimestamp".to_string(), modified_str.clone());
                raw_props.insert("Usage".to_string(), size.to_string());
                raw_props.insert("Limit".to_string(), u64::MAX.to_string());

                images.push(ImageRecord {
                    name,
                    image_type,
                    read_only,
                    usage_bytes: size,
                    limit_bytes: u64::MAX,
                    created: created_str,
                    modified: modified_str,
                    path: path.to_string_lossy().into_owned(),
                    raw_props,
                });
            }
        }
    }

    images.sort_by(|a, b| a.name.cmp(&b.name));
    images
}

// ── D-Bus Client ──────────────────────────────────────────────────────────

async fn query_machines_dbus() -> anyhow::Result<Vec<MachineRecord>> {
    let conn = Connection::system().await?;

    let reply = conn
        .call_method(
            Some("org.freedesktop.machine1"),
            "/org/freedesktop/machine1",
            Some("org.freedesktop.machine1.Manager"),
            "ListMachines",
            &(),
        )
        .await?;
    let list: Vec<(String, String, String, OwnedObjectPath)> = reply.body().deserialize()?;

    let mut machines = Vec::new();

    for (name, class, service, obj_path) in list {
        let machine_proxy = zbus::Proxy::new(
            &conn,
            "org.freedesktop.machine1",
            obj_path.as_ref(),
            "org.freedesktop.machine1.Machine",
        )
        .await?;

        let leader: u32 = machine_proxy.get_property("Leader").await.unwrap_or(0);
        let unit: String = machine_proxy.get_property("Unit").await.unwrap_or_default();
        let root_dir: String = machine_proxy
            .get_property("RootDirectory")
            .await
            .unwrap_or_default();
        let state: String = machine_proxy
            .get_property("State")
            .await
            .unwrap_or_else(|_| "running".to_string());
        let ts_usec: u64 = machine_proxy.get_property("Timestamp").await.unwrap_or(0);
        let id_bytes: Vec<u8> = machine_proxy.get_property("Id").await.unwrap_or_default();
        let id_str = if id_bytes.is_empty() {
            String::new()
        } else {
            id_bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };

        // Query OS release
        let os_release_res: Result<HashMap<String, String>, _> = conn
            .call_method(
                Some("org.freedesktop.machine1"),
                "/org/freedesktop/machine1",
                Some("org.freedesktop.machine1.Manager"),
                "GetMachineOSRelease",
                &(name.as_str()),
            )
            .await
            .and_then(|r| r.body().deserialize());

        let (os, version) = match os_release_res {
            Ok(ref map) => {
                let os_name = map
                    .get("PRETTY_NAME")
                    .or_else(|| map.get("NAME"))
                    .cloned()
                    .unwrap_or_else(|| "Linux".to_string());
                let ver = map
                    .get("VERSION_ID")
                    .or_else(|| map.get("VERSION"))
                    .cloned()
                    .unwrap_or_else(|| "-".to_string());
                (os_name, ver)
            }
            Err(_) => get_os_release_from_root(Path::new(&root_dir)),
        };

        // Query IP addresses
        let addr_res: Result<Vec<(i32, Vec<u8>)>, _> = conn
            .call_method(
                Some("org.freedesktop.machine1"),
                "/org/freedesktop/machine1",
                Some("org.freedesktop.machine1.Manager"),
                "GetMachineAddresses",
                &(name.as_str()),
            )
            .await
            .and_then(|r| r.body().deserialize());

        let mut addresses = Vec::new();
        if let Ok(addrs) = addr_res {
            for (family, bytes) in addrs {
                if family == libc::AF_INET && bytes.len() == 4 {
                    addresses.push(format!(
                        "{}.{}.{}.{}",
                        bytes[0], bytes[1], bytes[2], bytes[3]
                    ));
                } else if family == libc::AF_INET6 && bytes.len() == 16 {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&bytes);
                    let ip6 = Ipv6Addr::from(octets);
                    addresses.push(ip6.to_string());
                }
            }
        }
        if addresses.is_empty() && name == ".host" {
            addresses = get_host_ip_addresses();
        }

        let mut raw_props = BTreeMap::new();
        raw_props.insert("Name".to_string(), name.clone());
        raw_props.insert("Id".to_string(), id_str.clone());
        raw_props.insert("Timestamp".to_string(), format_timestamp(ts_usec));
        raw_props.insert("TimestampMonotonic".to_string(), "0".to_string());
        raw_props.insert("Unit".to_string(), unit.clone());
        raw_props.insert("Leader".to_string(), leader.to_string());
        raw_props.insert("LeaderPIDFDId".to_string(), leader.to_string());
        raw_props.insert("Supervisor".to_string(), "0".to_string());
        raw_props.insert("SupervisorPIDFDId".to_string(), "0".to_string());
        raw_props.insert("Class".to_string(), class.clone());
        raw_props.insert("Service".to_string(), service.clone());
        raw_props.insert("RootDirectory".to_string(), root_dir.clone());
        raw_props.insert("VSockCID".to_string(), "4294967295".to_string());
        raw_props.insert("State".to_string(), state.clone());
        raw_props.insert("UID".to_string(), "0".to_string());
        raw_props.insert("OS".to_string(), os.clone());
        raw_props.insert("Version".to_string(), version.clone());

        machines.push(MachineRecord {
            name,
            class,
            service,
            os,
            version,
            addresses,
            leader,
            unit,
            root_directory: root_dir,
            state,
            id: id_str,
            timestamp_usec: ts_usec,
            raw_props,
        });
    }

    Ok(machines)
}

async fn query_images_dbus() -> anyhow::Result<Vec<ImageRecord>> {
    let conn = Connection::system().await?;

    let reply = conn
        .call_method(
            Some("org.freedesktop.machine1"),
            "/org/freedesktop/machine1",
            Some("org.freedesktop.machine1.Manager"),
            "ListImages",
            &(),
        )
        .await?;
    let list: Vec<(String, String, bool, u64, u64, u64, OwnedObjectPath)> =
        reply.body().deserialize()?;

    let mut images = Vec::new();
    for (name, image_type, read_only, cr_ts, mod_ts, usage, obj_path) in list {
        let image_proxy = zbus::Proxy::new(
            &conn,
            "org.freedesktop.machine1",
            obj_path.as_ref(),
            "org.freedesktop.machine1.Image",
        )
        .await?;

        let path: String = image_proxy
            .get_property("Path")
            .await
            .unwrap_or_else(|_| format!("/var/lib/machines/{name}"));
        let limit: u64 = image_proxy.get_property("Limit").await.unwrap_or(u64::MAX);

        let created_str = format_timestamp(cr_ts);
        let modified_str = format_timestamp(mod_ts);

        let mut raw_props = BTreeMap::new();
        raw_props.insert("Name".to_string(), name.clone());
        raw_props.insert("Path".to_string(), path.clone());
        raw_props.insert("Type".to_string(), image_type.clone());
        raw_props.insert(
            "ReadOnly".to_string(),
            if read_only { "yes" } else { "no" }.to_string(),
        );
        raw_props.insert("CreationTimestamp".to_string(), created_str.clone());
        raw_props.insert("ModificationTimestamp".to_string(), modified_str.clone());
        raw_props.insert("Usage".to_string(), usage.to_string());
        raw_props.insert("Limit".to_string(), limit.to_string());

        images.push(ImageRecord {
            name,
            image_type,
            read_only,
            usage_bytes: usage,
            limit_bytes: limit,
            created: created_str,
            modified: modified_str,
            path,
            raw_props,
        });
    }

    Ok(images)
}

async fn query_manager_dbus() -> anyhow::Result<ManagerRecord> {
    let conn = Connection::system().await?;
    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.machine1",
        "/org/freedesktop/machine1",
        "org.freedesktop.machine1.Manager",
    )
    .await?;

    let pool_path: String = proxy
        .get_property("PoolPath")
        .await
        .unwrap_or_else(|_| "/var/lib/machines".to_string());
    let pool_usage: u64 = proxy.get_property("PoolUsage").await.unwrap_or(u64::MAX);
    let pool_limit: u64 = proxy.get_property("PoolLimit").await.unwrap_or(u64::MAX);

    Ok(ManagerRecord {
        pool_path,
        pool_usage,
        pool_limit,
    })
}

// ── Unified Collection ────────────────────────────────────────────────────

fn collect_all_machines() -> Vec<MachineRecord> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();

    let mut machines = if let Ok(ref runtime) = rt {
        runtime.block_on(query_machines_dbus()).unwrap_or_default()
    } else {
        Vec::new()
    };

    if machines.is_empty() {
        let mut fallback = scan_run_machines();
        fallback.extend(scan_cgroup_machines());
        let mut seen = HashSet::new();
        for m in fallback {
            if !seen.contains(&m.name) {
                seen.insert(m.name.clone());
                machines.push(m);
            }
        }
    }

    machines.sort_by(|a, b| a.name.cmp(&b.name));
    machines
}

fn collect_all_images() -> Vec<ImageRecord> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();

    let mut images = if let Ok(ref runtime) = rt {
        runtime.block_on(query_images_dbus()).unwrap_or_default()
    } else {
        Vec::new()
    };

    if images.is_empty() {
        images = discover_images_local();
    }

    // Filter out internal/hidden images from standard list if name is .host
    images.retain(|img| img.name != ".host");
    images.sort_by(|a, b| a.name.cmp(&b.name));
    images
}

fn get_manager_record() -> ManagerRecord {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();

    if let Ok(ref runtime) = rt {
        if let Ok(rec) = runtime.block_on(query_manager_dbus()) {
            return rec;
        }
    }

    ManagerRecord {
        pool_path: "/var/lib/machines".to_string(),
        pool_usage: u64::MAX,
        pool_limit: u64::MAX,
    }
}

// ── Subcommand Implementations ────────────────────────────────────────────

fn print_json<T: Serialize>(val: &T, mode: Option<JsonMode>) -> anyhow::Result<()> {
    match mode {
        Some(JsonMode::Pretty) => {
            println!("{}", serde_json::to_string_pretty(val)?);
        }
        _ => {
            println!("{}", serde_json::to_string(val)?);
        }
    }
    Ok(())
}

fn cmd_list(cli: &Cli) -> anyhow::Result<i32> {
    let mut machines = collect_all_machines();
    if !cli.all {
        machines.retain(|m| m.name != ".host");
    } else {
        let host = collect_host_machine();
        if !machines.iter().any(|m| m.name == ".host") {
            machines.push(host);
        }
    }

    if let Some(mode) = cli.json {
        if mode != JsonMode::Off {
            print_json(&machines, Some(mode))?;
            return Ok(0);
        }
    }

    if machines.is_empty() {
        if !cli.no_legend {
            println!("No machines.");
        }
        return Ok(0);
    }

    if !cli.no_legend {
        println!(
            "{:<16} {:<10} {:<15} {:<16} {:<10} {:<20}",
            "MACHINE", "CLASS", "SERVICE", "OS", "VERSION", "ADDRESSES"
        );
    }

    for m in &machines {
        let max_addrs = cli.max_addresses.unwrap_or(usize::MAX);
        let addrs_shown: Vec<String> = m.addresses.iter().take(max_addrs).cloned().collect();
        let addr_str = if addrs_shown.is_empty() {
            "-".to_string()
        } else if !cli.full && addrs_shown.len() > 1 {
            format!("{}...", addrs_shown[0])
        } else {
            addrs_shown.join(" ")
        };

        println!(
            "{:<16} {:<10} {:<15} {:<16} {:<10} {:<20}",
            m.name, m.class, m.service, m.os, m.version, addr_str
        );
    }

    if !cli.no_legend {
        println!("\n{} machines listed.", machines.len());
    }

    Ok(0)
}

fn cmd_list_images(cli: &Cli) -> anyhow::Result<i32> {
    let images = collect_all_images();

    if let Some(mode) = cli.json {
        if mode != JsonMode::Off {
            print_json(&images, Some(mode))?;
            return Ok(0);
        }
    }

    if images.is_empty() {
        if !cli.no_legend {
            println!("No images.");
        }
        return Ok(0);
    }

    if !cli.no_legend {
        println!(
            "{:<20} {:<12} {:<4} {:<8} {:<25} {:<25}",
            "NAME", "TYPE", "RO", "USAGE", "CREATED", "MODIFIED"
        );
    }

    for img in &images {
        let ro_str = if img.read_only { "yes" } else { "no" };
        let usage_str = format_bytes(img.usage_bytes);

        println!(
            "{:<20} {:<12} {:<4} {:<8} {:<25} {:<25}",
            img.name, img.image_type, ro_str, usage_str, img.created, img.modified
        );
    }

    if !cli.no_legend {
        println!("\n{} images listed.", images.len());
    }

    Ok(0)
}

fn cmd_status(names: &[String], cli: &Cli) -> anyhow::Result<i32> {
    let all_machines = collect_all_machines();
    let target_names = if names.is_empty() {
        if let Some(ref m) = cli.machine {
            vec![m.clone()]
        } else if !all_machines.is_empty() {
            vec![all_machines[0].name.clone()]
        } else {
            vec![".host".to_string()]
        }
    } else {
        names.to_vec()
    };

    let mut exit_code = 0;

    for (idx, name) in target_names.iter().enumerate() {
        if idx > 0 {
            println!();
        }

        let record = if name == ".host" {
            Some(collect_host_machine())
        } else {
            all_machines.iter().find(|m| &m.name == name).cloned()
        };

        if let Some(m) = record {
            if let Some(mode) = cli.json {
                if mode != JsonMode::Off {
                    print_json(&m, Some(mode))?;
                    continue;
                }
            }

            let id_display = if !m.id.is_empty() {
                m.id.clone()
            } else {
                m.leader.to_string()
            };

            println!("● {name} ({id_display})");
            if m.timestamp_usec > 0 {
                println!("           Since: {}", format_since(m.timestamp_usec));
            }
            let comm = get_process_name(m.leader);
            println!("          Leader: {} ({comm})", m.leader);
            println!("           Class: {}", m.class);
            if !m.service.is_empty() {
                println!("         Service: {}; class {}", m.service, m.class);
            }
            if !m.root_directory.is_empty() {
                println!("            Root: {}", m.root_directory);
            }
            if !m.unit.is_empty() {
                println!("            Unit: {}", m.unit);
                let procs = get_cgroup_processes(&m.unit);
                for (pid_idx, (p, cmd)) in procs.iter().enumerate() {
                    let branch = if pid_idx == procs.len() - 1 {
                        "└─"
                    } else {
                        "├─"
                    };
                    println!("                  {branch}{p} {cmd}");
                }
            }
            if !m.addresses.is_empty() {
                for (a_idx, addr) in m.addresses.iter().enumerate() {
                    if a_idx == 0 {
                        println!("         Address: {addr}");
                    } else {
                        println!("                  {addr}");
                    }
                }
            }
            if !m.os.is_empty() {
                println!("              OS: {}", m.os);
            }
        } else {
            eprintln!("No machine '{name}' known.");
            exit_code = 1;
        }
    }

    Ok(exit_code)
}

fn cmd_show(names: &[String], cli: &Cli) -> anyhow::Result<i32> {
    if names.is_empty() {
        // Show manager properties
        let mgr = get_manager_record();
        let mut props = BTreeMap::new();
        props.insert("PoolPath".to_string(), mgr.pool_path);
        props.insert("PoolUsage".to_string(), mgr.pool_usage.to_string());
        props.insert("PoolLimit".to_string(), mgr.pool_limit.to_string());

        let filtered_props: BTreeMap<_, _> = props
            .into_iter()
            .filter(|(k, _)| {
                if !cli.properties.is_empty()
                    && !cli.properties.iter().any(|p| p.eq_ignore_ascii_case(k))
                {
                    return false;
                }
                if let Some(ref p) = cli.print_property {
                    if !p.eq_ignore_ascii_case(k) {
                        return false;
                    }
                }
                true
            })
            .collect();

        if let Some(mode) = cli.json {
            if mode != JsonMode::Off {
                print_json(&filtered_props, Some(mode))?;
                return Ok(0);
            }
        }

        for (k, v) in &filtered_props {
            if cli.value || cli.print_property.is_some() {
                println!("{v}");
            } else {
                println!("{k}={v}");
            }
        }
        return Ok(0);
    }

    let all_machines = collect_all_machines();
    let mut exit_code = 0;

    for (idx, name) in names.iter().enumerate() {
        if idx > 0
            && !cli.value
            && cli.print_property.is_none()
            && (cli.json.is_none() || cli.json == Some(JsonMode::Off))
        {
            println!();
        }

        let record = if name == ".host" {
            Some(collect_host_machine())
        } else {
            all_machines.iter().find(|m| &m.name == name).cloned()
        };

        if let Some(m) = record {
            let filtered_props: BTreeMap<_, _> = m
                .raw_props
                .iter()
                .filter(|(k, _)| {
                    if !cli.properties.is_empty()
                        && !cli.properties.iter().any(|p| p.eq_ignore_ascii_case(k))
                    {
                        return false;
                    }
                    if let Some(ref p) = cli.print_property {
                        if !p.eq_ignore_ascii_case(k) {
                            return false;
                        }
                    }
                    true
                })
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();

            if let Some(mode) = cli.json {
                if mode != JsonMode::Off {
                    print_json(&filtered_props, Some(mode))?;
                    continue;
                }
            }

            for (k, v) in &filtered_props {
                if cli.value || cli.print_property.is_some() {
                    println!("{v}");
                } else {
                    println!("{k}={v}");
                }
            }
        } else {
            eprintln!("No machine '{name}' known.");
            exit_code = 1;
        }
    }

    Ok(exit_code)
}

fn cmd_image_status(names: &[String], _cli: &Cli) -> anyhow::Result<i32> {
    let images = collect_all_images();
    let mut exit_code = 0;

    for (idx, name) in names.iter().enumerate() {
        if idx > 0 {
            println!();
        }

        if let Some(img) = images.iter().find(|i| &i.name == name) {
            println!("● {name}");
            println!("           Image: {}", img.path);
            println!("            Type: {}", img.image_type);
            println!(
                "       Read-Only: {}",
                if img.read_only { "yes" } else { "no" }
            );
            println!("      Disk Space: {}", format_bytes(img.usage_bytes));
            println!("         Created: {}", img.created);
            println!("        Modified: {}", img.modified);
            let (os, _) = get_os_release_from_root(Path::new(&img.path));
            if !os.is_empty() {
                println!("              OS: {os}");
            }
        } else {
            eprintln!("Image '{name}' not found.");
            exit_code = 1;
        }
    }

    Ok(exit_code)
}

fn cmd_show_image(names: &[String], cli: &Cli) -> anyhow::Result<i32> {
    let images = collect_all_images();
    let mut exit_code = 0;

    for (idx, name) in names.iter().enumerate() {
        if idx > 0
            && !cli.value
            && cli.print_property.is_none()
            && (cli.json.is_none() || cli.json == Some(JsonMode::Off))
        {
            println!();
        }

        if let Some(img) = images.iter().find(|i| &i.name == name) {
            let filtered_props: BTreeMap<_, _> = img
                .raw_props
                .iter()
                .filter(|(k, _)| {
                    if !cli.properties.is_empty()
                        && !cli.properties.iter().any(|p| p.eq_ignore_ascii_case(k))
                    {
                        return false;
                    }
                    if let Some(ref p) = cli.print_property {
                        if !p.eq_ignore_ascii_case(k) {
                            return false;
                        }
                    }
                    true
                })
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();

            if let Some(mode) = cli.json {
                if mode != JsonMode::Off {
                    print_json(&filtered_props, Some(mode))?;
                    continue;
                }
            }

            for (k, v) in &filtered_props {
                if cli.value || cli.print_property.is_some() {
                    println!("{v}");
                } else {
                    println!("{k}={v}");
                }
            }
        } else {
            eprintln!("Image '{name}' not found.");
            exit_code = 1;
        }
    }

    Ok(exit_code)
}

// ── Machine Lifecycle Operations ──────────────────────────────────────────

fn cmd_start(names: &[String], _cli: &Cli) -> anyhow::Result<i32> {
    let mut exit_code = 0;
    for name in names {
        let service = format!("systemd-nspawn@{name}.service");
        let status = Command::new("systemctl")
            .arg("start")
            .arg(&service)
            .status();

        match status {
            Ok(s) if s.success() => {}
            _ => {
                eprintln!("Failed to start machine '{name}' via service {service}.");
                exit_code = 1;
            }
        }
    }
    Ok(exit_code)
}

fn cmd_stop_or_terminate(names: &[String], _is_stop: bool, _cli: &Cli) -> anyhow::Result<i32> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();

    let mut exit_code = 0;
    let all_machines = collect_all_machines();

    for name in names {
        let dbus_ok = if let Ok(ref runtime) = rt {
            runtime
                .block_on(async {
                    let conn = Connection::system().await?;
                    conn.call_method(
                        Some("org.freedesktop.machine1"),
                        "/org/freedesktop/machine1",
                        Some("org.freedesktop.machine1.Manager"),
                        "TerminateMachine",
                        &(name.as_str()),
                    )
                    .await?;
                    Ok::<_, anyhow::Error>(())
                })
                .is_ok()
        } else {
            false
        };

        if !dbus_ok {
            if let Some(m) = all_machines.iter().find(|m| &m.name == name) {
                if m.leader > 0 {
                    unsafe {
                        libc::kill(m.leader as i32, libc::SIGTERM);
                    }
                }
                let _ = Command::new("systemctl")
                    .arg("stop")
                    .arg(format!("machine-{name}.scope"))
                    .status();
                let _ = Command::new("systemctl")
                    .arg("stop")
                    .arg(format!("systemd-nspawn@{name}.service"))
                    .status();
            } else {
                eprintln!("No machine '{name}' known.");
                exit_code = 1;
            }
        }
    }

    Ok(exit_code)
}

fn cmd_kill(names: &[String], cli: &Cli) -> anyhow::Result<i32> {
    let sig_num = signal_from_name(&cli.signal);
    let kill_whom = if cli.kill_whom.eq_ignore_ascii_case("leader") {
        "leader"
    } else {
        "all"
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();

    let mut exit_code = 0;
    let all_machines = collect_all_machines();

    for name in names {
        let dbus_ok = if let Ok(ref runtime) = rt {
            runtime
                .block_on(async {
                    let conn = Connection::system().await?;
                    conn.call_method(
                        Some("org.freedesktop.machine1"),
                        "/org/freedesktop/machine1",
                        Some("org.freedesktop.machine1.Manager"),
                        "KillMachine",
                        &(name.as_str(), kill_whom, sig_num),
                    )
                    .await?;
                    Ok::<_, anyhow::Error>(())
                })
                .is_ok()
        } else {
            false
        };

        if !dbus_ok {
            if let Some(m) = all_machines.iter().find(|m| &m.name == name) {
                if kill_whom == "leader" && m.leader > 0 {
                    unsafe {
                        libc::kill(m.leader as i32, sig_num);
                    }
                } else {
                    let procs = get_cgroup_processes(&m.unit);
                    if !procs.is_empty() {
                        for (pid, _) in procs {
                            unsafe {
                                libc::kill(pid as i32, sig_num);
                            }
                        }
                    } else if m.leader > 0 {
                        unsafe {
                            libc::kill(m.leader as i32, sig_num);
                        }
                    }
                }
            } else {
                eprintln!("No machine '{name}' known.");
                exit_code = 1;
            }
        }
    }

    Ok(exit_code)
}

fn cmd_reboot(names: &[String], _cli: &Cli) -> anyhow::Result<i32> {
    let all_machines = collect_all_machines();
    let mut exit_code = 0;

    for name in names {
        if let Some(m) = all_machines.iter().find(|m| &m.name == name) {
            if m.leader > 0 {
                // In systemd containers, sending SIGINT to init PID initiates reboot
                unsafe {
                    libc::kill(m.leader as i32, libc::SIGINT);
                }
            }
            let _ = Command::new("systemctl")
                .arg(format!("--machine={name}"))
                .arg("reboot")
                .status();
        } else {
            eprintln!("No machine '{name}' known.");
            exit_code = 1;
        }
    }

    Ok(exit_code)
}

fn cmd_poweroff(names: &[String], _cli: &Cli) -> anyhow::Result<i32> {
    let all_machines = collect_all_machines();
    let mut exit_code = 0;

    for name in names {
        if let Some(m) = all_machines.iter().find(|m| &m.name == name) {
            if m.leader > 0 {
                // In systemd containers, sending SIGRTMIN+4 or SIGPWR / SIGTERM initiates poweroff
                unsafe {
                    libc::kill(m.leader as i32, libc::SIGPWR);
                }
            }
            let _ = Command::new("systemctl")
                .arg(format!("--machine={name}"))
                .arg("poweroff")
                .status();
        } else {
            eprintln!("No machine '{name}' known.");
            exit_code = 1;
        }
    }

    Ok(exit_code)
}

fn cmd_pause(names: &[String], pause: bool, _cli: &Cli) -> anyhow::Result<i32> {
    let all_machines = collect_all_machines();
    let mut exit_code = 0;

    for name in names {
        if let Some(m) = all_machines.iter().find(|m| &m.name == name) {
            let freeze_path = format!("/sys/fs/cgroup/machine.slice/{}/cgroup.freeze", m.unit);
            let freeze_val = if pause { "1" } else { "0" };
            if fs::write(&freeze_path, freeze_val).is_err() {
                let sig = if pause { libc::SIGSTOP } else { libc::SIGCONT };
                let procs = get_cgroup_processes(&m.unit);
                if !procs.is_empty() {
                    for (pid, _) in procs {
                        unsafe {
                            libc::kill(pid as i32, sig);
                        }
                    }
                } else if m.leader > 0 {
                    unsafe {
                        libc::kill(m.leader as i32, sig);
                    }
                }
            }
        } else {
            eprintln!("No machine '{name}' known.");
            exit_code = 1;
        }
    }

    Ok(exit_code)
}

// ── PTY & Interactive Operations (Shell, Login) ───────────────────────────

struct RawTerminalGuard {
    saved_termios: Option<libc::termios>,
}

impl RawTerminalGuard {
    fn new() -> Self {
        unsafe {
            if libc::isatty(libc::STDIN_FILENO) != 1 {
                return Self {
                    saved_termios: None,
                };
            }

            let mut orig: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(libc::STDIN_FILENO, &mut orig) != 0 {
                return Self {
                    saved_termios: None,
                };
            }

            let mut raw = orig;
            raw.c_iflag &= !(libc::IGNBRK
                | libc::BRKINT
                | libc::PARMRK
                | libc::ISTRIP
                | libc::INLCR
                | libc::IGNCR
                | libc::ICRNL
                | libc::IXON);
            raw.c_oflag &= !libc::OPOST;
            raw.c_lflag &= !(libc::ECHO | libc::ECHONL | libc::ICANON | libc::ISIG | libc::IEXTEN);
            raw.c_cflag &= !(libc::CSIZE | libc::PARENB);
            raw.c_cflag |= libc::CS8;
            raw.c_cc[libc::VMIN] = 1;
            raw.c_cc[libc::VTIME] = 0;

            if libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw) == 0 {
                Self {
                    saved_termios: Some(orig),
                }
            } else {
                Self {
                    saved_termios: None,
                }
            }
        }
    }
}

impl Drop for RawTerminalGuard {
    fn drop(&mut self) {
        if let Some(ref orig) = self.saved_termios {
            unsafe {
                let _ = libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, orig);
            }
        }
    }
}

fn sync_window_size(pty_fd: libc::c_int) {
    unsafe {
        if libc::isatty(libc::STDIN_FILENO) == 1 {
            let mut ws: libc::winsize = std::mem::zeroed();
            if libc::ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, &mut ws) == 0 {
                let _ = libc::ioctl(pty_fd, libc::TIOCSWINSZ, &ws);
            }
        }
    }
}

extern "C" fn handle_signal(_sig: libc::c_int) {
    RUNNING.store(false, Ordering::SeqCst);
}

fn forward_pty(pty_fd: i32) -> io::Result<()> {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handle_signal as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGHUP, &sa, std::ptr::null_mut());
    }

    sync_window_size(pty_fd);
    let _guard = RawTerminalGuard::new();

    let mut pollfds = [
        libc::pollfd {
            fd: libc::STDIN_FILENO,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: pty_fd,
            events: libc::POLLIN,
            revents: 0,
        },
    ];

    let mut buf = [0_u8; 4096];

    while RUNNING.load(Ordering::Relaxed) {
        let ret = unsafe { libc::poll(pollfds.as_mut_ptr(), 2, 250) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }

        // Stdin -> PTY
        if pollfds[0].revents & libc::POLLIN != 0 {
            let n = unsafe {
                libc::read(
                    libc::STDIN_FILENO,
                    buf.as_mut_ptr().cast::<libc::c_void>(),
                    buf.len(),
                )
            };
            if n <= 0 {
                break;
            }
            unsafe {
                let _ = libc::write(pty_fd, buf.as_ptr().cast::<libc::c_void>(), n as usize);
            }
        }

        // PTY -> Stdout
        if pollfds[1].revents & libc::POLLIN != 0 {
            let n =
                unsafe { libc::read(pty_fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
            if n <= 0 {
                break;
            }
            unsafe {
                let _ = libc::write(
                    libc::STDOUT_FILENO,
                    buf.as_ptr().cast::<libc::c_void>(),
                    n as usize,
                );
            }
        }

        if (pollfds[0].revents | pollfds[1].revents) & (libc::POLLHUP | libc::POLLERR) != 0 {
            break;
        }
    }

    unsafe {
        libc::close(pty_fd);
    }
    Ok(())
}

fn cmd_shell(target: Option<&str>, command: &[String], cli: &Cli) -> anyhow::Result<i32> {
    let (target_user, machine_name) = match target {
        Some(t) => {
            if let Some((user, m)) = t.split_once('@') {
                (Some(user.to_string()), m.to_string())
            } else {
                (None, t.to_string())
            }
        }
        None => (None, ".host".to_string()),
    };

    let user = cli.uid.clone().or(target_user).unwrap_or_else(|| {
        if machine_name == ".host" {
            std::env::var("USER").unwrap_or_else(|_| "root".to_string())
        } else {
            "root".to_string()
        }
    });

    let default_shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/bash".to_string());
    let exec_cmd = if command.is_empty() {
        vec![default_shell]
    } else {
        command.to_vec()
    };

    // If host, run directly
    if machine_name == ".host" {
        let mut cmd = Command::new(&exec_cmd[0]);
        cmd.args(&exec_cmd[1..]);
        for env_pair in &cli.setenv {
            if let Some((k, v)) = env_pair.split_once('=') {
                cmd.env(k, v);
            }
        }
        let status = cmd.status()?;
        return Ok(status.code().unwrap_or(1));
    }

    // Try DBus OpenMachineShell
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();

    let pty_opt = if let Ok(ref runtime) = rt {
        runtime
            .block_on(async {
                let conn = Connection::system().await?;
                let env_vec: Vec<String> = cli.setenv.clone();
                let args_vec: Vec<String> = exec_cmd.clone();
                let reply = conn
                    .call_method(
                        Some("org.freedesktop.machine1"),
                        "/org/freedesktop/machine1",
                        Some("org.freedesktop.machine1.Manager"),
                        "OpenMachineShell",
                        &(
                            machine_name.as_str(),
                            user.as_str(),
                            exec_cmd[0].as_str(),
                            args_vec,
                            env_vec,
                        ),
                    )
                    .await?;

                let (owned_fd, _): (zvariant::OwnedFd, String) = reply.body().deserialize()?;
                let raw_dup = unsafe { libc::dup(owned_fd.as_raw_fd()) };
                Ok::<_, anyhow::Error>(raw_dup)
            })
            .ok()
    } else {
        None
    };

    if let Some(pty_fd) = pty_opt {
        forward_pty(pty_fd)?;
        return Ok(0);
    }

    // Fallback: nsenter
    let all_machines = collect_all_machines();
    if let Some(m) = all_machines.iter().find(|m| m.name == machine_name) {
        if m.leader > 0 {
            let mut ns = Command::new("nsenter");
            ns.arg("-t").arg(m.leader.to_string());
            ns.arg("-m").arg("-u").arg("-i").arg("-n").arg("-p");
            ns.arg("--");
            ns.arg("su").arg("-").arg(&user);
            if !command.is_empty() {
                ns.arg("-c").arg(command.join(" "));
            }
            for env_pair in &cli.setenv {
                if let Some((k, v)) = env_pair.split_once('=') {
                    ns.env(k, v);
                }
            }
            let status = ns.status()?;
            return Ok(status.code().unwrap_or(1));
        }
    }

    eprintln!("Failed to invoke shell in machine '{machine_name}'.");
    Ok(1)
}

fn cmd_login(name: Option<&str>, _cli: &Cli) -> anyhow::Result<i32> {
    let machine_name = name.unwrap_or(".host");
    if machine_name == ".host" {
        let status = Command::new("login").status()?;
        return Ok(status.code().unwrap_or(1));
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();

    let pty_opt = if let Ok(ref runtime) = rt {
        runtime
            .block_on(async {
                let conn = Connection::system().await?;
                let reply = conn
                    .call_method(
                        Some("org.freedesktop.machine1"),
                        "/org/freedesktop/machine1",
                        Some("org.freedesktop.machine1.Manager"),
                        "OpenMachineLogin",
                        &(machine_name),
                    )
                    .await?;

                let (owned_fd, _): (zvariant::OwnedFd, String) = reply.body().deserialize()?;
                let raw_dup = unsafe { libc::dup(owned_fd.as_raw_fd()) };
                Ok::<_, anyhow::Error>(raw_dup)
            })
            .ok()
    } else {
        None
    };

    if let Some(pty_fd) = pty_opt {
        forward_pty(pty_fd)?;
        return Ok(0);
    }

    let all_machines = collect_all_machines();
    if let Some(m) = all_machines.iter().find(|m| m.name == machine_name) {
        if m.leader > 0 {
            let mut ns = Command::new("nsenter");
            ns.arg("-t").arg(m.leader.to_string());
            ns.arg("-m").arg("-u").arg("-i").arg("-n").arg("-p");
            ns.arg("--");
            ns.arg("login");
            let status = ns.status()?;
            return Ok(status.code().unwrap_or(1));
        }
    }

    eprintln!("Failed to open login prompt in machine '{machine_name}'.");
    Ok(1)
}

// ── Bind Mount & Copy Operations ──────────────────────────────────────────

fn cmd_bind(
    name: &str,
    source: &Path,
    destination: Option<&Path>,
    cli: &Cli,
) -> anyhow::Result<i32> {
    let dest = destination.unwrap_or(source);
    let src_str = source.to_string_lossy();
    let dst_str = dest.to_string_lossy();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();

    let dbus_ok = if let Ok(ref runtime) = rt {
        runtime
            .block_on(async {
                let conn = Connection::system().await?;
                conn.call_method(
                    Some("org.freedesktop.machine1"),
                    "/org/freedesktop/machine1",
                    Some("org.freedesktop.machine1.Manager"),
                    "BindMountMachine",
                    &(
                        name,
                        src_str.as_ref(),
                        dst_str.as_ref(),
                        cli.read_only,
                        cli.mkdir,
                    ),
                )
                .await?;
                Ok::<_, anyhow::Error>(())
            })
            .is_ok()
    } else {
        false
    };

    if dbus_ok {
        return Ok(0);
    }

    // Fallback: direct mount via nsenter
    let all_machines = collect_all_machines();
    if let Some(m) = all_machines.iter().find(|m| m.name == name) {
        if m.leader > 0 {
            if cli.mkdir {
                let target_dir = Path::new(&format!("/proc/{}/root", m.leader))
                    .join(dest.strip_prefix("/").unwrap_or(dest));
                let _ = fs::create_dir_all(&target_dir);
            }

            let mut mount_cmd = Command::new("nsenter");
            mount_cmd
                .arg("-t")
                .arg(m.leader.to_string())
                .arg("-m")
                .arg("--");
            mount_cmd.arg("mount").arg("--bind").arg(source).arg(dest);

            let status = mount_cmd.status()?;
            if status.success() {
                if cli.read_only {
                    let mut remount_cmd = Command::new("nsenter");
                    remount_cmd
                        .arg("-t")
                        .arg(m.leader.to_string())
                        .arg("-m")
                        .arg("--");
                    remount_cmd
                        .arg("mount")
                        .arg("-o")
                        .arg("remount,ro,bind")
                        .arg(dest);
                    let _ = remount_cmd.status();
                }
                return Ok(0);
            }
        }
    }

    eprintln!("Failed to bind mount '{src_str}' into machine '{name}'.");
    Ok(1)
}

fn copy_recursive(src: &Path, dst: &Path, force: bool) -> io::Result<()> {
    if src.is_dir() {
        if !dst.exists() {
            fs::create_dir_all(dst)?;
        }
        for entry in fs::read_dir(src)? {
            let entry = entry?;
            let entry_path = entry.path();
            let dest_child = dst.join(entry.file_name());
            copy_recursive(&entry_path, &dest_child, force)?;
        }
    } else {
        if dst.exists() && !force {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Target file exists",
            ));
        }
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(src, dst)?;
    }
    Ok(())
}

fn cmd_copy_to(
    name: &str,
    source: &Path,
    destination: Option<&Path>,
    cli: &Cli,
) -> anyhow::Result<i32> {
    let dest = destination.unwrap_or(source);
    let src_str = source.to_string_lossy();
    let dst_str = dest.to_string_lossy();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();

    let dbus_ok = if let Ok(ref runtime) = rt {
        runtime
            .block_on(async {
                let conn = Connection::system().await?;
                conn.call_method(
                    Some("org.freedesktop.machine1"),
                    "/org/freedesktop/machine1",
                    Some("org.freedesktop.machine1.Manager"),
                    "CopyToMachine",
                    &(name, src_str.as_ref(), dst_str.as_ref()),
                )
                .await?;
                Ok::<_, anyhow::Error>(())
            })
            .is_ok()
    } else {
        false
    };

    if dbus_ok {
        return Ok(0);
    }

    // Fallback: copy into /proc/<leader>/root/<dest>
    let all_machines = collect_all_machines();
    if let Some(m) = all_machines.iter().find(|m| m.name == name) {
        let container_root = if m.leader > 0 {
            PathBuf::from(format!("/proc/{}/root", m.leader))
        } else {
            PathBuf::from(&m.root_directory)
        };

        let target_path = container_root.join(dest.strip_prefix("/").unwrap_or(dest));
        match copy_recursive(source, &target_path, cli.force) {
            Ok(()) => return Ok(0),
            Err(e) => eprintln!("Failed to copy to machine '{name}': {e}"),
        }
    } else {
        eprintln!("No machine '{name}' known.");
    }

    Ok(1)
}

fn cmd_copy_from(
    name: &str,
    source: &Path,
    destination: Option<&Path>,
    cli: &Cli,
) -> anyhow::Result<i32> {
    let dest = destination.unwrap_or(source);
    let src_str = source.to_string_lossy();
    let dst_str = dest.to_string_lossy();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();

    let dbus_ok = if let Ok(ref runtime) = rt {
        runtime
            .block_on(async {
                let conn = Connection::system().await?;
                conn.call_method(
                    Some("org.freedesktop.machine1"),
                    "/org/freedesktop/machine1",
                    Some("org.freedesktop.machine1.Manager"),
                    "CopyFromMachine",
                    &(name, src_str.as_ref(), dst_str.as_ref()),
                )
                .await?;
                Ok::<_, anyhow::Error>(())
            })
            .is_ok()
    } else {
        false
    };

    if dbus_ok {
        return Ok(0);
    }

    // Fallback: copy from /proc/<leader>/root/<source>
    let all_machines = collect_all_machines();
    if let Some(m) = all_machines.iter().find(|m| m.name == name) {
        let container_root = if m.leader > 0 {
            PathBuf::from(format!("/proc/{}/root", m.leader))
        } else {
            PathBuf::from(&m.root_directory)
        };

        let target_path = container_root.join(source.strip_prefix("/").unwrap_or(source));
        match copy_recursive(&target_path, dest, cli.force) {
            Ok(()) => return Ok(0),
            Err(e) => eprintln!("Failed to copy from machine '{name}': {e}"),
        }
    } else {
        eprintln!("No machine '{name}' known.");
    }

    Ok(1)
}

// ── Image Management Operations ───────────────────────────────────────────

fn cmd_read_only(name: &str, read_only_val: Option<&str>, _cli: &Cli) -> anyhow::Result<i32> {
    let is_ro = match read_only_val {
        Some(v) => match v.to_lowercase().as_str() {
            "yes" | "true" | "1" | "on" => true,
            "no" | "false" | "0" | "off" => false,
            _ => true,
        },
        None => true,
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();

    let dbus_ok = if let Ok(ref runtime) = rt {
        runtime
            .block_on(async {
                let conn = Connection::system().await?;
                conn.call_method(
                    Some("org.freedesktop.machine1"),
                    "/org/freedesktop/machine1",
                    Some("org.freedesktop.machine1.Manager"),
                    "MarkImageReadOnly",
                    &(name, is_ro),
                )
                .await?;
                Ok::<_, anyhow::Error>(())
            })
            .is_ok()
    } else {
        false
    };

    if dbus_ok {
        return Ok(0);
    }

    let images = collect_all_images();
    if let Some(img) = images.iter().find(|i| i.name == name) {
        let p = Path::new(&img.path);
        if let Ok(meta) = p.metadata() {
            let mut perms = meta.permissions();
            perms.set_readonly(is_ro);
            if fs::set_permissions(p, perms).is_ok() {
                return Ok(0);
            }
        }
    }

    eprintln!("Failed to mark image '{name}' read-only={is_ro}.");
    Ok(1)
}

fn cmd_remove_image(names: &[String], _cli: &Cli) -> anyhow::Result<i32> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();

    let mut exit_code = 0;
    let images = collect_all_images();

    for name in names {
        let dbus_ok = if let Ok(ref runtime) = rt {
            runtime
                .block_on(async {
                    let conn = Connection::system().await?;
                    conn.call_method(
                        Some("org.freedesktop.machine1"),
                        "/org/freedesktop/machine1",
                        Some("org.freedesktop.machine1.Manager"),
                        "RemoveImage",
                        &(name.as_str()),
                    )
                    .await?;
                    Ok::<_, anyhow::Error>(())
                })
                .is_ok()
        } else {
            false
        };

        if !dbus_ok {
            if let Some(img) = images.iter().find(|i| &i.name == name) {
                let p = Path::new(&img.path);
                let res = if p.is_dir() {
                    fs::remove_dir_all(p)
                } else {
                    fs::remove_file(p)
                };
                if let Err(e) = res {
                    eprintln!("Failed to remove image '{name}': {e}");
                    exit_code = 1;
                }
            } else {
                eprintln!("Image '{name}' not found.");
                exit_code = 1;
            }
        }
    }

    Ok(exit_code)
}

fn cmd_clone_image(source: &str, dest: &str, cli: &Cli) -> anyhow::Result<i32> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();

    let dbus_ok = if let Ok(ref runtime) = rt {
        runtime
            .block_on(async {
                let conn = Connection::system().await?;
                conn.call_method(
                    Some("org.freedesktop.machine1"),
                    "/org/freedesktop/machine1",
                    Some("org.freedesktop.machine1.Manager"),
                    "CloneImage",
                    &(source, dest, cli.read_only),
                )
                .await?;
                Ok::<_, anyhow::Error>(())
            })
            .is_ok()
    } else {
        false
    };

    if dbus_ok {
        return Ok(0);
    }

    let images = collect_all_images();
    if let Some(img) = images.iter().find(|i| i.name == source) {
        let src_path = Path::new(&img.path);
        let dest_path = PathBuf::from("/var/lib/machines").join(dest);
        match copy_recursive(src_path, &dest_path, cli.force) {
            Ok(()) => {
                if cli.read_only {
                    let _ = cmd_read_only(dest, Some("yes"), cli);
                }
                return Ok(0);
            }
            Err(e) => eprintln!("Failed to clone image '{source}' to '{dest}': {e}"),
        }
    } else {
        eprintln!("Image '{source}' not found.");
    }

    Ok(1)
}

fn cmd_rename_image(source: &str, dest: &str, _cli: &Cli) -> anyhow::Result<i32> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();

    let dbus_ok = if let Ok(ref runtime) = rt {
        runtime
            .block_on(async {
                let conn = Connection::system().await?;
                conn.call_method(
                    Some("org.freedesktop.machine1"),
                    "/org/freedesktop/machine1",
                    Some("org.freedesktop.machine1.Manager"),
                    "RenameImage",
                    &(source, dest),
                )
                .await?;
                Ok::<_, anyhow::Error>(())
            })
            .is_ok()
    } else {
        false
    };

    if dbus_ok {
        return Ok(0);
    }

    let images = collect_all_images();
    if let Some(img) = images.iter().find(|i| i.name == source) {
        let src_path = Path::new(&img.path);
        let ext = src_path
            .extension()
            .map(|e| format!(".{}", e.to_string_lossy()))
            .unwrap_or_default();
        let dest_path = PathBuf::from("/var/lib/machines").join(format!("{dest}{ext}"));
        if let Err(e) = fs::rename(src_path, &dest_path) {
            eprintln!("Failed to rename image '{source}' to '{dest}': {e}");
            return Ok(1);
        }
        return Ok(0);
    }

    eprintln!("Image '{source}' not found.");
    Ok(1)
}

fn cmd_set_limit(name_or_bytes: &str, bytes_opt: Option<&str>, _cli: &Cli) -> anyhow::Result<i32> {
    let (target_image, bytes_str) = match bytes_opt {
        Some(b) => (Some(name_or_bytes), b),
        None => (None, name_or_bytes),
    };

    let bytes = match parse_bytes(bytes_str) {
        Some(b) => b,
        None => {
            eprintln!("Failed to parse size limit '{bytes_str}'.");
            return Ok(1);
        }
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();

    let dbus_ok = if let Ok(ref runtime) = rt {
        runtime
            .block_on(async {
                let conn = Connection::system().await?;
                if let Some(img_name) = target_image {
                    conn.call_method(
                        Some("org.freedesktop.machine1"),
                        "/org/freedesktop/machine1",
                        Some("org.freedesktop.machine1.Manager"),
                        "SetImageLimit",
                        &(img_name, bytes),
                    )
                    .await?;
                } else {
                    conn.call_method(
                        Some("org.freedesktop.machine1"),
                        "/org/freedesktop/machine1",
                        Some("org.freedesktop.machine1.Manager"),
                        "SetPoolLimit",
                        &(bytes),
                    )
                    .await?;
                }
                Ok::<_, anyhow::Error>(())
            })
            .is_ok()
    } else {
        false
    };

    if dbus_ok {
        return Ok(0);
    }

    if let Some(img_name) = target_image {
        let images = collect_all_images();
        if !images.iter().any(|i| i.name == img_name) {
            eprintln!("Image '{img_name}' not found.");
            return Ok(1);
        }
        eprintln!("Failed to set limit for image '{img_name}'.");
        return Ok(1);
    }

    eprintln!("Failed to set pool limit.");
    Ok(1)
}

fn cmd_clean(_cli: &Cli) -> anyhow::Result<i32> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();

    let _ = if let Ok(ref runtime) = rt {
        runtime
            .block_on(async {
                let conn = Connection::system().await?;
                conn.call_method(
                    Some("org.freedesktop.machine1"),
                    "/org/freedesktop/machine1",
                    Some("org.freedesktop.machine1.Manager"),
                    "CleanPool",
                    &("all"),
                )
                .await?;
                Ok::<_, anyhow::Error>(())
            })
            .is_ok()
    } else {
        false
    };

    let machines_dir = Path::new("/var/lib/machines");
    if machines_dir.is_dir() {
        if let Ok(entries) = fs::read_dir(machines_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with('.') || name.starts_with(".#") {
                    let path = entry.path();
                    if path.is_dir() {
                        let _ = fs::remove_dir_all(&path);
                    } else {
                        let _ = fs::remove_file(&path);
                    }
                }
            }
        }
    }

    Ok(0)
}

fn cmd_enable(names: &[String], enable: bool, cli: &Cli) -> anyhow::Result<i32> {
    let verb = if enable { "enable" } else { "disable" };
    let mut exit_code = 0;

    for name in names {
        let service = format!("systemd-nspawn@{name}.service");
        let mut cmd = Command::new("systemctl");
        cmd.arg(verb).arg(&service);
        if cli.now {
            cmd.arg("--now");
        }
        let status = cmd.status();
        match status {
            Ok(s) if s.success() => {}
            _ => {
                eprintln!("Failed to {verb} {service}.");
                exit_code = 1;
            }
        }
    }

    Ok(exit_code)
}

fn find_nspawn_settings(name: &str) -> Option<PathBuf> {
    let candidates = [
        PathBuf::from(format!("/etc/systemd/nspawn/{name}.nspawn")),
        PathBuf::from(format!("/run/systemd/nspawn/{name}.nspawn")),
        PathBuf::from(format!("/var/lib/machines/{name}.nspawn")),
    ];

    for c in &candidates {
        if c.exists() {
            return Some(c.clone());
        }
    }
    None
}

fn cmd_cat(names: &[String], _cli: &Cli) -> anyhow::Result<i32> {
    let mut exit_code = 0;
    for name in names {
        if let Some(path) = find_nspawn_settings(name) {
            if let Ok(content) = fs::read_to_string(&path) {
                println!("# {}", path.display());
                print!("{content}");
                if !content.ends_with('\n') {
                    println!();
                }
            }
        } else {
            eprintln!("No settings file found for machine '{name}'.");
            exit_code = 1;
        }
    }
    Ok(exit_code)
}

fn cmd_edit(names: &[String], _cli: &Cli) -> anyhow::Result<i32> {
    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "nano".to_string());
    let mut exit_code = 0;

    for name in names {
        let path = find_nspawn_settings(name).unwrap_or_else(|| {
            let p = PathBuf::from(format!("/etc/systemd/nspawn/{name}.nspawn"));
            if let Some(parent) = p.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let _ = OpenOptions::new().write(true).create_new(true).open(&p);
            p
        });

        let status = Command::new(&editor).arg(&path).status();
        match status {
            Ok(s) if s.success() => {}
            _ => {
                eprintln!(
                    "Failed to edit '{}' with editor '{editor}'.",
                    path.display()
                );
                exit_code = 1;
            }
        }
    }
    Ok(exit_code)
}

// ── Main Entrypoint ───────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();
    let command = cli.command.as_ref().unwrap_or(&Commands::List);

    let res = match command {
        Commands::List => cmd_list(&cli),
        Commands::ListImages => cmd_list_images(&cli),
        Commands::Status { names } => cmd_status(names, &cli),
        Commands::Show { names } => cmd_show(names, &cli),
        Commands::Start { names } => cmd_start(names, &cli),
        Commands::Stop { names } => cmd_stop_or_terminate(names, true, &cli),
        Commands::Terminate { names } => cmd_stop_or_terminate(names, false, &cli),
        Commands::Kill { names } => cmd_kill(names, &cli),
        Commands::Reboot { names } => cmd_reboot(names, &cli),
        Commands::Poweroff { names } => cmd_poweroff(names, &cli),
        Commands::Pause { names } => cmd_pause(names, true, &cli),
        Commands::Resume { names } => cmd_pause(names, false, &cli),
        Commands::Shell { target, command } => cmd_shell(target.as_deref(), command, &cli),
        Commands::Login { name } => cmd_login(name.as_deref(), &cli),
        Commands::Bind {
            name,
            source,
            destination,
        } => cmd_bind(name, source, destination.as_deref(), &cli),
        Commands::CopyTo {
            name,
            source,
            destination,
        } => cmd_copy_to(name, source, destination.as_deref(), &cli),
        Commands::CopyFrom {
            name,
            source,
            destination,
        } => cmd_copy_from(name, source, destination.as_deref(), &cli),
        Commands::ReadOnly { name, mode } => cmd_read_only(name, mode.as_deref(), &cli),
        Commands::ImageStatus { names } => cmd_image_status(names, &cli),
        Commands::ShowImage { names } => cmd_show_image(names, &cli),
        Commands::Clone {
            source,
            destination,
        } => cmd_clone_image(source, destination, &cli),
        Commands::Rename {
            source,
            destination,
        } => cmd_rename_image(source, destination, &cli),
        Commands::Remove { names } => cmd_remove_image(names, &cli),
        Commands::SetLimit {
            name_or_bytes,
            bytes,
        } => cmd_set_limit(name_or_bytes, bytes.as_deref(), &cli),
        Commands::Clean => cmd_clean(&cli),
        Commands::Enable { names } => cmd_enable(names, true, &cli),
        Commands::Disable { names } => cmd_enable(names, false, &cli),
        Commands::Cat { names } => cmd_cat(names, &cli),
        Commands::Edit { names } => cmd_edit(names, &cli),
    };

    let exit_code = match res {
        Ok(c) => c,
        Err(e) => {
            eprintln!("machinectl: {e}");
            1
        }
    };

    std::process::exit(exit_code);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(u64::MAX), "n/a");
        assert_eq!(format_bytes(500), "500B");
        assert_eq!(format_bytes(1024), "1.0K");
        assert_eq!(format_bytes(1024 * 1024), "1.0M");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0G");
        assert_eq!(format_bytes(1024 * 1024 * 1024 * 1024), "1.0T");
    }

    #[test]
    fn test_parse_bytes() {
        assert_eq!(parse_bytes("infinity"), Some(u64::MAX));
        assert_eq!(parse_bytes("max"), Some(u64::MAX));
        assert_eq!(parse_bytes("1024"), Some(1024));
        assert_eq!(parse_bytes("1K"), Some(1024));
        assert_eq!(parse_bytes("1M"), Some(1024 * 1024));
        assert_eq!(parse_bytes("1G"), Some(1024 * 1024 * 1024));
        assert_eq!(
            parse_bytes("1.5G"),
            Some((1.5 * 1024.0 * 1024.0 * 1024.0) as u64)
        );
    }

    #[test]
    fn test_signal_from_name() {
        assert_eq!(signal_from_name("SIGTERM"), libc::SIGTERM);
        assert_eq!(signal_from_name("TERM"), libc::SIGTERM);
        assert_eq!(signal_from_name("15"), libc::SIGTERM);
        assert_eq!(signal_from_name("SIGKILL"), libc::SIGKILL);
        assert_eq!(signal_from_name("9"), libc::SIGKILL);
        assert_eq!(signal_from_name("SIGINT"), libc::SIGINT);
        assert_eq!(signal_from_name("2"), libc::SIGINT);
        assert_eq!(signal_from_name("SIGHUP"), libc::SIGHUP);
        assert_eq!(signal_from_name("SIGSTOP"), libc::SIGSTOP);
        assert_eq!(signal_from_name("SIGCONT"), libc::SIGCONT);
        assert_eq!(signal_from_name("SIGPWR"), libc::SIGPWR);
    }

    #[test]
    fn test_cli_parsing_subcommands() {
        let cli = Cli::try_parse_from(["machinectl", "list"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::List)));

        let cli = Cli::try_parse_from(["machinectl", "list-images"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::ListImages)));

        let cli = Cli::try_parse_from(["machinectl", "status", "mybox"]).unwrap();
        if let Some(Commands::Status { names }) = cli.command {
            assert_eq!(names, vec!["mybox".to_string()]);
        } else {
            panic!("Expected Status subcommand");
        }

        let cli =
            Cli::try_parse_from(["machinectl", "show", "-p", "State", "--value", ".host"]).unwrap();
        assert!(cli.value);
        assert_eq!(cli.properties, vec!["State".to_string()]);
        if let Some(Commands::Show { names }) = cli.command {
            assert_eq!(names, vec![".host".to_string()]);
        } else {
            panic!("Expected Show subcommand");
        }

        let cli = Cli::try_parse_from([
            "machinectl",
            "kill",
            "--kill-whom=leader",
            "-s",
            "KILL",
            "mybox",
        ])
        .unwrap();
        assert_eq!(cli.kill_whom, "leader");
        assert_eq!(cli.signal, "KILL");
        if let Some(Commands::Kill { names }) = cli.command {
            assert_eq!(names, vec!["mybox".to_string()]);
        } else {
            panic!("Expected Kill subcommand");
        }

        let cli = Cli::try_parse_from([
            "machinectl",
            "bind",
            "--read-only",
            "--mkdir",
            "mybox",
            "/host/dir",
            "/cont/dir",
        ])
        .unwrap();
        assert!(cli.read_only);
        assert!(cli.mkdir);
        if let Some(Commands::Bind {
            name,
            source,
            destination,
        }) = cli.command
        {
            assert_eq!(name, "mybox");
            assert_eq!(source, PathBuf::from("/host/dir"));
            assert_eq!(destination, Some(PathBuf::from("/cont/dir")));
        } else {
            panic!("Expected Bind subcommand");
        }

        let cli = Cli::try_parse_from([
            "machinectl",
            "copy-to",
            "--force",
            "mybox",
            "/src/file",
            "/dst/file",
        ])
        .unwrap();
        assert!(cli.force);
        if let Some(Commands::CopyTo {
            name,
            source,
            destination,
        }) = cli.command
        {
            assert_eq!(name, "mybox");
            assert_eq!(source, PathBuf::from("/src/file"));
            assert_eq!(destination, Some(PathBuf::from("/dst/file")));
        } else {
            panic!("Expected CopyTo subcommand");
        }

        let cli = Cli::try_parse_from(["machinectl", "clone", "src_img", "dst_img"]).unwrap();
        if let Some(Commands::Clone {
            source,
            destination,
        }) = cli.command
        {
            assert_eq!(source, "src_img");
            assert_eq!(destination, "dst_img");
        } else {
            panic!("Expected Clone subcommand");
        }
    }

    #[test]
    fn test_host_machine_record() {
        let host = collect_host_machine();
        assert_eq!(host.name, ".host");
        assert_eq!(host.class, "host");
        assert_eq!(host.leader, 1);
        assert_eq!(host.root_directory, "/");
        assert_eq!(host.state, "running");
        assert_ne!(host.id, "");
    }

    #[test]
    fn test_serialization() {
        let host = collect_host_machine();
        let json = serde_json::to_string(&host).unwrap();
        assert!(json.contains(".host"));
        assert!(json.contains("running"));
    }

    #[test]
    fn test_read_only_cli_parsing() {
        let cli = Cli::try_parse_from(["machinectl", "read-only", "test-img"]).unwrap();
        if let Some(Commands::ReadOnly { name, mode }) = cli.command {
            assert_eq!(name, "test-img");
            assert_eq!(mode, None);
        } else {
            panic!("Expected ReadOnly subcommand");
        }

        let cli = Cli::try_parse_from(["machinectl", "read-only", "test-img", "true"]).unwrap();
        if let Some(Commands::ReadOnly { name, mode }) = cli.command {
            assert_eq!(name, "test-img");
            assert_eq!(mode.as_deref(), Some("true"));
        } else {
            panic!("Expected ReadOnly subcommand");
        }

        let cli = Cli::try_parse_from(["machinectl", "read-only", "test-img", "false"]).unwrap();
        if let Some(Commands::ReadOnly { name, mode }) = cli.command {
            assert_eq!(name, "test-img");
            assert_eq!(mode.as_deref(), Some("false"));
        } else {
            panic!("Expected ReadOnly subcommand");
        }
    }

    #[test]
    fn test_bare_json_flag_parsing() {
        let cli = Cli::try_parse_from(["machinectl", "list", "-j"]).unwrap();
        assert_eq!(cli.json, Some(JsonMode::Pretty));

        let cli = Cli::try_parse_from(["machinectl", "list", "--json"]).unwrap();
        assert_eq!(cli.json, Some(JsonMode::Pretty));

        let cli = Cli::try_parse_from(["machinectl", "list", "--json=short"]).unwrap();
        assert_eq!(cli.json, Some(JsonMode::Short));

        let cli = Cli::try_parse_from(["machinectl", "list", "--json=off"]).unwrap();
        assert_eq!(cli.json, Some(JsonMode::Off));

        let cli = Cli::try_parse_from(["machinectl", "list"]).unwrap();
        assert_eq!(cli.json, None);

        let cli = Cli::try_parse_from(["machinectl", "show", ".host", "-j"]).unwrap();
        assert_eq!(cli.json, Some(JsonMode::Pretty));
    }

    #[test]
    fn test_show_json_output() {
        let cli_json_pretty = Cli::try_parse_from(["machinectl", "show", ".host", "-j"]).unwrap();
        let res = cmd_show(&[".host".to_string()], &cli_json_pretty);
        assert_eq!(res.unwrap(), 0);

        let cli_json_short =
            Cli::try_parse_from(["machinectl", "show", ".host", "--json=short"]).unwrap();
        let res = cmd_show(&[".host".to_string()], &cli_json_short);
        assert_eq!(res.unwrap(), 0);

        let cli_mgr_json = Cli::try_parse_from(["machinectl", "show", "-j"]).unwrap();
        let res = cmd_show(&[], &cli_mgr_json);
        assert_eq!(res.unwrap(), 0);

        let cli_not_found =
            Cli::try_parse_from(["machinectl", "show", "nonexistent-machine-xyz"]).unwrap();
        let res = cmd_show(&["nonexistent-machine-xyz".to_string()], &cli_not_found);
        assert_eq!(res.unwrap(), 1);
    }

    #[test]
    fn test_set_limit_exit_code() {
        let cli = Cli::try_parse_from(["machinectl", "set-limit", "nonexistent-image-xyz", "10G"])
            .unwrap();
        let res = cmd_set_limit("nonexistent-image-xyz", Some("10G"), &cli);
        assert_eq!(res.unwrap(), 1);

        let cli_invalid =
            Cli::try_parse_from(["machinectl", "set-limit", "invalid_limit_format"]).unwrap();
        let res = cmd_set_limit("invalid_limit_format", None, &cli_invalid);
        assert_eq!(res.unwrap(), 1);
    }
}
