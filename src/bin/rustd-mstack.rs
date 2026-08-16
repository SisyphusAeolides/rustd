// SPDX-License-Identifier: LGPL-2.1-or-later
//! `systemd-mstack` — Mount stack manager utility.
//!
//! Inspects, establishes, and manages multi-layer overlay and stacked mount hierarchies.

use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader};
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
    name = "systemd-mstack",
    about = "Inspect and manage multi-layer mount stacks",
    version = VERSION_OUTPUT
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Target directory or root path
    #[arg(value_name = "TARGET")]
    target: Option<String>,

    /// Operate relative to specified root directory
    #[arg(long = "root", value_name = "PATH")]
    root: Option<String>,

    /// Mount stack read-only
    #[arg(short = 'r', long = "read-only")]
    read_only: bool,

    /// Output inspection data in JSON
    #[arg(long = "json", value_name = "MODE")]
    json: Option<JsonMode>,

    /// Equivalent to --json=pretty
    #[arg(short = 'j')]
    json_short: bool,

    /// Do not pipe output into a pager
    #[arg(long = "no-pager")]
    no_pager: bool,

    /// Do not show headers and footers
    #[arg(long = "no-legend")]
    no_legend: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Show status of stacked mount on target (default)
    Status {
        /// Target mount point path
        #[arg(value_name = "TARGET")]
        target: Option<String>,
    },
    /// List all active stacked and overlay mounts
    List,
    /// Establish a multi-layer stack mount on target
    Mount {
        /// Target mount directory
        #[arg(value_name = "TARGET")]
        target: String,
        /// Layer directory paths to stack
        #[arg(value_name = "LAYER", required = true)]
        layers: Vec<String>,
        /// Optional upper directory for read-write overlay
        #[arg(long = "upper", value_name = "PATH")]
        upper: Option<String>,
        /// Optional work directory for read-write overlay
        #[arg(long = "work", value_name = "PATH")]
        work: Option<String>,
    },
    /// Unmount a stacked mount hierarchy
    Umount {
        /// Target mount point to unmount
        #[arg(value_name = "TARGET")]
        target: String,
    },
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum JsonMode {
    Off,
    Pretty,
    Short,
}

#[derive(Clone, Debug, Serialize)]
struct MountStackEntry {
    mount_id: u32,
    parent_id: u32,
    major_minor: String,
    root: String,
    mount_point: String,
    mount_options: String,
    fs_type: String,
    mount_source: String,
    super_options: String,
    lower_layers: Vec<String>,
    upper_layer: Option<String>,
    work_layer: Option<String>,
}

fn unescape_octal(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let mut octal = String::new();
            for _ in 0..3 {
                if let Some(&digit) = chars.peek() {
                    if digit.is_digit(8) {
                        octal.push(chars.next().unwrap());
                    } else {
                        break;
                    }
                }
            }
            if octal.len() == 3 {
                if let Ok(byte) = u8::from_str_radix(&octal, 8) {
                    out.push(byte as char);
                    continue;
                }
            }
            out.push('\\');
            out.push_str(&octal);
        } else {
            out.push(c);
        }
    }
    out
}

fn parse_mountinfo() -> io::Result<Vec<MountStackEntry>> {
    let file = match File::open("/proc/self/mountinfo") {
        Ok(f) => f,
        Err(_) => File::open("/proc/mounts")?,
    };
    let reader = BufReader::new(file);
    let mut entries = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 7 {
            continue;
        }

        let mount_id = parts[0].parse().unwrap_or(0);
        let parent_id = parts[1].parse().unwrap_or(0);
        let major_minor = parts[2].to_string();
        let root = unescape_octal(parts[3]);
        let mount_point = unescape_octal(parts[4]);
        let mount_options = parts[5].to_string();

        // Find separator "-"
        let sep_pos = parts.iter().position(|&p| p == "-");
        let (fs_type, mount_source, super_options) = if let Some(pos) = sep_pos {
            let fstype = (*parts.get(pos + 1).unwrap_or(&"")).to_string();
            let src = parts
                .get(pos + 2)
                .map(|s| unescape_octal(s))
                .unwrap_or_default();
            let super_opts = (*parts.get(pos + 3).unwrap_or(&"")).to_string();
            (fstype, src, super_opts)
        } else {
            ("unknown".to_string(), parts[0].to_string(), String::new())
        };

        let mut lower_layers = Vec::new();
        let mut upper_layer = None;
        let mut work_layer = None;

        for opt in super_options.split(',') {
            if let Some(lower) = opt.strip_prefix("lowerdir=") {
                for layer in lower.split(':') {
                    lower_layers.push(unescape_octal(layer));
                }
            } else if let Some(upper) = opt.strip_prefix("upperdir=") {
                upper_layer = Some(unescape_octal(upper));
            } else if let Some(work) = opt.strip_prefix("workdir=") {
                work_layer = Some(unescape_octal(work));
            }
        }

        entries.push(MountStackEntry {
            mount_id,
            parent_id,
            major_minor,
            root,
            mount_point,
            mount_options,
            fs_type,
            mount_source,
            super_options,
            lower_layers,
            upper_layer,
            work_layer,
        });
    }

    Ok(entries)
}

fn print_stack_table(entries: &[MountStackEntry], no_legend: bool) {
    if !no_legend {
        println!(
            "{:<30} {:<10} {:<40} {:<20}",
            "MOUNTPOINT", "TYPE", "LAYERS", "UPPER"
        );
        println!("{:-<102}", "");
    }

    for e in entries {
        let layers_str = if e.lower_layers.is_empty() {
            "-".to_string()
        } else {
            e.lower_layers.join(":")
        };
        let upper_str = e.upper_layer.as_deref().unwrap_or("-");

        println!(
            "{:<30} {:<10} {:<40} {:<20}",
            e.mount_point, e.fs_type, layers_str, upper_str
        );
    }

    if !no_legend && entries.is_empty() {
        println!("(No active mount stacks found)");
    }
}

fn handle_mount(
    target: &str,
    layers: &[String],
    upper: Option<&str>,
    work: Option<&str>,
    read_only: bool,
) -> anyhow::Result<()> {
    let target_path = PathBuf::from(target);
    if !target_path.exists() {
        fs::create_dir_all(&target_path)?;
    }

    let mut overlay_opts = Vec::new();
    overlay_opts.push(format!("lowerdir={}", layers.join(":")));
    if let (Some(u), Some(w)) = (upper, work) {
        overlay_opts.push(format!("upperdir={u}"));
        overlay_opts.push(format!("workdir={w}"));
    }
    if read_only {
        overlay_opts.push("ro".to_string());
    }

    let data_str = overlay_opts.join(",");
    println!(
        "Mounting stack on {} with layers [{}]",
        target_path.display(),
        layers.join(", ")
    );

    let mut cmd = Command::new("mount");
    cmd.arg("-t").arg("overlay");
    cmd.arg("overlay");
    cmd.arg(&target_path);
    cmd.arg("-o").arg(&data_str);

    let status = cmd.status()?;
    if status.success() {
        println!("Successfully mounted stack on {}", target_path.display());
        Ok(())
    } else {
        Err(anyhow::anyhow!("Mount command exited with status {status}"))
    }
}

fn handle_umount(target: &str) -> anyhow::Result<()> {
    let target_path = Path::new(target);
    let c_tgt = CString::new(target_path.to_string_lossy().as_bytes()).unwrap();

    let ret = unsafe { libc::umount2(c_tgt.as_ptr(), 0) };
    if ret == 0 {
        println!("Successfully unmounted stack at {}", target_path.display());
        Ok(())
    } else {
        let err = io::Error::last_os_error();
        Err(anyhow::anyhow!(
            "Failed to unmount {}: {}",
            target_path.display(),
            err
        ))
    }
}

fn main() {
    let cli = Cli::parse();

    let json_mode = if cli.json_short {
        Some(JsonMode::Pretty)
    } else {
        cli.json
    };

    let mount_entries = match parse_mountinfo() {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!("systemd-mstack: Failed to read mount information: {e}");
            std::process::exit(1);
        }
    };

    let stack_entries: Vec<MountStackEntry> = mount_entries
        .into_iter()
        .filter(|e| e.fs_type == "overlay" || !e.lower_layers.is_empty())
        .collect();

    match cli.command {
        Some(Commands::List) => match json_mode {
            Some(JsonMode::Pretty) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&stack_entries).unwrap_or_default()
                );
            }
            Some(JsonMode::Short) => {
                println!(
                    "{}",
                    serde_json::to_string(&stack_entries).unwrap_or_default()
                );
            }
            _ => {
                print_stack_table(&stack_entries, cli.no_legend);
            }
        },
        Some(Commands::Mount {
            target,
            layers,
            upper,
            work,
        }) => {
            if let Err(e) = handle_mount(
                &target,
                &layers,
                upper.as_deref(),
                work.as_deref(),
                cli.read_only,
            ) {
                eprintln!("systemd-mstack: Mount failed: {e}");
                std::process::exit(1);
            }
        }
        Some(Commands::Umount { target }) => {
            if let Err(e) = handle_umount(&target) {
                eprintln!("systemd-mstack: Umount failed: {e}");
                std::process::exit(1);
            }
        }
        Some(Commands::Status { target }) => {
            let tgt = target.as_deref().or(cli.target.as_deref());
            let filtered: Vec<MountStackEntry> = match tgt {
                Some(t) => stack_entries
                    .into_iter()
                    .filter(|e| e.mount_point == t || e.mount_point.starts_with(t))
                    .collect(),
                None => stack_entries,
            };

            match json_mode {
                Some(JsonMode::Pretty) => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&filtered).unwrap_or_default()
                    );
                }
                Some(JsonMode::Short) => {
                    println!("{}", serde_json::to_string(&filtered).unwrap_or_default());
                }
                _ => {
                    print_stack_table(&filtered, cli.no_legend);
                }
            }
        }
        None => {
            let tgt = cli.target.as_deref();
            let filtered: Vec<MountStackEntry> = match tgt {
                Some(t) => stack_entries
                    .into_iter()
                    .filter(|e| e.mount_point == t || e.mount_point.starts_with(t))
                    .collect(),
                None => stack_entries,
            };

            match json_mode {
                Some(JsonMode::Pretty) => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&filtered).unwrap_or_default()
                    );
                }
                Some(JsonMode::Short) => {
                    println!("{}", serde_json::to_string(&filtered).unwrap_or_default());
                }
                _ => {
                    print_stack_table(&filtered, cli.no_legend);
                }
            }
        }
    }
}
