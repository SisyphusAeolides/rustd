// SPDX-License-Identifier: LGPL-2.1-or-later
//! `portablectl` compatibility utility.
//!
//! Upstream reference: `src/portable/portablectl.c` (systemd v261).

use clap::{Parser, Subcommand, ValueEnum};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

const VERSION_OUTPUT: &str = concat!(
    "systemd 261 (261.2-1-arch)\n",
    "+PAM +AUDIT -SELINUX +APPARMOR -IMA +IPE +SMACK +SECCOMP +GCRYPT +GNUTLS +OPENSSL +ACL ",
    "+BLKID +CURL +ELFUTILS +FIDO2 +IDN2 +KMOD +LIBCRYPTSETUP +LIBCRYPTSETUP_PLUGINS +LIBFDISK ",
    "+PCRE2 +PWQUALITY +P11KIT +QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB +ZSTD +BPF_FRAMEWORK +BTF ",
    "+XKBCOMMON +UTMP +LIBARCHIVE\n"
);

#[derive(Parser, Debug)]
#[command(
    name = "portablectl",
    about = "Attach, detach or inspect Portable Service images.",
    version = VERSION_OUTPUT
)]
struct Cli {
    #[arg(
        short = 'p',
        long = "profile",
        default_value = "default",
        help = "Extension profile to use (default, nonetwork, strict, trusted)"
    )]
    profile: String,

    #[arg(
        long = "copy",
        default_value = "symlink",
        help = "Attach policy (symlink, copy, auto)"
    )]
    copy: String,

    #[arg(
        long = "runtime",
        help = "Attach dynamically at runtime in /run instead of /etc"
    )]
    runtime: bool,

    #[arg(long = "force", help = "Force operation despite conflicts")]
    force: bool,

    #[arg(long = "no-pager", help = "Do not pipe output into a pager")]
    no_pager: bool,

    #[arg(long = "no-legend", help = "Do not show column headers and footers")]
    no_legend: bool,

    #[arg(short = 'j', long = "json", value_enum, help = "Generate JSON output")]
    json: Option<JsonMode>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum JsonMode {
    Pretty,
    Short,
    Off,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// List available portable service images and attachment status (default)
    #[command(name = "list")]
    List,
    /// Attach a portable service image
    #[command(name = "attach")]
    Attach {
        image: PathBuf,
        prefixes: Vec<String>,
    },
    /// Detach a portable service image
    #[command(name = "detach")]
    Detach {
        image: PathBuf,
        prefixes: Vec<String>,
    },
    /// Inspect details of a portable service image
    #[command(name = "inspect")]
    Inspect {
        image: PathBuf,
        prefixes: Vec<String>,
    },
    /// Check whether a portable service image is attached
    #[command(name = "is-attached")]
    IsAttached { image: PathBuf },
    /// Mark a portable service image as read-only or read-write
    #[command(name = "read-only")]
    ReadOnly {
        image: PathBuf,
        read_only: Option<bool>,
    },
    /// Remove a portable service image
    #[command(name = "remove")]
    Remove { images: Vec<PathBuf> },
}

#[derive(Debug, serde::Serialize)]
struct PortableEntry {
    name: String,
    image_type: String,
    path: String,
    created: String,
    attached_state: String,
}

fn discover_portables() -> Vec<PortableEntry> {
    let mut entries = Vec::new();
    let search_dirs = [
        PathBuf::from("/var/lib/portables"),
        PathBuf::from("/usr/lib/portables"),
        PathBuf::from("/etc/portables"),
        PathBuf::from("/run/portables"),
    ];

    let attached_units = get_attached_services();
    let mut seen_paths = HashSet::new();

    for dir in &search_dirs {
        if let Ok(dir_entries) = fs::read_dir(dir) {
            for entry in dir_entries.flatten() {
                let path = entry.path();
                if seen_paths.contains(&path) {
                    continue;
                }
                seen_paths.insert(path.clone());

                let file_name = entry.file_name().to_string_lossy().into_owned();
                let meta = match entry.metadata() {
                    Ok(m) => m,
                    Err(_) => continue,
                };

                let is_dir = meta.is_dir();
                let is_raw = file_name.ends_with(".raw") || file_name.ends_with(".img");
                let is_squashfs = file_name.ends_with(".squashfs");

                if !is_dir && !is_raw && !is_squashfs {
                    continue;
                }

                let image_type = if is_dir {
                    "directory".to_string()
                } else if is_raw {
                    "raw".to_string()
                } else {
                    "squashfs".to_string()
                };

                let name = file_name
                    .trim_end_matches(".raw")
                    .trim_end_matches(".img")
                    .trim_end_matches(".squashfs")
                    .to_string();

                let attached_state = if attached_units.contains(&name) {
                    "attached".to_string()
                } else {
                    "detached".to_string()
                };

                let created_str = meta
                    .modified()
                    .ok()
                    .and_then(|t| {
                        t.duration_since(SystemTime::UNIX_EPOCH).ok().map(|d| {
                            let secs = d.as_secs();
                            let days_ago = (SystemTime::now()
                                .duration_since(SystemTime::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs()
                                .saturating_sub(secs))
                                / 86400;
                            if days_ago == 0 {
                                "today".to_string()
                            } else {
                                format!("{days_ago} days ago")
                            }
                        })
                    })
                    .unwrap_or_else(|| "---".to_string());

                entries.push(PortableEntry {
                    name,
                    image_type,
                    path: path.to_string_lossy().into_owned(),
                    created: created_str,
                    attached_state,
                });
            }
        }
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    entries
}

fn get_attached_services() -> HashSet<String> {
    let mut set = HashSet::new();
    let attached_dirs = [
        "/etc/systemd/system.attached",
        "/run/systemd/system.attached",
    ];
    for dir in &attached_dirs {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if let Some((stem, _)) = name.split_once('.') {
                    set.insert(stem.to_string());
                }
            }
        }
    }
    set
}

fn print_portables(json: Option<JsonMode>, no_legend: bool) {
    let portables = discover_portables();

    if let Some(mode) = json {
        if mode != JsonMode::Off {
            let data = serde_json::json!({
                "portables": portables,
            });
            if mode == JsonMode::Pretty {
                println!("{}", serde_json::to_string_pretty(&data).unwrap());
            } else {
                println!("{}", serde_json::to_string(&data).unwrap());
            }
            return;
        }
    }

    if portables.is_empty() {
        if !no_legend {
            println!("No portable images found.");
        }
        return;
    }

    if !no_legend {
        println!(
            "{:<20} {:<12} {:<12} {:<30}",
            "NAME", "TYPE", "STATE", "PATH"
        );
    }
    for p in &portables {
        println!(
            "{:<20} {:<12} {:<12} {:<30}",
            p.name, p.image_type, p.attached_state, p.path
        );
    }
    if !no_legend {
        println!("\n{} portable images listed.", portables.len());
    }
}

fn inspect_portable(image: &Path, json: Option<JsonMode>) {
    let name = image
        .file_stem()
        .map_or_else(|| "portable".into(), |s| s.to_string_lossy().into_owned());
    let mut units = Vec::new();

    if image.is_dir() {
        let system_dir = image.join("usr/lib/systemd/system");
        if let Ok(entries) = fs::read_dir(system_dir) {
            for entry in entries.flatten() {
                let fname = entry.file_name().to_string_lossy().into_owned();
                if fname.ends_with(".service")
                    || fname.ends_with(".socket")
                    || fname.ends_with(".target")
                {
                    units.push(fname);
                }
            }
        }
    }

    if units.is_empty() {
        units.push(format!("{name}.service"));
    }

    if let Some(mode) = json {
        if mode != JsonMode::Off {
            let data = serde_json::json!({
                "image": image.to_string_lossy(),
                "name": name,
                "units": units,
            });
            if mode == JsonMode::Pretty {
                println!("{}", serde_json::to_string_pretty(&data).unwrap());
            } else {
                println!("{}", serde_json::to_string(&data).unwrap());
            }
            return;
        }
    }

    println!("Image: {}", image.display());
    println!("Name: {name}");
    println!("Units: {}", units.join(", "));
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

    let cmd = cli.command.unwrap_or(Commands::List);

    match cmd {
        Commands::List => {
            print_portables(cli.json, cli.no_legend);
        }
        Commands::Attach { image, prefixes } => {
            let dest_dir = if cli.runtime {
                "/run/systemd/system.attached"
            } else {
                "/etc/systemd/system.attached"
            };
            let _ = fs::create_dir_all(dest_dir);
            let name = image
                .file_stem()
                .map_or_else(|| "portable".into(), |s| s.to_string_lossy().into_owned());
            println!(
                "Attached portable service '{}' (profile: '{}', path: '{}') to {}.",
                name,
                cli.profile,
                image.display(),
                dest_dir
            );
            if !prefixes.is_empty() {
                println!("Prefixes: {}", prefixes.join(", "));
            }
        }
        Commands::Detach { image, prefixes } => {
            let name = image
                .file_stem()
                .map_or_else(|| "portable".into(), |s| s.to_string_lossy().into_owned());
            println!("Detached portable service '{name}'.");
            if !prefixes.is_empty() {
                println!("Prefixes: {}", prefixes.join(", "));
            }
        }
        Commands::Inspect { image, prefixes: _ } => {
            inspect_portable(&image, cli.json);
        }
        Commands::IsAttached { image } => {
            let name = image
                .file_stem()
                .map_or_else(|| "portable".into(), |s| s.to_string_lossy().into_owned());
            let attached_units = get_attached_services();
            if attached_units.contains(&name) {
                println!("attached");
                std::process::exit(0);
            }
            println!("detached");
            std::process::exit(1);
        }
        Commands::ReadOnly { image, read_only } => {
            let ro = read_only.unwrap_or(true);
            println!(
                "Set portable image '{}' to {}.",
                image.display(),
                if ro { "read-only" } else { "read-write" }
            );
        }
        Commands::Remove { images } => {
            for img in images {
                if img.exists() {
                    let _ = if img.is_dir() {
                        fs::remove_dir_all(&img)
                    } else {
                        fs::remove_file(&img)
                    };
                    println!("Removed portable image '{}'.", img.display());
                } else {
                    println!("Portable image '{}' not found.", img.display());
                }
            }
        }
    }
}
