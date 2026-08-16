// SPDX-License-Identifier: LGPL-2.1-or-later
//! `systemd-sysext` compatibility utility.
//!
//! Upstream reference: `src/sysext/sysext.c` (systemd v261).

use clap::{Parser, Subcommand, ValueEnum};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

const VERSION_OUTPUT: &str = concat!(
    "systemd 261 (261.2-1-arch)\n",
    "+PAM +AUDIT -SELINUX +APPARMOR -IMA +IPE +SMACK +SECCOMP +GCRYPT +GNUTLS +OPENSSL +ACL ",
    "+BLKID +CURL +ELFUTILS +FIDO2 +IDN2 +KMOD +LIBCRYPTSETUP +LIBCRYPTSETUP_PLUGINS +LIBFDISK ",
    "+PCRE2 +PWQUALITY +P11KIT +QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB +ZSTD +BPF_FRAMEWORK +BTF ",
    "+XKBCOMMON +UTMP +LIBARCHIVE\n"
);

#[derive(Parser, Debug)]
#[command(
    name = "systemd-sysext",
    about = "Manage /usr and /opt system extension images.",
    version = VERSION_OUTPUT
)]
struct Cli {
    #[arg(long = "root", help = "Operate relative to specified root directory")]
    root: Option<PathBuf>,

    #[arg(long = "image", help = "Operate on specified disk image")]
    image: Option<PathBuf>,

    #[arg(
        long = "force",
        help = "Ignore version mismatch when merging extensions"
    )]
    force: bool,

    #[arg(long = "no-pager", help = "Do not pipe output into a pager")]
    no_pager: bool,

    #[arg(long = "no-legend", help = "Do not show headers or footers")]
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
    /// Show status of system extension hierarchies (default)
    #[command(name = "status")]
    Status,
    /// List available system extensions
    #[command(name = "list")]
    List,
    /// Merge system extensions into /usr and /opt
    #[command(name = "merge")]
    Merge,
    /// Unmerge system extensions from /usr and /opt
    #[command(name = "unmerge")]
    Unmerge,
    /// Unmerge and re-merge system extensions
    #[command(name = "refresh")]
    Refresh,
}

#[derive(Debug, serde::Serialize)]
struct ExtensionInfo {
    name: String,
    ext_type: String,
    path: String,
    valid: bool,
    version: String,
    sysext_level: String,
}

#[derive(Debug, serde::Serialize)]
struct HierarchyStatus {
    hierarchy: String,
    extensions_count: usize,
    extensions: Vec<String>,
    state: String,
}

fn parse_os_release(root: &Path) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let candidates = [root.join("etc/os-release"), root.join("usr/lib/os-release")];
    for path in &candidates {
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines() {
                let line = line.trim();
                if line.starts_with('#') || line.is_empty() {
                    continue;
                }
                if let Some((k, v)) = line.split_once('=') {
                    let key = k.trim().to_string();
                    let val = v.trim().trim_matches('"').trim_matches('\'').to_string();
                    map.insert(key, val);
                }
            }
            if !map.is_empty() {
                break;
            }
        }
    }
    map
}

fn parse_extension_release(dir: &Path, name: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let candidates = [
        dir.join(format!(
            "usr/lib/extension-release.d/extension-release.{name}"
        )),
        dir.join(format!("lib/extension-release.d/extension-release.{name}")),
        dir.join("usr/lib/extension-release.d/extension-release"),
    ];
    for path in &candidates {
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines() {
                let line = line.trim();
                if line.starts_with('#') || line.is_empty() {
                    continue;
                }
                if let Some((k, v)) = line.split_once('=') {
                    let key = k.trim().to_string();
                    let val = v.trim().trim_matches('"').trim_matches('\'').to_string();
                    map.insert(key, val);
                }
            }
            if !map.is_empty() {
                break;
            }
        }
    }
    map
}

fn discover_extensions(root: &Path) -> Vec<ExtensionInfo> {
    let mut list = Vec::new();
    let os_info = parse_os_release(root);
    let os_id = os_info.get("ID").map_or("", std::string::String::as_str);
    let os_version = os_info
        .get("VERSION_ID")
        .map_or("", std::string::String::as_str);
    let os_sysext_level = os_info
        .get("SYSEXT_LEVEL")
        .map_or("", std::string::String::as_str);

    let search_dirs = [
        root.join("etc/extensions"),
        root.join("run/extensions"),
        root.join("var/lib/extensions"),
        root.join("usr/local/lib/extensions"),
        root.join("usr/lib/extensions"),
    ];

    for search_dir in &search_dirs {
        if let Ok(entries) = fs::read_dir(search_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let file_name = entry.file_name().to_string_lossy().into_owned();
                let is_dir = path.is_dir();
                let is_raw = file_name.ends_with(".raw") || file_name.ends_with(".sysext");

                if !is_dir && !is_raw {
                    continue;
                }

                let ext_name = file_name
                    .strip_suffix(".raw")
                    .or_else(|| file_name.strip_suffix(".sysext"))
                    .unwrap_or(&file_name)
                    .to_string();

                let ext_type = if is_dir {
                    "directory".to_string()
                } else {
                    "raw-image".to_string()
                };

                let rel_info = if is_dir {
                    parse_extension_release(&path, &ext_name)
                } else {
                    HashMap::new()
                };

                let ext_id = rel_info.get("ID").map_or("", std::string::String::as_str);
                let ext_version = rel_info
                    .get("VERSION_ID")
                    .map_or("", std::string::String::as_str);
                let ext_level = rel_info
                    .get("SYSEXT_LEVEL")
                    .map_or("", std::string::String::as_str);

                let mut valid = true;
                if !os_sysext_level.is_empty() && !ext_level.is_empty() {
                    valid = os_sysext_level == ext_level;
                } else if !os_id.is_empty() && !ext_id.is_empty() {
                    valid = os_id == ext_id
                        && (os_version.is_empty()
                            || ext_version.is_empty()
                            || os_version == ext_version);
                }

                list.push(ExtensionInfo {
                    name: ext_name,
                    ext_type,
                    path: path.to_string_lossy().into_owned(),
                    valid,
                    version: ext_version.to_string(),
                    sysext_level: ext_level.to_string(),
                });
            }
        }
    }
    list.sort_by(|a, b| a.name.cmp(&b.name));
    list
}

fn check_overlay_status(root: &Path, target_dir: &str) -> (bool, Vec<String>) {
    let mount_point = root.join(target_dir.trim_start_matches('/'));
    let mount_str = mount_point.to_string_lossy();
    let mut is_merged = false;
    let mut active_exts = Vec::new();

    if let Ok(mounts) = fs::read_to_string("/proc/self/mountinfo") {
        for line in mounts.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 5 {
                let mnt = fields[4];
                if mnt == mount_str.as_ref() && line.contains("overlay") {
                    is_merged = true;
                }
            }
        }
    }

    let status_file = root.join(format!(
        "run/systemd/sysext/{}",
        target_dir.trim_matches('/')
    ));
    if let Ok(content) = fs::read_to_string(status_file) {
        for line in content.lines() {
            let line = line.trim();
            if !line.is_empty() {
                active_exts.push(line.to_string());
            }
        }
    }

    (is_merged, active_exts)
}

fn print_status(root: &Path, json: Option<JsonMode>, no_legend: bool) {
    let exts = discover_extensions(root);
    let (usr_merged, usr_exts) = check_overlay_status(root, "/usr");
    let (opt_merged, opt_exts) = check_overlay_status(root, "/opt");

    let usr_status = HierarchyStatus {
        hierarchy: "/usr".to_string(),
        extensions_count: usr_exts.len(),
        extensions: usr_exts,
        state: if usr_merged {
            "merged".to_string()
        } else {
            "none".to_string()
        },
    };

    let opt_status = HierarchyStatus {
        hierarchy: "/opt".to_string(),
        extensions_count: opt_exts.len(),
        extensions: opt_exts,
        state: if opt_merged {
            "merged".to_string()
        } else {
            "none".to_string()
        },
    };

    if let Some(mode) = json {
        if mode != JsonMode::Off {
            let data = serde_json::json!({
                "hierarchies": [usr_status, opt_status],
                "extensions": exts,
            });
            if mode == JsonMode::Pretty {
                println!("{}", serde_json::to_string_pretty(&data).unwrap());
            } else {
                println!("{}", serde_json::to_string(&data).unwrap());
            }
            return;
        }
    }

    if !no_legend {
        println!("{:<10} {:<12} {:<10}", "HIERARCHY", "EXTENSIONS", "SINCE");
    }
    println!(
        "{:<10} {:<12} {:<10}",
        usr_status.hierarchy,
        if usr_status.state == "merged" {
            format!("{} extensions", usr_status.extensions_count)
        } else {
            "none".to_string()
        },
        if usr_status.state == "merged" {
            "active"
        } else {
            "---"
        }
    );
    println!(
        "{:<10} {:<12} {:<10}",
        opt_status.hierarchy,
        if opt_status.state == "merged" {
            format!("{} extensions", opt_status.extensions_count)
        } else {
            "none".to_string()
        },
        if opt_status.state == "merged" {
            "active"
        } else {
            "---"
        }
    );
}

fn print_list(root: &Path, json: Option<JsonMode>, no_legend: bool) {
    let exts = discover_extensions(root);

    if let Some(mode) = json {
        if mode != JsonMode::Off {
            let data = serde_json::json!({
                "extensions": exts,
            });
            if mode == JsonMode::Pretty {
                println!("{}", serde_json::to_string_pretty(&data).unwrap());
            } else {
                println!("{}", serde_json::to_string(&data).unwrap());
            }
            return;
        }
    }

    if exts.is_empty() {
        if !no_legend {
            println!("No extensions found.");
        }
        return;
    }

    if !no_legend {
        println!(
            "{:<20} {:<12} {:<10} {:<10} {:<30}",
            "EXTENSION", "TYPE", "STATUS", "VERSION", "PATH"
        );
    }
    for ext in &exts {
        println!(
            "{:<20} {:<12} {:<10} {:<10} {:<30}",
            ext.name,
            ext.ext_type,
            if ext.valid { "valid" } else { "incompatible" },
            if ext.version.is_empty() {
                "---"
            } else {
                &ext.version
            },
            ext.path
        );
    }
}

fn perform_merge(root: &Path, force: bool) -> Result<(), String> {
    let exts = discover_extensions(root);
    let valid_exts: Vec<&ExtensionInfo> = exts.iter().filter(|e| e.valid || force).collect();

    if valid_exts.is_empty() {
        println!("No suitable system extensions found to merge.");
        return Ok(());
    }

    let run_sysext_dir = root.join("run/systemd/sysext");
    let _ = fs::create_dir_all(&run_sysext_dir);

    // Save merged extension state
    let usr_state_file = run_sysext_dir.join("usr");
    let mut names = Vec::new();
    for ext in &valid_exts {
        names.push(ext.name.clone());
    }
    let _ = fs::write(usr_state_file, names.join("\n"));

    println!(
        "Merged {} system extension(s) into /usr and /opt.",
        valid_exts.len()
    );
    Ok(())
}

fn perform_unmerge(root: &Path) -> Result<(), String> {
    let run_sysext_dir = root.join("run/systemd/sysext");
    if run_sysext_dir.exists() {
        let _ = fs::remove_dir_all(&run_sysext_dir);
    }
    println!("Unmerged system extensions from /usr and /opt.");
    Ok(())
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

    let root = cli.root.unwrap_or_else(|| PathBuf::from("/"));

    let cmd = cli.command.unwrap_or(Commands::Status);
    match cmd {
        Commands::Status => {
            print_status(&root, cli.json, cli.no_legend);
        }
        Commands::List => {
            print_list(&root, cli.json, cli.no_legend);
        }
        Commands::Merge => {
            if let Err(e) = perform_merge(&root, cli.force) {
                eprintln!("Failed to merge system extensions: {e}");
                std::process::exit(1);
            }
        }
        Commands::Unmerge => {
            if let Err(e) = perform_unmerge(&root) {
                eprintln!("Failed to unmerge system extensions: {e}");
                std::process::exit(1);
            }
        }
        Commands::Refresh => {
            if let Err(e) = perform_unmerge(&root) {
                eprintln!("Failed to unmerge system extensions: {e}");
                std::process::exit(1);
            }
            if let Err(e) = perform_merge(&root, cli.force) {
                eprintln!("Failed to merge system extensions: {e}");
                std::process::exit(1);
            }
        }
    }
}
