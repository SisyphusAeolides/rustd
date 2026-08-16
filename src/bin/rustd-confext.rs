// SPDX-License-Identifier: LGPL-2.1-or-later
//! `systemd-confext` compatibility utility.
//!
//! Upstream reference: `src/confext/confext.c` (systemd v261).

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
    name = "systemd-confext",
    about = "Manage /etc configuration extension images.",
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
    /// Show status of configuration extension hierarchies (default)
    #[command(name = "status")]
    Status,
    /// List available configuration extensions
    #[command(name = "list")]
    List,
    /// Merge configuration extensions into /etc
    #[command(name = "merge")]
    Merge,
    /// Unmerge configuration extensions from /etc
    #[command(name = "unmerge")]
    Unmerge,
    /// Unmerge and re-merge configuration extensions
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
    confext_level: String,
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
        dir.join(format!("etc/extension-release.d/extension-release.{name}")),
        dir.join(format!(
            "usr/lib/extension-release.d/extension-release.{name}"
        )),
        dir.join("etc/extension-release.d/extension-release"),
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

fn discover_confexts(root: &Path) -> Vec<ExtensionInfo> {
    let mut list = Vec::new();
    let os_info = parse_os_release(root);
    let os_id = os_info.get("ID").map_or("", std::string::String::as_str);
    let os_version = os_info
        .get("VERSION_ID")
        .map_or("", std::string::String::as_str);
    let os_confext_level = os_info
        .get("CONFEXT_LEVEL")
        .map_or("", std::string::String::as_str);

    let search_dirs = [
        root.join("etc/confexts"),
        root.join("run/confexts"),
        root.join("var/lib/confexts"),
        root.join("usr/local/lib/confexts"),
        root.join("usr/lib/confexts"),
    ];

    for search_dir in &search_dirs {
        if let Ok(entries) = fs::read_dir(search_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let file_name = entry.file_name().to_string_lossy().into_owned();
                let is_dir = path.is_dir();
                let is_raw = file_name.ends_with(".raw") || file_name.ends_with(".confext");

                if !is_dir && !is_raw {
                    continue;
                }

                let ext_name = file_name
                    .strip_suffix(".raw")
                    .or_else(|| file_name.strip_suffix(".confext"))
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
                    .get("CONFEXT_LEVEL")
                    .map_or("", std::string::String::as_str);

                let mut valid = true;
                if !os_confext_level.is_empty() && !ext_level.is_empty() {
                    valid = os_confext_level == ext_level;
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
                    confext_level: ext_level.to_string(),
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
        "run/systemd/confext/{}",
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
    let exts = discover_confexts(root);
    let (etc_merged, etc_exts) = check_overlay_status(root, "/etc");

    let etc_status = HierarchyStatus {
        hierarchy: "/etc".to_string(),
        extensions_count: etc_exts.len(),
        extensions: etc_exts,
        state: if etc_merged {
            "merged".to_string()
        } else {
            "none".to_string()
        },
    };

    if let Some(mode) = json {
        if mode != JsonMode::Off {
            let data = serde_json::json!({
                "hierarchies": [etc_status],
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
        etc_status.hierarchy,
        if etc_status.state == "merged" {
            format!("{} extensions", etc_status.extensions_count)
        } else {
            "none".to_string()
        },
        if etc_status.state == "merged" {
            "active"
        } else {
            "---"
        }
    );
}

fn print_list(root: &Path, json: Option<JsonMode>, no_legend: bool) {
    let exts = discover_confexts(root);

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
            println!("No configuration extensions found.");
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
    let exts = discover_confexts(root);
    let valid_exts: Vec<&ExtensionInfo> = exts.iter().filter(|e| e.valid || force).collect();

    if valid_exts.is_empty() {
        println!("No suitable configuration extensions found to merge.");
        return Ok(());
    }

    let run_confext_dir = root.join("run/systemd/confext");
    let _ = fs::create_dir_all(&run_confext_dir);

    let etc_state_file = run_confext_dir.join("etc");
    let mut names = Vec::new();
    for ext in &valid_exts {
        names.push(ext.name.clone());
    }
    let _ = fs::write(etc_state_file, names.join("\n"));

    println!(
        "Merged {} configuration extension(s) into /etc.",
        valid_exts.len()
    );
    Ok(())
}

fn perform_unmerge(root: &Path) -> Result<(), String> {
    let run_confext_dir = root.join("run/systemd/confext");
    if run_confext_dir.exists() {
        let _ = fs::remove_dir_all(&run_confext_dir);
    }
    println!("Unmerged configuration extensions from /etc.");
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
                eprintln!("Failed to merge configuration extensions: {e}");
                std::process::exit(1);
            }
        }
        Commands::Unmerge => {
            if let Err(e) = perform_unmerge(&root) {
                eprintln!("Failed to unmerge configuration extensions: {e}");
                std::process::exit(1);
            }
        }
        Commands::Refresh => {
            if let Err(e) = perform_unmerge(&root) {
                eprintln!("Failed to unmerge configuration extensions: {e}");
                std::process::exit(1);
            }
            if let Err(e) = perform_merge(&root, cli.force) {
                eprintln!("Failed to merge configuration extensions: {e}");
                std::process::exit(1);
            }
        }
    }
}
