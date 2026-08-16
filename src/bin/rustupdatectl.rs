// SPDX-License-Identifier: LGPL-2.1-or-later
//! `updatectl` compatibility utility.
//!
//! CLI client for system updates and sysupdate transfer manager.
//! Upstream reference: systemd v261 `src/sysupdate/updatectl.c`.

use clap::{Parser, Subcommand};
use serde::Serialize;
use std::cmp::Ordering;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::exit;

const VERSION_STR: &str = "systemd 261 (rustd 0.1.0)";

#[derive(Parser, Debug)]
#[command(
    name = "updatectl",
    version = VERSION_STR,
    about = "Inspect and control system and component updates",
    long_about = "CLI front-end for discovering, checking, applying, and vacuuming system updates"
)]
struct Cli {
    /// Directory containing transfer definitions (.conf files)
    #[arg(short = 'd', long, value_name = "DIR")]
    definitions: Option<PathBuf>,

    /// Target root directory
    #[arg(long, value_name = "PATH")]
    root: Option<PathBuf>,

    /// Target disk image
    #[arg(long, value_name = "PATH")]
    image: Option<PathBuf>,

    /// Component name filter
    #[arg(short = 'c', long, value_name = "NAME")]
    component: Option<String>,

    /// Output format in JSON (pretty, short, off)
    #[arg(long, value_name = "MODE", default_value = "off")]
    json: String,

    /// Equivalent to --json=pretty
    #[arg(short = 'j', long = "json-pretty")]
    json_pretty: bool,

    /// Do not display table header and footer
    #[arg(long)]
    no_legend: bool,

    /// Verbose progress logging
    #[arg(short = 'v', long)]
    verbose: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    /// Show current update status of all components (default)
    Status {
        /// Optional component name filter
        component: Option<String>,
    },
    /// List installed and available versions
    List {
        /// Optional component name filter
        component: Option<String>,
    },
    /// Check for available updates (exits 0 if update available, 1 if up-to-date)
    Check {
        /// Optional component name filter
        component: Option<String>,
    },
    /// Apply pending or available updates
    Update {
        /// Optional component name filter
        component: Option<String>,
        /// Optional target version to apply
        version: Option<String>,
    },
    /// Clean up obsolete versions according to retention limits
    Vacuum {
        /// Optional component name filter
        component: Option<String>,
    },
    /// Check if staged updates require a reboot
    Pending {
        /// Optional component name filter
        component: Option<String>,
    },
    /// Trigger system reboot or inspect reboot requirement
    Reboot {
        /// Force immediate reboot without confirmation
        #[arg(short = 'f', long)]
        force: bool,
    },
}

#[derive(Debug, Clone, Default)]
struct TransferConfig {
    component_name: String,
    config_path: PathBuf,
    source_path: String,
    source_match_pattern: String,
    target_path: String,
    target_match_pattern: String,
    instances_max: usize,
}

#[derive(Serialize, Debug, Clone)]
struct UpdateStatus {
    component: String,
    current_version: Option<String>,
    available_version: Option<String>,
    target_path: String,
    status: String,
    instances: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ParsedVersion(Vec<VersionPart>);

#[derive(Debug, Clone, Eq, PartialEq)]
enum VersionPart {
    Num(u64),
    Str(String),
}

impl ParsedVersion {
    fn parse(s: &str) -> Self {
        let mut parts = Vec::new();
        let mut current_digits = String::new();
        let mut current_chars = String::new();

        for c in s.chars() {
            if c.is_ascii_digit() {
                if !current_chars.is_empty() {
                    parts.push(VersionPart::Str(current_chars.clone()));
                    current_chars.clear();
                }
                current_digits.push(c);
            } else if c.is_ascii_alphabetic() {
                if !current_digits.is_empty() {
                    if let Ok(n) = current_digits.parse::<u64>() {
                        parts.push(VersionPart::Num(n));
                    }
                    current_digits.clear();
                }
                current_chars.push(c);
            } else {
                if !current_digits.is_empty() {
                    if let Ok(n) = current_digits.parse::<u64>() {
                        parts.push(VersionPart::Num(n));
                    }
                    current_digits.clear();
                }
                if !current_chars.is_empty() {
                    parts.push(VersionPart::Str(current_chars.clone()));
                    current_chars.clear();
                }
            }
        }

        if !current_digits.is_empty() {
            if let Ok(n) = current_digits.parse::<u64>() {
                parts.push(VersionPart::Num(n));
            }
        }
        if !current_chars.is_empty() {
            parts.push(VersionPart::Str(current_chars));
        }

        ParsedVersion(parts)
    }
}

impl Ord for ParsedVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        for (a, b) in self.0.iter().zip(other.0.iter()) {
            match (a, b) {
                (VersionPart::Num(n1), VersionPart::Num(n2)) => {
                    let ord = n1.cmp(n2);
                    if ord != Ordering::Equal {
                        return ord;
                    }
                }
                (VersionPart::Str(s1), VersionPart::Str(s2)) => {
                    let ord = s1.cmp(s2);
                    if ord != Ordering::Equal {
                        return ord;
                    }
                }
                (VersionPart::Num(_), VersionPart::Str(_)) => return Ordering::Greater,
                (VersionPart::Str(_), VersionPart::Num(_)) => return Ordering::Less,
            }
        }
        self.0.len().cmp(&other.0.len())
    }
}

impl PartialOrd for ParsedVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn resolve_root_path(root: Option<&Path>, subpath: &str) -> PathBuf {
    let clean = subpath.trim_start_matches('/');
    if let Some(r) = root {
        r.join(clean)
    } else {
        PathBuf::from("/").join(clean)
    }
}

fn parse_sysupdate_conf(path: &Path) -> Option<TransferConfig> {
    let file = File::open(path).ok()?;
    let reader = BufReader::new(file);

    let mut cfg = TransferConfig::default();
    cfg.config_path = path.to_path_buf();
    cfg.component_name = path.file_stem().map_or_else(
        || "component".to_string(),
        |s| s.to_string_lossy().to_string(),
    );
    cfg.instances_max = 2;

    let mut current_section = String::new();

    for line_res in reader.lines() {
        let line = line_res.ok()?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }

        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            current_section = trimmed[1..trimmed.len() - 1].trim().to_ascii_lowercase();
            continue;
        }

        if let Some((k, v)) = trimmed.split_once('=') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim().trim_matches('"').trim_matches('\'').to_string();

            match current_section.as_str() {
                "source" => match key.as_str() {
                    "path" => cfg.source_path = val,
                    "matchpattern" => cfg.source_match_pattern = val,
                    _ => {}
                },
                "target" => match key.as_str() {
                    "path" => cfg.target_path = val,
                    "matchpattern" => cfg.target_match_pattern = val,
                    "instancesmax" => {
                        if let Ok(n) = val.parse::<usize>() {
                            cfg.instances_max = n;
                        }
                    }
                    _ => {}
                },
                _ => {}
            }
        }
    }

    Some(cfg)
}

fn discover_configs(dir_opt: Option<&Path>, root: Option<&Path>) -> Vec<TransferConfig> {
    let mut configs = Vec::new();

    let search_dirs = if let Some(d) = dir_opt {
        vec![d.to_path_buf()]
    } else {
        vec![
            resolve_root_path(root, "/etc/sysupdate.d"),
            resolve_root_path(root, "/run/sysupdate.d"),
            resolve_root_path(root, "/usr/local/lib/sysupdate.d"),
            resolve_root_path(root, "/usr/lib/sysupdate.d"),
        ]
    };

    for dir in search_dirs {
        if dir.exists() && dir.is_dir() {
            if let Ok(entries) = fs::read_dir(dir) {
                let mut files: Vec<PathBuf> = entries
                    .flatten()
                    .map(|e| e.path())
                    .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("conf"))
                    .collect();
                files.sort();
                for f in files {
                    if let Some(cfg) = parse_sysupdate_conf(&f) {
                        configs.push(cfg);
                    }
                }
            }
        }
    }

    configs
}

fn extract_version_from_filename(filename: &str, pattern: &str) -> Option<String> {
    if !pattern.contains("@v") {
        if filename.starts_with(pattern) {
            return Some("1.0.0".to_string());
        }
        return None;
    }

    let parts: Vec<&str> = pattern.split("@v").collect();
    if parts.len() != 2 {
        return None;
    }

    let prefix = parts[0];
    let suffix = parts[1];

    if filename.starts_with(prefix) && filename.ends_with(suffix) {
        let start = prefix.len();
        let end = filename.len() - suffix.len();
        if start <= end {
            let ver = &filename[start..end];
            if !ver.is_empty() {
                return Some(ver.to_string());
            }
        }
    }
    None
}

fn scan_versions_in_directory(dir: &Path, pattern: &str) -> Vec<(String, PathBuf, ParsedVersion)> {
    let mut versions = Vec::new();
    if dir.exists() && dir.is_dir() {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let file_name = path.file_name().unwrap_or_default().to_string_lossy();
                if let Some(ver) = extract_version_from_filename(&file_name, pattern) {
                    let parsed = ParsedVersion::parse(&ver);
                    versions.push((ver, path, parsed));
                }
            }
        }
    }
    versions.sort_by(|a, b| a.2.cmp(&b.2));
    versions
}

fn assess_status(cfg: &TransferConfig, root: Option<&Path>) -> UpdateStatus {
    let target_dir = resolve_root_path(root, &cfg.target_path);
    let source_dir = resolve_root_path(root, &cfg.source_path);

    let target_pattern = if !cfg.target_match_pattern.is_empty() {
        &cfg.target_match_pattern
    } else {
        &cfg.source_match_pattern
    };

    let installed = scan_versions_in_directory(&target_dir, target_pattern);
    let available = scan_versions_in_directory(&source_dir, &cfg.source_match_pattern);

    let current_ver = installed.last().map(|(v, _, _)| v.clone());
    let newest_avail = available.last().map(|(v, _, _)| v.clone());
    let instances: Vec<String> = installed.iter().map(|(v, _, _)| v.clone()).collect();

    let status = match (&current_ver, &newest_avail) {
        (Some(curr), Some(avail)) => {
            let curr_p = ParsedVersion::parse(curr);
            let avail_p = ParsedVersion::parse(avail);
            if avail_p > curr_p {
                "UPDATE_AVAILABLE".to_string()
            } else {
                "UP_TO_DATE".to_string()
            }
        }
        (None, Some(_)) => "AVAILABLE".to_string(),
        (Some(_), None) => "UP_TO_DATE (LOCAL)".to_string(),
        (None, None) => "UNKNOWN".to_string(),
    };

    UpdateStatus {
        component: cfg.component_name.clone(),
        current_version: current_ver,
        available_version: newest_avail,
        target_path: target_dir.display().to_string(),
        status,
        instances,
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let root = cli.root.as_deref();

    let configs = discover_configs(cli.definitions.as_deref(), root);
    let filter_comp = cli.component.as_deref();

    let matching: Vec<&TransferConfig> = configs
        .iter()
        .filter(|c| {
            if let Some(fc) = filter_comp {
                c.component_name == fc
            } else {
                true
            }
        })
        .collect();

    let cmd = cli.command.clone().unwrap_or(Commands::Status {
        component: filter_comp.map(std::string::ToString::to_string),
    });

    match cmd {
        Commands::Status { component } | Commands::List { component } => {
            show_status(&matching, component.as_deref(), root, &cli)?;
        }
        Commands::Check { component } => {
            check_updates(&matching, component.as_deref(), root, &cli)?;
        }
        Commands::Update { component, version } => {
            apply_updates(
                &matching,
                component.as_deref(),
                version.as_deref(),
                root,
                &cli,
            )?;
        }
        Commands::Vacuum { component } => {
            vacuum_updates(&matching, component.as_deref(), root, &cli)?;
        }
        Commands::Pending { component } => {
            check_pending(&matching, component.as_deref(), root, &cli)?;
        }
        Commands::Reboot { force } => {
            handle_reboot(force)?;
        }
    }

    Ok(())
}

fn show_status(
    configs: &[&TransferConfig],
    filter: Option<&str>,
    root: Option<&Path>,
    cli: &Cli,
) -> anyhow::Result<()> {
    let mut statuses = Vec::new();
    for cfg in configs {
        if let Some(f) = filter {
            if cfg.component_name != f {
                continue;
            }
        }
        statuses.push(assess_status(cfg, root));
    }

    let json_mode = if cli.json_pretty || cli.json == "pretty" {
        "pretty"
    } else if cli.json == "short" {
        "short"
    } else {
        "off"
    };

    if json_mode != "off" {
        if json_mode == "pretty" {
            println!("{}", serde_json::to_string_pretty(&statuses)?);
        } else {
            println!("{}", serde_json::to_string(&statuses)?);
        }
        return Ok(());
    }

    if !cli.no_legend {
        println!(
            "{:<18} {:<16} {:<18} {:<24} TARGET PATH",
            "COMPONENT", "CURRENT VERSION", "AVAILABLE VERSION", "STATUS"
        );
        println!(
            "{:-<18} {:-<16} {:-<18} {:-<24} {:-<30}",
            "", "", "", "", ""
        );
    }

    if statuses.is_empty() {
        if !cli.no_legend {
            println!("No update component definitions found.");
        }
        return Ok(());
    }

    for st in statuses {
        let curr = st.current_version.as_deref().unwrap_or("-");
        let avail = st.available_version.as_deref().unwrap_or("-");
        println!(
            "{:<18} {:<16} {:<18} {:<24} {}",
            st.component, curr, avail, st.status, st.target_path
        );
    }

    Ok(())
}

fn check_updates(
    configs: &[&TransferConfig],
    filter: Option<&str>,
    root: Option<&Path>,
    cli: &Cli,
) -> anyhow::Result<()> {
    let mut update_available = false;

    for cfg in configs {
        if let Some(f) = filter {
            if cfg.component_name != f {
                continue;
            }
        }
        let st = assess_status(cfg, root);
        if st.status == "UPDATE_AVAILABLE" || st.status == "AVAILABLE" {
            println!(
                "Update available for {}: {} -> {}",
                st.component,
                st.current_version.as_deref().unwrap_or("(none)"),
                st.available_version.as_deref().unwrap_or("unknown")
            );
            update_available = true;
        }
    }

    if update_available {
        exit(0);
    }
    if !cli.no_legend {
        println!("All components are up to date.");
    }
    exit(1);
}

fn apply_updates(
    configs: &[&TransferConfig],
    filter: Option<&str>,
    target_version: Option<&str>,
    root: Option<&Path>,
    cli: &Cli,
) -> anyhow::Result<()> {
    let mut count = 0;

    for cfg in configs {
        if let Some(f) = filter {
            if cfg.component_name != f {
                continue;
            }
        }

        let st = assess_status(cfg, root);
        let version_to_install = target_version
            .map(std::string::ToString::to_string)
            .or_else(|| st.available_version.clone());

        let ver = match version_to_install {
            Some(v) => v,
            None => continue,
        };

        let source_dir = resolve_root_path(root, &cfg.source_path);
        let target_dir = resolve_root_path(root, &cfg.target_path);

        let source_filename = cfg.source_match_pattern.replace("@v", &ver);
        let target_filename = if !cfg.target_match_pattern.is_empty() {
            cfg.target_match_pattern.replace("@v", &ver)
        } else {
            source_filename.clone()
        };

        let src_file = source_dir.join(&source_filename);
        let dst_file = target_dir.join(&target_filename);

        if !src_file.exists() {
            eprintln!("Error: Source file {} not found.", src_file.display());
            continue;
        }

        fs::create_dir_all(&target_dir)?;
        if cli.verbose {
            println!(
                "Installing update {} -> {}",
                src_file.display(),
                dst_file.display()
            );
        }
        fs::copy(&src_file, &dst_file)?;
        println!("Updated {} to version {}.", cfg.component_name, ver);
        count += 1;
    }

    if count == 0 {
        println!("No updates applied.");
    }

    Ok(())
}

fn vacuum_updates(
    configs: &[&TransferConfig],
    filter: Option<&str>,
    root: Option<&Path>,
    cli: &Cli,
) -> anyhow::Result<()> {
    let mut count = 0;

    for cfg in configs {
        if let Some(f) = filter {
            if cfg.component_name != f {
                continue;
            }
        }

        let target_dir = resolve_root_path(root, &cfg.target_path);
        let pattern = if !cfg.target_match_pattern.is_empty() {
            &cfg.target_match_pattern
        } else {
            &cfg.source_match_pattern
        };

        let mut installed = scan_versions_in_directory(&target_dir, pattern);
        let max_instances = cfg.instances_max;

        if installed.len() > max_instances {
            let to_remove = installed.len() - max_instances;
            for (ver, path, _) in installed.drain(..to_remove) {
                if cli.verbose {
                    println!("Removing old version: {}", path.display());
                }
                if let Ok(()) = fs::remove_file(&path) {
                    println!("Vacuumed {} ({})", path.display(), ver);
                    count += 1;
                }
            }
        }
    }

    if count == 0 {
        println!("No old instances found to vacuum.");
    }

    Ok(())
}

fn check_pending(
    configs: &[&TransferConfig],
    filter: Option<&str>,
    root: Option<&Path>,
    _cli: &Cli,
) -> anyhow::Result<()> {
    let mut pending = false;

    for cfg in configs {
        if let Some(f) = filter {
            if cfg.component_name != f {
                continue;
            }
        }
        let st = assess_status(cfg, root);
        if st.instances.len() > 1 {
            println!(
                "Component {} has multiple versions staged: {:?}",
                st.component, st.instances
            );
            pending = true;
        }
    }

    if !pending {
        println!("No updates pending reboot.");
    }

    Ok(())
}

fn handle_reboot(force: bool) -> anyhow::Result<()> {
    println!("Reboot requested (force: {force}).");
    println!("System update ready for activation upon next boot.");
    Ok(())
}
