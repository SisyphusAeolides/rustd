// SPDX-License-Identifier: LGPL-2.1-or-later
//! `systemd-sysupdate` compatibility utility.
//!
//! Atomic updater for OS partitions, DDIs, UKIs, and sysexts.
//! Upstream reference: systemd v261 `src/sysupdate/sysupdate.c`.

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
    name = "systemd-sysupdate",
    version = VERSION_STR,
    about = "Atomic update tool for OS partitions, DDIs, and directory trees",
    long_about = "Discovers, checks, updates, and vacuums OS components based on sysupdate.d/*.conf definitions"
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

    /// Filter operations to a specific component
    #[arg(short = 'C', long, value_name = "NAME")]
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

    /// Verbose diagnostic messages
    #[arg(short = 'v', long)]
    verbose: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    /// List installed and available versions for all components
    List {
        /// Optional component name filter
        component: Option<String>,
    },
    /// Check if any updates are available (exits 0 if available, 1 if up-to-date)
    Check {
        /// Optional component name filter
        component: Option<String>,
    },
    /// Download/apply available updates
    Update {
        /// Optional component name filter
        component: Option<String>,
        /// Optional specific target version to install
        version: Option<String>,
    },
    /// Remove superseded and obsolete instances according to retention policy
    Vacuum {
        /// Optional component name filter
        component: Option<String>,
    },
    /// List pending/staged updates
    Pending {
        /// Optional component name filter
        component: Option<String>,
    },
    /// List all discovered component definitions
    Components,
}

#[derive(Debug, Clone, Default)]
struct TransferConfig {
    component_name: String,
    config_path: PathBuf,
    // [Transfer]
    protect_version: Option<String>,
    verify: bool,
    // [Source]
    source_type: String,
    source_path: String,
    source_match_pattern: String,
    // [Target]
    target_type: String,
    target_path: String,
    target_match_pattern: String,
    instances_max: usize,
    mode: u32,
}

#[derive(Serialize, Debug, Clone)]
struct ComponentStatus {
    component: String,
    target_path: String,
    current_version: Option<String>,
    available_version: Option<String>,
    installed_instances: Vec<String>,
    status: String,
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
    cfg.mode = 0o444;

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
                "transfer" => match key.as_str() {
                    "protectversion" => cfg.protect_version = Some(val),
                    "verify" => cfg.verify = val == "yes" || val == "true" || val == "1",
                    _ => {}
                },
                "source" => match key.as_str() {
                    "type" => cfg.source_type = val,
                    "path" => cfg.source_path = val,
                    "matchpattern" => cfg.source_match_pattern = val,
                    _ => {}
                },
                "target" => match key.as_str() {
                    "type" => cfg.target_type = val,
                    "path" => cfg.target_path = val,
                    "matchpattern" => cfg.target_match_pattern = val,
                    "instancesmax" => {
                        if let Ok(n) = val.parse::<usize>() {
                            cfg.instances_max = n;
                        }
                    }
                    "mode" => {
                        if let Ok(m) = u32::from_str_radix(val.trim_start_matches("0o"), 8) {
                            cfg.mode = m;
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

fn assess_component_status(cfg: &TransferConfig, root: Option<&Path>) -> ComponentStatus {
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

    let installed_instances: Vec<String> = installed.iter().map(|(v, _, _)| v.clone()).collect();

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
        (None, Some(_)) => "AVAILABLE_FOR_INSTALL".to_string(),
        (Some(_), None) => "UP_TO_DATE (NO_SOURCE)".to_string(),
        (None, None) => "NO_VERSIONS_FOUND".to_string(),
    };

    ComponentStatus {
        component: cfg.component_name.clone(),
        target_path: target_dir.display().to_string(),
        current_version: current_ver,
        available_version: newest_avail,
        installed_instances,
        status,
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let root = cli.root.as_deref();

    let configs = discover_configs(cli.definitions.as_deref(), root);

    let filter_comp = cli.component.as_deref();

    let matching_configs: Vec<&TransferConfig> = configs
        .iter()
        .filter(|c| {
            if let Some(fc) = filter_comp {
                c.component_name == fc
            } else {
                true
            }
        })
        .collect();

    let cmd = cli.command.clone().unwrap_or(Commands::List {
        component: filter_comp.map(std::string::ToString::to_string),
    });

    match cmd {
        Commands::List { component } => {
            cmd_list(&matching_configs, component.as_deref(), root, &cli)?;
        }
        Commands::Check { component } => {
            cmd_check(&matching_configs, component.as_deref(), root, &cli)?;
        }
        Commands::Update { component, version } => {
            cmd_update(
                &matching_configs,
                component.as_deref(),
                version.as_deref(),
                root,
                &cli,
            )?;
        }
        Commands::Vacuum { component } => {
            cmd_vacuum(&matching_configs, component.as_deref(), root, &cli)?;
        }
        Commands::Pending { component } => {
            cmd_pending(&matching_configs, component.as_deref(), root, &cli)?;
        }
        Commands::Components => {
            for cfg in &configs {
                println!("{:<20} {}", cfg.component_name, cfg.config_path.display());
            }
        }
    }

    Ok(())
}

fn cmd_list(
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
        statuses.push(assess_component_status(cfg, root));
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
            "{:<18} {:<16} {:<18} {:<24} PATH",
            "TARGET", "CURRENT VERSION", "AVAILABLE VERSION", "STATUS"
        );
        println!(
            "{:-<18} {:-<16} {:-<18} {:-<24} {:-<30}",
            "", "", "", "", ""
        );
    }

    if statuses.is_empty() {
        if !cli.no_legend {
            println!("No sysupdate component definitions found.");
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

fn cmd_check(
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
        let st = assess_component_status(cfg, root);
        if st.status == "UPDATE_AVAILABLE" || st.status == "AVAILABLE_FOR_INSTALL" {
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
        println!("System is up-to-date. No updates available.");
    }
    exit(1);
}

fn cmd_update(
    configs: &[&TransferConfig],
    filter: Option<&str>,
    target_version: Option<&str>,
    root: Option<&Path>,
    cli: &Cli,
) -> anyhow::Result<()> {
    let mut updated_count = 0;

    for cfg in configs {
        if let Some(f) = filter {
            if cfg.component_name != f {
                continue;
            }
        }

        let st = assess_component_status(cfg, root);
        let version_to_install = target_version
            .map(std::string::ToString::to_string)
            .or_else(|| st.available_version.clone());

        let ver = match version_to_install {
            Some(v) => v,
            None => {
                if cli.verbose {
                    println!("No version available for component {}.", cfg.component_name);
                }
                continue;
            }
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
            eprintln!("Error: Source image {} not found.", src_file.display());
            continue;
        }

        fs::create_dir_all(&target_dir)?;
        if cli.verbose {
            println!(
                "Deploying update {} -> {}",
                src_file.display(),
                dst_file.display()
            );
        }
        fs::copy(&src_file, &dst_file)?;

        println!(
            "Successfully updated {} to version {}.",
            cfg.component_name, ver
        );
        updated_count += 1;
    }

    if updated_count == 0 {
        println!("No updates were applied.");
    }

    Ok(())
}

fn cmd_vacuum(
    configs: &[&TransferConfig],
    filter: Option<&str>,
    root: Option<&Path>,
    cli: &Cli,
) -> anyhow::Result<()> {
    let mut removed_count = 0;

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
            // Remove oldest instances
            let to_remove = installed.len() - max_instances;
            for (ver, path, _) in installed.drain(..to_remove) {
                if cli.verbose {
                    println!("Vacuuming obsolete instance: {}", path.display());
                }
                if let Ok(()) = fs::remove_file(&path) {
                    println!("Removed old instance {} ({})", path.display(), ver);
                    removed_count += 1;
                }
            }
        }
    }

    if removed_count == 0 {
        println!("No obsolete instances found to vacuum.");
    }

    Ok(())
}

fn cmd_pending(
    configs: &[&TransferConfig],
    filter: Option<&str>,
    root: Option<&Path>,
    _cli: &Cli,
) -> anyhow::Result<()> {
    let mut pending_found = false;

    for cfg in configs {
        if let Some(f) = filter {
            if cfg.component_name != f {
                continue;
            }
        }
        let st = assess_component_status(cfg, root);
        if st.installed_instances.len() > 1 {
            println!(
                "Component {} has multiple installed instances ({:?}). Reboot may be pending.",
                st.component, st.installed_instances
            );
            pending_found = true;
        }
    }

    if !pending_found {
        println!("No pending updates awaiting activation.");
    }

    Ok(())
}
