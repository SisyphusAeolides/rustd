// SPDX-License-Identifier: LGPL-2.1-or-later
//! `systemd-sysinstall` compatibility utility.
//!
//! System deployment and provisioning tool.
//! Upstream reference: systemd system installation and image provisioning specs.

use clap::Parser;
use serde::Serialize;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::exit;

const VERSION_STR: &str = "systemd 261 (rustd 0.1.0)";

#[derive(Parser, Debug)]
#[command(
    name = "systemd-sysinstall",
    version = VERSION_STR,
    about = "System deployment and OS root provisioning utility",
    long_about = "Prepares and deploys an operating system directory tree or disk image destination"
)]
struct Cli {
    /// Source directory or image to install from
    #[arg(value_name = "SOURCE")]
    source_arg: Option<PathBuf>,

    /// Destination root directory to install into
    #[arg(value_name = "DESTINATION")]
    dest_arg: Option<PathBuf>,

    /// Source tree / directory to install from
    #[arg(short = 's', long, value_name = "PATH")]
    source: Option<PathBuf>,

    /// Target destination root directory
    #[arg(short = 't', long, value_name = "PATH")]
    target: Option<PathBuf>,

    /// Override target root directory
    #[arg(long, value_name = "PATH")]
    root: Option<PathBuf>,

    /// Operate on the specified disk image
    #[arg(long, value_name = "PATH")]
    image: Option<PathBuf>,

    /// Simulate installation without making permanent changes
    #[arg(long)]
    dry_run: bool,

    /// Clean destination target before installing
    #[arg(long)]
    clean: bool,

    /// Set hostname in the installed target
    #[arg(long, value_name = "NAME")]
    hostname: Option<String>,

    /// Set machine ID in the installed target
    #[arg(long, value_name = "ID")]
    machine_id: Option<String>,

    /// Output inspection data in JSON (takes one of pretty, short, off)
    #[arg(long, value_name = "MODE", default_value = "off")]
    json: String,

    /// Equivalent to --json=pretty
    #[arg(short = 'j', long = "json-pretty")]
    json_pretty: bool,

    /// Enable verbose progress logging
    #[arg(short = 'v', long)]
    verbose: bool,
}

#[derive(Serialize, Debug)]
struct InstallReport {
    source: Option<String>,
    target: String,
    dry_run: bool,
    directories_created: usize,
    files_copied: usize,
    machine_id: String,
    hostname: Option<String>,
    status: String,
}

fn generate_random_machine_id() -> String {
    let mut buf = [0u8; 16];
    if let Ok(mut f) = File::open("/dev/urandom") {
        let _ = f.read_exact(&mut buf);
    } else {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(987_654_321, |d| d.as_nanos());
        buf.copy_from_slice(&now.to_le_bytes());
    }
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

fn copy_tree_recursive(
    src: &Path,
    dst: &Path,
    dry_run: bool,
    verbose: bool,
    dir_count: &mut usize,
    file_count: &mut usize,
) -> io::Result<()> {
    if !dry_run {
        fs::create_dir_all(dst)?;
    }
    *dir_count += 1;

    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let entry_path = entry.path();
        let file_name = entry.file_name();
        let target_item = dst.join(file_name);

        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            copy_tree_recursive(
                &entry_path,
                &target_item,
                dry_run,
                verbose,
                dir_count,
                file_count,
            )?;
        } else if file_type.is_symlink() {
            if verbose {
                println!(
                    "Symlink: {} -> {}",
                    entry_path.display(),
                    target_item.display()
                );
            }
            if !dry_run {
                #[cfg(unix)]
                if let Ok(link_target) = fs::read_link(&entry_path) {
                    let _ = fs::remove_file(&target_item);
                    let _ = std::os::unix::fs::symlink(link_target, &target_item);
                }
            }
            *file_count += 1;
        } else {
            if verbose {
                println!(
                    "Copying: {} -> {}",
                    entry_path.display(),
                    target_item.display()
                );
            }
            if !dry_run {
                fs::copy(&entry_path, &target_item)?;
            }
            *file_count += 1;
        }
    }
    Ok(())
}

fn create_essential_directories(
    target: &Path,
    dry_run: bool,
    verbose: bool,
    dir_count: &mut usize,
) -> io::Result<()> {
    let dirs = [
        ("usr", 0o755),
        ("usr/bin", 0o755),
        ("usr/lib", 0o755),
        ("usr/share", 0o755),
        ("usr/local", 0o755),
        ("etc", 0o755),
        ("var", 0o755),
        ("var/log", 0o755),
        ("var/lib", 0o755),
        ("var/tmp", 0o1777),
        ("root", 0o700),
        ("home", 0o755),
        ("tmp", 0o1777),
        ("run", 0o755),
        ("proc", 0o555),
        ("sys", 0o555),
        ("dev", 0o755),
        ("boot", 0o755),
        ("efi", 0o755),
    ];

    for (d, mode) in dirs {
        let p = target.join(d);
        if verbose {
            println!(
                "Creating layout directory: {} (mode: {:o})",
                p.display(),
                mode
            );
        }
        if !dry_run {
            fs::create_dir_all(&p)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&p, fs::Permissions::from_mode(mode));
            }
        }
        *dir_count += 1;
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Resolve target path
    let target_path = cli
        .target
        .or(cli.root)
        .or(cli.dest_arg)
        .unwrap_or_else(|| PathBuf::from("/"));

    // Resolve source path
    let source_path = cli.source.or(cli.source_arg);

    let mut dir_count = 0;
    let mut file_count = 0;

    if cli.verbose {
        println!("Target deployment root: {}", target_path.display());
        if let Some(ref s) = source_path {
            println!("Source tree: {}", s.display());
        }
        if cli.dry_run {
            println!("Dry-run mode enabled: no changes will be written to disk.");
        }
    }

    if cli.clean && !cli.dry_run && target_path.exists() && target_path != Path::new("/") {
        if cli.verbose {
            println!("Cleaning target directory: {}", target_path.display());
        }
        let _ = fs::remove_dir_all(&target_path);
    }

    // 1. Create standard root filesystem layout
    create_essential_directories(&target_path, cli.dry_run, cli.verbose, &mut dir_count)?;

    // 2. If source tree specified, copy files
    if let Some(ref src) = source_path {
        if !src.exists() {
            eprintln!("Error: Source path '{}' does not exist.", src.display());
            exit(1);
        }
        copy_tree_recursive(
            src,
            &target_path,
            cli.dry_run,
            cli.verbose,
            &mut dir_count,
            &mut file_count,
        )?;
    }

    // 3. Initialize Machine ID
    let machine_id = cli.machine_id.unwrap_or_else(generate_random_machine_id);
    let machine_id_file = target_path.join("etc").join("machine-id");
    if !cli.dry_run {
        if let Some(parent) = machine_id_file.parent() {
            fs::create_dir_all(parent)?;
        }
        if !machine_id_file.exists() {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&machine_id_file)?;
            writeln!(f, "{machine_id}")?;
            file_count += 1;
        }
    }

    // 4. Initialize Hostname
    if let Some(ref h) = cli.hostname {
        let hostname_file = target_path.join("etc").join("hostname");
        if !cli.dry_run {
            if let Some(parent) = hostname_file.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&hostname_file)?;
            writeln!(f, "{}", h.trim())?;
            file_count += 1;
        }
    }

    // 5. Initialize basic os-release if missing
    let os_release_file = target_path.join("usr").join("lib").join("os-release");
    if !cli.dry_run && !os_release_file.exists() {
        if let Some(parent) = os_release_file.parent() {
            fs::create_dir_all(parent)?;
        }
        let content = "NAME=Linux\nID=linux\nPRETTY_NAME=\"Linux\"\n";
        let _ = fs::write(&os_release_file, content);
        let etc_os_release = target_path.join("etc").join("os-release");
        #[cfg(unix)]
        {
            let _ = std::os::unix::fs::symlink("../usr/lib/os-release", etc_os_release);
        }
    }

    let report = InstallReport {
        source: source_path.map(|p| p.display().to_string()),
        target: target_path.display().to_string(),
        dry_run: cli.dry_run,
        directories_created: dir_count,
        files_copied: file_count,
        machine_id,
        hostname: cli.hostname,
        status: "SUCCESS".to_string(),
    };

    let json_mode = if cli.json_pretty || cli.json == "pretty" {
        "pretty"
    } else if cli.json == "short" {
        "short"
    } else {
        "off"
    };

    match json_mode {
        "pretty" => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        "short" => {
            println!("{}", serde_json::to_string(&report)?);
        }
        _ => {
            println!("System deployment completed successfully.");
            println!("  Target Root:          {}", report.target);
            println!("  Directories Created:  {}", report.directories_created);
            println!("  Files Deployed:       {}", report.files_copied);
            println!("  Machine ID:           {}", report.machine_id);
            if let Some(h) = report.hostname {
                println!("  Hostname:             {h}");
            }
        }
    }

    Ok(())
}
