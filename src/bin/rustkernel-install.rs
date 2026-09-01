// SPDX-License-Identifier: LGPL-2.1-or-later
//! `kernel-install` compatibility utility.
//!
//! Upstream reference: systemd v261 `src/kernel-install/kernel-install.c`.

use clap::{Parser, Subcommand};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{exit, Command};

const VERSION_STR: &str = "systemd 261 (rustd 0.1.0)";

#[derive(Parser, Debug)]
#[command(
    name = "kernel-install",
    version = VERSION_STR,
    about = "Add, inspect, and remove kernel and initramfs images to and from the ESP/BOOT partition",
    long_about = None
)]
struct Cli {
    /// Override the path to the EFI System Partition (ESP)
    #[arg(long, value_name = "PATH")]
    esp_path: Option<PathBuf>,

    /// Override the path to the Boot Loader Partition ($BOOT)
    #[arg(long, value_name = "PATH")]
    boot_path: Option<PathBuf>,

    /// Override the path to the root directory
    #[arg(long, value_name = "PATH")]
    root: Option<PathBuf>,

    /// Entry token type or value (machine-id, os-id, literal:STRING, etc.)
    #[arg(long, value_name = "TOKEN")]
    entry_token: Option<String>,

    /// Print additional debugging information
    #[arg(short = 'v', long)]
    verbose: bool,

    /// Do not show headers and footers
    #[arg(long)]
    no_legend: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Add kernel and initrd images and generate BLS configuration entry
    Add {
        /// Kernel version string (e.g. 6.8.0-generic)
        kernel_version: String,
        /// Path to the kernel image file
        kernel_image: PathBuf,
        /// Additional initramfs / initrd image files
        #[arg(required = false)]
        initrd: Vec<PathBuf>,
    },
    /// Remove installed kernel, initramfs, and BLS entry for specified version
    Remove {
        /// Kernel version string to remove
        kernel_version: String,
    },
    /// Inspect installed kernel images and bootloader configuration
    Inspect {
        /// Optional specific kernel version to inspect
        kernel_version: Option<String>,
    },
    /// List all installed kernel versions and entries
    List,
}

struct InstallContext {
    boot_path: PathBuf,
    esp_path: PathBuf,
    entry_token: String,
    verbose: bool,
    root: Option<PathBuf>,
}

fn resolve_root_path(root: Option<&Path>, relative_path: &str) -> PathBuf {
    let clean = relative_path.trim_start_matches('/');
    if let Some(r) = root {
        r.join(clean)
    } else {
        PathBuf::from("/").join(clean)
    }
}

fn find_esp_path(cli_esp: Option<&PathBuf>, root: Option<&Path>) -> PathBuf {
    if let Some(p) = cli_esp {
        return p.clone();
    }
    if let Ok(env_esp) = std::env::var("ESP_PATH") {
        if !env_esp.is_empty() {
            return PathBuf::from(env_esp);
        }
    }
    let candidates = ["/efi", "/boot/efi", "/boot"];
    for cand in &candidates {
        let p = resolve_root_path(root, cand);
        if p.exists() && p.is_dir() && (p.join("EFI").exists() || p.join("loader").exists()) {
            return p;
        }
    }
    // Default fallback
    resolve_root_path(root, "/efi")
}

fn find_boot_path(cli_boot: Option<&PathBuf>, esp: &Path, root: Option<&Path>) -> PathBuf {
    if let Some(p) = cli_boot {
        return p.clone();
    }
    if let Ok(env_boot) = std::env::var("BOOT_PATH") {
        if !env_boot.is_empty() {
            return PathBuf::from(env_boot);
        }
    }
    let boot_dir = resolve_root_path(root, "/boot");
    // Linux kernel artifacts and BLS entries belong in /boot even when an
    // EFI system partition is mounted at /boot/efi. During the first kernel
    // transaction /boot/loader may not exist yet, so waiting for a marker
    // directory incorrectly selects the ESP as $BOOT and makes dracut write
    // versioned kernel files under /boot/efi.
    if boot_dir.exists() && boot_dir.is_dir() {
        return boot_dir;
    }
    if esp.exists() {
        return esp.to_path_buf();
    }
    boot_dir
}

fn resolve_entry_token(cli_token: Option<&str>, root: Option<&Path>) -> String {
    if let Some(token) = cli_token {
        if let Some(literal) = token.strip_prefix("literal:") {
            return literal.to_string();
        }
        if token == "os-id" {
            if let Some(id) = get_os_release_field("ID", root) {
                return id;
            }
        } else if token == "os-image-id" {
            if let Some(id) = get_os_release_field("IMAGE_ID", root) {
                return id;
            }
        } else if token != "machine-id" {
            return token.to_string();
        }
    }

    // Check /etc/kernel/entry-token
    let token_file = resolve_root_path(root, "/etc/kernel/entry-token");
    if let Ok(content) = fs::read_to_string(token_file) {
        let trimmed = content.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    // Check /etc/machine-id
    let machine_id_file = resolve_root_path(root, "/etc/machine-id");
    if let Ok(content) = fs::read_to_string(machine_id_file) {
        let trimmed = content.trim();
        if trimmed.len() >= 32 && !trimmed.starts_with("uninitialized") {
            return trimmed[..32].to_string();
        }
    }

    "default".to_string()
}

fn get_os_release_field(field: &str, root: Option<&Path>) -> Option<String> {
    let files = ["/etc/os-release", "/usr/lib/os-release"];
    let prefix = format!("{field}=");
    for file in &files {
        let path = resolve_root_path(root, file);
        if let Ok(content) = fs::read_to_string(&path) {
            for line in content.lines() {
                let trimmed = line.trim();
                if let Some(val) = trimmed.strip_prefix(&prefix) {
                    return Some(val.trim_matches('"').trim_matches('\'').to_string());
                }
            }
        }
    }
    None
}

fn get_kernel_cmdline(root: Option<&Path>) -> String {
    let files = ["/etc/kernel/cmdline", "/usr/lib/kernel/cmdline"];
    for file in &files {
        let path = resolve_root_path(root, file);
        if let Ok(content) = fs::read_to_string(&path) {
            let trimmed = content.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }

    // During an RPM transaction the target's /proc/cmdline may still be the
    // installer command line. Derive the installed root from fstab instead of
    // leaking installer or build-host arguments into the new boot entry.
    let mut options = read_grub_cmdline(root)
        .unwrap_or_default()
        .split_whitespace()
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if !options.iter().any(|option| option.starts_with("root=")) {
        if let Some(root_option) = read_fstab_root(root) {
            options.insert(0, root_option);
        }
    }
    if !options
        .iter()
        .any(|option| option == "ro" || option == "rw")
    {
        options.push("ro".to_string());
    }
    if options.is_empty() {
        "quiet ro".to_string()
    } else {
        options.join(" ")
    }
}

fn parse_assignment_value(line: &str, key: &str) -> Option<String> {
    let value = line.trim().strip_prefix(key)?.strip_prefix('=')?.trim();
    if value.len() >= 2 {
        let first = value.as_bytes()[0] as char;
        let last = value.as_bytes()[value.len() - 1] as char;
        if (first == '\'' || first == '"') && first == last {
            return Some(value[1..value.len() - 1].to_string());
        }
    }
    Some(value.to_string())
}

fn read_grub_cmdline(root: Option<&Path>) -> Option<String> {
    let path = resolve_root_path(root, "/etc/default/grub");
    let content = fs::read_to_string(path).ok()?;
    let mut options = Vec::new();
    for line in content.lines() {
        for key in ["GRUB_CMDLINE_LINUX", "GRUB_CMDLINE_LINUX_DEFAULT"] {
            if let Some(value) = parse_assignment_value(line, key) {
                if !value.is_empty() {
                    options.push(value);
                }
            }
        }
    }
    (!options.is_empty()).then(|| options.join(" "))
}

fn read_fstab_root(root: Option<&Path>) -> Option<String> {
    let path = resolve_root_path(root, "/etc/fstab");
    let content = fs::read_to_string(path).ok()?;
    for line in content.lines() {
        let line = line.split('#').next()?.trim();
        if line.is_empty() {
            continue;
        }
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() >= 2 && fields[1] == "/" && fields[0] != "none" {
            return Some(format!("root={}", fields[0]));
        }
    }
    None
}

fn run_plugin_hooks(
    action: &str,
    kernel_version: &str,
    entry_dir: &Path,
    kernel_image: Option<&Path>,
    initrds: &[PathBuf],
    root: Option<&Path>,
    verbose: bool,
) -> anyhow::Result<()> {
    let hook_dirs = [
        resolve_root_path(root, "/etc/kernel/install.d"),
        resolve_root_path(root, "/usr/lib/kernel/install.d"),
    ];

    let mut hooks: Vec<PathBuf> = Vec::new();
    for dir in &hook_dirs {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    hooks.push(path);
                }
            }
        }
    }

    hooks.sort_by(|a, b| {
        a.file_name()
            .unwrap_or_default()
            .cmp(b.file_name().unwrap_or_default())
    });

    for hook in hooks {
        if verbose {
            println!("Executing plugin: {}", hook.display());
        }
        let mut cmd = Command::new(&hook);
        cmd.arg(action)
            .arg(kernel_version)
            .arg(entry_dir.as_os_str());

        if let Some(img) = kernel_image {
            cmd.arg(img.as_os_str());
        }
        for initrd in initrds {
            cmd.arg(initrd.as_os_str());
        }

        match cmd.status() {
            Ok(status) => {
                if !status.success() {
                    anyhow::bail!(
                        "kernel-install plugin {} exited with code {:?}",
                        hook.display(),
                        status.code()
                    );
                }
            }
            Err(e) => {
                anyhow::bail!(
                    "failed to execute kernel-install plugin {}: {}",
                    hook.display(),
                    e
                );
            }
        }
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let root_path = cli.root.as_deref();
    let esp = find_esp_path(cli.esp_path.as_ref(), root_path);
    let boot = find_boot_path(cli.boot_path.as_ref(), &esp, root_path);
    let token = resolve_entry_token(cli.entry_token.as_deref(), root_path);

    let ctx = InstallContext {
        boot_path: boot,
        esp_path: esp,
        entry_token: token,
        verbose: cli.verbose,
        root: cli.root,
    };

    match &cli.command {
        Commands::Add {
            kernel_version,
            kernel_image,
            initrd,
        } => {
            cmd_add(&ctx, kernel_version, kernel_image, initrd)?;
        }
        Commands::Remove { kernel_version } => {
            cmd_remove(&ctx, kernel_version)?;
        }
        Commands::Inspect { kernel_version } => {
            cmd_inspect(&ctx, kernel_version.as_deref(), cli.no_legend)?;
        }
        Commands::List => {
            cmd_list(&ctx, cli.no_legend)?;
        }
    }

    Ok(())
}

fn cmd_add(
    ctx: &InstallContext,
    version: &str,
    kernel_image: &Path,
    initrds: &[PathBuf],
) -> anyhow::Result<()> {
    if !kernel_image.exists() {
        eprintln!(
            "Error: Kernel image '{}' does not exist.",
            kernel_image.display()
        );
        exit(1);
    }

    let entry_dir = ctx.boot_path.join(&ctx.entry_token).join(version);
    fs::create_dir_all(&entry_dir)?;

    let target_linux = entry_dir.join("linux");
    if ctx.verbose {
        println!(
            "Copying {} -> {}",
            kernel_image.display(),
            target_linux.display()
        );
    }
    fs::copy(kernel_image, &target_linux)?;

    let mut initrd_relative_paths: Vec<String> = Vec::new();
    for (idx, initrd_path) in initrds.iter().enumerate() {
        if !initrd_path.exists() {
            eprintln!(
                "Warning: Initrd image '{}' not found, skipping.",
                initrd_path.display()
            );
            continue;
        }
        let target_initrd_name = if initrds.len() == 1 {
            "initrd".to_string()
        } else {
            format!("initrd-{}", idx + 1)
        };
        let target_initrd = entry_dir.join(&target_initrd_name);
        if ctx.verbose {
            println!(
                "Copying {} -> {}",
                initrd_path.display(),
                target_initrd.display()
            );
        }
        fs::copy(initrd_path, &target_initrd)?;
        initrd_relative_paths.push(format!(
            "/{}/{}/{}",
            ctx.entry_token, version, target_initrd_name
        ));
    }

    // Generate BLS Type #1 entry
    let entries_dir = ctx.boot_path.join("loader").join("entries");
    fs::create_dir_all(&entries_dir)?;

    let entry_file = entries_dir.join(format!("{}-{}.conf", ctx.entry_token, version));
    let title = get_os_release_field("PRETTY_NAME", ctx.root.as_deref())
        .or_else(|| get_os_release_field("NAME", ctx.root.as_deref()))
        .unwrap_or_else(|| "Linux".to_string());
    let cmdline = get_kernel_cmdline(ctx.root.as_deref());

    let mut entry_content = String::new();
    entry_content.push_str(&format!("title      {title} ({version})\n"));
    entry_content.push_str(&format!("version    {version}\n"));
    entry_content.push_str(&format!("machine-id {}\n", ctx.entry_token));
    entry_content.push_str(&format!(
        "linux      /{}/{}/linux\n",
        ctx.entry_token, version
    ));
    for initrd_rel in &initrd_relative_paths {
        entry_content.push_str(&format!("initrd     {initrd_rel}\n"));
    }
    entry_content.push_str(&format!("options    {cmdline}\n"));

    if ctx.verbose {
        println!("Writing BLS entry to {}", entry_file.display());
    }
    fs::write(&entry_file, entry_content)?;

    // Run plugin hooks
    run_plugin_hooks(
        "add",
        version,
        &entry_dir,
        Some(kernel_image),
        initrds,
        ctx.root.as_deref(),
        ctx.verbose,
    )?;

    println!(
        "Kernel {} installed successfully to {}",
        version,
        entry_dir.display()
    );
    Ok(())
}

fn cmd_remove(ctx: &InstallContext, version: &str) -> anyhow::Result<()> {
    let entry_dir = ctx.boot_path.join(&ctx.entry_token).join(version);
    let entries_dir = ctx.boot_path.join("loader").join("entries");
    let entry_file = entries_dir.join(format!("{}-{}.conf", ctx.entry_token, version));

    let mut removed = false;
    if entry_file.exists() {
        if ctx.verbose {
            println!("Removing BLS config: {}", entry_file.display());
        }
        fs::remove_file(&entry_file)?;
        removed = true;
    }

    if entry_dir.exists() {
        if ctx.verbose {
            println!("Removing kernel directory: {}", entry_dir.display());
        }
        fs::remove_dir_all(&entry_dir)?;
        removed = true;
    }

    // Run plugin hooks
    run_plugin_hooks(
        "remove",
        version,
        &entry_dir,
        None,
        &[],
        ctx.root.as_deref(),
        ctx.verbose,
    )?;

    if removed {
        println!("Kernel {version} removed successfully.");
    } else {
        println!("No files found for kernel version {version}.");
    }
    Ok(())
}

fn cmd_inspect(
    ctx: &InstallContext,
    target_version: Option<&str>,
    no_legend: bool,
) -> anyhow::Result<()> {
    if !no_legend {
        println!("Kernel Installation Configuration:");
        println!("        ESP Path: {}", ctx.esp_path.display());
        println!("       BOOT Path: {}", ctx.boot_path.display());
        println!("     Entry Token: {}", ctx.entry_token);
        let os_name = get_os_release_field("PRETTY_NAME", ctx.root.as_deref())
            .unwrap_or_else(|| "Linux".to_string());
        println!("       OS Target: {os_name}");
        println!();
    }

    let entries_dir = ctx.boot_path.join("loader").join("entries");
    if !entries_dir.exists() {
        println!("No boot loader entries directory found.");
        return Ok(());
    }

    let mut count = 0;
    if let Ok(read_dir) = fs::read_dir(&entries_dir) {
        for entry in read_dir.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("conf") {
                if let Ok(content) = fs::read_to_string(&path) {
                    let mut version = String::new();
                    let mut title = String::new();
                    let mut linux = String::new();
                    let mut initrds = Vec::new();
                    let mut options = String::new();

                    for line in content.lines() {
                        let trimmed = line.trim();
                        if let Some(v) = trimmed.strip_prefix("version") {
                            version = v.trim().to_string();
                        } else if let Some(t) = trimmed.strip_prefix("title") {
                            title = t.trim().to_string();
                        } else if let Some(l) = trimmed.strip_prefix("linux") {
                            linux = l.trim().to_string();
                        } else if let Some(i) = trimmed.strip_prefix("initrd") {
                            initrds.push(i.trim().to_string());
                        } else if let Some(o) = trimmed.strip_prefix("options") {
                            options = o.trim().to_string();
                        }
                    }

                    if let Some(wanted) = target_version {
                        if version != wanted && !path.to_string_lossy().contains(wanted) {
                            continue;
                        }
                    }

                    count += 1;
                    println!(
                        "Entry: {}",
                        path.file_name().unwrap_or_default().to_string_lossy()
                    );
                    println!("       Title: {title}");
                    println!("     Version: {version}");
                    println!("       Linux: {linux}");
                    if !initrds.is_empty() {
                        println!("      Initrd: {}", initrds.join(", "));
                    }
                    if !options.is_empty() {
                        println!("     Options: {options}");
                    }
                    println!();
                }
            }
        }
    }

    if count == 0 {
        if let Some(v) = target_version {
            println!("No entry found for version '{v}'.");
        } else {
            println!("No boot loader entries installed.");
        }
    }

    Ok(())
}

fn cmd_list(ctx: &InstallContext, no_legend: bool) -> anyhow::Result<()> {
    let entries_dir = ctx.boot_path.join("loader").join("entries");
    let mut versions: Vec<(String, String)> = Vec::new();

    if entries_dir.exists() {
        if let Ok(read_dir) = fs::read_dir(&entries_dir) {
            for entry in read_dir.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("conf") {
                    if let Ok(content) = fs::read_to_string(&path) {
                        let mut version = String::new();
                        let mut title = String::new();
                        for line in content.lines() {
                            let trimmed = line.trim();
                            if let Some(v) = trimmed.strip_prefix("version") {
                                version = v.trim().to_string();
                            } else if let Some(t) = trimmed.strip_prefix("title") {
                                title = t.trim().to_string();
                            }
                        }
                        if !version.is_empty() {
                            versions.push((version, title));
                        }
                    }
                }
            }
        }
    }

    if versions.is_empty() {
        if !no_legend {
            println!("No installed kernels found.");
        }
        return Ok(());
    }

    if !no_legend {
        println!("{:<25} {:<40}", "KERNEL VERSION", "TITLE");
        println!("{:-<25} {:-<40}", "", "");
    }
    for (ver, title) in versions {
        println!("{ver:<25} {title:<40}");
    }

    Ok(())
}
