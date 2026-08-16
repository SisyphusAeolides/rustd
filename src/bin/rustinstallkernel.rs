// SPDX-License-Identifier: LGPL-2.1-or-later
//! `installkernel` compatibility utility.
//!
//! Legacy kernel installation bridge invoked by Linux kernel `make install`.
//! Upstream reference: systemd `src/kernel-install/installkernel`.

use clap::Parser;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{exit, Command};

const VERSION_STR: &str = "systemd 261 (rustd 0.1.0)";

#[derive(Parser, Debug)]
#[command(
    name = "installkernel",
    version = VERSION_STR,
    about = "Legacy Linux kernel installer bridge for 'make install'",
    long_about = "Installs a new kernel binary and System.map into /boot or delegates to kernel-install"
)]
struct Cli {
    /// Kernel release version (e.g. 6.8.0-rc1)
    #[arg(value_name = "VERSION")]
    kernel_version: String,

    /// Path to the kernel image binary (e.g. arch/x86/boot/bzImage or vmlinux)
    vmlinux: PathBuf,

    /// Path to the System.map file
    system_map: PathBuf,

    /// Optional target installation directory (defaults to /boot)
    #[arg(default_value = "/boot")]
    install_dir: PathBuf,

    /// Do not delegate to kernel-install even if available
    #[arg(long)]
    no_kernel_install: bool,

    /// Print verbose progress messages
    #[arg(short = 'v', long)]
    verbose: bool,
}

fn find_kernel_install_executable() -> Option<PathBuf> {
    let candidates = [
        "kernel-install",
        "rustkernel-install",
        "/usr/bin/kernel-install",
        "/bin/kernel-install",
        "/usr/local/bin/kernel-install",
    ];

    for candidate in candidates {
        let p = Path::new(candidate);
        if p.is_absolute() && p.exists() {
            return Some(p.to_path_buf());
        }
        if let Ok(path_var) = std::env::var("PATH") {
            for dir in std::env::split_paths(&path_var) {
                let full = dir.join(candidate);
                if full.is_file() {
                    return Some(full);
                }
            }
        }
    }
    None
}

fn run_postinst_hooks(version: &str, kernel_path: &Path, verbose: bool) {
    let hook_dir = Path::new("/etc/kernel/postinst.d");
    if !hook_dir.exists() || !hook_dir.is_dir() {
        return;
    }

    if let Ok(entries) = fs::read_dir(hook_dir) {
        let mut hooks: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .collect();
        hooks.sort();

        for hook in hooks {
            if verbose {
                println!("Running postinst hook: {}", hook.display());
            }
            let mut cmd = Command::new(&hook);
            cmd.arg(version).arg(kernel_path.as_os_str());
            let _ = cmd.status();
        }
    }
}

fn backup_existing_file(target: &Path, backup: &Path, verbose: bool) {
    if target.exists() {
        if verbose {
            println!("Backing up {} -> {}", target.display(), backup.display());
        }
        let _ = fs::copy(target, backup);
    }
}

fn make_symlink(src: &str, dst: &Path, verbose: bool) {
    let _ = fs::remove_file(dst);
    #[cfg(unix)]
    {
        if verbose {
            println!("Creating symlink {} -> {}", dst.display(), src);
        }
        let _ = std::os::unix::fs::symlink(src, dst);
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if !cli.vmlinux.exists() {
        eprintln!(
            "Error: Kernel binary '{}' does not exist.",
            cli.vmlinux.display()
        );
        exit(1);
    }
    if !cli.system_map.exists() {
        eprintln!(
            "Error: System.map '{}' does not exist.",
            cli.system_map.display()
        );
        exit(1);
    }

    // Attempt delegating to kernel-install if not forbidden
    if !cli.no_kernel_install {
        if let Some(ki) = find_kernel_install_executable() {
            if cli.verbose {
                println!(
                    "Delegating to kernel-install ({}) add {} {}",
                    ki.display(),
                    cli.kernel_version,
                    cli.vmlinux.display()
                );
            }
            let status = Command::new(&ki)
                .arg("add")
                .arg(&cli.kernel_version)
                .arg(&cli.vmlinux)
                .status();

            if let Ok(st) = status {
                if st.success() {
                    println!(
                        "Kernel {} successfully installed via kernel-install.",
                        cli.kernel_version
                    );
                    return Ok(());
                } else if cli.verbose {
                    eprintln!("kernel-install exited with failure status; falling back to direct boot copy.");
                }
            }
        }
    }

    // Direct /boot installation fallback
    let install_dir = &cli.install_dir;
    fs::create_dir_all(install_dir)?;

    let target_vmlinuz = install_dir.join(format!("vmlinuz-{}", cli.kernel_version));
    let target_map = install_dir.join(format!("System.map-{}", cli.kernel_version));
    let backup_vmlinuz = install_dir.join("vmlinuz.old");
    let backup_map = install_dir.join("System.map.old");

    backup_existing_file(&target_vmlinuz, &backup_vmlinuz, cli.verbose);
    backup_existing_file(&target_map, &backup_map, cli.verbose);

    if cli.verbose {
        println!(
            "Installing {} -> {}",
            cli.vmlinux.display(),
            target_vmlinuz.display()
        );
    }
    fs::copy(&cli.vmlinux, &target_vmlinuz)?;

    if cli.verbose {
        println!(
            "Installing {} -> {}",
            cli.system_map.display(),
            target_map.display()
        );
    }
    fs::copy(&cli.system_map, &target_map)?;

    // Check if .config exists
    let config_candidates = [
        cli.vmlinux.parent().map(|p| p.join(".config")),
        cli.vmlinux.parent().map(|p| p.join("config")),
        Some(PathBuf::from(".config")),
    ];
    for cand in config_candidates.into_iter().flatten() {
        if cand.exists() && cand.is_file() {
            let target_config = install_dir.join(format!("config-{}", cli.kernel_version));
            if cli.verbose {
                println!(
                    "Installing {} -> {}",
                    cand.display(),
                    target_config.display()
                );
            }
            let _ = fs::copy(&cand, &target_config);
            break;
        }
    }

    // Update standard symlinks
    make_symlink(
        &format!("vmlinuz-{}", cli.kernel_version),
        &install_dir.join("vmlinuz"),
        cli.verbose,
    );
    make_symlink(
        &format!("System.map-{}", cli.kernel_version),
        &install_dir.join("System.map"),
        cli.verbose,
    );

    // Run postinst hooks
    run_postinst_hooks(&cli.kernel_version, &target_vmlinuz, cli.verbose);

    println!(
        "Kernel {} and System.map installed to {}",
        cli.kernel_version,
        install_dir.display()
    );

    Ok(())
}
