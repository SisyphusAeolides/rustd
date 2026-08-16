// SPDX-License-Identifier: LGPL-2.1-or-later
//! RustD boot-success generator.

use std::env;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

fn main() {
    if let Err(error) = run() {
        eprintln!("rustd-bless-boot-generator: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<_> = env::args_os().collect();
    let early = match args.len() {
        2 => PathBuf::from(&args[1]),
        4 => PathBuf::from(&args[2]),
        _ => return Err("Expected one or three generator output directories.".into()),
    };

    if in_initrd()
        || in_container()
        || soft_rebooted()
        || !is_efi_boot()
        || !loader_boot_count_path_exists()?
    {
        return Ok(());
    }

    let directory = early.join("basic.target.wants");
    fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
    let link = directory.join("rustd-bless-boot.service");
    match fs::remove_file(&link) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }
    symlink("/usr/lib/rustd/units/rustd-bless-boot.service", link)
        .map_err(|error| error.to_string())
}

fn in_initrd() -> bool {
    Path::new("/etc/initrd-release").exists()
        || env::var_os("RUSTD_IN_INITRD").as_deref() == Some(std::ffi::OsStr::new("1"))
}

fn in_container() -> bool {
    env::var_os("container").is_some()
        || Path::new("/run/rustd/container").exists()
        || env::var_os("RUSTD_CONTAINER").is_some()
}

fn soft_rebooted() -> bool {
    env::var("RUSTD_SOFT_REBOOTS_COUNT")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|value| value > 0)
}

fn efi_variables_directory() -> PathBuf {
    env::var_os("RUSTD_EFIVARS")
        .map_or_else(|| PathBuf::from("/sys/firmware/efi/efivars"), PathBuf::from)
}

fn is_efi_boot() -> bool {
    efi_variables_directory().is_dir()
}

fn loader_boot_count_path_exists() -> Result<bool, String> {
    let entries = fs::read_dir(efi_variables_directory()).map_err(|error| error.to_string())?;
    Ok(entries.flatten().any(|entry| {
        entry
            .file_name()
            .to_string_lossy()
            .starts_with("RustDBootCountPath-")
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn soft_reboot_default_false() {
        if env::var_os("RUSTD_SOFT_REBOOTS_COUNT").is_none() {
            assert!(!soft_rebooted());
        }
    }
}
