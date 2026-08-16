// SPDX-License-Identifier: LGPL-2.1-or-later
//! `RustD` backlight and LED state utility.

use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::exit;

const VERSION: &str = "RustD 0.1.0";

fn main() {
    if let Err(error) = run(env::args().skip(1).collect()) {
        eprintln!("rustd-backlight: {error}");
        exit(1);
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    if args.len() == 1 && (args[0] == "-h" || args[0] == "--help") {
        println!("rustd-backlight [load|save] DEVICE");
        return Ok(());
    }
    if args.len() == 1 && args[0] == "--version" {
        println!("{VERSION}");
        return Ok(());
    }
    if args.len() != 2 {
        return Err(String::from("Expected verb and device identifier."));
    }

    let (subsystem, device) = parse_device(&args[1])?;
    let sysfs_root =
        env::var_os("RUSTD_SYSFS_ROOT").map_or_else(|| PathBuf::from("/sys"), PathBuf::from);
    let state_root = env::var_os("RUSTD_BACKLIGHT_STATE_DIR")
        .map_or_else(|| PathBuf::from("/var/lib/rustd/backlight"), PathBuf::from);
    let device_dir = sysfs_root.join("class").join(subsystem).join(device);
    let state_path = state_root.join(format!("{subsystem}:{device}"));

    match args[0].as_str() {
        "save" => save(&device_dir, &state_path),
        "load" => load(&device_dir, &state_path),
        verb => Err(format!("Unknown verb '{verb}'.")),
    }
}

fn parse_device(value: &str) -> Result<(&str, &str), String> {
    let Some((subsystem, device)) = value.split_once(':') else {
        return Err(format!("Invalid device identifier '{value}'."));
    };
    if !matches!(subsystem, "backlight" | "leds") || device.is_empty() || device.contains('/') {
        return Err(format!("Invalid device identifier '{value}'."));
    }
    Ok((subsystem, device))
}

fn read_u64(path: &Path) -> Result<u64, String> {
    let value = fs::read_to_string(path)
        .map_err(|error| format!("Failed to read {}: {error}", path.display()))?;
    value
        .trim()
        .parse::<u64>()
        .map_err(|_| format!("Invalid numeric value in {}.", path.display()))
}

fn save(device_dir: &Path, state_path: &Path) -> Result<(), String> {
    let brightness = read_u64(&device_dir.join("brightness"))?;
    atomic_write(state_path, format!("{brightness}\n").as_bytes())
        .map_err(|error| format!("Failed to save {}: {error}", state_path.display()))
}

fn load(device_dir: &Path, state_path: &Path) -> Result<(), String> {
    let saved = match read_u64(state_path) {
        Ok(value) => value,
        Err(_) if !state_path.exists() => return Ok(()),
        Err(error) => return Err(error),
    };
    let maximum = read_u64(&device_dir.join("max_brightness"))?;
    let value = saved.min(maximum);
    fs::write(device_dir.join("brightness"), format!("{value}\n"))
        .map_err(|error| format!("Failed to restore brightness: {error}"))
}

fn atomic_write(path: &Path, data: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "state path has no parent"))?;
    fs::create_dir_all(parent)?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("state");
    let temporary = parent.join(format!(".{name}.tmp-{}", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(&temporary)?;
    file.write_all(data)?;
    file.sync_all()?;
    drop(file);
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_parser_accepts_supported_classes() {
        assert_eq!(
            parse_device("backlight:intel_backlight").unwrap(),
            ("backlight", "intel_backlight")
        );
        assert_eq!(
            parse_device("leds:kbd_backlight").unwrap(),
            ("leds", "kbd_backlight")
        );
        assert!(parse_device("input:event0").is_err());
        assert!(parse_device("backlight:../x").is_err());
    }
}
