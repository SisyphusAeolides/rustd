// SPDX-License-Identifier: LGPL-2.1-or-later
//! systemd-system-update-generator v261 compatibility generator.

use std::env;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

fn main() {
    if let Err(error) = run() {
        eprintln!("systemd-system-update-generator: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        return Err(String::from(
            "Generator expects normal, early, and late output directories.",
        ));
    }
    if in_initrd() {
        return Ok(());
    }
    if !offline_update_requested() {
        return Ok(());
    }

    let early = Path::new(&args[2]);
    fs::create_dir_all(early)
        .map_err(|error| format!("Failed to create {}: {error}", early.display()))?;
    let link = early.join("default.target");
    match fs::symlink_metadata(&link) {
        Ok(_) => fs::remove_file(&link)
            .map_err(|error| format!("Failed to replace {}: {error}", link.display()))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("Failed to inspect {}: {error}", link.display())),
    }
    symlink("/usr/lib/systemd/system/system-update.target", &link)
        .map_err(|error| format!("Failed to create symlink {}: {error}", link.display()))?;

    warn_for_cmdline_override();
    Ok(())
}

fn offline_update_requested() -> bool {
    ["/system-update", "/etc/system-update"]
        .iter()
        .any(|path| fs::symlink_metadata(path).is_ok())
}

fn warn_for_cmdline_override() {
    let path = env::var_os("RUSTD_PROC_CMDLINE")
        .map_or_else(|| PathBuf::from("/proc/cmdline"), PathBuf::from);
    let Ok(text) = fs::read_to_string(path) else {
        return;
    };
    for item in text.split_whitespace() {
        if item
            .strip_prefix("systemd.unit=")
            .is_some_and(|value| !value.is_empty())
        {
            eprintln!("systemd-system-update-generator: Offline system update overridden by kernel command line systemd.unit= setting");
        } else if runlevel_target(item).is_some() {
            eprintln!("systemd-system-update-generator: Offline system update overridden by runlevel '{item}' on the kernel command line");
        }
    }
}

fn runlevel_target(value: &str) -> Option<&'static str> {
    match value {
        "1" | "s" | "S" | "single" => Some("rescue.target"),
        "2" | "3" | "4" => Some("multi-user.target"),
        "5" => Some("graphical.target"),
        "6" => Some("reboot.target"),
        "emergency" | "-b" => Some("emergency.target"),
        _ => None,
    }
}

fn in_initrd() -> bool {
    env::var("SYSTEMD_IN_INITRD")
        .ok()
        .and_then(|value| parse_bool(&value))
        .unwrap_or_else(|| Path::new("/etc/initrd-release").exists())
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "yes" | "true" | "on" => Some(true),
        "0" | "no" | "false" | "off" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runlevel_detection_matches_debug_generator() {
        assert_eq!(runlevel_target("3"), Some("multi-user.target"));
        assert_eq!(runlevel_target("5"), Some("graphical.target"));
        assert_eq!(runlevel_target("not-a-runlevel"), None);
    }
}
