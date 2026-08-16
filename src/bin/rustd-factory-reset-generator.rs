// SPDX-License-Identifier: LGPL-2.1-or-later
//! Factory-reset generator for RustD.

use serde_json::Value;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

const COMPLETE_MARKER: &str = "/run/rustd/factory-reset-complete";
const COMPAT_COMPLETE_MARKER: &str = "/run/systemd/factory-reset-complete";
const FACTORY_RESET_TARGET: &str = "/usr/lib/rustd/system/factory-reset-now.target";

fn main() {
    if let Err(error) = run() {
        eprintln!("rustd-factory-reset-generator: {error}");
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

    if !factory_reset_supported()?
        || Path::new(COMPLETE_MARKER).exists()
        || Path::new(COMPAT_COMPLETE_MARKER).exists()
    {
        return Ok(());
    }
    if !factory_reset_on()? {
        return Ok(());
    }

    let directory = early.join("basic.target.wants");
    fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
    replace_symlink(
        FACTORY_RESET_TARGET,
        &directory.join("factory-reset-now.target"),
    )
}

fn factory_reset_supported() -> Result<bool, String> {
    for name in [
        "RUSTD_FACTORY_RESET_SUPPORTED",
        "SYSTEMD_FACTORY_RESET_SUPPORTED",
    ] {
        match env::var(name) {
            Ok(value) => {
                return parse_bool(&value).ok_or_else(|| format!("Invalid {name}={value}"));
            }
            Err(env::VarError::NotPresent) => {}
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(true)
}

fn factory_reset_on() -> Result<bool, String> {
    if let Some(value) = cmdline_setting()? {
        return Ok(value);
    }
    efi_request_for_current_boot()
}

fn cmdline_setting() -> Result<Option<bool>, String> {
    let text = env::var("RUSTD_PROC_CMDLINE").ok().map_or_else(
        || fs::read_to_string("/proc/cmdline").unwrap_or_default(),
        |path| fs::read_to_string(path).unwrap_or_default(),
    );
    cmdline_setting_from_text(&text)
}

fn cmdline_setting_from_text(text: &str) -> Result<Option<bool>, String> {
    for prefix in ["rustd.factory_reset", "systemd.factory_reset"] {
        for token in text.split_whitespace().rev() {
            if token == prefix {
                return Ok(Some(true));
            }
            if let Some(value) = token
                .strip_prefix(prefix)
                .and_then(|rest| rest.strip_prefix('='))
            {
                return parse_bool(value)
                    .map(Some)
                    .ok_or_else(|| format!("Invalid {prefix}={value}"));
            }
        }
    }
    Ok(None)
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "yes" | "true" | "on" => Some(true),
        "0" | "no" | "false" | "off" => Some(false),
        _ => None,
    }
}

fn efi_request_for_current_boot() -> Result<bool, String> {
    let root = env::var_os("RUSTD_EFIVARS")
        .map_or_else(|| PathBuf::from("/sys/firmware/efi/efivars"), PathBuf::from);
    if !root.is_dir() {
        return Ok(false);
    }

    let request = fs::read_dir(&root)
        .map_err(|error| error.to_string())?
        .flatten()
        .find(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("FactoryResetRequest-")
        });
    let Some(entry) = request else {
        return Ok(false);
    };

    let bytes = fs::read(entry.path()).map_err(|error| error.to_string())?;
    if bytes.len() <= 4 {
        return Ok(false);
    }

    let text = decode_efi_string(&bytes[4..]);
    let Ok(json) = serde_json::from_str::<Value>(&text) else {
        return Ok(false);
    };
    let Some(request_id) = json.get("osReleaseId").and_then(Value::as_str) else {
        return Ok(false);
    };
    let request_image = json.get("osReleaseImageId").and_then(Value::as_str);
    let Some(request_boot) = json.get("bootId").and_then(Value::as_str) else {
        return Ok(false);
    };

    let os = read_os_release();
    if os.get("ID").map(String::as_str) != Some(request_id) {
        return Ok(false);
    }
    if request_image != os.get("IMAGE_ID").map(String::as_str) {
        return Ok(false);
    }

    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap_or_default();
    if normalize_id(request_boot) == normalize_id(boot.trim()) {
        return Ok(false);
    }
    Ok(true)
}

fn decode_efi_string(bytes: &[u8]) -> String {
    if bytes.len() >= 2 && bytes[1] == 0 {
        let words: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .take_while(|word| *word != 0)
            .collect();
        String::from_utf16_lossy(&words)
    } else {
        String::from_utf8_lossy(bytes)
            .trim_end_matches('\0')
            .to_owned()
    }
}

fn read_os_release() -> HashMap<String, String> {
    let override_path = env::var_os("RUSTD_OS_RELEASE").map(PathBuf::from);
    let text = override_path
        .and_then(|path| fs::read_to_string(path).ok())
        .or_else(|| fs::read_to_string("/etc/os-release").ok())
        .or_else(|| fs::read_to_string("/usr/lib/os-release").ok())
        .unwrap_or_default();

    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (key, value) = line.split_once('=')?;
            Some((key.to_owned(), value.trim_matches('"').to_owned()))
        })
        .collect()
}

fn normalize_id(value: &str) -> String {
    value
        .chars()
        .filter(char::is_ascii_hexdigit)
        .flat_map(char::to_lowercase)
        .collect()
}

fn replace_symlink(target: &str, path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }
    symlink(target, path).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_boolean_values() {
        assert_eq!(parse_bool("yes"), Some(true));
        assert_eq!(parse_bool("off"), Some(false));
        assert_eq!(parse_bool("x"), None);
    }

    #[test]
    fn normalizes_ids() {
        assert_eq!(normalize_id("aabb-CC"), "aabbcc");
    }

    #[test]
    fn native_cmdline_setting_has_priority_over_compatibility_setting() {
        assert_eq!(
            cmdline_setting_from_text("rustd.factory_reset=no systemd.factory_reset=yes").unwrap(),
            Some(false)
        );
    }

    #[test]
    fn compatibility_cmdline_setting_remains_accepted() {
        assert_eq!(
            cmdline_setting_from_text("quiet systemd.factory_reset=on").unwrap(),
            Some(true)
        );
    }
}
