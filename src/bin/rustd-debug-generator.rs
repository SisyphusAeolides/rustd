// SPDX-License-Identifier: LGPL-2.1-or-later
//! `RustD` boot debug generator.

use std::env;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

const DEFAULT_UNIT_ROOT: &str = "/usr/lib/rustd/system";

#[derive(Debug, Default)]
struct Config {
    default_unit: Option<String>,
    masks: Vec<String>,
    wants: Vec<String>,
    debug_shell: bool,
    debug_tty: Option<String>,
    default_debug_tty: Option<String>,
    breakpoints: Vec<&'static str>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("rustd-debug-generator: {error}");
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
    let early = Path::new(&args[2]);
    fs::create_dir_all(early)
        .map_err(|error| format!("Failed to create {}: {error}", early.display()))?;

    let initrd = in_initrd();
    let mut config = Config::default();
    parse_cmdline(&mut config, initrd);

    if config.debug_shell {
        config.wants.push(String::from("rustd-debug-shell.service"));
        install_debug_shell_dropin(early, &config)?;
    }
    for unit in &config.breakpoints {
        config.wants.push((*unit).to_owned());
    }

    process_credentials(early)?;
    generate_masks(early, &config.masks)?;
    generate_wants(early, &config, initrd)?;
    Ok(())
}

fn cmdline_path() -> PathBuf {
    env::var_os("RUSTD_PROC_CMDLINE").map_or_else(|| PathBuf::from("/proc/cmdline"), PathBuf::from)
}

fn parse_cmdline(config: &mut Config, initrd: bool) {
    let Ok(text) = fs::read_to_string(cmdline_path()) else {
        return;
    };
    for raw in text.split_whitespace() {
        let item = if initrd {
            raw.strip_prefix("rd.").unwrap_or(raw)
        } else {
            raw
        };
        let (key, value) = item
            .split_once('=')
            .map_or((item, None), |(key, value)| (key, Some(value)));
        match key {
            "rustd.mask" => {
                if let Some(value) = value.and_then(mangle_unit) {
                    config.masks.push(value);
                }
            }
            "rustd.wants" => {
                if let Some(value) = value.and_then(mangle_unit) {
                    config.wants.push(value);
                }
            }
            "rustd.debug_shell" => match value {
                None => config.debug_shell = true,
                Some(value) => match parse_bool(value) {
                    Some(enabled) => config.debug_shell = enabled,
                    None => {
                        config.debug_shell = true;
                        config.debug_tty = Some(strip_dev(value).to_owned());
                    }
                },
            },
            "rustd.default_debug_tty" => {
                if let Some(value) = value.filter(|value| !value.is_empty()) {
                    config.default_debug_tty = Some(strip_dev(value).to_owned());
                }
            }
            "rustd.unit" => {
                if let Some(value) = value.filter(|value| !value.is_empty()) {
                    config.default_unit = Some(value.to_owned());
                }
            }
            "rustd.break" => parse_breakpoints(config, value.unwrap_or(""), initrd),
            _ if value.is_none() => {
                if let Some(target) = runlevel_target(key) {
                    config.default_unit = Some(target.to_owned());
                }
            }
            _ => {}
        }
    }
}

fn parse_breakpoints(config: &mut Config, value: &str, initrd: bool) {
    if value.is_empty() {
        if initrd {
            push_unique(
                &mut config.breakpoints,
                "rustd-breakpoint-pre-switch-root.service",
            );
        }
        return;
    }
    for name in value.split(',') {
        let unit = match name {
            "pre-udev" => Some("rustd-breakpoint-pre-udev.service"),
            "pre-basic" => Some("rustd-breakpoint-pre-basic.service"),
            "pre-mount" if initrd => Some("rustd-breakpoint-pre-mount.service"),
            "pre-switch-root" if initrd => Some("rustd-breakpoint-pre-switch-root.service"),
            _ => None,
        };
        if let Some(unit) = unit {
            push_unique(&mut config.breakpoints, unit);
        } else {
            eprintln!(
                "rustd-debug-generator: Invalid or inapplicable breakpoint '{name}', ignoring."
            );
        }
    }
}

fn push_unique(values: &mut Vec<&'static str>, value: &'static str) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn generate_masks(dest: &Path, masks: &[String]) -> Result<(), String> {
    for unit in masks {
        let path = dest.join(unit);
        remove_existing(&path)?;
        symlink("/dev/null", &path).map_err(|error| {
            format!("Failed to create mask symlink {}: {error}", path.display())
        })?;
    }
    Ok(())
}

fn generate_wants(dest: &Path, config: &Config, initrd: bool) -> Result<(), String> {
    let target = config.default_unit.as_deref().unwrap_or(if initrd {
        "initrd.target"
    } else {
        "default.target"
    });
    let wants = dest.join(format!("{target}.wants"));
    if !config.wants.is_empty() {
        fs::create_dir_all(&wants)
            .map_err(|error| format!("Failed to create {}: {error}", wants.display()))?;
    }
    let unit_root = unit_root();
    for unit in &config.wants {
        let path = wants.join(unit);
        remove_existing(&path)?;
        let source = unit_root.join(unit);
        symlink(&source, &path).map_err(|error| {
            format!("Failed to create wants symlink {}: {error}", path.display())
        })?;
    }
    Ok(())
}

fn install_debug_shell_dropin(dest: &Path, config: &Config) -> Result<(), String> {
    let Some(tty) = config
        .debug_tty
        .as_deref()
        .or(config.default_debug_tty.as_deref())
    else {
        return Ok(());
    };
    if tty == strip_dev(default_debug_tty()) {
        return Ok(());
    }
    let directory = dest.join("rustd-debug-shell.service.d");
    fs::create_dir_all(&directory)
        .map_err(|error| format!("Failed to create {}: {error}", directory.display()))?;
    let path = directory.join("50-tty.conf");
    let text = format!(
        "# Automatically generated by rustd-debug-generator\n\n[Unit]\nDescription=Early RustD root shell on /dev/{tty} FOR DEBUGGING ONLY\nConditionPathExists=\n\n[Service]\nTTYPath=/dev/{tty}\n"
    );
    fs::write(&path, text).map_err(|error| format!("Failed to write {}: {error}", path.display()))
}

fn process_credentials(dest: &Path) -> Result<(), String> {
    for variable in [
        "RUSTD_CREDENTIALS_DIRECTORY",
        "RUSTD_ENCRYPTED_CREDENTIALS_DIRECTORY",
    ] {
        let Some(directory) = env::var_os(variable) else {
            continue;
        };
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(format!(
                    "Failed to enumerate {}: {error}",
                    PathBuf::from(directory).display()
                ));
            }
        };
        let mut entries: Vec<_> = entries.flatten().collect();
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if !kind.is_file() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            let Ok(text) = fs::read_to_string(entry.path()) else {
                continue;
            };
            if let Some(unit) = name.strip_prefix("rustd.extra-unit.") {
                if !valid_unit(unit) {
                    continue;
                }
                fs::write(dest.join(unit), text)
                    .map_err(|error| format!("Failed to write credential unit {unit}: {error}"))?;
            } else if let Some(spec) = name.strip_prefix("rustd.unit-dropin.") {
                let (unit, dropin) = spec
                    .split_once('~')
                    .map_or((spec, "50-credential"), |(unit, dropin)| (unit, dropin));
                if !valid_unit(unit) || dropin.is_empty() || dropin.contains('/') {
                    continue;
                }
                let directory = dest.join(format!("{unit}.d"));
                fs::create_dir_all(&directory).map_err(|error| {
                    format!("Failed to create {}: {error}", directory.display())
                })?;
                let name = if dropin.ends_with(".conf") {
                    dropin.to_owned()
                } else {
                    format!("{dropin}.conf")
                };
                fs::write(directory.join(name), text).map_err(|error| {
                    format!("Failed to write credential drop-in for {unit}: {error}")
                })?;
            }
        }
    }
    Ok(())
}

fn remove_existing(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(_) => fs::remove_file(path)
            .map_err(|error| format!("Failed to replace {}: {error}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("Failed to inspect {}: {error}", path.display())),
    }
}

fn mangle_unit(value: &str) -> Option<String> {
    if value.is_empty() || value.contains('/') {
        return None;
    }
    if valid_unit(value) {
        Some(value.to_owned())
    } else {
        Some(format!("{value}.service"))
    }
}

fn valid_unit(value: &str) -> bool {
    !value.is_empty()
        && !value.contains('/')
        && [
            ".service",
            ".socket",
            ".target",
            ".mount",
            ".automount",
            ".path",
            ".timer",
            ".slice",
            ".scope",
            ".swap",
            ".device",
        ]
        .iter()
        .any(|suffix| value.ends_with(suffix))
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "yes" | "true" | "on" => Some(true),
        "0" | "no" | "false" | "off" => Some(false),
        _ => None,
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

fn strip_dev(value: &str) -> &str {
    value.strip_prefix("/dev/").unwrap_or(value)
}

fn default_debug_tty() -> &'static str {
    "tty9"
}

fn unit_root() -> PathBuf {
    env::var_os("RUSTD_UNIT_ROOT").map_or_else(|| PathBuf::from(DEFAULT_UNIT_ROOT), PathBuf::from)
}

fn in_initrd() -> bool {
    env::var("RUSTD_IN_INITRD")
        .ok()
        .and_then(|value| parse_bool(&value))
        .unwrap_or_else(|| Path::new("/etc/initrd-release").exists())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_mangling_matches_generator_intent() {
        assert_eq!(mangle_unit("foo"), Some(String::from("foo.service")));
        assert_eq!(mangle_unit("foo.target"), Some(String::from("foo.target")));
        assert_eq!(mangle_unit("bad/name"), None);
    }

    #[test]
    fn runlevels_map_to_rustd_targets() {
        assert_eq!(runlevel_target("3"), Some("multi-user.target"));
        assert_eq!(runlevel_target("5"), Some("graphical.target"));
        assert_eq!(runlevel_target("single"), Some("rescue.target"));
    }

    #[test]
    fn breakpoint_rules_are_initrd_sensitive() {
        let mut host = Config::default();
        parse_breakpoints(&mut host, "pre-basic,pre-mount", false);
        assert_eq!(host.breakpoints, vec!["rustd-breakpoint-pre-basic.service"]);
        let mut initrd = Config::default();
        parse_breakpoints(&mut initrd, "", true);
        assert_eq!(
            initrd.breakpoints,
            vec!["rustd-breakpoint-pre-switch-root.service"]
        );
    }

    #[test]
    fn native_cmdline_controls_are_authoritative() {
        let mut config = Config::default();
        let path = std::env::temp_dir().join(format!(
            "rustd-debug-generator-cmdline-{}",
            std::process::id()
        ));
        fs::write(
            &path,
            "systemd.mask=legacy.service rustd.mask=native.service rustd.unit=rescue.target",
        )
        .unwrap();
        let previous = env::var_os("RUSTD_PROC_CMDLINE");
        env::set_var("RUSTD_PROC_CMDLINE", &path);
        parse_cmdline(&mut config, false);
        if let Some(value) = previous {
            env::set_var("RUSTD_PROC_CMDLINE", value);
        } else {
            env::remove_var("RUSTD_PROC_CMDLINE");
        }
        let _ = fs::remove_file(path);
        assert_eq!(config.masks, vec!["native.service"]);
        assert_eq!(config.default_unit.as_deref(), Some("rescue.target"));
    }

    #[test]
    fn default_unit_root_is_native() {
        assert_eq!(DEFAULT_UNIT_ROOT, "/usr/lib/rustd/system");
    }
}
