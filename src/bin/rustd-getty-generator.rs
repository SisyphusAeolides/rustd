// SPDX-License-Identifier: LGPL-2.1-or-later
//! RustD getty generator.

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

const CREDENTIAL: u8 = 1;
const CONTAINER: u8 = 2;
const CONSOLE: u8 = 4;
const BUILTIN: u8 = 8;
const ALL: u8 = CREDENTIAL | CONTAINER | CONSOLE | BUILTIN;
const UNIT_ROOT: &str = "/usr/lib/rustd/system";

fn main() {
    if let Err(error) = run() {
        eprintln!("rustd-getty-generator: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<_> = env::args_os().collect();
    let dest = match args.len() {
        2 | 4 => PathBuf::from(&args[1]),
        _ => return Err("Expected one or three generator output directories.".into()),
    };
    if in_initrd() {
        return Ok(());
    }

    let mut sources = ALL;
    if let Some(value) = cmdline_value("rustd.getty_auto") {
        if let Some(parsed) = parse_sources(&value) {
            sources = parsed;
        }
    }
    if let Ok(value) = env::var("RUSTD_GETTY_AUTO") {
        if let Some(parsed) = parse_sources(&value) {
            sources = parsed;
        }
    }
    if let Some(value) = read_credential("getty.auto") {
        if let Some(parsed) = parse_sources(value.trim()) {
            sources = parsed;
        }
    }
    if sources == 0 {
        return Ok(());
    }
    fs::create_dir_all(&dest).map_err(|error| error.to_string())?;

    if sources & CREDENTIAL != 0 {
        for tty in credential_lines("getty.ttys.serial") {
            add_serial(&dest, &tty)?;
        }
        for tty in credential_lines("getty.ttys.container") {
            add_container(&dest, &tty)?;
        }
    }

    if is_container() {
        if sources & CONTAINER != 0 {
            add_want(
                &dest,
                "console-getty.service",
                &format!("{UNIT_ROOT}/console-getty.service"),
            )?;
            if let Ok(value) = env::var("container_ttys") {
                for tty in value
                    .split_whitespace()
                    .filter(|value| value.starts_with("/dev/pts/"))
                {
                    add_container(&dest, tty)?;
                }
            }
        }
        return Ok(());
    }

    if sources & CONSOLE != 0 {
        for tty in kernel_consoles() {
            if !is_vc(&tty) && Path::new(&tty).exists() {
                add_serial(&dest, &tty)?;
            }
        }
    }
    if sources & BUILTIN != 0 {
        for tty in [
            "hvc0",
            "xvc0",
            "hvsi0",
            "sclp_line0",
            "ttysclp0",
            "3270/tty1",
        ] {
            if Path::new("/dev").join(tty).exists() {
                add_serial(&dest, tty)?;
            }
        }
    }
    Ok(())
}

fn parse_sources(value: &str) -> Option<u8> {
    let value = value.trim();
    if value.is_empty() {
        return Some(ALL);
    }
    match value.to_ascii_lowercase().as_str() {
        "1" | "yes" | "true" | "on" => return Some(ALL),
        "0" | "no" | "false" | "off" => return Some(0),
        _ => {}
    }
    let mut result = 0;
    for part in value.split(',').map(str::trim) {
        result |= match part {
            "credential" => CREDENTIAL,
            "container" => CONTAINER,
            "console" => CONSOLE,
            "builtin" => BUILTIN,
            _ => return None,
        };
    }
    Some(result)
}

fn cmdline_value(key: &str) -> Option<String> {
    let text = env::var("RUSTD_PROC_CMDLINE").ok().map_or_else(
        || fs::read_to_string("/proc/cmdline").unwrap_or_default(),
        |path| fs::read_to_string(path).unwrap_or_default(),
    );
    text.split_whitespace().find_map(|entry| {
        let (entry_key, value) = entry.split_once('=')?;
        (entry_key == key || entry_key.strip_prefix("rd.") == Some(key)).then(|| value.to_owned())
    })
}

fn credential_dir() -> Option<PathBuf> {
    env::var_os("RUSTD_CREDENTIALS_DIRECTORY")
        .map(PathBuf::from)
        .or_else(|| env::var_os("CREDENTIALS_DIRECTORY").map(PathBuf::from))
}

fn read_credential(name: &str) -> Option<String> {
    fs::read_to_string(credential_dir()?.join(name)).ok()
}

fn credential_lines(name: &str) -> Vec<String> {
    read_credential(name)
        .map(|text| {
            text.lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn in_initrd() -> bool {
    Path::new("/etc/initrd-release").exists()
        || env::var_os("RUSTD_IN_INITRD").as_deref() == Some(std::ffi::OsStr::new("1"))
}

fn is_container() -> bool {
    env::var_os("container").is_some()
        || Path::new("/run/rustd/container").exists()
        || env::var_os("RUSTD_CONTAINER").is_some()
}

fn is_vc(path: &str) -> bool {
    let name = path.strip_prefix("/dev/").unwrap_or(path);
    name.starts_with("tty")
        && name[3..]
            .chars()
            .all(|character| character.is_ascii_digit())
}

fn kernel_consoles() -> BTreeSet<String> {
    let mut result = BTreeSet::new();
    if let Ok(text) = fs::read_to_string("/sys/class/tty/console/active") {
        for name in text.split_whitespace() {
            result.insert(format!("/dev/{name}"));
        }
    }
    if let Ok(text) = fs::read_to_string("/proc/consoles") {
        for line in text.lines() {
            if let Some(name) = line.split_whitespace().next() {
                result.insert(format!("/dev/{name}"));
            }
        }
    }
    result
}

fn add_serial(dest: &Path, tty_or_path: &str) -> Result<(), String> {
    let tty = tty_or_path.strip_prefix("/dev/").unwrap_or(tty_or_path);
    if tty.is_empty() || tty.contains('/') {
        return Ok(());
    }
    add_instance(
        dest,
        "serial-getty@.service",
        tty,
        &format!("{UNIT_ROOT}/serial-getty@.service"),
    )
}

fn add_container(dest: &Path, tty_or_path: &str) -> Result<(), String> {
    let tty = tty_or_path
        .strip_prefix("/dev/pts/")
        .or_else(|| tty_or_path.strip_prefix("pts/"))
        .unwrap_or(tty_or_path);
    if tty.is_empty() || tty.contains('/') {
        return Ok(());
    }
    add_instance(
        dest,
        "container-getty@.service",
        tty,
        &format!("{UNIT_ROOT}/container-getty@.service"),
    )
}

fn add_instance(dest: &Path, template: &str, instance: &str, target: &str) -> Result<(), String> {
    let unit = format!(
        "{}@{}.service",
        template.trim_end_matches("@.service"),
        escape_instance(instance)
    );
    let target = target.replace(
        "@.service",
        &format!("@{}.service", escape_instance(instance)),
    );
    add_want(dest, &unit, &target)
}

fn escape_instance(value: &str) -> String {
    value.replace('-', "\\x2d")
}

fn add_want(dest: &Path, unit: &str, target: &str) -> Result<(), String> {
    let directory = dest.join("getty.target.wants");
    fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
    let path = directory.join(unit);
    match fs::remove_file(&path) {
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
    fn sources() {
        assert_eq!(
            parse_sources("credential,console"),
            Some(CREDENTIAL | CONSOLE)
        );
        assert_eq!(parse_sources("no"), Some(0));
        assert_eq!(parse_sources("bogus"), None);
    }

    #[test]
    fn vc() {
        assert!(is_vc("/dev/tty1"));
        assert!(!is_vc("/dev/ttyS0"));
    }

    #[test]
    fn vendor_unit_root_is_native() {
        assert_eq!(UNIT_ROOT, "/usr/lib/rustd/system");
    }
}
