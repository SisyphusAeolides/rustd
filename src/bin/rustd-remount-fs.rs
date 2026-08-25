// SPDX-License-Identifier: LGPL-2.1-or-later
//! `RustD` remount helper with systemd-compatible inputs.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};

const API_MOUNT_POINTS: &[&str] = &[
    "/proc",
    "/sys",
    "/dev",
    "/sys/kernel/security",
    "/sys/fs/smackfs",
    "/dev/shm",
    "/dev/pts",
    "/run",
    "/sys/fs/cgroup",
    "/sys/fs/pstore",
    "/sys/firmware/efi/efivars",
    "/sys/fs/bpf",
];

fn main() {
    if let Err(error) = run() {
        eprintln!("rustd-remount-fs: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    if env::args_os().len() > 1 {
        return Err(String::from("This program takes no arguments."));
    }

    let (mut children, has_root) = remount_by_fstab()?;
    if !has_root
        && env_bool("SYSTEMD_REMOUNT_ROOT_RW").unwrap_or(false)
        && !root_is_overlay()
    {
        children.push((String::from("/"), spawn_remount("/", true)?));
    }

    let mut failed = false;
    for (path, mut child) in children {
        match child.wait() {
            Ok(status) if status.success() => {}
            Ok(status) => {
                eprintln!("mount for {path} exited with {status}.");
                failed = true;
            }
            Err(error) => return Err(format!("Failed to wait for mount for {path}: {error}")),
        }
    }

    if failed {
        Err(String::from("One or more remount operations failed."))
    } else {
        Ok(())
    }
}

fn remount_by_fstab() -> Result<(Vec<(String, Child)>, bool), String> {
    if !fstab_enabled() {
        return Ok((Vec::new(), false));
    }

    let path =
        env::var_os("RUSTD_FSTAB").map_or_else(|| PathBuf::from("/etc/fstab"), PathBuf::from);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((Vec::new(), false));
        }
        Err(error) => return Err(format!("Failed to parse {}: {error}", path.display())),
    };

    let mut children = Vec::new();
    let mut has_root = false;
    for line in text.lines() {
        let Some(target) = fstab_target(line) else {
            continue;
        };
        if target == "/" {
            has_root = true;
            if root_is_overlay() {
                continue;
            }
        } else if target != "/usr" && !mount_point_is_api(&target) {
            continue;
        }
        children.push((target.clone(), spawn_remount(&target, false)?));
    }
    Ok((children, has_root))
}

fn root_is_overlay() -> bool {
    let Ok(mountinfo) = fs::read_to_string("/proc/self/mountinfo") else {
        return false;
    };
    mountinfo.lines().any(|line| {
        let Some((mount_fields, filesystem_fields)) = line.split_once(" - ") else {
            return false;
        };
        let mut fields = mount_fields.split_whitespace();
        let mountpoint = fields.nth(4);
        let filesystem = filesystem_fields.split_whitespace().next();
        mountpoint == Some("/") && filesystem == Some("overlay")
    })
}

fn fstab_enabled() -> bool {
    match env::var("RUSTD_FSTAB_ENABLED").or_else(|_| env::var("SYSTEMD_FSTAB")) {
        Ok(value) => env_bool_value(&value).unwrap_or(true),
        Err(_) => true,
    }
}

fn spawn_remount(path: &str, force_rw: bool) -> Result<Child, String> {
    let mount =
        env::var_os("RUSTD_MOUNT").map_or_else(|| PathBuf::from("/usr/bin/mount"), PathBuf::from);
    let option = if force_rw { "remount,rw" } else { "remount" };
    Command::new(&mount)
        .arg(path)
        .arg("-o")
        .arg(option)
        .spawn()
        .map_err(|error| format!("Failed to execute {} for {path}: {error}", mount.display()))
}

fn mount_point_is_api(path: &str) -> bool {
    API_MOUNT_POINTS.contains(&path)
        || Path::new(path)
            .strip_prefix("/sys/fs/cgroup")
            .is_ok_and(|suffix| suffix != Path::new(""))
}

fn fstab_target(line: &str) -> Option<String> {
    let line = line.trim_start();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let fields = split_fstab_fields(line);
    if fields.len() < 2 {
        return None;
    }
    Some(decode_fstab_field(&fields[1]))
}

fn split_fstab_fields(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut chars = line.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '#' && field.is_empty() {
            break;
        }
        if ch.is_ascii_whitespace() {
            if !field.is_empty() {
                fields.push(std::mem::take(&mut field));
            }
            while chars.peek().is_some_and(char::is_ascii_whitespace) {
                chars.next();
            }
            continue;
        }
        field.push(ch);
    }
    if !field.is_empty() {
        fields.push(field);
    }
    fields
}

fn decode_fstab_field(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut result = String::with_capacity(value.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' && index + 3 < bytes.len() {
            let code = &value[index + 1..index + 4];
            let replacement = match code {
                "040" => Some(' '),
                "011" => Some('\t'),
                "134" => Some('\\'),
                "043" => Some('#'),
                _ => None,
            };
            if let Some(ch) = replacement {
                result.push(ch);
                index += 4;
                continue;
            }
        }
        let ch = value[index..].chars().next().expect("valid utf-8 boundary");
        result.push(ch);
        index += ch.len_utf8();
    }
    result
}

fn env_bool(name: &str) -> Result<bool, String> {
    match env::var(name) {
        Ok(value) => {
            env_bool_value(&value).ok_or_else(|| format!("Failed to parse ${name}: {value}"))
        }
        Err(env::VarError::NotPresent) => Ok(false),
        Err(error) => Err(format!("Failed to read ${name}: {error}")),
    }
}

fn env_bool_value(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "yes" | "true" | "on" => Some(true),
        "0" | "no" | "false" | "off" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_upstream_remount_targets() {
        assert!(mount_point_is_api("/proc"));
        assert!(mount_point_is_api("/sys/fs/cgroup/user.slice"));
        assert!(!mount_point_is_api("/home"));
    }

    #[test]
    fn parses_and_decodes_fstab_targets() {
        assert_eq!(
            fstab_target("UUID=x /usr ext4 defaults 0 2"),
            Some(String::from("/usr"))
        );
        assert_eq!(
            fstab_target("tmpfs /run/foo\\040bar tmpfs defaults 0 0"),
            Some(String::from("/run/foo bar"))
        );
        assert_eq!(fstab_target(" # comment"), None);
    }

    #[test]
    fn parses_systemd_boolean_syntax() {
        assert_eq!(env_bool_value("yes"), Some(true));
        assert_eq!(env_bool_value("OFF"), Some(false));
        assert_eq!(env_bool_value("maybe"), None);
    }

    #[test]
    fn recognizes_overlay_mountinfo() {
        let line = "36 25 0:32 / / rw,relatime - overlay overlay rw";
        let (mount_fields, filesystem_fields) = line.split_once(" - ").unwrap();
        let mut fields = mount_fields.split_whitespace();
        assert_eq!(fields.nth(4), Some("/"));
        assert_eq!(filesystem_fields.split_whitespace().next(), Some("overlay"));
    }
}
