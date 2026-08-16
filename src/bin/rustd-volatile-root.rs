// SPDX-License-Identifier: LGPL-2.1-or-later
//! `RustD` volatile-root helper.

use std::env;
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::Command;

const RUNTIME_ROOT: &str = "/run/rustd";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    No,
    Yes,
    State,
    Overlay,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("rustd-volatile-root: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let arguments: Vec<String> = env::args().collect();
    if arguments.len() > 3 {
        return Err("Too many arguments. Expected directory and mode.".into());
    }

    let command_line_mode = cmdline_mode(&read_cmdline())?;
    let mode = match command_line_mode {
        Some(mode) => mode,
        None if arguments.len() >= 2 => parse_mode(&arguments[1])?,
        None => Mode::No,
    };
    let path = arguments
        .get(2)
        .map_or_else(|| PathBuf::from("/sysroot"), PathBuf::from);
    validate_path(&path)?;

    if mode == Mode::No {
        return Ok(());
    }

    let mount =
        mount_info(&path)?.ok_or_else(|| format!("{} is not a mount point.", path.display()))?;
    if matches!(mount.fs_type.as_str(), "tmpfs" | "ramfs") && mode != Mode::State {
        println!("{} already is a temporary file system.", path.display());
        return Ok(());
    }
    record_backing_device(&path);

    match mode {
        Mode::No => Ok(()),
        Mode::Yes => make_volatile(&path),
        Mode::State => make_state_volatile(&path),
        Mode::Overlay => make_overlay(&path),
    }
}

fn read_cmdline() -> String {
    env::var("RUSTD_PROC_CMDLINE")
        .ok().map_or_else(|| fs::read_to_string("/proc/cmdline").unwrap_or_default(), |path| fs::read_to_string(path).unwrap_or_default())
}

fn cmdline_mode(cmdline: &str) -> Result<Option<Mode>, String> {
    for token in cmdline.split_whitespace().rev() {
        if token == "rustd.volatile" {
            return Ok(Some(Mode::Yes));
        }
        if let Some(value) = token.strip_prefix("rustd.volatile=") {
            return parse_mode(value).map(Some);
        }
    }
    Ok(None)
}

fn parse_mode(value: &str) -> Result<Mode, String> {
    match value.to_ascii_lowercase().as_str() {
        "0" | "no" | "false" | "off" => Ok(Mode::No),
        "1" | "yes" | "true" | "on" => Ok(Mode::Yes),
        "state" => Ok(Mode::State),
        "overlay" => Ok(Mode::Overlay),
        _ => Err(format!("Couldn't parse volatile mode: {value}")),
    }
}

fn validate_path(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Err("Directory name cannot be empty.".into());
    }
    if !path.is_absolute() {
        return Err("Directory must be specified as absolute path.".into());
    }
    if path == Path::new("/") {
        return Err("Directory cannot be the root directory.".into());
    }
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err("Directory must be normalized.".into());
    }
    Ok(())
}

#[derive(Debug)]
struct MountInfo {
    fs_type: String,
}

fn mount_info(path: &Path) -> Result<Option<MountInfo>, String> {
    let canonical =
        fs::canonicalize(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let mountinfo = env::var_os("RUSTD_MOUNTINFO")
        .map_or_else(|| PathBuf::from("/proc/self/mountinfo"), PathBuf::from);
    let text = fs::read_to_string(&mountinfo)
        .map_err(|error| format!("{}: {error}", mountinfo.display()))?;
    for line in text.lines() {
        let Some((left, right)) = line.split_once(" - ") else {
            continue;
        };
        let fields: Vec<_> = left.split_whitespace().collect();
        let right: Vec<_> = right.split_whitespace().collect();
        if fields.len() < 5 || right.is_empty() {
            continue;
        }
        if std::path::Path::new(&unescape_mountinfo(fields[4])) == canonical {
            return Ok(Some(MountInfo {
                fs_type: right[0].to_owned(),
            }));
        }
    }
    Ok(None)
}

fn unescape_mountinfo(value: &str) -> String {
    value
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

fn record_backing_device(path: &Path) {
    let Ok(metadata) = fs::metadata(path) else {
        return;
    };
    let device = metadata.dev();
    if device == 0 {
        return;
    }
    let directory = runtime_root();
    let _ = fs::create_dir_all(&directory);
    let link = directory.join("volatile-root");
    let _ = fs::remove_file(&link);
    let _ = symlink(
        format!("/dev/block/{}:{}", linux_major(device), linux_minor(device)),
        link,
    );
}

fn linux_major(device: u64) -> u64 {
    ((device >> 8) & 0xfff) | ((device >> 32) & !0xfff)
}

fn linux_minor(device: u64) -> u64 {
    (device & 0xff) | ((device >> 12) & !0xff)
}

fn make_volatile(path: &Path) -> Result<(), String> {
    let old_usr = path.join("usr");
    if !old_usr.exists() {
        return Err("/usr not available in old root".into());
    }
    let staging = runtime_root().join("volatile-sysroot");
    cleanup_mount(&staging);
    fs::create_dir_all(&staging).map_err(|error| error.to_string())?;
    run_mount(&[
        "-t",
        "tmpfs",
        "-o",
        "strictatime,mode=0755",
        "tmpfs",
        path_str(&staging)?,
    ])?;
    let result = (|| {
        let usr = staging.join("usr");
        fs::create_dir(&usr).map_err(|error| error.to_string())?;
        run_mount(&["--rbind", path_str(&old_usr)?, path_str(&usr)?])?;
        run_mount(&["-o", "remount,bind,ro", path_str(&usr)?])?;
        run_umount_recursive(path)?;
        let _ = run_mount(&["--make-rslave", "/"]);
        run_mount(&["--move", path_str(&staging)?, path_str(path)?])
    })();
    if result.is_err() {
        cleanup_mount(&staging);
    }
    result
}

fn make_state_volatile(path: &Path) -> Result<(), String> {
    let state = path.join("var");
    fs::create_dir_all(&state).map_err(|error| format!("{}: {error}", state.display()))?;
    run_mount(&[
        "-t",
        "tmpfs",
        "-o",
        "strictatime,mode=0755",
        "tmpfs",
        path_str(&state)?,
    ])
}

fn make_overlay(path: &Path) -> Result<(), String> {
    let staging = runtime_root().join("overlay-sysroot");
    cleanup_mount(&staging);
    fs::create_dir_all(&staging).map_err(|error| error.to_string())?;
    run_mount(&[
        "-t",
        "tmpfs",
        "-o",
        "strictatime,mode=0755",
        "tmpfs",
        path_str(&staging)?,
    ])?;
    let result = (|| {
        let upper = staging.join("upper");
        let work = staging.join("work");
        fs::create_dir(&upper).map_err(|error| error.to_string())?;
        fs::create_dir(&work).map_err(|error| error.to_string())?;
        let options = format!(
            "lowerdir={},upperdir={},workdir={}",
            escape_overlay(path_str(path)?),
            path_str(&upper)?,
            path_str(&work)?
        );
        run_mount(&["-t", "overlay", "-o", &options, "overlay", path_str(path)?])
    })();
    let _ = run_umount(&staging);
    let _ = fs::remove_dir(&staging);
    result
}

fn runtime_root() -> PathBuf {
    env::var_os("RUSTD_RUNTIME_ROOT").map_or_else(|| PathBuf::from(RUNTIME_ROOT), PathBuf::from)
}

fn escape_overlay(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace(',', "\\,")
        .replace(':', "\\:")
}

fn path_str(path: &Path) -> Result<&str, String> {
    path.to_str()
        .ok_or_else(|| format!("Non-UTF8 path: {}", path.display()))
}

fn mount_program() -> String {
    env::var("RUSTD_MOUNT").unwrap_or_else(|_| "/usr/bin/mount".into())
}

fn umount_program() -> String {
    env::var("RUSTD_UMOUNT").unwrap_or_else(|_| "/usr/bin/umount".into())
}

fn run_mount(arguments: &[&str]) -> Result<(), String> {
    run_command(&mount_program(), arguments)
}

fn run_umount(path: &Path) -> Result<(), String> {
    run_command(&umount_program(), &[path_str(path)?])
}

fn run_umount_recursive(path: &Path) -> Result<(), String> {
    run_command(&umount_program(), &["-R", path_str(path)?])
}

fn run_command(program: &str, arguments: &[&str]) -> Result<(), String> {
    let status = Command::new(program)
        .args(arguments)
        .status()
        .map_err(|error| format!("Failed to execute {program}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{program} exited with {status}"))
    }
}

fn cleanup_mount(path: &Path) {
    let _ = run_umount_recursive(path);
    let _ = fs::remove_dir_all(path);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_native_modes() {
        assert_eq!(parse_mode("yes").unwrap(), Mode::Yes);
        assert_eq!(parse_mode("state").unwrap(), Mode::State);
        assert_eq!(parse_mode("overlay").unwrap(), Mode::Overlay);
        assert!(parse_mode("bad").is_err());
    }

    #[test]
    fn native_bare_cmdline_means_yes() {
        assert_eq!(
            cmdline_mode("quiet rustd.volatile").unwrap(),
            Some(Mode::Yes)
        );
    }

    #[test]
    fn legacy_cmdline_is_not_authoritative() {
        assert_eq!(
            cmdline_mode("quiet systemd.volatile=overlay").unwrap(),
            None
        );
    }

    #[test]
    fn mountinfo_escapes() {
        assert_eq!(unescape_mountinfo("/a\\040b"), "/a b");
    }

    #[test]
    fn default_runtime_root_is_native() {
        assert_eq!(RUNTIME_ROOT, "/run/rustd");
    }
}
