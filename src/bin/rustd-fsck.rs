// SPDX-License-Identifier: LGPL-2.1-or-later
//! `RustD` filesystem-check helper.
//!
//! Compatibility reference: systemd-fsck v261.

use std::env;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const FSCK_ERROR_CORRECTED: i32 = 1 << 0;
const FSCK_SYSTEM_SHOULD_REBOOT: i32 = 1 << 1;
const FSCK_ERRORS_LEFT_UNCORRECTED: i32 = 1 << 2;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Mode {
    #[default]
    Auto,
    Force,
    Skip,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Repair {
    No,
    Yes,
    #[default]
    Preen,
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("rustd-fsck: {error}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<i32, String> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() > 1 {
        return Err(String::from("This program expects one or no arguments."));
    }

    let mut mode = Mode::Auto;
    let mut repair = Repair::Preen;
    merge_cmdline(&mut mode, &mut repair);
    merge_credentials(&mut mode, &mut repair);
    if mode == Mode::Skip {
        return Ok(0);
    }

    let (device, root_directory) = if let Some(device) = args.first() {
        let metadata =
            fs::metadata(device).map_err(|error| format!("Failed to stat {device}: {error}"))?;
        if !metadata.file_type().is_block_device() {
            return Err(format!("'{device}' is not a block device."));
        }
        (PathBuf::from(device), false)
    } else {
        if root_is_virtual()? {
            return Ok(0);
        }
        if root_is_writable()? {
            return Ok(0);
        }
        (root_device()?, true)
    };

    let fsck =
        env::var_os("RUSTD_FSCK").map_or_else(|| PathBuf::from("/usr/bin/fsck"), PathBuf::from);
    if !fsck.exists() && env::var_os("RUSTD_FSCK").is_none() {
        return Ok(0);
    }

    let mut command = Command::new(&fsck);
    command.arg(repair_option(repair)).arg("-T").arg("-l");
    if !root_directory {
        command.arg("-M");
    }
    if mode == Mode::Force {
        command.arg("-f");
    }

    let progress = progress_target();
    if let Some(fd_arg) = progress.as_ref().map(ProgressTarget::argument) {
        command.arg(fd_arg);
    }
    command.arg(&device);
    command.stdin(Stdio::null());

    let status = command
        .status()
        .map_err(|error| format!("Failed to execute {}: {error}", fsck.display()))?;
    let exit_status = status
        .code()
        .ok_or_else(|| String::from("fsck terminated by signal."))?;

    if exit_status & FSCK_ERROR_CORRECTED != 0 {
        touch_quotacheck_trigger()?;
    }

    if exit_status & FSCK_SYSTEM_SHOULD_REBOOT != 0 && root_directory {
        request_reboot();
        return Ok(1);
    }

    Ok(i32::from(
        exit_status & (FSCK_SYSTEM_SHOULD_REBOOT | FSCK_ERRORS_LEFT_UNCORRECTED) != 0,
    ))
}

fn merge_cmdline(mode: &mut Mode, repair: &mut Repair) {
    let path = env::var_os("RUSTD_PROC_CMDLINE")
        .map_or_else(|| PathBuf::from("/proc/cmdline"), PathBuf::from);
    let Ok(text) = fs::read_to_string(path) else {
        return;
    };
    for raw in text.split_whitespace() {
        let word = raw.strip_prefix("rd.").unwrap_or(raw);
        if word == "fastboot" {
            *mode = Mode::Skip;
        } else if word == "forcefsck" {
            *mode = Mode::Force;
        } else if let Some(value) = word.strip_prefix("fsck.mode=") {
            if let Some(parsed) = parse_mode(value) {
                *mode = parsed;
            } else {
                eprintln!("rustd-fsck: Invalid fsck.mode= parameter, ignoring: {value}");
            }
        } else if let Some(value) = word.strip_prefix("fsck.repair=") {
            if let Some(parsed) = parse_repair(value) {
                *repair = parsed;
            } else {
                eprintln!("rustd-fsck: Invalid fsck.repair= parameter, ignoring: {value}");
            }
        }
    }
}

fn merge_credentials(mode: &mut Mode, repair: &mut Repair) {
    let Some(directory) = env::var_os("CREDENTIALS_DIRECTORY") else {
        return;
    };
    if let Ok(value) = fs::read_to_string(Path::new(&directory).join("fsck.mode")) {
        let value = value.trim_end_matches(['\r', '\n']);
        if let Some(parsed) = parse_mode(value) {
            *mode = parsed;
        } else {
            eprintln!("rustd-fsck: Invalid 'fsck.mode' credential, ignoring: {value}");
        }
    }
    if let Ok(value) = fs::read_to_string(Path::new(&directory).join("fsck.repair")) {
        let value = value.trim_end_matches(['\r', '\n']);
        if let Some(parsed) = parse_repair(value) {
            *repair = parsed;
        } else {
            eprintln!("rustd-fsck: Invalid 'fsck.repair' credential, ignoring: {value}");
        }
    }
}

fn parse_mode(value: &str) -> Option<Mode> {
    match value.trim() {
        "auto" => Some(Mode::Auto),
        "force" => Some(Mode::Force),
        "skip" => Some(Mode::Skip),
        _ => None,
    }
}

fn parse_repair(value: &str) -> Option<Repair> {
    match value.trim().to_ascii_lowercase().as_str() {
        "no" | "false" | "0" | "off" => Some(Repair::No),
        "yes" | "true" | "1" | "on" => Some(Repair::Yes),
        "preen" => Some(Repair::Preen),
        _ => None,
    }
}

fn repair_option(repair: Repair) -> &'static str {
    match repair {
        Repair::No => "-n",
        Repair::Yes => "-y",
        Repair::Preen => "-a",
    }
}

fn root_is_virtual() -> Result<bool, String> {
    let metadata = fs::metadata("/").map_err(|error| format!("Failed to stat root: {error}"))?;
    Ok(libc::major(metadata.dev()) == 0)
}

fn root_is_writable() -> Result<bool, String> {
    let path = env::var_os("RUSTD_MOUNTINFO")
        .map_or_else(|| PathBuf::from("/proc/self/mountinfo"), PathBuf::from);
    let file =
        File::open(&path).map_err(|error| format!("Failed to read {}: {error}", path.display()))?;
    for line in BufReader::new(file).lines() {
        let line = line.map_err(|error| error.to_string())?;
        let mut fields = line.split_whitespace();
        let _id = fields.next();
        let _parent = fields.next();
        let _dev = fields.next();
        let _root = fields.next();
        if fields.next() != Some("/") {
            continue;
        }
        return Ok(fields
            .next()
            .is_some_and(|options| options.split(',').any(|option| option == "rw")));
    }
    Ok(false)
}

fn root_device() -> Result<PathBuf, String> {
    if let Some(path) = env::var_os("RUSTD_ROOT_DEVICE") {
        return Ok(PathBuf::from(path));
    }
    let metadata = fs::metadata("/").map_err(|error| format!("Failed to stat root: {error}"))?;
    let major = libc::major(metadata.dev());
    let minor = libc::minor(metadata.dev());
    let sys_path = PathBuf::from(format!("/dev/block/{major}:{minor}"));
    fs::canonicalize(&sys_path).map_err(|error| {
        format!(
            "Failed to detect device node of root directory from {}: {error}",
            sys_path.display()
        )
    })
}

fn touch_quotacheck_trigger() -> Result<(), String> {
    let path = env::var_os("RUSTD_QUOTACHECK_TRIGGER")
        .map_or_else(|| PathBuf::from("/run/rustd/quotacheck"), PathBuf::from);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("Failed to create {}: {error}", parent.display()))?;
    }
    File::create(&path)
        .map(|_| ())
        .map_err(|error| format!("Failed to touch {}: {error}", path.display()))
}

fn rustctl_path() -> PathBuf {
    env::var_os("RUSTD_RUSTCTL")
        .or_else(|| env::var_os("RUSTD_SYSTEMCTL"))
        .map_or_else(|| PathBuf::from("/usr/bin/rustctl"), PathBuf::from)
}

fn request_reboot() {
    let _ = Command::new(rustctl_path())
        .args(["start", "reboot.target"])
        .status();
}

enum ProgressTarget {
    Socket(UnixStream),
}

impl ProgressTarget {
    fn argument(&self) -> String {
        match self {
            Self::Socket(socket) => format!("-C{}", socket.as_raw_fd()),
        }
    }
}

fn progress_target() -> Option<ProgressTarget> {
    let show = env::var_os("RUSTD_SHOW_STATUS")
        .map_or_else(|| PathBuf::from("/run/rustd/show-status"), PathBuf::from);
    if !show.exists() {
        return None;
    }
    let socket_path = env::var_os("RUSTD_FSCK_PROGRESS")
        .map_or_else(|| PathBuf::from("/run/rustd/fsck.progress"), PathBuf::from);
    let socket = UnixStream::connect(socket_path).ok()?;
    let fd = socket.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0 {
        return None;
    }
    Some(ProgressTarget::Socket(socket))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_modes_and_repairs() {
        assert_eq!(parse_mode("force"), Some(Mode::Force));
        assert_eq!(parse_mode("skip"), Some(Mode::Skip));
        assert_eq!(parse_repair("yes"), Some(Repair::Yes));
        assert_eq!(parse_repair("preen"), Some(Repair::Preen));
        assert_eq!(repair_option(Repair::No), "-n");
    }

    #[test]
    fn maps_fsck_exit_bits_like_upstream() {
        let corrected = FSCK_ERROR_CORRECTED;
        let uncorrected = FSCK_ERRORS_LEFT_UNCORRECTED;
        assert_eq!(i32::from(corrected & uncorrected != 0), 0);
        assert_eq!(i32::from(uncorrected & uncorrected != 0), 1);
    }

    #[test]
    fn native_runtime_defaults_are_rustd_owned() {
        env::remove_var("RUSTD_RUSTCTL");
        env::remove_var("RUSTD_SYSTEMCTL");
        assert_eq!(rustctl_path(), PathBuf::from("/usr/bin/rustctl"));
        assert_eq!(
            env::var_os("RUSTD_QUOTACHECK_TRIGGER")
                .map_or_else(|| PathBuf::from("/run/rustd/quotacheck"), PathBuf::from),
            PathBuf::from("/run/rustd/quotacheck")
        );
    }
}
