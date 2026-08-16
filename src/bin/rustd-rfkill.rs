// SPDX-License-Identifier: LGPL-2.1-or-later

use std::collections::HashMap;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{exit, Command};
use std::thread;
use std::time::{Duration, Instant};

const RFKILL_EVENT_SIZE_V1: usize = 8;
const RFKILL_OP_ADD: u8 = 0;
const RFKILL_OP_DEL: u8 = 1;
const RFKILL_OP_CHANGE: u8 = 2;
const IDLE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug)]
struct RfkillEvent {
    idx: u32,
    kind: u8,
    op: u8,
    soft: bool,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("systemd-rfkill: {error}");
        exit(1);
    }
}

fn run() -> Result<(), String> {
    if env::args_os().len() > 1 {
        return Err(String::from("This program requires no arguments."));
    }

    let state_root = env::var_os("RUSTD_RFKILL_STATE_DIR").map_or_else(|| PathBuf::from("/var/lib/systemd/rfkill"), PathBuf::from);
    let mut device = open_rfkill()?;
    let mut queue: HashMap<u32, (PathBuf, bool)> = HashMap::new();
    let mut ready = false;
    let mut idle_since: Option<Instant> = None;
    let restore = shall_restore_state();

    loop {
        let mut bytes = [0u8; RFKILL_EVENT_SIZE_V1];
        match device.read(&mut bytes) {
            Ok(0) => return Err(String::from("Short read from /dev/rfkill.")),
            Ok(length) if length < RFKILL_EVENT_SIZE_V1 => {
                return Err(format!(
                    "Short read of struct rfkill_event ({length} < {RFKILL_EVENT_SIZE_V1})."
                ));
            }
            Ok(_) => {
                idle_since = None;
                let event = parse_event(bytes);
                if rfkill_type(event.kind).is_none() {
                    continue;
                }
                match event.op {
                    RFKILL_OP_ADD => {
                        load_state(&mut device, &state_root, event, restore)?;
                    }
                    RFKILL_OP_DEL => {
                        queue.remove(&event.idx);
                    }
                    RFKILL_OP_CHANGE => {
                        if let Ok(path) = determine_state_file(&state_root, event) {
                            queue.insert(event.idx, (path, event.soft));
                        }
                    }
                    _ => {}
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if !ready {
                    if let Err(error) = rustd::native::notify_ready() {
                        eprintln!("systemd-rfkill: failed to send readiness notification: {error}");
                    }
                    ready = true;
                }
                let started = *idle_since.get_or_insert_with(Instant::now);
                if started.elapsed() >= IDLE_TIMEOUT {
                    break;
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(format!("Failed to read from /dev/rfkill: {error}")),
        }
    }

    for (_, (path, state)) in queue {
        write_state(&path, state)?;
    }
    Ok(())
}

fn open_rfkill() -> Result<File, String> {
    let inherited = rustd::native::listen_fds(false)
        .map_err(|error| format!("Failed to read socket activation descriptors: {error}"))?;
    match inherited {
        0 => {
            let path = env::var_os("RUSTD_RFKILL_DEVICE").map_or_else(|| PathBuf::from("/dev/rfkill"), PathBuf::from);
            match OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOCTTY)
                .open(&path)
            {
                Ok(file) => Ok(file),
                Err(error) if error.kind() == io::ErrorKind::NotFound => exit(0),
                Err(error) => Err(format!("Failed to open {}: {error}", path.display())),
            }
        }
        1 => {
            let fd: RawFd = 3;
            // SAFETY: rustd_listen_fds() reported exactly one descriptor beginning at fd 3.
            Ok(unsafe { File::from_raw_fd(fd) })
        }
        count => Err(format!("Got too many file descriptors ({count}).")),
    }
}

fn parse_event(bytes: [u8; RFKILL_EVENT_SIZE_V1]) -> RfkillEvent {
    RfkillEvent {
        idx: u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        kind: bytes[4],
        op: bytes[5],
        soft: bytes[6] != 0,
    }
}

fn encode_change(event: RfkillEvent, state: bool) -> [u8; RFKILL_EVENT_SIZE_V1] {
    let mut bytes = [0u8; RFKILL_EVENT_SIZE_V1];
    bytes[..4].copy_from_slice(&event.idx.to_ne_bytes());
    bytes[4] = event.kind;
    bytes[5] = RFKILL_OP_CHANGE;
    bytes[6] = u8::from(state);
    bytes
}

fn rfkill_type(kind: u8) -> Option<&'static str> {
    match kind {
        0 => Some("all"),
        1 => Some("wlan"),
        2 => Some("bluetooth"),
        3 => Some("uwb"),
        4 => Some("wimax"),
        5 => Some("wwan"),
        6 => Some("gps"),
        7 => Some("fm"),
        8 => Some("nfc"),
        _ => None,
    }
}

fn determine_state_file(root: &Path, event: RfkillEvent) -> Result<PathBuf, String> {
    let kind =
        rfkill_type(event.kind).ok_or_else(|| format!("Unknown rfkill type {}.", event.kind))?;
    let sysfs_root = env::var_os("RUSTD_SYSFS_ROOT").map_or_else(|| PathBuf::from("/sys"), PathBuf::from);
    let device_path = sysfs_root
        .join("class/rfkill")
        .join(format!("rfkill{}", event.idx));

    if let Some(path_id) = udev_property(&device_path, "ID_PATH") {
        return Ok(root.join(format!("{}:{kind}", cescape(&path_id))));
    }
    Ok(root.join(kind))
}

fn udev_property(device: &Path, property: &str) -> Option<String> {
    let udevadm = env::var("RUSTD_UDEVADM").unwrap_or_else(|_| "udevadm".to_owned());
    let output = Command::new(udevadm)
        .args(["info", "--query=property", "--path"])
        .arg(device)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    text.lines().find_map(|line| {
        let (key, value) = line.split_once('=')?;
        (key == property).then(|| value.to_owned())
    })
}

fn cescape(value: &str) -> String {
    let mut escaped = String::new();
    for byte in value.bytes() {
        match byte {
            b'\\' => escaped.push_str("\\\\"),
            b'\n' => escaped.push_str("\\n"),
            b'\r' => escaped.push_str("\\r"),
            b'\t' => escaped.push_str("\\t"),
            0x20..=0x7e => escaped.push(char::from(byte)),
            _ => escaped.push_str(&format!("\\x{byte:02x}")),
        }
    }
    escaped
}

fn load_state(
    device: &mut File,
    state_root: &Path,
    event: RfkillEvent,
    restore: bool,
) -> Result<(), String> {
    if !restore {
        return Ok(());
    }
    let path = determine_state_file(state_root, event)?;
    let state = match fs::read_to_string(&path) {
        Ok(value) if value.trim().is_empty() => {
            write_state(&path, event.soft)?;
            return Ok(());
        }
        Ok(value) => parse_boolean(value.trim())
            .ok_or_else(|| format!("Failed to parse state file {}.", path.display()))?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            write_state(&path, event.soft)?;
            return Ok(());
        }
        Err(error) => return Err(format!("Failed to read {}: {error}", path.display())),
    };
    let bytes = encode_change(event, state);
    device
        .write_all(&bytes)
        .map_err(|error| format!("Failed to restore rfkill state for {}: {error}", event.idx))
}

fn write_state(path: &Path, state: bool) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("Invalid state path {}.", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("Failed to create {}: {error}", parent.display()))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("rfkill");
    let temporary = parent.join(format!(".{name}.tmp-{}", std::process::id()));
    fs::write(&temporary, if state { b"1\n" } else { b"0\n" })
        .map_err(|error| format!("Failed to write {}: {error}", temporary.display()))?;
    fs::rename(&temporary, path)
        .map_err(|error| format!("Failed to replace {}: {error}", path.display()))
}

fn shall_restore_state() -> bool {
    let path = env::var("RUSTD_PROC_CMDLINE").unwrap_or_else(|_| "/proc/cmdline".to_owned());
    let Ok(cmdline) = fs::read_to_string(path) else {
        return true;
    };
    for word in cmdline.split_whitespace() {
        if word == "systemd.restore_state" {
            return true;
        }
        if let Some(value) = word.strip_prefix("systemd.restore_state=") {
            return parse_boolean(value).unwrap_or(true);
        }
    }
    true
}

fn parse_boolean(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "yes" | "y" | "true" | "t" | "on" => Some(true),
        "0" | "no" | "n" | "false" | "f" | "off" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfkill_event_round_trip_fields() {
        let event = parse_event([7, 0, 0, 0, 1, RFKILL_OP_ADD, 1, 0]);
        assert_eq!(event.idx, 7);
        assert_eq!(event.kind, 1);
        assert!(event.soft);
        let change = encode_change(event, false);
        assert_eq!(change, [7, 0, 0, 0, 1, RFKILL_OP_CHANGE, 0, 0]);
    }

    #[test]
    fn type_names_match_kernel_abi() {
        assert_eq!(rfkill_type(1), Some("wlan"));
        assert_eq!(rfkill_type(2), Some("bluetooth"));
        assert_eq!(rfkill_type(8), Some("nfc"));
        assert_eq!(rfkill_type(9), None);
    }
}
