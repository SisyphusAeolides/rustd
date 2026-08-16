// SPDX-License-Identifier: LGPL-2.1-or-later
//! `systemd-battery-check` v261 compatibility helper.

use std::env;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

const HELP: &str = concat!(
    "systemd-battery-check\n\n",
    "Check battery level to see whether there's enough charge.\n\n",
    "  -h --help    Show this help\n",
    "     --version Show package version\n\n",
    "See the systemd-battery-check(8) man page for details.\n"
);
const VERSION: &str = concat!(
    "systemd 261 (261.2-1-arch)\n",
    "+PAM +AUDIT -SELINUX +APPARMOR -IMA +IPE +SMACK +SECCOMP +GCRYPT +GNUTLS +OPENSSL +ACL ",
    "+BLKID +CURL +ELFUTILS +FIDO2 +IDN2 +KMOD +LIBCRYPTSETUP +LIBCRYPTSETUP_PLUGINS +LIBFDISK ",
    "+PCRE2 +PWQUALITY +P11KIT +QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB +ZSTD +BPF_FRAMEWORK +BTF ",
    "+XKBCOMMON +UTMP +LIBARCHIVE\n"
);
const LOW_MESSAGE: &str =
    "Battery level critically low. Please connect your charger or the system will power off in 10 seconds.";
const RESTORED_MESSAGE: &str = "A.C. power restored, continuing.";
const LOW_CAPACITY_PERCENT: i32 = 5;

enum ParseResult {
    Run,
    Exit(&'static str),
}

fn main() {
    let arguments: Vec<OsString> = env::args_os().skip(1).collect();
    let result = match parse_options(&arguments) {
        Ok(ParseResult::Exit(output)) => io::stdout()
            .lock()
            .write_all(output.as_bytes())
            .map_err(|error| error.to_string().into_bytes()),
        Ok(ParseResult::Run) => run(),
        Err(error) => Err(error),
    };
    if let Err(error) = result {
        if !error.is_empty() {
            let mut stderr = io::stderr().lock();
            let _ = stderr.write_all(&error);
            let _ = stderr.write_all(b"\n");
        }
        std::process::exit(1);
    }
}

fn parse_options(arguments: &[OsString]) -> Result<ParseResult, Vec<u8>> {
    let mut parse_options = true;
    let mut positional = false;
    for argument in arguments {
        let argument = argument.as_os_str().as_bytes();
        if !parse_options || argument == b"-" || !argument.starts_with(b"-") {
            positional = true;
            continue;
        }
        if argument == b"--" {
            parse_options = false;
            continue;
        }
        if let Some(long) = argument.strip_prefix(b"--") {
            let (name, attached) = long
                .iter()
                .position(|byte| *byte == b'=')
                .map_or((long, None), |position| {
                    (&long[..position], Some(&long[position + 1..]))
                });
            let matches: Vec<&[u8]> = [b"help".as_slice(), b"version".as_slice()]
                .into_iter()
                .filter(|option| option.starts_with(name))
                .collect();
            match matches.as_slice() {
                [_] if attached.is_some() => {
                    return Err(option_error(
                        b"option '--",
                        name,
                        b"' doesn't allow an argument",
                    ));
                }
                [b"help"] => return Ok(ParseResult::Exit(HELP)),
                [b"version"] => return Ok(ParseResult::Exit(VERSION)),
                [] => return Err(option_error(b"unrecognized option '--", name, b"'")),
                _ => {
                    return Err(option_error(
                        b"option '--",
                        name,
                        b"' is ambiguous; possibilities: --help, --version",
                    ));
                }
            }
        }
        if let Some(option) = argument.get(1) {
            if *option == b'h' {
                return Ok(ParseResult::Exit(HELP));
            }
            return Err(option_error(b"unrecognized option '-", &[*option], b"'"));
        }
    }
    if positional {
        return Err(b"systemd-battery-check takes no argument.".to_vec());
    }
    Ok(ParseResult::Run)
}

fn option_error(prefix: &[u8], option: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut error = b"systemd-battery-check: ".to_vec();
    error.extend_from_slice(prefix);
    error.extend_from_slice(option);
    error.extend_from_slice(suffix);
    error
}

fn run() -> Result<(), Vec<u8>> {
    let cmdline = env::var_os("RUSTD_BATTERY_CHECK_CMDLINE").map_or_else(
        || fs::read("/proc/cmdline"),
        |value| Ok(value.as_bytes().to_vec()),
    );
    let enabled = match cmdline {
        Ok(value) => match battery_check_enabled(&value) {
            Ok(value) => value,
            Err(value) => {
                log_message("Failed to parse systemd.battery_check= kernel command line option, ignoring: Invalid argument");
                value
            }
        },
        Err(error) => {
            log_message(&format!(
                "Failed to parse systemd.battery_check= kernel command line option, ignoring: {}",
                io_error_text(&error)
            ));
            true
        }
    };
    if !enabled {
        log_message("Checking battery status and AC power existence is disabled by the kernel command line, skipping execution.");
        return Ok(());
    }

    let sysfs = env::var_os("RUSTD_BATTERY_CHECK_SYSFS_ROOT")
        .map_or_else(|| PathBuf::from("/sys/class"), PathBuf::from);
    if !battery_is_discharging_and_low(&sysfs) {
        return Ok(());
    }

    log_message(&format!("! {LOW_MESSAGE}"));
    write_console(&format!("\x1b[0;1;31m! {LOW_MESSAGE}\x1b[0m\n"));
    send_plymouth("shutdown", &format!("🪫 {LOW_MESSAGE}"));

    thread::sleep(Duration::from_millis(
        env::var("RUSTD_BATTERY_CHECK_DELAY_MS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(10_000),
    ));

    if battery_is_discharging_and_low(&sysfs) {
        log_message("Battery level critically low, powering off.");
        return Err(Vec::new());
    }

    log_message(RESTORED_MESSAGE);
    write_console(&format!("{RESTORED_MESSAGE}\n"));
    send_plymouth("boot-up", RESTORED_MESSAGE);
    Ok(())
}

fn battery_check_enabled(cmdline: &[u8]) -> Result<bool, bool> {
    let mut found = false;
    let mut value = None;
    for word in cmdline.split(u8::is_ascii_whitespace) {
        let word = word.strip_prefix(b"rd.").unwrap_or(word);
        if word == b"systemd.battery_check" {
            found = true;
        } else if let Some(candidate) = word.strip_prefix(b"systemd.battery_check=") {
            found = true;
            value = Some(candidate);
        }
    }
    if !found {
        return Ok(true);
    }
    let Some(value) = value else {
        return Ok(true);
    };
    parse_boolean(value).ok_or(true)
}

fn parse_boolean(value: &[u8]) -> Option<bool> {
    if [b"1".as_slice(), b"yes", b"y", b"true", b"t", b"on"].contains(&value) {
        Some(true)
    } else if [b"0".as_slice(), b"no", b"n", b"false", b"f", b"off"].contains(&value) {
        Some(false)
    } else {
        None
    }
}

fn log_message(message: &str) {
    if env::var("SYSTEMD_LOG_TARGET").ok().as_deref() != Some("null") {
        eprintln!("{message}");
    }
}

fn write_console(message: &str) {
    let override_path = env::var_os("RUSTD_BATTERY_CHECK_CONSOLE");
    let path = override_path
        .as_ref()
        .map_or_else(|| PathBuf::from("/dev/console"), PathBuf::from);
    let mut options = OpenOptions::new();
    options
        .write(true)
        .custom_flags(libc::O_NOCTTY | libc::O_CLOEXEC);
    if override_path.is_some() {
        options.create(true).append(true);
    }
    let _ = options
        .open(path)
        .and_then(|mut console| console.write_all(message.as_bytes()));
}

fn send_plymouth(mode: &str, message: &str) {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"C\x02");
    payload.push(u8::try_from(mode.len() + 1).unwrap_or(u8::MAX));
    payload.extend_from_slice(mode.as_bytes());
    payload.push(0);
    payload.extend_from_slice(b"M\x02");
    payload.push(u8::try_from(message.len() + 1).unwrap_or(u8::MAX));
    payload.extend_from_slice(message.as_bytes());
    payload.push(0);

    if let Some(path) = env::var_os("RUSTD_BATTERY_CHECK_PLYMOUTH") {
        let _ = UnixStream::connect(path).and_then(|mut stream| stream.write_all(&payload));
    } else {
        let _ = send_abstract_plymouth(&payload);
    }
}

fn send_abstract_plymouth(payload: &[u8]) -> io::Result<()> {
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let result = (|| {
        let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        address.sun_family =
            libc::sa_family_t::try_from(libc::AF_UNIX).expect("AF_UNIX fits in sa_family_t");
        let name = b"/org/freedesktop/plymouthd";
        for (destination, source) in address.sun_path[1..].iter_mut().zip(name) {
            *destination = libc::c_char::try_from(*source).expect("Plymouth socket name is ASCII");
        }
        let length = std::mem::size_of::<libc::sa_family_t>() + 1 + name.len();
        let connected = unsafe {
            libc::connect(
                fd,
                std::ptr::addr_of!(address).cast(),
                libc::socklen_t::try_from(length).expect("Unix socket address length fits"),
            )
        };
        if connected < 0 {
            return Err(io::Error::last_os_error());
        }
        write_fd(fd, payload)
    })();
    unsafe { libc::close(fd) };
    result
}

fn write_fd(fd: RawFd, mut payload: &[u8]) -> io::Result<()> {
    while !payload.is_empty() {
        let written = unsafe { libc::write(fd, payload.as_ptr().cast(), payload.len()) };
        if written < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        payload = &payload[usize::try_from(written).expect("successful write is nonnegative")..];
    }
    Ok(())
}

fn directory_entries(path: &Path) -> Vec<PathBuf> {
    fs::read_dir(path).map_or_else(
        |_| Vec::new(),
        |entries| {
            entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .collect()
        },
    )
}

fn read_attribute(device: &Path, attribute: &str) -> io::Result<String> {
    fs::read_to_string(device.join(attribute)).map(|value| value.trim().to_owned())
}

fn read_boolean_attribute(device: &Path, attribute: &str) -> io::Result<bool> {
    parse_boolean(read_attribute(device, attribute)?.as_bytes())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid boolean"))
}

fn read_unsigned_attribute(device: &Path, attribute: &str) -> io::Result<u64> {
    read_attribute(device, attribute)?
        .parse::<u64>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid unsigned integer"))
}

fn battery_is_discharging(device: &Path) -> bool {
    if read_attribute(device, "scope").is_ok_and(|value| value == "Device") {
        return false;
    }
    if read_boolean_attribute(device, "present").is_ok_and(|present| !present) {
        return false;
    }
    read_attribute(device, "status").map_or(true, |status| status == "Discharging")
}

fn device_is_power_sink(device: &Path, sysfs: &Path) -> io::Result<bool> {
    let canonical = fs::canonicalize(device)?;
    let immediate_parent = canonical
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "device has no parent"))?;
    let parent = if immediate_parent
        .file_name()
        .is_some_and(|name| name == "power_supply")
    {
        immediate_parent.parent().unwrap_or(immediate_parent)
    } else {
        immediate_parent
    };
    let mut found_source = false;
    let mut found_sink = false;
    for port in directory_entries(&sysfs.join("typec")) {
        let Ok(port_path) = fs::canonicalize(&port) else {
            continue;
        };
        if !port_path.starts_with(parent) {
            continue;
        }
        let Ok(role) = read_attribute(&port, "power_role") else {
            continue;
        };
        if role.contains("[source]") {
            found_source = true;
        } else if role.contains("[sink]") {
            found_sink = true;
        }
    }
    Ok(found_sink || !found_source)
}

fn on_ac_power(sysfs: &Path) -> bool {
    let mut found_ac_online = false;
    let mut found_discharging_battery = false;
    for device in directory_entries(&sysfs.join("power_supply")) {
        let Ok(kind) = read_attribute(&device, "type") else {
            continue;
        };
        if kind == "USB" && !device_is_power_sink(&device, sysfs).unwrap_or(false) {
            continue;
        }
        if kind == "Battery" {
            found_discharging_battery |= battery_is_discharging(&device);
        } else if read_unsigned_attribute(&device, "online").is_ok_and(|online| online > 0) {
            found_ac_online = true;
        }
    }
    found_ac_online || !found_discharging_battery
}

fn battery_is_discharging_and_low(sysfs: &Path) -> bool {
    if on_ac_power(sysfs) {
        return false;
    }
    let mut unsure = false;
    let mut found_low = false;
    for device in directory_entries(&sysfs.join("power_supply")) {
        if !read_attribute(&device, "type").is_ok_and(|value| value == "Battery")
            || !read_attribute(&device, "present").is_ok_and(|value| value == "1")
            || read_attribute(&device, "scope").is_ok_and(|value| value == "Device")
        {
            continue;
        }
        match read_attribute(&device, "capacity")
            .ok()
            .and_then(|value| value.parse::<i32>().ok())
            .filter(|value| (0..=100).contains(value))
        {
            Some(level) if level > LOW_CAPACITY_PERCENT => return false,
            Some(_) => found_low = true,
            None => unsure = true,
        }
    }
    found_low && !unsure
}

fn io_error_text(error: &io::Error) -> String {
    let text = error.to_string();
    text.rfind(" (os error ").map_or(text.clone(), |index| {
        if text.ends_with(')') {
            text[..index].to_owned()
        } else {
            text
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_command_line_boolean_contract() {
        assert_eq!(battery_check_enabled(b"quiet"), Ok(true));
        assert_eq!(battery_check_enabled(b"systemd.battery_check=0"), Ok(false));
        assert_eq!(
            battery_check_enabled(b"rd.systemd.battery_check=yes"),
            Ok(true)
        );
        assert_eq!(
            battery_check_enabled(b"systemd.battery_check=invalid"),
            Err(true)
        );
    }
}
