// SPDX-License-Identifier: LGPL-2.1-or-later
//! `systemd-ac-power` compatibility utility.
//!
//! Upstream reference: `src/ac-power/ac-power.c` and
//! `src/shared/battery-util.c` from systemd v261.

use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const VERSION_OUTPUT: &str = concat!(
    "systemd 261 (261.2-1-arch)\n",
    "+PAM +AUDIT -SELINUX +APPARMOR -IMA +IPE +SMACK +SECCOMP +GCRYPT +GNUTLS +OPENSSL +ACL ",
    "+BLKID +CURL +ELFUTILS +FIDO2 +IDN2 +KMOD +LIBCRYPTSETUP +LIBCRYPTSETUP_PLUGINS +LIBFDISK ",
    "+PCRE2 +PWQUALITY +P11KIT +QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB +ZSTD +BPF_FRAMEWORK +BTF ",
    "+XKBCOMMON +UTMP +LIBARCHIVE\n"
);

const HELP: &str = concat!(
    "> systemd-ac-power [OPTIONS...]\n\n",
    "Report whether we are connected to an external power source.\n\n",
    "Options:\n",
    "  -h --help    Show this help\n",
    "     --version Show package version\n",
    "  -v --verbose Show state as text\n",
    "     --low     Check if battery is discharging and low\n\n",
    "See the systemd-ac-power(1) man page for details.\n"
);

const BATTERY_LOW_CAPACITY_LEVEL: i32 = 5;
const SYSFS_OVERRIDE: &str = "SYSTEMD_AC_POWER_SYSFS_ROOT";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Action {
    AcPower,
    Low,
}

#[derive(Debug, Eq, PartialEq)]
struct Options {
    action: Action,
    verbose: bool,
}

#[derive(Debug, Eq, PartialEq)]
enum ParseResult {
    Run(Options),
    Exit(&'static str),
}

fn main() {
    let arguments: Vec<String> = env::args().skip(1).collect();
    let result = match parse_options(&arguments) {
        Ok(ParseResult::Exit(output)) => write_stdout(output.as_bytes()),
        Ok(ParseResult::Run(options)) => run(&options),
        Err(error) => {
            if !error.is_empty() {
                eprintln!("{error}");
            }
            Err(())
        }
    };

    if result.is_err() {
        std::process::exit(1);
    }
}

fn write_stdout(bytes: &[u8]) -> Result<(), ()> {
    io::stdout().lock().write_all(bytes).map_err(|_| ())
}

fn run(options: &Options) -> Result<(), ()> {
    let sysfs =
        env::var_os(SYSFS_OVERRIDE).map_or_else(|| PathBuf::from("/sys/class"), PathBuf::from);
    let state = match options.action {
        Action::AcPower => on_ac_power(&sysfs),
        Action::Low => battery_is_discharging_and_low(&sysfs),
    };

    if options.verbose {
        write_stdout(if state { b"yes\n" } else { b"no\n" })?;
    }
    if state {
        Ok(())
    } else {
        Err(())
    }
}

fn parse_options(arguments: &[String]) -> Result<ParseResult, String> {
    let mut options = Options {
        action: Action::AcPower,
        verbose: false,
    };
    let mut positional = 0_usize;
    let mut positional_only = false;

    for argument in arguments {
        if positional_only || argument == "-" || !argument.starts_with('-') {
            positional += 1;
            continue;
        }
        if argument == "--" {
            positional_only = true;
            continue;
        }
        if let Some(long) = argument.strip_prefix("--") {
            let (name, attached) = long
                .split_once('=')
                .map_or((long, None), |(name, value)| (name, Some(value)));
            match resolve_long_option(name)? {
                "help" => {
                    reject_attached_argument(name, attached)?;
                    return Ok(ParseResult::Exit(HELP));
                }
                "version" => {
                    reject_attached_argument(name, attached)?;
                    return Ok(ParseResult::Exit(VERSION_OUTPUT));
                }
                "verbose" => {
                    reject_attached_argument(name, attached)?;
                    options.verbose = true;
                }
                "low" => {
                    reject_attached_argument(name, attached)?;
                    options.action = Action::Low;
                }
                _ => unreachable!("complete long-option match"),
            }
            continue;
        }

        for short in argument[1..].chars() {
            match short {
                'h' => return Ok(ParseResult::Exit(HELP)),
                'v' => options.verbose = true,
                _ => {
                    return Err(format!("systemd-ac-power: unrecognized option '-{short}'"));
                }
            }
        }
    }

    if positional > 0 {
        return Err("This program takes no arguments.".to_owned());
    }
    Ok(ParseResult::Run(options))
}

fn resolve_long_option(value: &str) -> Result<&'static str, String> {
    const OPTIONS: &[&str] = &["help", "version", "verbose", "low"];
    let matches: Vec<&str> = OPTIONS
        .iter()
        .copied()
        .filter(|option| option.starts_with(value))
        .collect();
    match matches.as_slice() {
        [single] => Ok(single),
        [] => Err(format!("systemd-ac-power: unrecognized option '--{value}'")),
        _ => Err(format!(
            "systemd-ac-power: option '--{value}' is ambiguous; possibilities: {}",
            matches
                .iter()
                .map(|option| format!("--{option}"))
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

fn reject_attached_argument(name: &str, attached: Option<&str>) -> Result<(), String> {
    if attached.is_some() {
        return Err(format!(
            "systemd-ac-power: option '--{name}' doesn't allow an argument"
        ));
    }
    Ok(())
}

fn power_supplies(sysfs: &Path) -> Vec<PathBuf> {
    directory_entries(&sysfs.join("power_supply"))
}

fn directory_entries(path: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(path) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect()
}

fn read_attribute(device: &Path, attribute: &str) -> io::Result<String> {
    fs::read_to_string(device.join(attribute)).map(|value| value.trim().to_owned())
}

fn read_boolean_attribute(device: &Path, attribute: &str) -> io::Result<bool> {
    match read_attribute(device, attribute)?.as_str() {
        "1" | "yes" | "y" | "true" | "on" => Ok(true),
        "0" | "no" | "n" | "false" | "off" => Ok(false),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid boolean",
        )),
    }
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

    for device in power_supplies(sysfs) {
        let Ok(kind) = read_attribute(&device, "type") else {
            continue;
        };
        if kind == "USB" && !device_is_power_sink(&device, sysfs).unwrap_or(false) {
            continue;
        }
        if kind == "Battery" {
            found_discharging_battery |= battery_is_discharging(&device);
            continue;
        }
        if read_unsigned_attribute(&device, "online").is_ok_and(|online| online > 0) {
            found_ac_online = true;
        }
    }

    found_ac_online || !found_discharging_battery
}

fn battery_capacity_percentage(device: &Path) -> io::Result<i32> {
    let capacity = read_attribute(device, "capacity")?
        .parse::<i32>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid battery capacity"))?;
    if !(0..=100).contains(&capacity) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "battery capacity outside 0..=100",
        ));
    }
    Ok(capacity)
}

fn low_batteries(sysfs: &Path) -> Vec<PathBuf> {
    power_supplies(sysfs)
        .into_iter()
        .filter(|device| read_attribute(device, "type").is_ok_and(|kind| kind == "Battery"))
        .filter(|device| read_attribute(device, "present").is_ok_and(|present| present == "1"))
        .filter(|device| !read_attribute(device, "scope").is_ok_and(|scope| scope == "Device"))
        .collect()
}

fn battery_is_discharging_and_low(sysfs: &Path) -> bool {
    if on_ac_power(sysfs) {
        return false;
    }

    let mut unsure = false;
    let mut found_low = false;
    for battery in low_batteries(sysfs) {
        match battery_capacity_percentage(&battery) {
            Ok(level) if level > BATTERY_LOW_CAPACITY_LEVEL => return false,
            Ok(_) => found_low = true,
            Err(_) => unsure = true,
        }
    }
    found_low && !unsure
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_v261_option_surface() {
        assert_eq!(
            parse_options(&["--low".into(), "-vv".into()]),
            Ok(ParseResult::Run(Options {
                action: Action::Low,
                verbose: true,
            }))
        );
        assert_eq!(
            parse_options(&["--verb".into()]),
            Ok(ParseResult::Run(Options {
                action: Action::AcPower,
                verbose: true,
            }))
        );
    }

    #[test]
    fn help_and_version_exit_before_later_errors() {
        assert_eq!(
            parse_options(&["--version".into(), "--unknown".into()]),
            Ok(ParseResult::Exit(VERSION_OUTPUT))
        );
        assert_eq!(
            parse_options(&["-vh".into(), "argument".into()]),
            Ok(ParseResult::Exit(HELP))
        );
    }

    #[test]
    fn reports_v261_option_errors() {
        assert_eq!(
            parse_options(&["--v".into()]).unwrap_err(),
            "systemd-ac-power: option '--v' is ambiguous; possibilities: --version, --verbose"
        );
        assert_eq!(
            parse_options(&["--low=value".into()]).unwrap_err(),
            "systemd-ac-power: option '--low' doesn't allow an argument"
        );
        assert_eq!(
            parse_options(&["argument".into()]).unwrap_err(),
            "This program takes no arguments."
        );
    }
}
