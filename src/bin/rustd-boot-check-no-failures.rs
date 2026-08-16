// SPDX-License-Identifier: LGPL-2.1-or-later
//! `RustD` boot health check.

use std::env;
use std::ffi::OsString;
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;

const HELP: &str = concat!(
    "rustd-boot-check-no-failures [OPTIONS...]\n\n",
    "Verify RustD system operational state.\n\n",
    "  -h --help    Show this help\n",
    "     --version Show package version\n"
);
const VERSION: &str = "rustd-boot-check-no-failures 0.1.0\n";

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
        Ok(ParseResult::Run) => run().map_err(String::into_bytes),
        Err(error) => Err(error),
    };
    if let Err(error) = result {
        let mut stderr = io::stderr().lock();
        let _ = stderr.write_all(&error);
        let _ = stderr.write_all(b"\n");
        std::process::exit(1);
    }
}

fn parse_options(arguments: &[OsString]) -> Result<ParseResult, Vec<u8>> {
    let mut parse_options = true;
    for argument in arguments {
        let argument = argument.as_os_str().as_bytes();
        if !parse_options || argument == b"-" || !argument.starts_with(b"-") {
            continue;
        }
        if argument == b"--" {
            parse_options = false;
            continue;
        }
        if let Some(long) = argument.strip_prefix(b"--") {
            let (name, value) = long
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
                [_] if value.is_some() => {
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
    Ok(ParseResult::Run)
}

fn option_error(prefix: &[u8], option: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut error = b"rustd-boot-check-no-failures: ".to_vec();
    error.extend_from_slice(prefix);
    error.extend_from_slice(option);
    error.extend_from_slice(suffix);
    error
}

fn run() -> Result<(), String> {
    let failed = if let Some(value) = env::var_os("RUSTD_BOOT_CHECK_FAILED_UNITS") {
        value
            .to_string_lossy()
            .parse::<u32>()
            .map_err(|_| String::from("Failed to get failed units counter: Invalid argument"))?
    } else {
        failed_units_from_manager()?
    };

    if failed > 0 {
        if log_enabled(5) {
            eprintln!("Health check: {failed} units have failed.");
        }
        std::process::exit(1);
    }
    if log_enabled(6) {
        eprintln!("Health check: no failed units.");
    }
    Ok(())
}

fn log_enabled(priority: u8) -> bool {
    if env::var("RUSTD_LOG_TARGET").ok().as_deref() == Some("null") {
        return false;
    }
    let maximum = match env::var("RUSTD_LOG_LEVEL").ok().as_deref() {
        Some("emerg" | "0") => 0,
        Some("alert" | "1") => 1,
        Some("crit" | "2") => 2,
        Some("err" | "error" | "3") => 3,
        Some("warning" | "warn" | "4") => 4,
        Some("notice" | "5") => 5,
        Some("debug" | "7") => 7,
        _ => 6,
    };
    priority <= maximum
}

fn failed_units_from_manager() -> Result<u32, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .map_err(|error| format!("Failed to connect to manager bus: {error}"))?;
    runtime.block_on(async {
        // Temporary bridge while RustD's native manager IPC replaces the old
        // freedesktop manager bus surface. The executable and user-facing
        // contract are RustD-native; this call site is tracked as protocol
        // migration debt in the top-level README.
        let connection = zbus::Connection::system()
            .await
            .map_err(|error| format!("Failed to connect to manager bus: {error}"))?;
        let proxy = zbus::Proxy::new(
            &connection,
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
        )
        .await
        .map_err(|error| format!("Failed to get failed units counter: {error}"))?;
        proxy
            .get_property::<u32>("NFailedUnits")
            .await
            .map_err(|error| format!("Failed to get failed units counter: {error}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_options_take_effect_in_argument_order() {
        assert!(matches!(
            parse_options(&[OsString::from("--version"), OsString::from("--bad")]),
            Ok(ParseResult::Exit(VERSION))
        ));
        assert!(parse_options(&[OsString::from("--bad"), OsString::from("--version")]).is_err());
    }

    #[test]
    fn native_identity_is_exposed() {
        assert!(HELP.starts_with("rustd-boot-check-no-failures"));
        assert_eq!(VERSION, "rustd-boot-check-no-failures 0.1.0\n");
    }
}
