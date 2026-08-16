// SPDX-License-Identifier: LGPL-2.1-or-later

use std::env;
use std::fs;
use std::process::{exit, Command, ExitStatus};

const VERSION: &str = "systemd 261 (261.2-1-arch)";

fn main() {
    if let Err(error) = run() {
        eprintln!("systemd-sulogin-shell: {error}");
        exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.first().is_some_and(|arg| arg == "--version") {
        println!("{VERSION}");
        return Ok(());
    }
    if args
        .first()
        .is_some_and(|arg| arg == "-h" || arg == "--help")
    {
        println!("systemd-sulogin-shell [MODE]");
        return Ok(());
    }

    let mode = args.first().map_or("", String::as_str);
    print_mode(mode);

    let force = env_force().or_else(cmdline_force).unwrap_or(false);
    let sulogin = env::var("RUSTD_SULOGIN").unwrap_or_else(|_| "/usr/bin/sulogin".to_owned());
    let systemctl = env::var("RUSTD_SYSTEMCTL").unwrap_or_else(|_| "systemctl".to_owned());

    loop {
        let mut command = Command::new(&sulogin);
        if force {
            command.arg("--force");
        }
        wait_for_sulogin(command.status(), &sulogin)?;

        if !run_command(&systemctl, &["daemon-reload"])? {
            eprintln!(
                "Failed to reload system manager configuration; falling back to the single-user shell."
            );
            continue;
        }

        let target = if in_initrd() {
            "initrd.target"
        } else {
            "default.target"
        };
        let state = active_state(&systemctl, target)?;
        if state != "inactive" {
            eprintln!(
                "{target} is not inactive. Please review the {target} setting; falling back to the single-user shell."
            );
            continue;
        }

        if run_command(&systemctl, &["isolate", target])? {
            return Ok(());
        }
        eprintln!("Failed to start {target}; falling back to the single-user shell.");
    }
}

fn print_mode(mode: &str) {
    println!(
        "You are in {mode} mode. After logging in, type \"journalctl -xb\" to view\n\
         system logs, \"systemctl reboot\" to reboot, or \"exit\"\n\
         to continue bootup."
    );
}

fn env_force() -> Option<bool> {
    env::var("SYSTEMD_SULOGIN_FORCE")
        .ok()
        .and_then(|value| parse_boolean(&value))
}

fn cmdline_force() -> Option<bool> {
    let path = env::var("RUSTD_PROC_CMDLINE").unwrap_or_else(|_| "/proc/cmdline".to_owned());
    let cmdline = fs::read_to_string(path).ok()?;
    for word in cmdline.split_whitespace() {
        if word == "SYSTEMD_SULOGIN_FORCE" {
            return Some(true);
        }
        if let Some(value) = word.strip_prefix("SYSTEMD_SULOGIN_FORCE=") {
            return parse_boolean(value);
        }
    }
    None
}

fn parse_boolean(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "yes" | "y" | "true" | "t" | "on" => Some(true),
        "0" | "no" | "n" | "false" | "f" | "off" => Some(false),
        _ => None,
    }
}

fn in_initrd() -> bool {
    env::var_os("RUSTD_INITRD").is_some() || std::path::Path::new("/etc/initrd-release").exists()
}

fn wait_for_sulogin(
    status: Result<ExitStatus, std::io::Error>,
    program: &str,
) -> Result<(), String> {
    match status {
        Ok(_) => Ok(()),
        Err(error) => Err(format!("Failed to execute {program}: {error}")),
    }
}

fn run_command(program: &str, args: &[&str]) -> Result<bool, String> {
    Command::new(program)
        .args(args)
        .status()
        .map(|status| status.success())
        .map_err(|error| format!("Failed to execute {program}: {error}"))
}

fn active_state(program: &str, target: &str) -> Result<String, String> {
    let output = Command::new(program)
        .args(["show", "--property=ActiveState", "--value", target])
        .output()
        .map_err(|error| format!("Failed to query {target}: {error}"))?;
    if !output.status.success() {
        return Err(format!("Failed to retrieve unit state for {target}."));
    }
    String::from_utf8(output.stdout)
        .map(|state| state.trim().to_owned())
        .map_err(|_| format!("Manager returned non-UTF-8 state for {target}."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boolean_parser_matches_systemd_spellings() {
        for value in ["1", "yes", "TRUE", "on"] {
            assert_eq!(parse_boolean(value), Some(true));
        }
        for value in ["0", "no", "FALSE", "off"] {
            assert_eq!(parse_boolean(value), Some(false));
        }
        assert_eq!(parse_boolean("maybe"), None);
    }
}
