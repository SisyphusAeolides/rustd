// SPDX-License-Identifier: LGPL-2.1-or-later
//! `RustD` quota-check helper.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{exit, Command};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Mode {
    #[default]
    Auto,
    Force,
    Skip,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("rustd-quotacheck: {error}");
        exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() > 1 {
        return Err(String::from("This program expects one or no arguments."));
    }

    let mut mode = Mode::Auto;
    merge_cmdline(&mut mode);
    merge_credential(&mut mode);

    if mode == Mode::Skip {
        return Ok(());
    }

    if mode == Mode::Auto && !trigger_path().exists() {
        return Ok(());
    }

    let program = env::var_os("RUSTD_QUOTACHECK")
        .map_or_else(|| PathBuf::from("/usr/sbin/quotacheck"), PathBuf::from);
    let mut command = Command::new(&program);
    if let Some(path) = args.first() {
        command.arg("-nug").arg(path);
    } else {
        command.arg("-anug");
    }

    let status = command
        .status()
        .map_err(|error| format!("Failed to execute {}: {error}", program.display()))?;
    if !status.success() {
        return Err(format!("{} failed with {status}.", program.display()));
    }
    Ok(())
}

fn trigger_path() -> PathBuf {
    env::var_os("RUSTD_QUOTACHECK_TRIGGER")
        .map_or_else(|| PathBuf::from("/run/rustd/quotacheck"), PathBuf::from)
}

fn cmdline_path() -> PathBuf {
    env::var_os("RUSTD_PROC_CMDLINE").map_or_else(|| PathBuf::from("/proc/cmdline"), PathBuf::from)
}

fn parse_mode(value: &str) -> Option<Mode> {
    match value.trim() {
        "auto" => Some(Mode::Auto),
        "force" => Some(Mode::Force),
        "skip" => Some(Mode::Skip),
        _ => None,
    }
}

fn merge_cmdline(mode: &mut Mode) {
    let Ok(text) = fs::read_to_string(cmdline_path()) else {
        return;
    };
    for word in text.split_whitespace() {
        if word == "forcequotacheck" {
            *mode = Mode::Force;
            continue;
        }
        let Some(value) = word.strip_prefix("quotacheck.mode=") else {
            continue;
        };
        if let Some(parsed) = parse_mode(value) {
            *mode = parsed;
        } else {
            eprintln!("rustd-quotacheck: Invalid quotacheck.mode= value, ignoring: {value}");
        }
    }
}

fn merge_credential(mode: &mut Mode) {
    let Some(directory) = env::var_os("CREDENTIALS_DIRECTORY") else {
        return;
    };
    let path = Path::new(&directory).join("quotacheck.mode");
    let Ok(value) = fs::read_to_string(path) else {
        return;
    };
    let value = value.trim_end_matches(['\r', '\n']);
    if let Some(parsed) = parse_mode(value) {
        *mode = parsed;
    } else {
        eprintln!("rustd-quotacheck: Invalid 'quotacheck.mode' credential, ignoring: {value}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_upstream_modes() {
        assert_eq!(parse_mode("auto"), Some(Mode::Auto));
        assert_eq!(parse_mode("force"), Some(Mode::Force));
        assert_eq!(parse_mode("skip"), Some(Mode::Skip));
        assert_eq!(parse_mode("yes"), None);
    }

    #[test]
    fn credential_precedence_can_override_cmdline() {
        let root = std::env::temp_dir().join(format!("rustd-quotacheck-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let cmdline = root.join("cmdline");
        fs::write(&cmdline, "quotacheck.mode=force").unwrap();
        fs::write(root.join("quotacheck.mode"), "skip\n").unwrap();

        let old_cmdline = env::var_os("RUSTD_PROC_CMDLINE");
        let old_credentials = env::var_os("CREDENTIALS_DIRECTORY");
        env::set_var("RUSTD_PROC_CMDLINE", &cmdline);
        env::set_var("CREDENTIALS_DIRECTORY", &root);

        let mut mode = Mode::Auto;
        merge_cmdline(&mut mode);
        merge_credential(&mut mode);

        match old_cmdline {
            Some(value) => env::set_var("RUSTD_PROC_CMDLINE", value),
            None => env::remove_var("RUSTD_PROC_CMDLINE"),
        }
        match old_credentials {
            Some(value) => env::set_var("CREDENTIALS_DIRECTORY", value),
            None => env::remove_var("CREDENTIALS_DIRECTORY"),
        }
        let _ = fs::remove_dir_all(root);

        assert_eq!(mode, Mode::Skip);
    }
}
