// SPDX-License-Identifier: LGPL-2.1-or-later
use clap::Parser;
use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

#[derive(Parser, Debug)]
#[command(
    name = "rustd-home-fallback-shell",
    about = "Fallback emergency shell when home directory is inaccessible",
    version,
    long_about = "Emergency fallback shell invoked when a systemd-homed user account logs in while the user's home directory is locked, encrypted, or unmounted."
)]
struct Cli {
    /// Execute a single command string instead of starting an interactive shell
    #[arg(short = 'c', long = "command")]
    command: Option<String>,
}

fn get_current_username(uid: u32) -> String {
    if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 {
                if let Ok(parsed_uid) = parts[2].parse::<u32>() {
                    if parsed_uid == uid {
                        return parts[0].to_string();
                    }
                }
            }
        }
    }
    env::var("USER").unwrap_or_else(|_| uid.to_string())
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let uid = unsafe { libc::getuid() };
    let username = get_current_username(uid);

    let home_fallback = if Path::new("/tmp").is_dir() {
        "/tmp"
    } else {
        "/"
    };
    let _ = env::set_current_dir("/");
    env::set_var("HOME", home_fallback);
    env::set_var("PWD", "/");
    env::set_var("USER", &username);
    env::set_var("LOGNAME", &username);

    let shell = if Path::new("/bin/bash").exists() {
        "/bin/bash"
    } else if Path::new("/bin/sh").exists() {
        "/bin/sh"
    } else {
        "/usr/bin/sh"
    };

    if let Some(cmd_str) = cli.command {
        let status = Command::new(shell).arg("-c").arg(&cmd_str).status()?;
        std::process::exit(status.code().unwrap_or(1));
    }

    eprintln!("System Home Fallback Shell (rustd)");
    eprintln!(
        "User {username} (UID {uid}) home directory is currently not accessible or not unlocked."
    );
    eprintln!("Logging into temporary emergency environment (HOME={home_fallback}, PWD=/).\n");

    let status = Command::new(shell)
        .arg("--norc")
        .status()
        .or_else(|_| Command::new(shell).status())?;

    std::process::exit(status.code().unwrap_or(0));
}
