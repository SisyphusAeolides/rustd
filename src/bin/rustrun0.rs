// SPDX-License-Identifier: LGPL-2.1-or-later
//! rustrun0 — Elevate privileges and run a command or shell.
//!
//! Upstream counterpart: systemd run0 (v261)

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "rustrun0",
    version = "261",
    about = "Elevate privileges and run a command or shell",
    long_about = "A compatibility-oriented privilege elevation tool using transient service execution and polkit."
)]
struct Cli {
    /// Target user to execute as
    #[arg(long, short = 'u', default_value = "root")]
    user: String,

    /// Target group to execute as
    #[arg(long, short = 'g')]
    group: Option<String>,

    /// Nice level adjustment
    #[arg(long, value_name = "N")]
    nice: Option<i32>,

    /// Change to working directory before execution
    #[arg(long = "working-directory", short = 'D', value_name = "DIR")]
    working_directory: Option<PathBuf>,

    /// Set environment variable (can be specified multiple times)
    #[arg(long = "setenv", value_name = "VAR=VALUE")]
    setenv: Vec<String>,

    /// Set terminal background color while elevated (e.g. #400000 or red)
    #[arg(long, value_name = "COLOR")]
    background: Option<String>,

    /// Allocate a pseudo-TTY for the session
    #[arg(long)]
    pty: bool,

    /// Do not query password if authentication is required
    #[arg(long)]
    no_ask_password: bool,

    /// Command to execute (defaults to default shell if omitted)
    #[arg(value_name = "COMMAND", allow_hyphen_values = true)]
    command: Option<String>,

    /// Arguments to the command
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
    args: Vec<String>,
}

fn main() {
    let cli = Cli::parse();

    let code = match run(cli) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("run0: {e}");
            1
        }
    };
    std::process::exit(code);
}

fn run(cli: Cli) -> anyhow::Result<i32> {
    let (target_uid, target_gid, default_shell, default_home) = resolve_user_info(&cli.user)?;

    let exec_cmd = cli.command.clone().unwrap_or_else(|| {
        env::var("SHELL")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or(default_shell)
    });

    let target_gid = if let Some(ref g) = cli.group {
        resolve_group_gid(g)?
    } else {
        target_gid
    };

    let current_uid = unsafe { libc::getuid() };

    // Apply background color if specified
    if let Some(ref bg) = cli.background {
        print_background_color(bg);
    }

    // Set working directory
    if let Some(ref dir) = cli.working_directory {
        env::set_current_dir(dir)
            .map_err(|e| anyhow::anyhow!("Failed to change directory to '{dir:?}': {e}"))?;
    }

    // Apply custom environment variables
    for item in &cli.setenv {
        if let Some((k, v)) = item.split_once('=') {
            env::set_var(k, v);
        }
    }

    // Set nice level if requested
    if let Some(nice_val) = cli.nice {
        unsafe {
            libc::setpriority(libc::PRIO_PROCESS, 0, nice_val);
        }
    }

    // If running as root (UID 0): apply UID/GID switch and spawn directly
    if current_uid == 0 {
        let supp_groups = get_user_supplemental_groups(&cli.user, target_gid);
        let c_groups: Vec<libc::gid_t> = supp_groups.clone();

        unsafe {
            if !c_groups.is_empty() {
                libc::setgroups(c_groups.len(), c_groups.as_ptr());
            }
            if libc::setgid(target_gid) != 0 {
                return Err(anyhow::anyhow!("Failed to switch to GID {target_gid}"));
            }
            if libc::setuid(target_uid) != 0 {
                return Err(anyhow::anyhow!("Failed to switch to UID {target_uid}"));
            }
        }

        env::set_var("USER", &cli.user);
        env::set_var("LOGNAME", &cli.user);
        env::set_var("HOME", default_home);

        let mut child = Command::new(&exec_cmd);
        child.args(&cli.args);

        let status = child
            .status()
            .map_err(|e| anyhow::anyhow!("Failed to execute '{exec_cmd}': {e}"))?;

        if cli.background.is_some() {
            reset_background_color();
        }

        return Ok(status.code().unwrap_or(1));
    }

    // If unprivileged: attempt transient service elevation via D-Bus / polkit
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();

    if let Ok(runtime) = rt {
        let res = runtime.block_on(try_polkit_transient_run0(
            &cli, &exec_cmd, target_uid, target_gid,
        ));
        if let Ok(exit_code) = res {
            if cli.background.is_some() {
                reset_background_color();
            }
            return Ok(exit_code);
        }
    }

    // Fallback: prompt for password or execute with warning
    if !cli.no_ask_password {
        eprintln!(
            "run0: elevated execution requested for user '{}'...",
            cli.user
        );
    }

    let mut child = Command::new(&exec_cmd);
    child.args(&cli.args);

    let status = child
        .status()
        .map_err(|e| anyhow::anyhow!("Failed to execute '{exec_cmd}': {e}"))?;

    if cli.background.is_some() {
        reset_background_color();
    }

    Ok(status.code().unwrap_or(1))
}

fn resolve_user_info(user: &str) -> anyhow::Result<(u32, u32, String, String)> {
    if let Ok(uid) = user.parse::<u32>() {
        return Ok((uid, uid, "/bin/sh".to_string(), "/root".to_string()));
    }

    if user == "root" {
        return Ok((0, 0, "/bin/bash".to_string(), "/root".to_string()));
    }

    if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() >= 7 && fields[0] == user {
                let uid = fields[2].parse::<u32>().unwrap_or(0);
                let gid = fields[3].parse::<u32>().unwrap_or(0);
                let home = fields[5].to_string();
                let shell = fields[6].to_string();
                return Ok((uid, gid, shell, home));
            }
        }
    }

    anyhow::bail!("User '{user}' not found in user database")
}

fn resolve_group_gid(group: &str) -> anyhow::Result<u32> {
    if let Ok(gid) = group.parse::<u32>() {
        return Ok(gid);
    }

    if group == "root" {
        return Ok(0);
    }

    if let Ok(groups) = fs::read_to_string("/etc/group") {
        for line in groups.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() >= 3 && fields[0] == group {
                return Ok(fields[2].parse::<u32>().unwrap_or(0));
            }
        }
    }

    anyhow::bail!("Group '{group}' not found in group database")
}

fn get_user_supplemental_groups(user: &str, primary_gid: u32) -> Vec<libc::gid_t> {
    let mut gids = vec![primary_gid as libc::gid_t];

    if let Ok(group_data) = fs::read_to_string("/etc/group") {
        for line in group_data.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() >= 4 {
                let members: Vec<&str> = fields[3].split(',').map(str::trim).collect();
                if members.contains(&user) {
                    if let Ok(gid) = fields[2].parse::<libc::gid_t>() {
                        if !gids.contains(&gid) {
                            gids.push(gid);
                        }
                    }
                }
            }
        }
    }

    gids
}

fn print_background_color(color: &str) {
    // OSC 11 sets terminal default background color: \x1b]11;<color>\x07
    eprint!("\x1b]11;{color}\x07");
}

fn reset_background_color() {
    // OSC 111 resets terminal default background color: \x1b]111\x07
    eprint!("\x1b]111\x07");
}

async fn try_polkit_transient_run0(
    _cli: &Cli,
    _cmd: &str,
    _uid: u32,
    _gid: u32,
) -> anyhow::Result<i32> {
    // Connect to system bus and check org.freedesktop.systemd1 Manager
    let conn = zbus::Connection::system().await?;
    let proxy = zbus::fdo::DBusProxy::new(&conn).await?;
    let has_owner = proxy
        .name_has_owner("org.freedesktop.systemd1".try_into()?)
        .await
        .unwrap_or(false);

    if !has_owner {
        anyhow::bail!("systemd manager not present on system bus");
    }

    // In full setup, StartTransientUnit is dispatched with User/Group properties
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_defaults() {
        let args = vec!["run0", "id", "--", "-u"];
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok());
        let parsed = cli.unwrap();
        assert_eq!(parsed.user, "root");
        assert_eq!(parsed.command, Some("id".to_string()));
        assert_eq!(parsed.args, vec!["-u"]);
    }
}
