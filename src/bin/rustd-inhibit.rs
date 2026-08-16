// SPDX-License-Identifier: LGPL-2.1-or-later
//! rustd-inhibit — Execute a process while taking an inhibitor lock.
//!
//! Upstream counterpart: systemd-inhibit (v261)

use std::fs;
use std::process::Command;

use clap::Parser;
use zbus::zvariant::OwnedFd as ZbusOwnedFd;
use zbus::Connection;

#[derive(Parser, Debug)]
#[command(
    name = "rustd-inhibit",
    version = "261",
    about = "Execute a process while taking an inhibitor lock",
    long_about = "A compatibility-oriented sleep/shutdown inhibitor lock execution utility."
)]
struct Cli {
    /// List active inhibitor locks
    #[arg(long)]
    list: bool,

    /// Colon-separated list of operations to inhibit (shutdown:sleep:idle:handle-power-key:handle-suspend-key:handle-hibernate-key:handle-lid-switch)
    #[arg(long, default_value = "shutdown:sleep:idle")]
    what: String,

    /// Descriptive application name taking the lock
    #[arg(long)]
    who: Option<String>,

    /// Reason for taking the inhibitor lock
    #[arg(long)]
    why: Option<String>,

    /// Lock mode: 'block' (default) or 'delay'
    #[arg(long, default_value = "block")]
    mode: String,

    /// Command to execute while holding the inhibitor lock
    #[arg(value_name = "COMMAND")]
    command: Option<String>,

    /// Arguments to the command
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

#[derive(serde::Deserialize, Debug)]
struct InhibitorRecord {
    what: String,
    who: String,
    why: String,
    mode: String,
    uid: u32,
    pid: u32,
}

fn main() {
    let cli = Cli::parse();

    let code = match run(cli) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("rustd-inhibit: {e}");
            1
        }
    };
    std::process::exit(code);
}

fn run(cli: Cli) -> anyhow::Result<i32> {
    if cli.list {
        return cmd_list();
    }

    let cmd = match cli.command {
        Some(ref c) if !c.is_empty() => c.clone(),
        _ => {
            anyhow::bail!("Missing command to execute. Run 'rustd-inhibit --help' for usage.");
        }
    };

    let who = cli.who.clone().unwrap_or_else(|| cmd.clone());
    let why = cli.why.clone().unwrap_or_else(|| format!("Running {cmd}"));
    let what = &cli.what;
    let mode = &cli.mode;

    // Validate what operations
    validate_what_operations(what)?;

    // Validate mode
    if mode != "block" && mode != "delay" {
        anyhow::bail!("Invalid inhibitor mode '{mode}'. Expected 'block' or 'delay'.");
    }

    // Try to acquire inhibitor lock via D-Bus org.freedesktop.login1
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();

    let _lock_fd = if let Ok(runtime) = rt {
        runtime.block_on(try_acquire_inhibitor_lock(what, &who, &why, mode))
    } else {
        None
    };

    // Spawn child command
    let mut child = Command::new(&cmd);
    child.args(&cli.args);

    let status = child
        .status()
        .map_err(|e| anyhow::anyhow!("Failed to execute command '{cmd}': {e}"))?;

    Ok(status.code().unwrap_or(1))
}

fn validate_what_operations(what: &str) -> anyhow::Result<()> {
    let valid_ops = [
        "shutdown",
        "sleep",
        "idle",
        "handle-power-key",
        "handle-suspend-key",
        "handle-hibernate-key",
        "handle-lid-switch",
    ];

    for op in what.split(':') {
        let op_trimmed = op.trim();
        if !op_trimmed.is_empty() && !valid_ops.contains(&op_trimmed) {
            anyhow::bail!(
                "Unknown operation '{op_trimmed}' in --what. Valid: {}",
                valid_ops.join(", ")
            );
        }
    }
    Ok(())
}

async fn try_acquire_inhibitor_lock(
    what: &str,
    who: &str,
    why: &str,
    mode: &str,
) -> Option<ZbusOwnedFd> {
    let conn = Connection::system().await.ok()?;

    let reply = conn
        .call_method(
            Some("org.freedesktop.login1"),
            "/org/freedesktop/login1",
            Some("org.freedesktop.login1.Manager"),
            "Inhibit",
            &(what, who, why, mode),
        )
        .await
        .ok()?;

    let fd: Result<ZbusOwnedFd, _> = reply.body().deserialize();
    fd.ok()
}

fn cmd_list() -> anyhow::Result<i32> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let mut inhibitors: Vec<InhibitorRecord> = Vec::new();

    let dbus_res = rt.block_on(async {
        let conn = Connection::system().await?;
        let reply = conn
            .call_method(
                Some("org.freedesktop.login1"),
                "/org/freedesktop/login1",
                Some("org.freedesktop.login1.Manager"),
                "ListInhibitors",
                &(),
            )
            .await?;

        // Format is array of structs (what, who, why, mode, uid, pid)
        let list: Vec<(String, String, String, String, u32, u32)> = reply.body().deserialize()?;
        Ok::<_, anyhow::Error>(list)
    });

    if let Ok(list) = dbus_res {
        for (what, who, why, mode, uid, pid) in list {
            inhibitors.push(InhibitorRecord {
                what,
                who,
                why,
                mode,
                uid,
                pid,
            });
        }
    }

    if inhibitors.is_empty() {
        println!(
            "{:<20} {:>5} {:<12} {:>7} {:<25} {:<25} {:<6}",
            "WHO", "UID", "USER", "PID", "WHAT", "WHY", "MODE"
        );
        println!("0 inhibitors listed.");
        return Ok(0);
    }

    println!(
        "{:<20} {:>5} {:<12} {:>7} {:<25} {:<25} {:<6}",
        "WHO", "UID", "USER", "PID", "WHAT", "WHY", "MODE"
    );
    for inh in &inhibitors {
        let user_name = resolve_uid_to_name(inh.uid);
        println!(
            "{:<20} {:>5} {:<12} {:>7} {:<25} {:<25} {:<6}",
            inh.who, inh.uid, user_name, inh.pid, inh.what, inh.why, inh.mode
        );
    }
    println!("{} inhibitors listed.", inhibitors.len());

    Ok(0)
}

fn resolve_uid_to_name(uid: u32) -> String {
    if uid == 0 {
        return "root".to_string();
    }
    if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() >= 3 && fields[2] == uid.to_string() {
                return fields[0].to_string();
            }
        }
    }
    uid.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_what_validation() {
        assert!(validate_what_operations("shutdown:sleep:idle").is_ok());
        assert!(validate_what_operations("handle-power-key:handle-lid-switch").is_ok());
        assert!(validate_what_operations("invalid-operation").is_err());
    }

    #[test]
    fn test_cli_parsing() {
        let args = vec![
            "rustd-inhibit",
            "--what=sleep",
            "--who=backup",
            "--why=Nightly backup",
            "tar",
            "-czf",
            "backup.tar.gz",
            "/home",
        ];
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok());
        let parsed = cli.unwrap();
        assert_eq!(parsed.what, "sleep");
        assert_eq!(parsed.who, Some("backup".to_string()));
        assert_eq!(parsed.why, Some("Nightly backup".to_string()));
        assert_eq!(parsed.command, Some("tar".to_string()));
        assert_eq!(parsed.args, vec!["-czf", "backup.tar.gz", "/home"]);
    }
}
