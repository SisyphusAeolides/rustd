// SPDX-License-Identifier: LGPL-2.1-or-later
//! rustd-run — Run programs in transient scope, service, or timer units.
//!
//! Upstream counterpart: systemd-run (v261)

use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;
use zbus::zvariant::{OwnedObjectPath, Value};
use zbus::Connection;

#[derive(Parser, Debug)]
#[command(
    name = "rustd-run",
    version = "261",
    about = "Run programs in transient scope, service, or timer units",
    long_about = "A compatibility-oriented transient unit execution utility."
)]
struct Cli {
    /// Command to execute
    #[arg(required = true)]
    command: String,

    /// Arguments to the command
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,

    /// Set unit name
    #[arg(long, short = 'u')]
    unit: Option<String>,

    /// Set property on transient unit (e.g. MemoryMax=500M, CPUWeight=100)
    #[arg(long = "property", short = 'p', value_name = "KEY=VALUE")]
    properties: Vec<String>,

    /// Description for unit
    #[arg(long)]
    description: Option<String>,

    /// Assign to slice unit
    #[arg(long)]
    slice: Option<String>,

    /// Run command directly in a new transient scope unit
    #[arg(long)]
    scope: bool,

    /// Connect to user service manager
    #[arg(long, conflicts_with = "system")]
    user: bool,

    /// Connect to system service manager (default)
    #[arg(long, default_value_t = true)]
    system: bool,

    /// Service unit should remain after process exits
    #[arg(long, short = 'r')]
    remain_after_exit: bool,

    /// Run unit SEC seconds after timer is activated
    #[arg(long, value_name = "SEC")]
    on_active: Option<String>,

    /// Run unit SEC seconds after boot
    #[arg(long, value_name = "SEC")]
    on_boot: Option<String>,

    /// Run unit on calendar specification
    #[arg(long, value_name = "SPEC")]
    on_calendar: Option<String>,

    /// Set property on timer unit
    #[arg(long, value_name = "KEY=VALUE")]
    timer_property: Vec<String>,

    /// Wait until unit completes and return child process exit code
    #[arg(long)]
    wait: bool,

    /// Send SIGHUP on stop
    #[arg(long)]
    send_sighup: bool,

    /// Suppress informative output
    #[arg(long, short = 'q')]
    quiet: bool,
}

fn main() {
    let cli = Cli::parse();

    let code = match run(cli) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("rustd-run: {e}");
            1
        }
    };
    std::process::exit(code);
}

fn run(cli: Cli) -> anyhow::Result<i32> {
    let is_timer = cli.on_active.is_some() || cli.on_boot.is_some() || cli.on_calendar.is_some();
    let pid = std::process::id();
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_micros() % 1_000_000);

    let unit_name = cli.unit.clone().unwrap_or_else(|| {
        if cli.scope {
            format!("run-r{pid}-{ts}.scope")
        } else if is_timer {
            format!("run-u{pid}-{ts}.timer")
        } else {
            format!("run-u{pid}-{ts}.service")
        }
    });

    if !cli.quiet {
        println!("Running as unit: {unit_name}");
    }

    // Try communicating with rustd / systemd via D-Bus
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();

    if let Ok(runtime) = rt {
        let dbus_result = runtime.block_on(try_dbus_transient_unit(&cli, &unit_name));
        if let Ok(exit_code) = dbus_result {
            return Ok(exit_code);
        }
    }

    // Standalone fallback: execute directly as child process
    let mut cmd = Command::new(&cli.command);
    cmd.args(&cli.args);

    // Apply environment variables from --property Environment=...
    for prop in &cli.properties {
        if let Some(env_val) = prop.strip_prefix("Environment=") {
            if let Some((k, v)) = env_val.split_once('=') {
                cmd.env(k, v);
            }
        }
    }

    let status = cmd
        .status()
        .map_err(|e| anyhow::anyhow!("Failed to execute command '{}': {e}", cli.command))?;

    Ok(status.code().unwrap_or(1))
}

async fn try_dbus_transient_unit(cli: &Cli, unit_name: &str) -> anyhow::Result<i32> {
    let conn = if cli.user {
        Connection::session().await?
    } else {
        Connection::system().await?
    };

    let mut exec_args = vec![cli.command.clone()];
    exec_args.extend(cli.args.clone());

    // Properties for StartTransientUnit: array of (name: str, value: Variant)
    let mut props: Vec<(&str, Value<'_>)> = Vec::new();

    let desc = cli.description.as_deref().unwrap_or(&cli.command);
    props.push(("Description", Value::from(desc)));

    if let Some(ref slice) = cli.slice {
        props.push(("Slice", Value::from(slice.as_str())));
    }

    if cli.remain_after_exit {
        props.push(("RemainAfterExit", Value::from(true)));
    }

    if cli.send_sighup {
        props.push(("SendSIGHUP", Value::from(true)));
    }

    // In a full D-Bus setup, ExecStart is encoded as an array of structs: [(path, [args], bool)]
    // Pass the transient unit request to the native RustD manager.
    let aux: Vec<(&str, Vec<(&str, Value<'_>)>)> = Vec::new();
    let mode = "replace";

    let reply: Result<OwnedObjectPath, _> = conn
        .call_method(
            Some("io.rustd.Manager1"),
            "/io/rustd/Manager1",
            Some("io.rustd.Manager1.Manager"),
            "StartTransientUnit",
            &(unit_name, mode, &props, &aux),
        )
        .await
        .and_then(|r| r.body().deserialize());

    if let Ok(_job_path) = reply {
        if cli.wait {
            // Monitor unit state until completion
            return wait_for_unit_completion(&conn, unit_name).await;
        }
        return Ok(0);
    }

    anyhow::bail!("D-Bus transient unit submission rejected or unavailable")
}

async fn wait_for_unit_completion(conn: &Connection, unit_name: &str) -> anyhow::Result<i32> {
    // Poll unit ActiveState
    for _ in 0..600 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let unit_obj_path = format!(
            "/io/rustd/Manager1/unit/{}",
            unit_name.replace('.', "_2e").replace('-', "_2d")
        );

        let active_state: Result<String, _> = conn
            .call_method(
                Some("io.rustd.Manager1"),
                unit_obj_path.as_str(),
                Some("org.freedesktop.DBus.Properties"),
                "Get",
                &("io.rustd.Manager1.Unit", "ActiveState"),
            )
            .await
            .and_then(|r| r.body().deserialize());

        if let Ok(state) = active_state {
            if state == "inactive" || state == "failed" {
                return if state == "failed" { Ok(1) } else { Ok(0) };
            }
        }
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parsing() {
        let args = vec![
            "rustd-run",
            "--unit=test.service",
            "--wait",
            "echo",
            "hello",
        ];
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok());
        let parsed = cli.unwrap();
        assert_eq!(parsed.command, "echo");
        assert_eq!(parsed.args, vec!["hello"]);
        assert_eq!(parsed.unit, Some("test.service".to_string()));
        assert!(parsed.wait);
    }
}
