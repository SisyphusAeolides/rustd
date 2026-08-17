// SPDX-License-Identifier: LGPL-2.1-or-later
//! rustd-stdio-bridge — Forward standard I/O to system or session bus socket.
//!
//! Upstream counterpart: systemd-stdio-bridge (v261)

use std::env;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::thread;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "rustd-stdio-bridge",
    version = "261",
    about = "Forward standard I/O to system or session bus socket",
    long_about = "A compatibility-oriented stdio-to-D-Bus bridge utility for remote administration."
)]
struct Cli {
    /// Connect to user session bus
    #[arg(long, conflicts_with = "system")]
    user: bool,

    /// Connect to system bus (default)
    #[arg(long, default_value_t = true)]
    system: bool,

    /// Connect to specified bus socket path
    #[arg(long, short = 'p')]
    bus_path: Option<PathBuf>,

    /// Connect to container / VM machine bus
    #[arg(long, short = 'M')]
    machine: Option<String>,
}

fn main() {
    let cli = Cli::parse();

    if let Err(err) = run(cli) {
        eprintln!("rustd-stdio-bridge error: {err}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    let socket_path = resolve_socket_path(&cli)?;

    let mut stream = UnixStream::connect(&socket_path).map_err(|e| {
        anyhow::anyhow!(
            "Failed to connect to bus socket at '{}': {e}",
            socket_path.display()
        )
    })?;

    let mut stream_write = stream
        .try_clone()
        .map_err(|e| anyhow::anyhow!("Failed to clone socket handle: {e}"))?;

    // Spawn thread to forward stdin -> socket
    let t1 = thread::spawn(move || {
        let mut stdin = io::stdin().lock();
        let mut buffer = [0u8; 8192];
        loop {
            match stdin.read(&mut buffer) {
                Ok(0) => break, // EOF on stdin
                Ok(n) => {
                    if stream_write.write_all(&buffer[..n]).is_err() {
                        break;
                    }
                    let _ = stream_write.flush();
                }
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        let _ = stream_write.shutdown(std::net::Shutdown::Write);
    });

    // Main thread forwards socket -> stdout
    let mut stdout = io::stdout().lock();
    let mut buffer = [0u8; 8192];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break, // EOF on socket
            Ok(n) => {
                if stdout.write_all(&buffer[..n]).is_err() {
                    break;
                }
                let _ = stdout.flush();
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    let _ = stdout.flush();
    let _ = stream.shutdown(std::net::Shutdown::Both);

    let _ = t1.join();
    Ok(())
}

fn resolve_socket_path(cli: &Cli) -> anyhow::Result<PathBuf> {
    if let Some(ref path) = cli.bus_path {
        return Ok(path.clone());
    }

    if let Some(ref machine) = cli.machine {
        let candidate1 = PathBuf::from(format!("/run/systemd/machines/{machine}"));
        if candidate1.exists() {
            return Ok(candidate1);
        }
        let uid = unsafe { libc::getuid() };
        let candidate2 = PathBuf::from(format!("/run/user/{uid}/systemd/machines/{machine}"));
        if candidate2.exists() {
            return Ok(candidate2);
        }
        anyhow::bail!(
            "Machine bus socket for '{machine}' not found at {} or {}",
            candidate1.display(),
            candidate2.display()
        );
    }

    if cli.user {
        if let Ok(addr) = env::var("DBUS_SESSION_BUS_ADDRESS") {
            if let Some(path) = parse_dbus_unix_path(&addr) {
                return Ok(PathBuf::from(path));
            }
        }

        let uid = unsafe { libc::getuid() };
        let candidates = [
            format!("/run/user/{uid}/bus"),
            format!("/run/user/{uid}/systemd/private"),
        ];

        for c in &candidates {
            let p = Path::new(c);
            if p.exists() {
                return Ok(p.to_path_buf());
            }
        }

        anyhow::bail!(
            "Session bus socket not found in $DBUS_SESSION_BUS_ADDRESS or /run/user/{uid}/bus"
        );
    }

    // System bus fallback
    if let Ok(addr) = env::var("DBUS_SYSTEM_BUS_ADDRESS") {
        if let Some(path) = parse_dbus_unix_path(&addr) {
            return Ok(PathBuf::from(path));
        }
    }

    let candidates = [
        "/var/run/dbus/system_bus_socket",
        "/run/dbus/system_bus_socket",
        "/run/systemd/private",
    ];

    for c in &candidates {
        let p = Path::new(c);
        if p.exists() {
            return Ok(p.to_path_buf());
        }
    }

    // Default to standard system bus socket path even if not currently created
    Ok(PathBuf::from("/run/dbus/system_bus_socket"))
}

fn parse_dbus_unix_path(address: &str) -> Option<String> {
    for item in address.split(';') {
        let trimmed = item.trim();
        if trimmed.starts_with("unix:") {
            for kv in trimmed["unix:".len()..].split(',') {
                let kv_trimmed = kv.trim();
                if kv_trimmed.starts_with("path=") {
                    return Some(kv_trimmed["path=".len()..].to_string());
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dbus_unix_path() {
        let addr = "unix:path=/run/user/1000/bus,guid=12345";
        assert_eq!(
            parse_dbus_unix_path(addr),
            Some("/run/user/1000/bus".to_string())
        );

        let multi = "unix:path=/tmp/test.sock;tcp:host=localhost,port=1234";
        assert_eq!(
            parse_dbus_unix_path(multi),
            Some("/tmp/test.sock".to_string())
        );
    }
}
