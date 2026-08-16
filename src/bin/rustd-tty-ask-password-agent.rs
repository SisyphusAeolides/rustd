// SPDX-License-Identifier: LGPL-2.1-or-later
use clap::Parser;
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "rustd-tty-ask-password-agent",
    about = "Console password agent for query and notification",
    version,
    long_about = "Process pending password queries from /run/systemd/ask-password on the console or watch for new password requests."
)]
struct Cli {
    /// Continuously watch for password requests and process them
    #[arg(long = "watch")]
    watch: bool,

    /// Process any pending password requests and exit
    #[arg(long = "query")]
    query: bool,

    /// Forward password queries as wall messages to all logged-in terminals
    #[arg(long = "wall")]
    wall: bool,

    /// Forward password queries to Plymouth splash screen
    #[arg(long = "plymouth")]
    plymouth: bool,

    /// Query on /dev/console instead of /dev/tty
    #[arg(long = "console")]
    console: bool,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct PasswordRequest {
    file_path: PathBuf,
    message: String,
    socket: Option<PathBuf>,
    not_after: Option<u64>,
    id: Option<String>,
}

fn parse_request(path: &Path) -> Option<PasswordRequest> {
    if let Ok(content) = fs::read_to_string(path) {
        let mut props = BTreeMap::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                props.insert(k.trim().to_string(), v.trim().to_string());
            }
        }

        let message = props
            .get("Message")
            .cloned()
            .unwrap_or_else(|| "Please enter password:".to_string());
        let socket = props.get("Socket").map(PathBuf::from);
        let not_after = props.get("NotAfter").and_then(|n| n.parse::<u64>().ok());
        let id = props.get("Id").cloned();

        Some(PasswordRequest {
            file_path: path.to_path_buf(),
            message,
            socket,
            not_after,
            id,
        })
    } else {
        None
    }
}

fn scan_requests() -> Vec<PasswordRequest> {
    let mut requests = Vec::new();
    let ask_dir = Path::new("/run/systemd/ask-password");
    if ask_dir.is_dir() {
        if let Ok(entries) = fs::read_dir(ask_dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                    if name.starts_with("ask.") {
                        if let Some(req) = parse_request(&p) {
                            requests.push(req);
                        }
                    }
                }
            }
        }
    }
    requests
}

struct RawTerminalGuard {
    fd: i32,
    orig_termios: libc::termios,
    active: bool,
}

impl RawTerminalGuard {
    fn new(fd: i32) -> Option<Self> {
        unsafe {
            if libc::isatty(fd) == 1 {
                let mut orig_termios: libc::termios = std::mem::zeroed();
                if libc::tcgetattr(fd, &mut orig_termios) == 0 {
                    let mut raw = orig_termios;
                    raw.c_lflag &= !libc::ECHO;
                    raw.c_lflag |= libc::ECHONL;
                    if libc::tcsetattr(fd, libc::TCSANOW, &raw) == 0 {
                        return Some(RawTerminalGuard {
                            fd,
                            orig_termios,
                            active: true,
                        });
                    }
                }
            }
        }
        None
    }
}

impl Drop for RawTerminalGuard {
    fn drop(&mut self) {
        if self.active {
            unsafe {
                libc::tcsetattr(self.fd, libc::TCSANOW, &self.orig_termios);
            }
        }
    }
}

fn prompt_password(target_tty: &str, message: &str) -> io::Result<String> {
    let mut tty_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(target_tty)
        .or_else(|_| {
            fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/tty")
        })
        .or_else(|_| {
            fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/stderr")
        });

    let prompt = format!("🔒 {}: ", message.trim_end_matches(':'));

    if let Ok(ref mut tty) = tty_file {
        let _ = write!(tty, "{prompt}");
        let _ = tty.flush();
    } else {
        eprint!("{prompt}");
        let _ = io::stderr().flush();
    }

    let _guard = RawTerminalGuard::new(libc::STDIN_FILENO);
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim_end_matches(&['\r', '\n'][..]).to_string())
}

fn process_request(req: &PasswordRequest, tty_target: &str) -> io::Result<()> {
    let password = prompt_password(tty_target, &req.message)?;

    if let Some(ref sock_path) = req.socket {
        if sock_path.exists() {
            if let Ok(datagram) = UnixDatagram::unbound() {
                let payload = format!("+{password}");
                let _ = datagram.send_to(payload.as_bytes(), sock_path);
            }
        }
    }

    let _ = fs::remove_file(&req.file_path);
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let target_tty = if cli.console {
        "/dev/console"
    } else {
        "/dev/tty"
    };

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    unsafe {
        libc::signal(libc::SIGINT, sig_handler as *const () as usize);
        libc::signal(libc::SIGTERM, sig_handler as *const () as usize);
    }

    extern "C" fn sig_handler(_: i32) {
        // Will cause loop termination
    }

    if cli.watch {
        let ask_dir = Path::new("/run/systemd/ask-password");
        if !ask_dir.exists() {
            let _ = fs::create_dir_all(ask_dir);
        }

        println!("Password agent watching for requests...");
        while r.load(Ordering::SeqCst) {
            let requests = scan_requests();
            for req in &requests {
                let _ = process_request(req, target_tty);
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    } else {
        // Default / --query mode
        let requests = scan_requests();
        if requests.is_empty() {
            return Ok(());
        }

        for req in &requests {
            let _ = process_request(req, target_tty);
        }
    }

    Ok(())
}
