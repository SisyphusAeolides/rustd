use clap::Parser;
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(
    name = "rustd-ask-password",
    about = "Query password or passphrase from user or ask-password agents",
    version,
    long_about = "Query the user for a system password or passphrase via the TTY or notify system ask-password agents."
)]
struct Cli {
    /// Password prompt message to display to the user
    message: Option<String>,

    /// Icon name to use for graphical agents
    #[arg(long = "icon")]
    icon: Option<String>,

    /// Identifier string for credential or password request
    #[arg(long = "id")]
    id: Option<String>,

    /// Store the entered passphrase in kernel keyring
    #[arg(long = "keyring", default_value = "false")]
    keyring: bool,

    /// Timeout in seconds before giving up (0 for infinite)
    #[arg(long = "timeout", default_value = "0")]
    timeout: u64,

    /// Echo entered characters without masking
    #[arg(long = "echo")]
    echo: bool,

    /// Do not ask on console TTY, only query agents
    #[arg(long = "no-tty")]
    no_tty: bool,

    /// Accept cached credentials if available
    #[arg(long = "accept-cached")]
    accept_cached: bool,

    /// Prompt multiple times
    #[arg(long = "multiple")]
    multiple: bool,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct PasswordQuery {
    path: PathBuf,
    message: String,
    socket: Option<PathBuf>,
    pid: Option<u32>,
    id: Option<String>,
}

fn parse_ask_file(path: &Path) -> Option<PasswordQuery> {
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
        let pid = props.get("PID").and_then(|p| p.parse::<u32>().ok());
        let id = props.get("Id").cloned();

        Some(PasswordQuery {
            path: path.to_path_buf(),
            message,
            socket,
            pid,
            id,
        })
    } else {
        None
    }
}

fn scan_pending_queries() -> Vec<PasswordQuery> {
    let mut queries = Vec::new();
    let ask_dir = Path::new("/run/systemd/ask-password");
    if ask_dir.is_dir() {
        if let Ok(entries) = fs::read_dir(ask_dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if let Some(file_name) = p.file_name().and_then(|n| n.to_str()) {
                    if file_name.starts_with("ask.") {
                        if let Some(q) = parse_ask_file(&p) {
                            queries.push(q);
                        }
                    }
                }
            }
        }
    }
    queries
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

fn read_password_secure(prompt: &str, echo: bool) -> io::Result<String> {
    let mut tty_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .or_else(|_| {
            fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/stderr")
        });

    if let Ok(ref mut tty) = tty_file {
        let _ = write!(tty, "{prompt}");
        let _ = tty.flush();
    } else {
        eprint!("{prompt}");
        let _ = io::stderr().flush();
    }

    let password = if echo {
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        line.trim_end_matches(&['\r', '\n'][..]).to_string()
    } else {
        let _guard = RawTerminalGuard::new(libc::STDIN_FILENO);
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        line.trim_end_matches(&['\r', '\n'][..]).to_string()
    };

    Ok(password)
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let queries = scan_pending_queries();

    let default_message = cli.message.clone().unwrap_or_else(|| {
        if let Some(first) = queries.first() {
            first.message.clone()
        } else {
            "Password:".to_string()
        }
    });

    let prompt_text = format!("🔒 {} ", default_message.trim_end_matches(':'));
    let prompt_full = format!("{}: ", prompt_text.trim());

    let password = if !cli.no_tty {
        read_password_secure(&prompt_full, cli.echo)?
    } else {
        String::new()
    };

    // Forward password response to pending ask-password sockets
    for q in &queries {
        if let Some(ref sock_path) = q.socket {
            if sock_path.exists() {
                if let Ok(datagram) = UnixDatagram::unbound() {
                    let payload = format!("+{password}");
                    let _ = datagram.send_to(payload.as_bytes(), sock_path);
                }
            }
        }
    }

    // Output password to stdout for pipeline consumers
    println!("{password}");

    Ok(())
}
