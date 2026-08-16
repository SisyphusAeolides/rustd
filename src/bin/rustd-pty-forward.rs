// SPDX-License-Identifier: LGPL-2.1-or-later
//! `systemd-pty-forward` compatibility utility.
//!
//! Upstream reference: `src/ptyfwd/pty-forward.c` (systemd v261).

use clap::Parser;
use std::ffi::CString;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

const VERSION_OUTPUT: &str = concat!(
    "systemd 261 (261.2-1-arch)\n",
    "+PAM +AUDIT -SELINUX +APPARMOR -IMA +IPE +SMACK +SECCOMP +GCRYPT +GNUTLS +OPENSSL +ACL ",
    "+BLKID +CURL +ELFUTILS +FIDO2 +IDN2 +KMOD +LIBCRYPTSETUP +LIBCRYPTSETUP_PLUGINS +LIBFDISK ",
    "+PCRE2 +PWQUALITY +P11KIT +QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB +ZSTD +BPF_FRAMEWORK +BTF ",
    "+XKBCOMMON +UTMP +LIBARCHIVE\n"
);

static RUNNING: AtomicBool = AtomicBool::new(true);

#[derive(Parser, Debug)]
#[command(
    name = "systemd-pty-forward",
    about = "Forward terminal I/O bidirectionally to a pseudo-terminal.",
    version = VERSION_OUTPUT
)]
struct Cli {
    /// Path to pseudo-terminal device (e.g. /dev/pts/3)
    #[arg(required = true)]
    pty_path: PathBuf,
}

struct RawTerminalGuard {
    saved_termios: Option<libc::termios>,
}

impl RawTerminalGuard {
    fn new() -> Self {
        unsafe {
            if libc::isatty(libc::STDIN_FILENO) != 1 {
                return Self {
                    saved_termios: None,
                };
            }

            let mut orig: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(libc::STDIN_FILENO, &mut orig) != 0 {
                return Self {
                    saved_termios: None,
                };
            }

            let mut raw = orig;
            raw.c_iflag &= !(libc::IGNBRK
                | libc::BRKINT
                | libc::PARMRK
                | libc::ISTRIP
                | libc::INLCR
                | libc::IGNCR
                | libc::ICRNL
                | libc::IXON);
            raw.c_oflag &= !libc::OPOST;
            raw.c_lflag &= !(libc::ECHO | libc::ECHONL | libc::ICANON | libc::ISIG | libc::IEXTEN);
            raw.c_cflag &= !(libc::CSIZE | libc::PARENB);
            raw.c_cflag |= libc::CS8;
            raw.c_cc[libc::VMIN] = 1;
            raw.c_cc[libc::VTIME] = 0;

            if libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw) == 0 {
                Self {
                    saved_termios: Some(orig),
                }
            } else {
                Self {
                    saved_termios: None,
                }
            }
        }
    }
}

impl Drop for RawTerminalGuard {
    fn drop(&mut self) {
        if let Some(ref orig) = self.saved_termios {
            unsafe {
                let _ = libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, orig);
            }
        }
    }
}

fn sync_window_size(pty_fd: libc::c_int) {
    unsafe {
        if libc::isatty(libc::STDIN_FILENO) == 1 {
            let mut ws: libc::winsize = std::mem::zeroed();
            if libc::ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, &mut ws) == 0 {
                let _ = libc::ioctl(pty_fd, libc::TIOCSWINSZ, &ws);
            }
        }
    }
}

extern "C" fn handle_signal(_sig: libc::c_int) {
    RUNNING.store(false, Ordering::SeqCst);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let cli = match Cli::try_parse_from(args) {
        Ok(parsed) => parsed,
        Err(e) => {
            let _ = e.print();
            std::process::exit(i32::from(e.use_stderr()));
        }
    };

    if !cli.pty_path.exists() {
        eprintln!(
            "Device '{}' does not exist or is not accessible.",
            cli.pty_path.display()
        );
        std::process::exit(1);
    }

    let pty_c_path = match CString::new(cli.pty_path.to_string_lossy().as_bytes()) {
        Ok(p) => p,
        Err(_) => {
            eprintln!("Invalid PTY path.");
            std::process::exit(1);
        }
    };

    let pty_fd = unsafe {
        libc::open(
            pty_c_path.as_ptr(),
            libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
        )
    };

    if pty_fd < 0 {
        let err = io::Error::last_os_error();
        eprintln!(
            "Failed to open PTY device '{}': {}",
            cli.pty_path.display(),
            err
        );
        std::process::exit(1);
    }

    // Set up signal handlers for clean shutdown
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handle_signal as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGHUP, &sa, std::ptr::null_mut());
    }

    sync_window_size(pty_fd);

    let _raw_guard = RawTerminalGuard::new();

    let mut pollfds = [
        libc::pollfd {
            fd: libc::STDIN_FILENO,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: pty_fd,
            events: libc::POLLIN,
            revents: 0,
        },
    ];

    let mut buf = [0_u8; 4096];

    while RUNNING.load(Ordering::Relaxed) {
        let ret = unsafe { libc::poll(pollfds.as_mut_ptr(), 2, 250) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }

        // Stdin -> PTY
        if pollfds[0].revents & libc::POLLIN != 0 {
            let n = unsafe {
                libc::read(
                    libc::STDIN_FILENO,
                    buf.as_mut_ptr().cast::<libc::c_void>(),
                    buf.len(),
                )
            };
            if n <= 0 {
                break;
            }
            unsafe {
                let _ = libc::write(pty_fd, buf.as_ptr().cast::<libc::c_void>(), n as usize);
            }
        }

        // PTY -> Stdout
        if pollfds[1].revents & libc::POLLIN != 0 {
            let n =
                unsafe { libc::read(pty_fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
            if n <= 0 {
                break;
            }
            unsafe {
                let _ = libc::write(
                    libc::STDOUT_FILENO,
                    buf.as_ptr().cast::<libc::c_void>(),
                    n as usize,
                );
            }
        }

        if (pollfds[0].revents | pollfds[1].revents) & (libc::POLLHUP | libc::POLLERR) != 0 {
            break;
        }
    }

    unsafe {
        libc::close(pty_fd);
    }
}
