// SPDX-License-Identifier: LGPL-2.1-or-later
//! `systemd-umount` — Unmount transient mount and automount points.
//!
//! Unmounts file systems established by `systemd-mount` or standard mounts.

use clap::Parser;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader};
use std::path::PathBuf;

const VERSION_OUTPUT: &str = concat!(
    "systemd 261 (261.2-1-arch)\n",
    "+PAM +AUDIT -SELINUX +APPARMOR -IMA +IPE +SMACK +SECCOMP +GCRYPT +GNUTLS +OPENSSL +ACL ",
    "+BLKID +CURL +ELFUTILS +FIDO2 +IDN2 +KMOD +LIBCRYPTSETUP +LIBCRYPTSETUP_PLUGINS +LIBFDISK ",
    "+PCRE2 +PWQUALITY +P11KIT +QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB +ZSTD +BPF_FRAMEWORK +BTF ",
    "+XKBCOMMON +UTMP +LIBARCHIVE\n"
);

#[derive(Parser, Debug)]
#[allow(clippy::struct_excessive_bools)]
#[command(
    name = "systemd-umount",
    about = "Unmount transient mount and automount points",
    version = VERSION_OUTPUT
)]
struct Cli {
    /// Mount points or block devices to unmount
    #[arg(value_name = "WHERE|WHAT", required = true)]
    targets: Vec<String>,

    /// Do not canonicalize path
    #[arg(short = 'c', long = "no-canonicalize")]
    no_canonicalize: bool,

    /// Unmount flag (compatibility alias)
    #[arg(short = 'u', long = "umount")]
    umount: bool,

    /// Do not wait for unit stop
    #[arg(long = "no-block")]
    no_block: bool,

    /// Do not pipe output into a pager
    #[arg(long = "no-pager")]
    no_pager: bool,
}

fn unescape_octal(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let mut octal = String::new();
            for _ in 0..3 {
                if let Some(&digit) = chars.peek() {
                    if matches!(digit, '0'..='7') {
                        if let Some(digit) = chars.next() {
                            octal.push(digit);
                        }
                    } else {
                        break;
                    }
                }
            }
            if octal.len() == 3 {
                if let Ok(byte) = u8::from_str_radix(&octal, 8) {
                    out.push(char::from(byte));
                    continue;
                }
            }
            out.push('\\');
            out.push_str(&octal);
        } else {
            out.push(c);
        }
    }
    out
}

fn find_mountpoint_for_target(target: &str, canonicalize: bool) -> Option<PathBuf> {
    let target_path = if canonicalize {
        fs::canonicalize(target).unwrap_or_else(|_| PathBuf::from(target))
    } else {
        PathBuf::from(target)
    };

    let target_str = target_path.to_string_lossy().into_owned();

    let file = File::open("/proc/self/mountinfo")
        .or_else(|_| File::open("/proc/mounts"))
        .ok()?;
    let reader = BufReader::new(file);

    for line in reader.lines().map_while(Result::ok) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 5 {
            let mp = unescape_octal(parts[4]);
            if mp == target_str {
                return Some(PathBuf::from(mp));
            }
            // Also check device source match
            if let Some(pos) = parts.iter().position(|&p| p == "-") {
                if let Some(src) = parts.get(pos + 2) {
                    let unescaped_src = unescape_octal(src);
                    if unescaped_src == target_str {
                        return Some(PathBuf::from(mp));
                    }
                }
            } else if let Some(src) = parts.first() {
                let unescaped_src = unescape_octal(src);
                if unescaped_src == target_str {
                    return Some(PathBuf::from(mp));
                }
            }
        }
    }

    if target_path.exists() {
        Some(target_path)
    } else {
        None
    }
}

fn main() {
    let cli = Cli::parse();

    let mut had_error = false;

    for target_arg in &cli.targets {
        let Some(mount_point) = find_mountpoint_for_target(target_arg, !cli.no_canonicalize) else {
            eprintln!("rustd-umount: Target '{target_arg}' is not a known mount point or device.");
            had_error = true;
            continue;
        };

        let unit_name = format!(
            "{}.mount",
            mount_point
                .to_string_lossy()
                .trim_start_matches('/')
                .replace('/', "-")
        );

        let Ok(c_path) = CString::new(mount_point.to_string_lossy().as_bytes()) else {
            eprintln!("rustd-umount: Invalid path '{}'", mount_point.display());
            had_error = true;
            continue;
        };

        let ret = unsafe { libc::umount2(c_path.as_ptr(), 0) };
        if ret == 0 {
            println!("Stopped unit {unit_name} for {}", mount_point.display());
        } else {
            // Try lazy unmount if direct unmount failed
            let ret_lazy = unsafe { libc::umount2(c_path.as_ptr(), libc::MNT_DETACH) };
            if ret_lazy == 0 {
                println!(
                    "Stopped unit {unit_name} for {} (detached)",
                    mount_point.display()
                );
            } else {
                let err = io::Error::last_os_error();
                eprintln!(
                    "rustd-umount: Failed to unmount '{}': {err}",
                    mount_point.display()
                );
                had_error = true;
            }
        }
    }

    if had_error {
        std::process::exit(1);
    }
}
