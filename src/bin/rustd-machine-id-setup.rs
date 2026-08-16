// SPDX-License-Identifier: LGPL-2.1-or-later
//! `systemd-machine-id-setup` compatibility utility.
//!
//! Upstream reference: systemd v261 `src/core/machine-id-setup.c`.

use clap::Parser;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const VERSION_STR: &str = "systemd 261 (rustd 0.1.0)";

#[derive(Parser, Debug)]
#[command(
    name = "systemd-machine-id-setup",
    version = VERSION_STR,
    about = "Initialize /etc/machine-id",
    long_about = "Initializes the machine ID in /etc/machine-id from hardware firmware (DMI/device-tree) or random bytes"
)]
struct Cli {
    /// Operate relative to the specified root directory
    #[arg(long, value_name = "PATH")]
    root: Option<PathBuf>,

    /// Operate on the specified disk image
    #[arg(long, value_name = "PATH")]
    image: Option<PathBuf>,

    /// Commit a transient machine ID to disk
    #[arg(long)]
    commit: bool,

    /// Print the machine ID after setup
    #[arg(long)]
    print: bool,
}

fn is_valid_machine_id(s: &str) -> bool {
    let trimmed = s.trim();
    if trimmed.len() != 32 {
        return false;
    }
    if trimmed == "00000000000000000000000000000000"
        || trimmed == "ffffffffffffffffffffffffffffffff"
        || trimmed.eq_ignore_ascii_case("uninitialized")
    {
        return false;
    }
    trimmed.chars().all(|c| c.is_ascii_hexdigit())
}

fn normalize_uuid(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .filter(char::is_ascii_hexdigit)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if is_valid_machine_id(&cleaned) {
        Some(cleaned)
    } else {
        None
    }
}

fn read_dmi_product_uuid() -> Option<String> {
    let paths = [
        "/sys/class/dmi/id/product_uuid",
        "/sys/devices/virtual/dmi/id/product_uuid",
        "/proc/device-tree/system-id",
        "/proc/device-tree/vm,uuid",
    ];

    for p in paths {
        if let Ok(content) = fs::read_to_string(p) {
            if let Some(id) = normalize_uuid(&content) {
                return Some(id);
            }
        }
    }
    None
}

fn generate_random_machine_id() -> anyhow::Result<String> {
    let mut buf = [0u8; 16];

    // Try /dev/urandom first
    if let Ok(mut f) = File::open("/dev/urandom") {
        if f.read_exact(&mut buf).is_ok() {
            return Ok(format_hex_id(&buf));
        }
    }

    // Try libc getrandom
    let res = unsafe { libc::getrandom(buf.as_mut_ptr().cast::<libc::c_void>(), buf.len(), 0) };
    if res == buf.len() as isize {
        return Ok(format_hex_id(&buf));
    }

    // Fallback pseudo-random seed using system time and process ID
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(123_456_789, |d| d.as_nanos());
    let pid = u128::from(std::process::id());
    let mixed = now ^ (pid << 64) ^ 0x5a5a_5a5a_5a5a_5a5a_5a5a_5a5a_5a5a_5a5a;
    let bytes = mixed.to_le_bytes();
    Ok(format_hex_id(&bytes))
}

fn format_hex_id(bytes: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn resolve_target_file(root: Option<&Path>) -> PathBuf {
    if let Some(r) = root {
        r.join("etc").join("machine-id")
    } else {
        PathBuf::from("/etc/machine-id")
    }
}

fn write_machine_id_file(path: &Path, machine_id: &str) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Write to a temporary file in the same directory then rename for atomic update
    let temp_path = path.with_extension(format!("tmp-{}", std::process::id()));
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = file.set_permissions(fs::Permissions::from_mode(0o444));
        }
        writeln!(file, "{machine_id}")?;
        file.sync_all()?;
    }

    if fs::rename(&temp_path, path).is_err() {
        // If rename fails (e.g. cross-device or permission), try direct write
        let _ = fs::remove_file(&temp_path);
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        writeln!(file, "{machine_id}")?;
        file.sync_all()?;
    }

    Ok(())
}

fn check_mountpoint(path: &Path) -> bool {
    if let Ok(mounts) = fs::read_to_string("/proc/mounts") {
        let path_str = path.to_string_lossy();
        for line in mounts.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 && parts[1] == path_str {
                return true;
            }
        }
    }
    false
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let target_path = resolve_target_file(cli.root.as_deref());

    // Check if valid machine-id exists already
    let existing_content = fs::read_to_string(&target_path).ok();
    let is_existing_valid = existing_content
        .as_deref()
        .is_some_and(|s| is_valid_machine_id(s.trim()));

    if cli.commit && check_mountpoint(&target_path) {
        // Read transient machine ID
        if let Some(ref current_id) = existing_content {
            let trimmed = current_id.trim();
            if is_valid_machine_id(trimmed) {
                // Try unmounting transient mount
                #[cfg(unix)]
                unsafe {
                    let c_path =
                        std::ffi::CString::new(target_path.to_string_lossy().as_bytes()).unwrap();
                    libc::umount2(c_path.as_ptr(), libc::MNT_DETACH);
                }
                write_machine_id_file(&target_path, trimmed)?;
                println!("Committed machine ID {trimmed}.");
                if cli.print {
                    println!("{trimmed}");
                }
                return Ok(());
            }
        }
    }

    if is_existing_valid {
        let machine_id = existing_content.unwrap().trim().to_string();
        if cli.print {
            println!("{machine_id}");
        }
        return Ok(());
    }

    // Attempt to discover from DMI / firmware or generate new
    let machine_id = if let Some(dmi_id) = read_dmi_product_uuid() {
        dmi_id
    } else {
        generate_random_machine_id()?
    };

    write_machine_id_file(&target_path, &machine_id)?;

    if cli.print {
        println!("{machine_id}");
    }

    Ok(())
}
