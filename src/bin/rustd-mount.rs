// SPDX-License-Identifier: LGPL-2.1-or-later
//! `systemd-mount` — Establish transient mount or automount units.
//!
//! Mounts block devices, partitions, or disk images to target mount points
//! or lists available storage devices and file systems.

use clap::{Parser, ValueEnum};
use serde::Serialize;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::Command;

const VERSION_OUTPUT: &str = concat!(
    "systemd 261 (261.2-1-arch)\n",
    "+PAM +AUDIT -SELINUX +APPARMOR -IMA +IPE +SMACK +SECCOMP +GCRYPT +GNUTLS +OPENSSL +ACL ",
    "+BLKID +CURL +ELFUTILS +FIDO2 +IDN2 +KMOD +LIBCRYPTSETUP +LIBCRYPTSETUP_PLUGINS +LIBFDISK ",
    "+PCRE2 +PWQUALITY +P11KIT +QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB +ZSTD +BPF_FRAMEWORK +BTF ",
    "+XKBCOMMON +UTMP +LIBARCHIVE\n"
);

#[derive(Parser, Debug)]
#[command(
    name = "systemd-mount",
    about = "Establish transient mount or automount units",
    version = VERSION_OUTPUT
)]
struct Cli {
    /// Device, image, or specification to mount
    #[arg(value_name = "WHAT")]
    what: Option<String>,

    /// Destination mount directory
    #[arg(value_name = "WHERE")]
    where_path: Option<String>,

    /// List available block devices and file systems
    #[arg(short = 'l', long = "list")]
    list: bool,

    /// Filesystem type
    #[arg(short = 't', long = "type", value_name = "TYPE")]
    fs_type: Option<String>,

    /// Mount options
    #[arg(short = 'o', long = "options", value_name = "OPTIONS")]
    options: Option<String>,

    /// Set mount directory owner (user or user:group)
    #[arg(long = "owner", value_name = "USER")]
    owner: Option<String>,

    /// Run filesystem check prior to mounting
    #[arg(long = "fsck", value_name = "BOOL")]
    fsck: Option<bool>,

    /// Description for unit
    #[arg(long = "description", value_name = "TEXT")]
    description: Option<String>,

    /// Establish automount unit instead of direct mount
    #[arg(short = 'A', long = "automount")]
    automount: bool,

    /// Idle timeout for automount in seconds
    #[arg(long = "timeout-idle-sec", value_name = "SEC")]
    timeout_idle_sec: Option<u64>,

    /// Stop and unmount transient unit
    #[arg(short = 'u', long = "umount")]
    umount: bool,

    /// Collect unit after it stopped
    #[arg(short = 'G', long = "collect")]
    collect: bool,

    /// Discover partition table and probe
    #[arg(long = "discover")]
    discover: bool,

    /// Do not wait for unit start
    #[arg(long = "no-block")]
    no_block: bool,

    /// Output data in JSON
    #[arg(long = "json", value_name = "MODE")]
    json: Option<JsonMode>,

    /// Equivalent to --json=pretty
    #[arg(short = 'j')]
    json_short: bool,

    /// Do not pipe output into a pager
    #[arg(long = "no-pager")]
    no_pager: bool,

    /// Do not show headers and footers
    #[arg(long = "no-legend")]
    no_legend: bool,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum JsonMode {
    Off,
    Pretty,
    Short,
}

#[derive(Clone, Debug, Serialize)]
struct BlockDevice {
    node: String,
    model: String,
    label: String,
    uuid: String,
    fstype: String,
    size_bytes: u64,
    size_human: String,
    mountpoint: Option<String>,
}

fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    const TIB: u64 = 1024 * GIB;

    if bytes >= TIB {
        format!("{:.1}T", bytes as f64 / TIB as f64)
    } else if bytes >= GIB {
        format!("{:.1}G", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1}M", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1}K", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes}B")
    }
}

fn probe_fs(dev_path: &Path) -> String {
    let mut file = match File::open(dev_path) {
        Ok(f) => f,
        Err(_) => return "unknown".to_string(),
    };
    let mut buf = [0u8; 4096];
    let n = file.read(&mut buf).unwrap_or(0);
    if n < 512 {
        return "unknown".to_string();
    }

    if &buf[0..4] == b"hsqs" || &buf[0..4] == b"sqsh" {
        return "squashfs".to_string();
    }
    if &buf[0..6] == b"LUKS\xba\xbe" {
        return "crypto_LUKS".to_string();
    }
    if &buf[0..4] == b"XFSB" {
        return "xfs".to_string();
    }
    if (&buf[54..62] == b"FAT12   " || &buf[54..62] == b"FAT16   ")
        || (n >= 90 && &buf[82..90] == b"FAT32   ")
    {
        return "vfat".to_string();
    }
    if n >= 1028 && &buf[1024..1028] == &[0xe2, 0xf5, 0x6f, 0x0e] {
        return "erofs".to_string();
    }
    if n >= 1082 && buf[1080] == 0x53 && buf[1081] == 0xef {
        return "ext4".to_string();
    }
    if file.seek(SeekFrom::Start(0x10000)).is_ok() {
        let mut btrfs_buf = [0u8; 128];
        if file.read(&mut btrfs_buf).unwrap_or(0) >= 72 && &btrfs_buf[0x40..0x48] == b"_BHRfS_M" {
            return "btrfs".to_string();
        }
    }

    "unknown".to_string()
}

fn get_mount_map() -> io::Result<std::collections::HashMap<String, String>> {
    let file = match File::open("/proc/self/mountinfo") {
        Ok(f) => f,
        Err(_) => File::open("/proc/mounts")?,
    };
    let reader = BufReader::new(file);
    let mut map = std::collections::HashMap::new();

    for line in reader.lines() {
        let line = line?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 5 {
            let mountpoint = parts[4].to_string();
            // Source is usually after '-'
            if let Some(pos) = parts.iter().position(|&p| p == "-") {
                if let Some(src) = parts.get(pos + 2) {
                    map.insert((*src).to_string(), mountpoint);
                }
            } else if let Some(src) = parts.first() {
                map.insert((*src).to_string(), mountpoint);
            }
        }
    }

    Ok(map)
}

fn list_block_devices() -> io::Result<Vec<BlockDevice>> {
    let mut devices = Vec::new();
    let mount_map = get_mount_map().unwrap_or_default();
    let block_dir = Path::new("/sys/class/block");

    if !block_dir.exists() {
        return Ok(devices);
    }

    for entry in fs::read_dir(block_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();

        // Skip ram, loop, dm if desired, or keep all real disks and partitions
        if name.starts_with("ram") {
            continue;
        }

        let dev_node = PathBuf::from(format!("/dev/{name}"));
        let sys_path = entry.path();

        let size_sectors: u64 = fs::read_to_string(sys_path.join("size"))
            .unwrap_or_default()
            .trim()
            .parse()
            .unwrap_or(0);
        let size_bytes = size_sectors * 512;

        let model = fs::read_to_string(sys_path.join("device/model"))
            .unwrap_or_default()
            .trim()
            .to_string();

        // Check symlinks in /dev/disk/by-uuid and /dev/disk/by-label
        let mut uuid = String::new();
        if let Ok(by_uuid) = fs::read_dir("/dev/disk/by-uuid") {
            for link in by_uuid.flatten() {
                if let Ok(target) = fs::read_link(link.path()) {
                    if target.file_name() == Some(entry.file_name().as_os_str()) {
                        uuid = link.file_name().to_string_lossy().to_string();
                        break;
                    }
                }
            }
        }

        let mut label = String::new();
        if let Ok(by_label) = fs::read_dir("/dev/disk/by-label") {
            for link in by_label.flatten() {
                if let Ok(target) = fs::read_link(link.path()) {
                    if target.file_name() == Some(entry.file_name().as_os_str()) {
                        label = link.file_name().to_string_lossy().to_string();
                        break;
                    }
                }
            }
        }

        let fstype = if dev_node.exists() {
            probe_fs(&dev_node)
        } else {
            "unknown".to_string()
        };

        let mountpoint = mount_map.get(&dev_node.display().to_string()).cloned();

        devices.push(BlockDevice {
            node: dev_node.display().to_string(),
            model: if model.is_empty() {
                "-".to_string()
            } else {
                model
            },
            label: if label.is_empty() {
                "-".to_string()
            } else {
                label
            },
            uuid: if uuid.is_empty() {
                "-".to_string()
            } else {
                uuid
            },
            fstype,
            size_bytes,
            size_human: format_bytes(size_bytes),
            mountpoint,
        });
    }

    devices.sort_by(|a, b| a.node.cmp(&b.node));
    Ok(devices)
}

fn print_block_table(devices: &[BlockDevice], no_legend: bool) {
    if !no_legend {
        println!(
            "{:<16} {:<18} {:<12} {:<8} {:<8} {:<24}",
            "NODE", "MODEL", "LABEL", "FSTYPE", "SIZE", "MOUNTPOINT"
        );
        println!("{:-<90}", "");
    }

    for d in devices {
        let mp = d.mountpoint.as_deref().unwrap_or("-");
        println!(
            "{:<16} {:<18} {:<12} {:<8} {:<8} {:<24}",
            d.node, d.model, d.label, d.fstype, d.size_human, mp
        );
    }

    if !no_legend && devices.is_empty() {
        println!("(No block devices found)");
    }
}

fn resolve_device(spec: &str) -> PathBuf {
    if let Some(uuid) = spec.strip_prefix("UUID=") {
        let p = PathBuf::from(format!("/dev/disk/by-uuid/{}", uuid.trim_matches('"')));
        if p.exists() {
            return fs::canonicalize(&p).unwrap_or(p);
        }
    } else if let Some(label) = spec.strip_prefix("LABEL=") {
        let p = PathBuf::from(format!("/dev/disk/by-label/{}", label.trim_matches('"')));
        if p.exists() {
            return fs::canonicalize(&p).unwrap_or(p);
        }
    }
    let p = PathBuf::from(spec);
    fs::canonicalize(&p).unwrap_or(p)
}

fn handle_mount(
    what: &str,
    where_path: Option<&str>,
    fs_type: Option<&str>,
    options: Option<&str>,
    owner: Option<&str>,
    _automount: bool,
) -> anyhow::Result<()> {
    let dev = resolve_device(what);
    if !dev.exists() {
        return Err(anyhow::anyhow!("Device or file '{what}' does not exist"));
    }

    let target_dir = match where_path {
        Some(w) => PathBuf::from(w),
        None => {
            let name = dev.file_name().and_then(|s| s.to_str()).unwrap_or("mount");

            PathBuf::from(format!("/run/media/system/{name}"))
        }
    };

    if !target_dir.exists() {
        fs::create_dir_all(&target_dir)?;
    }

    if let Some(user_spec) = owner {
        let mut chown_cmd = Command::new("chown");
        chown_cmd.arg(user_spec);
        chown_cmd.arg(&target_dir);
        let _ = chown_cmd.status();
    }

    let unit_name = format!(
        "{}.mount",
        target_dir
            .to_string_lossy()
            .trim_start_matches('/')
            .replace('/', "-")
    );

    let mut cmd = Command::new("mount");
    if let Some(t) = fs_type {
        cmd.arg("-t").arg(t);
    }
    if let Some(o) = options {
        cmd.arg("-o").arg(o);
    }
    cmd.arg(&dev);
    cmd.arg(&target_dir);

    let status = cmd.status()?;
    if status.success() {
        println!("Started unit {} for {}", unit_name, target_dir.display());
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "mount command failed with exit status {status}"
        ))
    }
}

fn handle_umount(what: &str) -> anyhow::Result<()> {
    let target = resolve_device(what);
    let c_tgt = CString::new(target.to_string_lossy().as_bytes()).unwrap();

    let ret = unsafe { libc::umount2(c_tgt.as_ptr(), 0) };
    if ret == 0 {
        println!("Successfully unmounted {}", target.display());
        Ok(())
    } else {
        let err = io::Error::last_os_error();
        Err(anyhow::anyhow!(
            "Failed to unmount {}: {}",
            target.display(),
            err
        ))
    }
}

fn main() {
    let cli = Cli::parse();

    let json_mode = if cli.json_short {
        Some(JsonMode::Pretty)
    } else {
        cli.json
    };

    if cli.list {
        match list_block_devices() {
            Ok(devices) => match json_mode {
                Some(JsonMode::Pretty) => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&devices).unwrap_or_default()
                    );
                }
                Some(JsonMode::Short) => {
                    println!("{}", serde_json::to_string(&devices).unwrap_or_default());
                }
                _ => {
                    print_block_table(&devices, cli.no_legend);
                }
            },
            Err(e) => {
                eprintln!("systemd-mount: Failed to list block devices: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    if cli.umount {
        let what = match cli.what.as_deref() {
            Some(w) => w,
            None => {
                eprintln!("systemd-mount: Missing target to unmount.");
                std::process::exit(1);
            }
        };
        if let Err(e) = handle_umount(what) {
            eprintln!("systemd-mount: Umount failed: {e}");
            std::process::exit(1);
        }
        return;
    }

    let what = match cli.what.as_deref() {
        Some(w) => w,
        None => {
            eprintln!("systemd-mount: No device or mountpoint specified. Use --help for usage.");
            std::process::exit(1);
        }
    };

    if let Err(e) = handle_mount(
        what,
        cli.where_path.as_deref(),
        cli.fs_type.as_deref(),
        cli.options.as_deref(),
        cli.owner.as_deref(),
        cli.automount,
    ) {
        eprintln!("systemd-mount: {e}");
        std::process::exit(1);
    }
}
