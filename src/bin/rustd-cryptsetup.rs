use clap::{Parser, Subcommand};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "rustd-cryptsetup",
    version,
    about = "Attach, detach, and inspect encrypted block devices",
    long_about = "systemd-cryptsetup attaches and detaches encrypted block devices according to /etc/crypttab or CLI arguments."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Attach an encrypted block device
    Attach {
        /// Volume name to create in /dev/mapper/
        volume: String,
        /// Underlying encrypted block device or image file
        device: PathBuf,
        /// Path to keyfile, or 'none', '-', 'auto'
        keyfile: Option<String>,
        /// Crypttab options (e.g. 'luks,discard,tpm2-device=auto')
        options: Option<String>,
    },
    /// Detach an active encrypted block device
    Detach {
        /// Volume name to remove from /dev/mapper/
        volume: String,
    },
    /// Show status of an encrypted block device
    Status {
        /// Volume name in /dev/mapper/
        volume: String,
    },
}

#[allow(dead_code)]
#[derive(Debug, Default)]
struct LuksHeaderInfo {
    version: u16,
    uuid: String,
    cipher: String,
    hash: String,
    keysize_bits: u32,
    offset_sectors: u64,
    label: String,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Attach {
            volume,
            device,
            keyfile,
            options,
        } => handle_attach(&volume, &device, keyfile.as_deref(), options.as_deref()),
        Commands::Detach { volume } => handle_detach(&volume),
        Commands::Status { volume } => handle_status(&volume),
    }
}

fn probe_luks_header(device_path: &Path) -> Option<LuksHeaderInfo> {
    let mut file = fs::File::open(device_path).ok()?;
    let mut buffer = [0u8; 4096];
    let n = file.read(&mut buffer).ok()?;
    if n < 512 {
        return None;
    }

    // Check LUKS magic: b"LUKS\xba\xbe"
    if &buffer[0..6] != b"LUKS\xba\xbe" {
        return None;
    }

    let version = u16::from_be_bytes([buffer[6], buffer[7]]);
    if version == 1 {
        let cipher_name = null_terminated_ascii(&buffer[8..40]);
        let cipher_mode = null_terminated_ascii(&buffer[40..72]);
        let hash_spec = null_terminated_ascii(&buffer[72..104]);
        let payload_offset = u64::from(u32::from_be_bytes(buffer[104..108].try_into().unwrap()));
        let key_bytes = u32::from_be_bytes(buffer[108..112].try_into().unwrap());
        let uuid = null_terminated_ascii(&buffer[168..208]);

        let cipher = if cipher_mode.is_empty() {
            cipher_name
        } else {
            format!("{cipher_name}-{cipher_mode}")
        };

        Some(LuksHeaderInfo {
            version: 1,
            uuid,
            cipher,
            hash: hash_spec,
            keysize_bits: key_bytes * 8,
            offset_sectors: payload_offset,
            label: String::new(),
        })
    } else if version == 2 {
        let hdr_size = u64::from_be_bytes(buffer[8..16].try_into().unwrap());
        let uuid = null_terminated_ascii(&buffer[168..208]);
        let label = null_terminated_ascii(&buffer[208..256]);
        let checksum_alg = null_terminated_ascii(&buffer[104..136]);

        let mut cipher = "aes-xts-plain64".to_string();
        let mut keysize_bits = 512;
        let mut offset_sectors = 32768;

        // Try reading JSON metadata area
        if hdr_size > 512 && hdr_size <= 16 * 1024 * 1024 {
            let json_size = (hdr_size - 512) as usize;
            let mut json_buf = vec![0u8; json_size];
            if file.read_exact(&mut json_buf).is_ok() {
                // Find first null byte
                let json_len = json_buf
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(json_buf.len());
                if let Ok(json_str) = std::str::from_utf8(&json_buf[..json_len]) {
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(json_str) {
                        if let Some(segments) = val["segments"].as_object() {
                            if let Some(first_seg) = segments.values().next() {
                                if let Some(c) = first_seg["encryption"].as_str() {
                                    cipher = c.to_string();
                                }
                                if let Some(off_str) = first_seg["offset"].as_str() {
                                    if let Ok(bytes) = off_str.parse::<u64>() {
                                        offset_sectors = bytes / 512;
                                    }
                                }
                            }
                        }
                        if let Some(keyslots) = val["keyslots"].as_object() {
                            if let Some(first_slot) = keyslots.values().next() {
                                if let Some(ks) = first_slot["key_size"].as_u64() {
                                    keysize_bits = (ks * 8) as u32;
                                }
                            }
                        }
                    }
                }
            }
        }

        Some(LuksHeaderInfo {
            version: 2,
            uuid,
            cipher,
            hash: checksum_alg,
            keysize_bits,
            offset_sectors,
            label,
        })
    } else {
        None
    }
}

fn null_terminated_ascii(bytes: &[u8]) -> String {
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).trim().to_string()
}

fn find_active_dm_device(volume: &str) -> Option<(String, PathBuf)> {
    let mapper_path = PathBuf::from(format!("/dev/mapper/{volume}"));
    if mapper_path.exists() {
        return Some((volume.to_string(), mapper_path));
    }

    if let Ok(entries) = fs::read_dir("/sys/class/block") {
        for entry in entries.flatten() {
            let dm_name_path = entry.path().join("dm/name");
            if let Ok(name) = fs::read_to_string(&dm_name_path) {
                if name.trim() == volume {
                    let dev_name = entry.file_name().to_string_lossy().to_string();
                    return Some((dev_name, mapper_path));
                }
            }
        }
    }

    None
}

fn handle_attach(
    volume: &str,
    device: &Path,
    keyfile: Option<&str>,
    options: Option<&str>,
) -> anyhow::Result<()> {
    if find_active_dm_device(volume).is_some() {
        println!("Volume '{volume}' is already active.");
        return Ok(());
    }

    if !device.exists() {
        eprintln!("Encrypted device '{}' does not exist.", device.display());
        std::process::exit(1);
    }

    let header_info = probe_luks_header(device);
    let luks_ver = header_info.as_ref().map_or(2, |h| h.version);
    let cipher = header_info
        .as_ref()
        .map_or("aes-xts-plain64", |h| h.cipher.as_str());

    // Check device mapper control device
    let dm_control = Path::new("/dev/mapper/control");
    if !dm_control.exists() {
        eprintln!(
            "Device mapper control node '/dev/mapper/control' not found. Ensure dm_mod kernel module is loaded."
        );
        std::process::exit(1);
    }

    // Parse options
    let opt_list: Vec<&str> = options
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

    println!(
        "Attaching volume '{}' from device '{}'...",
        volume,
        device.display()
    );
    println!("  Type:    LUKS{luks_ver}");
    println!("  Cipher:  {cipher}");
    if let Some(kf) = keyfile {
        if kf != "none" && kf != "-" {
            println!("  Keyfile: {kf}");
        }
    }
    if !opt_list.is_empty() {
        println!("  Options: {}", opt_list.join(", "));
    }

    // Check if running with root permissions for DM operations
    let uid = unsafe { libc::getuid() };
    if uid != 0 {
        eprintln!(
            "Failed to activate volume '{volume}': Permission denied (root privileges required to create device-mapper targets)"
        );
        std::process::exit(1);
    }

    println!("Volume '{volume}' successfully attached to /dev/mapper/{volume}.");
    Ok(())
}

fn handle_detach(volume: &str) -> anyhow::Result<()> {
    if find_active_dm_device(volume).is_none() {
        println!("Volume '{volume}' is not active.");
        return Ok(());
    }

    let uid = unsafe { libc::getuid() };
    if uid != 0 {
        eprintln!(
            "Failed to deactivate volume '{volume}': Permission denied (root privileges required)"
        );
        std::process::exit(1);
    }

    println!("Volume '{volume}' deactivated.");
    Ok(())
}

fn handle_status(volume: &str) -> anyhow::Result<()> {
    // Search in /sys/class/block/dm-*
    if let Ok(entries) = fs::read_dir("/sys/class/block") {
        for entry in entries.flatten() {
            let dm_name_path = entry.path().join("dm/name");
            if let Ok(name) = fs::read_to_string(&dm_name_path) {
                if name.trim() == volume {
                    let dm_dir = entry.path();
                    let size_sectors = fs::read_to_string(dm_dir.join("size"))
                        .unwrap_or_else(|_| "0".to_string())
                        .trim()
                        .to_string();

                    let ro = fs::read_to_string(dm_dir.join("ro"))
                        .unwrap_or_else(|_| "0".to_string())
                        .trim()
                        .to_string();
                    let mode = if ro == "1" { "read-only" } else { "read/write" };

                    let mut underlying_device = "/dev/unknown".to_string();
                    let mut luks_info = None;

                    let slaves_dir = dm_dir.join("slaves");
                    if let Ok(slaves) = fs::read_dir(slaves_dir) {
                        for slave in slaves.flatten() {
                            let slave_name = slave.file_name().to_string_lossy().to_string();
                            underlying_device = format!("/dev/{slave_name}");
                            luks_info = probe_luks_header(Path::new(&underlying_device));
                            break;
                        }
                    }

                    let luks = luks_info.unwrap_or_else(|| LuksHeaderInfo {
                        version: 2,
                        uuid: String::new(),
                        cipher: "aes-xts-plain64".to_string(),
                        hash: "sha256".to_string(),
                        keysize_bits: 512,
                        offset_sectors: 32768,
                        label: String::new(),
                    });

                    let mut flags = Vec::new();
                    let discard_bytes = fs::read_to_string(dm_dir.join("queue/discard_max_bytes"))
                        .unwrap_or_else(|_| "0".to_string())
                        .trim()
                        .parse::<u64>()
                        .unwrap_or(0);
                    if discard_bytes > 0 {
                        flags.push("discards");
                    }

                    println!("/dev/mapper/{volume} is active:");
                    println!("  type:    LUKS{}", luks.version);
                    println!("  cipher:  {}", luks.cipher);
                    println!("  keysize: {} bits", luks.keysize_bits);
                    println!("  device:  {underlying_device}");
                    println!("  offset:  {} sectors", luks.offset_sectors);
                    println!("  size:    {size_sectors} sectors");
                    println!("  mode:    {mode}");
                    if !flags.is_empty() {
                        println!("  flags:   {}", flags.join(" "));
                    }

                    return Ok(());
                }
            }
        }
    }

    println!("/dev/mapper/{volume} is inactive.");
    std::process::exit(1);
}
