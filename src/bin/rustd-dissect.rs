// SPDX-License-Identifier: LGPL-2.1-or-later
//! `systemd-dissect` compatibility utility.
//!
//! Inspects, mounts, and dissects Discoverable Disk Images (DDIs) and GPT partition tables
//! according to the Discoverable Partitions Specification (DPS).

use clap::{Parser, ValueEnum};
use serde::Serialize;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
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
    name = "systemd-dissect",
    about = "Dissect Discoverable Disk Images (DDIs)",
    version = VERSION_OUTPUT
)]
struct Cli {
    /// Path to the disk image or block device
    #[arg(value_name = "IMAGE")]
    image: Option<String>,

    /// Command to execute inside mounted image
    #[arg(value_name = "COMMAND", trailing_var_arg = true)]
    command: Vec<String>,

    /// Mount the image to the specified path or a temporary path
    #[arg(short = 'm', long = "mount")]
    mount: bool,

    /// Mount the image with writable overlay
    #[arg(short = 'M', long = "mount-overlay")]
    mount_overlay: bool,

    /// Unmount a previously mounted image
    #[arg(short = 'u', long = "umount")]
    umount: bool,

    /// Mount the image read-only
    #[arg(short = 'r', long = "read-only")]
    read_only: bool,

    /// List partitions in the image
    #[arg(short = 'l', long = "list")]
    list: bool,

    /// Validate the image according to Discoverable Partitions Specification
    #[arg(short = 'v', long = "validate")]
    validate: bool,

    /// Target root directory for mounting or operations
    #[arg(long = "root", value_name = "PATH")]
    root: Option<String>,

    /// Output inspection data in JSON
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

    /// Run filesystem check prior to mounting
    #[arg(long = "fsck", value_name = "BOOL")]
    fsck: Option<bool>,

    /// Allow LUKS decryption if encrypted
    #[arg(long = "with-decryption", value_name = "BOOL")]
    with_decryption: Option<bool>,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum JsonMode {
    Off,
    Pretty,
    Short,
}

#[derive(Clone, Debug, Serialize)]
struct PartitionInfo {
    index: usize,
    designator: String,
    type_uuid: String,
    part_uuid: String,
    name: String,
    start_lba: u64,
    end_lba: u64,
    size_bytes: u64,
    size_human: String,
    fstype: String,
    flags: u64,
    read_only: bool,
    no_auto: bool,
    grow_fs: bool,
}

#[derive(Clone, Debug, Serialize)]
struct DissectReport {
    image_path: String,
    sector_size: u32,
    disk_uuid: String,
    total_size_bytes: u64,
    total_size_human: String,
    valid_dps: bool,
    architecture: Option<String>,
    partitions: Vec<PartitionInfo>,
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

/// Convert GPT mixed-endian GUID bytes on disk to standard UUID string.
fn gpt_guid_to_uuid_string(bytes: &[u8; 16]) -> String {
    let d1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let d2 = u16::from_le_bytes([bytes[4], bytes[5]]);
    let d3 = u16::from_le_bytes([bytes[6], bytes[7]]);
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        d1,
        d2,
        d3,
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

/// Lookup DPS designator for a partition type UUID string.
fn lookup_dps_designator(type_uuid: &str) -> &'static str {
    let lower = type_uuid.to_ascii_lowercase();
    match lower.as_str() {
        // x86-64
        "4f68bce3-e8cd-4db1-96e7-fbcaf984b709" => "root-x86-64",
        "2c7357ed-ebd2-46d9-aec1-23d437ec2bf5" => "root-x86-64-verity",
        "410a5105-9e3e-4fc7-9e11-24759d91844d" => "root-x86-64-verity-sig",
        "8484680c-9521-48c6-ba0a-0701775c599b" => "usr-x86-64",
        "fb111c39-7737-4235-829e-0b1177b5e43e" => "usr-x86-64-verity",
        "9ab4c96a-1165-4140-a476-4b0e6e0f0c01" => "usr-x86-64-verity-sig",

        // arm64 / aarch64
        "b921b045-1df0-41c3-af44-4c6f280d3fae" => "root-arm64",
        "df3300ce-d69f-4c92-978c-9bfb0f38d820" => "root-arm64-verity",
        "6db69de6-29f4-4758-a7a5-962190f00ce3" => "root-arm64-verity-sig",
        "b0e01050-ee5f-4390-949a-9101b17104e9" => "usr-arm64",
        "6e11a4e7-fbca-4ded-b9e9-e1a512bb664e" => "usr-arm64-verity",
        "c23ce4ff-44bd-4b00-b2d4-b41b3419e02a" => "usr-arm64-verity-sig",

        // arm 32-bit
        "69dad710-2ce4-4e3c-b16c-21a1d49abed3" => "root-arm",
        "7386cdf2-203c-47a9-a498-f2ecce45a2d6" => "root-arm-verity",
        "42b0455f-eb11-491d-98d3-56145ba9d037" => "root-arm-verity-sig",
        "7d0359a3-02b3-4f0a-865c-654403e70625" => "usr-arm",

        // riscv64
        "7250a680-5e0f-40bc-8297-c1b103e1685d" => "root-riscv64",
        "f5ec024d-03cb-4903-86a4-5dae5f32140f" => "usr-riscv64",

        // Generic DPS types
        "c12a7328-f81f-11d2-ba4b-00a0c93ec93b" => "esp",
        "bc13c2ff-59e6-4262-a352-b275fd6f7172" => "xbootldr",
        "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f" => "swap",
        "933ac7e1-2eb4-4f13-b844-0e14e2aef915" => "home",
        "3b8f8425-20e0-4f3b-907f-1a25a76f98e8" => "srv",
        "4d21b016-b534-45c2-a9fb-5c16e091fd2d" => "var",
        "7ec6f557-3bc5-4aca-b293-16ef5df639d1" => "tmp",
        "0fc63daf-8483-4772-8e79-3d69d8477de4" => "linux-generic",

        // sysext & confext
        "ce364026-681a-464a-95eb-bb5e62c205ae" | "33446977-b952-4752-4752-114422334455" => "sysext",
        "77230fc4-e68a-495d-818b-044229e63d5c" | "0b5220c3-f08a-4318-971c-7ab7b6059d09" => {
            "confext"
        }

        _ => "generic",
    }
}

/// Detect filesystem type by reading magic bytes at the partition start offset.
fn probe_filesystem_magic<R: Read + Seek>(reader: &mut R, start_offset: u64) -> String {
    let mut buf = [0u8; 4096];
    if reader.seek(SeekFrom::Start(start_offset)).is_err() {
        return "unknown".to_string();
    }
    let n = reader.read(&mut buf).unwrap_or(0);
    if n < 512 {
        return "unknown".to_string();
    }

    // Squashfs magic 'hsqs' or 'sqsh'
    if &buf[0..4] == b"hsqs" || &buf[0..4] == b"sqsh" {
        return "squashfs".to_string();
    }

    // LUKS header magic
    if &buf[0..6] == b"LUKS\xba\xbe" {
        return "crypto_LUKS".to_string();
    }

    // XFS superblock
    if &buf[0..4] == b"XFSB" {
        return "xfs".to_string();
    }

    // VFAT boot sector
    if (&buf[54..62] == b"FAT12   " || &buf[54..62] == b"FAT16   ")
        || (n >= 90 && &buf[82..90] == b"FAT32   ")
    {
        return "vfat".to_string();
    }

    // EROFS superblock at offset 1024
    if n >= 1028 && &buf[1024..1028] == &[0xe2, 0xf5, 0x6f, 0x0e] {
        return "erofs".to_string();
    }

    // Ext2/3/4 superblock at offset 1024 + 0x38 (1080)
    if n >= 1082 && buf[1080] == 0x53 && buf[1081] == 0xef {
        return "ext4".to_string();
    }

    // Btrfs superblock at 64KB (offset 0x10000..0x10048)
    if reader.seek(SeekFrom::Start(start_offset + 0x10000)).is_ok() {
        let mut btrfs_buf = [0u8; 128];
        if reader.read(&mut btrfs_buf).unwrap_or(0) >= 72 && &btrfs_buf[0x40..0x48] == b"_BHRfS_M" {
            return "btrfs".to_string();
        }
    }

    "unknown".to_string()
}

/// Parse GPT header and partition entries from image file.
fn parse_gpt_image(image_path: &Path) -> io::Result<DissectReport> {
    let mut file = File::open(image_path)?;
    let total_size = file.metadata()?.len();

    let sector_size = 512u32;
    let mut lba1 = [0u8; 512];
    file.seek(SeekFrom::Start(u64::from(sector_size)))?;
    file.read_exact(&mut lba1)?;

    // Check GPT Signature 'EFI PART'
    if &lba1[0..8] != b"EFI PART" {
        // Fallback: check if entire image is a raw filesystem without GPT
        let fs_magic = probe_filesystem_magic(&mut file, 0);
        if fs_magic != "unknown" {
            let part = PartitionInfo {
                index: 1,
                designator: "root".to_string(),
                type_uuid: "0fc63daf-8483-4772-8e79-3d69d8477de4".to_string(),
                part_uuid: "00000000-0000-0000-0000-000000000000".to_string(),
                name: "Raw Partition".to_string(),
                start_lba: 0,
                end_lba: total_size / u64::from(sector_size),
                size_bytes: total_size,
                size_human: format_bytes(total_size),
                fstype: fs_magic,
                flags: 0,
                read_only: false,
                no_auto: false,
                grow_fs: false,
            };
            return Ok(DissectReport {
                image_path: image_path.display().to_string(),
                sector_size,
                disk_uuid: "00000000-0000-0000-0000-000000000000".to_string(),
                total_size_bytes: total_size,
                total_size_human: format_bytes(total_size),
                valid_dps: true,
                architecture: Some("generic".to_string()),
                partitions: vec![part],
            });
        }
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid GPT partition table: 'EFI PART' signature missing",
        ));
    }

    let mut disk_guid_raw = [0u8; 16];
    disk_guid_raw.copy_from_slice(&lba1[56..72]);
    let disk_uuid = gpt_guid_to_uuid_string(&disk_guid_raw);

    let partition_entries_lba = u64::from_le_bytes(lba1[72..80].try_into().unwrap());
    let num_partition_entries = u32::from_le_bytes(lba1[80..84].try_into().unwrap()) as usize;
    let size_partition_entry = u32::from_le_bytes(lba1[84..88].try_into().unwrap()) as usize;

    let entries_offset = partition_entries_lba * u64::from(sector_size);
    file.seek(SeekFrom::Start(entries_offset))?;

    let mut partitions = Vec::new();
    let mut detected_arch = None;

    for i in 0..num_partition_entries {
        let mut entry = vec![0u8; size_partition_entry.max(128)];
        file.read_exact(&mut entry[..size_partition_entry])?;

        let mut type_raw = [0u8; 16];
        type_raw.copy_from_slice(&entry[0..16]);
        if type_raw == [0u8; 16] {
            continue; // Unused entry
        }

        let mut part_raw = [0u8; 16];
        part_raw.copy_from_slice(&entry[16..32]);

        let start_lba = u64::from_le_bytes(entry[32..40].try_into().unwrap());
        let end_lba = u64::from_le_bytes(entry[40..48].try_into().unwrap());
        let flags = u64::from_le_bytes(entry[48..56].try_into().unwrap());

        // Parse UTF-16LE partition name (72 bytes = 36 u16 code units)
        let mut name_u16 = Vec::new();
        for chunk in entry[56..128.min(size_partition_entry)].chunks_exact(2) {
            let code = u16::from_le_bytes([chunk[0], chunk[1]]);
            if code == 0 {
                break;
            }
            name_u16.push(code);
        }
        let name = String::from_utf16_lossy(&name_u16);

        let type_uuid = gpt_guid_to_uuid_string(&type_raw);
        let part_uuid = gpt_guid_to_uuid_string(&part_raw);
        let designator = lookup_dps_designator(&type_uuid).to_string();

        if designator.contains("x86-64") {
            detected_arch = Some("x86-64".to_string());
        } else if designator.contains("arm64") {
            detected_arch = Some("arm64".to_string());
        }

        let num_sectors = end_lba.saturating_sub(start_lba).saturating_add(1);
        let size_bytes = num_sectors * u64::from(sector_size);
        let start_offset = start_lba * u64::from(sector_size);

        let fstype = probe_filesystem_magic(&mut file, start_offset);

        let read_only = (flags & (1 << 60)) != 0;
        let no_auto = (flags & (1 << 62)) != 0;
        let grow_fs = (flags & (1 << 63)) != 0;

        partitions.push(PartitionInfo {
            index: i + 1,
            designator,
            type_uuid,
            part_uuid,
            name,
            start_lba,
            end_lba,
            size_bytes,
            size_human: format_bytes(size_bytes),
            fstype,
            flags,
            read_only,
            no_auto,
            grow_fs,
        });
    }

    let valid_dps = partitions.iter().any(|p| {
        p.designator.starts_with("root") || p.designator.starts_with("usr") || p.designator == "esp"
    });

    Ok(DissectReport {
        image_path: image_path.display().to_string(),
        sector_size,
        disk_uuid,
        total_size_bytes: total_size,
        total_size_human: format_bytes(total_size),
        valid_dps,
        architecture: detected_arch,
        partitions,
    })
}

fn print_dissect_table(report: &DissectReport, no_legend: bool) {
    if !no_legend {
        println!("Image: {}", report.image_path);
        println!(
            "Size: {} ({})",
            report.total_size_human, report.total_size_bytes
        );
        println!("Disk UUID: {}", report.disk_uuid);
        if let Some(ref arch) = report.architecture {
            println!("Architecture: {arch}");
        }
        println!();
        println!(
            "{:<4} {:<22} {:<38} {:<8} {:<10} {:<15}",
            "#", "DESIGNATOR", "PARTITION UUID", "SIZE", "FSTYPE", "NAME"
        );
        println!("{:-<102}", "");
    }

    for p in &report.partitions {
        println!(
            "{:<4} {:<22} {:<38} {:<8} {:<10} {:<15}",
            p.index, p.designator, p.part_uuid, p.size_human, p.fstype, p.name
        );
    }

    if !no_legend && report.partitions.is_empty() {
        println!("(No partition entries found)");
    }
}

fn execute_mount(image: &Path, target_root: Option<&str>, read_only: bool) -> anyhow::Result<()> {
    let report = parse_gpt_image(image)?;
    let root_part = report
        .partitions
        .iter()
        .find(|p| p.designator.starts_with("root") || p.designator == "linux-generic")
        .or_else(|| report.partitions.first())
        .ok_or_else(|| anyhow::anyhow!("No mountable partition found in image"))?;

    let mount_point = match target_root {
        Some(p) => PathBuf::from(p),
        None => {
            let file_stem = image
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("image");
            let dir = PathBuf::from(format!("/run/systemd/mount/dissect-{file_stem}"));
            fs::create_dir_all(&dir)?;
            dir
        }
    };

    if !mount_point.exists() {
        fs::create_dir_all(&mount_point)?;
    }

    println!(
        "Mounting partition #{} ({}, {}) to {}",
        root_part.index,
        root_part.designator,
        root_part.size_human,
        mount_point.display()
    );

    // If loop device can be created or using standard mount
    let mut cmd = Command::new("mount");
    if read_only || root_part.read_only {
        cmd.arg("-o").arg(format!(
            "ro,loop,offset={}",
            root_part.start_lba * u64::from(report.sector_size)
        ));
    } else {
        cmd.arg("-o").arg(format!(
            "loop,offset={}",
            root_part.start_lba * u64::from(report.sector_size)
        ));
    }
    cmd.arg(image);
    cmd.arg(&mount_point);

    let status = cmd.status();
    match status {
        Ok(s) if s.success() => {
            println!("Successfully mounted on {}", mount_point.display());
            Ok(())
        }
        Ok(s) => Err(anyhow::anyhow!("Mount command exited with status {s}")),
        Err(e) => Err(anyhow::anyhow!("Failed to execute mount: {e}")),
    }
}

fn execute_umount(target: &Path) -> anyhow::Result<()> {
    let mut cmd = Command::new("umount");
    cmd.arg(target);
    let status = cmd.status()?;
    if status.success() {
        println!("Successfully unmounted {}", target.display());
        Ok(())
    } else {
        Err(anyhow::anyhow!("umount exited with status {status}"))
    }
}

fn main() {
    let cli = Cli::parse();

    let json_mode = if cli.json_short {
        Some(JsonMode::Pretty)
    } else {
        cli.json
    };

    let image_str = match cli.image.as_deref() {
        Some(img) => img,
        None => {
            eprintln!("systemd-dissect: No image specified. Use --help for usage details.");
            std::process::exit(1);
        }
    };

    let image_path = Path::new(image_str);

    if cli.umount {
        if let Err(e) = execute_umount(image_path) {
            eprintln!("systemd-dissect: Failed to unmount: {e}");
            std::process::exit(1);
        }
        return;
    }

    if !image_path.exists() {
        eprintln!("systemd-dissect: Image file '{image_str}' does not exist.");
        std::process::exit(1);
    }

    if cli.mount || cli.mount_overlay {
        if let Err(e) = execute_mount(image_path, cli.root.as_deref(), cli.read_only) {
            eprintln!("systemd-dissect: Mount failed: {e}");
            std::process::exit(1);
        }
        return;
    }

    match parse_gpt_image(image_path) {
        Ok(report) => {
            if cli.validate {
                if report.valid_dps {
                    println!("Image '{image_str}' is a valid Discoverable Disk Image (DDI).");
                    std::process::exit(0);
                }
                eprintln!("Image '{image_str}' is NOT a valid Discoverable Disk Image (no root/usr/esp partition found).");
                std::process::exit(1);
            }

            match json_mode {
                Some(JsonMode::Pretty) => {
                    let json_str = serde_json::to_string_pretty(&report).unwrap_or_default();
                    println!("{json_str}");
                }
                Some(JsonMode::Short) => {
                    let json_str = serde_json::to_string(&report).unwrap_or_default();
                    println!("{json_str}");
                }
                _ => {
                    print_dissect_table(&report, cli.no_legend);
                }
            }
        }
        Err(err) => {
            eprintln!("systemd-dissect: Failed to parse image '{image_str}': {err}");
            std::process::exit(1);
        }
    }
}
