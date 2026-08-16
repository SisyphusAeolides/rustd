// SPDX-License-Identifier: LGPL-2.1-or-later
//! `systemd-repart` — Grow and partition GPT disk images automatically from declarative definitions.
//!
//! Parses `repart.d/*.conf` partition specifications and computes/applies GPT partition layouts.

use clap::{Parser, ValueEnum};
use serde::Serialize;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const VERSION_OUTPUT: &str = concat!(
    "systemd 261 (261.2-1-arch)\n",
    "+PAM +AUDIT -SELINUX +APPARMOR -IMA +IPE +SMACK +SECCOMP +GCRYPT +GNUTLS +OPENSSL +ACL ",
    "+BLKID +CURL +ELFUTILS +FIDO2 +IDN2 +KMOD +LIBCRYPTSETUP +LIBCRYPTSETUP_PLUGINS +LIBFDISK ",
    "+PCRE2 +PWQUALITY +P11KIT +QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB +ZSTD +BPF_FRAMEWORK +BTF ",
    "+XKBCOMMON +UTMP +LIBARCHIVE\n"
);

#[derive(Parser, Debug)]
#[command(
    name = "systemd-repart",
    about = "Grow and partition GPT disk images automatically",
    version = VERSION_OUTPUT
)]
struct Cli {
    /// Device node or image file path
    #[arg(value_name = "DEVICE|IMAGE")]
    image: Option<String>,

    /// Dry run (do not modify disk)
    #[arg(long = "dry-run", default_value = "yes")]
    dry_run: String,

    /// Handling of empty partition tables (create, refuse, require, force)
    #[arg(long = "empty", value_name = "MODE", default_value = "create")]
    empty: String,

    /// Target image size in bytes or with suffix (e.g. 10G, 500M)
    #[arg(long = "size", value_name = "BYTES")]
    size: Option<String>,

    /// Directory containing repart.d partition definition files
    #[arg(long = "definitions", value_name = "DIR")]
    definitions: Option<String>,

    /// Seed UUID for reproducible partition UUIDs
    #[arg(long = "seed", value_name = "UUID")]
    seed: Option<String>,

    /// Output data in JSON
    #[arg(long = "json", value_name = "MODE")]
    json: Option<JsonMode>,

    /// Equivalent to --json=pretty
    #[arg(short = 'j')]
    json_short: bool,

    /// Split partition output
    #[arg(long = "split")]
    split: Option<bool>,

    /// Discard empty blocks
    #[arg(long = "discard")]
    discard: Option<bool>,

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
struct PartitionDef {
    file_name: String,
    part_type: String,
    type_uuid: String,
    label: String,
    uuid: Option<String>,
    size_min_bytes: u64,
    size_max_bytes: u64,
    weight: u32,
    padding_min_bytes: u64,
    format: Option<String>,
    encrypt: Option<String>,
    read_only: bool,
    grow_fs: bool,
}

#[derive(Clone, Debug, Serialize)]
struct PlannedPartition {
    index: usize,
    type_name: String,
    type_uuid: String,
    label: String,
    part_uuid: String,
    file_name: String,
    start_lba: u64,
    end_lba: u64,
    size_bytes: u64,
    size_human: String,
    padding_bytes: u64,
    activity: String,
    format: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct RepartReport {
    image: String,
    total_size_bytes: u64,
    total_size_human: String,
    sector_size: u32,
    table_type: String,
    seed: Option<String>,
    dry_run: bool,
    partitions: Vec<PlannedPartition>,
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

fn parse_size_str(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() || s.eq_ignore_ascii_case("infinity") || s.eq_ignore_ascii_case("auto") {
        return None;
    }

    let (num_part, mul) = if let Some(stripped) = s.strip_suffix(|c: char| c.is_alphabetic()) {
        let suffix = &s[stripped.len()..];
        let mul = match suffix.to_ascii_uppercase().as_str() {
            "K" | "KB" | "KIB" => 1024u64,
            "M" | "MB" | "MIB" => 1024 * 1024,
            "G" | "GB" | "GIB" => 1024 * 1024 * 1024,
            "T" | "TB" | "TIB" => 1024 * 1024 * 1024 * 1024,
            "P" | "PB" | "PIB" => 1024 * 1024 * 1024 * 1024 * 1024,
            _ => 1,
        };
        (stripped, mul)
    } else {
        (s, 1u64)
    };

    num_part.parse::<u64>().ok().map(|n| n * mul)
}

fn resolve_type_uuid(type_str: &str) -> (String, String) {
    let lower = type_str.to_ascii_lowercase();
    match lower.as_str() {
        "root-x86-64" | "root-x86_64" => (
            "root-x86-64".to_string(),
            "4f68bce3-e8cd-4db1-96e7-fbcaf984b709".to_string(),
        ),
        "root-arm64" | "root-aarch64" => (
            "root-arm64".to_string(),
            "b921b045-1df0-41c3-af44-4c6f280d3fae".to_string(),
        ),
        "root-arm" => (
            "root-arm".to_string(),
            "69dad710-2ce4-4e3c-b16c-21a1d49abed3".to_string(),
        ),
        "root-riscv64" => (
            "root-riscv64".to_string(),
            "7250a680-5e0f-40bc-8297-c1b103e1685d".to_string(),
        ),
        "root" => {
            #[cfg(target_arch = "x86_64")]
            {
                (
                    "root-x86-64".to_string(),
                    "4f68bce3-e8cd-4db1-96e7-fbcaf984b709".to_string(),
                )
            }
            #[cfg(target_arch = "aarch64")]
            {
                (
                    "root-arm64".to_string(),
                    "b921b045-1df0-41c3-af44-4c6f280d3fae".to_string(),
                )
            }
            #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
            {
                (
                    "root-x86-64".to_string(),
                    "4f68bce3-e8cd-4db1-96e7-fbcaf984b709".to_string(),
                )
            }
        }
        "usr-x86-64" | "usr-x86_64" => (
            "usr-x86-64".to_string(),
            "8484680c-9521-48c6-ba0a-0701775c599b".to_string(),
        ),
        "usr-arm64" | "usr-aarch64" => (
            "usr-arm64".to_string(),
            "b0e01050-ee5f-4390-949a-9101b17104e9".to_string(),
        ),
        "usr" => (
            "usr-x86-64".to_string(),
            "8484680c-9521-48c6-ba0a-0701775c599b".to_string(),
        ),
        "esp" => (
            "esp".to_string(),
            "c12a7328-f81f-11d2-ba4b-00a0c93ec93b".to_string(),
        ),
        "xbootldr" => (
            "xbootldr".to_string(),
            "bc13c2ff-59e6-4262-a352-b275fd6f7172".to_string(),
        ),
        "swap" => (
            "swap".to_string(),
            "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f".to_string(),
        ),
        "home" => (
            "home".to_string(),
            "933ac7e1-2eb4-4f13-b844-0e14e2aef915".to_string(),
        ),
        "srv" => (
            "srv".to_string(),
            "3b8f8425-20e0-4f3b-907f-1a25a76f98e8".to_string(),
        ),
        "var" => (
            "var".to_string(),
            "4d21b016-b534-45c2-a9fb-5c16e091fd2d".to_string(),
        ),
        "tmp" => (
            "tmp".to_string(),
            "7ec6f557-3bc5-4aca-b293-16ef5df639d1".to_string(),
        ),
        "linux-generic" => (
            "linux-generic".to_string(),
            "0fc63daf-8483-4772-8e79-3d69d8477de4".to_string(),
        ),
        "sysext" => (
            "sysext".to_string(),
            "ce364026-681a-464a-95eb-bb5e62c205ae".to_string(),
        ),
        "confext" => (
            "confext".to_string(),
            "77230fc4-e68a-495d-818b-044229e63d5c".to_string(),
        ),
        uuid if uuid.len() == 36 && uuid.contains('-') => ("custom".to_string(), uuid.to_string()),
        _ => (
            type_str.to_string(),
            "0fc63daf-8483-4772-8e79-3d69d8477de4".to_string(),
        ),
    }
}

fn parse_definition_file(path: &Path) -> io::Result<Option<PartitionDef>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let mut inside_section = false;
    let mut part_type = "linux-generic".to_string();
    let mut label = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("part")
        .to_string();
    let mut uuid = None;
    let mut size_min = 10 * 1024 * 1024; // 10MB default
    let mut size_max = u64::MAX;
    let mut weight = 1000u32;
    let mut padding_min = 0u64;
    let mut format = None;
    let mut encrypt = None;
    let mut read_only = false;
    let mut grow_fs = false;

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            let section = &trimmed[1..trimmed.len() - 1].trim();
            inside_section = section.eq_ignore_ascii_case("Partition");
            continue;
        }
        if !inside_section {
            continue;
        }

        if let Some((k, v)) = trimmed.split_once('=') {
            let key = k.trim();
            let val = v.trim().trim_matches('"');
            match key.to_ascii_lowercase().as_str() {
                "type" => part_type = val.to_string(),
                "label" => label = val.to_string(),
                "uuid" => uuid = Some(val.to_string()),
                "sizeminbytes" | "size-min-bytes" => {
                    if let Some(s) = parse_size_str(val) {
                        size_min = s;
                    }
                }
                "sizemaxbytes" | "size-max-bytes" => {
                    if let Some(s) = parse_size_str(val) {
                        size_max = s;
                    }
                }
                "weight" => {
                    if let Ok(w) = val.parse::<u32>() {
                        weight = w;
                    }
                }
                "paddingminbytes" | "padding-min-bytes" => {
                    if let Some(p) = parse_size_str(val) {
                        padding_min = p;
                    }
                }
                "format" => format = Some(val.to_string()),
                "encrypt" => encrypt = Some(val.to_string()),
                "readonly" | "read-only" => read_only = val == "yes" || val == "true" || val == "1",
                "growfilesystem" | "grow-file-system" => {
                    grow_fs = val == "yes" || val == "true" || val == "1";
                }
                _ => {}
            }
        }
    }

    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_string();
    let (name, type_uuid) = resolve_type_uuid(&part_type);

    Ok(Some(PartitionDef {
        file_name,
        part_type: name,
        type_uuid,
        label,
        uuid,
        size_min_bytes: size_min,
        size_max_bytes: size_max,
        weight,
        padding_min_bytes: padding_min,
        format,
        encrypt,
        read_only,
        grow_fs,
    }))
}

fn load_definitions(custom_dir: Option<&str>) -> Vec<PartitionDef> {
    let mut search_dirs = Vec::new();
    if let Some(d) = custom_dir {
        search_dirs.push(PathBuf::from(d));
    } else {
        search_dirs.push(PathBuf::from("/etc/repart.d"));
        search_dirs.push(PathBuf::from("/run/repart.d"));
        search_dirs.push(PathBuf::from("/usr/local/lib/repart.d"));
        search_dirs.push(PathBuf::from("/usr/lib/repart.d"));
    }

    let mut defs = Vec::new();
    let mut seen_files = std::collections::HashSet::new();

    for dir in search_dirs {
        if let Ok(entries) = fs::read_dir(dir) {
            let mut paths: Vec<PathBuf> = entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|ext| ext == "conf"))
                .collect();
            paths.sort();

            for path in paths {
                let filename = path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                if seen_files.contains(&filename) {
                    continue;
                }
                if let Ok(Some(def)) = parse_definition_file(&path) {
                    seen_files.insert(filename);
                    defs.push(def);
                }
            }
        }
    }

    defs.sort_by(|a, b| a.file_name.cmp(&b.file_name));
    defs
}

fn generate_deterministic_uuid(seed: &str, index: usize, label: &str) -> String {
    let input = format!("{seed}:{index}:{label}");
    // Simple FNV-1a / hash based pseudo-UUID
    let mut h1: u64 = 0xcbf2_9ce4_8422_2325;
    let mut h2: u64 = 0x0100_0000_01b3;
    for b in input.bytes() {
        h1 = (h1 ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
        h2 = (h2 ^ u64::from(b)).wrapping_mul(0xcbf2_9ce4_8422_2325);
    }
    // Format as RFC4122 v4 UUID
    let b1 = h1.to_be_bytes();
    let b2 = h2.to_be_bytes();
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-4{:01x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b1[0], b1[1], b1[2], b1[3],
        b1[4], b1[5],
        b1[6] & 0x0f, b1[7],
        (b2[0] & 0x3f) | 0x80, b2[1],
        b2[2], b2[3], b2[4], b2[5], b2[6], b2[7]
    )
}

fn plan_partitions(
    defs: &[PartitionDef],
    total_size: u64,
    seed: Option<&str>,
) -> Vec<PlannedPartition> {
    let sector_size = 512u64;
    let start_offset = 2048u64 * sector_size; // 1MB align (LBA 2048)
    let end_reserved = 2048u64 * sector_size; // 1MB backup GPT reserve at end
    let usable_size = total_size.saturating_sub(start_offset + end_reserved);

    let total_min_size: u64 = defs.iter().map(|d| d.size_min_bytes).sum();
    let total_weight: u32 = defs.iter().map(|d| d.weight).sum();
    let extra_pool = usable_size.saturating_sub(total_min_size);

    let seed_str = seed.unwrap_or("rustd-repart-seed-v1");
    let mut planned = Vec::new();
    let mut current_offset = start_offset;

    for (i, d) in defs.iter().enumerate() {
        let extra = if total_weight > 0 {
            (u128::from(extra_pool) * u128::from(d.weight) / u128::from(total_weight)) as u64
        } else {
            0
        };

        let calculated_size = (d.size_min_bytes + extra).min(d.size_max_bytes);
        // Align partition size to 1MB (2048 sectors)
        let aligned_size = (calculated_size / (2048 * sector_size)) * (2048 * sector_size);
        let final_size = aligned_size.max(d.size_min_bytes);

        let start_lba = current_offset / sector_size;
        let num_sectors = final_size / sector_size;
        let end_lba = start_lba + num_sectors.saturating_sub(1);

        let part_uuid = d
            .uuid
            .clone()
            .unwrap_or_else(|| generate_deterministic_uuid(seed_str, i + 1, &d.label));

        planned.push(PlannedPartition {
            index: i + 1,
            type_name: d.part_type.clone(),
            type_uuid: d.type_uuid.clone(),
            label: d.label.clone(),
            part_uuid,
            file_name: d.file_name.clone(),
            start_lba,
            end_lba,
            size_bytes: final_size,
            size_human: format_bytes(final_size),
            padding_bytes: d.padding_min_bytes,
            activity: "create".to_string(),
            format: d.format.clone(),
        });

        current_offset += final_size + d.padding_min_bytes;
    }

    planned
}

fn print_repart_table(report: &RepartReport, no_legend: bool) {
    if !no_legend {
        println!("Target: {}", report.image);
        println!(
            "Size: {} ({} bytes)",
            report.total_size_human, report.total_size_bytes
        );
        println!("Table Type: {}", report.table_type);
        if report.dry_run {
            println!("Mode: Dry Run (no changes applied)");
        }
        println!();
        println!(
            "{:<4} {:<16} {:<16} {:<38} {:<12} {:<8} {:<8}",
            "#", "TYPE", "LABEL", "UUID", "FILE", "SIZE", "ACTIVITY"
        );
        println!("{:-<108}", "");
    }

    for p in &report.partitions {
        println!(
            "{:<4} {:<16} {:<16} {:<38} {:<12} {:<8} {:<8}",
            p.index, p.type_name, p.label, p.part_uuid, p.file_name, p.size_human, p.activity
        );
    }

    if !no_legend && report.partitions.is_empty() {
        println!("(No partition definitions found or planned)");
    }
}

fn apply_partitions_to_image(
    image_path: &Path,
    planned: &[PlannedPartition],
    total_size: u64,
) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(image_path)?;
    file.set_len(total_size)?;

    // Write Protective MBR at LBA 0
    let mut mbr = [0u8; 512];
    mbr[446 + 4] = 0xee; // GPT Protective Partition Type
    mbr[446 + 8] = 0x01; // Starting LBA 1
    let total_sectors = (total_size / 512).min(u64::from(u32::MAX)) as u32;
    mbr[446 + 12..446 + 16].copy_from_slice(&total_sectors.to_le_bytes());
    mbr[510] = 0x55;
    mbr[511] = 0xaa;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&mbr)?;

    // Write Primary GPT Header at LBA 1 (offset 512)
    let mut gpt_header = [0u8; 512];
    gpt_header[0..8].copy_from_slice(b"EFI PART");
    gpt_header[8..12].copy_from_slice(&0x0001_0000_u32.to_le_bytes()); // Revision 1.0
    gpt_header[12..16].copy_from_slice(&92u32.to_le_bytes()); // Header size
    gpt_header[24..32].copy_from_slice(&1u64.to_le_bytes()); // Current LBA 1
    let backup_lba = (total_size / 512).saturating_sub(1);
    gpt_header[32..40].copy_from_slice(&backup_lba.to_le_bytes()); // Backup LBA
    gpt_header[40..48].copy_from_slice(&34u64.to_le_bytes()); // First usable LBA
    let last_usable_lba = backup_lba.saturating_sub(34);
    gpt_header[48..56].copy_from_slice(&last_usable_lba.to_le_bytes()); // Last usable LBA
    gpt_header[72..80].copy_from_slice(&2u64.to_le_bytes()); // Partition entries LBA 2
    gpt_header[80..84].copy_from_slice(&128u32.to_le_bytes()); // Number of entries
    gpt_header[84..88].copy_from_slice(&128u32.to_le_bytes()); // Entry size

    file.seek(SeekFrom::Start(512))?;
    file.write_all(&gpt_header)?;

    // Write Partition Entries at LBA 2..33 (offset 1024)
    file.seek(SeekFrom::Start(1024))?;
    for p in planned {
        let mut entry = [0u8; 128];
        // Parse type UUID
        if let Some(type_id) = parse_uuid_to_mixed_endian(&p.type_uuid) {
            entry[0..16].copy_from_slice(&type_id);
        }
        if let Some(part_id) = parse_uuid_to_mixed_endian(&p.part_uuid) {
            entry[16..32].copy_from_slice(&part_id);
        }
        entry[32..40].copy_from_slice(&p.start_lba.to_le_bytes());
        entry[40..48].copy_from_slice(&p.end_lba.to_le_bytes());

        // UTF-16LE label
        let mut offset = 56;
        for c in p.label.encode_utf16().take(36) {
            entry[offset..offset + 2].copy_from_slice(&c.to_le_bytes());
            offset += 2;
        }

        file.write_all(&entry)?;
    }

    file.flush()?;
    Ok(())
}

fn parse_uuid_to_mixed_endian(uuid_str: &str) -> Option<[u8; 16]> {
    let clean: String = uuid_str.chars().filter(char::is_ascii_hexdigit).collect();
    if clean.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for i in 0..16 {
        bytes[i] = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).ok()?;
    }
    // Mixed-endian swap
    let mut mixed = bytes;
    mixed[0..4].reverse();
    mixed[4..6].reverse();
    mixed[6..8].reverse();
    Some(mixed)
}

fn main() {
    let cli = Cli::parse();

    let json_mode = if cli.json_short {
        Some(JsonMode::Pretty)
    } else {
        cli.json
    };

    let is_dry_run = cli.dry_run == "yes" || cli.dry_run == "true" || cli.dry_run == "1";

    let defs = load_definitions(cli.definitions.as_deref());

    let target_image = cli.image.as_deref().unwrap_or("/dev/null");
    let target_path = Path::new(target_image);

    let total_size = if let Some(ref sz) = cli.size {
        parse_size_str(sz).unwrap_or(10 * 1024 * 1024 * 1024) // 10GB default
    } else if target_path.exists() {
        target_path
            .metadata()
            .map_or(10 * 1024 * 1024 * 1024, |m| m.len())
    } else {
        10 * 1024 * 1024 * 1024 // 10GB default
    };

    let planned = plan_partitions(&defs, total_size, cli.seed.as_deref());

    let report = RepartReport {
        image: target_image.to_string(),
        total_size_bytes: total_size,
        total_size_human: format_bytes(total_size),
        sector_size: 512,
        table_type: "GPT".to_string(),
        seed: cli.seed.clone(),
        dry_run: is_dry_run,
        partitions: planned.clone(),
    };

    match json_mode {
        Some(JsonMode::Pretty) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).unwrap_or_default()
            );
        }
        Some(JsonMode::Short) => {
            println!("{}", serde_json::to_string(&report).unwrap_or_default());
        }
        _ => {
            print_repart_table(&report, cli.no_legend);
        }
    }

    if !is_dry_run && target_image != "/dev/null" {
        if let Err(e) = apply_partitions_to_image(target_path, &planned, total_size) {
            eprintln!("systemd-repart: Failed to write partition table: {e}");
            std::process::exit(1);
        }
        println!("Successfully applied GPT partition layout to {target_image}");
    }
}
