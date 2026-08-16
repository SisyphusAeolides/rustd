// SPDX-License-Identifier: LGPL-2.1-or-later
//! `mount.ddi` — Filesystem mount helper for Discoverable Disk Images (DDIs).
//!
//! Invoked by `mount -t ddi <image> <directory> [-o options]`.

use std::env;
use std::ffi::CString;
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

const HELP_OUTPUT: &str = concat!(
    "mount.ddi [OPTIONS...] SOURCE TARGET [-o OPTIONS]\n\n",
    "Mount Discoverable Disk Image (DDI) to target directory.\n\n",
    "Options:\n",
    "  -o OPTIONS           Comma-separated mount options (ro, rw, root-hash=..., etc.)\n",
    "  -r, --read-only      Mount read-only\n",
    "  -w, --rw             Mount read-write\n",
    "  -n, --no-mtab        Do not update /etc/mtab\n",
    "  -v, --verbose        Verbose output\n",
    "  -h, --help           Show this help\n",
    "  -V, --version        Show version\n"
);

/// Parse GPT GUID to string.
fn gpt_guid_to_string(bytes: &[u8; 16]) -> String {
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

/// Detect filesystem type by reading partition start.
fn probe_fstype(file: &mut File, offset: u64) -> Option<&'static str> {
    let mut buf = [0u8; 4096];
    if file.seek(SeekFrom::Start(offset)).is_err() {
        return None;
    }
    let n = file.read(&mut buf).unwrap_or(0);
    if n < 512 {
        return None;
    }

    if &buf[0..4] == b"hsqs" || &buf[0..4] == b"sqsh" {
        return Some("squashfs");
    }
    if &buf[0..6] == b"LUKS\xba\xbe" {
        return Some("crypto_LUKS");
    }
    if &buf[0..4] == b"XFSB" {
        return Some("xfs");
    }
    if (&buf[54..62] == b"FAT12   " || &buf[54..62] == b"FAT16   ")
        || (n >= 90 && &buf[82..90] == b"FAT32   ")
    {
        return Some("vfat");
    }
    if n >= 1028 && &buf[1024..1028] == &[0xe2, 0xf5, 0x6f, 0x0e] {
        return Some("erofs");
    }
    if n >= 1082 && buf[1080] == 0x53 && buf[1081] == 0xef {
        return Some("ext4");
    }
    if file.seek(SeekFrom::Start(offset + 0x10000)).is_ok() {
        let mut btrfs_buf = [0u8; 128];
        if file.read(&mut btrfs_buf).unwrap_or(0) >= 72 && &btrfs_buf[0x40..0x48] == b"_BHRfS_M" {
            return Some("btrfs");
        }
    }

    None
}

/// Find root partition offset and size from GPT header.
fn find_root_partition_offset(image_path: &Path) -> io::Result<(u64, u64, Option<&'static str>)> {
    let mut file = File::open(image_path)?;
    let total_size = file.metadata()?.len();

    let mut lba1 = [0u8; 512];
    file.seek(SeekFrom::Start(512))?;
    file.read_exact(&mut lba1)?;

    if &lba1[0..8] != b"EFI PART" {
        // Raw filesystem image without GPT
        let fstype = probe_fstype(&mut file, 0);
        return Ok((0, total_size, fstype));
    }

    let partition_entries_lba = u64::from_le_bytes(lba1[72..80].try_into().unwrap());
    let num_entries = u32::from_le_bytes(lba1[80..84].try_into().unwrap()) as usize;
    let entry_size = u32::from_le_bytes(lba1[84..88].try_into().unwrap()) as usize;

    file.seek(SeekFrom::Start(partition_entries_lba * 512))?;

    let mut selected: Option<(u64, u64, Option<&'static str>)> = None;

    for _ in 0..num_entries {
        let mut entry = vec![0u8; entry_size.max(128)];
        file.read_exact(&mut entry[..entry_size])?;

        let mut type_raw = [0u8; 16];
        type_raw.copy_from_slice(&entry[0..16]);
        if type_raw == [0u8; 16] {
            continue;
        }

        let start_lba = u64::from_le_bytes(entry[32..40].try_into().unwrap());
        let end_lba = u64::from_le_bytes(entry[40..48].try_into().unwrap());
        let type_uuid = gpt_guid_to_string(&type_raw).to_ascii_lowercase();

        let offset = start_lba * 512;
        let size = (end_lba.saturating_sub(start_lba) + 1) * 512;

        // Check if root partition (x86_64, arm64, or generic linux)
        let is_root = type_uuid == "4f68bce3-e8cd-4db1-96e7-fbcaf984b709" // root-x86-64
            || type_uuid == "b921b045-1df0-41c3-af44-4c6f280d3fae" // root-arm64
            || type_uuid == "69dad710-2ce4-4e3c-b16c-21a1d49abed3" // root-arm
            || type_uuid == "7250a680-5e0f-40bc-8297-c1b103e1685d" // root-riscv64
            || type_uuid == "0fc63daf-8483-4772-8e79-3d69d8477de4"; // linux generic

        let is_usr = type_uuid == "8484680c-9521-48c6-ba0a-0701775c599b"
            || type_uuid == "b0e01050-ee5f-4390-949a-9101b17104e9";

        let is_sysext = type_uuid == "ce364026-681a-464a-95eb-bb5e62c205ae"
            || type_uuid == "33446977-b952-4752-4752-114422334455";

        let fstype = probe_fstype(&mut file, offset);

        if is_root {
            return Ok((offset, size, fstype));
        }

        if selected.is_none() && (is_usr || is_sysext) {
            selected = Some((offset, size, fstype));
        }
    }

    selected.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "No mountable partition found in DDI image",
        )
    })
}

fn parse_mount_flags(options: &str, read_only_flag: bool) -> (u64, Vec<String>) {
    let mut flags = 0u64;
    let mut remaining = Vec::new();

    if read_only_flag {
        flags |= libc::MS_RDONLY;
    }

    for opt in options.split(',') {
        let opt = opt.trim();
        if opt.is_empty() {
            continue;
        }
        match opt {
            "ro" => flags |= libc::MS_RDONLY,
            "rw" => flags &= !libc::MS_RDONLY,
            "nosuid" => flags |= libc::MS_NOSUID,
            "suid" => flags &= !libc::MS_NOSUID,
            "nodev" => flags |= libc::MS_NODEV,
            "dev" => flags &= !libc::MS_NODEV,
            "noexec" => flags |= libc::MS_NOEXEC,
            "exec" => flags &= !libc::MS_NOEXEC,
            "sync" => flags |= libc::MS_SYNCHRONOUS,
            "async" => flags &= !libc::MS_SYNCHRONOUS,
            "noatime" => flags |= libc::MS_NOATIME,
            "nodiratime" => flags |= libc::MS_NODIRATIME,
            "relatime" => flags |= libc::MS_RELATIME,
            _ => remaining.push(opt.to_string()),
        }
    }

    (flags, remaining)
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut source: Option<String> = None;
    let mut target: Option<String> = None;
    let mut options = String::new();
    let mut read_only = false;
    let mut verbose = false;

    let mut i = 1;
    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "-h" | "--help" => {
                print!("{HELP_OUTPUT}");
                std::process::exit(0);
            }
            "-V" | "--version" => {
                print!("{VERSION_OUTPUT}");
                std::process::exit(0);
            }
            "-r" | "--read-only" => {
                read_only = true;
            }
            "-w" | "--rw" => {
                read_only = false;
            }
            "-v" | "--verbose" => {
                verbose = true;
            }
            "-n" | "--no-mtab" => {
                // Ignore for modern Linux
            }
            "-o" => {
                i += 1;
                if i < args.len() {
                    if !options.is_empty() {
                        options.push(',');
                    }
                    options.push_str(&args[i]);
                }
            }
            _ if arg.starts_with("-o") => {
                let opt = &arg[2..];
                if !options.is_empty() {
                    options.push(',');
                }
                options.push_str(opt);
            }
            _ if arg.starts_with('-') => {
                // Ignore unknown flags or handle
            }
            _ => {
                if source.is_none() {
                    source = Some(arg.clone());
                } else if target.is_none() {
                    target = Some(arg.clone());
                }
            }
        }
        i += 1;
    }

    let (source_path, target_path) = match (source, target) {
        (Some(s), Some(t)) => (PathBuf::from(s), PathBuf::from(t)),
        _ => {
            eprintln!("mount.ddi: Missing source or target directory.\nUsage: mount.ddi <image> <target> [-o options]");
            std::process::exit(1);
        }
    };

    if !source_path.exists() {
        eprintln!(
            "mount.ddi: Source image '{}' does not exist.",
            source_path.display()
        );
        std::process::exit(1);
    }

    if !target_path.exists() {
        if let Err(e) = fs::create_dir_all(&target_path) {
            eprintln!(
                "mount.ddi: Failed to create target mount directory '{}': {}",
                target_path.display(),
                e
            );
            std::process::exit(1);
        }
    }

    let (offset, size, probed_fstype) = match find_root_partition_offset(&source_path) {
        Ok(res) => res,
        Err(e) => {
            eprintln!(
                "mount.ddi: Failed to dissect image '{}': {}",
                source_path.display(),
                e
            );
            std::process::exit(1);
        }
    };

    if verbose {
        eprintln!(
            "mount.ddi: Dissected partition: offset={offset}, size={size}, fstype={probed_fstype:?}"
        );
    }

    let (flags, extra_opts) = parse_mount_flags(&options, read_only);
    let mut mount_opts = Vec::new();
    if (flags & libc::MS_RDONLY) != 0 {
        mount_opts.push("ro".to_string());
    }
    mount_opts.push(format!("loop,offset={offset},sizelimit={size}"));
    mount_opts.extend(extra_opts);

    let opts_str = mount_opts.join(",");

    // Attempt mounting via system mount command with loop and offset
    let mut cmd = Command::new("mount");
    if let Some(fstype) = probed_fstype {
        cmd.arg("-t").arg(fstype);
    }
    cmd.arg("-o").arg(&opts_str);
    cmd.arg(&source_path);
    cmd.arg(&target_path);

    if verbose {
        eprintln!("mount.ddi: Executing: {cmd:?}");
    }

    match cmd.status() {
        Ok(status) if status.success() => {
            if verbose {
                println!(
                    "mount.ddi: Mounted {} -> {}",
                    source_path.display(),
                    target_path.display()
                );
            }
            std::process::exit(0);
        }
        Ok(status) => {
            // Direct syscall fallback if mount tool failed
            let c_src = CString::new(source_path.to_string_lossy().as_bytes()).unwrap();
            let c_tgt = CString::new(target_path.to_string_lossy().as_bytes()).unwrap();
            let fstype_str = probed_fstype.unwrap_or("auto");
            let c_fstype = CString::new(fstype_str).unwrap();
            let c_data = CString::new(opts_str.as_bytes()).unwrap();

            let ret = unsafe {
                libc::mount(
                    c_src.as_ptr(),
                    c_tgt.as_ptr(),
                    c_fstype.as_ptr(),
                    flags as libc::c_ulong,
                    c_data.as_ptr().cast::<libc::c_void>(),
                )
            };

            if ret == 0 {
                std::process::exit(0);
            } else {
                let err = io::Error::last_os_error();
                eprintln!("mount.ddi: Mount failed with status {status}: {err}");
                std::process::exit(status.code().unwrap_or(1));
            }
        }
        Err(e) => {
            eprintln!("mount.ddi: Failed to execute mount command: {e}");
            std::process::exit(1);
        }
    }
}
