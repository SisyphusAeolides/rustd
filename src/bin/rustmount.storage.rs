// SPDX-License-Identifier: LGPL-2.1-or-later
//! `mount.storage` — Filesystem mount helper for storage subsystem mounts.
//!
//! Invoked by `mount -t storage <spec> <target> [-o options]`.

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
    "mount.storage [OPTIONS...] SPEC TARGET [-o OPTIONS]\n\n",
    "Mount block and NVMe storage devices by spec (UUID, LABEL, PARTUUID, or node).\n\n",
    "Arguments:\n",
    "  SPEC                 Device specifier (UUID=..., LABEL=..., PARTUUID=..., or /dev/node)\n",
    "  TARGET               Destination mount directory\n\n",
    "Options:\n",
    "  -t TYPE              Filesystem type\n",
    "  -o OPTIONS           Mount options (ro, rw, noatime, etc.)\n",
    "  -r, --read-only      Mount read-only\n",
    "  -w, --rw             Mount read-write\n",
    "  -v, --verbose        Verbose output\n",
    "  -h, --help           Show this help\n",
    "  -V, --version        Show version\n"
);

/// Probe filesystem type by reading magic bytes.
fn probe_filesystem(dev_path: &Path) -> Option<&'static str> {
    let mut file = File::open(dev_path).ok()?;
    let mut buf = [0u8; 4096];
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
    if file.seek(SeekFrom::Start(0x10000)).is_ok() {
        let mut btrfs_buf = [0u8; 128];
        if file.read(&mut btrfs_buf).unwrap_or(0) >= 72 && &btrfs_buf[0x40..0x48] == b"_BHRfS_M" {
            return Some("btrfs");
        }
    }

    None
}

/// Resolve device specification (UUID=..., LABEL=..., PARTUUID=..., PARTLABEL=..., or device path).
fn resolve_spec(spec: &str) -> Option<PathBuf> {
    if let Some(uuid) = spec.strip_prefix("UUID=") {
        let path = PathBuf::from(format!("/dev/disk/by-uuid/{}", uuid.trim_matches('"')));
        if path.exists() {
            return fs::canonicalize(&path).ok().or(Some(path));
        }
    } else if let Some(label) = spec.strip_prefix("LABEL=") {
        let path = PathBuf::from(format!("/dev/disk/by-label/{}", label.trim_matches('"')));
        if path.exists() {
            return fs::canonicalize(&path).ok().or(Some(path));
        }
    } else if let Some(partuuid) = spec.strip_prefix("PARTUUID=") {
        let path = PathBuf::from(format!(
            "/dev/disk/by-partuuid/{}",
            partuuid.trim_matches('"')
        ));
        if path.exists() {
            return fs::canonicalize(&path).ok().or(Some(path));
        }
    } else if let Some(partlabel) = spec.strip_prefix("PARTLABEL=") {
        let path = PathBuf::from(format!(
            "/dev/disk/by-partlabel/{}",
            partlabel.trim_matches('"')
        ));
        if path.exists() {
            return fs::canonicalize(&path).ok().or(Some(path));
        }
    } else if let Some(id) = spec.strip_prefix("ID=") {
        let path = PathBuf::from(format!("/dev/disk/by-id/{}", id.trim_matches('"')));
        if path.exists() {
            return fs::canonicalize(&path).ok().or(Some(path));
        }
    }

    let direct = PathBuf::from(spec);
    if direct.exists() {
        return fs::canonicalize(&direct).ok().or(Some(direct));
    }

    None
}

fn parse_mount_flags(options: &str, read_only_flag: bool) -> (u64, Vec<String>) {
    let mut flags = 0u64;
    let mut extra = Vec::new();

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
            _ => extra.push(opt.to_string()),
        }
    }

    (flags, extra)
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut spec: Option<String> = None;
    let mut target: Option<String> = None;
    let mut fstype: Option<String> = None;
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
            "-t" => {
                i += 1;
                if i < args.len() {
                    fstype = Some(args[i].clone());
                }
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
                // Ignore unknown flags
            }
            _ => {
                if spec.is_none() {
                    spec = Some(arg.clone());
                } else if target.is_none() {
                    target = Some(arg.clone());
                }
            }
        }
        i += 1;
    }

    let (spec_str, target_str) = match (spec, target) {
        (Some(s), Some(t)) => (s, t),
        _ => {
            eprintln!("mount.storage: Missing SPEC or TARGET directory.\nUsage: mount.storage <spec> <target> [-o options]");
            std::process::exit(1);
        }
    };

    let dev_path = match resolve_spec(&spec_str) {
        Some(p) => p,
        None => {
            eprintln!("mount.storage: Could not resolve storage device '{spec_str}'");
            std::process::exit(1);
        }
    };

    let target_path = PathBuf::from(&target_str);
    if !target_path.exists() {
        if let Err(e) = fs::create_dir_all(&target_path) {
            eprintln!(
                "mount.storage: Failed to create target directory '{}': {}",
                target_path.display(),
                e
            );
            std::process::exit(1);
        }
    }

    let detected_type = fstype.as_deref().or_else(|| probe_filesystem(&dev_path));
    let (flags, extra_opts) = parse_mount_flags(&options, read_only);

    let mut mount_opts = Vec::new();
    if (flags & libc::MS_RDONLY) != 0 {
        mount_opts.push("ro".to_string());
    }
    mount_opts.extend(extra_opts);
    let opts_str = mount_opts.join(",");

    if verbose {
        eprintln!(
            "mount.storage: Mounting {} (type: {:?}) on {} with options: {}",
            dev_path.display(),
            detected_type,
            target_path.display(),
            opts_str
        );
    }

    let mut cmd = Command::new("mount");
    if let Some(t) = detected_type {
        cmd.arg("-t").arg(t);
    }
    if !opts_str.is_empty() {
        cmd.arg("-o").arg(&opts_str);
    }
    cmd.arg(&dev_path);
    cmd.arg(&target_path);

    match cmd.status() {
        Ok(status) if status.success() => {
            if verbose {
                println!(
                    "mount.storage: Mounted {} on {}",
                    dev_path.display(),
                    target_path.display()
                );
            }
            std::process::exit(0);
        }
        Ok(status) => {
            // Direct syscall fallback
            let c_src = CString::new(dev_path.to_string_lossy().as_bytes()).unwrap();
            let c_tgt = CString::new(target_path.to_string_lossy().as_bytes()).unwrap();
            let c_fstype = CString::new(detected_type.unwrap_or("auto")).unwrap();
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
                eprintln!("mount.storage: Mount failed with status {status}: {err}");
                std::process::exit(status.code().unwrap_or(1));
            }
        }
        Err(e) => {
            eprintln!("mount.storage: Failed to execute mount: {e}");
            std::process::exit(1);
        }
    }
}
