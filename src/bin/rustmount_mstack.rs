// SPDX-License-Identifier: LGPL-2.1-or-later
//! `mount.mstack` — Filesystem mount helper for multi-layer stacked mounts.
//!
//! Invoked by `mount -t mstack <spec> <target> [-o options]`.

use std::env;
use std::ffi::CString;
use std::fs;
use std::io;
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
    "mount.mstack [OPTIONS...] SPEC TARGET [-o OPTIONS]\n\n",
    "Mount multi-layer stacked filesystem (overlayfs / stacked directories) onto target.\n\n",
    "Arguments:\n",
    "  SPEC                 Colon-separated layer paths (e.g. /layer1:/layer2) or stack spec\n",
    "  TARGET               Destination mount directory\n\n",
    "Options:\n",
    "  -o OPTIONS           Mount options (lowerdir=..., upperdir=..., workdir=..., ro, rw)\n",
    "  -r, --read-only      Mount read-only\n",
    "  -w, --rw             Mount read-write\n",
    "  -v, --verbose        Verbose output\n",
    "  -h, --help           Show this help\n",
    "  -V, --version        Show version\n"
);

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
            _ => extra.push(opt.to_string()),
        }
    }

    (flags, extra)
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut spec: Option<String> = None;
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
            eprintln!("mount.mstack: Missing SPEC or TARGET directory.\nUsage: mount.mstack <spec> <target> [-o options]");
            std::process::exit(1);
        }
    };

    let target_path = PathBuf::from(&target_str);
    if !target_path.exists() {
        if let Err(e) = fs::create_dir_all(&target_path) {
            eprintln!(
                "mount.mstack: Failed to create target directory '{}': {}",
                target_path.display(),
                e
            );
            std::process::exit(1);
        }
    }

    let (flags, extra_opts) = parse_mount_flags(&options, read_only);

    // Extract layers from spec or options
    let mut lowerdirs = Vec::new();
    let mut upperdir: Option<String> = None;
    let mut workdir: Option<String> = None;
    let mut other_overlay_opts = Vec::new();

    for opt in &extra_opts {
        if let Some(lower) = opt.strip_prefix("lowerdir=") {
            for layer in lower.split(':') {
                if !layer.is_empty() {
                    lowerdirs.push(layer.to_string());
                }
            }
        } else if let Some(upper) = opt.strip_prefix("upperdir=") {
            upperdir = Some(upper.to_string());
        } else if let Some(work) = opt.strip_prefix("workdir=") {
            workdir = Some(work.to_string());
        } else {
            other_overlay_opts.push(opt.clone());
        }
    }

    // If SPEC contains colon-separated paths and lowerdir not explicitly set
    if lowerdirs.is_empty() {
        for part in spec_str.split(':') {
            let part = part.trim();
            if !part.is_empty() {
                lowerdirs.push(part.to_string());
            }
        }
    }

    if lowerdirs.is_empty() {
        eprintln!("mount.mstack: No layers specified in SPEC or lowerdir option.");
        std::process::exit(1);
    }

    // Verify lower layers exist
    for layer in &lowerdirs {
        let p = Path::new(layer);
        if !p.exists() && verbose {
            eprintln!("mount.mstack: Warning: layer '{layer}' does not currently exist");
        }
    }

    // Assemble overlayfs options
    let mut overlay_opts = Vec::new();
    overlay_opts.push(format!("lowerdir={}", lowerdirs.join(":")));
    if let (Some(u), Some(w)) = (upperdir, workdir) {
        overlay_opts.push(format!("upperdir={u}"));
        overlay_opts.push(format!("workdir={w}"));
    }
    overlay_opts.extend(other_overlay_opts);

    let overlay_data = overlay_opts.join(",");

    if verbose {
        eprintln!(
            "mount.mstack: Mounting overlayfs on {} with options: {}",
            target_path.display(),
            overlay_data
        );
    }

    // Attempt system mount
    let mut cmd = Command::new("mount");
    cmd.arg("-t").arg("overlay");
    cmd.arg("overlay");
    cmd.arg(&target_path);
    cmd.arg("-o").arg(&overlay_data);

    match cmd.status() {
        Ok(status) if status.success() => {
            if verbose {
                println!(
                    "mount.mstack: Successfully mounted stack on {}",
                    target_path.display()
                );
            }
            std::process::exit(0);
        }
        Ok(status) => {
            // Direct syscall fallback
            let c_src = CString::new("overlay").unwrap();
            let c_tgt = CString::new(target_path.to_string_lossy().as_bytes()).unwrap();
            let c_fstype = CString::new("overlay").unwrap();
            let c_data = CString::new(overlay_data.as_bytes()).unwrap();

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
                eprintln!("mount.mstack: Mount failed with status {status}: {err}");
                std::process::exit(status.code().unwrap_or(1));
            }
        }
        Err(e) => {
            eprintln!("mount.mstack: Failed to execute mount: {e}");
            std::process::exit(1);
        }
    }
}
