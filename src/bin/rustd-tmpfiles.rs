// SPDX-License-Identifier: LGPL-2.1-or-later
//! `rustd-tmpfiles` — Create, delete, and clean up volatile and temporary files and directories based on tmpfiles.d rules.
//!
//! Upstream counterpart: `systemd-tmpfiles` (v261).

use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use clap::Parser;

const VERSION_OUTPUT: &str = concat!(
    "systemd 261 (261.2-1-arch)\n",
    "+PAM +AUDIT -SELINUX +APPARMOR -IMA +IPE +SMACK +SECCOMP +GCRYPT +GNUTLS +OPENSSL +ACL ",
    "+BLKID +CURL +ELFUTILS +FIDO2 +IDN2 +KMOD +LIBCRYPTSETUP +LIBCRYPTSETUP_PLUGINS +LIBFDISK ",
    "+PCRE2 +PWQUALITY +P11KIT +QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB +ZSTD +BPF_FRAMEWORK +BTF ",
    "+XKBCOMMON +UTMP +LIBARCHIVE\n"
);

#[derive(Parser, Debug)]
#[command(
    name = "rustd-tmpfiles",
    about = "Create, delete, and clean up temporary files and directories",
    version = VERSION_OUTPUT,
)]
struct Cli {
    /// Create files, directories, symlinks, and write configuration
    #[arg(long = "create")]
    create: bool,

    /// Clean up files and directories according to age limits
    #[arg(long = "clean")]
    clean: bool,

    /// Remove files and directories marked for deletion
    #[arg(long = "remove")]
    remove: bool,

    /// Execute user configuration
    #[arg(long = "user")]
    user: bool,

    /// Execute boot-only actions (marked with !)
    #[arg(long = "boot")]
    boot: bool,

    /// Only apply rules matching this path prefix
    #[arg(long = "prefix")]
    prefix: Vec<PathBuf>,

    /// Ignore rules matching this path prefix
    #[arg(long = "exclude-prefix")]
    exclude_prefix: Vec<PathBuf>,

    /// Operate relative to specified filesystem root
    #[arg(long = "root")]
    root: Option<PathBuf>,

    /// Print configuration files without executing
    #[arg(long = "cat-config")]
    cat_config: bool,

    /// Do not pipe output into a pager
    #[arg(long = "no-pager")]
    no_pager: bool,

    /// Specific tmpfiles.d configuration files to execute
    files: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
struct TmpfileEntry {
    action_type: char,
    force: bool,
    boot_only: bool,
    path: PathBuf,
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
    age_secs: Option<u64>,
    argument: Option<String>,
}

fn parse_octal_mode(s: &str) -> Option<u32> {
    if s == "-" || s.is_empty() {
        return None;
    }
    u32::from_str_radix(s.trim_start_matches('0'), 8)
        .ok()
        .or_else(|| {
            if s == "0" {
                Some(0)
            } else {
                u32::from_str_radix(s, 8).ok()
            }
        })
}

fn parse_uid(s: &str) -> Option<u32> {
    if s == "-" || s.is_empty() {
        return None;
    }
    if let Ok(num) = s.parse::<u32>() {
        return Some(num);
    }
    if s == "root" {
        return Some(0);
    }
    if s == "nobody" {
        return Some(65534);
    }
    // Lookup user name via getpwnam
    if let Ok(cname) = CString::new(s) {
        unsafe {
            let pwd = libc::getpwnam(cname.as_ptr());
            if !pwd.is_null() {
                return Some((*pwd).pw_uid);
            }
        }
    }
    None
}

fn parse_gid(s: &str) -> Option<u32> {
    if s == "-" || s.is_empty() {
        return None;
    }
    if let Ok(num) = s.parse::<u32>() {
        return Some(num);
    }
    if s == "root" {
        return Some(0);
    }
    if s == "nogroup" || s == "nobody" {
        return Some(65534);
    }
    // Lookup group name via getgrnam
    if let Ok(cname) = CString::new(s) {
        unsafe {
            let grp = libc::getgrnam(cname.as_ptr());
            if !grp.is_null() {
                return Some((*grp).gr_gid);
            }
        }
    }
    None
}

fn parse_age(s: &str) -> Option<u64> {
    if s == "-" || s.is_empty() || s == "0" {
        return None;
    }

    let mut total_secs = 0u64;
    let mut current_num = 0u64;

    for ch in s.chars() {
        if ch.is_ascii_digit() {
            let digit = u64::from(ch.to_digit(10).unwrap());
            current_num = current_num.saturating_mul(10).saturating_add(digit);
        } else {
            let multiplier = match ch {
                's' | 'S' => 1,
                'm' | 'M' => 60,
                'h' | 'H' => 3600,
                'd' | 'D' => 86400,
                'w' | 'W' => 86400 * 7,
                _ => 1,
            };
            total_secs = total_secs.saturating_add(current_num.saturating_mul(multiplier));
            current_num = 0;
        }
    }
    if current_num > 0 {
        total_secs = total_secs.saturating_add(current_num);
    }

    Some(total_secs)
}

fn expand_specifiers(input: &str, user: bool) -> String {
    let mut out = String::new();
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '%' {
            if let Some(spec) = chars.next() {
                match spec {
                    '%' => out.push('%'),
                    't' => {
                        if user {
                            let runtime = std::env::var("XDG_RUNTIME_DIR")
                                .unwrap_or_else(|_| "/run/user/1000".to_string());
                            out.push_str(&runtime);
                        } else {
                            out.push_str("/run");
                        }
                    }
                    'T' => out.push_str("/tmp"),
                    'V' => out.push_str("/var/tmp"),
                    'u' => {
                        let user_str = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
                        out.push_str(&user_str);
                    }
                    'U' => {
                        let uid = unsafe { libc::getuid() };
                        out.push_str(&uid.to_string());
                    }
                    'g' => {
                        let group_str =
                            std::env::var("USER").unwrap_or_else(|_| "root".to_string());
                        out.push_str(&group_str);
                    }
                    'G' => {
                        let gid = unsafe { libc::getgid() };
                        out.push_str(&gid.to_string());
                    }
                    'h' => {
                        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
                        out.push_str(&home);
                    }
                    'm' => {
                        let machine_id = fs::read_to_string("/etc/machine-id")
                            .unwrap_or_default()
                            .trim()
                            .to_string();
                        out.push_str(&machine_id);
                    }
                    'b' => {
                        let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")
                            .unwrap_or_default()
                            .trim()
                            .to_string();
                        out.push_str(&boot_id);
                    }
                    'H' => {
                        let hostname = fs::read_to_string("/etc/hostname")
                            .unwrap_or_else(|_| "localhost".to_string())
                            .trim()
                            .to_string();
                        out.push_str(&hostname);
                    }
                    other => {
                        out.push('%');
                        out.push(other);
                    }
                }
            } else {
                out.push('%');
            }
        } else {
            out.push(ch);
        }
    }

    out
}

fn parse_line(line: &str, user: bool, root: Option<&Path>) -> Option<TmpfileEntry> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
        return None;
    }

    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }

    let type_str = parts[0];
    let boot_only = type_str.starts_with('!');
    let clean_type = type_str.trim_start_matches('!');
    let force = clean_type.ends_with('+');
    let action_type = clean_type.chars().next()?;

    let raw_path = expand_specifiers(parts[1], user);
    let mut resolved_path = PathBuf::from(&raw_path);
    if let Some(r) = root {
        let clean = raw_path.trim_start_matches('/');
        resolved_path = r.join(clean);
    }

    let mode = parts.get(2).and_then(|s| parse_octal_mode(s));
    let uid = parts.get(3).and_then(|s| parse_uid(s));
    let gid = parts.get(4).and_then(|s| parse_gid(s));
    let age_secs = parts.get(5).and_then(|s| parse_age(s));

    let argument = if parts.len() > 6 {
        let arg_str = parts[6..].join(" ");
        Some(expand_specifiers(&arg_str, user))
    } else {
        None
    };

    Some(TmpfileEntry {
        action_type,
        force,
        boot_only,
        path: resolved_path,
        mode,
        uid,
        gid,
        age_secs,
        argument,
    })
}

fn find_config_files(user: bool, root: Option<&Path>) -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    if user {
        if let Ok(config_home) = std::env::var("XDG_CONFIG_HOME") {
            dirs.push(PathBuf::from(config_home).join("user-tmpfiles.d"));
        } else if let Ok(home) = std::env::var("HOME") {
            dirs.push(PathBuf::from(home).join(".config/user-tmpfiles.d"));
        }
        dirs.push(PathBuf::from("/etc/user-tmpfiles.d"));
        dirs.push(PathBuf::from("/run/user-tmpfiles.d"));
        dirs.push(PathBuf::from("/usr/lib/user-tmpfiles.d"));
    } else {
        dirs.push(PathBuf::from("/etc/tmpfiles.d"));
        dirs.push(PathBuf::from("/run/tmpfiles.d"));
        dirs.push(PathBuf::from("/usr/lib/tmpfiles.d"));
    }

    let mut files = Vec::new();

    for dir in dirs {
        let actual_dir = if let Some(r) = root {
            let rel = dir.strip_prefix("/").unwrap_or(&dir);
            r.join(rel)
        } else {
            dir
        };

        if let Ok(entries) = fs::read_dir(&actual_dir) {
            let mut confs = Vec::new();
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("conf") {
                    confs.push(path);
                }
            }
            confs.sort();
            files.extend(confs);
        }
    }

    files
}

fn apply_ownership_and_mode(path: &Path, mode: Option<u32>, uid: Option<u32>, gid: Option<u32>) {
    if let Some(m) = mode {
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(m));
    }
    if uid.is_some() || gid.is_some() {
        let c_path = CString::new(path.as_os_str().to_string_lossy().as_bytes());
        if let Ok(cp) = c_path {
            let u = uid.unwrap_or(u32::MAX);
            let g = gid.unwrap_or(u32::MAX);
            unsafe {
                libc::chown(cp.as_ptr(), u, g);
            }
        }
    }
}

fn restorecon_created_path(path: &Path) {
    if let Err(error) = rustd::selinux::restorecon_path(path) {
        eprintln!(
            "rustd-tmpfiles: restorecon failed for {}: {error}",
            path.display()
        );
    }
}

fn execute_create(entry: &TmpfileEntry) -> io::Result<()> {
    match entry.action_type {
        'd' | 'D' | 'v' | 'q' | 'Q' => {
            fs::create_dir_all(&entry.path)?;
            apply_ownership_and_mode(&entry.path, entry.mode, entry.uid, entry.gid);
        }
        'e' => {
            if entry.path.exists() {
                if entry.path.is_dir() {
                    if let Ok(read_dir) = fs::read_dir(&entry.path) {
                        for child in read_dir.flatten() {
                            let child_path = child.path();
                            if child_path.is_dir() {
                                let _ = fs::remove_dir_all(&child_path);
                            } else {
                                let _ = fs::remove_file(&child_path);
                            }
                        }
                    }
                }
            } else {
                fs::create_dir_all(&entry.path)?;
            }
            apply_ownership_and_mode(&entry.path, entry.mode, entry.uid, entry.gid);
        }
        'f' | 'F' => {
            if let Some(parent) = entry.path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let truncate = entry.action_type == 'F' || entry.force;
            if !entry.path.exists() || truncate {
                let mut file = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(truncate)
                    .open(&entry.path)?;
                if let Some(content) = &entry.argument {
                    let _ = file.write_all(content.as_bytes());
                }
            }
            apply_ownership_and_mode(&entry.path, entry.mode, entry.uid, entry.gid);
        }
        'w' => {
            if entry.path.exists() {
                if let Some(content) = &entry.argument {
                    let mut file = if entry.force {
                        OpenOptions::new().append(true).open(&entry.path)?
                    } else {
                        OpenOptions::new()
                            .write(true)
                            .truncate(true)
                            .open(&entry.path)?
                    };
                    let _ = file.write_all(content.as_bytes());
                }
            }
        }
        'L' => {
            if let Some(target) = &entry.argument {
                if entry.path.exists() || entry.path.is_symlink() {
                    if entry.force {
                        let _ = fs::remove_file(&entry.path);
                        let _ = symlink(target, &entry.path);
                    }
                } else {
                    if let Some(parent) = entry.path.parent() {
                        let _ = fs::create_dir_all(parent);
                    }
                    let _ = symlink(target, &entry.path);
                }
            }
        }
        'p' => {
            if !entry.path.exists() {
                if let Some(parent) = entry.path.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                if let Ok(c_path) =
                    CString::new(entry.path.as_os_str().to_string_lossy().as_bytes())
                {
                    let mode = entry.mode.unwrap_or(0o644);
                    unsafe {
                        libc::mkfifo(c_path.as_ptr(), mode);
                    }
                }
            }
            apply_ownership_and_mode(&entry.path, entry.mode, entry.uid, entry.gid);
        }
        'z' | 'Z' => {
            if entry.path.exists() {
                apply_ownership_and_mode(&entry.path, entry.mode, entry.uid, entry.gid);
                if entry.action_type == 'Z' && entry.path.is_dir() {
                    if let Ok(read_dir) = fs::read_dir(&entry.path) {
                        for child in read_dir.flatten() {
                            apply_ownership_and_mode(
                                &child.path(),
                                entry.mode,
                                entry.uid,
                                entry.gid,
                            );
                        }
                    }
                }
            }
        }
        _ => {}
    }
    if entry.action_type != 'L' {
        restorecon_created_path(&entry.path);
    }
    Ok(())
}

fn execute_remove(entry: &TmpfileEntry) -> io::Result<()> {
    match entry.action_type {
        'r' => {
            if entry.path.exists() {
                if entry.path.is_dir() {
                    let _ = fs::remove_dir(&entry.path);
                } else {
                    let _ = fs::remove_file(&entry.path);
                }
            }
        }
        'R' => {
            if entry.path.exists() {
                if entry.path.is_dir() {
                    let _ = fs::remove_dir_all(&entry.path);
                } else {
                    let _ = fs::remove_file(&entry.path);
                }
            }
        }
        'D' => {
            if entry.path.is_dir() {
                if let Ok(read_dir) = fs::read_dir(&entry.path) {
                    for child in read_dir.flatten() {
                        let p = child.path();
                        if p.is_dir() {
                            let _ = fs::remove_dir_all(&p);
                        } else {
                            let _ = fs::remove_file(&p);
                        }
                    }
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn execute_clean(entry: &TmpfileEntry) -> io::Result<()> {
    let Some(age_limit) = entry.age_secs else {
        return Ok(());
    };

    if !entry.path.exists() || !entry.path.is_dir() {
        return Ok(());
    }

    let now = SystemTime::now();

    if let Ok(read_dir) = fs::read_dir(&entry.path) {
        for child in read_dir.flatten() {
            let child_path = child.path();
            if let Ok(meta) = fs::metadata(&child_path) {
                if let Ok(mtime) = meta.modified() {
                    if let Ok(elapsed) = now.duration_since(mtime) {
                        if elapsed.as_secs() > age_limit {
                            if child_path.is_dir() {
                                let _ = fs::remove_dir_all(&child_path);
                            } else {
                                let _ = fs::remove_file(&child_path);
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

fn main() {
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let cli = Cli::parse();

    let root = cli.root.as_deref();
    let config_files = if cli.files.is_empty() {
        find_config_files(cli.user, root)
    } else {
        cli.files.clone()
    };

    if cli.cat_config {
        for file in &config_files {
            if let Ok(content) = fs::read_to_string(file) {
                println!("# {}", file.display());
                println!("{content}");
            }
        }
        return;
    }

    let mut entries = Vec::new();

    for file in &config_files {
        if let Ok(content) = fs::read_to_string(file) {
            for line in content.lines() {
                if let Some(entry) = parse_line(line, cli.user, root) {
                    // Filter boot-only
                    if entry.boot_only && !cli.boot {
                        continue;
                    }

                    // Filter prefixes
                    if !cli.prefix.is_empty()
                        && !cli.prefix.iter().any(|p| entry.path.starts_with(p))
                    {
                        continue;
                    }
                    if !cli.exclude_prefix.is_empty()
                        && cli.exclude_prefix.iter().any(|p| entry.path.starts_with(p))
                    {
                        continue;
                    }

                    entries.push(entry);
                }
            }
        }
    }

    // Default action if neither --create, --clean, --remove specified: --create
    let do_create = cli.create || (!cli.clean && !cli.remove);
    let do_remove = cli.remove;
    let do_clean = cli.clean;

    if do_remove {
        for entry in &entries {
            let _ = execute_remove(entry);
        }
    }

    if do_create {
        for entry in &entries {
            let _ = execute_create(entry);
        }
    }

    if do_clean {
        for entry in &entries {
            let _ = execute_clean(entry);
        }
    }
}
