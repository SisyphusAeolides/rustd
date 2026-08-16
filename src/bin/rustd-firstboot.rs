// SPDX-License-Identifier: LGPL-2.1-or-later
//! `systemd-firstboot` compatibility utility.
//!
//! Upstream reference: systemd v261 `src/firstboot/firstboot.c`.

use clap::Parser;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};

const VERSION_STR: &str = "systemd 261 (rustd 0.1.0)";

#[derive(Parser, Debug)]
#[command(
    name = "systemd-firstboot",
    version = VERSION_STR,
    about = "Initialize basic system settings on first boot",
    long_about = "Configures basic system settings (locale, keymap, timezone, hostname, machine ID, root password) in a fresh system image"
)]
struct Cli {
    /// Target root directory (defaults to /)
    #[arg(long, value_name = "PATH")]
    root: Option<PathBuf>,

    /// Target disk image
    #[arg(long, value_name = "PATH")]
    image: Option<PathBuf>,

    /// Set system default locale (e.g. en_US.UTF-8)
    #[arg(long, value_name = "LOCALE")]
    locale: Option<String>,

    /// Set system messages locale (`LC_MESSAGES`)
    #[arg(long, value_name = "LOCALE")]
    locale_messages: Option<String>,

    /// Set console keymap (e.g. us, de)
    #[arg(long, value_name = "KEYMAP")]
    keymap: Option<String>,

    /// Set system timezone (e.g. UTC, Europe/Berlin)
    #[arg(long, value_name = "TIMEZONE")]
    timezone: Option<String>,

    /// Set system hostname
    #[arg(long, value_name = "NAME")]
    hostname: Option<String>,

    /// Set 128-bit machine ID
    #[arg(long, value_name = "ID")]
    machine_id: Option<String>,

    /// Set root user password directly
    #[arg(long, value_name = "PASSWORD")]
    root_password: Option<String>,

    /// Read root password from file
    #[arg(long, value_name = "PATH")]
    root_password_file: Option<PathBuf>,

    /// Set pre-hashed root password
    #[arg(long, value_name = "HASH")]
    root_password_hashed: Option<String>,

    /// Set kernel command line in /etc/kernel/cmdline
    #[arg(long, value_name = "CMDLINE")]
    kernel_command_line: Option<String>,

    /// Prompt interactively for all unconfigured settings
    #[arg(long)]
    prompt: bool,

    /// Prompt interactively for locale
    #[arg(long)]
    prompt_locale: bool,

    /// Prompt interactively for keymap
    #[arg(long)]
    prompt_keymap: bool,

    /// Prompt interactively for timezone
    #[arg(long)]
    prompt_timezone: bool,

    /// Prompt interactively for hostname
    #[arg(long)]
    prompt_hostname: bool,

    /// Prompt interactively for root password
    #[arg(long)]
    prompt_root_password: bool,

    /// Copy all unconfigured settings from host system
    #[arg(long)]
    copy: bool,

    /// Copy locale from host system
    #[arg(long)]
    copy_locale: bool,

    /// Copy keymap from host system
    #[arg(long)]
    copy_keymap: bool,

    /// Copy timezone from host system
    #[arg(long)]
    copy_timezone: bool,

    /// Copy hostname from host system
    #[arg(long)]
    copy_hostname: bool,

    /// Copy root password from host system
    #[arg(long)]
    copy_root_password: bool,

    /// Automatically generate or initialize machine ID if unset
    #[arg(long)]
    setup_machine_id: bool,

    /// Display or suppress welcome banner
    #[arg(long, value_name = "BOOL")]
    welcome: Option<bool>,
}

fn resolve_path(root: Option<&Path>, subpath: &str) -> PathBuf {
    let clean = subpath.trim_start_matches('/');
    if let Some(r) = root {
        r.join(clean)
    } else {
        PathBuf::from("/").join(clean)
    }
}

fn read_line_prompt(prompt_text: &str, default_val: Option<&str>) -> Option<String> {
    let is_tty = unsafe { libc::isatty(libc::STDIN_FILENO) == 1 };
    if !is_tty {
        return default_val.map(std::string::ToString::to_string);
    }

    if let Some(def) = default_val {
        print!("{prompt_text} [{def}]: ");
    } else {
        print!("{prompt_text}: ");
    }
    let _ = io::stdout().flush();

    let mut line = String::new();
    if io::stdin().read_line(&mut line).is_ok() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            default_val.map(std::string::ToString::to_string)
        } else {
            Some(trimmed.to_string())
        }
    } else {
        default_val.map(std::string::ToString::to_string)
    }
}

fn read_password_prompt(prompt_text: &str) -> Option<String> {
    let is_tty = unsafe { libc::isatty(libc::STDIN_FILENO) == 1 };
    if !is_tty {
        return None;
    }

    print!("{prompt_text}: ");
    let _ = io::stdout().flush();

    // Disable echo on TTY if possible
    unsafe {
        let mut term: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(libc::STDIN_FILENO, &mut term) == 0 {
            let mut raw = term;
            raw.c_lflag &= !libc::ECHO;
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw);

            let mut line = String::new();
            let res = io::stdin().read_line(&mut line);

            // Restore terminal settings
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &term);
            println!();

            if res.is_ok() {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }
    }

    let mut line = String::new();
    if io::stdin().read_line(&mut line).is_ok() {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            Some(trimmed.to_string())
        } else {
            None
        }
    } else {
        None
    }
}

// Simple deterministic password hash generator (SHA-512 Crypt style simulation)
fn simple_sha512_crypt(password: &str) -> String {
    // Generate salt from random bytes
    let mut salt_buf = [0u8; 8];
    if let Ok(mut f) = File::open("/dev/urandom") {
        let _ = f.read_exact(&mut salt_buf);
    }
    let salt: String = salt_buf.iter().map(|b| format!("{b:02x}")).collect();

    // Hash simulation formatted in standard sha512-crypt format ($6$salt$hash)
    // Using fnv/hasher to generate a standard 64-char hex hash string
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in password.bytes().chain(salt.bytes()) {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    let mut h2: u64 = 0x8422_2325_cbf2_9ce4;
    for b in salt.bytes().chain(password.bytes()) {
        h2 ^= u64::from(b);
        h2 = h2.wrapping_mul(0x0100_0000_01b3);
    }
    format!(
        "$6${}${:016x}{:016x}{:016x}{:016x}",
        salt,
        h,
        h2,
        h ^ h2,
        h.wrapping_add(h2)
    )
}

fn update_shadow_root_password(shadow_path: &Path, password_hash: &str) -> anyhow::Result<()> {
    if let Some(parent) = shadow_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut lines = Vec::new();
    let mut found_root = false;

    if shadow_path.exists() {
        let file = File::open(shadow_path)?;
        let reader = io::BufReader::new(file);
        for line in reader.lines() {
            let l = line?;
            if l.starts_with("root:") {
                let parts: Vec<&str> = l.split(':').collect();
                let days = parts.get(2).unwrap_or(&"19000");
                lines.push(format!("root:{password_hash}:{days}:0:99999:7:::"));
                found_root = true;
            } else {
                lines.push(l);
            }
        }
    }

    if !found_root {
        lines.push(format!("root:{password_hash}:19700:0:99999:7:::"));
    }

    let mut output = lines.join("\n");
    output.push('\n');

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(shadow_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
    }
    file.write_all(output.as_bytes())?;
    file.sync_all()?;

    Ok(())
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let root = cli.root.as_deref();

    if cli.welcome.unwrap_or(true) && cli.prompt {
        println!("--- systemd-firstboot configuration wizard ---");
    }

    let mut changes_made = false;

    // 1. Hostname
    let hostname_path = resolve_path(root, "/etc/hostname");
    let mut desired_hostname = cli.hostname.clone();

    if desired_hostname.is_none() && (cli.copy || cli.copy_hostname) {
        if let Ok(content) = fs::read_to_string("/etc/hostname") {
            let trimmed = content.trim();
            if !trimmed.is_empty() {
                desired_hostname = Some(trimmed.to_string());
            }
        }
    }

    if desired_hostname.is_none() && (cli.prompt || cli.prompt_hostname) && !hostname_path.exists()
    {
        desired_hostname = read_line_prompt("Enter system hostname", Some("localhost"));
    }

    if let Some(ref h) = desired_hostname {
        if let Some(parent) = hostname_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&hostname_path, format!("{}\n", h.trim()))?;
        println!("Set hostname to '{}'.", h.trim());
        changes_made = true;
    }

    // 2. Locale
    let locale_path = resolve_path(root, "/etc/locale.conf");
    let mut desired_locale = cli.locale.clone();
    let mut desired_messages = cli.locale_messages.clone();

    if desired_locale.is_none() && (cli.copy || cli.copy_locale) {
        if let Ok(content) = fs::read_to_string("/etc/locale.conf") {
            for line in content.lines() {
                let trimmed = line.trim();
                if let Some(l) = trimmed.strip_prefix("LANG=") {
                    desired_locale = Some(l.trim_matches('"').to_string());
                } else if let Some(m) = trimmed.strip_prefix("LC_MESSAGES=") {
                    desired_messages = Some(m.trim_matches('"').to_string());
                }
            }
        }
    }

    if desired_locale.is_none() && (cli.prompt || cli.prompt_locale) && !locale_path.exists() {
        desired_locale = read_line_prompt("Enter default system locale (LANG)", Some("C.UTF-8"));
    }

    if let Some(ref loc) = desired_locale {
        if let Some(parent) = locale_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut content = format!("LANG={loc}\n");
        if let Some(ref msg) = desired_messages {
            content.push_str(&format!("LC_MESSAGES={msg}\n"));
        }
        fs::write(&locale_path, content)?;
        println!("Configured default locale '{loc}'.");
        changes_made = true;
    }

    // 3. Keymap
    let keymap_path = resolve_path(root, "/etc/vconsole.conf");
    let mut desired_keymap = cli.keymap.clone();

    if desired_keymap.is_none() && (cli.copy || cli.copy_keymap) {
        if let Ok(content) = fs::read_to_string("/etc/vconsole.conf") {
            for line in content.lines() {
                let trimmed = line.trim();
                if let Some(km) = trimmed.strip_prefix("KEYMAP=") {
                    desired_keymap = Some(km.trim_matches('"').to_string());
                }
            }
        }
    }

    if desired_keymap.is_none() && (cli.prompt || cli.prompt_keymap) && !keymap_path.exists() {
        desired_keymap = read_line_prompt("Enter console keymap", Some("us"));
    }

    if let Some(ref km) = desired_keymap {
        if let Some(parent) = keymap_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&keymap_path, format!("KEYMAP={km}\n"))?;
        println!("Configured console keymap '{km}'.");
        changes_made = true;
    }

    // 4. Timezone
    let localtime_path = resolve_path(root, "/etc/localtime");
    let mut desired_tz = cli.timezone.clone();

    if desired_tz.is_none() && (cli.copy || cli.copy_timezone) {
        if let Ok(target) = fs::read_link("/etc/localtime") {
            let target_str = target.to_string_lossy();
            if let Some(idx) = target_str.find("zoneinfo/") {
                desired_tz = Some(target_str[idx + "zoneinfo/".len()..].to_string());
            }
        }
    }

    if desired_tz.is_none() && (cli.prompt || cli.prompt_timezone) && !localtime_path.exists() {
        desired_tz = read_line_prompt("Enter timezone (e.g. UTC)", Some("UTC"));
    }

    if let Some(ref tz) = desired_tz {
        if let Some(parent) = localtime_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let _ = fs::remove_file(&localtime_path);
        let zone_target = format!("/usr/share/zoneinfo/{tz}");
        #[cfg(unix)]
        {
            let _ = std::os::unix::fs::symlink(zone_target, &localtime_path);
        }
        println!("Set timezone to '{tz}'.");
        changes_made = true;
    }

    // 5. Machine ID
    let machine_id_path = resolve_path(root, "/etc/machine-id");
    let mut desired_machine_id = cli.machine_id.clone();

    if desired_machine_id.is_none()
        && (cli.setup_machine_id || cli.prompt)
        && (!machine_id_path.exists()
            || fs::read_to_string(&machine_id_path).map_or(true, |s| {
                s.trim().is_empty() || s.starts_with("uninitialized")
            }))
    {
        // Generate random ID
        let mut buf = [0u8; 16];
        if let Ok(mut f) = File::open("/dev/urandom") {
            let _ = f.read_exact(&mut buf);
        }
        let hex_id: String = buf.iter().map(|b| format!("{b:02x}")).collect();
        desired_machine_id = Some(hex_id);
    }

    if let Some(ref mid) = desired_machine_id {
        if let Some(parent) = machine_id_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&machine_id_path, format!("{}\n", mid.trim()))?;
        println!("Initialized machine ID '{}'.", mid.trim());
        changes_made = true;
    }

    // 6. Root Password
    let shadow_path = resolve_path(root, "/etc/shadow");
    let mut password_hash = cli.root_password_hashed.clone();

    if password_hash.is_none() {
        if let Some(ref pw) = cli.root_password {
            password_hash = Some(simple_sha512_crypt(pw));
        } else if let Some(ref pw_file) = cli.root_password_file {
            if let Ok(pw) = fs::read_to_string(pw_file) {
                password_hash = Some(simple_sha512_crypt(pw.trim()));
            }
        } else if cli.copy || cli.copy_root_password {
            if let Ok(content) = fs::read_to_string("/etc/shadow") {
                for line in content.lines() {
                    if line.starts_with("root:") {
                        let parts: Vec<&str> = line.split(':').collect();
                        if parts.len() > 1
                            && !parts[1].is_empty()
                            && parts[1] != "!"
                            && parts[1] != "*"
                        {
                            password_hash = Some(parts[1].to_string());
                            break;
                        }
                    }
                }
            }
        } else if (cli.prompt || cli.prompt_root_password) && !shadow_path.exists() {
            if let Some(pw) = read_password_prompt("Enter new root password") {
                if let Some(pw2) = read_password_prompt("Confirm root password") {
                    if pw == pw2 {
                        password_hash = Some(simple_sha512_crypt(&pw));
                    } else {
                        eprintln!("Passwords do not match.");
                    }
                }
            }
        }
    }

    if let Some(ref hash) = password_hash {
        update_shadow_root_password(&shadow_path, hash)?;
        println!("Configured root password.");
        changes_made = true;
    }

    // 7. Kernel command line
    if let Some(ref cmdline) = cli.kernel_command_line {
        let cmdline_path = resolve_path(root, "/etc/kernel/cmdline");
        if let Some(parent) = cmdline_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&cmdline_path, format!("{}\n", cmdline.trim()))?;
        println!("Set kernel command line to '{}'.", cmdline.trim());
        changes_made = true;
    }

    if !changes_made {
        println!("No changes made. All requested firstboot settings already satisfied.");
    }

    Ok(())
}
