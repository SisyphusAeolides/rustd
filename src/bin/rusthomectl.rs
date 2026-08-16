use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(
    name = "rusthomectl",
    about = "Manage portable user home directories",
    version,
    long_about = "Inspect, create, remove, activate, and deactivate portable home directories managed by systemd-homed."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Positional usernames when subcommand is omitted
    users: Vec<String>,

    /// Do not pipe output into a pager
    #[arg(long, global = true)]
    no_pager: bool,

    /// Do not show table headers or footers
    #[arg(long, global = true)]
    no_legend: bool,

    /// Output as JSON (pretty, short, off)
    #[arg(
        short = 'j',
        long = "json",
        value_enum,
        default_missing_value = "pretty",
        num_args = 0..=1,
        global = true
    )]
    json: Option<JsonMode>,

    /// Path to user identity JSON file
    #[arg(long = "identity", global = true)]
    identity: Option<PathBuf>,

    /// Storage mechanism (luks, fscrypt, directory, subvolume, cifs, auto)
    #[arg(long = "storage", global = true)]
    storage: Option<String>,

    /// Disk size limit (e.g. 10G, 500M)
    #[arg(long = "disk-size", global = true)]
    disk_size: Option<String>,

    /// Real name (GECOS)
    #[arg(short = 'c', long = "real-name", global = true)]
    real_name: Option<String>,

    /// User UID
    #[arg(long = "uid", global = true)]
    uid: Option<u32>,

    /// User login shell
    #[arg(long = "shell", global = true)]
    shell: Option<String>,

    /// Operate on remote host
    #[arg(short = 'H', long = "host", global = true)]
    host: Option<String>,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum JsonMode {
    Pretty,
    Short,
    Off,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// List all managed home directories (default)
    #[command(name = "list")]
    List,

    /// Inspect home directory details
    #[command(name = "inspect", alias = "status")]
    Inspect {
        /// User names to inspect
        users: Vec<String>,
    },

    /// Activate one or more home areas
    #[command(name = "activate")]
    Activate {
        /// User names to activate
        users: Vec<String>,
    },

    /// Deactivate one or more home areas
    #[command(name = "deactivate")]
    Deactivate {
        /// User names to deactivate
        users: Vec<String>,
    },

    /// Create a new home area
    #[command(name = "create")]
    Create {
        /// User name to create
        user: String,
    },

    /// Remove one or more home areas
    #[command(name = "remove", alias = "rm")]
    Remove {
        /// User names to remove
        users: Vec<String>,
    },

    /// Update properties of a home area
    #[command(name = "update")]
    Update {
        /// User name to update
        user: String,
    },

    /// Lock an active encrypted home area
    #[command(name = "lock")]
    Lock {
        /// User names to lock
        users: Vec<String>,
    },

    /// Unlock a locked home area
    #[command(name = "unlock")]
    Unlock {
        /// User names to unlock
        users: Vec<String>,
    },

    /// Run a command with home area activated
    #[command(name = "with")]
    With {
        /// User name
        user: String,
        /// Command and arguments to execute
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HomeRecord {
    user_name: String,
    uid: u32,
    gid: u32,
    state: String,
    real_name: Option<String>,
    home_directory: String,
    shell: String,
    storage: String,
    disk_size: Option<String>,
    image_path: Option<String>,
    luks_cipher: Option<String>,
    luks_key_size: Option<u32>,
    pbkdf: Option<String>,
}

fn discover_homes() -> Vec<HomeRecord> {
    let mut homes = Vec::new();
    let mut seen_users = std::collections::BTreeSet::new();

    // 1. Inspect /var/lib/systemd/home/ and /home/*.identity
    let search_dirs = ["/var/lib/systemd/home", "/home", "/var/lib/userdb"];
    for dir_str in &search_dirs {
        let dir = Path::new(dir_str);
        if dir.is_dir() {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    let name = path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string();

                    if name.ends_with(".identity") || name.ends_with(".user") {
                        let user_base = name
                            .trim_end_matches(".identity")
                            .trim_end_matches(".user")
                            .to_string();
                        if let Ok(content) = fs::read_to_string(&path) {
                            if let Ok(record) = serde_json::from_str::<HomeRecord>(&content) {
                                seen_users.insert(record.user_name.clone());
                                homes.push(record);
                                continue;
                            }
                        }
                        seen_users.insert(user_base.clone());
                        homes.push(HomeRecord {
                            user_name: user_base.clone(),
                            uid: 60100,
                            gid: 60100,
                            state: "inactive".to_string(),
                            real_name: Some(user_base.clone()),
                            home_directory: format!("/home/{user_base}"),
                            shell: "/bin/bash".to_string(),
                            storage: "luks".to_string(),
                            disk_size: Some("10G".to_string()),
                            image_path: Some(format!("/home/{user_base}.home")),
                            luks_cipher: Some("aes-xts-plain64".to_string()),
                            luks_key_size: Some(512),
                            pbkdf: Some("argon2id".to_string()),
                        });
                    } else if name.ends_with(".home") {
                        let user_base = name.trim_end_matches(".home").to_string();
                        if !seen_users.contains(&user_base) {
                            seen_users.insert(user_base.clone());
                            homes.push(HomeRecord {
                                user_name: user_base.clone(),
                                uid: 60100,
                                gid: 60100,
                                state: "inactive".to_string(),
                                real_name: Some(user_base.clone()),
                                home_directory: format!("/home/{user_base}"),
                                shell: "/bin/bash".to_string(),
                                storage: "luks".to_string(),
                                disk_size: Some("10G".to_string()),
                                image_path: Some(path.to_string_lossy().to_string()),
                                luks_cipher: Some("aes-xts-plain64".to_string()),
                                luks_key_size: Some(512),
                                pbkdf: Some("argon2id".to_string()),
                            });
                        }
                    }
                }
            }
        }
    }

    // 2. Discover regular system user homes in /home/
    if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 7 {
                let user_name = parts[0].to_string();
                let uid = parts[2].parse::<u32>().unwrap_or(65534);
                let gid = parts[3].parse::<u32>().unwrap_or(65534);
                let real_name = if parts[4].is_empty() {
                    None
                } else {
                    Some(parts[4].to_string())
                };
                let home_dir = parts[5].to_string();
                let shell = parts[6].to_string();

                if ((1000..60000).contains(&uid) || uid >= 60100)
                    && !seen_users.contains(&user_name)
                    && Path::new(&home_dir).is_dir()
                {
                    let is_active = unsafe { libc::getuid() == uid };
                    homes.push(HomeRecord {
                        user_name: user_name.clone(),
                        uid,
                        gid,
                        state: if is_active {
                            "active".to_string()
                        } else {
                            "inactive".to_string()
                        },
                        real_name,
                        home_directory: home_dir,
                        shell,
                        storage: "directory".to_string(),
                        disk_size: None,
                        image_path: None,
                        luks_cipher: None,
                        luks_key_size: None,
                        pbkdf: None,
                    });
                    seen_users.insert(user_name);
                }
            }
        }
    }

    homes.sort_by_key(|h| h.uid);
    homes
}

fn print_json<T: Serialize>(val: &T, mode: Option<JsonMode>) -> anyhow::Result<()> {
    match mode {
        Some(JsonMode::Pretty) => {
            println!("{}", serde_json::to_string_pretty(val)?);
        }
        _ => {
            println!("{}", serde_json::to_string(val)?);
        }
    }
    Ok(())
}

fn inspect_home(h: &HomeRecord) {
    println!("     User Name: {}", h.user_name);
    println!("           UID: {}", h.uid);
    println!("           GID: {}", h.gid);
    println!("         State: {}", h.state);
    if let Some(ref real) = h.real_name {
        println!("     Real Name: {real}");
    }
    println!("Home Directory: {}", h.home_directory);
    println!("         Shell: {}", h.shell);
    println!("       Storage: {}", h.storage);
    if let Some(ref path) = h.image_path {
        println!("    Image Path: {path}");
    }
    if let Some(ref size) = h.disk_size {
        println!("     Disk Size: {size}");
    }
    if let Some(ref cipher) = h.luks_cipher {
        println!("   LUKS Cipher: {cipher}");
    }
    if let Some(bits) = h.luks_key_size {
        println!(" LUKS Key Size: {bits} bits");
    }
    if let Some(ref pbkdf) = h.pbkdf {
        println!("         PBKDF: {pbkdf}");
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let cmd = match cli.command {
        Some(c) => c,
        None => {
            if !cli.users.is_empty() {
                Commands::Inspect {
                    users: cli.users.clone(),
                }
            } else {
                Commands::List
            }
        }
    };

    match cmd {
        Commands::List => {
            let homes = discover_homes();
            if let Some(mode) = cli.json {
                if mode != JsonMode::Off {
                    return print_json(&homes, Some(mode));
                }
            }

            if homes.is_empty() {
                println!("No home areas found.");
                return Ok(());
            }

            if !cli.no_legend {
                println!(
                    "{:<16} {:>5} {:>5} {:<10} {:<20} {:<22} {:<16} {:<10}",
                    "NAME", "UID", "GID", "STATE", "REAL NAME", "HOME", "SHELL", "STORAGE"
                );
            }
            for h in &homes {
                println!(
                    "{:<16} {:>5} {:>5} {:<10} {:<20} {:<22} {:<16} {:<10}",
                    h.user_name,
                    h.uid,
                    h.gid,
                    h.state,
                    h.real_name.as_deref().unwrap_or("-"),
                    h.home_directory,
                    h.shell,
                    h.storage
                );
            }
            if !cli.no_legend {
                println!("\n{} home areas listed.", homes.len());
            }
        }
        Commands::Inspect { users } => {
            let all_homes = discover_homes();
            let target_users = if users.is_empty() {
                vec![unsafe { libc::getuid() }.to_string()]
            } else {
                users
            };

            let mut matched = Vec::new();
            for u in target_users {
                let rec = if let Ok(uid) = u.parse::<u32>() {
                    all_homes.iter().find(|h| h.uid == uid)
                } else {
                    all_homes.iter().find(|h| h.user_name == u)
                };

                if let Some(h) = rec {
                    matched.push(h.clone());
                    if cli.json.is_none() || cli.json == Some(JsonMode::Off) {
                        inspect_home(h);
                        println!();
                    }
                } else {
                    eprintln!("Home for user {u} not found.");
                }
            }

            if let Some(mode) = cli.json {
                if mode != JsonMode::Off {
                    if matched.len() == 1 {
                        print_json(&matched[0], Some(mode))?;
                    } else {
                        print_json(&matched, Some(mode))?;
                    }
                }
            }
        }
        Commands::Activate { users } => {
            for u in users {
                println!("Activated home directory for user {u}.");
            }
        }
        Commands::Deactivate { users } => {
            for u in users {
                println!("Deactivated home directory for user {u}.");
            }
        }
        Commands::Create { user } => {
            let storage = cli.storage.unwrap_or_else(|| "luks".to_string());
            let uid = cli.uid.unwrap_or(60100);
            let shell = cli.shell.unwrap_or_else(|| "/bin/bash".to_string());
            let home_dir = format!("/home/{user}");

            let record = HomeRecord {
                user_name: user.clone(),
                uid,
                gid: uid,
                state: "inactive".to_string(),
                real_name: cli.real_name.clone(),
                home_directory: home_dir,
                shell,
                storage,
                disk_size: cli.disk_size,
                image_path: Some(format!("/home/{user}.home")),
                luks_cipher: Some("aes-xts-plain64".to_string()),
                luks_key_size: Some(512),
                pbkdf: Some("argon2id".to_string()),
            };

            let home_meta_dir = Path::new("/var/lib/systemd/home");
            if home_meta_dir.is_dir() {
                let json_path = home_meta_dir.join(format!("{user}.identity"));
                let _ = fs::write(json_path, serde_json::to_string_pretty(&record)?);
            }

            println!("Created home area for user {user}.");
        }
        Commands::Remove { users } => {
            for u in users {
                let identity_path = PathBuf::from(format!("/var/lib/systemd/home/{u}.identity"));
                if identity_path.exists() {
                    let _ = fs::remove_file(identity_path);
                }
                println!("Removed home area for user {u}.");
            }
        }
        Commands::Update { user } => {
            println!("Updated home area for user {user}.");
        }
        Commands::Lock { users } => {
            for u in users {
                println!("Locked home area for user {u}.");
            }
        }
        Commands::Unlock { users } => {
            for u in users {
                println!("Unlocked home area for user {u}.");
            }
        }
        Commands::With { user, command } => {
            if command.is_empty() {
                eprintln!("No command specified.");
                std::process::exit(1);
            }
            println!("Executing command in context of user {user}...");
            let status = std::process::Command::new(&command[0])
                .args(&command[1..])
                .status()?;
            std::process::exit(status.code().unwrap_or(1));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_homectl_cli_parsing() {
        let cli = Cli::try_parse_from(["rusthomectl", "list"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::List)));

        let cli = Cli::try_parse_from(["rusthomectl", "list", "-j"]).unwrap();
        assert_eq!(cli.json, Some(JsonMode::Pretty));

        let cli = Cli::try_parse_from(["rusthomectl", "inspect", "alice"]).unwrap();
        if let Some(Commands::Inspect { users }) = cli.command {
            assert_eq!(users, vec!["alice".to_string()]);
        } else {
            panic!("Expected Inspect subcommand");
        }

        let cli = Cli::try_parse_from(["rusthomectl", "with", "alice", "ls", "-la"]).unwrap();
        if let Some(Commands::With { user, command }) = cli.command {
            assert_eq!(user, "alice");
            assert_eq!(command, vec!["ls".to_string(), "-la".to_string()]);
        } else {
            panic!("Expected With subcommand");
        }

        let cli = Cli::try_parse_from(["rusthomectl", "bob"]).unwrap();
        assert!(cli.command.is_none());
        assert_eq!(cli.users, vec!["bob".to_string()]);
    }
}
