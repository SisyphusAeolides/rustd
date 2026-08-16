use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

#[derive(Parser, Debug)]
#[command(
    name = "rustuserdbctl",
    about = "Inspect users, groups and group memberships",
    version,
    long_about = "Query and display user and group records from the UserDB subsystem, /etc/passwd, /etc/group, and drop-in configurations."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Positional user/group names when subcommand is omitted
    names: Vec<String>,

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

    /// Filter by service name (e.g. io.systemd.Multiplexer, io.systemd.Home, nss)
    #[arg(short = 's', long = "service", global = true)]
    service: Option<String>,

    /// Include NSS (Name Service Switch) lookups
    #[arg(long = "with-nss", default_value = "true", global = true)]
    with_nss: bool,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum JsonMode {
    Pretty,
    Short,
    Off,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Show user details (default if user name provided)
    #[command(name = "user", alias = "show-user")]
    User {
        /// User names or UIDs to query
        names: Vec<String>,
    },

    /// List all users
    #[command(name = "users", alias = "list-users")]
    Users,

    /// Show group details
    #[command(name = "group", alias = "show-group")]
    Group {
        /// Group names or GIDs to query
        names: Vec<String>,
    },

    /// List all groups
    #[command(name = "groups", alias = "list-groups")]
    Groups,

    /// List group memberships
    #[command(name = "members", alias = "list-members")]
    Members {
        /// Group names to query (all if omitted)
        groups: Vec<String>,
    },

    /// List `UserDB` services
    #[command(name = "services", alias = "list-services")]
    Services,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserRecord {
    user_name: String,
    uid: u32,
    gid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    real_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    home_directory: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    shell: Option<String>,
    service: String,
    disposition: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    locked: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GroupRecord {
    group_name: String,
    gid: u32,
    members: Vec<String>,
    service: String,
    disposition: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MembershipRecord {
    user: String,
    group: String,
    service: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServiceRecord {
    service: String,
    socket: String,
    description: String,
}

fn load_users(service_filter: Option<&str>) -> Vec<UserRecord> {
    let mut users = Vec::new();
    let mut seen_users = BTreeSet::new();

    // 1. Check /run/systemd/userdb/*.json and /etc/userdb/*.json
    let dropin_dirs = ["/run/systemd/userdb", "/etc/userdb", "/var/lib/userdb"];
    for dir_str in &dropin_dirs {
        let dir = Path::new(dir_str);
        if dir.is_dir() {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|e| e.to_str()) == Some("user")
                        || path.extension().and_then(|e| e.to_str()) == Some("json")
                    {
                        if let Ok(content) = fs::read_to_string(&path) {
                            if let Ok(record) = serde_json::from_str::<UserRecord>(&content) {
                                if let Some(filter) = service_filter {
                                    if !record.service.contains(filter) {
                                        continue;
                                    }
                                }
                                seen_users.insert(record.user_name.clone());
                                users.push(record);
                            }
                        }
                    }
                }
            }
        }
    }

    // 2. Parse /etc/passwd
    if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 7 {
                let user_name = parts[0].to_string();
                if seen_users.contains(&user_name) {
                    continue;
                }
                let uid = parts[2].parse::<u32>().unwrap_or(65534);
                let gid = parts[3].parse::<u32>().unwrap_or(65534);
                let real_name = if parts[4].is_empty() {
                    None
                } else {
                    Some(parts[4].to_string())
                };
                let home_directory = if parts[5].is_empty() {
                    None
                } else {
                    Some(parts[5].to_string())
                };
                let shell = if parts[6].is_empty() {
                    None
                } else {
                    Some(parts[6].to_string())
                };
                let disposition = if uid == 0 {
                    "intrinsic".to_string()
                } else if uid < 1000 {
                    "system".to_string()
                } else if (60000..=65534).contains(&uid) {
                    "dynamic".to_string()
                } else {
                    "regular".to_string()
                };

                let service = "io.systemd.Multiplexer".to_string();
                if let Some(filter) = service_filter {
                    if !service.contains(filter) && filter != "nss" {
                        continue;
                    }
                }

                seen_users.insert(user_name.clone());
                users.push(UserRecord {
                    user_name,
                    uid,
                    gid,
                    real_name,
                    home_directory,
                    shell,
                    service,
                    disposition,
                    locked: Some(parts[1] == "!" || parts[1] == "*"),
                });
            }
        }
    }

    users.sort_by_key(|u| u.uid);
    users
}

fn load_groups(service_filter: Option<&str>) -> Vec<GroupRecord> {
    let mut groups = Vec::new();
    let mut seen_groups = BTreeSet::new();

    // 1. Drop-ins
    let dropin_dirs = ["/run/systemd/userdb", "/etc/userdb", "/var/lib/userdb"];
    for dir_str in &dropin_dirs {
        let dir = Path::new(dir_str);
        if dir.is_dir() {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|e| e.to_str()) == Some("group") {
                        if let Ok(content) = fs::read_to_string(&path) {
                            if let Ok(record) = serde_json::from_str::<GroupRecord>(&content) {
                                if let Some(filter) = service_filter {
                                    if !record.service.contains(filter) {
                                        continue;
                                    }
                                }
                                seen_groups.insert(record.group_name.clone());
                                groups.push(record);
                            }
                        }
                    }
                }
            }
        }
    }

    // 2. /etc/group
    if let Ok(group_file) = fs::read_to_string("/etc/group") {
        for line in group_file.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 {
                let group_name = parts[0].to_string();
                if seen_groups.contains(&group_name) {
                    continue;
                }
                let gid = parts[2].parse::<u32>().unwrap_or(65534);
                let members = if parts.len() > 3 && !parts[3].is_empty() {
                    parts[3]
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                } else {
                    Vec::new()
                };

                let disposition = if gid == 0 {
                    "intrinsic".to_string()
                } else if gid < 1000 {
                    "system".to_string()
                } else {
                    "regular".to_string()
                };

                let service = "io.systemd.Multiplexer".to_string();
                if let Some(filter) = service_filter {
                    if !service.contains(filter) && filter != "nss" {
                        continue;
                    }
                }

                seen_groups.insert(group_name.clone());
                groups.push(GroupRecord {
                    group_name,
                    gid,
                    members,
                    service,
                    disposition,
                });
            }
        }
    }

    groups.sort_by_key(|g| g.gid);
    groups
}

fn load_services() -> Vec<ServiceRecord> {
    vec![
        ServiceRecord {
            service: "io.systemd.Multiplexer".to_string(),
            socket: "/run/systemd/userdb/io.systemd.Multiplexer".to_string(),
            description: "User Database Multiplexer".to_string(),
        },
        ServiceRecord {
            service: "io.systemd.Name".to_string(),
            socket: "/run/systemd/userdb/io.systemd.Name".to_string(),
            description: "System Name Database".to_string(),
        },
        ServiceRecord {
            service: "io.systemd.Home".to_string(),
            socket: "/run/systemd/userdb/io.systemd.Home".to_string(),
            description: "Home Directory User Database".to_string(),
        },
        ServiceRecord {
            service: "io.systemd.DropIn".to_string(),
            socket: "/run/systemd/userdb/io.systemd.DropIn".to_string(),
            description: "Drop-in Record User Database".to_string(),
        },
        ServiceRecord {
            service: "io.systemd.Shadow".to_string(),
            socket: "/run/systemd/userdb/io.systemd.Shadow".to_string(),
            description: "Shadow Password User Database".to_string(),
        },
    ]
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

fn show_user_record(u: &UserRecord) {
    println!("     User Name: {}", u.user_name);
    println!("           UID: {}", u.uid);
    println!("           GID: {}", u.gid);
    if let Some(ref real) = u.real_name {
        println!("     Real Name: {real}");
    }
    if let Some(ref home) = u.home_directory {
        println!("Home Directory: {home}");
    }
    if let Some(ref sh) = u.shell {
        println!("         Shell: {sh}");
    }
    println!("       Service: {}", u.service);
    println!("   Disposition: {}", u.disposition);
    if let Some(locked) = u.locked {
        println!("        Locked: {}", if locked { "yes" } else { "no" });
    }
}

fn show_group_record(g: &GroupRecord) {
    let members_str = if g.members.is_empty() {
        "(none)".to_string()
    } else {
        g.members.join(", ")
    };
    println!("    Group Name: {}", g.group_name);
    println!("           GID: {}", g.gid);
    println!("       Members: {members_str}");
    println!("       Service: {}", g.service);
    println!("   Disposition: {}", g.disposition);
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let filter = cli.service.as_deref();

    let cmd = match cli.command {
        Some(c) => c,
        None => {
            if !cli.names.is_empty() {
                Commands::User {
                    names: cli.names.clone(),
                }
            } else {
                Commands::Users
            }
        }
    };

    match cmd {
        Commands::User { names } => {
            let all_users = load_users(filter);
            let target_names = if names.is_empty() {
                vec![unsafe { libc::getuid() }.to_string()]
            } else {
                names
            };

            let mut matched_users = Vec::new();
            for query in &target_names {
                let user_opt = if let Ok(uid) = query.parse::<u32>() {
                    all_users.iter().find(|u| u.uid == uid)
                } else {
                    all_users.iter().find(|u| &u.user_name == query)
                };

                if let Some(u) = user_opt {
                    matched_users.push(u.clone());
                    if cli.json.is_none() || cli.json == Some(JsonMode::Off) {
                        show_user_record(u);
                        println!();
                    }
                } else {
                    eprintln!("User {query} not found.");
                }
            }

            if let Some(mode) = cli.json {
                if mode != JsonMode::Off {
                    if matched_users.len() == 1 {
                        print_json(&matched_users[0], Some(mode))?;
                    } else {
                        print_json(&matched_users, Some(mode))?;
                    }
                }
            }
        }
        Commands::Users => {
            let users = load_users(filter);
            if let Some(mode) = cli.json {
                if mode != JsonMode::Off {
                    return print_json(&users, Some(mode));
                }
            }

            if !cli.no_legend {
                println!(
                    "{:<20} {:>5} {:>5} {:<20} {:<24} {:<16} {:<20}",
                    "USER", "UID", "GID", "REALNAME", "HOME", "SHELL", "SERVICE"
                );
            }
            for u in &users {
                println!(
                    "{:<20} {:>5} {:>5} {:<20} {:<24} {:<16} {:<20}",
                    u.user_name,
                    u.uid,
                    u.gid,
                    u.real_name.as_deref().unwrap_or("-"),
                    u.home_directory.as_deref().unwrap_or("-"),
                    u.shell.as_deref().unwrap_or("-"),
                    u.service
                );
            }
            if !cli.no_legend {
                println!("\n{} users listed.", users.len());
            }
        }
        Commands::Group { names } => {
            let all_groups = load_groups(filter);
            let target_names = if names.is_empty() {
                vec![unsafe { libc::getgid() }.to_string()]
            } else {
                names
            };

            let mut matched_groups = Vec::new();
            for query in &target_names {
                let group_opt = if let Ok(gid) = query.parse::<u32>() {
                    all_groups.iter().find(|g| g.gid == gid)
                } else {
                    all_groups.iter().find(|g| &g.group_name == query)
                };

                if let Some(g) = group_opt {
                    matched_groups.push(g.clone());
                    if cli.json.is_none() || cli.json == Some(JsonMode::Off) {
                        show_group_record(g);
                        println!();
                    }
                } else {
                    eprintln!("Group {query} not found.");
                }
            }

            if let Some(mode) = cli.json {
                if mode != JsonMode::Off {
                    if matched_groups.len() == 1 {
                        print_json(&matched_groups[0], Some(mode))?;
                    } else {
                        print_json(&matched_groups, Some(mode))?;
                    }
                }
            }
        }
        Commands::Groups => {
            let groups = load_groups(filter);
            if let Some(mode) = cli.json {
                if mode != JsonMode::Off {
                    return print_json(&groups, Some(mode));
                }
            }

            if !cli.no_legend {
                println!(
                    "{:<20} {:>5} {:<30} {:<20}",
                    "GROUP", "GID", "MEMBERS", "SERVICE"
                );
            }
            for g in &groups {
                let members_str = if g.members.is_empty() {
                    "-".to_string()
                } else {
                    g.members.join(",")
                };
                println!(
                    "{:<20} {:>5} {:<30} {:<20}",
                    g.group_name, g.gid, members_str, g.service
                );
            }
            if !cli.no_legend {
                println!("\n{} groups listed.", groups.len());
            }
        }
        Commands::Members { groups } => {
            let all_groups = load_groups(filter);
            let mut members = Vec::new();

            for g in &all_groups {
                if !groups.is_empty() && !groups.contains(&g.group_name) {
                    continue;
                }
                for u in &g.members {
                    members.push(MembershipRecord {
                        user: u.clone(),
                        group: g.group_name.clone(),
                        service: g.service.clone(),
                    });
                }
            }

            if let Some(mode) = cli.json {
                if mode != JsonMode::Off {
                    return print_json(&members, Some(mode));
                }
            }

            if !cli.no_legend {
                println!("{:<20} {:<20} {:<20}", "USER", "GROUP", "SERVICE");
            }
            for m in &members {
                println!("{:<20} {:<20} {:<20}", m.user, m.group, m.service);
            }
            if !cli.no_legend {
                println!("\n{} memberships listed.", members.len());
            }
        }
        Commands::Services => {
            let services = load_services();
            if let Some(mode) = cli.json {
                if mode != JsonMode::Off {
                    return print_json(&services, Some(mode));
                }
            }

            if !cli.no_legend {
                println!("{:<26} {:<45} {:<30}", "SERVICE", "SOCKET", "DESCRIPTION");
            }
            for s in &services {
                println!("{:<26} {:<45} {:<30}", s.service, s.socket, s.description);
            }
            if !cli.no_legend {
                println!("\n{} services listed.", services.len());
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_userdbctl_cli_parsing() {
        let cli = Cli::try_parse_from(["rustuserdbctl", "users"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Users)));

        let cli = Cli::try_parse_from(["rustuserdbctl", "users", "-j"]).unwrap();
        assert_eq!(cli.json, Some(JsonMode::Pretty));

        let cli = Cli::try_parse_from(["rustuserdbctl", "user", "root"]).unwrap();
        if let Some(Commands::User { names }) = cli.command {
            assert_eq!(names, vec!["root".to_string()]);
        } else {
            panic!("Expected User subcommand");
        }

        let cli = Cli::try_parse_from(["rustuserdbctl", "members", "wheel", "sudo"]).unwrap();
        if let Some(Commands::Members { groups }) = cli.command {
            assert_eq!(groups, vec!["wheel".to_string(), "sudo".to_string()]);
        } else {
            panic!("Expected Members subcommand");
        }

        let cli = Cli::try_parse_from(["rustuserdbctl", "root"]).unwrap();
        assert!(cli.command.is_none());
        assert_eq!(cli.names, vec!["root".to_string()]);
    }
}
