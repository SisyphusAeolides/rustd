// SPDX-License-Identifier: LGPL-2.1-or-later
use clap::Parser;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(
    name = "rustd-sysusers",
    about = "Allocate system users and groups according to sysusers.d files",
    version,
    long_about = "Creates system users and groups and adds users to groups at package installation or boot time according to declarative sysusers.d configurations."
)]
struct Cli {
    /// Configuration files or directories to load
    config_files: Vec<PathBuf>,

    /// Operates on the specified filesystem root directory
    #[arg(long = "root", default_value = "/")]
    root: PathBuf,

    /// Override config files with path
    #[arg(long = "replace")]
    replace: Option<PathBuf>,

    /// Read declarative rules from stdin
    #[arg(long = "inline")]
    inline: bool,

    /// Concatenate and dump configuration files to stdout
    #[arg(long = "cat-config")]
    cat_config: bool,

    /// Do not modify system databases, only simulate actions
    #[arg(long = "dry-run")]
    dry_run: bool,

    /// Do not pipe output into a pager
    #[arg(long = "no-pager")]
    no_pager: bool,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum SysUserRule {
    User {
        name: String,
        uid_spec: String,
        gecos: String,
        home: String,
        shell: String,
    },
    Group {
        name: String,
        gid_spec: String,
    },
    Member {
        user: String,
        group: String,
    },
    Range {
        min: u32,
        max: u32,
    },
}

#[derive(Debug, Clone)]
struct ExistingUser {
    name: String,
    uid: u32,
    gid: u32,
    gecos: String,
    home: String,
    shell: String,
}

#[derive(Debug, Clone)]
struct ExistingGroup {
    name: String,
    gid: u32,
    members: Vec<String>,
}

fn parse_rule_line(line: &str) -> Option<SysUserRule> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
        return None;
    }

    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for ch in line.chars() {
        if ch == '"' {
            in_quotes = !in_quotes;
        } else if ch.is_whitespace() && !in_quotes {
            if !current.is_empty() {
                tokens.push(current.clone());
                current.clear();
            }
        } else {
            current.push(ch);
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }

    if tokens.is_empty() {
        return None;
    }

    let kind = tokens[0].as_str();
    match kind {
        "u" | "u!" => {
            if tokens.len() < 2 {
                return None;
            }
            let name = tokens[1].clone();
            let uid_spec = tokens.get(2).cloned().unwrap_or_else(|| "-".to_string());
            let gecos = tokens.get(3).cloned().unwrap_or_else(|| "-".to_string());
            let home = tokens.get(4).cloned().unwrap_or_else(|| "-".to_string());
            let shell = tokens.get(5).cloned().unwrap_or_else(|| "-".to_string());
            Some(SysUserRule::User {
                name,
                uid_spec,
                gecos,
                home,
                shell,
            })
        }
        "g" | "g!" => {
            if tokens.len() < 2 {
                return None;
            }
            let name = tokens[1].clone();
            let gid_spec = tokens.get(2).cloned().unwrap_or_else(|| "-".to_string());
            Some(SysUserRule::Group { name, gid_spec })
        }
        "m" | "m!" => {
            if tokens.len() < 3 {
                return None;
            }
            let user = tokens[1].clone();
            let group = tokens[2].clone();
            Some(SysUserRule::Member { user, group })
        }
        "r" => {
            if tokens.len() >= 3 {
                let range_str = &tokens[2];
                if let Some((min_str, max_str)) = range_str.split_once('-') {
                    if let (Ok(min), Ok(max)) = (min_str.parse::<u32>(), max_str.parse::<u32>()) {
                        return Some(SysUserRule::Range { min, max });
                    }
                }
            }
            None
        }
        _ => None,
    }
}

fn load_config_paths(root: &Path, cli_files: &[PathBuf]) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let mut file_map = BTreeMap::new();

    if !cli_files.is_empty() {
        for f in cli_files {
            if f.is_file() {
                paths.push(f.clone());
            } else if f.is_dir() {
                if let Ok(entries) = fs::read_dir(f) {
                    for entry in entries.flatten() {
                        let p = entry.path();
                        if p.extension().and_then(|s| s.to_str()) == Some("conf") {
                            paths.push(p);
                        }
                    }
                }
            }
        }
        return paths;
    }

    let search_dirs = [
        root.join("etc/sysusers.d"),
        root.join("run/sysusers.d"),
        root.join("usr/lib/sysusers.d"),
        root.join("lib/sysusers.d"),
    ];

    for dir in &search_dirs {
        if dir.is_dir() {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("conf") {
                        if let Some(filename) = path.file_name() {
                            file_map.entry(filename.to_os_string()).or_insert(path);
                        }
                    }
                }
            }
        }
    }

    for path in file_map.into_values() {
        paths.push(path);
    }
    paths.sort();
    paths
}

fn read_passwd(root: &Path) -> (BTreeMap<String, ExistingUser>, BTreeSet<u32>) {
    let mut users = BTreeMap::new();
    let mut uids = BTreeSet::new();
    let passwd_path = root.join("etc/passwd");

    if let Ok(content) = fs::read_to_string(passwd_path) {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 7 {
                let name = parts[0].to_string();
                let uid = parts[2].parse::<u32>().unwrap_or(65534);
                let gid = parts[3].parse::<u32>().unwrap_or(65534);
                let gecos = parts[4].to_string();
                let home = parts[5].to_string();
                let shell = parts[6].to_string();

                uids.insert(uid);
                users.insert(
                    name.clone(),
                    ExistingUser {
                        name,
                        uid,
                        gid,
                        gecos,
                        home,
                        shell,
                    },
                );
            }
        }
    }

    (users, uids)
}

fn read_group(root: &Path) -> (BTreeMap<String, ExistingGroup>, BTreeSet<u32>) {
    let mut groups = BTreeMap::new();
    let mut gids = BTreeSet::new();
    let group_path = root.join("etc/group");

    if let Ok(content) = fs::read_to_string(group_path) {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 {
                let name = parts[0].to_string();
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

                gids.insert(gid);
                groups.insert(name.clone(), ExistingGroup { name, gid, members });
            }
        }
    }

    (groups, gids)
}

fn allocate_next_id(used: &BTreeSet<u32>, preferred: Option<u32>, min: u32, max: u32) -> u32 {
    if let Some(pref) = preferred {
        if !used.contains(&pref) {
            return pref;
        }
    }
    for id in min..=max {
        if !used.contains(&id) {
            return id;
        }
    }
    // Fallback if system range is exhausted
    for id in 1000..60000 {
        if !used.contains(&id) {
            return id;
        }
    }
    65534
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let root = cli.root.canonicalize().unwrap_or(cli.root.clone());

    let config_files = load_config_paths(&root, &cli.config_files);

    if cli.cat_config {
        if config_files.is_empty() {
            println!("# No configuration files found.");
            return Ok(());
        }
        for file in &config_files {
            println!("# {}", file.display());
            if let Ok(content) = fs::read_to_string(file) {
                print!("{content}");
                if !content.ends_with('\n') {
                    println!();
                }
            }
            println!();
        }
        return Ok(());
    }

    let mut rules = Vec::new();

    if cli.inline {
        let stdin = io::stdin();
        for line in stdin.lock().lines() {
            if let Ok(l) = line {
                if let Some(rule) = parse_rule_line(&l) {
                    rules.push(rule);
                }
            }
        }
    } else {
        for file in &config_files {
            if let Ok(content) = fs::read_to_string(file) {
                for line in content.lines() {
                    if let Some(rule) = parse_rule_line(line) {
                        rules.push(rule);
                    }
                }
            }
        }
    }

    let (mut users, mut used_uids) = read_passwd(&root);
    let (mut groups, mut used_gids) = read_group(&root);

    let mut new_groups = Vec::new();
    let mut new_users = Vec::new();
    let mut new_memberships = Vec::new();

    // 1. Process Groups
    for rule in &rules {
        if let SysUserRule::Group { name, gid_spec } = rule {
            if !groups.contains_key(name) {
                let preferred_gid = gid_spec.parse::<u32>().ok();
                let gid = allocate_next_id(&used_gids, preferred_gid, 100, 999);
                used_gids.insert(gid);
                let g = ExistingGroup {
                    name: name.clone(),
                    gid,
                    members: Vec::new(),
                };
                groups.insert(name.clone(), g.clone());
                new_groups.push(g);
            }
        }
    }

    // 2. Process Users
    for rule in &rules {
        if let SysUserRule::User {
            name,
            uid_spec,
            gecos,
            home,
            shell,
        } = rule
        {
            let (target_uid, group_name_or_gid) = if let Some((u, g)) = uid_spec.split_once(':') {
                (u.to_string(), Some(g.to_string()))
            } else {
                (uid_spec.clone(), None)
            };

            let gid = if let Some(ref grp_str) = group_name_or_gid {
                if let Ok(num_gid) = grp_str.parse::<u32>() {
                    num_gid
                } else if let Some(g) = groups.get(grp_str) {
                    g.gid
                } else {
                    let new_gid = allocate_next_id(&used_gids, None, 100, 999);
                    used_gids.insert(new_gid);
                    let g = ExistingGroup {
                        name: grp_str.clone(),
                        gid: new_gid,
                        members: Vec::new(),
                    };
                    groups.insert(grp_str.clone(), g.clone());
                    new_groups.push(g);
                    new_gid
                }
            } else if let Some(g) = groups.get(name) {
                g.gid
            } else {
                let new_gid = allocate_next_id(&used_gids, None, 100, 999);
                used_gids.insert(new_gid);
                let g = ExistingGroup {
                    name: name.clone(),
                    gid: new_gid,
                    members: Vec::new(),
                };
                groups.insert(name.clone(), g.clone());
                new_groups.push(g);
                new_gid
            };

            if !users.contains_key(name) {
                let preferred_uid = target_uid.parse::<u32>().ok();
                let uid = allocate_next_id(&used_uids, preferred_uid, 100, 999);
                used_uids.insert(uid);

                let real_gecos = if gecos == "-" {
                    name.clone()
                } else {
                    gecos.clone()
                };
                let real_home = if home == "-" {
                    "/".to_string()
                } else {
                    home.clone()
                };
                let real_shell = if shell == "-" {
                    if Path::new("/sbin/nologin").exists() {
                        "/sbin/nologin".to_string()
                    } else if Path::new("/usr/sbin/nologin").exists() {
                        "/usr/sbin/nologin".to_string()
                    } else {
                        "/bin/false".to_string()
                    }
                } else {
                    shell.clone()
                };

                let u = ExistingUser {
                    name: name.clone(),
                    uid,
                    gid,
                    gecos: real_gecos,
                    home: real_home,
                    shell: real_shell,
                };
                users.insert(name.clone(), u.clone());
                new_users.push(u);
            }
        }
    }

    // 3. Process Memberships
    for rule in &rules {
        if let SysUserRule::Member { user, group } = rule {
            if let Some(g) = groups.get_mut(group) {
                if !g.members.contains(user) {
                    g.members.push(user.clone());
                    new_memberships.push((user.clone(), group.clone()));
                }
            }
        }
    }

    // Output actions
    for g in &new_groups {
        println!("Creating group '{}' with GID {}.", g.name, g.gid);
    }
    for u in &new_users {
        println!(
            "Creating user '{}' (UID {}, GID {}, Home '{}', Shell '{}').",
            u.name, u.uid, u.gid, u.home, u.shell
        );
    }
    for (u, g) in &new_memberships {
        println!("Adding user '{u}' to group '{g}'.");
    }

    if cli.dry_run {
        println!("Dry run complete. No modifications written to system databases.");
        return Ok(());
    }

    // Write modifications to /etc/group and /etc/passwd if changes occurred and permissions allow
    if !new_groups.is_empty() || !new_memberships.is_empty() {
        let group_path = root.join("etc/group");
        if group_path.exists() {
            if let Ok(mut file) = OpenOptions::new().append(true).open(&group_path) {
                for g in &new_groups {
                    let mem_str = g.members.join(",");
                    let _ = writeln!(file, "{}:x:{}:{}", g.name, g.gid, mem_str);
                }
            }
        }
    }

    if !new_users.is_empty() {
        let passwd_path = root.join("etc/passwd");
        if passwd_path.exists() {
            if let Ok(mut file) = OpenOptions::new().append(true).open(&passwd_path) {
                for u in &new_users {
                    let _ = writeln!(
                        file,
                        "{}:x:{}:{}:{}:{}:{}",
                        u.name, u.uid, u.gid, u.gecos, u.home, u.shell
                    );
                }
            }
        }

        let shadow_path = root.join("etc/shadow");
        if shadow_path.exists() {
            if let Ok(mut file) = OpenOptions::new().append(true).open(&shadow_path) {
                for u in &new_users {
                    let _ = writeln!(file, "{}:!*:19000:0:99999:7:::", u.name);
                }
            }
        }
    }

    Ok(())
}
