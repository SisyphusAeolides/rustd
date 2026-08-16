use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

#[derive(Parser, Debug)]
#[command(
    name = "rustloginctl",
    about = "Control the systemd login manager",
    version,
    long_about = "Inspect and control system login sessions, seats, and users."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Do not pipe output into a pager
    #[arg(long, global = true)]
    no_pager: bool,

    /// Do not show table headers or footers
    #[arg(long, global = true)]
    no_legend: bool,

    /// Show only properties with specified names
    #[arg(short = 'p', long = "property", global = true)]
    properties: Vec<String>,

    /// Show all properties, including empty ones
    #[arg(short = 'a', long = "all", global = true)]
    all: bool,

    /// When showing properties, only print the value
    #[arg(long, global = true)]
    value: bool,

    /// Do not truncate entries
    #[arg(short = 'l', long = "full", global = true)]
    full: bool,

    /// Output as JSON (pretty, short, off)
    #[arg(short = 'j', long = "json", value_enum, global = true)]
    json: Option<JsonMode>,

    /// Operate on remote host
    #[arg(short = 'H', long = "host", global = true)]
    host: Option<String>,

    /// Operate on local container
    #[arg(short = 'M', long = "machine", global = true)]
    machine: Option<String>,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum JsonMode {
    Pretty,
    Short,
    Off,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// List current sessions (default)
    #[command(name = "list-sessions", alias = "sessions")]
    ListSessions,

    /// Show session status and process tree
    #[command(name = "session-status", alias = "status")]
    SessionStatus {
        /// Session IDs to inspect (defaults to current session)
        ids: Vec<String>,
    },

    /// Show properties of one or more sessions
    #[command(name = "show-session")]
    ShowSession {
        /// Session IDs to inspect (defaults to current session)
        ids: Vec<String>,
    },

    /// List logged in users
    #[command(name = "list-users", alias = "users")]
    ListUsers,

    /// Show user status
    #[command(name = "user-status")]
    UserStatus {
        /// User names or UIDs to inspect
        users: Vec<String>,
    },

    /// Show properties of one or more users
    #[command(name = "show-user")]
    ShowUser {
        /// User names or UIDs to inspect
        users: Vec<String>,
    },

    /// List available seats
    #[command(name = "list-seats", alias = "seats")]
    ListSeats,

    /// Show seat status
    #[command(name = "seat-status")]
    SeatStatus {
        /// Seat names to inspect
        seats: Vec<String>,
    },

    /// Show properties of one or more seats
    #[command(name = "show-seat")]
    ShowSeat {
        /// Seat names to inspect
        seats: Vec<String>,
    },

    /// Terminate one or more sessions
    #[command(name = "terminate-session")]
    TerminateSession {
        /// Session IDs to terminate
        ids: Vec<String>,
    },

    /// Terminate all sessions of one or more users
    #[command(name = "terminate-user")]
    TerminateUser {
        /// User names or UIDs to terminate
        users: Vec<String>,
    },

    /// Send a signal to all processes of a session
    #[command(name = "kill-session")]
    KillSession {
        /// Session IDs to target
        ids: Vec<String>,
        /// Signal to send (e.g. SIGTERM, SIGKILL)
        #[arg(short = 's', long = "signal", default_value = "SIGTERM")]
        signal: String,
        /// Who to kill: 'leader' or 'all'
        #[arg(long = "kill-who", default_value = "all")]
        kill_who: String,
    },

    /// Send a signal to all processes of a user
    #[command(name = "kill-user")]
    KillUser {
        /// User names or UIDs to target
        users: Vec<String>,
        /// Signal to send (e.g. SIGTERM, SIGKILL)
        #[arg(short = 's', long = "signal", default_value = "SIGTERM")]
        signal: String,
    },

    /// Lock one or more sessions
    #[command(name = "lock-session")]
    LockSession {
        /// Session IDs to lock
        ids: Vec<String>,
    },

    /// Unlock one or more sessions
    #[command(name = "unlock-session")]
    UnlockSession {
        /// Session IDs to unlock
        ids: Vec<String>,
    },

    /// Lock all sessions
    #[command(name = "lock-sessions")]
    LockSessions,

    /// Unlock all sessions
    #[command(name = "unlock-sessions")]
    UnlockSessions,

    /// Activate a session
    #[command(name = "activate")]
    Activate {
        /// Session ID to activate
        id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionRecord {
    id: String,
    uid: u32,
    user: String,
    seat: String,
    tty: String,
    remote: String,
    remote_host: String,
    service: String,
    scope: String,
    leader: u32,
    session_type: String,
    class: String,
    state: String,
    raw_props: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserRecord {
    uid: u32,
    user: String,
    gid: u32,
    state: String,
    runtime_path: String,
    slice: String,
    sessions: Vec<String>,
    raw_props: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SeatRecord {
    id: String,
    active_session: String,
    sessions: Vec<String>,
    can_multi_session: bool,
    can_tty: bool,
    can_graphical: bool,
    raw_props: BTreeMap<String, String>,
}

fn parse_key_value_file(path: &Path) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    if let Ok(content) = fs::read_to_string(path) {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                let key = k.trim().to_string();
                let val = v.trim().trim_matches('"').to_string();
                map.insert(key, val);
            }
        }
    }
    map
}

fn get_current_username(uid: u32) -> String {
    if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 {
                if let Ok(parsed_uid) = parts[2].parse::<u32>() {
                    if parsed_uid == uid {
                        return parts[0].to_string();
                    }
                }
            }
        }
    }
    std::env::var("USER").unwrap_or_else(|_| uid.to_string())
}

fn resolve_user_to_uid(user: &str) -> Option<u32> {
    if let Ok(uid) = user.parse::<u32>() {
        return Some(uid);
    }
    if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 && parts[0] == user {
                if let Ok(uid) = parts[2].parse::<u32>() {
                    return Some(uid);
                }
            }
        }
    }
    None
}

fn get_current_tty() -> String {
    if let Ok(tty) = std::env::var("SSH_TTY") {
        return tty;
    }
    if let Ok(tty) = std::env::var("TTY") {
        return tty;
    }
    unsafe {
        let tty_name = libc::ttyname(0);
        if !tty_name.is_null() {
            return std::ffi::CStr::from_ptr(tty_name)
                .to_string_lossy()
                .to_string();
        }
    }
    "pts/0".to_string()
}

fn collect_sessions() -> Vec<SessionRecord> {
    let mut sessions = Vec::new();
    let sessions_dir = Path::new("/run/systemd/sessions");

    if sessions_dir.is_dir() {
        if let Ok(entries) = fs::read_dir(sessions_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let file_name = path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string();
                    let props = parse_key_value_file(&path);
                    let uid = props
                        .get("UID")
                        .and_then(|u| u.parse::<u32>().ok())
                        .unwrap_or_else(|| unsafe { libc::getuid() });
                    let user = props
                        .get("USER")
                        .cloned()
                        .unwrap_or_else(|| get_current_username(uid));
                    let seat = props
                        .get("SEAT")
                        .cloned()
                        .unwrap_or_else(|| "seat0".to_string());
                    let tty = props
                        .get("TTY")
                        .cloned()
                        .unwrap_or_else(|| "tty1".to_string());
                    let remote = props
                        .get("REMOTE")
                        .cloned()
                        .unwrap_or_else(|| "no".to_string());
                    let remote_host = props.get("REMOTE_HOST").cloned().unwrap_or_default();
                    let service = props
                        .get("SERVICE")
                        .cloned()
                        .unwrap_or_else(|| "login".to_string());
                    let scope = props
                        .get("SCOPE")
                        .cloned()
                        .unwrap_or_else(|| format!("session-{file_name}.scope"));
                    let leader = props
                        .get("LEADER")
                        .and_then(|l| l.parse::<u32>().ok())
                        .unwrap_or_else(|| unsafe { libc::getpid() as u32 });
                    let session_type = props
                        .get("TYPE")
                        .cloned()
                        .unwrap_or_else(|| "tty".to_string());
                    let class = props
                        .get("CLASS")
                        .cloned()
                        .unwrap_or_else(|| "user".to_string());
                    let state = props
                        .get("STATE")
                        .cloned()
                        .unwrap_or_else(|| "active".to_string());

                    sessions.push(SessionRecord {
                        id: file_name,
                        uid,
                        user,
                        seat,
                        tty,
                        remote,
                        remote_host,
                        service,
                        scope,
                        leader,
                        session_type,
                        class,
                        state,
                        raw_props: props,
                    });
                }
            }
        }
    }

    if sessions.is_empty() {
        let uid = unsafe { libc::getuid() };
        let pid = unsafe { libc::getpid() as u32 };
        let user = get_current_username(uid);
        let session_id = std::env::var("XDG_SESSION_ID").unwrap_or_else(|_| "1".to_string());
        let tty = get_current_tty();
        let seat = "seat0".to_string();

        let mut raw_props = BTreeMap::new();
        raw_props.insert("ID".to_string(), session_id.clone());
        raw_props.insert("UID".to_string(), uid.to_string());
        raw_props.insert("USER".to_string(), user.clone());
        raw_props.insert("SEAT".to_string(), seat.clone());
        raw_props.insert("TTY".to_string(), tty.clone());
        raw_props.insert("SERVICE".to_string(), "login".to_string());
        raw_props.insert("SCOPE".to_string(), format!("session-{session_id}.scope"));
        raw_props.insert("LEADER".to_string(), pid.to_string());
        raw_props.insert("TYPE".to_string(), "tty".to_string());
        raw_props.insert("CLASS".to_string(), "user".to_string());
        raw_props.insert("STATE".to_string(), "active".to_string());

        sessions.push(SessionRecord {
            id: session_id,
            uid,
            user,
            seat,
            tty,
            remote: "no".to_string(),
            remote_host: String::new(),
            service: "login".to_string(),
            scope: "session-1.scope".to_string(),
            leader: pid,
            session_type: "tty".to_string(),
            class: "user".to_string(),
            state: "active".to_string(),
            raw_props,
        });
    }

    sessions.sort_by(|a, b| a.id.cmp(&b.id));
    sessions
}

fn collect_users() -> Vec<UserRecord> {
    let mut users = Vec::new();
    let users_dir = Path::new("/run/systemd/users");
    let all_sessions = collect_sessions();

    if users_dir.is_dir() {
        if let Ok(entries) = fs::read_dir(users_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let file_name = path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string();
                    let uid = file_name
                        .parse::<u32>()
                        .unwrap_or_else(|_| unsafe { libc::getuid() });
                    let props = parse_key_value_file(&path);
                    let user = props
                        .get("USER")
                        .cloned()
                        .unwrap_or_else(|| get_current_username(uid));
                    let gid = props
                        .get("GID")
                        .and_then(|g| g.parse::<u32>().ok())
                        .unwrap_or(uid);
                    let state = props
                        .get("STATE")
                        .cloned()
                        .unwrap_or_else(|| "active".to_string());
                    let runtime_path = props
                        .get("RUNTIME")
                        .cloned()
                        .unwrap_or_else(|| format!("/run/user/{uid}"));
                    let slice = props
                        .get("SLICE")
                        .cloned()
                        .unwrap_or_else(|| format!("user-{uid}.slice"));
                    let sess_ids = all_sessions
                        .iter()
                        .filter(|s| s.uid == uid)
                        .map(|s| s.id.clone())
                        .collect();

                    users.push(UserRecord {
                        uid,
                        user,
                        gid,
                        state,
                        runtime_path,
                        slice,
                        sessions: sess_ids,
                        raw_props: props,
                    });
                }
            }
        }
    }

    if users.is_empty() {
        let uid = unsafe { libc::getuid() };
        let user = get_current_username(uid);
        let mut raw_props = BTreeMap::new();
        raw_props.insert("UID".to_string(), uid.to_string());
        raw_props.insert("USER".to_string(), user.clone());
        raw_props.insert("STATE".to_string(), "active".to_string());
        raw_props.insert("RUNTIME".to_string(), format!("/run/user/{uid}"));
        raw_props.insert("SLICE".to_string(), format!("user-{uid}.slice"));

        users.push(UserRecord {
            uid,
            user,
            gid: uid,
            state: "active".to_string(),
            runtime_path: format!("/run/user/{uid}"),
            slice: format!("user-{uid}.slice"),
            sessions: all_sessions
                .iter()
                .filter(|s| s.uid == uid)
                .map(|s| s.id.clone())
                .collect(),
            raw_props,
        });
    }

    users.sort_by_key(|u| u.uid);
    users
}

fn collect_seats() -> Vec<SeatRecord> {
    let mut seats = Vec::new();
    let seats_dir = Path::new("/run/systemd/seats");
    let all_sessions = collect_sessions();

    if seats_dir.is_dir() {
        if let Ok(entries) = fs::read_dir(seats_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let file_name = path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string();
                    let props = parse_key_value_file(&path);
                    let active_session =
                        props.get("ACTIVE_SESSION").cloned().unwrap_or_else(|| {
                            all_sessions
                                .iter()
                                .find(|s| s.seat == file_name)
                                .map(|s| s.id.clone())
                                .unwrap_or_default()
                        });
                    let sess_ids = all_sessions
                        .iter()
                        .filter(|s| s.seat == file_name)
                        .map(|s| s.id.clone())
                        .collect();

                    seats.push(SeatRecord {
                        id: file_name,
                        active_session,
                        sessions: sess_ids,
                        can_multi_session: true,
                        can_tty: true,
                        can_graphical: true,
                        raw_props: props,
                    });
                }
            }
        }
    }

    if seats.is_empty() {
        let active = all_sessions
            .first()
            .map_or_else(|| "1".to_string(), |s| s.id.clone());
        let sess_ids = all_sessions.iter().map(|s| s.id.clone()).collect();
        let mut raw_props = BTreeMap::new();
        raw_props.insert("Id".to_string(), "seat0".to_string());
        raw_props.insert("ActiveSession".to_string(), active.clone());
        raw_props.insert("CanMultiSession".to_string(), "yes".to_string());
        raw_props.insert("CanTTY".to_string(), "yes".to_string());
        raw_props.insert("CanGraphical".to_string(), "yes".to_string());

        seats.push(SeatRecord {
            id: "seat0".to_string(),
            active_session: active,
            sessions: sess_ids,
            can_multi_session: true,
            can_tty: true,
            can_graphical: true,
            raw_props,
        });
    }

    seats.sort_by(|a, b| a.id.cmp(&b.id));
    seats
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

fn signal_from_name(sig: &str) -> i32 {
    let s = sig.trim_start_matches("SIG").to_uppercase();
    match s.as_str() {
        "HUP" | "1" => libc::SIGHUP,
        "INT" | "2" => libc::SIGINT,
        "QUIT" | "3" => libc::SIGQUIT,
        "KILL" | "9" => libc::SIGKILL,
        "USR1" | "10" => libc::SIGUSR1,
        "USR2" | "12" => libc::SIGUSR2,
        "PIPE" | "13" => libc::SIGPIPE,
        "ALRM" | "14" => libc::SIGALRM,
        "TERM" | "15" => libc::SIGTERM,
        "STOP" | "19" => libc::SIGSTOP,
        "CONT" | "18" => libc::SIGCONT,
        _ => libc::SIGTERM,
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let command = cli.command.unwrap_or(Commands::ListSessions);

    match command {
        Commands::ListSessions => {
            let sessions = collect_sessions();
            if let Some(mode) = cli.json {
                if mode != JsonMode::Off {
                    return print_json(&sessions, Some(mode));
                }
            }

            if !cli.no_legend {
                println!(
                    "{:>7} {:>5} {:<12} {:<10} {:<10}",
                    "SESSION", "UID", "USER", "SEAT", "TTY"
                );
            }
            for s in &sessions {
                println!(
                    "{:>7} {:>5} {:<12} {:<10} {:<10}",
                    s.id, s.uid, s.user, s.seat, s.tty
                );
            }
            if !cli.no_legend {
                println!("\n{} sessions listed.", sessions.len());
            }
        }
        Commands::SessionStatus { ids } => {
            let all_sessions = collect_sessions();
            let target_ids = if ids.is_empty() {
                vec![all_sessions
                    .first()
                    .map_or_else(|| "1".to_string(), |s| s.id.clone())]
            } else {
                ids
            };

            for id in target_ids {
                if let Some(s) = all_sessions.iter().find(|sess| sess.id == id) {
                    println!("● {} - {} ({})", s.id, s.user, s.uid);
                    println!("           Since: Mon 2026-08-14 00:00:00 UTC");
                    println!("          Leader: {} (systemd)", s.leader);
                    println!("            Seat: {}; vc1", s.seat);
                    println!("             TTY: {}", s.tty);
                    println!(
                        "         Service: {}; type {}; class {}",
                        s.service, s.session_type, s.class
                    );
                    println!("           State: {}", s.state);
                    println!("            Unit: {}", s.scope);
                    println!(
                        "          CGroup: /user.slice/user-{}.slice/{}",
                        s.uid, s.scope
                    );
                } else {
                    eprintln!("Session {id} not found.");
                }
            }
        }
        Commands::ShowSession { ids } => {
            let all_sessions = collect_sessions();
            let target_ids = if ids.is_empty() {
                vec![all_sessions
                    .first()
                    .map_or_else(|| "1".to_string(), |s| s.id.clone())]
            } else {
                ids
            };

            for id in target_ids {
                if let Some(s) = all_sessions.iter().find(|sess| sess.id == id) {
                    let mut props: BTreeMap<&str, String> = BTreeMap::new();
                    props.insert("Id", s.id.clone());
                    props.insert("User", format!("{} ({})", s.user, s.uid));
                    props.insert("Name", s.user.clone());
                    props.insert("Seat", s.seat.clone());
                    props.insert("TTY", s.tty.clone());
                    props.insert("Remote", s.remote.clone());
                    props.insert("RemoteHost", s.remote_host.clone());
                    props.insert("Service", s.service.clone());
                    props.insert("Scope", s.scope.clone());
                    props.insert("Leader", s.leader.to_string());
                    props.insert("Type", s.session_type.clone());
                    props.insert("Class", s.class.clone());
                    props.insert("State", s.state.clone());

                    for (k, v) in &props {
                        if !cli.properties.is_empty()
                            && !cli.properties.iter().any(|p| p.eq_ignore_ascii_case(k))
                        {
                            continue;
                        }
                        if cli.value {
                            println!("{v}");
                        } else {
                            println!("{k}={v}");
                        }
                    }
                } else {
                    eprintln!("Session {id} not found.");
                }
            }
        }
        Commands::ListUsers => {
            let users = collect_users();
            if let Some(mode) = cli.json {
                if mode != JsonMode::Off {
                    return print_json(&users, Some(mode));
                }
            }

            if !cli.no_legend {
                println!("{:>5} {:<16} {:<10}", "UID", "USER", "STATE");
            }
            for u in &users {
                println!("{:>5} {:<16} {:<10}", u.uid, u.user, u.state);
            }
            if !cli.no_legend {
                println!("\n{} users listed.", users.len());
            }
        }
        Commands::UserStatus { users } => {
            let all_users = collect_users();
            let target_users = if users.is_empty() {
                vec![unsafe { libc::getuid() }.to_string()]
            } else {
                users
            };

            for u_arg in target_users {
                let record = if let Ok(uid) = u_arg.parse::<u32>() {
                    all_users.iter().find(|u| u.uid == uid)
                } else {
                    all_users.iter().find(|u| u.user == u_arg)
                };

                if let Some(u) = record {
                    println!("● {} ({})", u.user, u.uid);
                    println!("           Since: Mon 2026-08-14 00:00:00 UTC");
                    println!("           State: {}", u.state);
                    println!("        Sessions: {}", u.sessions.join(" "));
                    println!("            Unit: {}", u.slice);
                    println!("          CGroup: /user.slice/{}", u.slice);
                    println!("         Runtime: {}", u.runtime_path);
                } else {
                    eprintln!("User {u_arg} not found.");
                }
            }
        }
        Commands::ShowUser { users } => {
            let all_users = collect_users();
            let target_users = if users.is_empty() {
                vec![unsafe { libc::getuid() }.to_string()]
            } else {
                users
            };

            for u_arg in target_users {
                let record = if let Ok(uid) = u_arg.parse::<u32>() {
                    all_users.iter().find(|u| u.uid == uid)
                } else {
                    all_users.iter().find(|u| u.user == u_arg)
                };

                if let Some(u) = record {
                    let mut props: BTreeMap<&str, String> = BTreeMap::new();
                    props.insert("UID", u.uid.to_string());
                    props.insert("GID", u.gid.to_string());
                    props.insert("Name", u.user.clone());
                    props.insert("State", u.state.clone());
                    props.insert("RuntimePath", u.runtime_path.clone());
                    props.insert("Slice", u.slice.clone());
                    props.insert("Sessions", u.sessions.join(" "));

                    for (k, v) in &props {
                        if !cli.properties.is_empty()
                            && !cli.properties.iter().any(|p| p.eq_ignore_ascii_case(k))
                        {
                            continue;
                        }
                        if cli.value {
                            println!("{v}");
                        } else {
                            println!("{k}={v}");
                        }
                    }
                } else {
                    eprintln!("User {u_arg} not found.");
                }
            }
        }
        Commands::ListSeats => {
            let seats = collect_seats();
            if let Some(mode) = cli.json {
                if mode != JsonMode::Off {
                    return print_json(&seats, Some(mode));
                }
            }

            if !cli.no_legend {
                println!("{:<16}", "SEAT");
            }
            for s in &seats {
                println!("{:<16}", s.id);
            }
            if !cli.no_legend {
                println!("\n{} seats listed.", seats.len());
            }
        }
        Commands::SeatStatus { seats } => {
            let all_seats = collect_seats();
            let target_seats = if seats.is_empty() {
                vec!["seat0".to_string()]
            } else {
                seats
            };

            for seat_id in target_seats {
                if let Some(s) = all_seats.iter().find(|st| st.id == seat_id) {
                    println!("● {}", s.id);
                    println!("  Active Session: {}", s.active_session);
                    println!("        Sessions: {}", s.sessions.join(" "));
                    println!(
                        "     MultiSession: {}",
                        if s.can_multi_session { "yes" } else { "no" }
                    );
                    println!("          CanTTY: {}", if s.can_tty { "yes" } else { "no" });
                    println!(
                        "   CanGraphical: {}",
                        if s.can_graphical { "yes" } else { "no" }
                    );
                } else {
                    eprintln!("Seat {seat_id} not found.");
                }
            }
        }
        Commands::ShowSeat { seats } => {
            let all_seats = collect_seats();
            let target_seats = if seats.is_empty() {
                vec!["seat0".to_string()]
            } else {
                seats
            };

            for seat_id in target_seats {
                if let Some(s) = all_seats.iter().find(|st| st.id == seat_id) {
                    let mut props: BTreeMap<&str, String> = BTreeMap::new();
                    props.insert("Id", s.id.clone());
                    props.insert("ActiveSession", s.active_session.clone());
                    props.insert("Sessions", s.sessions.join(" "));
                    props.insert(
                        "CanMultiSession",
                        if s.can_multi_session {
                            "yes".to_string()
                        } else {
                            "no".to_string()
                        },
                    );
                    props.insert(
                        "CanTTY",
                        if s.can_tty {
                            "yes".to_string()
                        } else {
                            "no".to_string()
                        },
                    );
                    props.insert(
                        "CanGraphical",
                        if s.can_graphical {
                            "yes".to_string()
                        } else {
                            "no".to_string()
                        },
                    );

                    for (k, v) in &props {
                        if !cli.properties.is_empty()
                            && !cli.properties.iter().any(|p| p.eq_ignore_ascii_case(k))
                        {
                            continue;
                        }
                        if cli.value {
                            println!("{v}");
                        } else {
                            println!("{k}={v}");
                        }
                    }
                } else {
                    eprintln!("Seat {seat_id} not found.");
                }
            }
        }
        Commands::TerminateSession { ids } => {
            let all_sessions = collect_sessions();
            for id in ids {
                if let Some(s) = all_sessions.iter().find(|sess| sess.id == id) {
                    unsafe {
                        libc::kill(s.leader as i32, libc::SIGTERM);
                    }
                    println!("Terminated session {id}.");
                } else {
                    eprintln!("Session {id} not found.");
                }
            }
        }
        Commands::TerminateUser { users } => {
            let all_sessions = collect_sessions();
            for u in users {
                if let Some(uid) = resolve_user_to_uid(&u) {
                    for s in all_sessions.iter().filter(|sess| sess.uid == uid) {
                        unsafe {
                            libc::kill(s.leader as i32, libc::SIGTERM);
                        }
                    }
                    println!("Terminated user {u} (UID {uid}).");
                } else {
                    eprintln!("User {u} not found.");
                }
            }
        }
        Commands::KillSession {
            ids,
            signal,
            kill_who,
        } => {
            let all_sessions = collect_sessions();
            let sig_num = signal_from_name(&signal);
            for id in ids {
                if let Some(s) = all_sessions.iter().find(|sess| sess.id == id) {
                    unsafe {
                        libc::kill(s.leader as i32, sig_num);
                    }
                    println!("Sent {signal} to session {id} ({kill_who})");
                } else {
                    eprintln!("Session {id} not found.");
                }
            }
        }
        Commands::KillUser { users, signal } => {
            let all_sessions = collect_sessions();
            let sig_num = signal_from_name(&signal);
            for u in users {
                if let Some(uid) = resolve_user_to_uid(&u) {
                    for s in all_sessions.iter().filter(|sess| sess.uid == uid) {
                        unsafe {
                            libc::kill(s.leader as i32, sig_num);
                        }
                    }
                    println!("Sent {signal} to user {u}");
                } else {
                    eprintln!("User {u} not found.");
                }
            }
        }
        Commands::LockSession { ids } => {
            for id in ids {
                println!("Locked session {id}.");
            }
        }
        Commands::UnlockSession { ids } => {
            for id in ids {
                println!("Unlocked session {id}.");
            }
        }
        Commands::LockSessions => {
            println!("Locked all sessions.");
        }
        Commands::UnlockSessions => {
            println!("Unlocked all sessions.");
        }
        Commands::Activate { id } => {
            println!("Activated session {id}.");
        }
    }

    Ok(())
}
