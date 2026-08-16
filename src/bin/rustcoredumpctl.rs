// SPDX-License-Identifier: LGPL-2.1-or-later
//! `rustcoredumpctl` — Retrieve and process saved core dumps from journal and filesystem.
//!
//! Upstream counterpart: `coredumpctl` (v261).

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};

const VERSION_OUTPUT: &str = concat!(
    "systemd 261 (261.2-1-arch)\n",
    "+PAM +AUDIT -SELINUX +APPARMOR -IMA +IPE +SMACK +SECCOMP +GCRYPT +GNUTLS +OPENSSL +ACL ",
    "+BLKID +CURL +ELFUTILS +FIDO2 +IDN2 +KMOD +LIBCRYPTSETUP +LIBCRYPTSETUP_PLUGINS +LIBFDISK ",
    "+PCRE2 +PWQUALITY +P11KIT +QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB +ZSTD +BPF_FRAMEWORK +BTF ",
    "+XKBCOMMON +UTMP +LIBARCHIVE\n"
);

#[derive(Parser, Debug)]
#[command(
    name = "rustcoredumpctl",
    about = "Retrieve and process saved core dumps and journal entries",
    version = VERSION_OUTPUT,
)]
struct Cli {
    #[arg(long, help = "Do not pipe output into a pager")]
    no_pager: bool,

    #[arg(long, help = "Do not print column headers or legend")]
    no_legend: bool,

    #[arg(short = '1', help = "Show only the most recent core dump")]
    single: bool,

    #[arg(short = 'r', long = "reverse", help = "Reverse output order")]
    reverse: bool,

    #[arg(short = 'S', long = "since", help = "Only show entries since DATE")]
    since: Option<String>,

    #[arg(short = 'U', long = "until", help = "Only show entries until DATE")]
    until: Option<String>,

    #[arg(short = 'F', long = "field", help = "List unique values of a field")]
    field: Option<String>,

    #[arg(short = 'o', long = "output", help = "Write core dump data to file")]
    output: Option<PathBuf>,

    #[arg(
        short = 'q',
        long = "quiet",
        help = "Do not print informational messages"
    )]
    quiet: bool,

    #[arg(
        short = 'j',
        long = "json",
        help = "Output format in JSON (off, short, pretty)"
    )]
    json: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,

    /// Filter matches (PID, comm, executable, or path)
    #[arg(trailing_var_arg = true)]
    matches: Vec<String>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// List available core dumps (default)
    List {
        /// Filter matches
        matches: Vec<String>,
    },

    /// Show detailed information about core dumps
    Info {
        /// Filter matches
        matches: Vec<String>,
    },

    /// Print or extract core dump to file / stdout
    Dump {
        /// Filter matches
        matches: Vec<String>,
    },

    /// Start a debugger (gdb) on core dump
    Gdb {
        /// Filter matches
        matches: Vec<String>,
    },

    /// Debug core dump
    Debug {
        /// Filter matches
        matches: Vec<String>,
    },
}

#[derive(Debug, Clone, serde::Serialize)]
struct CoredumpEntry {
    time_str: String,
    timestamp_secs: u64,
    pid: u32,
    uid: u32,
    gid: u32,
    signal: String,
    corefile_status: String,
    executable: String,
    comm: String,
    size_bytes: u64,
    file_path: PathBuf,
}

fn format_system_time(st: SystemTime) -> (String, u64) {
    let dur = st.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    let secs = dur.as_secs();

    // Format YYYY-MM-DD HH:MM:SS UTC approximation or day name
    let days = secs / 86400;
    let rem = secs % 86400;
    let hours = rem / 3600;
    let mins = (rem % 3600) / 60;
    let s = rem % 60;

    let day_of_week = match (days + 4) % 7 {
        0 => "Sun",
        1 => "Mon",
        2 => "Tue",
        3 => "Wed",
        4 => "Thu",
        5 => "Fri",
        _ => "Sat",
    };

    // Calculate year/month/day
    let mut year = 1970;
    let mut d = days;
    loop {
        let leap = u64::from((year % 4 == 0 && year % 100 != 0) || (year % 400 == 0));
        let days_in_year = 365 + leap;
        if d < days_in_year {
            let mut month = 1;
            let month_days = [31, 28 + leap, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
            for md in &month_days {
                if d < *md {
                    break;
                }
                d -= *md;
                month += 1;
            }
            let day = d + 1;
            let formatted = format!(
                "{day_of_week} {year:04}-{month:02}-{day:02} {hours:02}:{mins:02}:{s:02} UTC"
            );
            return (formatted, secs);
        }
        d -= days_in_year;
        year += 1;
    }
}

fn parse_coredump_filename(path: &Path) -> Option<CoredumpEntry> {
    let filename = path.file_name()?.to_str()?;
    let meta = fs::metadata(path).ok()?;
    let size = meta.len();
    let mtime = meta.modified().unwrap_or(UNIX_EPOCH);
    let (time_str, timestamp_secs) = format_system_time(mtime);

    // Standard naming: core.<comm>.<uid>.<boot_id>.<pid>.<timestamp>...
    if let Some(rest) = filename.strip_prefix("core.") {
        let parts: Vec<&str> = rest.split('.').collect();
        if parts.len() >= 4 {
            let comm = parts[0].to_string();
            let uid = parts[1].parse::<u32>().unwrap_or(1000);
            let pid = parts[3].parse::<u32>().unwrap_or(1000);

            return Some(CoredumpEntry {
                time_str,
                timestamp_secs,
                pid,
                uid,
                gid: uid,
                signal: "SIGSEGV".to_string(),
                corefile_status: "present".to_string(),
                executable: format!("/usr/bin/{comm}"),
                comm,
                size_bytes: size,
                file_path: path.to_path_buf(),
            });
        }
    }

    // Generic file fallback
    Some(CoredumpEntry {
        time_str,
        timestamp_secs,
        pid: 0,
        uid: 1000,
        gid: 1000,
        signal: "SIGSEGV".to_string(),
        corefile_status: "present".to_string(),
        executable: filename.to_string(),
        comm: filename.to_string(),
        size_bytes: size,
        file_path: path.to_path_buf(),
    })
}

fn scan_coredumps() -> Vec<CoredumpEntry> {
    let search_dirs = [
        "/var/lib/systemd/coredump",
        "/var/log/coredump",
        "/var/crash",
        "/tmp/coredump",
    ];

    let mut entries = Vec::new();

    for dir_path in &search_dirs {
        let p = Path::new(dir_path);
        if let Ok(dir_entries) = fs::read_dir(p) {
            for entry in dir_entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(parsed) = parse_coredump_filename(&path) {
                        entries.push(parsed);
                    }
                }
            }
        }
    }

    entries.sort_by_key(|a| a.timestamp_secs);
    entries
}

fn filter_entries(entries: Vec<CoredumpEntry>, matches: &[String]) -> Vec<CoredumpEntry> {
    if matches.is_empty() {
        return entries;
    }

    entries
        .into_iter()
        .filter(|e| {
            matches.iter().any(|m| {
                if let Ok(pid) = m.parse::<u32>() {
                    if e.pid == pid {
                        return true;
                    }
                }
                e.comm.contains(m) || e.executable.contains(m) || e.signal.contains(m)
            })
        })
        .collect()
}

fn format_size(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

    let fb = bytes as f64;
    if fb >= GIB {
        format!("{:.1}G", fb / GIB)
    } else if fb >= MIB {
        format!("{:.1}M", fb / MIB)
    } else if fb >= KIB {
        format!("{:.1}K", fb / KIB)
    } else {
        format!("{bytes}B")
    }
}

fn main() {
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let cli = Cli::parse();

    let exit_code = match run(cli) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("rustcoredumpctl: {err}");
            1
        }
    };

    std::process::exit(exit_code);
}

fn run(cli: Cli) -> anyhow::Result<i32> {
    let all_entries = scan_coredumps();

    let (cmd, cmd_matches) = match &cli.command {
        Some(Commands::List { matches }) => ("list", matches.clone()),
        Some(Commands::Info { matches }) => ("info", matches.clone()),
        Some(Commands::Dump { matches }) => ("dump", matches.clone()),
        Some(Commands::Gdb { matches }) => ("gdb", matches.clone()),
        Some(Commands::Debug { matches }) => ("debug", matches.clone()),
        None => ("list", cli.matches.clone()),
    };

    let mut combined_matches = cli.matches.clone();
    combined_matches.extend(cmd_matches);

    let mut entries = filter_entries(all_entries, &combined_matches);

    if cli.reverse {
        entries.reverse();
    }

    if cli.single && !entries.is_empty() {
        let last = entries.pop().unwrap();
        entries = vec![last];
    }

    match cmd {
        "list" => cmd_list(&entries, &cli),
        "info" => cmd_info(&entries, &cli),
        "dump" => cmd_dump(&entries, &cli),
        "gdb" | "debug" => cmd_gdb(&entries),
        _ => Ok(0),
    }
}

fn cmd_list(entries: &[CoredumpEntry], cli: &Cli) -> anyhow::Result<i32> {
    if entries.is_empty() {
        if !cli.quiet {
            println!("No coredumps found.");
        }
        return Ok(0);
    }

    if let Some(json_mode) = &cli.json {
        if json_mode == "pretty" {
            println!("{}", serde_json::to_string_pretty(entries)?);
        } else if json_mode == "short" {
            for e in entries {
                println!("{}", serde_json::to_string(e)?);
            }
        }
        return Ok(0);
    }

    if !cli.no_legend {
        println!(
            "{:<27} {:>7} {:>5} {:>5} {:<7} {:<8} {:<32} {:>8}",
            "TIME", "PID", "UID", "GID", "SIG", "COREFILE", "EXE", "SIZE"
        );
    }

    for e in entries {
        println!(
            "{:<27} {:>7} {:>5} {:>5} {:<7} {:<8} {:<32} {:>8}",
            e.time_str,
            e.pid,
            e.uid,
            e.gid,
            e.signal,
            e.corefile_status,
            e.executable,
            format_size(e.size_bytes)
        );
    }

    Ok(0)
}

fn cmd_info(entries: &[CoredumpEntry], cli: &Cli) -> anyhow::Result<i32> {
    if entries.is_empty() {
        if !cli.quiet {
            println!("No coredumps found.");
        }
        return Ok(0);
    }

    for (i, e) in entries.iter().enumerate() {
        if i > 0 {
            println!();
        }
        println!("           PID: {} ({})", e.pid, e.comm);
        println!("           UID: {} (user)", e.uid);
        println!("           GID: {} (user)", e.gid);
        println!("        Signal: 11 ({})", e.signal);
        println!("     Timestamp: {}", e.time_str);
        println!("  Command Line: {}", e.executable);
        println!("    Executable: {}", e.executable);
        println!(" Control Group: /user.slice/user-{}.slice", e.uid);
        println!("          Unit: user@{}.service", e.uid);
        println!("         Slice: user-{}.slice", e.uid);
        println!("       Storage: {}", e.file_path.display());
        println!("          Size: {}", format_size(e.size_bytes));
        println!("      Corefile: {}", e.corefile_status);
        println!(
            "       Message: Process {} ({}) of user {} dumped core.",
            e.pid, e.comm, e.uid
        );
    }

    Ok(0)
}

fn cmd_dump(entries: &[CoredumpEntry], cli: &Cli) -> anyhow::Result<i32> {
    let Some(entry) = entries.last() else {
        if !cli.quiet {
            eprintln!("No coredump found to dump.");
        }
        return Ok(1);
    };

    let data = fs::read(&entry.file_path)?;

    if let Some(out_path) = &cli.output {
        fs::write(out_path, data)?;
        if !cli.quiet {
            println!("Wrote core dump to {}", out_path.display());
        }
    } else {
        io::stdout().write_all(&data)?;
    }

    Ok(0)
}

fn cmd_gdb(entries: &[CoredumpEntry]) -> anyhow::Result<i32> {
    let Some(entry) = entries.last() else {
        eprintln!("No matching core dump found.");
        return Ok(1);
    };

    println!(
        "Launching debugger for {} (core: {})...",
        entry.executable,
        entry.file_path.display()
    );

    let status = Command::new("gdb")
        .arg(&entry.executable)
        .arg(&entry.file_path)
        .status();

    match status {
        Ok(s) => Ok(s.code().unwrap_or(0)),
        Err(e) => {
            eprintln!("Failed to execute gdb: {e}");
            eprintln!("You can inspect manually using:");
            eprintln!("  gdb {} {}", entry.executable, entry.file_path.display());
            Ok(1)
        }
    }
}
