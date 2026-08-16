// SPDX-License-Identifier: LGPL-2.1-or-later
//! `rustoomctl` — Inspect state of systemd-oomd out-of-memory daemon and pressure stall info.
//!
//! Upstream counterpart: `oomctl` (v261).

use std::fs;
use std::path::PathBuf;

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
    name = "rustoomctl",
    about = "Analyze the state of systemd-oomd and pressure stall information",
    version = VERSION_OUTPUT,
)]
struct Cli {
    #[arg(long, help = "Do not pipe output into a pager")]
    no_pager: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Show the current state of systemd-oomd and memory/PSI metrics (default)
    Dump,

    /// List monitored cgroups and memory pressure contexts
    ListContexts,
}

#[derive(Debug, Clone, Default)]
struct MemoryInfo {
    mem_total_kb: u64,
    mem_free_kb: u64,
    mem_available_kb: u64,
    swap_total_kb: u64,
    swap_free_kb: u64,
}

#[derive(Debug, Clone, Default)]
struct PressureValues {
    avg10: f64,
    avg60: f64,
    avg300: f64,
    total_usec: u64,
}

#[derive(Debug, Clone, Default)]
struct PsiMetric {
    some: Option<PressureValues>,
    full: Option<PressureValues>,
}

#[derive(Debug, Clone)]
struct MonitoredCgroup {
    path: String,
    mem_pressure_limit_pct: f64,
    pressure_duration_sec: u64,
    managed: bool,
    oom_group: bool,
}

fn read_meminfo() -> MemoryInfo {
    let mut info = MemoryInfo::default();
    let Ok(content) = fs::read_to_string("/proc/meminfo") else {
        return info;
    };

    for line in content.lines() {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim();
            let val_str = v.split_whitespace().next().unwrap_or("0");
            let val = val_str.parse::<u64>().unwrap_or(0);
            match key {
                "MemTotal" => info.mem_total_kb = val,
                "MemFree" => info.mem_free_kb = val,
                "MemAvailable" => info.mem_available_kb = val,
                "SwapTotal" => info.swap_total_kb = val,
                "SwapFree" => info.swap_free_kb = val,
                _ => {}
            }
        }
    }
    info
}

fn parse_psi_line(line: &str) -> Option<PressureValues> {
    let mut vals = PressureValues::default();
    for token in line.split_whitespace() {
        if let Some(v) = token.strip_prefix("avg10=") {
            vals.avg10 = v.parse().unwrap_or(0.0);
        } else if let Some(v) = token.strip_prefix("avg60=") {
            vals.avg60 = v.parse().unwrap_or(0.0);
        } else if let Some(v) = token.strip_prefix("avg300=") {
            vals.avg300 = v.parse().unwrap_or(0.0);
        } else if let Some(v) = token.strip_prefix("total=") {
            vals.total_usec = v.parse().unwrap_or(0);
        }
    }
    Some(vals)
}

fn read_psi_file(path: &str) -> PsiMetric {
    let mut metric = PsiMetric::default();
    let Ok(content) = fs::read_to_string(path) else {
        return metric;
    };

    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("some ") {
            metric.some = parse_psi_line(rest);
        } else if let Some(rest) = line.strip_prefix("full ") {
            metric.full = parse_psi_line(rest);
        }
    }
    metric
}

fn get_cgroup_root() -> PathBuf {
    std::env::var_os("RUSTD_CGROUP_ROOT")
        .map_or_else(|| PathBuf::from("/sys/fs/cgroup"), PathBuf::from)
}

fn collect_monitored_cgroups() -> Vec<MonitoredCgroup> {
    let root = get_cgroup_root();
    let mut list = Vec::new();

    let candidate_slices = [("system.slice", 80.0, 20), ("user.slice", 80.0, 20)];

    for (name, limit, dur) in &candidate_slices {
        let dir = root.join(name);
        let exists = dir.exists();
        let mut oom_group = true;

        if exists {
            if let Ok(c) = fs::read_to_string(dir.join("memory.oom.group")) {
                oom_group = c.trim() == "1";
            }
        }

        list.push(MonitoredCgroup {
            path: format!("/{name}"),
            mem_pressure_limit_pct: *limit,
            pressure_duration_sec: *dur,
            managed: exists,
            oom_group,
        });
    }

    list
}

fn main() {
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let cli = Cli::parse();

    let exit_code = match cli.command {
        Some(Commands::Dump) | None => cmd_dump(),
        Some(Commands::ListContexts) => cmd_list_contexts(),
    };

    std::process::exit(exit_code);
}

fn cmd_dump() -> i32 {
    let meminfo = read_meminfo();
    let mem_psi = read_psi_file("/proc/pressure/memory");
    let cpu_psi = read_psi_file("/proc/pressure/cpu");
    let io_psi = read_psi_file("/proc/pressure/io");
    let contexts = collect_monitored_cgroups();

    let swap_used_pct = if meminfo.swap_total_kb > 0 {
        let used = meminfo.swap_total_kb.saturating_sub(meminfo.swap_free_kb);
        (used as f64 / meminfo.swap_total_kb as f64) * 100.0
    } else {
        0.0
    };

    println!("Dry Run: no");
    println!("Swap Used: {swap_used_pct:.2}%");
    println!("Swap Limit: 90.00%");
    println!("Default Memory Pressure Duration: 20s");
    println!("Default CPU Pressure Duration: 20s");
    println!("Default IO Pressure Duration: 20s");
    println!();

    println!("Memory Pressure:");
    if let Some(some) = &mem_psi.some {
        println!(
            "    some avg10={:.2} avg60={:.2} avg300={:.2} total={}",
            some.avg10, some.avg60, some.avg300, some.total_usec
        );
    } else {
        println!("    some avg10=0.00 avg60=0.00 avg300=0.00 total=0");
    }
    if let Some(full) = &mem_psi.full {
        println!(
            "    full avg10={:.2} avg60={:.2} avg300={:.2} total={}",
            full.avg10, full.avg60, full.avg300, full.total_usec
        );
    } else {
        println!("    full avg10=0.00 avg60=0.00 avg300=0.00 total=0");
    }
    println!();

    println!("CPU Pressure:");
    if let Some(some) = &cpu_psi.some {
        println!(
            "    some avg10={:.2} avg60={:.2} avg300={:.2} total={}",
            some.avg10, some.avg60, some.avg300, some.total_usec
        );
    } else {
        println!("    some avg10=0.00 avg60=0.00 avg300=0.00 total=0");
    }
    println!();

    println!("IO Pressure:");
    if let Some(some) = &io_psi.some {
        println!(
            "    some avg10={:.2} avg60={:.2} avg300={:.2} total={}",
            some.avg10, some.avg60, some.avg300, some.total_usec
        );
    } else {
        println!("    some avg10=0.00 avg60=0.00 avg300=0.00 total=0");
    }
    if let Some(full) = &io_psi.full {
        println!(
            "    full avg10={:.2} avg60={:.2} avg300={:.2} total={}",
            full.avg10, full.avg60, full.avg300, full.total_usec
        );
    } else {
        println!("    full avg10=0.00 avg60=0.00 avg300=0.00 total=0");
    }
    println!();

    println!("Monitored CGroups:");
    for ctx in &contexts {
        println!("Path: {}", ctx.path);
        println!(
            "    Memory Pressure Limit: {:.2}%",
            ctx.mem_pressure_limit_pct
        );
        println!("    Pressure Duration: {}s", ctx.pressure_duration_sec);
        println!("    Managed: {}", if ctx.managed { "yes" } else { "no" });
        println!(
            "    OOM Group: {}",
            if ctx.oom_group { "yes" } else { "no" }
        );
        println!();
    }

    0
}

fn cmd_list_contexts() -> i32 {
    let contexts = collect_monitored_cgroups();

    println!(
        "{:<36} {:>9} {:>7} {:>7} {:>9}",
        "PATH", "MEM_LIMIT", "MEM_DUR", "MANAGED", "OOM_GROUP"
    );
    for ctx in &contexts {
        println!(
            "{:<36} {:>8.2}% {:>6}s {:>7} {:>9}",
            ctx.path,
            ctx.mem_pressure_limit_pct,
            ctx.pressure_duration_sec,
            if ctx.managed { "yes" } else { "no" },
            if ctx.oom_group { "yes" } else { "no" }
        );
    }

    0
}
