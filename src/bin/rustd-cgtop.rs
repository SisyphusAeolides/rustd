// SPDX-License-Identifier: LGPL-2.1-or-later
//! `rustd-cgtop` — Real-time top viewer for control group hierarchy and resource usage.
//!
//! Upstream counterpart: `systemd-cgtop` (v261).

use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use clap::{Parser, ValueEnum};

const VERSION_OUTPUT: &str = concat!(
    "systemd 261 (261.2-1-arch)\n",
    "+PAM +AUDIT -SELINUX +APPARMOR -IMA +IPE +SMACK +SECCOMP +GCRYPT +GNUTLS +OPENSSL +ACL ",
    "+BLKID +CURL +ELFUTILS +FIDO2 +IDN2 +KMOD +LIBCRYPTSETUP +LIBCRYPTSETUP_PLUGINS +LIBFDISK ",
    "+PCRE2 +PWQUALITY +P11KIT +QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB +ZSTD +BPF_FRAMEWORK +BTF ",
    "+XKBCOMMON +UTMP +LIBARCHIVE\n"
);

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Order {
    Path,
    Tasks,
    Cpu,
    Memory,
    Io,
}

#[derive(Parser, Debug)]
#[command(
    name = "rustd-cgtop",
    about = "Show top control groups by their resource usage",
    version = VERSION_OUTPUT,
)]
struct Cli {
    /// Order by path
    #[arg(short = 'p', long = "order-path", conflicts_with_all = ["order_tasks", "order_cpu", "order_memory", "order_io"])]
    order_path: bool,

    /// Order by number of tasks
    #[arg(short = 't', long = "order-tasks", conflicts_with_all = ["order_path", "order_cpu", "order_memory", "order_io"])]
    order_tasks: bool,

    /// Order by CPU load (default)
    #[arg(short = 'c', long = "order-cpu", conflicts_with_all = ["order_path", "order_tasks", "order_memory", "order_io"])]
    order_cpu: bool,

    /// Order by memory usage
    #[arg(short = 'm', long = "order-memory", conflicts_with_all = ["order_path", "order_tasks", "order_cpu", "order_io"])]
    order_memory: bool,

    /// Order by I/O load
    #[arg(short = 'i', long = "order-io", conflicts_with_all = ["order_path", "order_tasks", "order_cpu", "order_memory"])]
    order_io: bool,

    /// Run in batch mode (no terminal control escapes)
    #[arg(short = 'b', long = "batch")]
    batch: bool,

    /// Number of iterations before exiting
    #[arg(short = 'n', long = "iterations")]
    iterations: Option<usize>,

    /// Refresh delay in seconds (default 1.0)
    #[arg(short = 'd', long = "delay", default_value = "1.0")]
    delay: f64,

    /// Maximum traversal depth
    #[arg(long = "depth", default_value = "3")]
    depth: usize,

    /// Shortcut for --iterations=1 --batch
    #[arg(short = '1', long = "once")]
    once: bool,

    /// Print raw byte values
    #[arg(long = "raw")]
    raw: bool,

    /// Root control group to inspect
    cgroup: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct CgroupSample {
    tasks: Option<u64>,
    cpu_usec: Option<u64>,
    memory_bytes: Option<u64>,
    io_rbytes: Option<u64>,
    io_wbytes: Option<u64>,
    timestamp: Option<Instant>,
}

#[derive(Debug, Clone)]
struct CgroupRow {
    path_name: String,
    tasks: Option<u64>,
    cpu_pct: Option<f64>,
    memory_bytes: Option<u64>,
    io_input_rate: Option<f64>,
    io_output_rate: Option<f64>,
}

fn get_cgroup_root() -> PathBuf {
    std::env::var_os("RUSTD_CGROUP_ROOT")
        .map_or_else(|| PathBuf::from("/sys/fs/cgroup"), PathBuf::from)
}

fn read_tasks(dir: &Path) -> Option<u64> {
    if let Ok(content) = fs::read_to_string(dir.join("pids.current")) {
        if let Ok(val) = content.trim().parse::<u64>() {
            return Some(val);
        }
    }
    if let Ok(content) = fs::read_to_string(dir.join("cgroup.procs")) {
        let count = content.lines().filter(|l| !l.trim().is_empty()).count() as u64;
        return Some(count);
    }
    None
}

fn read_cpu_usec(dir: &Path) -> Option<u64> {
    let content = fs::read_to_string(dir.join("cpu.stat")).ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("usage_usec ") {
            if let Ok(val) = rest.trim().parse::<u64>() {
                return Some(val);
            }
        }
    }
    None
}

fn read_memory_bytes(dir: &Path) -> Option<u64> {
    if let Ok(content) = fs::read_to_string(dir.join("memory.current")) {
        if let Ok(val) = content.trim().parse::<u64>() {
            return Some(val);
        }
    }
    if let Ok(content) = fs::read_to_string(dir.join("memory.usage_in_bytes")) {
        if let Ok(val) = content.trim().parse::<u64>() {
            return Some(val);
        }
    }
    None
}

fn read_io_bytes(dir: &Path) -> (Option<u64>, Option<u64>) {
    let Ok(content) = fs::read_to_string(dir.join("io.stat")) else {
        return (None, None);
    };

    let mut total_r = 0u64;
    let mut total_w = 0u64;
    let mut found = false;

    for line in content.lines() {
        let mut r = 0u64;
        let mut w = 0u64;
        for token in line.split_whitespace() {
            if let Some(val) = token.strip_prefix("rbytes=") {
                if let Ok(b) = val.parse::<u64>() {
                    r = b;
                    found = true;
                }
            } else if let Some(val) = token.strip_prefix("wbytes=") {
                if let Ok(b) = val.parse::<u64>() {
                    w = b;
                    found = true;
                }
            }
        }
        total_r = total_r.saturating_add(r);
        total_w = total_w.saturating_add(w);
    }

    if found {
        (Some(total_r), Some(total_w))
    } else {
        (None, None)
    }
}

fn sample_cgroup(dir: &Path) -> CgroupSample {
    let (io_r, io_w) = read_io_bytes(dir);
    CgroupSample {
        tasks: read_tasks(dir),
        cpu_usec: read_cpu_usec(dir),
        memory_bytes: read_memory_bytes(dir),
        io_rbytes: io_r,
        io_wbytes: io_w,
        timestamp: Some(Instant::now()),
    }
}

fn collect_cgroups(
    base_root: &Path,
    rel_path: &Path,
    current_depth: usize,
    max_depth: usize,
    out: &mut Vec<(String, PathBuf)>,
) {
    if current_depth > max_depth {
        return;
    }

    let full_path = base_root.join(rel_path);
    let rel_str = if rel_path.as_os_str().is_empty() || rel_path == Path::new(".") {
        "/".to_string()
    } else {
        format!("/{}", rel_path.display())
    };

    out.push((rel_str, full_path.clone()));

    if current_depth == max_depth {
        return;
    }

    if let Ok(entries) = fs::read_dir(&full_path) {
        let mut subdirs = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    // Skip internal / sysfs specific folders
                    if !name.starts_with('.') && name != "cgroup.subsystems" {
                        subdirs.push(rel_path.join(name));
                    }
                }
            }
        }
        subdirs.sort();
        for sub in subdirs {
            collect_cgroups(base_root, &sub, current_depth + 1, max_depth, out);
        }
    }
}

fn format_bytes(bytes: Option<u64>, raw: bool) -> String {
    let Some(b) = bytes else {
        return "-".to_string();
    };
    if raw {
        return b.to_string();
    }
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    const TIB: f64 = 1024.0 * 1024.0 * 1024.0 * 1024.0;

    let fb = b as f64;
    if fb >= TIB {
        format!("{:.1}T", fb / TIB)
    } else if fb >= GIB {
        format!("{:.1}G", fb / GIB)
    } else if fb >= MIB {
        format!("{:.1}M", fb / MIB)
    } else if fb >= KIB {
        format!("{:.1}K", fb / KIB)
    } else {
        format!("{b}B")
    }
}

fn format_rate(rate: Option<f64>, raw: bool) -> String {
    let Some(r) = rate else {
        return "-".to_string();
    };
    if raw {
        return format!("{r:.0}");
    }
    if r < 1.0 {
        return "-".to_string();
    }
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

    if r >= GIB {
        format!("{:.1}G", r / GIB)
    } else if r >= MIB {
        format!("{:.1}M", r / MIB)
    } else if r >= KIB {
        format!("{:.1}K", r / KIB)
    } else {
        format!("{r:.0}B")
    }
}

#[allow(
    clippy::cast_precision_loss,
    clippy::too_many_lines,
    clippy::struct_excessive_bools
)]
fn main() {
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let cli = Cli::parse();

    let order = if cli.order_path {
        Order::Path
    } else if cli.order_tasks {
        Order::Tasks
    } else if cli.order_memory {
        Order::Memory
    } else if cli.order_io {
        Order::Io
    } else {
        Order::Cpu
    };

    let batch = cli.batch || cli.once;
    let max_iterations = if cli.once { Some(1) } else { cli.iterations };

    let delay_dur = Duration::from_secs_f64(cli.delay.max(0.1));
    let root = get_cgroup_root();

    let start_subpath = cli
        .cgroup
        .as_deref()
        .map_or("", |p| p.trim_start_matches('/'));

    let mut prev_samples: HashMap<String, CgroupSample> = HashMap::new();
    let mut iteration = 0;

    loop {
        iteration += 1;

        let mut cgroups = Vec::new();
        collect_cgroups(&root, Path::new(start_subpath), 0, cli.depth, &mut cgroups);

        let mut current_samples: HashMap<String, CgroupSample> = HashMap::new();
        for (rel, full) in &cgroups {
            current_samples.insert(rel.clone(), sample_cgroup(full));
        }

        // If this is the first iteration and we need CPU delta, sleep briefly if interactive or once
        if prev_samples.is_empty() {
            let sample_interval = if batch && max_iterations == Some(1) {
                Duration::from_millis(150)
            } else {
                delay_dur
            };
            thread::sleep(sample_interval);

            let mut second_samples = HashMap::new();
            for (rel, full) in &cgroups {
                second_samples.insert(rel.clone(), sample_cgroup(full));
            }
            prev_samples = current_samples;
            current_samples = second_samples;
        }

        let mut rows: Vec<CgroupRow> = Vec::new();

        for (rel, _) in &cgroups {
            let cur = &current_samples[rel];
            let prev = prev_samples.get(rel);

            let mut cpu_pct = None;
            let mut io_input_rate = None;
            let mut io_output_rate = None;

            if let (Some(p), Some(c_cpu), Some(p_cpu)) =
                (prev, cur.cpu_usec, prev.and_then(|p| p.cpu_usec))
            {
                if let (Some(c_time), Some(p_time)) = (cur.timestamp, p.timestamp) {
                    let elapsed_usec = c_time.duration_since(p_time).as_micros() as f64;
                    if elapsed_usec > 0.0 {
                        let delta_cpu = c_cpu.saturating_sub(p_cpu) as f64;
                        cpu_pct = Some((delta_cpu / elapsed_usec) * 100.0);
                    }
                }
            }

            if let (Some(p), Some(c_r), Some(p_r)) =
                (prev, cur.io_rbytes, prev.and_then(|p| p.io_rbytes))
            {
                if let (Some(c_time), Some(p_time)) = (cur.timestamp, p.timestamp) {
                    let elapsed_sec = c_time.duration_since(p_time).as_secs_f64();
                    if elapsed_sec > 0.0 {
                        io_input_rate = Some(c_r.saturating_sub(p_r) as f64 / elapsed_sec);
                    }
                }
            }

            if let (Some(p), Some(c_w), Some(p_w)) =
                (prev, cur.io_wbytes, prev.and_then(|p| p.io_wbytes))
            {
                if let (Some(c_time), Some(p_time)) = (cur.timestamp, p.timestamp) {
                    let elapsed_sec = c_time.duration_since(p_time).as_secs_f64();
                    if elapsed_sec > 0.0 {
                        io_output_rate = Some(c_w.saturating_sub(p_w) as f64 / elapsed_sec);
                    }
                }
            }

            rows.push(CgroupRow {
                path_name: rel.clone(),
                tasks: cur.tasks,
                cpu_pct,
                memory_bytes: cur.memory_bytes,
                io_input_rate,
                io_output_rate,
            });
        }

        // Sort rows
        match order {
            Order::Path => rows.sort_by(|a, b| a.path_name.cmp(&b.path_name)),
            Order::Tasks => rows.sort_by(|a, b| b.tasks.unwrap_or(0).cmp(&a.tasks.unwrap_or(0))),
            Order::Cpu => rows.sort_by(|a, b| {
                b.cpu_pct
                    .unwrap_or(0.0)
                    .partial_cmp(&a.cpu_pct.unwrap_or(0.0))
                    .unwrap_or(std::cmp::Ordering::Equal)
            }),
            Order::Memory => rows.sort_by(|a, b| {
                b.memory_bytes
                    .unwrap_or(0)
                    .cmp(&a.memory_bytes.unwrap_or(0))
            }),
            Order::Io => rows.sort_by(|a, b| {
                let a_io = a.io_input_rate.unwrap_or(0.0) + a.io_output_rate.unwrap_or(0.0);
                let b_io = b.io_input_rate.unwrap_or(0.0) + b.io_output_rate.unwrap_or(0.0);
                b_io.partial_cmp(&a_io).unwrap_or(std::cmp::Ordering::Equal)
            }),
        }

        // Render screen
        if !batch {
            // ANSI screen clear and home cursor
            print!("\x1B[H\x1B[2J");
        }

        println!(
            "{:<44} {:>7} {:>6} {:>8} {:>8} {:>8}",
            "Control Group", "Tasks", "%CPU", "Memory", "Input/s", "Output/s"
        );

        for row in &rows {
            let tasks_str = row.tasks.map_or_else(|| "-".to_string(), |t| t.to_string());
            let cpu_str = row
                .cpu_pct
                .map_or_else(|| "-".to_string(), |c| format!("{c:.1}"));
            let mem_str = format_bytes(row.memory_bytes, cli.raw);
            let in_str = format_rate(row.io_input_rate, cli.raw);
            let out_str = format_rate(row.io_output_rate, cli.raw);

            let mut display_path = row.path_name.clone();
            if display_path.len() > 44 {
                display_path.truncate(41);
                display_path.push_str("...");
            }

            println!(
                "{display_path:<44} {tasks_str:>7} {cpu_str:>6} {mem_str:>8} {in_str:>8} {out_str:>8}"
            );
        }

        let _ = io::stdout().flush();

        if let Some(max_iter) = max_iterations {
            if iteration >= max_iter {
                break;
            }
        }

        prev_samples = current_samples;
        thread::sleep(delay_dur);
    }
}
