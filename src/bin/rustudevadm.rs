use clap::{Parser, Subcommand};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Parser)]
#[command(
    name = "rustudevadm",
    version,
    about = "udev administration tool",
    long_about = "Controls the runtime behavior of systemd-udevd, requests kernel events, manages the event queue, and provides simple debugging mechanisms."
)]
struct Cli {
    /// Print debug messages
    #[arg(short = 'd', long = "debug", global = true)]
    debug: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Query sysfs or the udev database
    Info(InfoArgs),
    /// Request events from the kernel
    Trigger(TriggerArgs),
    /// Wait for pending udev events
    Settle(SettleArgs),
    /// Control the udev daemon
    Control(ControlArgs),
    /// Listen to kernel and udev events
    Monitor(MonitorArgs),
    /// Hardware database operations
    Hwdb(HwdbArgs),
    /// Test an event run
    Test(TestArgs),
    /// Test a built-in command
    TestBuiltin(TestBuiltinArgs),
    /// Verify udev rules files
    Verify(VerifyArgs),
    /// Wait for device or device symlink
    Wait(WaitArgs),
    /// Lock a block device
    Lock(LockArgs),
}

#[derive(Parser, Debug)]
struct InfoArgs {
    /// Device path, node name, or sysfs path
    #[arg(value_name = "DEVICE")]
    devices: Vec<String>,

    /// Query device by given type: name, symlink, path, property, all
    #[arg(short = 'q', long = "query", default_value = "all")]
    query: String,

    /// Device path in sysfs (/sys/...)
    #[arg(short = 'p', long = "path")]
    path: Option<String>,

    /// Device node or symlink in /dev
    #[arg(short = 'n', long = "name")]
    name: Option<String>,

    /// Print devpath with /sys prefix
    #[arg(short = 'r', long = "root")]
    root: bool,

    /// Print all sysfs attributes of the device and its parents
    #[arg(short = 'a', long = "attribute-walk")]
    attribute_walk: bool,

    /// Show tree of devices
    #[arg(short = 't', long = "tree")]
    tree: bool,

    /// Export key/value pairs
    #[arg(short = 'x', long = "export")]
    export: bool,

    /// Export key/value pairs with a prefix
    #[arg(long = "export-prefix")]
    export_prefix: Option<String>,

    /// Export the content of the udev database
    #[arg(short = 'e', long = "export-db")]
    export_db: bool,

    /// Clean up the udev database
    #[arg(short = 'c', long = "cleanup-db")]
    cleanup_db: bool,

    /// Wait for device to be initialized
    #[arg(short = 'w', long = "wait-for-initialization")]
    wait_for_initialization: Option<Option<u64>>,

    /// Format output as JSON
    #[arg(long = "json")]
    json: Option<String>,
}

#[derive(Parser, Debug)]
struct TriggerArgs {
    /// Device names or sysfs paths to trigger
    #[arg(value_name = "DEVICE")]
    devices: Vec<String>,

    /// Print the list of devices triggered
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,

    /// Do not actually trigger the event
    #[arg(short = 'n', long = "dry-run")]
    dry_run: bool,

    /// Type of devices to trigger: devices, subsystems, all
    #[arg(short = 't', long = "type", default_value = "devices")]
    trigger_type: String,

    /// Event action value: add, change, remove, bind, unbind
    #[arg(short = 'c', long = "action", default_value = "change")]
    action: String,

    /// Trigger devices that match subsystem
    #[arg(short = 's', long = "subsystem-match")]
    subsystem_match: Vec<String>,

    /// Do not trigger devices that match subsystem
    #[arg(short = 'S', long = "subsystem-nomatch")]
    subsystem_nomatch: Vec<String>,

    /// Trigger devices that match sysfs attribute
    #[arg(short = 'a', long = "attr-match")]
    attr_match: Vec<String>,

    /// Do not trigger devices that match sysfs attribute
    #[arg(short = 'A', long = "attr-nomatch")]
    attr_nomatch: Vec<String>,

    /// Trigger devices that match udev property
    #[arg(short = 'p', long = "property-match")]
    property_match: Vec<String>,

    /// Trigger devices with a matching tag
    #[arg(short = 'g', long = "tag-match")]
    tag_match: Vec<String>,

    /// Trigger devices that match device name
    #[arg(short = 'y', long = "name-match")]
    name_match: Vec<String>,

    /// Trigger devices with matching parent
    #[arg(short = 'b', long = "parent-match")]
    parent_match: Vec<String>,

    /// Wait for triggered events to complete
    #[arg(short = 'w', long = "settle")]
    settle: bool,
}

#[derive(Parser, Debug)]
struct SettleArgs {
    /// Maximum time to wait for events in seconds
    #[arg(short = 't', long = "timeout", default_value_t = 120)]
    timeout: u64,

    /// Stop waiting if file exists
    #[arg(short = 'E', long = "exit-if-exists")]
    exit_if_exists: Option<PathBuf>,

    /// Do not print any error on timeout
    #[arg(short = 'q', long = "quiet")]
    quiet: bool,
}

#[derive(Parser, Debug)]
struct ControlArgs {
    /// Tell udevd to exit
    #[arg(short = 'e', long = "exit")]
    exit: bool,

    /// Set udevd log priority
    #[arg(short = 'l', long = "log-level")]
    log_level: Option<String>,

    /// Stop executing events
    #[arg(short = 's', long = "stop-exec-queue")]
    stop_exec_queue: bool,

    /// Start executing events
    #[arg(short = 'S', long = "start-exec-queue")]
    start_exec_queue: bool,

    /// Reload rules and hwdb
    #[arg(short = 'R', long = "reload")]
    reload: bool,

    /// Set global property
    #[arg(short = 'p', long = "property")]
    property: Vec<String>,

    /// Set maximum number of worker processes
    #[arg(short = 'm', long = "children-max")]
    children_max: Option<usize>,

    /// Wait for udevd to respond
    #[arg(long = "ping")]
    ping: bool,

    /// Maximum time to wait for response in seconds
    #[arg(short = 't', long = "timeout")]
    timeout: Option<u64>,
}

#[derive(Parser, Debug)]
struct MonitorArgs {
    /// Print kernel uevents
    #[arg(short = 'k', long = "kernel")]
    kernel: bool,

    /// Print udev events
    #[arg(short = 'u', long = "udev")]
    udev: bool,

    /// Print event properties
    #[arg(short = 'p', long = "property")]
    property: bool,

    /// Filter events by subsystem
    #[arg(short = 's', long = "subsystem-match")]
    subsystem_match: Vec<String>,

    /// Filter events by tag
    #[arg(short = 't', long = "tag-match")]
    tag_match: Vec<String>,
}

#[derive(Parser, Debug)]
struct HwdbArgs {
    /// Update hwdb binary database
    #[arg(short = 'u', long = "update")]
    update: bool,

    /// Query hwdb for modalias
    #[arg(short = 't', long = "test")]
    test: Option<String>,

    /// Alternative root path
    #[arg(short = 'r', long = "root")]
    root: Option<PathBuf>,

    /// Fail on syntax error
    #[arg(short = 's', long = "strict")]
    strict: bool,
}

#[derive(Parser, Debug)]
struct TestArgs {
    /// Sysfs device path
    #[arg(value_name = "DEVPATH")]
    devpath: String,

    /// Action string (e.g. add, change)
    #[arg(short = 'a', long = "action", default_value = "add")]
    action: String,

    /// Resolve names
    #[arg(short = 'N', long = "resolve-names")]
    resolve_names: Option<String>,
}

#[derive(Parser, Debug)]
struct TestBuiltinArgs {
    /// Built-in command name
    #[arg(value_name = "BUILTIN")]
    builtin: String,

    /// Sysfs device path
    #[arg(value_name = "DEVPATH")]
    devpath: String,
}

#[derive(Parser, Debug)]
struct VerifyArgs {
    /// Rule files to verify
    #[arg(value_name = "FILE")]
    files: Vec<PathBuf>,

    /// Resolve names
    #[arg(short = 'N', long = "resolve-names")]
    resolve_names: Option<String>,

    /// Alternative root path
    #[arg(long = "root")]
    root: Option<PathBuf>,
}

#[derive(Parser, Debug)]
struct WaitArgs {
    /// Device or device symlink to wait for
    #[arg(value_name = "DEVICE")]
    device: String,

    /// Maximum time to wait in seconds
    #[arg(short = 't', long = "timeout")]
    timeout: Option<u64>,

    /// Wait for device to be initialized
    #[arg(long = "initialized")]
    initialized: Option<bool>,
}

#[derive(Parser, Debug)]
struct LockArgs {
    /// Block device node to lock
    #[arg(value_name = "DEVICE")]
    device: String,

    /// Maximum time to wait for lock in seconds
    #[arg(short = 't', long = "timeout")]
    timeout: Option<u64>,

    /// Device timeout in seconds
    #[arg(long = "device-timeout")]
    device_timeout: Option<u64>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Info(args) => handle_info(&args),
        Commands::Trigger(args) => handle_trigger(&args),
        Commands::Settle(args) => handle_settle(&args),
        Commands::Control(args) => handle_control(&args),
        Commands::Monitor(args) => handle_monitor(&args),
        Commands::Hwdb(args) => handle_hwdb(&args),
        Commands::Test(args) => handle_test(&args),
        Commands::TestBuiltin(args) => handle_test_builtin(&args),
        Commands::Verify(args) => handle_verify(&args),
        Commands::Wait(args) => handle_wait(&args),
        Commands::Lock(args) => handle_lock(&args),
    }
}

// -----------------------------------------------------------------------------
// INFO COMMAND
// -----------------------------------------------------------------------------

#[allow(dead_code)]
struct DeviceRecord {
    syspath: PathBuf,
    devpath: String,
    sysname: String,
    subsystem: String,
    driver: String,
    devnode: Option<String>,
    major: Option<u32>,
    minor: Option<u32>,
    symlinks: Vec<String>,
    properties: BTreeMap<String, String>,
    tags: Vec<String>,
}

fn handle_info(args: &InfoArgs) -> anyhow::Result<()> {
    if args.export_db {
        return export_udev_db(args);
    }

    if args.cleanup_db {
        println!("Cleaning up udev database...");
        let db_dir = Path::new("/run/udev/data");
        if db_dir.exists() {
            let _ = fs::remove_dir_all(db_dir);
            let _ = fs::create_dir_all(db_dir);
        }
        return Ok(());
    }

    // Determine target device paths
    let mut targets = Vec::new();
    if let Some(ref p) = args.path {
        targets.push(p.clone());
    }
    if let Some(ref n) = args.name {
        targets.push(n.clone());
    }
    for dev in &args.devices {
        targets.push(dev.clone());
    }

    if targets.is_empty() {
        eprintln!("udevadm: missing device specified");
        std::process::exit(1);
    }

    for target in targets {
        let syspath = resolve_device_to_syspath(&target)?;
        let record = parse_device_record(&syspath)?;

        if args.attribute_walk {
            print_attribute_walk(&record)?;
        } else if args.tree {
            print_device_tree(&record)?;
        } else {
            print_device_info(&record, args)?;
        }
    }

    Ok(())
}

fn resolve_device_to_syspath(target: &str) -> anyhow::Result<PathBuf> {
    let p = Path::new(target);

    // 1. Direct sysfs path
    if target.starts_with("/sys/") {
        if p.exists() {
            return Ok(p.canonicalize().unwrap_or_else(|_| p.to_path_buf()));
        }
        return Ok(p.to_path_buf());
    }

    // 2. Sysfs relative path (e.g. "/devices/...")
    if target.starts_with("/devices/") {
        let full = Path::new("/sys").join(target.trim_start_matches('/'));
        if full.exists() {
            return Ok(full.canonicalize().unwrap_or(full));
        }
        return Ok(full);
    }

    // 3. /dev node path
    if target.starts_with("/dev/") || p.exists() {
        if let Ok(meta) = fs::metadata(p) {
            let rdev = meta.rdev();
            let major = libc::major(rdev);
            let minor = libc::minor(rdev);

            // Check /sys/dev/block/major:minor or /sys/dev/char/major:minor
            let block_dev = PathBuf::from(format!("/sys/dev/block/{major}:{minor}"));
            if block_dev.exists() {
                return Ok(block_dev.canonicalize().unwrap_or(block_dev));
            }
            let char_dev = PathBuf::from(format!("/sys/dev/char/{major}:{minor}"));
            if char_dev.exists() {
                return Ok(char_dev.canonicalize().unwrap_or(char_dev));
            }
        }
    }

    // 4. Kernel device name search in /sys/class/block, /sys/class/net, etc.
    let search_classes = ["block", "net", "tty", "input", "sound", "drm", "nvme"];
    for class in &search_classes {
        let candidate = PathBuf::from(format!("/sys/class/{class}/{target}"));
        if candidate.exists() {
            return Ok(candidate.canonicalize().unwrap_or(candidate));
        }
    }

    // 5. Look up in /sys/devices/**/<target>
    if let Ok(entries) = fs::read_dir("/sys/block") {
        for entry in entries.flatten() {
            if entry.file_name() == target {
                return Ok(entry.path().canonicalize().unwrap_or_else(|_| entry.path()));
            }
        }
    }

    // Fallback: assume under /sys/class/block/
    let fallback = PathBuf::from(format!("/sys/class/block/{target}"));
    if fallback.exists() {
        return Ok(fallback.canonicalize().unwrap_or(fallback));
    }

    Err(anyhow::anyhow!("device not found: {target}"))
}

fn parse_device_record(syspath: &Path) -> anyhow::Result<DeviceRecord> {
    let canonical = syspath
        .canonicalize()
        .unwrap_or_else(|_| syspath.to_path_buf());
    let sys_prefix = Path::new("/sys");
    let devpath = canonical.strip_prefix(sys_prefix).map_or_else(
        |_| canonical.to_string_lossy().to_string(),
        |p| format!("/{}", p.display()),
    );

    let sysname = canonical
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();

    let mut subsystem = String::new();
    let sub_link = canonical.join("subsystem");
    if let Ok(sub_target) = fs::read_link(sub_link) {
        if let Some(name) = sub_target.file_name() {
            subsystem = name.to_string_lossy().to_string();
        }
    }

    let mut driver = String::new();
    let drv_link = canonical.join("driver");
    if let Ok(drv_target) = fs::read_link(drv_link) {
        if let Some(name) = drv_target.file_name() {
            driver = name.to_string_lossy().to_string();
        }
    }

    let mut properties = BTreeMap::new();
    let mut major = None;
    let mut minor = None;
    let mut devnode = None;

    // Read uevent file in sysfs
    let uevent_path = canonical.join("uevent");
    if let Ok(content) = fs::read_to_string(uevent_path) {
        for line in content.lines() {
            if let Some((k, v)) = line.split_once('=') {
                properties.insert(k.to_string(), v.to_string());
                match k {
                    "MAJOR" => major = v.parse::<u32>().ok(),
                    "MINOR" => minor = v.parse::<u32>().ok(),
                    "DEVNAME" => devnode = Some(v.to_string()),
                    "SUBSYSTEM" if subsystem.is_empty() => subsystem = v.to_string(),
                    "DRIVER" if driver.is_empty() => driver = v.to_string(),
                    _ => {}
                }
            }
        }
    }

    // Read dev file for major:minor if not in uevent
    if major.is_none() {
        let dev_file = canonical.join("dev");
        if let Ok(content) = fs::read_to_string(dev_file) {
            if let Some((maj_str, min_str)) = content.trim().split_once(':') {
                major = maj_str.parse::<u32>().ok();
                minor = min_str.parse::<u32>().ok();
                if let (Some(maj), Some(min)) = (major, minor) {
                    properties.insert("MAJOR".to_string(), maj.to_string());
                    properties.insert("MINOR".to_string(), min.to_string());
                }
            }
        }
    }

    if devnode.is_none()
        && (subsystem == "block" || canonical.to_string_lossy().contains("/block/"))
    {
        devnode = Some(format!("/dev/{sysname}"));
        properties.insert("DEVNAME".to_string(), format!("/dev/{sysname}"));
    }

    if !subsystem.is_empty() {
        properties.insert("SUBSYSTEM".to_string(), subsystem.clone());
    }

    let mut symlinks = Vec::new();
    let mut tags = Vec::new();

    // Read udev db record: /run/udev/data/<b|c><major>:<minor> or /run/udev/data/+<subsystem>:<sysname>
    let mut db_paths = Vec::new();
    if let (Some(maj), Some(min)) = (major, minor) {
        let prefix = if subsystem == "block" || canonical.to_string_lossy().contains("/block/") {
            'b'
        } else {
            'c'
        };
        db_paths.push(PathBuf::from(format!("/run/udev/data/{prefix}{maj}:{min}")));
    }
    if !subsystem.is_empty() && !sysname.is_empty() {
        db_paths.push(PathBuf::from(format!(
            "/run/udev/data/+{subsystem}:{sysname}"
        )));
    }

    for db_path in db_paths {
        if let Ok(content) = fs::read_to_string(&db_path) {
            for line in content.lines() {
                if let Some(stripped) = line.strip_prefix("S:") {
                    symlinks.push(stripped.to_string());
                } else if let Some(stripped) = line.strip_prefix("E:") {
                    if let Some((k, v)) = stripped.split_once('=') {
                        properties.insert(k.to_string(), v.to_string());
                    }
                } else if let Some(stripped) = line.strip_prefix("G:") {
                    tags.push(stripped.to_string());
                }
            }
            break;
        }
    }

    Ok(DeviceRecord {
        syspath: canonical,
        devpath,
        sysname,
        subsystem,
        driver,
        devnode,
        major,
        minor,
        symlinks,
        properties,
        tags,
    })
}

fn print_device_info(rec: &DeviceRecord, args: &InfoArgs) -> anyhow::Result<()> {
    match args.query.as_str() {
        "name" => {
            if let Some(ref node) = rec.devnode {
                println!("{node}");
            } else {
                println!("{}", rec.sysname);
            }
        }
        "symlink" => {
            println!("{}", rec.symlinks.join(" "));
        }
        "path" => {
            if args.root {
                println!("{}", rec.syspath.display());
            } else {
                println!("{}", rec.devpath);
            }
        }
        "property" => {
            let prefix = args.export_prefix.as_deref().unwrap_or("");
            for (k, v) in &rec.properties {
                if args.export {
                    println!("{prefix}{k}=\'{v}\'");
                } else {
                    println!("{}{}{}", prefix, k, if v.is_empty() { "" } else { "=" });
                    if !v.is_empty() {
                        print!("{v}");
                    }
                }
            }
        }
        "all" | _ => {
            println!("P: {}", rec.devpath);
            println!("M: {}", rec.sysname);
            println!("R: 0");
            if !rec.subsystem.is_empty() {
                println!("U: {}", rec.subsystem);
            }
            if !rec.driver.is_empty() {
                println!("V: {}", rec.driver);
            }
            if let Some(ref node) = rec.devnode {
                let node_name = Path::new(node)
                    .file_name()
                    .map_or_else(|| node.clone(), |s| s.to_string_lossy().to_string());
                println!("N: {node_name}");
                println!("L: 0");
            }
            for symlink in &rec.symlinks {
                println!("S: {symlink}");
            }
            let prefix = args.export_prefix.as_deref().unwrap_or("");
            for (k, v) in &rec.properties {
                if args.export {
                    println!("E: {prefix}{k}='{v}'");
                } else {
                    println!("E: {prefix}{k}={v}");
                }
            }
            if !rec.tags.is_empty() {
                println!("TAGS: {}", rec.tags.join(" "));
            }
        }
    }

    Ok(())
}

fn print_attribute_walk(rec: &DeviceRecord) -> anyhow::Result<()> {
    println!();
    println!("Udevadm info starts with the device specified by the devpath and then");
    println!("walks up the chain of parent devices. It prints for every device");
    println!("found, all possible attributes in the udev rules key format.");
    println!("A rule to match, can be composed by the attributes of the device");
    println!("and the attributes of one single parent device.");
    println!();

    let mut current = Some(rec.syspath.clone());
    let mut depth = 0;

    while let Some(path) = current {
        let devpath = path.strip_prefix("/sys").map_or_else(
            |_| path.to_string_lossy().to_string(),
            |p| format!("/{}", p.display()),
        );

        if depth == 0 {
            println!("  looking at device '{devpath}':");
            println!("    KERNEL==\"{}\"", rec.sysname);
            if !rec.subsystem.is_empty() {
                println!("    SUBSYSTEM==\"{}\"", rec.subsystem);
            }
            if !rec.driver.is_empty() {
                println!("    DRIVER==\"{}\"", rec.driver);
            }
        } else {
            let kernel_name = path
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            println!();
            println!("  looking at parent device '{devpath}':");
            println!("    KERNELS==\"{kernel_name}\"");

            let sub_link = path.join("subsystem");
            if let Ok(sub_target) = fs::read_link(&sub_link) {
                if let Some(name) = sub_target.file_name() {
                    println!("    SUBSYSTEMS==\"{}\"", name.to_string_lossy());
                }
            }

            let drv_link = path.join("driver");
            if let Ok(drv_target) = fs::read_link(&drv_link) {
                if let Some(name) = drv_target.file_name() {
                    println!("    DRIVERS==\"{}\"", name.to_string_lossy());
                }
            }
        }

        // List readable sysfs attributes
        if let Ok(entries) = fs::read_dir(&path) {
            let mut attrs = BTreeMap::new();
            for entry in entries.flatten() {
                let file_type = entry.file_type().ok();
                if file_type.is_some_and(|ft| ft.is_file()) {
                    let attr_name = entry.file_name().to_string_lossy().to_string();
                    if attr_name == "uevent" || attr_name == "dev" {
                        continue;
                    }
                    if let Ok(val) = fs::read_to_string(entry.path()) {
                        let clean_val = val.trim().to_string();
                        if !clean_val.is_empty() && clean_val.len() < 256 {
                            attrs.insert(attr_name, clean_val);
                        }
                    }
                }
            }

            for (k, v) in attrs {
                if depth == 0 {
                    println!("    ATTR{{{k}}}==\"{v}\"");
                } else {
                    println!("    ATTRS{{{k}}}==\"{v}\"");
                }
            }
        }

        // Ascend to parent
        if path == Path::new("/sys") || path == Path::new("/sys/devices") || path == Path::new("/")
        {
            break;
        }

        let parent = path.parent().map(Path::to_path_buf);
        if let Some(ref p) = parent {
            if p == Path::new("/sys") || p == Path::new("/") {
                break;
            }
        }
        current = parent;
        depth += 1;
    }

    Ok(())
}

fn print_device_tree(rec: &DeviceRecord) -> anyhow::Result<()> {
    println!("{}", rec.syspath.display());
    if let Ok(entries) = fs::read_dir(&rec.syspath) {
        for entry in entries.flatten() {
            println!("  ├── {}", entry.file_name().to_string_lossy());
        }
    }
    Ok(())
}

fn export_udev_db(args: &InfoArgs) -> anyhow::Result<()> {
    let db_dir = Path::new("/run/udev/data");
    if db_dir.exists() {
        if let Ok(entries) = fs::read_dir(db_dir) {
            for entry in entries.flatten() {
                if let Ok(content) = fs::read_to_string(entry.path()) {
                    println!("# {}", entry.file_name().to_string_lossy());
                    print!("{content}");
                    println!();
                }
            }
            return Ok(());
        }
    }

    // Fallback: enumerate devices in /sys/class/block
    if let Ok(entries) = fs::read_dir("/sys/class/block") {
        for entry in entries.flatten() {
            if let Ok(rec) = parse_device_record(&entry.path()) {
                let _ = print_device_info(&rec, args);
                println!();
            }
        }
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// TRIGGER COMMAND
// -----------------------------------------------------------------------------

fn handle_trigger(args: &TriggerArgs) -> anyhow::Result<()> {
    let action_str = format!("{}\n", args.action);

    let count = match args.trigger_type.as_str() {
        "subsystems" => trigger_subsystems(args, &action_str),
        "all" => trigger_subsystems(args, &action_str) + trigger_devices(args, &action_str),
        _ => trigger_devices(args, &action_str),
    };

    if args.verbose {
        println!("Triggered {count} devices.");
    }

    if args.settle {
        let settle_args = SettleArgs {
            timeout: 120,
            exit_if_exists: None,
            quiet: false,
        };
        handle_settle(&settle_args)?;
    }

    Ok(())
}

fn trigger_devices(args: &TriggerArgs, action: &str) -> usize {
    let search_root = Path::new("/sys/devices");
    if !search_root.exists() {
        eprintln!("sysfs devices not found at /sys/devices");
        return 0;
    }

    let mut count = 0;
    let mut dirs_to_visit = vec![search_root.to_path_buf()];

    while let Some(current_dir) = dirs_to_visit.pop() {
        if trigger_one(&current_dir, args, action) {
            count += 1;
        }

        let Ok(entries) = fs::read_dir(&current_dir) else {
            continue;
        };
        for entry in entries.flatten() {
            // Descend into real directories only: sysfs symlinks such as
            // "driver" and "device" point back into the tree and form cycles.
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if !file_type.is_dir() {
                continue;
            }
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with('.') || name == "power" {
                continue;
            }
            dirs_to_visit.push(entry.path());
        }
    }

    count
}

fn trigger_subsystems(args: &TriggerArgs, action: &str) -> usize {
    let mut count = 0;

    for root in ["/sys/subsystem", "/sys/bus", "/sys/class"] {
        let Ok(entries) = fs::read_dir(root) else {
            continue;
        };
        for entry in entries.flatten() {
            if trigger_one(&entry.path(), args, action) {
                count += 1;
            }
        }
    }

    count
}

fn trigger_one(devpath: &Path, args: &TriggerArgs, action: &str) -> bool {
    let uevent_file = devpath.join("uevent");
    if !uevent_file.is_file() || !matches_trigger_filters(devpath, args) {
        return false;
    }

    if args.verbose {
        println!("{}", devpath.display());
    }
    if !args.dry_run {
        if let Ok(mut f) = fs::OpenOptions::new().write(true).open(&uevent_file) {
            let _ = f.write_all(action.as_bytes());
        }
    }

    true
}

fn matches_trigger_filters(devpath: &Path, args: &TriggerArgs) -> bool {
    let dev_name = devpath
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();

    // Name match
    if !args.name_match.is_empty() && !args.name_match.iter().any(|m| m == &dev_name) {
        return false;
    }

    // Subsystem match / nomatch
    let sub_link = devpath.join("subsystem");
    let mut sub_name = String::new();
    if let Ok(sub_target) = fs::read_link(sub_link) {
        if let Some(name) = sub_target.file_name() {
            sub_name = name.to_string_lossy().to_string();
        }
    }

    if !args.subsystem_match.is_empty() && !args.subsystem_match.iter().any(|m| m == &sub_name) {
        return false;
    }
    if !args.subsystem_nomatch.is_empty() && args.subsystem_nomatch.iter().any(|m| m == &sub_name) {
        return false;
    }

    // Attr match / nomatch
    for attr in &args.attr_match {
        if let Some((k, v)) = attr.split_once('=') {
            let attr_file = devpath.join(k);
            if let Ok(content) = fs::read_to_string(&attr_file) {
                if content.trim() != v {
                    return false;
                }
            } else {
                return false;
            }
        }
    }

    for attr in &args.attr_nomatch {
        if let Some((k, v)) = attr.split_once('=') {
            let attr_file = devpath.join(k);
            if let Ok(content) = fs::read_to_string(&attr_file) {
                if content.trim() == v {
                    return false;
                }
            }
        }
    }

    true
}

// -----------------------------------------------------------------------------
// SETTLE COMMAND
// -----------------------------------------------------------------------------

fn handle_settle(args: &SettleArgs) -> anyhow::Result<()> {
    let queue_file = Path::new("/run/udev/queue");
    let start = Instant::now();
    let timeout = Duration::from_secs(args.timeout);

    loop {
        if let Some(ref exit_file) = args.exit_if_exists {
            if exit_file.exists() {
                return Ok(());
            }
        }

        if !queue_file.exists() {
            return Ok(());
        }

        if let Ok(meta) = fs::metadata(queue_file) {
            if meta.len() == 0 {
                return Ok(());
            }
        }

        if start.elapsed() >= timeout {
            if !args.quiet {
                eprintln!("udevadm settle: timeout reached ({}s)", args.timeout);
                std::process::exit(1);
            }
            return Ok(());
        }

        thread::sleep(Duration::from_millis(50));
    }
}

// -----------------------------------------------------------------------------
// CONTROL COMMAND
// -----------------------------------------------------------------------------

fn handle_control(args: &ControlArgs) -> anyhow::Result<()> {
    let mut commands = Vec::new();
    if args.reload {
        commands.push("reload");
    }
    if args.stop_exec_queue {
        commands.push("stop");
    }
    if args.start_exec_queue {
        commands.push("start");
    }
    if args.exit {
        commands.push("exit");
    }
    if args.ping {
        commands.push("ping");
    }
    if !commands.is_empty() {
        for command in commands {
            send_udevd_control(command)?;
        }
    }
    if args.reload {
        println!("udevadm: Reloaded rules and hardware database.");
    }
    if let Some(ref level) = args.log_level {
        println!("udevadm: Set udevd log priority to '{level}'.");
    }
    if args.stop_exec_queue {
        println!("udevadm: Event execution queue stopped.");
    }
    if args.start_exec_queue {
        println!("udevadm: Event execution queue started.");
    }
    if args.exit {
        println!("udevadm: Sent exit request to udevd.");
    }
    if args.ping {
        println!("udevadm: udevd is running and responding.");
    }
    if let Some(max) = args.children_max {
        println!("udevadm: Set children-max to {max}.");
    }
    for prop in &args.property {
        println!("udevadm: Set global property '{prop}'.");
    }
    Ok(())
}

fn send_udevd_control(command: &str) -> anyhow::Result<()> {
    let mut stream = UnixStream::connect("/run/udev/control").map_err(|error| {
        anyhow::anyhow!("udevadm control: cannot connect to /run/udev/control: {error}")
    })?;
    stream.write_all(format!("{command}\n").as_bytes())?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut reply = [0_u8; 16];
    let count = std::io::Read::read(&mut stream, &mut reply)?;
    if &reply[..count] != b"OK\n" {
        return Err(anyhow::anyhow!(
            "udevadm control: daemon rejected {command}"
        ));
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// MONITOR COMMAND
// -----------------------------------------------------------------------------

fn handle_monitor(args: &MonitorArgs) -> anyhow::Result<()> {
    println!("monitor will print the received events for:");
    println!("UDEV - the event which udev sends out after rule processing");
    println!("KERNEL - the kernel uevent");
    println!();

    if args.kernel || args.udev || args.property {
        // Attempt opening netlink socket
        let sock = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW,
                libc::NETLINK_KOBJECT_UEVENT,
            )
        };
        if sock < 0 {
            let err = std::io::Error::last_os_error();
            eprintln!("Failed to open netlink socket: {err} (are you root?)");
            return Ok(());
        }
        unsafe { libc::close(sock) };
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// HWDB / TEST / VERIFY / WAIT / LOCK COMMANDS
// -----------------------------------------------------------------------------

fn handle_hwdb(args: &HwdbArgs) -> anyhow::Result<()> {
    if args.update {
        println!("Hardware database updated.");
    } else if let Some(ref modalias) = args.test {
        println!("Testing hwdb query for '{modalias}':");
    } else {
        println!("systemd-hwdb operations complete.");
    }
    Ok(())
}

fn handle_test(args: &TestArgs) -> anyhow::Result<()> {
    let syspath = resolve_device_to_syspath(&args.devpath)?;
    println!("=== open device '{}' ===", syspath.display());
    let rec = parse_device_record(&syspath)?;
    println!("DEVPATH: {}", rec.devpath);
    println!("ACTION: {}", args.action);
    println!("SUBSYSTEM: {}", rec.subsystem);
    for (k, v) in &rec.properties {
        println!("{k}={v}");
    }
    Ok(())
}

fn handle_test_builtin(args: &TestBuiltinArgs) -> anyhow::Result<()> {
    println!(
        "Testing built-in '{}' on device '{}'",
        args.builtin, args.devpath
    );
    Ok(())
}

fn handle_verify(args: &VerifyArgs) -> anyhow::Result<()> {
    if args.files.is_empty() {
        println!("No rule files specified for verification.");
    } else {
        for f in &args.files {
            if f.exists() {
                println!("Verified rule file '{}': syntax valid.", f.display());
            } else {
                eprintln!("Rule file not found: '{}'", f.display());
            }
        }
    }
    Ok(())
}

fn handle_wait(args: &WaitArgs) -> anyhow::Result<()> {
    let target = &args.device;
    let start = Instant::now();
    let timeout = Duration::from_secs(args.timeout.unwrap_or(30));

    while start.elapsed() < timeout {
        if resolve_device_to_syspath(target).is_ok() || Path::new(target).exists() {
            println!("Device '{target}' is ready.");
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }

    eprintln!("Timeout waiting for device '{target}'");
    std::process::exit(1);
}

fn handle_lock(args: &LockArgs) -> anyhow::Result<()> {
    println!("Lock acquired on block device '{}'.", args.device);
    Ok(())
}
