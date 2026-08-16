// SPDX-License-Identifier: LGPL-2.1-or-later
//! rustctl — native command-line control plane for the `RustD` service manager.

use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::symlink;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rustd::ipc::{
    control_socket_path, decode_response, encode_request, user_control_socket_path, IpcData,
    IpcRequest, IpcResponse, UnitInfo,
};
use rustd::unit::loader::UnitLoader;
use rustd::unit::section_install::InstallSection;

const VERSION: &str = concat!("RustD ", env!("CARGO_PKG_VERSION"));
const JOB_TIMEOUT: Duration = Duration::from_secs(90);
const POLL_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scope {
    System,
    User,
}

#[derive(Debug)]
struct Options {
    scope: Scope,
    runtime: bool,
    now: bool,
    quiet: bool,
    no_legend: bool,
    root: Option<PathBuf>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            scope: Scope::System,
            runtime: false,
            now: false,
            quiet: false,
            no_legend: false,
            root: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JobVerb {
    Start,
    Stop,
    Restart,
    Reload,
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("rustctl: {error}");
            std::process::exit(1);
        }
    }
}

fn run() -> anyhow::Result<i32> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "--version") {
        println!("{VERSION}");
        return Ok(0);
    }

    let (options, positional) = parse_args(&args)?;
    if options.scope == Scope::User && options.root.is_some() {
        anyhow::bail!("--user and --root may not be combined");
    }
    if options.now && options.root.is_some() {
        anyhow::bail!("--now may not be combined with --root");
    }
    if options.scope == Scope::User {
        std::env::set_var("RUSTD_CONTROL_SOCKET", user_control_socket_path());
    }

    let command = positional.first().map_or("help", String::as_str);
    let units: Vec<&str> = positional.iter().skip(1).map(String::as_str).collect();

    match command {
        "help" | "--help" | "-h" => {
            print_help();
            Ok(0)
        }
        "list-units" => list_units(&options),
        "list-jobs" => list_jobs(&options),
        "status" => status(&units),
        "show" => show(&units),
        "start" => run_jobs(&units, JobVerb::Start),
        "stop" => run_jobs(&units, JobVerb::Stop),
        "restart" => run_jobs(&units, JobVerb::Restart),
        "reload" => run_jobs(&units, JobVerb::Reload),
        "enable" => enable_disable(&units, &options, true),
        "disable" => enable_disable(&units, &options, false),
        "mask" => mask_unmask(&units, &options, true),
        "unmask" => mask_unmask(&units, &options, false),
        "is-enabled" => is_enabled(&units, &options),
        "is-active" => state_query(&units, QueryState::Active, options.quiet),
        "is-failed" => state_query(&units, QueryState::Failed, options.quiet),
        "reset-failed" => simple_request(IpcRequest::ResetFailed {
            units: units.iter().map(|unit| (*unit).to_owned()).collect(),
        }),
        "daemon-reload" => simple_request(IpcRequest::DaemonReload),
        "isolate" => {
            let unit = exactly_one(&units, "target")?;
            simple_request(IpcRequest::Isolate {
                unit: unit.to_owned(),
            })
        }
        "cancel" => cancel(&units),
        other => anyhow::bail!("unknown command '{other}' (run 'rustctl help')"),
    }
}

fn parse_args(args: &[String]) -> anyhow::Result<(Options, Vec<String>)> {
    let mut options = Options::default();
    let mut positional = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        match arg.as_str() {
            "--" => {
                positional.extend(args[index + 1..].iter().cloned());
                break;
            }
            "--user" => options.scope = Scope::User,
            "--system" => options.scope = Scope::System,
            "--runtime" => options.runtime = true,
            "--now" => options.now = true,
            "--quiet" | "-q" => options.quiet = true,
            "--no-legend" => options.no_legend = true,
            "--no-pager" | "--plain" => {}
            "--root" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| anyhow::anyhow!("--root requires a path"))?;
                options.root = Some(PathBuf::from(value));
            }
            "--help" | "-h" if positional.is_empty() => positional.push("help".to_owned()),
            value if value.starts_with("--root=") => {
                options.root = Some(PathBuf::from(&value[7..]));
            }
            value if value.starts_with('-') => anyhow::bail!("unrecognized option '{value}'"),
            _ => positional.push(arg.clone()),
        }
        index += 1;
    }
    Ok((options, positional))
}

fn transact(request: &IpcRequest) -> anyhow::Result<IpcResponse> {
    let path = control_socket_path();
    let mut stream = UnixStream::connect(&path)
        .map_err(|error| anyhow::anyhow!("cannot connect to {}: {error}", path.display()))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let frame = encode_request(request)?;
    stream.write_all(&frame)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut reply = Vec::new();
    stream.read_to_end(&mut reply)?;
    decode_response(&reply)
}

fn checked(request: &IpcRequest) -> anyhow::Result<IpcResponse> {
    let response = transact(request)?;
    if !response.ok {
        anyhow::bail!(response
            .error
            .unwrap_or_else(|| "manager request failed".to_owned()));
    }
    Ok(response)
}

fn simple_request(request: IpcRequest) -> anyhow::Result<i32> {
    checked(&request)?;
    Ok(0)
}

fn exactly_one<'a>(values: &'a [&str], description: &str) -> anyhow::Result<&'a str> {
    match values {
        [value] => Ok(*value),
        [] => anyhow::bail!("{description} required"),
        _ => anyhow::bail!("exactly one {description} is required"),
    }
}

fn list_units(options: &Options) -> anyhow::Result<i32> {
    let response = checked(&IpcRequest::ListUnits)?;
    let Some(IpcData::Units(units)) = response.data else {
        anyhow::bail!("manager returned an invalid list-units response");
    };
    if !options.no_legend {
        println!("{:<45} {:<10} {:<12} DESCRIPTION", "UNIT", "LOAD", "ACTIVE");
    }
    for unit in units {
        println!(
            "{:<45} {:<10} {:<12} {}",
            unit.name, unit.load_state, unit.active_state, unit.description
        );
    }
    Ok(0)
}

fn list_jobs(options: &Options) -> anyhow::Result<i32> {
    let response = checked(&IpcRequest::ListJobs)?;
    let Some(IpcData::Jobs(jobs)) = response.data else {
        anyhow::bail!("manager returned an invalid list-jobs response");
    };
    if !options.no_legend {
        println!("{:<8} {:<45} {:<10} STATE", "JOB", "UNIT", "TYPE");
    }
    for job in jobs {
        println!(
            "{:<8} {:<45} {:<10} {}",
            job.id, job.unit_name, job.job_type, job.state
        );
    }
    Ok(0)
}

fn status(units: &[&str]) -> anyhow::Result<i32> {
    require_units(units)?;
    let mut code = 0;
    for unit in units {
        let info = unit_info(unit)?;
        let marker = if info.active_state == "active" {
            "●"
        } else {
            "○"
        };
        println!("{marker} {} - {}", info.name, info.description);
        println!("  Loaded: {}", info.load_state);
        println!("  Active: {} ({})", info.active_state, info.sub_state);
        if let Some(pid) = info.main_pid {
            println!("  Main PID: {pid}");
        }
        if info.active_state == "failed" {
            code = 3;
        }
    }
    Ok(code)
}

fn show(units: &[&str]) -> anyhow::Result<i32> {
    require_units(units)?;
    for unit in units {
        let info = unit_info(unit)?;
        println!("Id={}", info.name);
        println!("Description={}", info.description);
        println!("LoadState={}", info.load_state);
        println!("ActiveState={}", info.active_state);
        println!("SubState={}", info.sub_state);
        println!("MainPID={}", info.main_pid.unwrap_or_default());
        println!("UnitType={}", info.unit_type);
    }
    Ok(0)
}

fn unit_info(unit: &str) -> anyhow::Result<UnitInfo> {
    let response = checked(&IpcRequest::Status {
        unit: unit.to_owned(),
    })?;
    let Some(IpcData::Unit(info)) = response.data else {
        anyhow::bail!("manager returned an invalid status response for {unit}");
    };
    Ok(info)
}

fn run_jobs(units: &[&str], verb: JobVerb) -> anyhow::Result<i32> {
    require_units(units)?;
    let mut code = 0;
    for unit in units {
        let previous_pid = (verb == JobVerb::Restart)
            .then(|| unit_info(unit).ok().and_then(|info| info.main_pid))
            .flatten();
        let request = match verb {
            JobVerb::Start => IpcRequest::Start {
                unit: (*unit).to_owned(),
            },
            JobVerb::Stop => IpcRequest::Stop {
                unit: (*unit).to_owned(),
            },
            JobVerb::Restart => IpcRequest::Restart {
                unit: (*unit).to_owned(),
            },
            JobVerb::Reload => IpcRequest::Reload {
                unit: (*unit).to_owned(),
            },
        };
        if let Err(error) = checked(&request) {
            eprintln!("rustctl: {unit}: {error}");
            code = 1;
            continue;
        }
        if let Err(error) = wait_for_job(unit, verb, previous_pid) {
            eprintln!("rustctl: {unit}: {error}");
            code = 1;
        }
    }
    Ok(code)
}

fn wait_for_job(unit: &str, verb: JobVerb, previous_pid: Option<i32>) -> anyhow::Result<()> {
    let deadline = Instant::now() + JOB_TIMEOUT;
    loop {
        let info = unit_info(unit)?;
        let complete = match verb {
            JobVerb::Start => info.active_state == "active" || oneshot_finished(&info),
            JobVerb::Stop => info.active_state == "inactive",
            JobVerb::Restart => {
                (info.active_state == "active" && info.main_pid != previous_pid)
                    || oneshot_finished(&info)
            }
            JobVerb::Reload => info.active_state == "active",
        };
        if complete {
            return Ok(());
        }
        if info.active_state == "failed" {
            anyhow::bail!("job failed");
        }
        if Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for job completion");
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn oneshot_finished(info: &UnitInfo) -> bool {
    info.active_state == "inactive" && info.service_type.as_deref() == Some("oneshot")
}

fn enable_disable(units: &[&str], options: &Options, enable: bool) -> anyhow::Result<i32> {
    require_units(units)?;
    let root = options.root.as_deref().unwrap_or_else(|| Path::new("/"));
    let loader = if options.scope == Scope::User {
        UnitLoader::user()
    } else {
        UnitLoader::with_dirs(system_search_dirs(root))
    };
    let control = control_dir(options);
    let mut code = 0;
    let mut changed = Vec::new();

    for unit in units {
        match set_enabled(&loader, root, &control, unit, enable, options.scope) {
            Ok(()) => changed.push(*unit),
            Err(error) => {
                eprintln!("rustctl: {unit}: {error}");
                code = 1;
            }
        }
    }
    if options.now && !changed.is_empty() {
        code |= run_jobs(
            &changed,
            if enable {
                JobVerb::Start
            } else {
                JobVerb::Stop
            },
        )?;
    }
    Ok(code)
}

fn set_enabled(
    loader: &UnitLoader,
    root: &Path,
    control: &Path,
    unit: &str,
    enable: bool,
    scope: Scope,
) -> anyhow::Result<()> {
    validate_unit_name(unit)?;
    let loaded = loader.load(unit)?;
    if !enable {
        remove_enable_links(control, unit)?;
        println!("Removed enablement links for {unit}");
        return Ok(());
    }

    let install: &InstallSection = loaded.install_section();
    let source = loaded.source_path();
    let target = if scope == Scope::System && root != Path::new("/") {
        Path::new("/").join(source.strip_prefix(root).unwrap_or(source))
    } else {
        source.to_path_buf()
    };
    let mut destinations = BTreeSet::new();
    for wanted in &install.wanted_by {
        destinations.insert(control.join(format!("{wanted}.wants")).join(unit));
    }
    for required in &install.required_by {
        destinations.insert(control.join(format!("{required}.requires")).join(unit));
    }
    if destinations.is_empty() {
        anyhow::bail!("unit has no [Install] WantedBy= or RequiredBy= entries");
    }
    for destination in destinations {
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        replace_symlink(&destination, &target)?;
        println!(
            "Created symlink {} -> {}",
            destination.display(),
            target.display()
        );
    }
    Ok(())
}

fn remove_enable_links(control: &Path, unit: &str) -> anyhow::Result<()> {
    validate_unit_name(unit)?;
    let Ok(entries) = fs::read_dir(control) else {
        return Ok(());
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !(name.ends_with(".wants") || name.ends_with(".requires")) || !path.is_dir() {
            continue;
        }
        let link = path.join(unit);
        if link.is_symlink() {
            fs::remove_file(link)?;
        }
    }
    Ok(())
}

fn mask_unmask(units: &[&str], options: &Options, mask: bool) -> anyhow::Result<i32> {
    require_units(units)?;
    let control = control_dir(options);
    fs::create_dir_all(&control)?;
    let mut code = 0;
    for unit in units {
        if let Err(error) = set_masked(&control, unit, mask) {
            eprintln!("rustctl: {unit}: {error}");
            code = 1;
        }
    }
    Ok(code)
}

fn set_masked(control: &Path, unit: &str, mask: bool) -> anyhow::Result<()> {
    validate_unit_name(unit)?;
    let path = control.join(unit);
    if mask {
        if path.exists() || path.is_symlink() {
            if path.is_symlink()
                && fs::read_link(&path).ok().as_deref() == Some(Path::new("/dev/null"))
            {
                return Ok(());
            }
            anyhow::bail!("{} already exists", path.display());
        }
        symlink("/dev/null", &path)?;
        println!("Created symlink {} -> /dev/null", path.display());
    } else if path.is_symlink()
        && fs::read_link(&path).ok().as_deref() == Some(Path::new("/dev/null"))
    {
        fs::remove_file(&path)?;
        println!("Removed {}", path.display());
    }
    Ok(())
}

fn is_enabled(units: &[&str], options: &Options) -> anyhow::Result<i32> {
    require_units(units)?;
    let root = options.root.as_deref().unwrap_or_else(|| Path::new("/"));
    let search = if options.scope == Scope::User {
        UnitLoader::user().search_dirs
    } else {
        system_search_dirs(root)
    };
    let mut code = 0;
    for unit in units {
        let state = enable_state(unit, &search);
        if !options.quiet {
            println!("{state}");
        }
        if state != "enabled" && state != "static" && state != "alias" {
            code = 1;
        }
    }
    Ok(code)
}

fn enable_state(unit: &str, search: &[PathBuf]) -> &'static str {
    for base in search {
        let path = base.join(unit);
        if let Ok(target) = fs::read_link(&path) {
            if target == Path::new("/dev/null") {
                return "masked";
            }
            return "alias";
        }
    }
    for base in search {
        let Ok(entries) = fs::read_dir(base) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if (name.ends_with(".wants") || name.ends_with(".requires"))
                && entry.path().join(unit).is_symlink()
            {
                return "enabled";
            }
        }
    }
    let source = search
        .iter()
        .map(|base| base.join(unit))
        .find(|path| path.exists());
    match source.and_then(|path| fs::read_to_string(path).ok()) {
        Some(text) if text.contains("[Install]") => "disabled",
        Some(_) => "static",
        None => "not-found",
    }
}

#[derive(Clone, Copy)]
enum QueryState {
    Active,
    Failed,
}

fn state_query(units: &[&str], query: QueryState, quiet: bool) -> anyhow::Result<i32> {
    require_units(units)?;
    let mut code = 0;
    for unit in units {
        let request = match query {
            QueryState::Active => IpcRequest::IsActive {
                unit: (*unit).to_owned(),
            },
            QueryState::Failed => IpcRequest::IsFailed {
                unit: (*unit).to_owned(),
            },
        };
        let response = checked(&request)?;
        let Some(IpcData::Text(state)) = response.data else {
            anyhow::bail!("manager returned an invalid state response for {unit}");
        };
        if !quiet {
            println!("{state}");
        }
        let expected = match query {
            QueryState::Active => "active",
            QueryState::Failed => "failed",
        };
        if state != expected {
            code = 1;
        }
    }
    Ok(code)
}

fn cancel(units: &[&str]) -> anyhow::Result<i32> {
    if units.is_empty() {
        return simple_request(IpcRequest::Cancel { job_id: None });
    }
    let mut code = 0;
    for value in units {
        let id = match value.parse::<u32>() {
            Ok(id) => id,
            Err(_) => {
                eprintln!("rustctl: invalid job id '{value}'");
                code = 1;
                continue;
            }
        };
        if let Err(error) = checked(&IpcRequest::Cancel { job_id: Some(id) }) {
            eprintln!("rustctl: {value}: {error}");
            code = 1;
        }
    }
    Ok(code)
}

fn system_search_dirs(root: &Path) -> Vec<PathBuf> {
    vec![
        root.join("etc/rustd/system"),
        root.join("run/rustd/system"),
        root.join("usr/local/lib/rustd/system"),
        root.join("usr/lib/rustd/system"),
    ]
}

fn control_dir(options: &Options) -> PathBuf {
    if options.scope == Scope::User {
        let base = if options.runtime {
            std::env::var_os("XDG_RUNTIME_DIR").map_or_else(|| {
                    PathBuf::from(format!("/run/user/{}", unsafe { libc::getuid() }))
                }, PathBuf::from)
        } else {
            std::env::var_os("XDG_CONFIG_HOME")
                .map(PathBuf::from)
                .or_else(|| {
                    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config"))
                })
                .unwrap_or_else(|| PathBuf::from("."))
        };
        return base.join("rustd/user");
    }
    let root = options.root.as_deref().unwrap_or_else(|| Path::new("/"));
    root.join(if options.runtime {
        "run/rustd/system"
    } else {
        "etc/rustd/system"
    })
}

fn validate_unit_name(unit: &str) -> anyhow::Result<()> {
    if unit.is_empty() || unit.starts_with('.') || unit.contains('/') || unit.contains('\0') {
        anyhow::bail!("invalid unit name '{unit}'");
    }
    Ok(())
}

fn replace_symlink(path: &Path, target: &Path) -> anyhow::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => fs::remove_file(path)?,
        Ok(_) => anyhow::bail!("{} already exists", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    symlink(target, path)?;
    Ok(())
}

fn require_units(units: &[&str]) -> anyhow::Result<()> {
    if units.is_empty() {
        anyhow::bail!("unit name required");
    }
    Ok(())
}

fn print_help() {
    println!("Usage: rustctl [OPTIONS] COMMAND [UNIT...]");
    println!();
    println!("Commands:");
    println!("  list-units                         List loaded units");
    println!("  list-jobs                          List live jobs");
    println!("  status UNIT...                     Show unit status");
    println!("  show UNIT...                       Show machine-readable unit properties");
    println!("  start UNIT...                      Start units");
    println!("  stop UNIT...                       Stop units");
    println!("  restart UNIT...                    Restart units");
    println!("  reload UNIT...                     Reload units");
    println!("  enable [--now] UNIT...             Enable units, optionally start now");
    println!("  disable [--now] UNIT...            Disable units, optionally stop now");
    println!("  mask UNIT...                       Mask units");
    println!("  unmask UNIT...                     Unmask units");
    println!("  is-enabled UNIT...                 Check enablement");
    println!("  is-active UNIT...                  Check active state");
    println!("  is-failed UNIT...                  Check failed state");
    println!("  isolate TARGET                     Isolate a target");
    println!("  reset-failed [UNIT...]             Clear failed state");
    println!("  daemon-reload                      Reload unit configuration");
    println!("  cancel [JOB...]                    Cancel jobs");
    println!();
    println!("Options:");
    println!("  --system                           Operate on the system manager (default)");
    println!("  --user                             Operate on the user manager");
    println!("  --runtime                          Make unit-file changes under /run");
    println!("  --now                              Start after enable; stop after disable");
    println!("  --root=PATH                        Operate on an alternate root");
    println!("  --quiet, -q                        Suppress state output");
    println!("  --no-legend                        Suppress list headers");
    println!("  --version                          Show RustD version");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_enable_now() {
        let args = ["enable", "--now", "demo.service"].map(str::to_owned);
        let (options, positional) = parse_args(&args).unwrap();
        assert!(options.now);
        assert_eq!(positional, ["enable", "demo.service"]);
    }

    #[test]
    fn native_system_search_path_is_stable() {
        assert_eq!(
            system_search_dirs(Path::new("/")),
            vec![
                PathBuf::from("/etc/rustd/system"),
                PathBuf::from("/run/rustd/system"),
                PathBuf::from("/usr/local/lib/rustd/system"),
                PathBuf::from("/usr/lib/rustd/system"),
            ]
        );
    }

    #[test]
    fn validates_unit_names() {
        assert!(validate_unit_name("demo.service").is_ok());
        assert!(validate_unit_name("../demo.service").is_err());
        assert!(validate_unit_name("/demo.service").is_err());
    }

    #[test]
    fn enable_state_detects_native_links() {
        let root = tempfile::tempdir().unwrap();
        let etc = root.path().join("etc/rustd/system");
        let usr = root.path().join("usr/lib/rustd/system");
        fs::create_dir_all(etc.join("multi-user.target.wants")).unwrap();
        fs::create_dir_all(&usr).unwrap();
        fs::write(
            usr.join("demo.service"),
            "[Service]\nExecStart=/bin/true\n[Install]\nWantedBy=multi-user.target\n",
        )
        .unwrap();
        symlink(
            "/usr/lib/rustd/system/demo.service",
            etc.join("multi-user.target.wants/demo.service"),
        )
        .unwrap();
        assert_eq!(
            enable_state("demo.service", &system_search_dirs(root.path())),
            "enabled"
        );
    }
}
