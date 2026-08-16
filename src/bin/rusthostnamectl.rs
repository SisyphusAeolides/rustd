// SPDX-License-Identifier: LGPL-2.1-or-later
use std::collections::BTreeMap;
use std::env;
use std::ffi::{CStr, CString};
use std::fs;
use std::io;
use std::path::Path;
use std::process::exit;

const HOSTNAME_PATH: &str = "/etc/hostname";
const MACHINE_INFO_PATH: &str = "/etc/machine-info";
const VERSION: &str = "systemd 261 (261.2-1-arch)\n";

#[derive(Default)]
struct Options {
    transient: bool,
    pretty: bool,
    static_name: bool,
    json: Option<String>,
}

fn read_env(path: &str) -> BTreeMap<String, String> {
    let Ok(text) = fs::read_to_string(path) else {
        return BTreeMap::new();
    };
    text.lines()
        .filter_map(|raw| {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (key, value) = line.split_once('=')?;
            Some((
                key.trim().to_owned(),
                value.trim().trim_matches('"').to_owned(),
            ))
        })
        .collect()
}

fn quote_env(value: &str) -> String {
    if value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':' | b'/'))
    {
        value.to_owned()
    } else {
        format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
    }
}

fn write_env(path: &str, values: &BTreeMap<String, String>) -> io::Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)?;
    }
    let mut output = String::new();
    for (key, value) in values {
        output.push_str(key);
        output.push('=');
        output.push_str(&quote_env(value));
        output.push('\n');
    }
    let tmp = format!("{path}.tmp.{}", std::process::id());
    fs::write(&tmp, output)?;
    fs::rename(tmp, path)
}

fn kernel_hostname() -> String {
    unsafe {
        let mut uts: libc::utsname = std::mem::zeroed();
        if libc::uname(&mut uts) == 0 {
            return CStr::from_ptr(uts.nodename.as_ptr())
                .to_string_lossy()
                .into_owned();
        }
    }
    String::new()
}

fn set_kernel_hostname(value: &str) -> anyhow::Result<()> {
    let c = CString::new(value)?;
    let rc = unsafe { libc::sethostname(c.as_ptr(), value.len()) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn static_hostname() -> String {
    fs::read_to_string(HOSTNAME_PATH)
        .unwrap_or_default()
        .trim()
        .to_owned()
}

fn machine_info_get(key: &str) -> String {
    read_env(MACHINE_INFO_PATH).remove(key).unwrap_or_default()
}

fn machine_info_set(key: &str, value: &str) -> anyhow::Result<()> {
    let mut info = read_env(MACHINE_INFO_PATH);
    if value.is_empty() {
        info.remove(key);
    } else {
        info.insert(key.to_owned(), value.to_owned());
    }
    write_env(MACHINE_INFO_PATH, &info)?;
    Ok(())
}

fn set_hostname(value: &str, opts: &Options) -> anyhow::Result<()> {
    let explicit = opts.transient || opts.pretty || opts.static_name;
    if opts.pretty {
        machine_info_set("PRETTY_HOSTNAME", value)?;
    }
    if opts.transient || !explicit {
        set_kernel_hostname(value)?;
    }
    if opts.static_name || !explicit {
        fs::write(HOSTNAME_PATH, format!("{value}\n"))?;
    }
    Ok(())
}

fn print_status(opts: &Options) {
    let transient = kernel_hostname();
    let static_name = static_hostname();
    let info = read_env(MACHINE_INFO_PATH);
    let pretty = info.get("PRETTY_HOSTNAME").cloned().unwrap_or_default();
    let icon = info.get("ICON_NAME").cloned().unwrap_or_default();
    let chassis = info.get("CHASSIS").cloned().unwrap_or_default();
    let deployment = info.get("DEPLOYMENT").cloned().unwrap_or_default();
    let location = info.get("LOCATION").cloned().unwrap_or_default();
    let tags = info.get("TAGS").cloned().unwrap_or_default();
    let machine_id = fs::read_to_string("/etc/machine-id")
        .unwrap_or_default()
        .trim()
        .to_owned();
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .unwrap_or_default()
        .trim()
        .to_owned();
    let os_release = read_env("/etc/os-release");
    let os_name = os_release.get("PRETTY_NAME").cloned().unwrap_or_default();
    let vendor = fs::read_to_string("/sys/class/dmi/id/sys_vendor")
        .unwrap_or_default()
        .trim()
        .to_owned();
    let model = fs::read_to_string("/sys/class/dmi/id/product_name")
        .unwrap_or_default()
        .trim()
        .to_owned();
    let (kernel, arch) = uname_info();

    if let Some(mode) = &opts.json {
        let compact = mode == "short" || mode == "compact";
        let value = serde_json::json!({
            "Hostname": transient,
            "StaticHostname": static_name,
            "PrettyHostname": pretty,
            "IconName": icon,
            "Chassis": chassis,
            "Deployment": deployment,
            "Location": location,
            "Tags": tags.split(':').filter(|tag| !tag.is_empty()).collect::<Vec<_>>(),
            "MachineID": machine_id,
            "BootID": boot_id,
            "OperatingSystemPrettyName": os_name,
            "KernelName": kernel.0,
            "KernelRelease": kernel.1,
            "Architecture": arch,
            "HardwareVendor": vendor,
            "HardwareModel": model,
        });
        if compact {
            println!("{}", serde_json::to_string(&value).unwrap());
        } else {
            println!("{}", serde_json::to_string_pretty(&value).unwrap());
        }
        return;
    }

    if !transient.is_empty() && transient != static_name {
        println!(" Transient hostname: {transient}");
    }
    println!(
        "    Static hostname: {}",
        if static_name.is_empty() {
            "n/a"
        } else {
            &static_name
        }
    );
    if !pretty.is_empty() && pretty != static_name {
        println!("    Pretty hostname: {pretty}");
    }
    if !icon.is_empty() {
        println!("          Icon name: {icon}");
    }
    if !chassis.is_empty() {
        println!("            Chassis: {chassis}");
    }
    if !deployment.is_empty() {
        println!("         Deployment: {deployment}");
    }
    if !location.is_empty() {
        println!("           Location: {location}");
    }
    if !tags.is_empty() {
        println!("               Tags: {}", tags.replace(':', " "));
    }
    if !machine_id.is_empty() {
        println!("         Machine ID: {machine_id}");
    }
    if !boot_id.is_empty() {
        println!("            Boot ID: {boot_id}");
    }
    if !os_name.is_empty() {
        println!("   Operating System: {os_name}");
    }
    println!("             Kernel: {} {}", kernel.0, kernel.1);
    println!("       Architecture: {arch}");
    if !vendor.is_empty() {
        println!("    Hardware Vendor: {vendor}");
    }
    if !model.is_empty() {
        println!("     Hardware Model: {model}");
    }
}

fn uname_info() -> ((String, String), String) {
    unsafe {
        let mut uts: libc::utsname = std::mem::zeroed();
        if libc::uname(&mut uts) == 0 {
            return (
                (
                    CStr::from_ptr(uts.sysname.as_ptr())
                        .to_string_lossy()
                        .into_owned(),
                    CStr::from_ptr(uts.release.as_ptr())
                        .to_string_lossy()
                        .into_owned(),
                ),
                CStr::from_ptr(uts.machine.as_ptr())
                    .to_string_lossy()
                    .into_owned(),
            );
        }
    }
    (("Unknown".into(), "Unknown".into()), "Unknown".into())
}

fn get_or_set(args: &[String], key: &str) -> i32 {
    if let Some(value) = args.first() {
        if let Err(error) = machine_info_set(key, value) {
            eprintln!("Failed to set property: {error}");
            return 1;
        }
    } else {
        println!("{}", machine_info_get(key));
    }
    0
}

fn tags(args: &[String]) -> i32 {
    if args.is_empty() {
        let value = machine_info_get("TAGS");
        for tag in value.split(':').filter(|tag| !tag.is_empty()) {
            println!("{tag}");
        }
        return 0;
    }
    let mut values = args.to_vec();
    values.sort();
    values.dedup();
    match machine_info_set("TAGS", &values.join(":")) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("Failed to set tags: {error}");
            1
        }
    }
}

fn help() {
    println!("hostnamectl [OPTIONS...] COMMAND ...\n\nQuery or change system hostname.\n\nCommands:\n  status\n  hostname [NAME]\n  icon-name [NAME]\n  chassis [NAME]\n  deployment [NAME]\n  location [NAME]\n  tags [TAG...]\n\nCompatibility aliases:\n  set-hostname NAME\n  set-icon-name NAME\n  set-chassis NAME\n  set-deployment NAME\n  set-location NAME\n\nOptions:\n  -h --help\n     --version\n     --transient\n     --static\n     --pretty\n     --json[=MODE]\n     --no-ask-password");
}

fn parse(args: &[String]) -> Result<(Options, Vec<String>), String> {
    let mut opts = Options::default();
    let mut positional = Vec::new();
    for arg in args {
        match arg.as_str() {
            "-h" | "--help" => return Err("help".into()),
            "--version" => return Err("version".into()),
            "--transient" => opts.transient = true,
            "--pretty" => opts.pretty = true,
            "--static" => opts.static_name = true,
            "--no-ask-password" | "--no-pager" => {}
            "--json" => opts.json = Some("pretty".into()),
            _ if arg.starts_with("--json=") => opts.json = Some(arg[7..].to_owned()),
            _ if arg.starts_with('-') => return Err(format!("Unknown option {arg}")),
            _ => positional.push(arg.clone()),
        }
    }
    Ok((opts, positional))
}

fn main() {
    let raw: Vec<String> = env::args().skip(1).collect();
    let (opts, positional) = match parse(&raw) {
        Ok(v) => v,
        Err(e) if e == "help" => {
            help();
            return;
        }
        Err(e) if e == "version" => {
            print!("{VERSION}");
            return;
        }
        Err(e) => {
            eprintln!("hostnamectl: {e}");
            exit(1);
        }
    };
    let verb = positional.first().map_or("status", String::as_str);
    let args = &positional[usize::from(!positional.is_empty())..];
    let code = match verb {
        "status" => {
            print_status(&opts);
            0
        }
        "hostname" | "set-hostname" => {
            if let Some(value) = args.first() {
                match set_hostname(value, &opts) {
                    Ok(()) => 0,
                    Err(e) => {
                        eprintln!("Failed to set hostname: {e}");
                        1
                    }
                }
            } else if verb == "hostname" {
                let value = if opts.pretty {
                    machine_info_get("PRETTY_HOSTNAME")
                } else if opts.static_name {
                    static_hostname()
                } else {
                    kernel_hostname()
                };
                println!("{value}");
                0
            } else {
                eprintln!("hostnamectl set-hostname: NAME is required");
                1
            }
        }
        "icon-name" | "set-icon-name" => get_or_set(args, "ICON_NAME"),
        "chassis" | "set-chassis" => get_or_set(args, "CHASSIS"),
        "deployment" | "set-deployment" => get_or_set(args, "DEPLOYMENT"),
        "location" | "set-location" => get_or_set(args, "LOCATION"),
        "tags" => tags(args),
        "help" => {
            help();
            0
        }
        other => {
            eprintln!("Unknown command '{other}'.");
            1
        }
    };
    exit(code);
}
