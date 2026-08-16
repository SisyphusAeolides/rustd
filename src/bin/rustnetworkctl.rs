// SPDX-License-Identifier: LGPL-2.1-or-later
//! networkctl v261 compatibility client.

use libc::{
    freeifaddrs, getifaddrs, if_nametoindex, ifaddrs, sockaddr_in, sockaddr_in6, AF_INET, AF_INET6,
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::env;
use std::ffi::CString;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::symlink;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

const NETWORKD_VARLINK: &str = "/run/systemd/netif/io.systemd.Network";
const VERSION: &str = "systemd 261 (261.2-1-arch)\n";

#[derive(Clone)]
struct Link {
    index: u32,
    name: String,
    kind: String,
    oper: String,
    setup: String,
    mac: String,
}

#[derive(Default)]
struct Opts {
    no_legend: bool,
    stats: bool,
    json: Option<String>,
    no_reload: bool,
    runtime: bool,
    stdin: bool,
    drop_in: Option<String>,
    no_ask_password: bool,
}

fn kv(path: &Path) -> HashMap<String, String> {
    fs::read_to_string(path)
        .ok()
        .map_or_else(HashMap::new, |text| {
            text.lines()
                .filter_map(|line| {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        return None;
                    }
                    let (key, value) = line.split_once('=')?;
                    Some((key.to_owned(), value.trim_matches('"').to_owned()))
                })
                .collect()
        })
}

fn state(index: u32) -> HashMap<String, String> {
    kv(&Path::new("/run/systemd/netif/links").join(index.to_string()))
}

fn links() -> Vec<Link> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir("/sys/class/net") else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let index = fs::read_to_string(path.join("ifindex"))
            .ok()
            .and_then(|value| value.trim().parse().ok())
            .unwrap_or(0);
        let status = state(index);
        let oper = status.get("OPER_STATE").cloned().unwrap_or_else(|| {
            fs::read_to_string(path.join("operstate"))
                .unwrap_or_else(|_| "unknown".into())
                .trim()
                .to_owned()
        });
        let setup = status
            .get("SETUP_STATE")
            .cloned()
            .unwrap_or_else(|| "unmanaged".into());
        let mac = fs::read_to_string(path.join("address"))
            .unwrap_or_default()
            .trim()
            .to_owned();
        let kind = match fs::read_to_string(path.join("type"))
            .ok()
            .and_then(|value| value.trim().parse::<u32>().ok())
            .unwrap_or(0)
        {
            1 => "ether",
            772 => "loopback",
            768 => "ipip",
            769 => "tunnel",
            776 => "sit",
            778 => "gre",
            801 => "ieee802.11",
            _ => "unknown",
        }
        .to_owned();
        out.push(Link {
            index,
            name,
            kind,
            oper,
            setup,
            mac,
        });
    }
    out.sort_by_key(|link| link.index);
    out
}

fn ips() -> HashMap<String, Vec<IpAddr>> {
    let mut out = HashMap::<String, Vec<IpAddr>>::new();
    unsafe {
        let mut head: *mut ifaddrs = std::ptr::null_mut();
        if getifaddrs(&mut head) == 0 {
            let mut current = head;
            while !current.is_null() {
                let ifa = &*current;
                if !ifa.ifa_addr.is_null() {
                    let name = std::ffi::CStr::from_ptr(ifa.ifa_name)
                        .to_string_lossy()
                        .into_owned();
                    match i32::from((*ifa.ifa_addr).sa_family) {
                        AF_INET => {
                            let address = &*(ifa.ifa_addr.cast::<sockaddr_in>());
                            out.entry(name).or_default().push(IpAddr::V4(Ipv4Addr::from(
                                address.sin_addr.s_addr.to_ne_bytes(),
                            )));
                        }
                        AF_INET6 => {
                            let address = &*(ifa.ifa_addr.cast::<sockaddr_in6>());
                            out.entry(name)
                                .or_default()
                                .push(IpAddr::V6(Ipv6Addr::from(address.sin6_addr.s6_addr)));
                        }
                        _ => {}
                    }
                }
                current = ifa.ifa_next;
            }
            freeifaddrs(head);
        }
    }
    out
}

fn ifindex(value: &str) -> Result<u32, String> {
    if let Ok(index) = value.parse::<u32>() {
        if links().iter().any(|link| link.index == index) {
            return Ok(index);
        }
    }
    let name = CString::new(value).map_err(|_| format!("Invalid interface name: {value}"))?;
    let index = unsafe { if_nametoindex(name.as_ptr()) };
    (index != 0)
        .then_some(index)
        .ok_or_else(|| format!("Interface {value} not found."))
}

fn wildcard_match(name: &str, pattern: &str) -> bool {
    fn inner(value: &[u8], pattern: &[u8]) -> bool {
        match pattern.first().copied() {
            None => value.is_empty(),
            Some(b'*') => {
                inner(value, &pattern[1..]) || (!value.is_empty() && inner(&value[1..], pattern))
            }
            Some(b'?') => !value.is_empty() && inner(&value[1..], &pattern[1..]),
            Some(ch) => value.first().copied() == Some(ch) && inner(&value[1..], &pattern[1..]),
        }
    }
    inner(name.as_bytes(), pattern.as_bytes())
}

fn select(patterns: &[String]) -> Vec<Link> {
    let all = links();
    if patterns.is_empty() {
        return all;
    }
    all.into_iter()
        .filter(|link| {
            patterns.iter().any(|pattern| {
                wildcard_match(&link.name, pattern) || *pattern == link.index.to_string()
            })
        })
        .collect()
}

fn json_out(value: &Value, mode: &str) {
    if matches!(mode, "short" | "compact") {
        println!("{}", serde_json::to_string(value).unwrap());
    } else {
        println!("{}", serde_json::to_string_pretty(value).unwrap());
    }
}

fn list_cmd(patterns: &[String], opts: &Opts) -> i32 {
    let rows = select(patterns);
    if let Some(mode) = &opts.json {
        let rows = rows
            .iter()
            .map(|link| {
                json!({
                    "Index": link.index,
                    "Name": link.name,
                    "Type": link.kind,
                    "OperationalState": link.oper,
                    "SetupState": link.setup,
                })
            })
            .collect();
        json_out(&Value::Array(rows), mode);
        return 0;
    }
    if !opts.no_legend {
        println!(
            "{:>3} {:<15} {:<10} {:<15} {:<12}",
            "IDX", "LINK", "TYPE", "OPERATIONAL", "SETUP"
        );
    }
    for link in &rows {
        println!(
            "{:>3} {:<15} {:<10} {:<15} {:<12}",
            link.index, link.name, link.kind, link.oper, link.setup
        );
    }
    if !opts.no_legend {
        println!("\n{} links listed.", rows.len());
    }
    0
}

fn status_cmd(patterns: &[String], opts: &Opts) -> i32 {
    let rows = select(patterns);
    if rows.is_empty() && !patterns.is_empty() {
        eprintln!("No matching links found.");
        return 1;
    }
    let addresses = ips();
    if let Some(mode) = &opts.json {
        let values: Vec<_> = rows
            .iter()
            .map(|link| json!({
                "Index": link.index,
                "Name": link.name,
                "Type": link.kind,
                "OperationalState": link.oper,
                "SetupState": link.setup,
                "HardwareAddress": link.mac,
                "Addresses": addresses.get(&link.name).cloned().unwrap_or_default().iter().map(ToString::to_string).collect::<Vec<_>>(),
                "NetworkFile": state(link.index).get("NETWORK_FILE").cloned(),
            }))
            .collect();
        if values.len() == 1 {
            json_out(&values[0], mode);
        } else {
            json_out(&Value::Array(values), mode);
        }
        return 0;
    }
    for (number, link) in rows.iter().enumerate() {
        if number > 0 {
            println!();
        }
        println!("● {}: {}", link.index, link.name);
        println!("       State: {} ({})", link.oper, link.setup);
        if !link.mac.is_empty() && link.mac != "00:00:00:00:00:00" {
            println!("  HW Address: {}", link.mac);
        }
        if let Some(file) = state(link.index).get("NETWORK_FILE") {
            println!("Network File: {file}");
        }
        if let Some(values) = addresses.get(&link.name) {
            for address in values {
                println!("     Address: {address}");
            }
        }
        if opts.stats {
            let base = Path::new("/sys/class/net")
                .join(&link.name)
                .join("statistics");
            for (label, key) in [
                ("RX Bytes", "rx_bytes"),
                ("RX Packets", "rx_packets"),
                ("TX Bytes", "tx_bytes"),
                ("TX Packets", "tx_packets"),
            ] {
                let value = fs::read_to_string(base.join(key)).unwrap_or_else(|_| "0".into());
                println!("{label:>13}: {}", value.trim());
            }
        }
    }
    0
}

fn varlink(method: &str, params: Value) -> Result<Value, String> {
    let mut stream = UnixStream::connect(NETWORKD_VARLINK).map_err(|error| {
        format!("Failed to connect to network service {NETWORKD_VARLINK}: {error}")
    })?;
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|error| error.to_string())?;
    let mut request = serde_json::to_vec(&json!({"method": method, "parameters": params}))
        .map_err(|error| error.to_string())?;
    request.push(0);
    stream
        .write_all(&request)
        .map_err(|error| error.to_string())?;
    let mut response = Vec::new();
    BufReader::new(&mut stream)
        .read_until(0, &mut response)
        .map_err(|error| error.to_string())?;
    if response.last() == Some(&0) {
        response.pop();
    }
    let value: Value = serde_json::from_slice(&response).map_err(|error| error.to_string())?;
    if let Some(error) = value.get("error").and_then(Value::as_str) {
        return Err(format!(
            "{error}: {}",
            value.get("parameters").unwrap_or(&Value::Null)
        ));
    }
    Ok(value.get("parameters").cloned().unwrap_or(Value::Null))
}

fn link_method(verb: &str, args: &[String], opts: &Opts) -> i32 {
    if args.is_empty() {
        eprintln!("networkctl {verb}: at least one interface is required");
        return 1;
    }
    let method = match verb {
        "up" => "io.systemd.Network.Link.Up",
        "down" => "io.systemd.Network.Link.Down",
        "renew" => "io.systemd.Network.Link.Renew",
        "forcerenew" => "io.systemd.Network.Link.ForceRenew",
        _ => "io.systemd.Network.Link.Reconfigure",
    };
    let mut failed = false;
    for arg in args {
        let result = ifindex(arg).and_then(|index| {
            varlink(
                method,
                json!({
                    "InterfaceIndex": index,
                    "allowInteractiveAuthentication": !opts.no_ask_password,
                }),
            )
            .map(|_| ())
        });
        if let Err(error) = result {
            eprintln!("Failed to {verb} interface {arg}: {error}");
            failed = true;
        }
    }
    i32::from(failed)
}

fn reload_cmd(opts: &Opts) -> i32 {
    match varlink(
        "io.systemd.service.Reload",
        json!({"allowInteractiveAuthentication": !opts.no_ask_password}),
    ) {
        Ok(_) => 0,
        Err(error) => {
            eprintln!("Failed to reload network service: {error}");
            1
        }
    }
}

fn dhcp_cmd(args: &[String], opts: &Opts) -> i32 {
    let Some(device) = args.first() else {
        eprintln!("networkctl dhcp-lease: interface is required");
        return 1;
    };
    let index = match ifindex(device) {
        Ok(index) => index,
        Err(error) => {
            eprintln!("{error}");
            return 1;
        }
    };
    let status = state(index);
    let lease_id = status
        .get("DHCP_LEASE")
        .or_else(|| status.get("DHCP6_LEASE"))
        .cloned()
        .unwrap_or_else(|| index.to_string());
    let lease = kv(&Path::new("/run/systemd/netif/leases").join(lease_id));
    if lease.is_empty() {
        eprintln!("No DHCP lease found for {device}.");
        return 1;
    }
    if let Some(mode) = &opts.json {
        json_out(&serde_json::to_value(&lease).unwrap(), mode);
        return 0;
    }
    if args.len() == 1 {
        let mut values: Vec<_> = lease.iter().collect();
        values.sort_by(|a, b| a.0.cmp(b.0));
        for (key, value) in values {
            println!("{key}={value}");
        }
        return 0;
    }
    let mut failed = false;
    for key in &args[1..] {
        let key = key.split(':').next().unwrap_or(key);
        if let Some(value) = lease.get(key) {
            println!("{value}");
        } else {
            failed = true;
        }
    }
    i32::from(failed)
}

fn lldp_cmd(patterns: &[String], opts: &Opts) -> i32 {
    let mut rows = Vec::new();
    let mut failed = false;
    for link in select(patterns) {
        match varlink("io.systemd.Network.Link.Describe", json!({"InterfaceIndex": link.index})) {
            Ok(value) => rows.push(json!({
                "InterfaceIndex": link.index,
                "InterfaceName": link.name,
                "Neighbors": value.get("LLDPNeighbors").or_else(|| value.get("LLDP")).cloned().unwrap_or(Value::Null),
            })),
            Err(error) => {
                eprintln!("Failed to query LLDP data for {}: {error}", link.name);
                failed = true;
            }
        }
    }
    if let Some(mode) = &opts.json {
        json_out(&Value::Array(rows), mode);
    } else {
        for value in rows {
            let name = value["InterfaceName"].as_str().unwrap_or("");
            let neighbors = &value["Neighbors"];
            if !neighbors.is_null() && neighbors != &json!([]) {
                println!("{name}: {neighbors}");
            }
        }
    }
    i32::from(failed)
}

#[repr(C)]
struct NetlinkHeader {
    len: u32,
    kind: u16,
    flags: u16,
    seq: u32,
    pid: u32,
}

#[repr(C)]
struct InterfaceInfo {
    family: u8,
    pad: u8,
    kind: u16,
    index: i32,
    flags: u32,
    change: u32,
}

#[repr(C)]
struct SockAddrNetlink {
    family: u16,
    pad: u16,
    pid: u32,
    groups: u32,
}

fn append_struct<T>(buffer: &mut Vec<u8>, value: &T) {
    let bytes = unsafe {
        std::slice::from_raw_parts((value as *const T).cast::<u8>(), std::mem::size_of::<T>())
    };
    buffer.extend_from_slice(bytes);
}

fn delete_one(index: u32) -> Result<(), String> {
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }

    let header = NetlinkHeader {
        len: (std::mem::size_of::<NetlinkHeader>() + std::mem::size_of::<InterfaceInfo>()) as u32,
        kind: 17,
        flags: 5,
        seq: 1,
        pid: 0,
    };
    let interface = InterfaceInfo {
        family: libc::AF_UNSPEC as u8,
        pad: 0,
        kind: 0,
        index: index as i32,
        flags: 0,
        change: 0,
    };
    let mut buffer: Vec<u8> = Vec::with_capacity(header.len as usize);
    append_struct(&mut buffer, &header);
    append_struct(&mut buffer, &interface);

    let address = SockAddrNetlink {
        family: libc::AF_NETLINK as u16,
        pad: 0,
        pid: 0,
        groups: 0,
    };
    let sent = unsafe {
        libc::sendto(
            fd,
            buffer.as_ptr().cast::<libc::c_void>(),
            buffer.len(),
            0,
            (&address as *const SockAddrNetlink).cast::<libc::sockaddr>(),
            std::mem::size_of::<SockAddrNetlink>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        let error = std::io::Error::last_os_error().to_string();
        unsafe { libc::close(fd) };
        return Err(error);
    }

    let mut response = [0u8; 256];
    let received = unsafe {
        libc::recv(
            fd,
            response.as_mut_ptr().cast::<libc::c_void>(),
            response.len(),
            0,
        )
    };
    unsafe { libc::close(fd) };
    if received < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    if received as usize >= std::mem::size_of::<NetlinkHeader>() + 4 {
        let reply = unsafe { &*response.as_ptr().cast::<NetlinkHeader>() };
        if reply.kind == 2 {
            let error = unsafe {
                *response
                    .as_ptr()
                    .add(std::mem::size_of::<NetlinkHeader>())
                    .cast::<i32>()
            };
            if error != 0 {
                return Err(std::io::Error::from_raw_os_error(-error).to_string());
            }
        }
    }
    Ok(())
}

fn delete_cmd(args: &[String]) -> i32 {
    if args.is_empty() {
        eprintln!("networkctl delete: at least one interface is required");
        return 1;
    }
    let mut failed = false;
    for arg in args {
        if let Err(error) = ifindex(arg).and_then(delete_one) {
            eprintln!("Failed to delete interface {arg}: {error}");
            failed = true;
        }
    }
    i32::from(failed)
}

fn dirs(runtime: bool) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if !runtime {
        dirs.push("/etc/systemd/network".into());
    }
    dirs.extend([
        PathBuf::from("/run/systemd/network"),
        PathBuf::from("/usr/local/lib/systemd/network"),
        PathBuf::from("/usr/lib/systemd/network"),
    ]);
    dirs
}

fn find_file(name: &str, runtime: bool) -> Option<PathBuf> {
    let path = Path::new(name);
    if path.is_absolute() && path.exists() {
        return Some(path.into());
    }
    for dir in dirs(runtime) {
        let candidate = dir.join(name);
        if candidate.exists() || candidate.is_symlink() {
            return Some(candidate);
        }
    }
    if let Ok(index) = ifindex(name) {
        if let Some(path) = state(index).get("NETWORK_FILE") {
            let path = PathBuf::from(path);
            if path.exists() {
                return Some(path);
            }
        }
    }
    None
}

fn cat_cmd(args: &[String], opts: &Opts) -> i32 {
    let names = if args.is_empty() {
        let mut names = Vec::new();
        for dir in dirs(opts.runtime) {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    if let Some(name) = entry.path().file_name().and_then(|name| name.to_str()) {
                        names.push(name.to_owned());
                    }
                }
            }
        }
        names.sort();
        names.dedup();
        names
    } else {
        args.to_vec()
    };
    let mut failed = false;
    for name in names {
        if let Some(path) = find_file(&name, opts.runtime) {
            match fs::read_to_string(&path) {
                Ok(text) => {
                    println!("# {}", path.display());
                    print!("{text}");
                    if !text.ends_with('\n') {
                        println!();
                    }
                }
                Err(error) => {
                    eprintln!("Failed to read {}: {error}", path.display());
                    failed = true;
                }
            }
        } else {
            eprintln!("No network configuration file found for {name}.");
            failed = true;
        }
    }
    i32::from(failed)
}

fn root(opts: &Opts) -> PathBuf {
    if opts.runtime {
        "/run/systemd/network".into()
    } else {
        "/etc/systemd/network".into()
    }
}

fn mask_cmd(args: &[String], opts: &Opts, mask: bool) -> i32 {
    if args.is_empty() {
        eprintln!(
            "networkctl {}: at least one file is required",
            if mask { "mask" } else { "unmask" }
        );
        return 1;
    }
    let root = root(opts);
    if let Err(error) = fs::create_dir_all(&root) {
        eprintln!("{error}");
        return 1;
    }
    let mut failed = false;
    for name in args {
        if name.contains('/') {
            eprintln!("Invalid network configuration file name: {name}");
            failed = true;
            continue;
        }
        let path = root.join(name);
        if mask {
            let _ = fs::remove_file(&path);
            if let Err(error) = symlink("/dev/null", &path) {
                eprintln!("Failed to mask {}: {error}", path.display());
                failed = true;
            }
        } else if path.is_symlink()
            && fs::read_link(&path).ok().as_deref() == Some(Path::new("/dev/null"))
        {
            if let Err(error) = fs::remove_file(&path) {
                eprintln!("Failed to unmask {}: {error}", path.display());
                failed = true;
            }
        }
    }
    if !failed && !opts.no_reload {
        let _ = reload_cmd(opts);
    }
    i32::from(failed)
}

fn edit_cmd(args: &[String], opts: &Opts) -> i32 {
    if args.is_empty() {
        eprintln!("networkctl edit: at least one file or interface is required");
        return 1;
    }
    let root = root(opts);
    let _ = fs::create_dir_all(&root);
    let mut failed = false;
    for name in args {
        let base = find_file(name, opts.runtime).unwrap_or_else(|| root.join(name));
        let path = if let Some(drop_in) = &opts.drop_in {
            let dir = PathBuf::from(format!("{}.d", base.display()));
            if let Err(error) = fs::create_dir_all(&dir) {
                eprintln!("{error}");
                failed = true;
                continue;
            }
            dir.join(drop_in)
        } else {
            base
        };
        if opts.stdin {
            let mut text = String::new();
            if let Err(error) = std::io::stdin()
                .read_to_string(&mut text)
                .and_then(|_| fs::write(&path, text))
            {
                eprintln!("Failed to write {}: {error}", path.display());
                failed = true;
            }
        } else {
            let editor = env::var("SYSTEMD_EDITOR")
                .or_else(|_| env::var("EDITOR"))
                .or_else(|_| env::var("VISUAL"))
                .unwrap_or_else(|_| "vi".into());
            match Command::new(&editor)
                .arg(&path)
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()
            {
                Ok(status) if status.success() => {}
                Ok(status) => {
                    eprintln!("Editor exited with {status}");
                    failed = true;
                }
                Err(error) => {
                    eprintln!("Failed to start editor {editor}: {error}");
                    failed = true;
                }
            }
        }
    }
    if !failed && !opts.no_reload {
        let _ = reload_cmd(opts);
    }
    i32::from(failed)
}

fn label_cmd(opts: &Opts) -> i32 {
    match Command::new("ip").args(["addrlabel", "list"]).output() {
        Ok(output) if output.status.success() => {
            if let Some(mode) = &opts.json {
                let values = String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .map(|line| Value::String(line.into()))
                    .collect();
                json_out(&Value::Array(values), mode);
            } else {
                print!("{}", String::from_utf8_lossy(&output.stdout));
            }
            0
        }
        Ok(output) => {
            eprint!("{}", String::from_utf8_lossy(&output.stderr));
            1
        }
        Err(error) => {
            eprintln!("Failed to query kernel address labels: {error}");
            1
        }
    }
}

fn persistent_cmd(args: &[String]) -> i32 {
    let Some(value) = args.first() else {
        eprintln!("networkctl persistent-storage: boolean argument required");
        return 1;
    };
    let ready = match value.to_ascii_lowercase().as_str() {
        "1" | "yes" | "true" | "on" => true,
        "0" | "no" | "false" | "off" => false,
        _ => {
            eprintln!("Failed to parse argument: {value}");
            return 1;
        }
    };
    match varlink(
        "io.systemd.Network.SetPersistentStorage",
        json!({"Ready": ready}),
    ) {
        Ok(_) => 0,
        Err(error) => {
            eprintln!("Failed to notify network service about persistent storage: {error}");
            1
        }
    }
}

fn help() {
    println!("networkctl [OPTIONS...] COMMAND\n\nQuery and control the networking subsystem.\n\nCommands:\n  list [PATTERN...]\n  status [PATTERN...]\n  dhcp-lease INTERFACE [CODE[:FORMAT]...]\n  lldp [PATTERN...]\n  label\n  delete DEVICES...\n  up DEVICES...\n  down DEVICES...\n  renew DEVICES...\n  forcerenew DEVICES...\n  reconfigure DEVICES...\n  reload\n  edit FILES|DEVICES...\n  cat [FILES|DEVICES...]\n  mask FILES...\n  unmask FILES...\n  persistent-storage BOOL\n\nOptions:\n  -h --help\n     --version\n     --no-pager\n     --no-legend\n  -a --all\n  -s --stats\n  -l --full\n  -n --lines=INTEGER\n     --json=MODE\n     --no-reload\n     --drop-in=NAME\n     --runtime\n     --stdin\n     --no-ask-password");
}

fn drop_name(value: &str) -> Result<String, String> {
    if value.is_empty() || value.contains('/') {
        return Err(format!("Invalid drop-in file name '{value}'."));
    }
    Ok(if value.ends_with(".conf") {
        value.into()
    } else {
        format!("{value}.conf")
    })
}

fn parse(args: &[String]) -> Result<(Opts, Vec<String>), String> {
    let mut opts = Opts::default();
    let mut positional = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        match arg.as_str() {
            "--" => {
                positional.extend_from_slice(&args[index + 1..]);
                break;
            }
            "-h" | "--help" => return Err("help".into()),
            "--version" => return Err("version".into()),
            "--no-pager" | "-a" | "--all" | "-l" | "--full" => {}
            "--no-legend" => opts.no_legend = true,
            "-s" | "--stats" => opts.stats = true,
            "--no-reload" => opts.no_reload = true,
            "--runtime" => opts.runtime = true,
            "--stdin" => opts.stdin = true,
            "--no-ask-password" => opts.no_ask_password = true,
            "--json" => opts.json = Some("pretty".into()),
            "-n" | "--lines" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| format!("{arg} requires an argument"))?;
                let _: usize = value
                    .parse()
                    .map_err(|_| format!("Failed to parse --lines value '{value}'"))?;
            }
            "--drop-in" => {
                index += 1;
                opts.drop_in =
                    Some(drop_name(args.get(index).ok_or_else(|| {
                        "--drop-in requires an argument".to_owned()
                    })?)?);
            }
            _ if arg.starts_with("--json=") => opts.json = Some(arg[7..].into()),
            _ if arg.starts_with("--lines=") => {
                let _: usize = arg[8..]
                    .parse()
                    .map_err(|_| format!("Failed to parse --lines value '{}'", &arg[8..]))?;
            }
            _ if arg.starts_with("--drop-in=") => opts.drop_in = Some(drop_name(&arg[10..])?),
            _ if arg.starts_with('-') => return Err(format!("Unknown option {arg}")),
            _ => positional.push(arg.clone()),
        }
        index += 1;
    }
    Ok((opts, positional))
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let (opts, positional) = match parse(&args) {
        Ok(value) => value,
        Err(error) if error == "help" => {
            help();
            return;
        }
        Err(error) if error == "version" => {
            print!("{VERSION}");
            return;
        }
        Err(error) => {
            eprintln!("networkctl: {error}");
            std::process::exit(1);
        }
    };
    let verb = positional.first().map_or("list", String::as_str);
    let rest = &positional[usize::from(!positional.is_empty())..];
    let code = match verb {
        "list" => list_cmd(rest, &opts),
        "status" => status_cmd(rest, &opts),
        "dhcp-lease" => dhcp_cmd(rest, &opts),
        "lldp" => lldp_cmd(rest, &opts),
        "label" => label_cmd(&opts),
        "delete" => delete_cmd(rest),
        "up" | "down" | "renew" | "forcerenew" | "reconfigure" => link_method(verb, rest, &opts),
        "reload" => reload_cmd(&opts),
        "edit" => edit_cmd(rest, &opts),
        "cat" => cat_cmd(rest, &opts),
        "mask" => mask_cmd(rest, &opts, true),
        "unmask" => mask_cmd(rest, &opts, false),
        "persistent-storage" => persistent_cmd(rest),
        "help" => {
            help();
            0
        }
        other => {
            eprintln!("Unknown command {other}");
            1
        }
    };
    std::process::exit(code);
}
