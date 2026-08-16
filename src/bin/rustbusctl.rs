// SPDX-License-Identifier: LGPL-2.1-or-later
//! rustbusctl — Introspect and monitor the D-Bus bus.
//!
//! Upstream counterpart: systemd busctl (v261)

use std::collections::HashSet;
use std::fs;
use std::future::Future;
use std::pin::Pin;

use clap::{Parser, Subcommand, ValueEnum};
use zbus::fdo::{DBusProxy, PropertiesProxy};
use zbus::names::InterfaceName;
use zbus::zvariant::{ObjectPath, Value};
use zbus::Connection;

#[derive(Parser, Debug)]
#[command(
    name = "rustbusctl",
    version = "261",
    about = "Introspect and monitor the D-Bus bus",
    long_about = "A compatibility-oriented D-Bus introspection, monitoring, and administration tool."
)]
struct Cli {
    /// Connect to system bus (default)
    #[arg(long, default_value_t = true, conflicts_with = "user")]
    system: bool,

    /// Connect to user session bus
    #[arg(long)]
    user: bool,

    /// Connect to specified D-Bus bus address
    #[arg(long)]
    address: Option<String>,

    /// Show machine ID
    #[arg(long)]
    show_machine: bool,

    /// Show only unique bus names
    #[arg(long)]
    unique: bool,

    /// Show only acquired (well-known) bus names
    #[arg(long)]
    acquired: bool,

    /// Show only activatable bus names
    #[arg(long)]
    activatable: bool,

    /// Show all bus names (unique, well-known, and activatable)
    #[arg(long, short = 'a')]
    all: bool,

    /// Output formatting mode
    #[arg(long, value_enum, default_value_t = JsonMode::Off)]
    json: JsonMode,

    /// Do not pipe output into a pager
    #[arg(long)]
    no_pager: bool,

    /// Quiet operation
    #[arg(long, short = 'q')]
    quiet: bool,

    /// Verbose operation
    #[arg(long, short = 'v')]
    verbose: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum JsonMode {
    Off,
    Pretty,
    Short,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    /// List active and acquired bus names (default)
    List {
        /// Show only unique bus names
        #[arg(long)]
        unique: bool,

        /// Show only acquired bus names
        #[arg(long)]
        acquired: bool,

        /// Show only activatable bus names
        #[arg(long)]
        activatable: bool,

        /// Show all names
        #[arg(long, short = 'a')]
        all: bool,
    },

    /// Show process information and credentials of a bus service
    Status {
        /// Service name (e.g. org.freedesktop.systemd1 or :1.123)
        service: Option<String>,
    },

    /// Monitor D-Bus traffic
    Monitor {
        /// Optional services to filter by
        services: Vec<String>,
    },

    /// Capture D-Bus traffic
    Capture {
        /// Optional services to filter by
        services: Vec<String>,
    },

    /// Show object tree of a service
    Tree {
        /// Service name
        service: String,

        /// Root object path (default: /)
        #[arg(default_value = "/")]
        path: String,
    },

    /// Introspect an object and print interfaces, methods, properties, signals
    Introspect {
        /// Service name
        service: String,

        /// Object path
        path: String,

        /// Optional interface filter
        interface: Option<String>,

        /// Print raw XML introspection data
        #[arg(long)]
        xml: bool,
    },

    /// Call a D-Bus method
    Call {
        /// Destination service
        service: String,

        /// Object path
        path: String,

        /// Interface name
        interface: String,

        /// Method name
        method: String,

        /// Signature of arguments (e.g. 's', 'ss', 'u', 'as')
        signature: Option<String>,

        /// Arguments matching the signature
        args: Vec<String>,
    },

    /// Read D-Bus properties
    GetProperty {
        /// Service name
        service: String,

        /// Object path
        path: String,

        /// Interface name
        interface: String,

        /// Property names to read
        properties: Vec<String>,
    },

    /// Set a D-Bus property
    SetProperty {
        /// Service name
        service: String,

        /// Object path
        path: String,

        /// Interface name
        interface: String,

        /// Property name
        property: String,

        /// Signature of the value (e.g. 's', 'u', 'b')
        signature: String,

        /// Value elements
        values: Vec<String>,
    },
}

fn main() {
    let cli = Cli::parse();

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("busctl error: failed to build runtime: {e}");
            std::process::exit(1);
        }
    };

    if let Err(err) = rt.block_on(run(cli)) {
        eprintln!("busctl error: {err}");
        std::process::exit(1);
    }
}

async fn get_connection(cli: &Cli) -> anyhow::Result<Connection> {
    if let Some(ref addr) = cli.address {
        let conn = zbus::connection::Builder::address(addr.as_str())?
            .build()
            .await?;
        return Ok(conn);
    }

    if cli.user {
        Connection::session()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to connect to user session bus: {e}"))
    } else {
        Connection::system()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to connect to system bus: {e}"))
    }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let conn = get_connection(&cli).await?;

    let cmd = cli.command.clone().unwrap_or(Commands::List {
        unique: cli.unique,
        acquired: cli.acquired,
        activatable: cli.activatable,
        all: cli.all,
    });

    match cmd {
        Commands::List {
            unique,
            acquired,
            activatable,
            all,
        } => {
            cmd_list(
                &conn,
                &cli,
                unique || cli.unique,
                acquired || cli.acquired,
                activatable || cli.activatable,
                all || cli.all,
            )
            .await?;
        }
        Commands::Status { service } => {
            cmd_status(&conn, &cli, service).await?;
        }
        Commands::Monitor { services } | Commands::Capture { services } => {
            cmd_monitor(&conn, services).await?;
        }
        Commands::Tree { service, path } => {
            cmd_tree(&conn, &service, &path).await?;
        }
        Commands::Introspect {
            service,
            path,
            interface,
            xml,
        } => {
            cmd_introspect(&conn, &service, &path, interface.as_deref(), xml).await?;
        }
        Commands::Call {
            service,
            path,
            interface,
            method,
            signature,
            args,
        } => {
            cmd_call(
                &conn,
                &service,
                &path,
                &interface,
                &method,
                signature.as_deref(),
                &args,
            )
            .await?;
        }
        Commands::GetProperty {
            service,
            path,
            interface,
            properties,
        } => {
            cmd_get_property(&conn, &service, &path, &interface, &properties).await?;
        }
        Commands::SetProperty {
            service,
            path,
            interface,
            property,
            signature,
            values,
        } => {
            cmd_set_property(
                &conn, &service, &path, &interface, &property, &signature, &values,
            )
            .await?;
        }
    }

    Ok(())
}

#[derive(serde::Serialize)]
struct BusNameEntry {
    name: String,
    pid: Option<u32>,
    process: Option<String>,
    user: Option<String>,
    connection: Option<String>,
    unit: Option<String>,
    activatable: bool,
}

async fn cmd_list(
    conn: &Connection,
    cli: &Cli,
    unique_only: bool,
    acquired_only: bool,
    activatable_only: bool,
    show_all: bool,
) -> anyhow::Result<()> {
    let proxy = DBusProxy::new(conn).await?;

    let mut names = Vec::new();
    let mut activatable_set = HashSet::new();

    if !unique_only && !acquired_only || activatable_only || show_all {
        if let Ok(activatable_names) = proxy.list_activatable_names().await {
            for name in activatable_names {
                activatable_set.insert(name.to_string());
            }
        }
    }

    if !activatable_only || show_all {
        if let Ok(active_names) = proxy.list_names().await {
            for name in active_names {
                names.push(name.to_string());
            }
        }
    }

    if (activatable_only || show_all) && !names.is_empty() {
        for act in &activatable_set {
            if !names.contains(act) {
                names.push(act.clone());
            }
        }
    } else if activatable_only {
        names = activatable_set.iter().cloned().collect();
    }

    names.sort();

    let mut entries = Vec::new();

    for name in names {
        let is_unique = name.starts_with(':');
        let is_activatable = activatable_set.contains(&name);

        if unique_only && !is_unique {
            continue;
        }
        if acquired_only && is_unique {
            continue;
        }

        let mut pid = None;
        let mut user = None;
        let mut conn_owner = None;

        if !is_activatable || is_unique {
            if let Ok(owner) = proxy.get_name_owner(name.as_str().try_into()?).await {
                conn_owner = Some(owner.to_string());
            }
            if let Ok(p) = proxy
                .get_connection_unix_process_id(name.as_str().try_into()?)
                .await
            {
                pid = Some(p);
            }
            if let Ok(u) = proxy
                .get_connection_unix_user(name.as_str().try_into()?)
                .await
            {
                user = resolve_uid_to_username(u);
            }
        }

        let process = pid.and_then(get_process_name);
        let unit = pid.and_then(get_process_unit);

        entries.push(BusNameEntry {
            name,
            pid,
            process,
            user,
            connection: conn_owner,
            unit,
            activatable: is_activatable,
        });
    }

    if cli.json != JsonMode::Off {
        match cli.json {
            JsonMode::Pretty => println!("{}", serde_json::to_string_pretty(&entries)?),
            JsonMode::Short => println!("{}", serde_json::to_string(&entries)?),
            JsonMode::Off => {}
        }
        return Ok(());
    }

    if !cli.quiet {
        println!(
            "{:<45} {:>7} {:<15} {:<12} {:<12} {:<20}",
            "NAME", "PID", "PROCESS", "USER", "CONNECTION", "UNIT"
        );
    }

    for e in entries {
        let pid_str = e.pid.map_or_else(|| "-".to_string(), |p| p.to_string());
        let proc_str = e.process.as_deref().unwrap_or("-");
        let user_str = e.user.as_deref().unwrap_or("-");
        let conn_str =
            e.connection
                .as_deref()
                .unwrap_or(if e.activatable { "(activatable)" } else { "-" });
        let unit_str = e.unit.as_deref().unwrap_or("-");

        println!(
            "{:<45} {:>7} {:<15} {:<12} {:<12} {:<20}",
            e.name, pid_str, proc_str, user_str, conn_str, unit_str
        );
    }

    Ok(())
}

async fn cmd_status(conn: &Connection, cli: &Cli, service: Option<String>) -> anyhow::Result<()> {
    let proxy = DBusProxy::new(conn).await?;

    if let Some(name) = service {
        let owner = proxy
            .get_name_owner(name.as_str().try_into()?)
            .await
            .map_or_else(|_| "-".to_string(), |o| o.to_string());
        let pid = proxy
            .get_connection_unix_process_id(name.as_str().try_into()?)
            .await
            .ok();
        let uid = proxy
            .get_connection_unix_user(name.as_str().try_into()?)
            .await
            .ok();
        let user_name = uid.and_then(resolve_uid_to_username);
        let proc_name = pid.and_then(get_process_name);
        let cmdline = pid.and_then(get_process_cmdline);
        let unit = pid.and_then(get_process_unit);

        if cli.json != JsonMode::Off {
            let info = serde_json::json!({
                "service": name,
                "owner": owner,
                "pid": pid,
                "user": user_name,
                "uid": uid,
                "process": proc_name,
                "cmdline": cmdline,
                "unit": unit
            });
            match cli.json {
                JsonMode::Pretty => println!("{}", serde_json::to_string_pretty(&info)?),
                JsonMode::Short => println!("{}", serde_json::to_string(&info)?),
                JsonMode::Off => {}
            }
            return Ok(());
        }

        println!("   Service: {name}");
        println!("     Owner: {owner}");
        if let Some(p) = pid {
            println!("       PID: {p}");
        }
        if let Some(u) = user_name {
            println!("      User: {u} ({})", uid.unwrap_or(0));
        }
        if let Some(cmd) = cmdline {
            println!("      Exec: {cmd}");
        } else if let Some(proc) = proc_name {
            println!("   Process: {proc}");
        }
        if let Some(un) = unit {
            println!("      Unit: {un}");
        }
    } else {
        let unique_name = conn.unique_name().map_or("-", |u| u.as_str());
        let server_id = conn.server_guid();
        println!("  Unique Name: {unique_name}");
        println!("    Server ID: {server_id}");
        let creds_ok = conn.peer_credentials().await.is_ok();
        println!(
            "  Bus Address: {}",
            if creds_ok { "connected" } else { "standard" }
        );
    }

    Ok(())
}

async fn cmd_monitor(conn: &Connection, services: Vec<String>) -> anyhow::Result<()> {
    println!("Monitoring D-Bus traffic. Press Ctrl+C to stop.");
    let proxy = DBusProxy::new(conn).await?;
    let mut signal_stream = proxy.receive_name_owner_changed().await?;

    // Monitor NameOwnerChanged signals
    use zbus::export::ordered_stream::OrderedStreamExt;
    while let Some(signal) = signal_stream.next().await {
        if let Ok(args) = signal.args() {
            let name = args.name();
            let old = args.old_owner();
            let new = args.new_owner();

            if !services.is_empty() && !services.iter().any(|s| s == name.as_str()) {
                continue;
            }

            println!(
                "NameOwnerChanged: name={} old_owner={} new_owner={}",
                name,
                old.as_deref().unwrap_or("<none>"),
                new.as_deref().unwrap_or("<none>")
            );
        }
    }
    Ok(())
}

async fn cmd_tree(conn: &Connection, service: &str, path: &str) -> anyhow::Result<()> {
    println!("Service {service}:");
    let mut visited = HashSet::new();
    print_tree_node(conn, service, path.to_string(), String::new(), &mut visited).await?;
    Ok(())
}

fn print_tree_node<'a>(
    conn: &'a Connection,
    service: &'a str,
    path: String,
    prefix: String,
    visited: &'a mut HashSet<String>,
) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + 'a>> {
    Box::pin(async move {
        if visited.contains(&path) {
            return Ok(());
        }
        visited.insert(path.clone());

        println!("{prefix}└─{path}");

        let xml: Result<String, _> = conn
            .call_method(
                Some(service),
                path.as_str(),
                Some("org.freedesktop.DBus.Introspectable"),
                "Introspect",
                &(),
            )
            .await
            .and_then(|reply| reply.body().deserialize());

        if let Ok(xml_str) = xml {
            let subnodes = parse_subnodes_from_xml(&xml_str);
            let next_prefix = format!("{prefix}  ");
            for sub in subnodes {
                let sub_path = if path == "/" {
                    format!("/{sub}")
                } else {
                    format!("{path}/{sub}")
                };
                let _ =
                    print_tree_node(conn, service, sub_path, next_prefix.clone(), visited).await;
            }
        }

        Ok(())
    })
}

fn parse_subnodes_from_xml(xml: &str) -> Vec<String> {
    let mut nodes = Vec::new();
    for line in xml.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("<node ") && trimmed.contains("name=\"") {
            if let Some(start) = trimmed.find("name=\"") {
                let rest = &trimmed[start + 6..];
                if let Some(end) = rest.find('"') {
                    let name = &rest[..end];
                    if !name.is_empty() && !name.contains('/') {
                        nodes.push(name.to_string());
                    }
                }
            }
        }
    }
    nodes
}

async fn cmd_introspect(
    conn: &Connection,
    service: &str,
    path: &str,
    filter_iface: Option<&str>,
    xml: bool,
) -> anyhow::Result<()> {
    let xml_data: String = conn
        .call_method(
            Some(service),
            path,
            Some("org.freedesktop.DBus.Introspectable"),
            "Introspect",
            &(),
        )
        .await?
        .body()
        .deserialize()?;

    if xml {
        println!("{xml_data}");
        return Ok(());
    }

    println!(
        "{:<50} {:<10} {:<15} {:<15} {:<10}",
        "NAME", "TYPE", "SIGNATURE", "RESULT/VALUE", "FLAGS"
    );
    parse_and_print_introspection(&xml_data, filter_iface);
    Ok(())
}

fn parse_and_print_introspection(xml: &str, filter_iface: Option<&str>) {
    let mut current_iface = None;

    for line in xml.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("<interface ") {
            if let Some(start) = trimmed.find("name=\"") {
                let rest = &trimmed[start + 6..];
                if let Some(end) = rest.find('"') {
                    let iface = &rest[..end];
                    current_iface = Some(iface.to_string());
                    if filter_iface.map_or(true, |f| f == iface) {
                        println!(
                            "{:<50} {:<10} {:<15} {:<15} {:<10}",
                            iface, "interface", "-", "-", "-"
                        );
                    }
                }
            }
        } else if trimmed.starts_with("</interface>") {
            current_iface = None;
        } else if let Some(ref iface) = current_iface {
            if !filter_iface.map_or(true, |f| f == iface) {
                continue;
            }
            if trimmed.starts_with("<method ") {
                if let Some(start) = trimmed.find("name=\"") {
                    let rest = &trimmed[start + 6..];
                    if let Some(end) = rest.find('"') {
                        let method = &rest[..end];
                        println!(
                            "  .{:<48} {:<10} {:<15} {:<15} {:<10}",
                            method, "method", "-", "-", "-"
                        );
                    }
                }
            } else if trimmed.starts_with("<signal ") {
                if let Some(start) = trimmed.find("name=\"") {
                    let rest = &trimmed[start + 6..];
                    if let Some(end) = rest.find('"') {
                        let sig = &rest[..end];
                        println!(
                            "  .{:<48} {:<10} {:<15} {:<15} {:<10}",
                            sig, "signal", "-", "-", "-"
                        );
                    }
                }
            } else if trimmed.starts_with("<property ") {
                if let Some(start) = trimmed.find("name=\"") {
                    let rest = &trimmed[start + 6..];
                    if let Some(end) = rest.find('"') {
                        let prop = &rest[..end];
                        let access = if trimmed.contains("access=\"readwrite\"") {
                            "readwrite"
                        } else if trimmed.contains("access=\"write\"") {
                            "write"
                        } else {
                            "read"
                        };
                        println!(
                            "  .{:<48} {:<10} {:<15} {:<15} {:<10}",
                            prop, "property", "-", "-", access
                        );
                    }
                }
            }
        }
    }
}

async fn cmd_call(
    conn: &Connection,
    service: &str,
    path: &str,
    interface: &str,
    method: &str,
    signature: Option<&str>,
    args: &[String],
) -> anyhow::Result<()> {
    let reply = if let Some(sig) = signature {
        match sig {
            "s" => {
                let arg0 = args.first().map_or("", String::as_str);
                conn.call_method(Some(service), path, Some(interface), method, &(arg0,))
                    .await?
            }
            "ss" => {
                let arg0 = args.first().map_or("", String::as_str);
                let arg1 = args.get(1).map_or("", String::as_str);
                conn.call_method(Some(service), path, Some(interface), method, &(arg0, arg1))
                    .await?
            }
            "b" => {
                let b = args.first().is_some_and(|s| s == "true" || s == "1");
                conn.call_method(Some(service), path, Some(interface), method, &(b,))
                    .await?
            }
            "u" => {
                let u: u32 = args.first().and_then(|s| s.parse().ok()).unwrap_or(0);
                conn.call_method(Some(service), path, Some(interface), method, &(u,))
                    .await?
            }
            "i" => {
                let i: i32 = args.first().and_then(|s| s.parse().ok()).unwrap_or(0);
                conn.call_method(Some(service), path, Some(interface), method, &(i,))
                    .await?
            }
            "as" => {
                let v: Vec<&str> = args.iter().map(String::as_str).collect();
                conn.call_method(Some(service), path, Some(interface), method, &(v,))
                    .await?
            }
            _ => {
                conn.call_method(Some(service), path, Some(interface), method, &())
                    .await?
            }
        }
    } else {
        conn.call_method(Some(service), path, Some(interface), method, &())
            .await?
    };

    println!("Call completed successfully.");
    let body_str = format!("{:?}", reply.body());
    if body_str != "Body([])" {
        println!("Return: {body_str}");
    }

    Ok(())
}

async fn cmd_get_property(
    conn: &Connection,
    service: &str,
    path: &str,
    interface: &str,
    properties: &[String],
) -> anyhow::Result<()> {
    let obj_path = ObjectPath::try_from(path)?;
    let props = PropertiesProxy::builder(conn)
        .destination(service)?
        .path(obj_path)?
        .build()
        .await?;

    let iface_name = InterfaceName::try_from(interface)?;

    if properties.is_empty() {
        let all = props.get_all(Some(iface_name).into()).await?;
        for (k, v) in all {
            println!("{k}: {v:?}");
        }
    } else {
        for prop in properties {
            match props.get(iface_name.as_ref(), prop.as_str()).await {
                Ok(val) => println!("{prop}: {val:?}"),
                Err(e) => eprintln!("{prop}: <error: {e}>"),
            }
        }
    }

    Ok(())
}

async fn cmd_set_property(
    conn: &Connection,
    service: &str,
    path: &str,
    interface: &str,
    property: &str,
    signature: &str,
    values: &[String],
) -> anyhow::Result<()> {
    let obj_path = ObjectPath::try_from(path)?;
    let props = PropertiesProxy::builder(conn)
        .destination(service)?
        .path(obj_path)?
        .build()
        .await?;

    let val = match signature {
        "s" => Value::from(values.first().map_or("", String::as_str)),
        "b" => Value::from(values.first().is_some_and(|v| v == "true" || v == "1")),
        "u" => Value::from(
            values
                .first()
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(0),
        ),
        "i" => Value::from(
            values
                .first()
                .and_then(|v| v.parse::<i32>().ok())
                .unwrap_or(0),
        ),
        _ => Value::from(values.first().map_or("", String::as_str)),
    };

    let iface_name = InterfaceName::try_from(interface)?;
    props.set(iface_name.as_ref(), property, &val).await?;
    println!("Property {property} set successfully.");
    Ok(())
}

fn resolve_uid_to_username(uid: u32) -> Option<String> {
    if uid == 0 {
        return Some("root".to_string());
    }
    if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 && parts[2] == uid.to_string() {
                return Some(parts[0].to_string());
            }
        }
    }
    Some(uid.to_string())
}

fn get_process_name(pid: u32) -> Option<String> {
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim().to_string())
}

fn get_process_cmdline(pid: u32) -> Option<String> {
    fs::read(format!("/proc/{pid}/cmdline")).ok().map(|bytes| {
        bytes
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s))
            .collect::<Vec<_>>()
            .join(" ")
    })
}

fn get_process_unit(pid: u32) -> Option<String> {
    if let Ok(cgroup) = fs::read_to_string(format!("/proc/{pid}/cgroup")) {
        for line in cgroup.lines() {
            if let Some(path) = line.split(':').nth(2) {
                let name = path.trim_start_matches('/');
                if !name.is_empty() {
                    return Some(name.to_string());
                }
            }
        }
    }
    None
}
