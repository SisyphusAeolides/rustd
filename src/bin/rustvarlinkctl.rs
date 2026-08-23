// SPDX-License-Identifier: LGPL-2.1-or-later
//! rustvarlinkctl — Introspect and invoke Varlink services.
//!
//! Upstream counterpart: systemd varlinkctl (v261)

use std::collections::BTreeSet;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Parser, Debug)]
#[command(
    name = "rustvarlinkctl",
    version = "261",
    about = "Introspect and invoke Varlink services",
    long_about = "A compatibility-oriented Varlink IPC introspection, schema inspection, and method invocation utility."
)]
struct Cli {
    /// Output formatting mode
    #[arg(long, short = 'j', value_enum, default_value_t = JsonMode::Off)]
    json: JsonMode,

    /// Collect multiple method call replies
    #[arg(long, short = 'm')]
    more: bool,

    /// Do not pipe output into a pager
    #[arg(long)]
    no_pager: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum JsonMode {
    Off,
    Pretty,
    Short,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    /// Show Varlink service information and available interfaces
    Info {
        /// Varlink service address (e.g. <unix:/run/systemd/userdb/io.systemd.Home> or /run/...)
        address: String,
    },

    /// List interface names provided by a Varlink service
    ListInterfaces {
        /// Varlink service address
        address: String,
    },

    /// Print the Varlink IDL interface definition
    Introspect {
        /// Varlink service address
        address: String,

        /// Interface name to introspect (e.g. org.varlink.service or io.systemd.UserDatabase)
        interface: String,
    },

    /// Call a Varlink method with JSON arguments
    Call {
        /// Varlink service address
        address: String,

        /// Method name (e.g. io.systemd.UserDatabase.GetUserRecord)
        method: String,

        /// Method arguments formatted as JSON object (e.g. '{"userName": "root"}')
        arguments: Option<String>,

        /// Collect multiple replies
        #[arg(long, short = 'm')]
        more: bool,

        /// One-way method call without waiting for reply
        #[arg(long)]
        oneway: bool,
    },

    /// Parse and validate a Varlink IDL schema file
    ValidateIdl {
        /// Path to IDL file (or stdin if omitted)
        file: Option<PathBuf>,
    },
}

#[derive(Serialize, Deserialize, Debug)]
struct VarlinkRequest {
    method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parameters: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    more: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    oneway: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug)]
#[allow(dead_code)]
struct VarlinkResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    parameters: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    continues: Option<bool>,
}

#[derive(Deserialize, Debug)]
struct ServiceInfo {
    vendor: Option<String>,
    product: Option<String>,
    version: Option<String>,
    url: Option<String>,
    interfaces: Option<Vec<String>>,
}

enum VarlinkTransport {
    Unix(UnixStream),
    ChildProcess(std::process::ChildStdin, std::process::ChildStdout),
}

impl VarlinkTransport {
    fn connect(address: &str) -> anyhow::Result<Self> {
        let clean_addr = address.trim();
        if clean_addr.starts_with("exec:") {
            let cmd_str = clean_addr.trim_start_matches("exec:").trim();
            let parts: Vec<&str> = cmd_str.split_whitespace().collect();
            if parts.is_empty() {
                anyhow::bail!("Empty exec command in address");
            }
            let mut child = Command::new(parts[0])
                .args(&parts[1..])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .map_err(|e| anyhow::anyhow!("Failed to spawn exec process '{}': {e}", parts[0]))?;
            let stdin = child
                .stdin
                .take()
                .ok_or_else(|| anyhow::anyhow!("Failed to open child stdin"))?;
            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| anyhow::anyhow!("Failed to open child stdout"))?;
            Ok(Self::ChildProcess(stdin, stdout))
        } else {
            let socket_path = if clean_addr.starts_with("unix:") {
                clean_addr.trim_start_matches("unix:")
            } else {
                clean_addr
            };

            let stream = UnixStream::connect(socket_path).map_err(|e| {
                anyhow::anyhow!("Failed to connect to Varlink socket '{socket_path}': {e}")
            })?;
            let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
            Ok(Self::Unix(stream))
        }
    }

    fn send_request(&mut self, req: &VarlinkRequest) -> anyhow::Result<()> {
        let mut bytes = serde_json::to_vec(req)?;
        bytes.push(0); // NUL delimiter

        match self {
            Self::Unix(stream) => {
                stream.write_all(&bytes)?;
                stream.flush()?;
            }
            Self::ChildProcess(stdin, _) => {
                stdin.write_all(&bytes)?;
                stdin.flush()?;
            }
        }
        Ok(())
    }

    fn read_message(&mut self) -> anyhow::Result<Value> {
        let mut buf = Vec::new();
        match self {
            Self::Unix(stream) => {
                let mut reader = BufReader::new(stream);
                reader.read_until(0, &mut buf)?;
            }
            Self::ChildProcess(_, stdout) => {
                let mut reader = BufReader::new(stdout);
                reader.read_until(0, &mut buf)?;
            }
        }

        if buf.is_empty() {
            anyhow::bail!("Connection closed by remote peer without response");
        }
        if buf.last() == Some(&0) {
            buf.pop();
        }

        let val: Value = serde_json::from_slice(&buf)
            .map_err(|e| anyhow::anyhow!("Failed to parse Varlink JSON reply: {e}"))?;
        Ok(val)
    }
}

fn main() {
    let cli = Cli::parse();

    if let Err(err) = run(cli) {
        eprintln!("varlinkctl error: {err}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Commands::Info { address } => {
            cmd_info(&address, cli.json)?;
        }
        Commands::ListInterfaces { address } => {
            cmd_list_interfaces(&address, cli.json)?;
        }
        Commands::Introspect { address, interface } => {
            cmd_introspect(&address, &interface, cli.json)?;
        }
        Commands::Call {
            address,
            method,
            arguments,
            more,
            oneway,
        } => {
            cmd_call(
                &address,
                &method,
                arguments.as_deref(),
                more || cli.more,
                oneway,
                cli.json,
            )?;
        }
        Commands::ValidateIdl { file } => {
            cmd_validate_idl(file.as_deref())?;
        }
    }

    Ok(())
}

fn cmd_info(address: &str, json_mode: JsonMode) -> anyhow::Result<()> {
    let mut transport = VarlinkTransport::connect(address)?;
    let req = VarlinkRequest {
        method: "org.varlink.service.GetInfo".to_string(),
        parameters: Some(serde_json::json!({})),
        more: None,
        oneway: None,
    };

    transport.send_request(&req)?;
    let reply = transport.read_message()?;

    if let Some(err) = reply.get("error") {
        anyhow::bail!("Varlink error returned: {err}");
    }

    let params = reply.get("parameters").cloned().unwrap_or(Value::Null);

    if json_mode != JsonMode::Off {
        match json_mode {
            JsonMode::Pretty => println!("{}", serde_json::to_string_pretty(&params)?),
            JsonMode::Short => println!("{}", serde_json::to_string(&params)?),
            JsonMode::Off => {}
        }
        return Ok(());
    }

    let info: ServiceInfo = serde_json::from_value(params)?;
    if let Some(v) = info.vendor {
        println!("     Vendor: {v}");
    }
    if let Some(p) = info.product {
        println!("    Product: {p}");
    }
    if let Some(ver) = info.version {
        println!("    Version: {ver}");
    }
    if let Some(u) = info.url {
        println!("        URL: {u}");
    }
    if let Some(ifaces) = info.interfaces {
        println!(" Interfaces:");
        for iface in ifaces {
            println!("   {iface}");
        }
    }

    Ok(())
}

fn cmd_list_interfaces(address: &str, json_mode: JsonMode) -> anyhow::Result<()> {
    let mut transport = VarlinkTransport::connect(address)?;
    let req = VarlinkRequest {
        method: "org.varlink.service.GetInfo".to_string(),
        parameters: Some(serde_json::json!({})),
        more: None,
        oneway: None,
    };

    transport.send_request(&req)?;
    let reply = transport.read_message()?;

    if let Some(err) = reply.get("error") {
        anyhow::bail!("Varlink error returned: {err}");
    }

    let params = reply.get("parameters").cloned().unwrap_or(Value::Null);
    let info: ServiceInfo = serde_json::from_value(params)?;
    let interfaces = info.interfaces.unwrap_or_default();

    if json_mode != JsonMode::Off {
        match json_mode {
            JsonMode::Pretty => println!("{}", serde_json::to_string_pretty(&interfaces)?),
            JsonMode::Short => println!("{}", serde_json::to_string(&interfaces)?),
            JsonMode::Off => {}
        }
        return Ok(());
    }

    for iface in interfaces {
        println!("{iface}");
    }

    Ok(())
}

fn cmd_introspect(address: &str, interface: &str, json_mode: JsonMode) -> anyhow::Result<()> {
    let mut transport = VarlinkTransport::connect(address)?;
    let req = VarlinkRequest {
        method: "org.varlink.service.GetInterfaceDescription".to_string(),
        parameters: Some(serde_json::json!({
            "interface": interface
        })),
        more: None,
        oneway: None,
    };

    transport.send_request(&req)?;
    let reply = transport.read_message()?;

    if let Some(err) = reply.get("error") {
        anyhow::bail!("Varlink error returned: {err}");
    }

    let description = reply
        .get("parameters")
        .and_then(|p| p.get("description"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            anyhow::anyhow!("Missing 'description' parameter in GetInterfaceDescription reply")
        })?;

    if json_mode != JsonMode::Off {
        let val = serde_json::json!({
            "interface": interface,
            "description": description
        });
        match json_mode {
            JsonMode::Pretty => println!("{}", serde_json::to_string_pretty(&val)?),
            JsonMode::Short => println!("{}", serde_json::to_string(&val)?),
            JsonMode::Off => {}
        }
        return Ok(());
    }

    println!("{description}");
    Ok(())
}

fn cmd_call(
    address: &str,
    method: &str,
    arguments_json: Option<&str>,
    more: bool,
    oneway: bool,
    json_mode: JsonMode,
) -> anyhow::Result<()> {
    let params: Value = if let Some(arg_str) = arguments_json {
        serde_json::from_str(arg_str)
            .map_err(|e| anyhow::anyhow!("Invalid arguments JSON '{arg_str}': {e}"))?
    } else {
        serde_json::json!({})
    };

    let mut transport = VarlinkTransport::connect(address)?;
    let req = VarlinkRequest {
        method: method.to_string(),
        parameters: Some(params),
        more: if more { Some(true) } else { None },
        oneway: if oneway { Some(true) } else { None },
    };

    transport.send_request(&req)?;

    if oneway {
        return Ok(());
    }

    loop {
        let reply = transport.read_message()?;

        let continues = reply
            .get("continues")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        if json_mode == JsonMode::Short {
            println!("{}", serde_json::to_string(&reply)?);
        } else {
            println!("{}", serde_json::to_string_pretty(&reply)?);
        }

        if !more || !continues {
            break;
        }
    }

    Ok(())
}

fn cmd_validate_idl(file: Option<&Path>) -> anyhow::Result<()> {
    let content = match file {
        Some(path) => fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read IDL file '{}': {e}", path.display()))?,
        None => {
            let mut input = String::new();
            std::io::stdin()
                .read_to_string(&mut input)
                .map_err(|e| anyhow::anyhow!("Failed to read IDL from stdin: {e}"))?;
            input
        }
    };

    let result = parse_and_validate_idl(&content)?;
    println!("Valid Varlink IDL interface: {result}");
    Ok(())
}

fn parse_and_validate_idl(idl: &str) -> anyhow::Result<String> {
    let mut interface_name = None;
    let mut open_paren = 0;
    let mut open_brace = 0;
    let mut open_bracket = 0;
    let mut declared_symbols = BTreeSet::new();

    for (line_num, raw_line) in idl.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        for ch in line.chars() {
            match ch {
                '(' => open_paren += 1,
                ')' => {
                    if open_paren == 0 {
                        anyhow::bail!("Unmatched ')' at line {}", line_num + 1);
                    }
                    open_paren -= 1;
                }
                '{' => open_brace += 1,
                '}' => {
                    if open_brace == 0 {
                        anyhow::bail!("Unmatched '}}' at line {}", line_num + 1);
                    }
                    open_brace -= 1;
                }
                '[' => open_bracket += 1,
                ']' => {
                    if open_bracket == 0 {
                        anyhow::bail!("Unmatched ']' at line {}", line_num + 1);
                    }
                    open_bracket -= 1;
                }
                _ => {}
            }
        }

        if line.starts_with("interface ") {
            let name = line.trim_start_matches("interface ").trim();
            if name.is_empty() {
                anyhow::bail!("Empty interface name at line {}", line_num + 1);
            }
            interface_name = Some(name.to_string());
        } else if line.starts_with("type ") {
            let rest = line.trim_start_matches("type ").trim();
            if let Some(ident) = rest.split([' ', '(', '{']).next() {
                if !ident.is_empty() {
                    declared_symbols.insert(ident.to_string());
                }
            }
        } else if line.starts_with("method ") {
            let rest = line.trim_start_matches("method ").trim();
            if let Some(ident) = rest.split([' ', '(', '{']).next() {
                if !ident.is_empty() {
                    declared_symbols.insert(ident.to_string());
                }
            }
        } else if line.starts_with("error ") {
            let rest = line.trim_start_matches("error ").trim();
            if let Some(ident) = rest.split([' ', '(', '{']).next() {
                if !ident.is_empty() {
                    declared_symbols.insert(ident.to_string());
                }
            }
        }
    }

    if open_paren != 0 {
        anyhow::bail!("Unclosed '(' in Varlink IDL");
    }
    if open_brace != 0 {
        anyhow::bail!("Unclosed '{{' in Varlink IDL");
    }
    if open_bracket != 0 {
        anyhow::bail!("Unclosed '[' in Varlink IDL");
    }

    let iface = interface_name.ok_or_else(|| {
        anyhow::anyhow!("Varlink IDL schema must contain an 'interface <name>' declaration")
    })?;

    Ok(iface)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_varlink_idl() {
        let idl = r"
        # Example Varlink IDL
        interface org.example.UserDatabase

        type User (
            name: string,
            uid: int,
            home: ?string
        )

        method GetUser(name: string) -> (user: User)
        error UserNotFound (name: string)
        ";

        let res = parse_and_validate_idl(idl);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), "org.example.UserDatabase");
    }

    #[test]
    fn test_unmatched_brace_idl() {
        let idl = r"
        interface org.example.Bad
        type User (
            name: string
        ";
        let res = parse_and_validate_idl(idl);
        assert!(res.is_err());
    }
}
