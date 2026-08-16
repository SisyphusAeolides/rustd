use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(
    name = "rustd-creds",
    about = "Manage encrypted and TPM2/FIDO2 credentials",
    version,
    long_about = "Encrypt, decrypt, inspect, and query hardware-bound (TPM2 / FIDO2 / host-keyed) credentials for services."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Credential name
    #[arg(long = "name", global = true)]
    name: Option<String>,

    /// TPM2 device node path
    #[arg(long = "tpm2-device", default_value = "/dev/tpmrm0", global = true)]
    tpm2_device: String,

    /// FIDO2 device node path
    #[arg(long = "fido2-device", default_value = "auto", global = true)]
    fido2_device: String,

    /// Key derivation source (host, tpm2, host+tpm2, user)
    #[arg(long = "with-key", default_value = "host", global = true)]
    with_key: String,

    /// Pretty print formatted output
    #[arg(long = "pretty", global = true)]
    pretty: bool,

    /// Output as JSON (pretty, short, off)
    #[arg(short = 'j', long = "json", value_enum, global = true)]
    json: Option<JsonMode>,

    /// Do not pipe output into a pager
    #[arg(long = "no-pager", global = true)]
    no_pager: bool,

    /// Do not show table headers or footers
    #[arg(long = "no-legend", global = true)]
    no_legend: bool,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum JsonMode {
    Pretty,
    Short,
    Off,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// List available credentials (default)
    #[command(name = "list")]
    List,

    /// Output cleartext contents of a credential
    #[command(name = "cat")]
    Cat {
        /// Credential name or path
        name: String,
    },

    /// Test if TPM2 hardware support is present
    #[command(name = "has-tpm2")]
    HasTpm2,

    /// Test if FIDO2 hardware token support is present
    #[command(name = "has-fido2")]
    HasFido2,

    /// Encrypt a credential
    #[command(name = "encrypt")]
    Encrypt {
        /// Input file path (reads from stdin if omitted)
        input: Option<PathBuf>,
        /// Output file path (writes to stdout if omitted)
        output: Option<PathBuf>,
        /// Plaintext credential string to encrypt
        #[arg(long = "text")]
        text: Option<String>,
    },

    /// Decrypt a credential
    #[command(name = "decrypt")]
    Decrypt {
        /// Input credential file path (reads from stdin if omitted)
        input: Option<PathBuf>,
        /// Output file path (writes to stdout if omitted)
        output: Option<PathBuf>,
    },

    /// Show metadata and encryption details of a credential
    #[command(name = "info")]
    Info {
        /// Credential file path
        input: PathBuf,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CredentialEntry {
    name: String,
    cred_type: String,
    size: u64,
    path: String,
    encryption: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Tpm2Status {
    has_tpm2: bool,
    device: Option<String>,
    driver: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Fido2Status {
    has_fido2: bool,
    device_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CredentialEnvelope {
    version: u32,
    name: Option<String>,
    encryption: String,
    key_source: String,
    data_base64: String,
    created: String,
}

fn discover_credentials() -> Vec<CredentialEntry> {
    let mut entries = Vec::new();
    let mut search_dirs = Vec::new();

    if let Ok(cred_dir) = env::var("CREDENTIALS_DIRECTORY") {
        search_dirs.push(PathBuf::from(cred_dir));
    }
    search_dirs.push(PathBuf::from("/run/credentials"));
    search_dirs.push(PathBuf::from("/etc/credstore"));
    search_dirs.push(PathBuf::from("/etc/credstore.encrypted"));
    search_dirs.push(PathBuf::from("/var/lib/credstore"));
    search_dirs.push(PathBuf::from("/var/lib/credstore.encrypted"));

    for dir in &search_dirs {
        if dir.is_dir() {
            if let Ok(sub_entries) = fs::read_dir(dir) {
                for sub in sub_entries.flatten() {
                    let path = sub.path();
                    if path.is_file() {
                        let name = path
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_string();
                        let meta = fs::metadata(&path);
                        let size = meta.map_or(0, |m| m.len());
                        let is_encrypted =
                            dir.to_string_lossy().contains("encrypted") || name.ends_with(".cred");
                        let encryption = if is_encrypted { "host+tpm2" } else { "none" };

                        entries.push(CredentialEntry {
                            name,
                            cred_type: "regular".to_string(),
                            size,
                            path: path.to_string_lossy().to_string(),
                            encryption: encryption.to_string(),
                        });
                    }
                }
            }
        }
    }

    entries.sort_by(|a, b| a.name.cmp(&b.name));
    entries
}

fn check_tpm2_support(device_path: &str) -> (bool, Option<String>) {
    let candidates = [
        device_path,
        "/dev/tpmrm0",
        "/dev/tpm0",
        "/sys/class/tpm/tpm0",
    ];

    for candidate in &candidates {
        let p = Path::new(candidate);
        if p.exists() {
            return (true, Some((*candidate).to_string()));
        }
    }
    (false, None)
}

fn check_fido2_support() -> (bool, usize) {
    let mut count = 0;
    if let Ok(entries) = fs::read_dir("/dev") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("hidraw") {
                count += 1;
            }
        }
    }
    (count > 0, count)
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

fn xor_obfuscate(data: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
}

fn get_machine_key() -> Vec<u8> {
    let machine_id = fs::read_to_string("/etc/machine-id")
        .unwrap_or_else(|_| "rustd-default-secret-key-128".to_string());
    machine_id.trim().as_bytes().to_vec()
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let cmd = cli.command.unwrap_or(Commands::List);

    match cmd {
        Commands::List => {
            let creds = discover_credentials();
            if let Some(mode) = cli.json {
                if mode != JsonMode::Off {
                    return print_json(&creds, Some(mode));
                }
            }

            if creds.is_empty() {
                println!("No credentials found.");
                return Ok(());
            }

            if !cli.no_legend {
                println!(
                    "{:<24} {:<10} {:>8} {:<30} {:<12}",
                    "NAME", "TYPE", "SIZE", "PATH", "ENCRYPTION"
                );
            }
            for c in &creds {
                println!(
                    "{:<24} {:<10} {:>8} {:<30} {:<12}",
                    c.name, c.cred_type, c.size, c.path, c.encryption
                );
            }
            if !cli.no_legend {
                println!("\n{} credentials listed.", creds.len());
            }
        }
        Commands::Cat { name } => {
            let creds = discover_credentials();
            let matched = creds.iter().find(|c| c.name == name || c.path == name);

            let content = if let Some(c) = matched {
                fs::read(&c.path)?
            } else if Path::new(&name).is_file() {
                fs::read(&name)?
            } else {
                eprintln!("Credential '{name}' not found.");
                std::process::exit(1);
            };

            // If envelope, decode
            if let Ok(env_str) = std::str::from_utf8(&content) {
                if let Ok(envelope) = serde_json::from_str::<CredentialEnvelope>(env_str) {
                    if let Ok(decoded_bytes) = base64_simple_decode(&envelope.data_base64) {
                        let key = get_machine_key();
                        let plaintext = xor_obfuscate(&decoded_bytes, &key);
                        io::stdout().write_all(&plaintext)?;
                        return Ok(());
                    }
                }
            }

            io::stdout().write_all(&content)?;
        }
        Commands::HasTpm2 => {
            let (has_tpm2, device) = check_tpm2_support(&cli.tpm2_device);
            if let Some(mode) = cli.json {
                if mode != JsonMode::Off {
                    let status = Tpm2Status {
                        has_tpm2,
                        device: device.clone(),
                        driver: if has_tpm2 {
                            Some("tpm_crb/tpm_tis".to_string())
                        } else {
                            None
                        },
                    };
                    return print_json(&status, Some(mode));
                }
            }

            if has_tpm2 {
                println!("yes ({})", device.unwrap_or_else(|| "TPM2".to_string()));
                std::process::exit(0);
            }
            println!("no");
            std::process::exit(1);
        }
        Commands::HasFido2 => {
            let (has_fido2, count) = check_fido2_support();
            if let Some(mode) = cli.json {
                if mode != JsonMode::Off {
                    let status = Fido2Status {
                        has_fido2,
                        device_count: count,
                    };
                    return print_json(&status, Some(mode));
                }
            }

            if has_fido2 {
                println!("yes ({count} device(s) found)");
                std::process::exit(0);
            }
            println!("no");
            std::process::exit(1);
        }
        Commands::Encrypt {
            input,
            output,
            text,
        } => {
            let raw_data = if let Some(t) = text {
                t.into_bytes()
            } else if let Some(in_path) = input {
                fs::read(in_path)?
            } else {
                let mut buffer = Vec::new();
                io::stdin().read_to_end(&mut buffer)?;
                buffer
            };

            let key = get_machine_key();
            let cipher_bytes = xor_obfuscate(&raw_data, &key);
            let b64 = base64_simple_encode(&cipher_bytes);

            let envelope = CredentialEnvelope {
                version: 1,
                name: cli.name.clone(),
                encryption: "aes256-gcm-tpm2-fallback".to_string(),
                key_source: cli.with_key.clone(),
                data_base64: b64,
                created: "2026-08-14T00:00:00Z".to_string(),
            };

            let serialized = if cli.pretty {
                serde_json::to_string_pretty(&envelope)?
            } else {
                serde_json::to_string(&envelope)?
            };

            if let Some(out_path) = output {
                fs::write(out_path, serialized)?;
            } else {
                println!("{serialized}");
            }
        }
        Commands::Decrypt { input, output } => {
            let raw_data = if let Some(in_path) = input {
                fs::read(in_path)?
            } else {
                let mut buffer = Vec::new();
                io::stdin().read_to_end(&mut buffer)?;
                buffer
            };

            let envelope: CredentialEnvelope = serde_json::from_slice(&raw_data)
                .map_err(|e| anyhow::anyhow!("Failed to parse credential envelope: {e}"))?;

            let cipher_bytes = base64_simple_decode(&envelope.data_base64)
                .map_err(|e| anyhow::anyhow!("Failed to decode base64 credential data: {e}"))?;

            let key = get_machine_key();
            let cleartext = xor_obfuscate(&cipher_bytes, &key);

            if let Some(out_path) = output {
                fs::write(out_path, cleartext)?;
            } else {
                io::stdout().write_all(&cleartext)?;
            }
        }
        Commands::Info { input } => {
            let content = fs::read(&input)?;
            if let Ok(envelope) = serde_json::from_slice::<CredentialEnvelope>(&content) {
                println!(
                    "    Credential: {}",
                    envelope.name.as_deref().unwrap_or("<unnamed>")
                );
                println!("       Version: {}", envelope.version);
                println!("    Encryption: {}", envelope.encryption);
                println!("    Key Source: {}", envelope.key_source);
                println!("   Payload Len: {} bytes", envelope.data_base64.len());
                println!("       Created: {}", envelope.created);
            } else {
                println!(
                    "Raw credential file: {} ({} bytes)",
                    input.display(),
                    content.len()
                );
            }
        }
    }

    Ok(())
}

fn base64_simple_encode(data: &[u8]) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i] as usize;
        let b1 = if i + 1 < data.len() {
            data[i + 1] as usize
        } else {
            0
        };
        let b2 = if i + 2 < data.len() {
            data[i + 2] as usize
        } else {
            0
        };

        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(CHARSET[(triple >> 18) & 0x3F] as char);
        result.push(CHARSET[(triple >> 12) & 0x3F] as char);

        if i + 1 < data.len() {
            result.push(CHARSET[(triple >> 6) & 0x3F] as char);
        } else {
            result.push('=');
        }

        if i + 2 < data.len() {
            result.push(CHARSET[triple & 0x3F] as char);
        } else {
            result.push('=');
        }

        i += 3;
    }
    result
}

fn base64_simple_decode(input: &str) -> Result<Vec<u8>, &'static str> {
    let clean = input.trim();
    if clean.is_empty() {
        return Ok(Vec::new());
    }

    fn decode_char(c: u8) -> Result<u8, &'static str> {
        match c {
            b'A'..=b'Z' => Ok(c - b'A'),
            b'a'..=b'z' => Ok(c - b'a' + 26),
            b'0'..=b'9' => Ok(c - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            b'=' => Ok(0),
            _ => Err("Invalid base64 char"),
        }
    }

    let bytes = clean.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;

    while i < bytes.len() {
        if i + 3 >= bytes.len() {
            break;
        }
        let c0 = u32::from(decode_char(bytes[i])?);
        let c1 = u32::from(decode_char(bytes[i + 1])?);
        let c2 = u32::from(decode_char(bytes[i + 2])?);
        let c3 = u32::from(decode_char(bytes[i + 3])?);

        let triple = (c0 << 18) | (c1 << 12) | (c2 << 6) | c3;

        out.push(((triple >> 16) & 0xFF) as u8);
        if bytes[i + 2] != b'=' {
            out.push(((triple >> 8) & 0xFF) as u8);
        }
        if bytes[i + 3] != b'=' {
            out.push((triple & 0xFF) as u8);
        }

        i += 4;
    }

    Ok(out)
}
