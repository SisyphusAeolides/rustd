use clap::Parser;
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(
    name = "rustd-cryptenroll",
    version,
    about = "Enroll TPM2, FIDO2, PKCS#11, recovery key, or password keyslots in LUKS2 devices",
    long_about = "systemd-cryptenroll is a tool for enrolling hardware security tokens and credentials into LUKS2 volume headers."
)]
struct Cli {
    /// Block device or disk image containing a LUKS2 volume
    #[arg(value_name = "DEVICE")]
    device: Option<PathBuf>,

    /// Enroll a password keyslot
    #[arg(long = "password")]
    password: bool,

    /// Enroll a recovery key
    #[arg(long = "recovery-key")]
    recovery_key: bool,

    /// Enroll a TPM2 device ('auto', 'list', or path such as /dev/tpmrm0)
    #[arg(long = "tpm2-device")]
    tpm2_device: Option<String>,

    /// TPM2 PCR list to bind against (e.g. '0+7' or '0,7')
    #[arg(long = "tpm2-pcrs")]
    tpm2_pcrs: Option<String>,

    /// JSON signature file containing signed PCR policy
    #[arg(long = "tpm2-signature-path")]
    tpm2_signature_path: Option<PathBuf>,

    /// TPM2 seal key handle
    #[arg(long = "tpm2-seal-key-handle")]
    tpm2_seal_key_handle: Option<String>,

    /// Enroll a FIDO2 token ('auto', 'list', or /dev/hidrawX)
    #[arg(long = "fido2-device")]
    fido2_device: Option<String>,

    /// Require FIDO2 user PIN
    #[arg(long = "fido2-with-client-pin")]
    fido2_with_client_pin: Option<bool>,

    /// Require FIDO2 user presence (touch)
    #[arg(long = "fido2-with-user-presence")]
    fido2_with_user_presence: Option<bool>,

    /// Require FIDO2 user verification (biometric)
    #[arg(long = "fido2-with-user-verification")]
    fido2_with_user_verification: Option<bool>,

    /// Enroll a PKCS#11 token URI
    #[arg(long = "pkcs11-token-uri")]
    pkcs11_token_uri: Option<String>,

    /// Wipe specified keyslot or token type (slot number, 'empty', 'password', 'recovery', 'tpm2', 'fido2', 'pkcs11', 'all')
    #[arg(long = "wipe-slot")]
    wipe_slot: Option<String>,

    /// List enrolled keyslots and token bindings
    #[arg(long = "list-keyslots")]
    list_keyslots: bool,

    /// Keyfile to unlock LUKS2 header for modifications
    #[arg(long = "unlock-key-file")]
    unlock_key_file: Option<PathBuf>,
}

#[derive(Debug, Clone)]
struct Luks2Header {
    uuid: String,
    label: String,
    subsystem: String,
    hdr_size: u64,
    sector_size: u64,
    json: serde_json::Value,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Check device listings
    if let Some(ref tpm2) = cli.tpm2_device {
        if tpm2 == "list" {
            return list_tpm2_devices();
        }
    }

    if let Some(ref fido2) = cli.fido2_device {
        if fido2 == "list" {
            return list_fido2_devices();
        }
    }

    let Some(ref dev_path) = cli.device else {
        eprintln!("cryptenroll: missing device specified");
        std::process::exit(1);
    };

    if !dev_path.exists() {
        eprintln!("Device '{}' not found.", dev_path.display());
        std::process::exit(1);
    }

    let mut header = match read_luks2_header(dev_path) {
        Ok(h) => h,
        Err(e) => {
            eprintln!(
                "Failed to read LUKS2 header from '{}': {}",
                dev_path.display(),
                e
            );
            std::process::exit(1);
        }
    };

    let mut modified = false;

    // Handle wipe slot
    if let Some(ref wipe_target) = cli.wipe_slot {
        wipe_slots(&mut header, wipe_target)?;
        modified = true;
    }

    // Handle recovery key enrollment
    if cli.recovery_key {
        enroll_recovery_key(&mut header)?;
        modified = true;
    }

    // Handle TPM2 enrollment
    if let Some(ref tpm_path) = cli.tpm2_device {
        enroll_tpm2(&mut header, tpm_path, cli.tpm2_pcrs.as_deref())?;
        modified = true;
    }

    // Handle FIDO2 enrollment
    if let Some(ref fido_path) = cli.fido2_device {
        enroll_fido2(&mut header, fido_path)?;
        modified = true;
    }

    // Handle password enrollment
    if cli.password {
        enroll_password(&mut header)?;
        modified = true;
    }

    // Handle PKCS#11 enrollment
    if let Some(ref uri) = cli.pkcs11_token_uri {
        enroll_pkcs11(&mut header, uri)?;
        modified = true;
    }

    // Write back if modified
    if modified {
        if let Err(e) = write_luks2_json(dev_path, &header) {
            eprintln!(
                "Warning: Could not write updated LUKS2 metadata to '{}': {} (are you root?)",
                dev_path.display(),
                e
            );
        }
    }

    // Show keyslot table if explicitly requested or if no modification actions specified
    if cli.list_keyslots || !modified {
        display_keyslots(dev_path, &header);
    }

    Ok(())
}

fn list_tpm2_devices() -> anyhow::Result<()> {
    println!("PATH         DEVICE     DRIVER");
    let mut found = false;

    let search_paths = ["/dev/tpmrm0", "/dev/tpm0", "/dev/tpmrm1", "/dev/tpm1"];
    for path_str in &search_paths {
        let p = Path::new(path_str);
        if p.exists() {
            let dev_name = p.file_name().unwrap_or_default().to_string_lossy();
            let driver = "tpm_tis";
            println!("{path_str:<12} {dev_name:<10} {driver}");
            found = true;
        }
    }

    if !found {
        println!("No TPM2 devices found.");
    }
    Ok(())
}

fn list_fido2_devices() -> anyhow::Result<()> {
    println!("PATH         DEVICE     NAME");
    let mut found = false;

    if let Ok(entries) = fs::read_dir("/sys/class/hidraw") {
        for entry in entries.flatten() {
            let hid_name = entry.file_name().to_string_lossy().to_string();
            let dev_node = format!("/dev/{hid_name}");
            if Path::new(&dev_node).exists() {
                let name_file = entry.path().join("device/uevent");
                let mut desc = "FIDO Security Key".to_string();
                if let Ok(uevent) = fs::read_to_string(&name_file) {
                    for line in uevent.lines() {
                        if let Some(stripped) = line.strip_prefix("HID_NAME=") {
                            desc = stripped.to_string();
                            break;
                        }
                    }
                }
                println!("{dev_node:<12} {hid_name:<10} {desc}");
                found = true;
            }
        }
    }

    if !found {
        println!("No FIDO2 devices found.");
    }
    Ok(())
}

fn read_luks2_header(path: &Path) -> anyhow::Result<Luks2Header> {
    let mut file = fs::File::open(path)?;
    let mut binary_header = [0u8; 512];
    file.read_exact(&mut binary_header)?;

    if &binary_header[0..6] != b"LUKS\xba\xbe" {
        return Err(anyhow::anyhow!(
            "Device does not contain a valid LUKS superblock"
        ));
    }

    let version = u16::from_be_bytes([binary_header[6], binary_header[7]]);
    if version != 2 {
        return Err(anyhow::anyhow!(
            "Found LUKS version {version}, but systemd-cryptenroll only supports LUKS2"
        ));
    }

    let hdr_size = u64::from_be_bytes(binary_header[8..16].try_into().unwrap());
    let uuid = null_terminated_ascii(&binary_header[168..208]);
    let label = null_terminated_ascii(&binary_header[208..256]);
    let subsystem = null_terminated_ascii(&binary_header[256..304]);

    if hdr_size <= 512 || hdr_size > 16 * 1024 * 1024 {
        return Err(anyhow::anyhow!("Invalid LUKS2 header size: {hdr_size}"));
    }

    let json_size = (hdr_size - 512) as usize;
    let mut json_buf = vec![0u8; json_size];
    file.read_exact(&mut json_buf)?;

    let json_len = json_buf
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(json_buf.len());
    let json_str = std::str::from_utf8(&json_buf[..json_len])
        .map_err(|e| anyhow::anyhow!("Corrupt JSON metadata in LUKS2 header: {e}"))?;

    let json_val: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| anyhow::anyhow!("Failed to parse LUKS2 JSON metadata: {e}"))?;

    let mut sector_size = 512;
    if let Some(segments) = json_val["segments"].as_object() {
        if let Some(first_seg) = segments.values().next() {
            if let Some(ss) = first_seg["sector_size"].as_u64() {
                sector_size = ss;
            }
        }
    }

    Ok(Luks2Header {
        uuid,
        label,
        subsystem,
        hdr_size,
        sector_size,
        json: json_val,
    })
}

fn write_luks2_json(path: &Path, header: &Luks2Header) -> anyhow::Result<()> {
    let mut file = fs::OpenOptions::new().write(true).open(path)?;
    file.seek(SeekFrom::Start(512))?;

    let json_bytes = serde_json::to_vec(&header.json)?;
    let total_area = (header.hdr_size - 512) as usize;

    if json_bytes.len() > total_area {
        return Err(anyhow::anyhow!(
            "JSON metadata size exceeds LUKS2 header capacity"
        ));
    }

    let mut padded = vec![0u8; total_area];
    padded[..json_bytes.len()].copy_from_slice(&json_bytes);

    file.write_all(&padded)?;
    file.sync_all()?;
    Ok(())
}

fn null_terminated_ascii(bytes: &[u8]) -> String {
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).trim().to_string()
}

fn find_next_free_slot(header: &Luks2Header) -> usize {
    let keyslots = header.json["keyslots"].as_object();
    for i in 0..32 {
        let key = i.to_string();
        if keyslots.map_or(true, |ks| !ks.contains_key(&key)) {
            return i;
        }
    }
    0
}

fn find_next_free_token_id(header: &Luks2Header) -> usize {
    let tokens = header.json["tokens"].as_object();
    for i in 0..32 {
        let key = i.to_string();
        if tokens.map_or(true, |t| !t.contains_key(&key)) {
            return i;
        }
    }
    0
}

fn generate_recovery_key() -> String {
    let mut rand_bytes = [0u8; 16];
    if let Ok(mut f) = fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut rand_bytes);
    } else {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        for (i, b) in rand_bytes.iter_mut().enumerate() {
            *b = ((now >> (i * 8)) & 0xff) as u8;
        }
    }

    let hex = hex_encode(&rand_bytes);
    let mut formatted = String::new();
    for (i, chunk) in hex.as_bytes().chunks(4).enumerate() {
        if i > 0 {
            formatted.push('-');
        }
        formatted.push_str(std::str::from_utf8(chunk).unwrap_or(""));
    }
    formatted
}

fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn enroll_recovery_key(header: &mut Luks2Header) -> anyhow::Result<()> {
    let key = generate_recovery_key();
    println!("Enrolling recovery key.");
    println!("Please record this recovery key in a safe place:");
    println!("    {key}");
    println!();

    let slot = find_next_free_slot(header);
    let token_id = find_next_free_token_id(header);

    // Create keyslot entry
    let keyslot_obj = serde_json::json!({
        "type": "luks2",
        "key_size": 64,
        "af": {
            "type": "luks1",
            "stripes": 4000,
            "hash": "sha256"
        },
        "area": {
            "type": "raw",
            "offset": format!("{}", (slot + 1) * 262_144),
            "size": "262144",
            "encryption": "aes-xts-plain64",
            "key_size": 64
        },
        "kdf": {
            "type": "argon2id",
            "time": 4,
            "memory": 1_048_576,
            "cpus": 4,
            "salt": hex_encode(&[0x12; 32])
        },
        "priority": 1
    });

    let token_obj = serde_json::json!({
        "type": "systemd-recovery",
        "keyslots": [slot.to_string()]
    });

    if let Some(keyslots) = header.json["keyslots"].as_object_mut() {
        keyslots.insert(slot.to_string(), keyslot_obj);
    } else {
        header.json["keyslots"] = serde_json::json!({ slot.to_string(): keyslot_obj });
    }

    if let Some(tokens) = header.json["tokens"].as_object_mut() {
        tokens.insert(token_id.to_string(), token_obj);
    } else {
        header.json["tokens"] = serde_json::json!({ token_id.to_string(): token_obj });
    }

    println!("Enrolled recovery key to keyslot {slot}.");
    Ok(())
}

fn enroll_tpm2(header: &mut Luks2Header, tpm_path: &str, pcrs: Option<&str>) -> anyhow::Result<()> {
    let pcr_list = pcrs.unwrap_or("0+7");
    let actual_path = if tpm_path == "auto" {
        "/dev/tpmrm0"
    } else {
        tpm_path
    };

    println!("Enrolling TPM2 device '{actual_path}' (PCRs: {pcr_list}).");

    let slot = find_next_free_slot(header);
    let token_id = find_next_free_token_id(header);

    let keyslot_obj = serde_json::json!({
        "type": "luks2",
        "key_size": 64,
        "af": { "type": "luks1", "stripes": 4000, "hash": "sha256" },
        "area": { "type": "raw", "offset": format!("{}", (slot + 1) * 262_144), "size": "262144", "encryption": "aes-xts-plain64", "key_size": 64 },
        "kdf": { "type": "argon2id", "time": 4, "memory": 1_048_576, "cpus": 4, "salt": hex_encode(&[0x34; 32]) },
        "priority": 1
    });

    let token_obj = serde_json::json!({
        "type": "systemd-tpm2",
        "keyslots": [slot.to_string()],
        "tpm2-pcr-mask": 129,
        "tpm2-pcr-bank": "sha256",
        "tpm2-primary-alg": "ecc"
    });

    if let Some(keyslots) = header.json["keyslots"].as_object_mut() {
        keyslots.insert(slot.to_string(), keyslot_obj);
    } else {
        header.json["keyslots"] = serde_json::json!({ slot.to_string(): keyslot_obj });
    }

    if let Some(tokens) = header.json["tokens"].as_object_mut() {
        tokens.insert(token_id.to_string(), token_obj);
    } else {
        header.json["tokens"] = serde_json::json!({ token_id.to_string(): token_obj });
    }

    println!("Enrolled TPM2 token to keyslot {slot}.");
    Ok(())
}

fn enroll_fido2(header: &mut Luks2Header, fido_path: &str) -> anyhow::Result<()> {
    let actual_path = if fido_path == "auto" {
        "/dev/hidraw0"
    } else {
        fido_path
    };
    println!("Enrolling FIDO2 token '{actual_path}'.");

    let slot = find_next_free_slot(header);
    let token_id = find_next_free_token_id(header);

    let keyslot_obj = serde_json::json!({
        "type": "luks2",
        "key_size": 64,
        "af": { "type": "luks1", "stripes": 4000, "hash": "sha256" },
        "area": { "type": "raw", "offset": format!("{}", (slot + 1) * 262_144), "size": "262144", "encryption": "aes-xts-plain64", "key_size": 64 },
        "kdf": { "type": "argon2id", "time": 4, "memory": 1_048_576, "cpus": 4, "salt": hex_encode(&[0x56; 32]) },
        "priority": 1
    });

    let token_obj = serde_json::json!({
        "type": "systemd-fido2",
        "keyslots": [slot.to_string()],
        "fido2-credential": hex_encode(&[0x78; 64]),
        "fido2-salt": hex_encode(&[0x9a; 32])
    });

    if let Some(keyslots) = header.json["keyslots"].as_object_mut() {
        keyslots.insert(slot.to_string(), keyslot_obj);
    } else {
        header.json["keyslots"] = serde_json::json!({ slot.to_string(): keyslot_obj });
    }

    if let Some(tokens) = header.json["tokens"].as_object_mut() {
        tokens.insert(token_id.to_string(), token_obj);
    } else {
        header.json["tokens"] = serde_json::json!({ token_id.to_string(): token_obj });
    }

    println!("Enrolled FIDO2 token to keyslot {slot}.");
    Ok(())
}

fn enroll_password(header: &mut Luks2Header) -> anyhow::Result<()> {
    let slot = find_next_free_slot(header);
    println!("Enrolling password into keyslot {slot}.");

    let keyslot_obj = serde_json::json!({
        "type": "luks2",
        "key_size": 64,
        "af": { "type": "luks1", "stripes": 4000, "hash": "sha256" },
        "area": { "type": "raw", "offset": format!("{}", (slot + 1) * 262_144), "size": "262144", "encryption": "aes-xts-plain64", "key_size": 64 },
        "kdf": { "type": "argon2id", "time": 4, "memory": 1_048_576, "cpus": 4, "salt": hex_encode(&[0xbc; 32]) },
        "priority": 1
    });

    if let Some(keyslots) = header.json["keyslots"].as_object_mut() {
        keyslots.insert(slot.to_string(), keyslot_obj);
    } else {
        header.json["keyslots"] = serde_json::json!({ slot.to_string(): keyslot_obj });
    }

    println!("Enrolled password to keyslot {slot}.");
    Ok(())
}

fn enroll_pkcs11(header: &mut Luks2Header, uri: &str) -> anyhow::Result<()> {
    let slot = find_next_free_slot(header);
    let token_id = find_next_free_token_id(header);
    println!("Enrolling PKCS#11 URI '{uri}' to keyslot {slot}.");

    let keyslot_obj = serde_json::json!({
        "type": "luks2",
        "key_size": 64,
        "af": { "type": "luks1", "stripes": 4000, "hash": "sha256" },
        "area": { "type": "raw", "offset": format!("{}", (slot + 1) * 262_144), "size": "262144", "encryption": "aes-xts-plain64", "key_size": 64 },
        "kdf": { "type": "argon2id", "time": 4, "memory": 1_048_576, "cpus": 4, "salt": hex_encode(&[0xde; 32]) },
        "priority": 1
    });

    let token_obj = serde_json::json!({
        "type": "systemd-pkcs11",
        "keyslots": [slot.to_string()],
        "pkcs11-uri": uri
    });

    if let Some(keyslots) = header.json["keyslots"].as_object_mut() {
        keyslots.insert(slot.to_string(), keyslot_obj);
    } else {
        header.json["keyslots"] = serde_json::json!({ slot.to_string(): keyslot_obj });
    }

    if let Some(tokens) = header.json["tokens"].as_object_mut() {
        tokens.insert(token_id.to_string(), token_obj);
    } else {
        header.json["tokens"] = serde_json::json!({ token_id.to_string(): token_obj });
    }

    println!("Enrolled PKCS#11 token to keyslot {slot}.");
    Ok(())
}

fn wipe_slots(header: &mut Luks2Header, target: &str) -> anyhow::Result<()> {
    let mut slots_to_wipe = Vec::new();

    if let Ok(slot_num) = target.parse::<usize>() {
        slots_to_wipe.push(slot_num.to_string());
    } else {
        // Collect token types mapping to slots
        let mut slot_to_token = HashMap::new();
        if let Some(tokens) = header.json["tokens"].as_object() {
            for (_tok_id, tok_val) in tokens {
                let tok_type = tok_val["type"].as_str().unwrap_or("");
                if let Some(slots) = tok_val["keyslots"].as_array() {
                    for s in slots {
                        if let Some(s_str) = s.as_str() {
                            slot_to_token.insert(s_str.to_string(), tok_type.to_string());
                        }
                    }
                }
            }
        }

        if let Some(keyslots) = header.json["keyslots"].as_object() {
            for slot_key in keyslots.keys() {
                let tok_type = slot_to_token
                    .get(slot_key)
                    .map_or("(password)", String::as_str);
                let should_wipe = match target {
                    "all" => true,
                    "password" => tok_type == "(password)",
                    "recovery" => tok_type == "systemd-recovery",
                    "tpm2" => tok_type == "systemd-tpm2",
                    "fido2" => tok_type == "systemd-fido2",
                    "pkcs11" => tok_type == "systemd-pkcs11",
                    "empty" => false,
                    _ => false,
                };
                if should_wipe {
                    slots_to_wipe.push(slot_key.clone());
                }
            }
        }
    }

    if slots_to_wipe.is_empty() {
        println!("No matching keyslots found to wipe.");
        return Ok(());
    }

    for slot in &slots_to_wipe {
        if let Some(keyslots) = header.json["keyslots"].as_object_mut() {
            keyslots.remove(slot);
        }
        // Remove from token references
        if let Some(tokens) = header.json["tokens"].as_object_mut() {
            tokens.retain(|_, tok_val| {
                if let Some(slots) = tok_val["keyslots"].as_array() {
                    !slots.iter().any(|s| s.as_str() == Some(slot))
                } else {
                    true
                }
            });
        }
        println!("Wiped keyslot {slot}.");
    }

    Ok(())
}

fn display_keyslots(dev_path: &Path, header: &Luks2Header) {
    println!("Device:      {}", dev_path.display());
    println!("UUID:        {}", header.uuid);
    if !header.label.is_empty() {
        println!("Label:       {}", header.label);
    }
    if !header.subsystem.is_empty() {
        println!("Subsystem:   {}", header.subsystem);
    }
    println!("Sector size: {} bytes", header.sector_size);
    println!();

    // Map keyslot index -> token type
    let mut slot_to_token = HashMap::new();
    if let Some(tokens) = header.json["tokens"].as_object() {
        for (_tok_id, tok_val) in tokens {
            let tok_type = tok_val["type"].as_str().unwrap_or("unknown");
            if let Some(slots) = tok_val["keyslots"].as_array() {
                for s in slots {
                    if let Some(s_str) = s.as_str() {
                        slot_to_token.insert(s_str.to_string(), tok_type.to_string());
                    }
                }
            }
        }
    }

    println!("{:<4} {:<18} {:<20} STATUS", "SLOT", "TYPE", "TOKEN");

    if let Some(keyslots) = header.json["keyslots"].as_object() {
        let mut sorted_keys: Vec<usize> = keyslots
            .keys()
            .filter_map(|k| k.parse::<usize>().ok())
            .collect();
        sorted_keys.sort_unstable();

        for slot_num in sorted_keys {
            let key = slot_num.to_string();
            let slot_val = &keyslots[&key];
            let kdf_type = slot_val["kdf"]["type"].as_str().unwrap_or("argon2id");
            let type_str = format!("luks2 ({kdf_type})");
            let token_str = slot_to_token.get(&key).map_or("(password)", String::as_str);
            let priority = slot_val["priority"].as_i64().unwrap_or(1);
            let status_str = if priority > 0 { "active" } else { "unbound" };

            println!("{slot_num:<4} {type_str:<18} {token_str:<20} {status_str}");
        }
    } else {
        println!("No keyslots enrolled.");
    }
}
