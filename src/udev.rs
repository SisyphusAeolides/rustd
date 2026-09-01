// SPDX-License-Identifier: LGPL-2.1-or-later
//! Small, synchronous udev rule engine used by `rustd-udevd`.
//!
//! It deliberately keeps device processing in the daemon process for the first
//! native implementation.  A later worker pool can retain this API.

use crate::glob::matches_no_escape;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const RULE_DIRS: [&str; 3] = [
    "/usr/lib/udev/rules.d",
    "/etc/udev/rules.d",
    "/run/udev/rules.d",
];

#[derive(Clone, Debug, Default)]
pub struct Device {
    pub action: String,
    pub devpath: String,
    pub syspath: PathBuf,
    pub kernel: String,
    pub subsystem: String,
    pub properties: BTreeMap<String, String>,
    pub name: Option<String>,
    pub symlinks: BTreeSet<String>,
    pub tags: BTreeSet<String>,
    pub owner: Option<String>,
    pub group: Option<String>,
    pub mode: Option<u32>,
}

impl Device {
    pub fn from_uevent(bytes: &[u8]) -> Option<Self> {
        let fields: Vec<&str> = bytes
            .split(|byte| *byte == 0)
            .filter_map(|field| std::str::from_utf8(field).ok())
            .filter(|field| !field.is_empty())
            .collect();
        let first = fields.first()?;
        let (action, devpath) = first.split_once('@')?;
        let mut properties = BTreeMap::new();
        for field in fields.iter().skip(1) {
            if let Some((key, value)) = field.split_once('=') {
                properties.insert(key.to_string(), value.to_string());
            }
        }
        let devpath = properties
            .get("DEVPATH")
            .cloned()
            .unwrap_or_else(|| devpath.to_string());
        let syspath = PathBuf::from("/sys").join(devpath.trim_start_matches('/'));
        let kernel = syspath
            .file_name()
            .map_or_else(String::new, |name| name.to_string_lossy().to_string());
        let subsystem = properties
            .get("SUBSYSTEM")
            .cloned()
            .or_else(|| subsystem_name(&syspath))
            .unwrap_or_default();
        Some(Self {
            action: properties
                .get("ACTION")
                .cloned()
                .unwrap_or_else(|| action.to_string()),
            devpath,
            syspath,
            kernel,
            subsystem,
            properties,
            ..Self::default()
        })
    }

    /// Build a device record from a sysfs path.
    ///
    /// # Errors
    ///
    /// Currently always succeeds; the `Result` is retained for call-site
    /// compatibility with future I/O that may fail while reading sysfs.
    pub fn from_syspath(action: &str, syspath: &Path) -> io::Result<Self> {
        let syspath = syspath
            .canonicalize()
            .unwrap_or_else(|_| syspath.to_path_buf());
        let devpath = syspath.strip_prefix("/sys").map_or_else(
            |_| syspath.to_string_lossy().to_string(),
            |path| format!("/{}", path.display()),
        );
        let mut properties = BTreeMap::new();
        if let Ok(uevent) = fs::read_to_string(syspath.join("uevent")) {
            for line in uevent.lines() {
                if let Some((key, value)) = line.split_once('=') {
                    properties.insert(key.to_string(), value.to_string());
                }
            }
        }
        let kernel = syspath
            .file_name()
            .map_or_else(String::new, |name| name.to_string_lossy().to_string());
        let subsystem = properties
            .get("SUBSYSTEM")
            .cloned()
            .or_else(|| subsystem_name(&syspath))
            .unwrap_or_default();
        // A sysfs enumeration is not accompanied by the kernel's uevent
        // header.  Populate the structural keys that normal netlink events
        // carry so the same rule engine sees an identical device record when
        // coldplugging from a live/read-only sysfs tree.
        properties.insert("ACTION".to_string(), action.to_string());
        properties.insert("DEVPATH".to_string(), devpath.clone());
        properties.insert("KERNEL".to_string(), kernel.clone());
        properties.insert("SUBSYSTEM".to_string(), subsystem.clone());
        Ok(Self {
            action: action.to_string(),
            devpath,
            syspath,
            kernel,
            subsystem,
            properties,
            ..Self::default()
        })
    }

    fn property(&self, key: &str) -> String {
        match key {
            "ACTION" => self.action.clone(),
            "KERNEL" => self.kernel.clone(),
            "SUBSYSTEM" => self.subsystem.clone(),
            _ => self.properties.get(key).cloned().unwrap_or_default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Operator {
    Match,
    NoMatch,
    Assign,
    Add,
    Final,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    pub key: String,
    pub attr: Option<String>,
    pub op: Operator,
    pub value: String,
}

#[derive(Clone, Debug, Default)]
pub struct Rule {
    pub tokens: Vec<Token>,
    pub source: PathBuf,
    pub line: usize,
}

/// Load udev rules from the standard rule directories.
///
/// # Errors
///
/// Returns an error when a rules directory exists but cannot be read.
pub fn load_rules() -> io::Result<Vec<Rule>> {
    let mut files = BTreeMap::<String, PathBuf>::new();
    // Entries overwrite earlier paths: /run > /etc > /usr/lib.
    for directory in RULE_DIRS {
        let entries = match fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) == Some("rules") {
                if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
                    files.insert(name.to_string(), path);
                }
            }
        }
    }
    let mut rules = Vec::new();
    for path in files.into_values() {
        rules.extend(parse_rule_file(&path)?);
    }
    Ok(rules)
}

/// Parse one `.rules` file into rule records.
///
/// # Errors
///
/// Returns an error when the file cannot be read.
pub fn parse_rule_file(path: &Path) -> io::Result<Vec<Rule>> {
    let text = fs::read_to_string(path)?;
    let mut rules = Vec::new();
    let mut logical = String::new();
    let mut logical_line = 0_usize;
    for (index, physical) in text.lines().enumerate() {
        let mut line = physical.trim();
        if logical.is_empty() {
            logical_line = index + 1;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let trailing_backslashes = line
            .as_bytes()
            .iter()
            .rev()
            .take_while(|byte| **byte == b'\\')
            .count();
        let continued = trailing_backslashes % 2 == 1;
        if continued {
            line = line[..line.len() - 1].trim_end();
        }
        if !logical.is_empty() && !line.is_empty() {
            logical.push(' ');
        }
        logical.push_str(line);
        if continued {
            continue;
        }
        match parse_rule_line(&logical) {
            Ok(tokens) if !tokens.is_empty() => rules.push(Rule {
                tokens,
                source: path.to_path_buf(),
                line: logical_line,
            }),
            Ok(_) => {}
            Err(error) => eprintln!("rustd-udevd: {}:{}: {error}", path.display(), logical_line),
        }
        logical.clear();
    }
    if !logical.is_empty() {
        match parse_rule_line(&logical) {
            Ok(tokens) if !tokens.is_empty() => rules.push(Rule {
                tokens,
                source: path.to_path_buf(),
                line: logical_line,
            }),
            Ok(_) => {}
            Err(error) => eprintln!("rustd-udevd: {}:{}: {error}", path.display(), logical_line),
        }
    }
    Ok(rules)
}

/// Parse a single udev rule line into tokens.
///
/// # Errors
///
/// Returns an error string when the line has unbalanced quotes or an
/// unrecognized key/operator form.
pub fn parse_rule_line(line: &str) -> Result<Vec<Token>, String> {
    let mut fields = Vec::new();
    let mut start = 0;
    let mut quote = false;
    let mut escape = false;
    for (index, character) in line.char_indices() {
        if escape {
            escape = false;
            continue;
        }
        if character == '\\' {
            escape = true;
            continue;
        }
        if character == '"' {
            quote = !quote;
            continue;
        }
        if character == ',' && !quote {
            fields.push(line[start..index].trim());
            start = index + 1;
        }
    }
    if quote {
        return Err("unterminated quoted value".to_string());
    }
    fields.push(line[start..].trim());
    fields.into_iter().map(parse_token).collect()
}

fn parse_token(field: &str) -> Result<Token, String> {
    for (marker, op) in [
        ("==", Operator::Match),
        ("!=", Operator::NoMatch),
        (":=", Operator::Final),
        ("+=", Operator::Add),
        ("=", Operator::Assign),
    ] {
        if let Some((raw_key, raw_value)) = field.split_once(marker) {
            let raw_key = raw_key.trim();
            let value = raw_value.trim().trim_matches('"').replace("\\\"", "\"");
            let (key, attr) = if let Some(open) = raw_key.find('{') {
                let close = raw_key
                    .rfind('}')
                    .ok_or_else(|| format!("bad key {raw_key}"))?;
                (
                    raw_key[..open].trim().to_ascii_uppercase(),
                    Some(raw_key[open + 1..close].to_string()),
                )
            } else {
                (raw_key.to_ascii_uppercase(), None)
            };
            return Ok(Token {
                key,
                attr,
                op,
                value,
            });
        }
    }
    Err(format!("missing operator in {field}"))
}

pub fn apply_rules(rules: &[Rule], device: &mut Device) {
    let mut labels = BTreeMap::new();
    for (index, rule) in rules.iter().enumerate() {
        for token in &rule.tokens {
            if token.key == "LABEL" {
                labels.insert(token.value.clone(), index);
            }
        }
    }
    let mut index = 0;
    while index < rules.len() {
        let rule = &rules[index];
        if rule_matches(rule, device) {
            let mut jump = None;
            for token in &rule.tokens {
                if !matches!(token.op, Operator::Assign | Operator::Add | Operator::Final) {
                    continue;
                }
                if token.key == "GOTO" {
                    jump = labels.get(&token.value).copied();
                } else {
                    apply_assignment(token, device);
                }
            }
            if let Some(target) = jump {
                index = target;
                continue;
            }
        }
        index += 1;
    }
}

fn rule_matches(rule: &Rule, device: &mut Device) -> bool {
    rule.tokens.iter().all(|token| match token.op {
        Operator::Match => {
            let pattern = expand(&token.value, device);
            if token.key == "TEST" {
                test_path_matches(device, &pattern)
            } else if token.key == "SYMLINK" {
                device
                    .symlinks
                    .iter()
                    .any(|link| value_matches(link, &pattern))
            } else {
                value_matches(&token_value(token, device), &pattern)
            }
        }
        Operator::NoMatch => {
            let pattern = expand(&token.value, device);
            if token.key == "TEST" {
                !test_path_matches(device, &pattern)
            } else if token.key == "SYMLINK" {
                !device
                    .symlinks
                    .iter()
                    .any(|link| value_matches(link, &pattern))
            } else {
                !value_matches(&token_value(token, device), &pattern)
            }
        }
        _ => true,
    })
}

/// Implement udev's `TEST` match against a path relative to the device's
/// sysfs directory.  A few distribution rules use an absolute path, so that
/// form is accepted as well.  Globs are matched against the final path
/// component, which covers the standard udev rule form without allowing a
/// rule to escape its intended parent directory.
fn test_path_matches(device: &Device, pattern: &str) -> bool {
    let path = Path::new(pattern);
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        device.syspath.join(path)
    };
    if !pattern
        .as_bytes()
        .iter()
        .any(|byte| matches!(byte, b'*' | b'?' | b'['))
    {
        return path.exists() || path.is_symlink();
    }
    let Some(file_pattern) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let Some(parent) = path.parent() else {
        return false;
    };
    fs::read_dir(parent)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .any(|name| matches_no_escape(file_pattern, &name))
}

fn value_matches(value: &str, pattern: &str) -> bool {
    pattern
        .split('|')
        .any(|part| matches_no_escape(part, value))
}

fn token_value(token: &Token, device: &Device) -> String {
    match token.key.as_str() {
        "ATTR" => token
            .attr
            .as_deref()
            .and_then(|name| read_attr(&device.syspath, name))
            .unwrap_or_default(),
        "ATTRS" => token
            .attr
            .as_deref()
            .and_then(|name| parent_attr(&device.syspath, name))
            .unwrap_or_default(),
        "ENV" => token
            .attr
            .as_deref()
            .map_or_else(String::new, |name| device.property(name)),
        "ACTION" | "KERNEL" | "SUBSYSTEM" => device.property(&token.key),
        _ => String::new(),
    }
}

fn apply_assignment(token: &Token, device: &mut Device) {
    let value = expand(&token.value, device);
    match token.key.as_str() {
        "ENV" => {
            if let Some(key) = &token.attr {
                device.properties.insert(key.clone(), value);
            }
        }
        "NAME" => device.name = Some(value),
        "SYMLINK" => {
            for link in value.split_whitespace() {
                device.symlinks.insert(link.to_string());
            }
        }
        "OWNER" => device.owner = Some(value),
        "GROUP" => device.group = Some(value),
        "MODE" => device.mode = u32::from_str_radix(value.trim_start_matches('0'), 8).ok(),
        "TAG" => {
            for tag in value.split_whitespace() {
                device.tags.insert(tag.to_string());
            }
        }
        "IMPORT" => import_value(token.attr.as_deref(), &value, device),
        "RUN" => match token.attr.as_deref() {
            Some("builtin") => run_builtin(&value, device),
            None | Some("program") => run_command(&value, device),
            Some(_) => {}
        },
        _ => {}
    }
}

fn import_value(kind: Option<&str>, value: &str, device: &mut Device) {
    match kind.unwrap_or_default() {
        "builtin" => run_builtin(value, device),
        "program" => {
            if let Ok(output) = command_output(value, device) {
                for line in String::from_utf8_lossy(&output.stdout).lines() {
                    if let Some((key, value)) = line.split_once('=') {
                        device
                            .properties
                            .insert(key.to_string(), unquote_import_value(value));
                    }
                }
            }
        }
        _ => {}
    }
}

fn run_builtin(spec: &str, device: &mut Device) {
    let mut fields = spec.split_whitespace();
    let Some(name) = fields.next() else { return };
    match name {
        "kmod" => {
            let mut arguments = fields.collect::<Vec<_>>();
            if arguments.first() == Some(&"load") {
                arguments.remove(0);
            }
            let modules = if arguments.is_empty() {
                device
                    .properties
                    .get("MODALIAS")
                    .map_or_else(Vec::new, |alias| vec![alias.as_str()])
            } else {
                arguments
            };
            for module in modules {
                let _ = Command::new("modprobe")
                    .args(["-b", "-q", "--", module])
                    .status();
            }
        }
        "blkid" => {
            if let Some(node) = device_node(device) {
                if let Ok(output) = Command::new("blkid")
                    .args(["-o", "export", "-p", &node])
                    .output()
                {
                    import_blkid_export(&String::from_utf8_lossy(&output.stdout), device);
                }
            }
        }
        "path_id" => {
            device.properties.insert(
                "ID_PATH".to_string(),
                device.devpath.trim_start_matches('/').replace('/', "-"),
            );
        }
        "net_id" => {
            if device.subsystem == "net" {
                device
                    .properties
                    .insert("ID_NET_NAME_PATH".to_string(), device.kernel.clone());
            }
        }
        "usb_id" => {
            if let Some(vendor) = read_attr(&device.syspath, "idVendor") {
                device.properties.insert("ID_VENDOR_ID".to_string(), vendor);
            }
            if let Some(product) = read_attr(&device.syspath, "idProduct") {
                device.properties.insert("ID_MODEL_ID".to_string(), product);
            }
        }
        "hwdb" => {
            if let Some(modalias) = read_attr(&device.syspath, "modalias") {
                if let Ok(output) = Command::new("rustd-hwdb")
                    .args(["query", &modalias])
                    .output()
                {
                    for line in String::from_utf8_lossy(&output.stdout).lines() {
                        if let Some((key, value)) = line.split_once('=') {
                            device.properties.insert(key.to_string(), value.to_string());
                        }
                    }
                }
            }
        }
        _ => {}
    }
}

fn import_blkid_export(export: &str, device: &mut Device) {
    for line in export.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let property = match key {
            "UUID" => Some("ID_FS_UUID"),
            "UUID_SUB" => Some("ID_FS_UUID_SUB"),
            "LABEL" => Some("ID_FS_LABEL"),
            "TYPE" => Some("ID_FS_TYPE"),
            "USAGE" => Some("ID_FS_USAGE"),
            "VERSION" => Some("ID_FS_VERSION"),
            "PTTYPE" => Some("ID_PART_TABLE_TYPE"),
            "PTUUID" => Some("ID_PART_TABLE_UUID"),
            _ => None,
        };
        if let Some(property) = property {
            device
                .properties
                .insert(property.to_string(), value.to_string());
            if matches!(key, "UUID" | "UUID_SUB" | "LABEL") {
                device
                    .properties
                    .insert(format!("{property}_ENC"), udev_escape(value));
            }
        } else if let Some(suffix) = key.strip_prefix("PART_ENTRY_") {
            device
                .properties
                .insert(format!("ID_PART_ENTRY_{suffix}"), value.to_string());
        }
    }
}

/// Probe filesystem and partition metadata for a block event before applying
/// distribution rules. This guarantees that early userspace can identify its
/// root device even when a reduced or newer rule file is not understood by the
/// native rule engine yet.
pub fn probe_block_metadata(device: &mut Device) {
    if device.subsystem != "block" {
        return;
    }
    let Some(node) = device_node(device) else {
        return;
    };
    let Ok(output) = Command::new("blkid")
        .args(["-o", "export", "-p", &node])
        .output()
    else {
        return;
    };
    if output.status.success() {
        import_blkid_export(&String::from_utf8_lossy(&output.stdout), device);
    }
}

/// Populate the device-mapper properties and links that early userspace needs
/// before it can mount an LVM-backed root filesystem.
///
/// The initramfs intentionally uses RustD's reduced udev rule set. Fedora's
/// full device-mapper rules normally obtain these values from the uevent
/// cookie and create both `/dev/mapper/*` and `/dev/<vg>/<lv>`. Kernel DM
/// events do not reliably carry the name on every path, so derive it from
/// sysfs and use `dmsetup splitname` for the LVM-compatible namespace.
pub fn populate_device_mapper_metadata(device: &mut Device) {
    if device.subsystem != "block" && !device.kernel.starts_with("dm-") {
        return;
    }

    let dm_name = device
        .properties
        .get("DM_NAME")
        .cloned()
        .filter(|name| valid_link_component(name))
        .or_else(|| read_attr(&device.syspath, "dm/name"));
    let Some(dm_name) = dm_name.filter(|name| valid_link_component(name)) else {
        return;
    };

    device
        .properties
        .entry("DM_NAME".to_string())
        .or_insert_with(|| dm_name.clone());
    device
        .properties
        .entry("DM_UDEV_RULES_VSN".to_string())
        .or_insert_with(|| "3".to_string());
    device.symlinks.insert(format!("mapper/{dm_name}"));
    device
        .symlinks
        .insert(format!("disk/by-id/dm-name-{dm_name}"));

    if let Some(dm_uuid) = device
        .properties
        .get("DM_UUID")
        .cloned()
        .filter(|uuid| valid_link_component(uuid))
        .or_else(|| read_attr(&device.syspath, "dm/uuid"))
    {
        device
            .properties
            .entry("DM_UUID".to_string())
            .or_insert_with(|| dm_uuid.clone());
        device
            .symlinks
            .insert(format!("disk/by-id/dm-uuid-{dm_uuid}"));
    }

    // dmsetup is already required by dracut's device-mapper module. Its
    // splitname output handles escaped hyphens and other valid LVM names;
    // silently retaining the mapper link is preferable if the helper is not
    // present in a reduced initramfs.
    if let Ok(output) = Command::new("dmsetup")
        .args(["splitname", "--nameprefixes", "--noheadings", "--rows"])
        .arg(&dm_name)
        .output()
    {
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let Some((key, raw_value)) = line.split_once('=') else {
                continue;
            };
            let value = unquote_import_value(raw_value);
            if !value.is_empty() {
                device.properties.insert(key.to_string(), value);
            }
        }
    }

    let volume_group = device.property("DM_VG_NAME");
    let logical_volume = device.property("DM_LV_NAME");
    if valid_link_component(&volume_group)
        && valid_link_component(&logical_volume)
        && device.property("DM_LV_LAYER").is_empty()
    {
        device
            .symlinks
            .insert(format!("{volume_group}/{logical_volume}"));
    }
}

fn valid_link_component(value: &str) -> bool {
    !value.is_empty() && value != "." && value != ".." && !value.contains('/')
}

fn udev_escape(value: &str) -> String {
    let mut escaped = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'+') {
            escaped.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(escaped, "\\x{byte:02x}");
        }
    }
    escaped
}

fn command_output(command: &str, device: &Device) -> io::Result<std::process::Output> {
    let mut process = Command::new("/bin/sh");
    process.arg("-c").arg(command);
    process
        .envs(&device.properties)
        .env("ACTION", &device.action)
        .env("DEVPATH", &device.devpath)
        .env("SUBSYSTEM", &device.subsystem);
    process.output()
}

fn run_command(command: &str, device: &Device) {
    if let Err(error) = command_output(command, device) {
        eprintln!("rustd-udevd: RUN {command:?}: {error}");
    }
}

fn expand(value: &str, device: &Device) -> String {
    let node = device_node(device).unwrap_or_default();
    let number = device
        .kernel
        .trim_start_matches(|character: char| !character.is_ascii_digit());
    let mut result = value
        .replace("$devnode", &node)
        .replace("$kernel", &device.kernel)
        .replace("$number", number)
        .replace("$devpath", &device.devpath)
        .replace("$name", node.trim_start_matches("/dev/"))
        .replace("$sys", "/sys")
        .replace("$root", "/dev")
        .replace("%N", &node)
        .replace("%k", &device.kernel)
        .replace("%p", &device.devpath)
        .replace("%n", number)
        .replace("%S", "/sys")
        .replace("%r", "/dev")
        .replace("%M", &device.property("MAJOR"))
        .replace("%m", &device.property("MINOR"));
    while let Some(start) = result.find("$env{") {
        let Some(end) = result[start + 5..].find('}') else {
            break;
        };
        let end = start + 5 + end;
        let key = &result[start + 5..end];
        result.replace_range(start..=end, &device.property(key));
    }
    while let Some(start) = result.find("$attr{") {
        let Some(end) = result[start + 6..].find('}') else {
            break;
        };
        let end = start + 6 + end;
        let name = &result[start + 6..end];
        let replacement = read_attr(&device.syspath, name).unwrap_or_default();
        result.replace_range(start..=end, &replacement);
    }
    while let Some(start) = result.find("%E{") {
        let Some(end) = result[start + 3..].find('}') else {
            break;
        };
        let end = start + 3 + end;
        let key = &result[start + 3..end];
        result.replace_range(start..=end, &device.property(key));
    }
    result
}

/// `IMPORT{program}` commonly consumes tools that emit shell-style values,
/// for example `DM_NAME='live-rw'` from `dmsetup --nameprefixes`.  udev stores
/// the value, not the presentation quotes; accepting both quote styles keeps
/// the compatibility path faithful when a `TEST` fallback is unavoidable.
fn unquote_import_value(value: &str) -> String {
    let value = value.trim();
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if (bytes[0] == b'\'' && bytes[value.len() - 1] == b'\'')
            || (bytes[0] == b'"' && bytes[value.len() - 1] == b'"')
        {
            return value[1..value.len() - 1].to_string();
        }
    }
    value.to_string()
}

/// Create device nodes/symlinks and write the `/run/udev/data` record.
///
/// # Errors
///
/// Returns an error when node creation or database writes fail.
pub fn persist_device(device: &Device) -> io::Result<()> {
    use std::fmt::Write as _;

    fs::create_dir_all("/run/udev/data")?;
    if device.action == "remove" {
        remove_device(device);
        return Ok(());
    }
    if let Some(node) = device_node(device) {
        create_node(device, &node)?;
        for link in &device.symlinks {
            create_symlink(link, &node)?;
        }
    }
    let id = database_id(device);
    let mut data = format!("P:{}\n", device.devpath);
    if let Some(node) = device_node(device) {
        let _ = writeln!(data, "N:{}", node.trim_start_matches("/dev/"));
    }
    for link in &device.symlinks {
        let _ = writeln!(data, "S:{link}");
    }
    for tag in &device.tags {
        let _ = writeln!(data, "G:{tag}");
    }
    for (key, value) in &device.properties {
        let _ = writeln!(data, "E:{key}={value}");
    }
    fs::write(Path::new("/run/udev/data").join(id), data)
}

/// Add the canonical persistent-storage links implied by probed filesystem and
/// partition metadata. Distribution rule files normally request these links,
/// but creating them from the normalized properties also makes early userspace
/// robust when its reduced rule set omits or cannot parse those assignments.
pub fn add_persistent_storage_links(device: &mut Device) {
    let usage = device.property("ID_FS_USAGE");
    if matches!(usage.as_str(), "filesystem" | "other" | "crypto") {
        if let Some(uuid) = device.properties.get("ID_FS_UUID_ENC") {
            if !uuid.is_empty() {
                device.symlinks.insert(format!("disk/by-uuid/{uuid}"));
            }
        }
        if let Some(label) = device.properties.get("ID_FS_LABEL_ENC") {
            if !label.is_empty() {
                device.symlinks.insert(format!("disk/by-label/{label}"));
            }
        }
    }
    if let Some(uuid) = device.properties.get("ID_PART_ENTRY_UUID") {
        if !uuid.is_empty() {
            device.symlinks.insert(format!("disk/by-partuuid/{uuid}"));
        }
    }
    if device.property("ID_PART_ENTRY_SCHEME") == "gpt" {
        if let Some(name) = device.properties.get("ID_PART_ENTRY_NAME") {
            if !name.is_empty() {
                device
                    .symlinks
                    .insert(format!("disk/by-partlabel/{}", udev_escape(name)));
            }
        }
    }
}

fn device_node(device: &Device) -> Option<String> {
    let name = device
        .name
        .clone()
        .or_else(|| device.properties.get("DEVNAME").cloned())?;
    let name = name.trim_start_matches("/dev/");
    (!name.is_empty() && !name.contains("..")).then(|| format!("/dev/{name}"))
}

fn create_node(device: &Device, node: &str) -> io::Result<()> {
    let (Some(major), Some(minor)) = (
        device.properties.get("MAJOR"),
        device.properties.get("MINOR"),
    ) else {
        return Ok(());
    };
    let (Ok(major), Ok(minor)) = (major.parse::<u32>(), minor.parse::<u32>()) else {
        return Ok(());
    };
    let path = Path::new(node);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let kind = if device.subsystem == "block" {
        libc::S_IFBLK
    } else {
        libc::S_IFCHR
    };
    let mode = device.mode.unwrap_or(0o660) | kind;
    let c_path = CString::new(node)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad device name"))?;
    // An existing node may have been created by the kernel/initramfs.
    let result = unsafe { libc::mknod(c_path.as_ptr(), mode, libc::makedev(major, minor)) };
    if result != 0 && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists {
        return Err(io::Error::last_os_error());
    }
    apply_node_permissions(path, device.mode, result == 0)?;
    crate::selinux::restorecon_path(path)
        .map_err(|error| io::Error::other(format!("restore SELinux label on {path:?}: {error}")))?;
    let uid = device
        .owner
        .as_deref()
        .and_then(resolve_user)
        .unwrap_or(u32::MAX);
    let gid = device
        .group
        .as_deref()
        .and_then(resolve_group)
        .unwrap_or(u32::MAX);
    if uid != u32::MAX || gid != u32::MAX {
        let _ = unsafe { libc::chown(c_path.as_ptr(), uid, gid) };
    }
    Ok(())
}

fn apply_node_permissions(
    path: &Path,
    explicit_mode: Option<u32>,
    created: bool,
) -> io::Result<()> {
    // devtmpfs creates kernel device nodes as 0600 before userspace udev has
    // applied its default policy.  Standard udev promotes that untouched
    // kernel default to 0660 (and then applies the rule-selected group),
    // which is required for non-root graphical sessions to open DRM, input,
    // and other device nodes.  Preserve any mode that was already customized
    // by an earlier rule or by the initramfs.
    let apply_default_mode = if !created && explicit_mode.is_none() {
        fs::metadata(path)?.permissions().mode() & 0o777 == 0o600
    } else {
        false
    };
    if created || explicit_mode.is_some() || apply_default_mode {
        fs::set_permissions(
            path,
            fs::Permissions::from_mode(explicit_mode.unwrap_or(0o660)),
        )?;
    }
    Ok(())
}

fn create_symlink(link: &str, node: &str) -> io::Result<()> {
    if link.starts_with('/') || link.contains("..") {
        return Ok(());
    }
    let path = Path::new("/dev").join(link);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let _ = fs::remove_file(&path);
    std::os::unix::fs::symlink(node, path)
}

fn remove_device(device: &Device) {
    if let Some(node) = device_node(device) {
        let _ = fs::remove_file(node);
    }
    for link in &device.symlinks {
        if !link.contains("..") {
            let _ = fs::remove_file(Path::new("/dev").join(link));
        }
    }
    let _ = fs::remove_file(Path::new("/run/udev/data").join(database_id(device)));
}

fn database_id(device: &Device) -> String {
    if let (Some(major), Some(minor)) = (
        device.properties.get("MAJOR"),
        device.properties.get("MINOR"),
    ) {
        let prefix = if device.subsystem == "block" {
            "b"
        } else {
            "c"
        };
        return format!("{prefix}{major}:{minor}");
    }
    format!("+{}:{}", device.subsystem, device.kernel)
}

fn subsystem_name(path: &Path) -> Option<String> {
    fs::read_link(path.join("subsystem"))
        .ok()?
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
}
fn read_attr(path: &Path, name: &str) -> Option<String> {
    fs::read_to_string(path.join(name))
        .ok()
        .map(|value| value.trim().to_string())
}
fn parent_attr(path: &Path, name: &str) -> Option<String> {
    let mut current = path.parent();
    while let Some(parent) = current {
        if let Some(value) = read_attr(parent, name) {
            return Some(value);
        }
        if parent == Path::new("/sys") {
            break;
        }
        current = parent.parent();
    }
    None
}
fn resolve_user(value: &str) -> Option<u32> {
    if let Ok(id) = value.parse() {
        return Some(id);
    }
    let name = CString::new(value).ok()?;
    let entry = unsafe { libc::getpwnam(name.as_ptr()) };
    (!entry.is_null()).then(|| unsafe { (*entry).pw_uid })
}
fn resolve_group(value: &str) -> Option<u32> {
    if let Ok(id) = value.parse() {
        return Some(id);
    }
    let name = CString::new(value).ok()?;
    let entry = unsafe { libc::getgrnam(name.as_ptr()) };
    (!entry.is_null()).then(|| unsafe { (*entry).gr_gid })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    #[test]
    fn parses_quoted_rule_assignments() {
        let rule = parse_rule_line(r#"ACTION=="add", SUBSYSTEM=="block", ENV{ID_FS_TYPE}="ext4", SYMLINK+="disk/by-id/foo bar""#).unwrap();
        assert_eq!(rule.len(), 4);
        assert_eq!(rule[0].op, Operator::Match);
        assert_eq!(rule[2].attr.as_deref(), Some("ID_FS_TYPE"));
        assert_eq!(rule[3].op, Operator::Add);
    }
    #[test]
    fn parses_attr_and_control_tokens() {
        let rule =
            parse_rule_line(r#"ATTRS{idVendor}=="1234", GOTO="done", LABEL="done""#).unwrap();
        assert_eq!(rule[0].key, "ATTRS");
        assert_eq!(rule[0].attr.as_deref(), Some("idVendor"));
        assert_eq!(rule[1].key, "GOTO");
    }

    #[test]
    fn test_match_and_attr_substitution_support_device_mapper_rules() {
        let sysfs = tempfile::tempdir().unwrap();
        fs::create_dir(sysfs.path().join("dm")).unwrap();
        fs::write(sysfs.path().join("dm/name"), "live-rw\n").unwrap();

        let rules = vec![Rule {
            tokens: parse_rule_line(
                r#"TEST=="dm", ENV{DM_NAME}="$attr{dm/name}", SYMLINK+="mapper/$env{DM_NAME}""#,
            )
            .unwrap(),
            source: PathBuf::from("10-dm.rules"),
            line: 1,
        }];
        let mut device = Device {
            syspath: sysfs.path().to_path_buf(),
            ..Device::default()
        };

        apply_rules(&rules, &mut device);

        assert_eq!(device.property("DM_NAME"), "live-rw");
        assert!(device.symlinks.contains("mapper/live-rw"));
    }

    #[test]
    fn imported_shell_values_are_stored_without_presentation_quotes() {
        assert_eq!(unquote_import_value("'live-rw'"), "live-rw");
        assert_eq!(unquote_import_value("\"live-rw\""), "live-rw");
        assert_eq!(unquote_import_value("''"), "");
        assert_eq!(unquote_import_value("plain"), "plain");
    }

    #[test]
    fn rule_files_join_backslash_continuations_into_one_logical_rule() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            file,
            "ACTION==\"add\", \\\n+             SUBSYSTEM==\"block\", \\\n+             ENV{{RUSTD_CONTINUED}}=\"yes\""
        )
        .unwrap();

        let rules = parse_rule_file(file.path()).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].line, 1);
        assert_eq!(rules[0].tokens.len(), 3);
        assert_eq!(rules[0].tokens[2].attr.as_deref(), Some("RUSTD_CONTINUED"));
    }

    #[test]
    fn existing_device_nodes_keep_their_mode_without_an_explicit_rule() {
        let file = tempfile::NamedTempFile::new().unwrap();
        fs::set_permissions(file.path(), fs::Permissions::from_mode(0o666)).unwrap();

        apply_node_permissions(file.path(), None, false).unwrap();
        assert_eq!(
            fs::metadata(file.path()).unwrap().permissions().mode() & 0o777,
            0o666
        );

        apply_node_permissions(file.path(), Some(0o640), false).unwrap();
        assert_eq!(
            fs::metadata(file.path()).unwrap().permissions().mode() & 0o777,
            0o640
        );

        fs::set_permissions(file.path(), fs::Permissions::from_mode(0o600)).unwrap();
        apply_node_permissions(file.path(), None, false).unwrap();
        assert_eq!(
            fs::metadata(file.path()).unwrap().permissions().mode() & 0o777,
            0o660
        );

        apply_node_permissions(file.path(), None, true).unwrap();
        assert_eq!(
            fs::metadata(file.path()).unwrap().permissions().mode() & 0o777,
            0o660
        );
    }

    #[test]
    fn packaged_default_rules_cover_coldplug_core_and_storage_nodes() {
        let rules = parse_rule_file(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("dist/fedora/compat/50-rustd-default.rules")
                .as_path(),
        )
        .unwrap();
        let mut null = Device {
            action: "change".into(),
            kernel: "null".into(),
            subsystem: "mem".into(),
            ..Device::default()
        };
        apply_rules(&rules, &mut null);
        assert_eq!(null.mode, Some(0o666));

        let mut disk = Device {
            action: "change".into(),
            kernel: "vda".into(),
            subsystem: "block".into(),
            ..Device::default()
        };
        apply_rules(&rules, &mut disk);
        assert_eq!(disk.group.as_deref(), Some("disk"));
    }

    #[test]
    fn run_builtin_dispatches_to_the_builtin_engine() {
        let mut device = Device {
            devpath: "/devices/pci0000:00/0000:00:04.0".into(),
            ..Device::default()
        };
        let rules = vec![Rule {
            tokens: parse_rule_line(r#"RUN{builtin}+="path_id""#).unwrap(),
            source: PathBuf::from("80-drivers.rules"),
            line: 1,
        }];

        apply_rules(&rules, &mut device);

        assert_eq!(
            device.property("ID_PATH"),
            "devices-pci0000:00-0000:00:04.0"
        );
    }

    #[test]
    fn symlink_matches_can_trigger_late_live_root_rules() {
        let rules = vec![Rule {
            tokens: parse_rule_line(
                r#"SYMLINK=="disk/by-label/ARACHOS", ENV{RUSTD_LIVE_ROOT}="ready""#,
            )
            .unwrap(),
            source: PathBuf::from("99-live-root.rules"),
            line: 1,
        }];
        let mut device = Device::default();
        device.symlinks.insert("disk/by-label/ARACHOS".into());

        apply_rules(&rules, &mut device);

        assert_eq!(device.property("RUSTD_LIVE_ROOT"), "ready");
    }

    #[test]
    fn expands_standard_device_rule_substitutions() {
        let mut device = Device {
            devpath: "/devices/virtual/tty/tty0".into(),
            kernel: "tty0".into(),
            name: Some("tty0".into()),
            ..Device::default()
        };
        device.properties.insert("MAJOR".into(), "4".into());
        device.properties.insert("MINOR".into(), "0".into());

        assert_eq!(expand("$root/$name", &device), "/dev/tty0");
        assert_eq!(
            expand("%N %S%p %M:%m %n", &device),
            "/dev/tty0 /sys/devices/virtual/tty/tty0 4:0 0"
        );
    }

    #[test]
    fn blkid_export_uses_udev_property_names() {
        let mut device = Device::default();
        import_blkid_export(
            "DEVNAME=/dev/vda1\nUUID=01582c00-2b49-4e9b-86ee-75f418a4b720\nLABEL=root fs\nTYPE=xfs\nUSAGE=filesystem\nPTTYPE=gpt\nPART_ENTRY_NUMBER=1\n",
            &mut device,
        );
        assert_eq!(device.property("ID_FS_TYPE"), "xfs");
        assert_eq!(device.property("ID_FS_USAGE"), "filesystem");
        assert_eq!(
            device.property("ID_FS_UUID_ENC"),
            "01582c00-2b49-4e9b-86ee-75f418a4b720"
        );
        assert_eq!(device.property("ID_FS_LABEL_ENC"), "root\\x20fs");
        assert_eq!(device.property("ID_PART_TABLE_TYPE"), "gpt");
        assert_eq!(device.property("ID_PART_ENTRY_NUMBER"), "1");
        assert!(device.property("DEVNAME").is_empty());
    }

    #[test]
    fn probed_storage_metadata_always_creates_canonical_links() {
        let mut device = Device::default();
        device
            .properties
            .insert("ID_FS_USAGE".into(), "filesystem".into());
        device
            .properties
            .insert("ID_FS_UUID_ENC".into(), "1234-abcd".into());
        device
            .properties
            .insert("ID_FS_LABEL_ENC".into(), "root\\x20disk".into());
        device
            .properties
            .insert("ID_PART_ENTRY_UUID".into(), "part-uuid".into());

        add_persistent_storage_links(&mut device);

        assert!(device.symlinks.contains("disk/by-uuid/1234-abcd"));
        assert!(device.symlinks.contains("disk/by-label/root\\x20disk"));
        assert!(device.symlinks.contains("disk/by-partuuid/part-uuid"));
    }

    #[test]
    fn device_mapper_metadata_creates_mapper_and_lvm_links() {
        let mut device = Device {
            kernel: "dm-0".into(),
            subsystem: "block".into(),
            ..Device::default()
        };
        device
            .properties
            .insert("DM_NAME".into(), "fedora_fedora-root".into());
        device
            .properties
            .insert("DM_UUID".into(), "LVM-root-uuid".into());
        device
            .properties
            .insert("DM_VG_NAME".into(), "fedora_fedora".into());
        device.properties.insert("DM_LV_NAME".into(), "root".into());

        populate_device_mapper_metadata(&mut device);

        assert!(device.symlinks.contains("mapper/fedora_fedora-root"));
        assert!(device.symlinks.contains("fedora_fedora/root"));
    }
}
