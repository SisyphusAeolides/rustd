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
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match parse_rule_line(line) {
            Ok(tokens) if !tokens.is_empty() => rules.push(Rule {
                tokens,
                source: path.to_path_buf(),
                line: index + 1,
            }),
            Ok(_) => {}
            Err(error) => eprintln!("rustd-udevd: {}:{}: {error}", path.display(), index + 1),
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
            value_matches(&token_value(token, device), &expand(&token.value, device))
        }
        Operator::NoMatch => {
            !value_matches(&token_value(token, device), &expand(&token.value, device))
        }
        _ => true,
    })
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
        "RUN" => run_command(&value, device),
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
                        device.properties.insert(key.to_string(), value.to_string());
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
            let module = arguments.join(" ");
            if !module.is_empty() {
                let _ = Command::new("modprobe").args(["-b", &module]).status();
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
    let mut result = value
        .replace("%k", &device.kernel)
        .replace("%p", &device.devpath)
        .replace("%n", &device.kernel);
    while let Some(start) = result.find("$env{") {
        let Some(end) = result[start + 5..].find('}') else {
            break;
        };
        let end = start + 5 + end;
        let key = &result[start + 5..end];
        result.replace_range(start..=end, &device.property(key));
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
    fs::set_permissions(
        path,
        fs::Permissions::from_mode(device.mode.unwrap_or(0o660)),
    )?;
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
}
