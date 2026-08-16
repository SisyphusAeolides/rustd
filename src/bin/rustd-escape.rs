// SPDX-License-Identifier: LGPL-2.1-or-later
//! systemd-escape — escape strings for use in unit names.
//!
//! Upstream reference: `src/escape/escape-tool.c` and
//! `src/basic/unit-name.c` (systemd v261).

use std::path::{Component, Path};

const VERSION_OUTPUT: &str = concat!(
    "systemd 261 (261.2-1-arch)\n",
    "+PAM +AUDIT -SELINUX +APPARMOR -IMA +IPE +SMACK +SECCOMP +GCRYPT +GNUTLS +OPENSSL +ACL ",
    "+BLKID +CURL +ELFUTILS +FIDO2 +IDN2 +KMOD +LIBCRYPTSETUP +LIBCRYPTSETUP_PLUGINS +LIBFDISK ",
    "+PCRE2 +PWQUALITY +P11KIT +QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB +ZSTD +BPF_FRAMEWORK +BTF ",
    "+XKBCOMMON +UTMP +LIBARCHIVE\n"
);

const UNIT_TYPES: &[&str] = &[
    "service",
    "mount",
    "swap",
    "socket",
    "target",
    "device",
    "automount",
    "timer",
    "path",
    "slice",
    "scope",
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    Escape,
    Unescape,
    Mangle,
}

struct Options {
    action: Action,
    suffix: Option<String>,
    template: Option<String>,
    path: bool,
    instance: bool,
    names: Vec<String>,
}

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match run(&args) {
        Ok(output) => print!("{output}"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

fn run(args: &[String]) -> Result<String, String> {
    if args.iter().any(|argument| argument == "--version") {
        return Ok(VERSION_OUTPUT.to_owned());
    }
    if args
        .iter()
        .any(|argument| argument == "--help" || argument == "-h")
    {
        return Ok(help());
    }

    let options = parse_options(args)?;
    let mut output = Vec::with_capacity(options.names.len());
    for name in &options.names {
        let mut escaped = match options.action {
            Action::Escape if options.path => path_escape(name)?,
            Action::Escape => unit_name_escape(name),
            Action::Unescape => {
                let encoded = if options.instance || options.template.is_some() {
                    extract_instance(name, options.template.as_deref())?
                } else {
                    name.clone()
                };
                if options.path {
                    path_unescape(&encoded)?
                } else {
                    unit_name_unescape(&encoded)?
                }
            }
            Action::Mangle => unit_name_mangle(name)?,
        };

        if options.action == Action::Escape {
            if let Some(template) = &options.template {
                escaped = replace_instance(template, &escaped)?;
            } else if let Some(suffix) = &options.suffix {
                escaped.push('.');
                escaped.push_str(suffix);
            }
        }
        output.push(escaped);
    }
    Ok(format!("{}\n", output.join(" ")))
}

fn parse_options(args: &[String]) -> Result<Options, String> {
    let mut options = Options {
        action: Action::Escape,
        suffix: None,
        template: None,
        path: false,
        instance: false,
        names: Vec::new(),
    };
    let mut index = 0;
    let mut positional_only = false;
    while index < args.len() {
        let argument = &args[index];
        if positional_only || !argument.starts_with('-') || argument == "-" {
            options.names.push(argument.clone());
            index += 1;
            continue;
        }
        if argument == "--" {
            positional_only = true;
            index += 1;
            continue;
        }
        match argument.as_str() {
            "-u" | "--unescape" => options.action = Action::Unescape,
            "-m" | "--mangle" => options.action = Action::Mangle,
            "-p" | "--path" => options.path = true,
            "--instance" => options.instance = true,
            "--suffix" | "--template" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| format!("Option {argument} requires an argument."))?;
                if argument == "--suffix" {
                    options.suffix = Some(value.clone());
                } else {
                    options.template = Some(value.clone());
                }
            }
            _ if argument.starts_with("--suffix=") => {
                options.suffix = Some(argument[9..].to_owned());
            }
            _ if argument.starts_with("--template=") => {
                options.template = Some(argument[11..].to_owned());
            }
            _ if argument.starts_with('-') && !argument.starts_with("--") => {
                for short in argument[1..].chars() {
                    match short {
                        'u' => options.action = Action::Unescape,
                        'm' => options.action = Action::Mangle,
                        'p' => options.path = true,
                        'h' => return Err("Use --help by itself.".to_owned()),
                        _ => return Err(format!("Unknown option -{short}.")),
                    }
                }
            }
            _ => return Err(format!("Unknown option {argument}.")),
        }
        index += 1;
    }

    if options.names.is_empty() {
        return Err("Not enough arguments.".to_owned());
    }
    if let Some(suffix) = &options.suffix {
        if !UNIT_TYPES.contains(&suffix.as_str()) {
            return Err(format!("Invalid unit suffix type \"{suffix}\"."));
        }
    }
    if let Some(template) = &options.template {
        if !is_valid_template(template) {
            return Err(format!("Template name {template} is not valid."));
        }
    }
    if options.template.is_some() && options.suffix.is_some() {
        return Err("--suffix= and --template= may not be combined.".to_owned());
    }
    if (options.template.is_some() || options.suffix.is_some()) && options.action == Action::Mangle
    {
        return Err("--suffix= and --template= are not compatible with --mangle.".to_owned());
    }
    if options.suffix.is_some() && options.action == Action::Unescape {
        return Err("--suffix is not compatible with --unescape.".to_owned());
    }
    if options.path && options.action == Action::Mangle {
        return Err("--path may not be combined with --mangle.".to_owned());
    }
    if options.instance && options.action != Action::Unescape {
        return Err("--instance must be used in conjunction with --unescape.".to_owned());
    }
    if options.instance && options.template.is_some() {
        return Err("--instance may not be combined with --template.".to_owned());
    }
    Ok(options)
}

fn help() -> String {
    concat!(
        "systemd-escape [OPTIONS...] [NAME...]\n\n",
        "Escape strings for usage in systemd unit names.\n\n",
        "  -h --help              Show this help\n",
        "     --version           Show package version\n",
        "     --suffix=SUFFIX     Unit suffix to append to escaped strings\n",
        "     --template=TEMPLATE Insert strings as instance into template\n",
        "     --instance          With --unescape, show just the instance part\n",
        "  -u --unescape          Unescape strings\n",
        "  -m --mangle            Mangle strings\n",
        "  -p --path              When escaping/unescaping assume the string is a path\n\n",
        "See the systemd-escape(1) man page for details.\n"
    )
    .to_owned()
}

fn valid_unit_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'.')
}

fn unit_name_escape(value: &str) -> String {
    let mut result = String::with_capacity(value.len().saturating_mul(4));
    for (index, byte) in value.bytes().enumerate() {
        if byte == b'/' {
            result.push('-');
        } else if (index == 0 && byte == b'.')
            || byte == b'-'
            || byte == b'\\'
            || !valid_unit_byte(byte)
        {
            push_hex_escape(&mut result, byte);
        } else {
            result.push(char::from(byte));
        }
    }
    result
}

fn push_hex_escape(output: &mut String, byte: u8) {
    use std::fmt::Write as _;
    let _ = write!(output, "\\x{byte:02x}");
}

fn unit_name_unescape(value: &str) -> Result<String, String> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'-' {
            output.push(b'/');
            index += 1;
        } else if bytes[index] == b'\\' {
            if bytes.get(index + 1) != Some(&b'x') {
                return Err("Failed to unescape string: Invalid argument".to_owned());
            }
            let high = hex_value(*bytes.get(index + 2).unwrap_or(&0));
            let low = hex_value(*bytes.get(index + 3).unwrap_or(&0));
            let (Some(high), Some(low)) = (high, low) else {
                return Err("Failed to unescape string: Invalid argument".to_owned());
            };
            output.push((high << 4) | low);
            index += 4;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    if let Some(nul) = output.iter().position(|byte| *byte == 0) {
        output.truncate(nul);
    }
    String::from_utf8(output).map_err(|_| "Failed to unescape string: Invalid argument".to_owned())
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn simplify_path(path: &str) -> String {
    let absolute = path.starts_with('/');
    let parts: Vec<&str> = path
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect();
    if parts.is_empty() {
        return if absolute { "/" } else { "." }.to_owned();
    }
    let joined = parts.join("/");
    if absolute {
        format!("/{joined}")
    } else {
        joined
    }
}

fn is_normalized_path(path: &str) -> bool {
    !Path::new(path)
        .components()
        .any(|component| component == Component::ParentDir)
}

fn path_escape(value: &str) -> Result<String, String> {
    if value.contains('\0') {
        return Err(format!(
            "Input '{value}' is not a valid file system path, failed to escape."
        ));
    }
    if !is_normalized_path(value) {
        return Err(format!(
            "Input '{value}' is not a normalized file system path, failed to escape."
        ));
    }
    if value == "." {
        return Err("Input '.' is not an absolute file system path, failed to escape.".to_owned());
    }
    let simplified = simplify_path(value);
    if simplified == "/" || simplified == "." {
        return Ok("-".to_owned());
    }
    let escaped = unit_name_escape(simplified.trim_start_matches('/'));
    if !value.starts_with('/') {
        eprintln!(
            "Input '{value}' is not an absolute file system path, escaping is likely not going to be reversible."
        );
    }
    Ok(escaped)
}

fn path_unescape(value: &str) -> Result<String, String> {
    if value.is_empty() {
        return Err("Failed to unescape string: Invalid argument".to_owned());
    }
    if value == "-" {
        return Ok("/".to_owned());
    }
    let decoded = unit_name_unescape(value)?;
    if decoded.starts_with('/') || decoded.ends_with('/') {
        return Err("Failed to unescape string: Invalid argument".to_owned());
    }
    let path = format!("/{decoded}");
    if !is_normalized_path(&path) {
        return Err("Failed to unescape string: Invalid argument".to_owned());
    }
    Ok(path)
}

fn unit_name_mangle(value: &str) -> Result<String, String> {
    if value.is_empty() {
        return Err("Invalid argument".to_owned());
    }
    if is_valid_unit_name(value) {
        return Ok(value.to_owned());
    }
    if value.starts_with('/') {
        let simplified = simplify_path(value);
        let suffix = if simplified == "/dev" || simplified.starts_with("/dev/") {
            "device"
        } else {
            "mount"
        };
        return Ok(format!("{}.{}", path_escape(&simplified)?, suffix));
    }
    let mut output = String::with_capacity(value.len().saturating_mul(4) + 8);
    for byte in value.bytes() {
        if byte == b'/' {
            output.push('-');
        } else if valid_unit_byte(byte) || matches!(byte, b'-' | b'@') {
            output.push(char::from(byte));
        } else {
            push_hex_escape(&mut output, byte);
        }
    }
    if !has_valid_suffix(&output) {
        output.push_str(".service");
    }
    if !is_valid_unit_name(&output) {
        return Err("Invalid argument".to_owned());
    }
    Ok(output)
}

fn has_valid_suffix(value: &str) -> bool {
    value
        .rsplit_once('.')
        .is_some_and(|(_, suffix)| UNIT_TYPES.contains(&suffix))
}

fn is_valid_unit_name(value: &str) -> bool {
    if value.is_empty() || value.len() >= 256 || !has_valid_suffix(value) {
        return false;
    }
    let stem = value.rsplit_once('.').map_or("", |(stem, _)| stem);
    if stem.is_empty() || stem.starts_with('@') {
        return false;
    }
    let mut ats = 0;
    stem.bytes().all(|byte| {
        if byte == b'@' {
            ats += 1;
            ats <= 1
        } else {
            valid_unit_byte(byte) || matches!(byte, b'-' | b'\\')
        }
    })
}

fn is_valid_template(value: &str) -> bool {
    let Some((stem, suffix)) = value.rsplit_once('.') else {
        return false;
    };
    UNIT_TYPES.contains(&suffix)
        && stem.ends_with('@')
        && !stem.starts_with('@')
        && stem[..stem.len() - 1]
            .bytes()
            .all(|byte| valid_unit_byte(byte) || matches!(byte, b'-' | b'\\'))
}

fn replace_instance(template: &str, instance: &str) -> Result<String, String> {
    let Some((prefix, suffix)) = template.split_once("@.") else {
        return Err("Failed to replace instance: Invalid argument".to_owned());
    };
    Ok(format!("{prefix}@{instance}.{suffix}"))
}

fn extract_instance(value: &str, expected_template: Option<&str>) -> Result<String, String> {
    if !is_valid_unit_name(value) {
        return Err("Failed to extract instance: Invalid argument".to_owned());
    }
    let Some(at) = value.find('@') else {
        return Err("Failed to extract instance: Invalid argument".to_owned());
    };
    let dot = value
        .rfind('.')
        .ok_or_else(|| "Failed to extract instance: Invalid argument".to_owned())?;
    if dot == at + 1 {
        return Err(format!("Unit {value} is missing the instance name."));
    }
    let template = format!("{}@{}", &value[..at], &value[dot..]);
    if let Some(expected) = expected_template {
        if template != expected {
            return Err(format!(
                "Unit {value} template {template} does not match specified template {expected}."
            ));
        }
    }
    Ok(value[at + 1..dot].to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_and_unescape_match_v261_examples() {
        assert_eq!(unit_name_escape("foo/bar"), "foo-bar");
        assert_eq!(unit_name_escape("foo-bar"), "foo\\x2dbar");
        assert_eq!(unit_name_escape(".foo"), "\\x2efoo");
        assert_eq!(unit_name_escape("föo"), "f\\xc3\\xb6o");
        assert_eq!(unit_name_unescape("foo\\x2dbar").unwrap(), "foo-bar");
        assert_eq!(unit_name_unescape("foo-bar").unwrap(), "foo/bar");
    }

    #[test]
    fn path_and_mangle_match_v261_examples() {
        assert_eq!(path_escape("/").unwrap(), "-");
        assert_eq!(path_escape("/foo//bar/").unwrap(), "foo-bar");
        assert!(path_escape("/foo/../bar").is_err());
        assert_eq!(path_unescape("foo-bar").unwrap(), "/foo/bar");
        assert_eq!(unit_name_mangle("/dev/sda").unwrap(), "dev-sda.device");
        assert_eq!(unit_name_mangle("/srv/data").unwrap(), "srv-data.mount");
        assert_eq!(unit_name_mangle("foo bar").unwrap(), "foo\\x20bar.service");
    }

    #[test]
    fn options_apply_suffix_template_and_instance() {
        assert_eq!(
            run(&["--suffix=service".into(), "hello".into()]).unwrap(),
            "hello.service\n"
        );
        assert_eq!(
            run(&["--template=foo@.service".into(), "hello/world".into()]).unwrap(),
            "foo@hello-world.service\n"
        );
        assert_eq!(
            run(&[
                "--unescape".into(),
                "--instance".into(),
                "foo@bar\\x2dbaz.service".into()
            ])
            .unwrap(),
            "bar-baz\n"
        );
    }
}
