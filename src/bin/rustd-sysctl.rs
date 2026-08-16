// SPDX-License-Identifier: LGPL-2.1-or-later
//! `systemd-sysctl` compatibility utility.
//!
//! Upstream reference: systemd v261 `src/sysctl/sysctl.c` and
//! `src/basic/sysctl-util.c` at the pinned RustD baseline.

use std::collections::{BTreeMap, HashSet};
use std::env;
use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};

const VERSION: &str = "systemd 261 (rustd 0.1.0)";
const PROC_SYS: &str = "/proc/sys";
const CONF_DIRS: [&str; 4] = [
    "/etc/sysctl.d",
    "/run/sysctl.d",
    "/usr/local/lib/sysctl.d",
    "/usr/lib/sysctl.d",
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct SysctlOption {
    key: String,
    value: Option<String>,
    ignore_failure: bool,
}

#[derive(Debug, Default)]
struct Args {
    prefixes: Vec<String>,
    cat_config: bool,
    tldr: bool,
    strict: bool,
    inline: bool,
    positional: Vec<String>,
}

fn print_help(program: &str) {
    println!(
        "{program} [OPTIONS...] [CONFIGURATION FILE...]\n\n\
         Applies kernel sysctl settings.\n\n\
         Options:\n\
           -h --help              Show this help\n\
              --version           Show package version\n\
              --cat-config        Show configuration files instead of applying\n\
              --tldr              Show configuration without comments/empty lines\n\
              --prefix=PATH       Only apply rules with the specified prefix\n\
              --no-pager          Do not pipe output into a pager\n\
              --strict            Fail on any kind of failure\n\
              --inline            Treat positional arguments as configuration lines"
    );
}

fn parse_args() -> Result<Option<Args>, String> {
    let argv: Vec<String> = env::args().collect();
    let program = argv.first().map_or("systemd-sysctl", String::as_str);
    let mut out = Args::default();
    let mut i = 1usize;

    while i < argv.len() {
        let arg = &argv[i];
        match arg.as_str() {
            "-h" | "--help" => {
                print_help(program);
                return Ok(None);
            }
            "--version" => {
                println!("{VERSION}");
                return Ok(None);
            }
            "--cat-config" => out.cat_config = true,
            "--tldr" => out.tldr = true,
            "--no-pager" => {}
            "--strict" => out.strict = true,
            "--inline" => out.inline = true,
            "--prefix" => {
                i += 1;
                let value = argv
                    .get(i)
                    .ok_or_else(|| "--prefix requires an argument".to_string())?;
                out.prefixes.push(normalize_prefix(value)?);
            }
            "--" => {
                out.positional.extend(argv[i + 1..].iter().cloned());
                break;
            }
            _ if arg.starts_with("--prefix=") => {
                let value = &arg["--prefix=".len()..];
                if value.is_empty() {
                    return Err("--prefix requires a non-empty argument".to_string());
                }
                out.prefixes.push(normalize_prefix(value)?);
            }
            _ if arg.starts_with('-') => return Err(format!("unknown option: {arg}")),
            _ => out.positional.push(arg.clone()),
        }
        i += 1;
    }

    if (out.cat_config || out.tldr) && !out.positional.is_empty() {
        return Err("positional arguments are not allowed with --cat-config/--tldr".to_string());
    }

    Ok(Some(out))
}

fn normalize_prefix(value: &str) -> Result<String, String> {
    let mut v = value.trim().to_string();
    if let Some(rest) = v.strip_prefix("/proc/sys/") {
        v = rest.to_string();
    } else if v == "/proc/sys" {
        v.clear();
    }
    normalize_key(&v)
}

fn normalize_key(raw: &str) -> Result<String, String> {
    let mut s = raw.trim().to_string();
    if let Some(rest) = s.strip_prefix("/proc/sys/") {
        s = rest.to_string();
    }

    let first_sep = s
        .char_indices()
        .find(|(_, c)| *c == '/' || *c == '.')
        .map(|(_, c)| c);
    if first_sep == Some('.') {
        s = s
            .chars()
            .map(|c| match c {
                '.' => '/',
                '/' => '.',
                other => other,
            })
            .collect();
    }

    while s.starts_with('/') {
        s.remove(0);
    }

    let mut parts = Vec::new();
    for component in Path::new(&s).components() {
        match component {
            Component::Normal(part) => parts.push(part.to_string_lossy().into_owned()),
            Component::CurDir => {}
            Component::ParentDir => return Err(format!("invalid sysctl path: {raw}")),
            Component::RootDir | Component::Prefix(_) => {}
        }
    }
    Ok(parts.join("/"))
}

fn has_glob(s: &str) -> bool {
    s.bytes().any(|b| matches!(b, b'*' | b'?' | b'['))
}

fn parse_config_line(line: &str) -> Result<Option<SysctlOption>, String> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
        return Ok(None);
    }

    let (ignore_failure, body) = if let Some(rest) = trimmed.strip_prefix('-') {
        (true, rest.trim_start())
    } else {
        (false, trimmed)
    };

    if let Some((key, value)) = body.split_once('=') {
        let key = normalize_key(key.trim())?;
        if key.is_empty() {
            return Err("empty sysctl key".to_string());
        }
        return Ok(Some(SysctlOption {
            key,
            value: Some(value.trim().to_string()),
            ignore_failure,
        }));
    }

    if ignore_failure {
        let key = normalize_key(body.trim())?;
        if key.is_empty() {
            return Err("empty sysctl exclusion".to_string());
        }
        return Ok(Some(SysctlOption {
            key,
            value: None,
            ignore_failure: false,
        }));
    }

    Err(format!("line is not an assignment, ignoring: {trimmed}"))
}

fn logical_lines(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut pending = String::new();

    for physical in input.lines() {
        let trailing = physical.trim_end();
        let continued = trailing.ends_with('\\');
        let piece = if continued {
            &trailing[..trailing.len().saturating_sub(1)]
        } else {
            physical
        };

        if !pending.is_empty() {
            pending.push(' ');
        }
        pending.push_str(piece.trim());

        if !continued {
            out.push(std::mem::take(&mut pending));
        }
    }
    if !pending.is_empty() {
        out.push(pending);
    }
    out
}

fn add_option(options: &mut Vec<SysctlOption>, option: SysctlOption) {
    if let Some(index) = options.iter().position(|old| old.key == option.key) {
        if options[index].value == option.value {
            options[index].ignore_failure |= option.ignore_failure;
            return;
        }
        options.remove(index);
    }
    options.push(option);
}

fn parse_text(
    name: &str,
    text: &str,
    prefixes: &[String],
    options: &mut Vec<SysctlOption>,
) -> bool {
    let mut ok = true;
    for (index, line) in logical_lines(text).iter().enumerate() {
        match parse_config_line(line) {
            Ok(Some(option)) => {
                if !has_glob(&option.key) && !prefix_matches(&option.key, prefixes) {
                    continue;
                }
                add_option(options, option);
            }
            Ok(None) => {}
            Err(error) => {
                eprintln!("{name}:{}: {error}", index + 1);
                ok = false;
            }
        }
    }
    ok
}

fn parse_file(
    path: &Path,
    ignore_enoent: bool,
    prefixes: &[String],
    options: &mut Vec<SysctlOption>,
) -> io::Result<bool> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(parse_text(
            &path.display().to_string(),
            &text,
            prefixes,
            options,
        )),
        Err(error) if ignore_enoent && error.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error),
    }
}

fn config_files() -> io::Result<Vec<PathBuf>> {
    let mut selected: BTreeMap<String, PathBuf> = BTreeMap::new();

    // Earlier directories have higher precedence. Selecting by basename first
    // and iterating the BTreeMap later reproduces systemd's lexical ordering.
    for directory in CONF_DIRS {
        let entries = match fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.extension() != Some(OsStr::new("conf")) {
                continue;
            }
            let Some(name) = path.file_name().and_then(OsStr::to_str) else {
                continue;
            };
            selected.entry(name.to_string()).or_insert(path);
        }
    }

    Ok(selected.into_values().collect())
}

fn show_config(files: &[PathBuf], tldr: bool) -> io::Result<()> {
    for path in files {
        let text = fs::read_to_string(path)?;
        println!("# {}", path.display());
        if tldr {
            for line in logical_lines(&text) {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                    continue;
                }
                println!("{line}");
            }
        } else {
            print!("{text}");
            if !text.ends_with('\n') {
                println!();
            }
        }
    }
    Ok(())
}

fn prefix_matches(key: &str, prefixes: &[String]) -> bool {
    prefixes.is_empty()
        || prefixes.iter().any(|prefix| {
            prefix.is_empty() || key == prefix || key.starts_with(&format!("{prefix}/"))
        })
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    wildcard_match_bytes(pattern.as_bytes(), value.as_bytes())
}

fn wildcard_match_bytes(pattern: &[u8], value: &[u8]) -> bool {
    if pattern.is_empty() {
        return value.is_empty();
    }

    match pattern[0] {
        b'*' => {
            wildcard_match_bytes(&pattern[1..], value)
                || (!value.is_empty()
                    && value[0] != b'/'
                    && wildcard_match_bytes(pattern, &value[1..]))
        }
        b'?' => {
            !value.is_empty()
                && value[0] != b'/'
                && wildcard_match_bytes(&pattern[1..], &value[1..])
        }
        b'[' => match_class(pattern, value),
        literal => {
            !value.is_empty()
                && literal == value[0]
                && wildcard_match_bytes(&pattern[1..], &value[1..])
        }
    }
}

fn match_class(pattern: &[u8], value: &[u8]) -> bool {
    if value.is_empty() || value[0] == b'/' {
        return false;
    }
    let Some(close) = pattern.iter().position(|b| *b == b']') else {
        return pattern[0] == value[0] && wildcard_match_bytes(&pattern[1..], &value[1..]);
    };
    if close <= 1 {
        return false;
    }

    let class = &pattern[1..close];
    let negated = class
        .first()
        .is_some_and(|byte| matches!(*byte, b'!' | b'^'));
    let class = if negated { &class[1..] } else { class };
    let mut matched = false;
    let mut i = 0usize;
    while i < class.len() {
        if i + 2 < class.len() && class[i + 1] == b'-' {
            matched |= (class[i]..=class[i + 2]).contains(&value[0]);
            i += 3;
        } else {
            matched |= class[i] == value[0];
            i += 1;
        }
    }

    if matched == negated {
        return false;
    }
    wildcard_match_bytes(&pattern[close + 1..], &value[1..])
}

fn walk_proc_sys(directory: &Path, root: &Path, out: &mut Vec<String>) -> io::Result<()> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return Ok(()),
        Err(error) => return Err(error),
    };
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            walk_proc_sys(&path, root, out)?;
        } else if file_type.is_file() {
            if let Ok(relative) = path.strip_prefix(root) {
                out.push(relative.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    Ok(())
}

fn errno_is_write_refused(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(1 | 13 | 30))
}

fn write_sysctl(key: &str, value: &str) -> io::Result<()> {
    let path = Path::new(PROC_SYS).join(key);
    let mut file = OpenOptions::new().write(true).open(path)?;
    file.write_all(value.as_bytes())?;
    Ok(())
}

fn apply_one(key: &str, value: &str, ignore_failure: bool, strict: bool) -> bool {
    match write_sysctl(key, value) {
        Ok(()) => true,
        Err(error) => {
            let ignore = ignore_failure
                || (!strict && errno_is_write_refused(&error))
                || (!strict && error.kind() == io::ErrorKind::NotFound);
            if ignore {
                eprintln!("Couldn't write '{value}' to '{key}', ignoring: {error}");
                true
            } else {
                eprintln!("Couldn't write '{value}' to '{key}': {error}");
                false
            }
        }
    }
}

fn apply(options: &[SysctlOption], prefixes: &[String], strict: bool) -> bool {
    let explicit: HashSet<&str> = options.iter().map(|option| option.key.as_str()).collect();
    let mut all_keys = Vec::new();
    let mut keys_loaded = false;
    let mut ok = true;

    for option in options {
        let Some(value) = option.value.as_deref() else {
            continue;
        };

        if !has_glob(&option.key) {
            if prefix_matches(&option.key, prefixes) {
                ok &= apply_one(&option.key, value, option.ignore_failure, strict);
            }
            continue;
        }

        if !keys_loaded {
            if let Err(error) =
                walk_proc_sys(Path::new(PROC_SYS), Path::new(PROC_SYS), &mut all_keys)
            {
                if option.ignore_failure || error.kind() == io::ErrorKind::PermissionDenied {
                    eprintln!(
                        "Failed to enumerate sysctls for '{}', ignoring: {error}",
                        option.key
                    );
                } else {
                    eprintln!("Failed to enumerate sysctls for '{}': {error}", option.key);
                    ok = false;
                }
            }
            all_keys.sort();
            keys_loaded = true;
        }

        let mut matched = false;
        for key in &all_keys {
            if !wildcard_match(&option.key, key) || !prefix_matches(key, prefixes) {
                continue;
            }
            matched = true;
            if explicit.contains(key.as_str()) {
                continue;
            }
            ok &= apply_one(key, value, option.ignore_failure, strict);
        }
        if !matched {
            // v261 treats a glob with no matches as non-fatal.
        }
    }

    ok
}

fn read_credential(options: &mut Vec<SysctlOption>, prefixes: &[String]) -> bool {
    let Some(dir) = env::var_os("CREDENTIALS_DIRECTORY") else {
        return true;
    };
    let path = PathBuf::from(dir).join("sysctl.extra");
    match parse_file(&path, true, prefixes, options) {
        Ok(ok) => ok,
        Err(error) => {
            eprintln!("Failed to read {}: {error}", path.display());
            false
        }
    }
}

fn run(args: Args) -> i32 {
    let mut options = Vec::new();
    let mut ok = true;

    if !args.positional.is_empty() {
        for (position, item) in args.positional.iter().enumerate() {
            if args.inline {
                ok &= parse_text(
                    &format!("(argument):{}", position + 1),
                    item,
                    &args.prefixes,
                    &mut options,
                );
            } else {
                let path = Path::new(item);
                match parse_file(path, false, &args.prefixes, &mut options) {
                    Ok(parsed) => ok &= parsed,
                    Err(error) => {
                        eprintln!("Failed to read {}: {error}", path.display());
                        ok = false;
                    }
                }
            }
        }
    } else {
        let files = match config_files() {
            Ok(files) => files,
            Err(error) => {
                eprintln!("Failed to enumerate sysctl.d files: {error}");
                return 1;
            }
        };

        if args.cat_config || args.tldr {
            return match show_config(&files, args.tldr) {
                Ok(()) => 0,
                Err(error) => {
                    eprintln!("Failed to show configuration: {error}");
                    1
                }
            };
        }

        for path in files {
            match parse_file(&path, true, &args.prefixes, &mut options) {
                Ok(parsed) => ok &= parsed,
                Err(error) => {
                    eprintln!("Failed to read {}: {error}", path.display());
                    ok = false;
                }
            }
        }
        ok &= read_credential(&mut options, &args.prefixes);
    }

    ok &= apply(&options, &args.prefixes, args.strict);
    if ok {
        0
    } else {
        1
    }
}

fn main() {
    let code = match parse_args() {
        Ok(Some(args)) => run(args),
        Ok(None) => 0,
        Err(error) => {
            eprintln!("systemd-sysctl: {error}");
            1
        }
    };
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_dot_and_slash_syntax_like_systemd() {
        assert_eq!(
            normalize_key("net.ipv4.ip_forward").unwrap(),
            "net/ipv4/ip_forward"
        );
        assert_eq!(
            normalize_key("net/ipv4/conf/eth0.100/rp_filter").unwrap(),
            "net/ipv4/conf/eth0.100/rp_filter"
        );
        assert_eq!(
            normalize_key("/proc/sys/kernel/domainname").unwrap(),
            "kernel/domainname"
        );
        assert!(normalize_key("kernel/../passwd").is_err());
    }

    #[test]
    fn parses_assignment_ignore_and_negative_match() {
        assert_eq!(
            parse_config_line("-net.ipv4.ip_forward = 1").unwrap(),
            Some(SysctlOption {
                key: "net/ipv4/ip_forward".into(),
                value: Some("1".into()),
                ignore_failure: true,
            })
        );
        assert_eq!(
            parse_config_line("-net/ipv4/conf/lo/rp_filter").unwrap(),
            Some(SysctlOption {
                key: "net/ipv4/conf/lo/rp_filter".into(),
                value: None,
                ignore_failure: false,
            })
        );
    }

    #[test]
    fn later_assignment_replaces_and_moves_to_end() {
        let mut entries = vec![
            SysctlOption {
                key: "a".into(),
                value: Some("1".into()),
                ignore_failure: false,
            },
            SysctlOption {
                key: "b".into(),
                value: Some("2".into()),
                ignore_failure: false,
            },
        ];
        add_option(
            &mut entries,
            SysctlOption {
                key: "a".into(),
                value: Some("3".into()),
                ignore_failure: false,
            },
        );
        assert_eq!(entries[0].key, "b");
        assert_eq!(entries[1].value.as_deref(), Some("3"));
    }

    #[test]
    fn glob_matching_does_not_cross_path_components() {
        assert!(wildcard_match(
            "net/ipv4/conf/*/rp_filter",
            "net/ipv4/conf/eth0/rp_filter"
        ));
        assert!(!wildcard_match(
            "net/ipv4/conf/*/rp_filter",
            "net/ipv4/conf/a/b/rp_filter"
        ));
        assert!(wildcard_match("kernel/[a-z]*", "kernel/domainname"));
    }

    #[test]
    fn prefix_filter_is_component_aware() {
        let prefixes = vec!["net/ipv4".to_string()];
        assert!(prefix_matches("net/ipv4/ip_forward", &prefixes));
        assert!(!prefix_matches("net/ipv40/value", &prefixes));
    }
}
