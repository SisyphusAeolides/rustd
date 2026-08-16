// SPDX-License-Identifier: LGPL-2.1-or-later
//! `RustD` binary-format registration utility.

use std::collections::BTreeMap;
use std::env;
use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const VERSION: &str = "rustd 0.1.0";
const BINFMT_DIR: &str = "/proc/sys/fs/binfmt_misc";
const CONF_DIRS: [&str; 4] = [
    "/etc/binfmt.d",
    "/run/binfmt.d",
    "/usr/local/lib/binfmt.d",
    "/usr/lib/binfmt.d",
];

#[derive(Default)]
struct Args {
    cat_config: bool,
    tldr: bool,
    unregister: bool,
    files: Vec<String>,
}

fn help(program: &str) {
    println!(
        "{program} [OPTIONS...] [CONFIGURATION FILE...]\n\n\
         Registers binary formats with the kernel.\n\n\
         Options:\n\
           -h --help          Show this help\n\
              --version       Show package version\n\
              --cat-config    Show configuration files instead of applying\n\
              --tldr          Show configuration without comments/empty lines\n\
              --no-pager      Do not pipe output into a pager\n\
              --unregister    Unregister all existing entries"
    );
}

fn parse_args() -> Result<Option<Args>, String> {
    let argv: Vec<String> = env::args().collect();
    let program = argv.first().map_or("rustd-binfmt", String::as_str);
    let mut args = Args::default();
    let mut options = true;

    for arg in argv.iter().skip(1) {
        if options && arg == "--" {
            options = false;
        } else if options && matches!(arg.as_str(), "-h" | "--help") {
            help(program);
            return Ok(None);
        } else if options && arg == "--version" {
            println!("{VERSION}");
            return Ok(None);
        } else if options && arg == "--cat-config" {
            args.cat_config = true;
        } else if options && arg == "--tldr" {
            args.tldr = true;
        } else if options && arg == "--no-pager" {
        } else if options && arg == "--unregister" {
            args.unregister = true;
        } else if options && arg.starts_with('-') {
            return Err(format!("unknown option: {arg}"));
        } else {
            args.files.push(arg.clone());
        }
    }

    if (args.unregister || args.cat_config || args.tldr) && !args.files.is_empty() {
        return Err(
            "positional arguments are not allowed with --cat-config/--tldr or --unregister"
                .to_string(),
        );
    }
    Ok(Some(args))
}

fn conf_files() -> io::Result<Vec<PathBuf>> {
    let mut selected: BTreeMap<String, PathBuf> = BTreeMap::new();
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

fn resolve_named_config(name: &str) -> Option<PathBuf> {
    let direct = Path::new(name);
    if direct.is_absolute() || direct.components().count() > 1 {
        return direct.exists().then(|| direct.to_path_buf());
    }
    for directory in CONF_DIRS {
        let candidate = Path::new(directory).join(name);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

fn write_control(path: &Path, value: &str) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).open(path)?;
    file.write_all(value.as_bytes())
}

fn mounted_and_writable() -> bool {
    let register = Path::new(BINFMT_DIR).join("register");
    OpenOptions::new().write(true).open(register).is_ok()
}

fn valid_rule_name(name: &str) -> bool {
    !name.is_empty()
        && name != "register"
        && name != "status"
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.bytes().any(|b| b == 0)
}

fn rule_name(rule: &str) -> Result<&str, String> {
    let mut chars = rule.char_indices();
    let Some((_, delimiter)) = chars.next() else {
        return Err("empty binfmt rule".to_string());
    };
    let rest = &rule[delimiter.len_utf8()..];
    let Some(end) = rest.find(delimiter) else {
        return Err("rule has no terminating name delimiter".to_string());
    };
    let name = &rest[..end];
    if !valid_rule_name(name) {
        return Err(format!("rule name '{name}' is not valid, refusing"));
    }
    Ok(name)
}

fn apply_rule(filename: &str, line: usize, rule: &str) -> bool {
    let name = match rule_name(rule) {
        Ok(name) => name,
        Err(error) => {
            eprintln!("{filename}:{line}: {error}");
            return false;
        }
    };

    let existing = Path::new(BINFMT_DIR).join(name);
    if let Err(error) = write_control(&existing, "-1") {
        if error.kind() != io::ErrorKind::NotFound {
            eprintln!("{filename}:{line}: Failed to delete rule '{name}', ignoring: {error}");
        }
    }

    let register = Path::new(BINFMT_DIR).join("register");
    match write_control(&register, rule) {
        Ok(()) => true,
        Err(error) => {
            eprintln!("{filename}:{line}: Failed to add binary format '{name}': {error}");
            false
        }
    }
}

fn apply_file(path: &Path, ignore_enoent: bool) -> bool {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if ignore_enoent && error.kind() == io::ErrorKind::NotFound => return true,
        Err(error) => {
            eprintln!("Failed to open file '{}': {error}", path.display());
            return false;
        }
    };

    let mut ok = true;
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        ok &= apply_rule(&path.display().to_string(), index + 1, line);
    }
    ok
}

fn show_config(files: &[PathBuf], tldr: bool) -> io::Result<()> {
    for path in files {
        let text = fs::read_to_string(path)?;
        println!("# {}", path.display());
        if tldr {
            for line in text.lines() {
                let line = line.trim();
                if !line.is_empty() && !line.starts_with('#') && !line.starts_with(';') {
                    println!("{line}");
                }
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

fn unregister_all() -> bool {
    match write_control(&Path::new(BINFMT_DIR).join("status"), "-1") {
        Ok(()) => true,
        Err(error) => {
            eprintln!("Failed to unregister binary formats: {error}");
            false
        }
    }
}

fn run(args: Args) -> i32 {
    if args.unregister {
        return i32::from(!unregister_all());
    }

    let files = if args.files.is_empty() {
        match conf_files() {
            Ok(files) => files,
            Err(error) => {
                eprintln!("Failed to enumerate binfmt.d files: {error}");
                return 1;
            }
        }
    } else {
        let mut files = Vec::new();
        for name in &args.files {
            let Some(path) = resolve_named_config(name) else {
                eprintln!("Failed to open file '{name}': No such file or directory");
                return 1;
            };
            files.push(path);
        }
        files
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

    if !mounted_and_writable() {
        return 0;
    }

    let mut ok = true;
    if args.files.is_empty() {
        if let Err(error) = write_control(&Path::new(BINFMT_DIR).join("status"), "-1") {
            eprintln!("Failed to flush binfmt_misc rules, ignoring: {error}");
        }
    }

    for file in files {
        ok &= apply_file(&file, args.files.is_empty());
    }
    i32::from(!ok)
}

fn main() {
    let code = match parse_args() {
        Ok(Some(args)) => run(args),
        Ok(None) => 0,
        Err(error) => {
            eprintln!("rustd-binfmt: {error}");
            1
        }
    };
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_rule_name() {
        assert_eq!(
            rule_name(":qemu-aarch64:M::\\x7fELF::/usr/bin/qemu-aarch64:"),
            Ok("qemu-aarch64")
        );
        assert!(rule_name(":register:M::x::/bin/x:").is_err());
        assert!(rule_name(":bad/name:M::x::/bin/x:").is_err());
    }
}
