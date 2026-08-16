// SPDX-License-Identifier: LGPL-2.1-or-later
//! `RustD` kernel module loader.

use std::collections::{BTreeMap, HashSet};
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

const VERSION: &str = "RustD 0.1.0";
const MODULE_NAME_MAX: usize = 4096;
const CONF_DIRS: [&str; 4] = [
    "/etc/modules-load.d",
    "/run/modules-load.d",
    "/usr/local/lib/modules-load.d",
    "/usr/lib/modules-load.d",
];

fn help(program: &str) {
    println!(
        "{program} [OPTIONS...] [CONFIGURATION FILE...]\n\n\
         Loads statically configured kernel modules for RustD.\n\n\
         Options:\n\
           -h --help      Show this help\n\
              --version   Show package version"
    );
}

fn parse_args() -> Result<Option<Vec<String>>, String> {
    let argv: Vec<String> = env::args().collect();
    let program = argv.first().map_or("rustd-modules-load", String::as_str);
    let mut positional = Vec::new();
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
        } else if options && arg.starts_with('-') {
            return Err(format!("unknown option: {arg}"));
        } else {
            positional.push(arg.clone());
        }
    }

    Ok(Some(positional))
}

fn canonical_module_name(raw: &str) -> Result<String, String> {
    let module = raw.trim();
    if module.len() > MODULE_NAME_MAX {
        return Err(format!(
            "module name max length exceeded ({MODULE_NAME_MAX}): {module}"
        ));
    }
    if module.is_empty() || module.bytes().any(|b| b == 0 || b.is_ascii_whitespace()) {
        return Err(format!("invalid module name: {module:?}"));
    }
    Ok(module.replace('-', "_"))
}

fn enqueue(modules: &mut Vec<String>, seen: &mut HashSet<String>, raw: &str) -> bool {
    match canonical_module_name(raw) {
        Ok(module) => {
            if seen.insert(module.clone()) {
                modules.push(module);
            }
            true
        }
        Err(error) => {
            eprintln!("{error}");
            false
        }
    }
}

fn parse_module_file(
    path: &Path,
    modules: &mut Vec<String>,
    seen: &mut HashSet<String>,
) -> io::Result<bool> {
    let text = fs::read_to_string(path)?;
    let mut ok = true;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        ok &= enqueue(modules, seen, line);
    }
    Ok(ok)
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

fn find_named_config(name: &str) -> Option<PathBuf> {
    let direct = Path::new(name);
    if direct.components().count() > 1 || direct.is_absolute() {
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

fn kernel_cmdline_modules(modules: &mut Vec<String>, seen: &mut HashSet<String>) -> bool {
    let text = match fs::read_to_string("/proc/cmdline") {
        Ok(text) => text,
        Err(error) => {
            eprintln!("Failed to parse kernel command line, ignoring: {error}");
            return true;
        }
    };

    let mut ok = true;
    for field in text.split_whitespace() {
        let Some((key, value)) = field.split_once('=') else {
            continue;
        };
        if key != "modules_load" && key != "rd.modules_load" {
            continue;
        }
        for module in value.split(',').filter(|m| !m.is_empty()) {
            ok &= enqueue(modules, seen, module);
        }
    }
    ok
}

fn modprobe_program() -> &'static str {
    for candidate in ["/usr/bin/modprobe", "/usr/sbin/modprobe", "/sbin/modprobe"] {
        if Path::new(candidate).exists() {
            return candidate;
        }
    }
    "modprobe"
}

fn load_module(module: &str) -> bool {
    let status = Command::new(modprobe_program()).arg(module).status();
    match status {
        Ok(status) if status.success() => true,
        Ok(status) => {
            // A missing module is intentionally non-fatal during early boot.
            // A modprobe exit status alone cannot distinguish it reliably, so
            // preserve boot robustness while still reporting the failed probe.
            eprintln!("Failed to insert module '{module}' (exit status {status})");
            true
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            eprintln!("Failed to initialize module loader: {error}");
            false
        }
        Err(error) => {
            eprintln!("Failed to insert module '{module}': {error}");
            false
        }
    }
}

fn run(files: &[String]) -> i32 {
    let mut modules = Vec::new();
    let mut seen = HashSet::new();
    let mut ok = kernel_cmdline_modules(&mut modules, &mut seen);

    if files.is_empty() {
        match conf_files() {
            Ok(paths) => {
                for path in paths {
                    match parse_module_file(&path, &mut modules, &mut seen) {
                        Ok(parsed) => ok &= parsed,
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                        Err(error) => {
                            eprintln!("Failed to open {}: {error}", path.display());
                            ok = false;
                        }
                    }
                }
            }
            Err(error) => {
                eprintln!("Failed to enumerate modules-load.d files: {error}");
                ok = false;
            }
        }
    } else {
        for file in files {
            let Some(path) = find_named_config(file) else {
                eprintln!("Failed to open {file}: No such file or directory");
                ok = false;
                continue;
            };
            match parse_module_file(&path, &mut modules, &mut seen) {
                Ok(parsed) => ok &= parsed,
                Err(error) => {
                    eprintln!("Failed to open {}: {error}", path.display());
                    ok = false;
                }
            }
        }
    }

    // Probe in deterministic order while preserving deduplication and
    // dash-to-underscore normalization semantics.
    for module in modules {
        ok &= load_module(&module);
    }

    i32::from(!ok)
}

fn main() {
    let code = match parse_args() {
        Ok(Some(files)) => run(&files),
        Ok(None) => 0,
        Err(error) => {
            eprintln!("rustd-modules-load: {error}");
            1
        }
    };
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_name_is_canonicalized() {
        assert_eq!(
            canonical_module_name("nf-conntrack").unwrap(),
            "nf_conntrack"
        );
        assert!(canonical_module_name("bad module").is_err());
    }

    #[test]
    fn duplicate_spellings_collapse() {
        let mut modules = Vec::new();
        let mut seen = HashSet::new();
        assert!(enqueue(&mut modules, &mut seen, "nf-conntrack"));
        assert!(enqueue(&mut modules, &mut seen, "nf_conntrack"));
        assert_eq!(modules, vec!["nf_conntrack"]);
    }
}
