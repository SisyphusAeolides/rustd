// SPDX-License-Identifier: LGPL-2.1-or-later

use std::collections::HashSet;
use std::env;
use std::ffi::CString;
use std::fs::{self, File};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

const LOADER_GUID: &str = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f";
const BOOT_COUNT_VARIABLE: &str = "LoaderBootCountPath";

#[derive(Clone, Debug, Eq, PartialEq)]
struct BootCounter {
    path: PathBuf,
    prefix: PathBuf,
    left: u64,
    done: u64,
    suffix: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mark {
    Good,
    Bad,
    Indeterminate,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rustd-bless-boot: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut paths = Vec::new();
    let mut command = None;
    let mut args = env::args().skip(1).peekable();

    while let Some(argument) = args.next() {
        match argument.as_str() {
            "-h" | "--help" => {
                print_help();
                return Ok(());
            }
            "--version" => {
                println!("RustD {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "--path" => {
                let value = args
                    .next()
                    .ok_or_else(|| String::from("--path requires an argument"))?;
                paths.push(PathBuf::from(value));
            }
            value if value.starts_with("--path=") => {
                paths.push(PathBuf::from(&value[7..]));
            }
            value if value.starts_with('-') => {
                return Err(format!("unknown option '{value}'"));
            }
            value => {
                if command.replace(value.to_owned()).is_some() || args.peek().is_some() {
                    return Err(String::from("too many command arguments"));
                }
            }
        }
    }

    if !Path::new("/sys/firmware/efi/efivars").is_dir() {
        return Err(String::from(
            "marking a boot is only supported on EFI systems",
        ));
    }
    if Path::new("/run/rustd/container").exists() || env::var_os("container").is_some() {
        return Err(String::from(
            "marking a boot is not supported in containers",
        ));
    }

    let command = command.as_deref().unwrap_or("status");
    let counter = match acquire_boot_counter() {
        Ok(counter) => counter,
        Err(error) if error.kind() == io::ErrorKind::NotFound && command == "status" => {
            println!("clean");
            return Ok(());
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(String::from("not booted with boot counting in effect"));
        }
        Err(error) => return Err(error.to_string()),
    };

    if paths.is_empty() {
        paths = discover_boot_paths();
    }
    if paths.is_empty() {
        return Err(String::from(
            "couldn't find $BOOT partition; use --path= to specify it",
        ));
    }

    match command {
        "status" => status(&paths, &counter),
        "good" => set_mark(&paths, &counter, Mark::Good),
        "bad" => set_mark(&paths, &counter, Mark::Bad),
        "indeterminate" => set_mark(&paths, &counter, Mark::Indeterminate),
        other => Err(format!("unknown command '{other}'")),
    }
}

fn print_help() {
    println!("rustd-bless-boot [OPTIONS...] COMMAND");
    println!();
    println!("Commands:");
    println!("  status          Show status of current boot loader entry");
    println!("  good            Mark this boot as good");
    println!("  bad             Mark this boot as bad");
    println!("  indeterminate   Undo a good/bad marking");
    println!();
    println!("Options:");
    println!("  -h, --help      Show this help");
    println!("      --version   Show package version");
    println!("      --path=PATH Path to a $BOOT partition; may be repeated");
}

fn acquire_boot_counter() -> io::Result<BootCounter> {
    let variable =
        Path::new("/sys/firmware/efi/efivars").join(format!("{BOOT_COUNT_VARIABLE}-{LOADER_GUID}"));
    let bytes = fs::read(variable)?;
    if bytes.len() < 6 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "LoaderBootCountPath EFI variable is too short",
        ));
    }

    let payload = &bytes[4..];
    if payload.len() % 2 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "LoaderBootCountPath EFI value is malformed UTF-16",
        ));
    }
    let mut words = Vec::with_capacity(payload.len() / 2);
    for pair in payload.chunks_exact(2) {
        let word = u16::from_le_bytes([pair[0], pair[1]]);
        if word == 0 {
            break;
        }
        words.push(word);
    }
    let mut path = String::from_utf16(&words).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "LoaderBootCountPath EFI value is not valid UTF-16",
        )
    })?;
    path = path.replace('\\', "/");
    parse_boot_counter(&path)
}

fn parse_boot_counter(value: &str) -> io::Result<BootCounter> {
    let path = PathBuf::from(value);
    if !path.is_absolute() || !is_normalized(&path) || path == Path::new("/") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "LoaderBootCountPath is not a normalized absolute file path",
        ));
    }
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "LoaderBootCountPath has no filename",
            )
        })?;
    let plus = filename.rfind('+').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "LoaderBootCountPath does not contain a boot counter",
        )
    })?;

    let counter_and_suffix = &filename[plus + 1..];
    let left_len = counter_and_suffix
        .bytes()
        .take_while(u8::is_ascii_digit)
        .count();
    if left_len == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "LoaderBootCountPath has an empty tries-left counter",
        ));
    }
    let left = counter_and_suffix[..left_len]
        .parse::<u64>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid tries-left counter"))?;

    let mut offset = left_len;
    let mut done = 0;
    if counter_and_suffix.as_bytes().get(offset) == Some(&b'-') {
        offset += 1;
        let done_len = counter_and_suffix[offset..]
            .bytes()
            .take_while(u8::is_ascii_digit)
            .count();
        if done_len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "LoaderBootCountPath has an empty tries-done counter",
            ));
        }
        done = counter_and_suffix[offset..offset + done_len]
            .parse::<u64>()
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid tries-done counter")
            })?;
        offset += done_len;
    }

    let suffix = counter_and_suffix[offset..].to_owned();
    let parent = path.parent().unwrap_or_else(|| Path::new("/"));
    let prefix_name = &filename[..plus];
    let prefix = parent.join(prefix_name);

    Ok(BootCounter {
        path,
        prefix,
        left,
        done,
        suffix,
    })
}

fn is_normalized(path: &Path) -> bool {
    path.components()
        .all(|component| !matches!(component, Component::CurDir | Component::ParentDir))
}

fn good_path(counter: &BootCounter) -> PathBuf {
    let mut bytes = counter.prefix.as_os_str().as_bytes().to_vec();
    bytes.extend_from_slice(counter.suffix.as_bytes());
    PathBuf::from(std::ffi::OsString::from_vec(bytes))
}

fn bad_path(counter: &BootCounter) -> PathBuf {
    let mut text = counter.prefix.as_os_str().to_string_lossy().into_owned();
    if counter.done == 0 {
        text.push_str("+0");
    } else {
        text.push_str(&format!("+0-{}", counter.done));
    }
    text.push_str(&counter.suffix);
    PathBuf::from(text)
}

fn discover_boot_paths() -> Vec<PathBuf> {
    let mut result = Vec::new();
    let mut devices = HashSet::new();
    for candidate in ["/boot", "/efi", "/boot/efi"] {
        let path = PathBuf::from(candidate);
        let Ok(metadata) = fs::metadata(&path) else {
            continue;
        };
        if !metadata.is_dir() || !devices.insert(metadata.dev()) {
            continue;
        }
        if path.join("loader").exists() || path.join("EFI").exists() {
            result.push(path);
        }
    }
    result
}

fn relative_boot_path(path: &Path) -> &Path {
    path.strip_prefix("/").unwrap_or(path)
}

fn status(paths: &[PathBuf], counter: &BootCounter) -> Result<(), String> {
    let good = good_path(counter);
    let bad = bad_path(counter);

    for root in paths {
        let current = root.join(relative_boot_path(&counter.path));
        if current.exists() {
            println!(
                "{}",
                if counter.left == 0 {
                    "dirty"
                } else {
                    "indeterminate"
                }
            );
            return Ok(());
        }
        if root.join(relative_boot_path(&good)).exists() {
            println!("good");
            return Ok(());
        }
        if root.join(relative_boot_path(&bad)).exists() {
            println!("bad");
            return Ok(());
        }
    }
    Err(String::from("couldn't determine boot state"))
}

fn set_mark(paths: &[PathBuf], counter: &BootCounter, mark: Mark) -> Result<(), String> {
    let good = good_path(counter);
    let bad = bad_path(counter);
    if mark == Mark::Indeterminate && counter.left == 0 {
        return Err(String::from(
            "current boot entry was already marked bad in a previous boot",
        ));
    }

    let (target, source1, source2) = match mark {
        Mark::Good => (&good, &counter.path, &bad),
        Mark::Bad => (&bad, &counter.path, &good),
        Mark::Indeterminate => (&counter.path, &good, &bad),
    };

    for root in paths {
        let target = root.join(relative_boot_path(target));
        let source1 = root.join(relative_boot_path(source1));
        let source2 = root.join(relative_boot_path(source2));

        match rename_idempotent(&source1, &target) {
            Ok(true) => return sync_and_finish(root, &target),
            Ok(false) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return Ok(()),
            Err(error) => return Err(format!("failed to rename {}: {error}", source1.display())),
        }
        match rename_idempotent(&source2, &target) {
            Ok(true) => return sync_and_finish(root, &target),
            Ok(false) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if target.exists() {
                    return Ok(());
                }
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return Ok(()),
            Err(error) => return Err(format!("failed to rename {}: {error}", source2.display())),
        }
    }

    Err(format!(
        "can't find boot counter source file for {}",
        target_name(mark)
    ))
}

fn target_name(mark: Mark) -> &'static str {
    match mark {
        Mark::Good => "good",
        Mark::Bad => "bad",
        Mark::Indeterminate => "indeterminate",
    }
}

fn rename_idempotent(from: &Path, to: &Path) -> io::Result<bool> {
    if from == to {
        fs::symlink_metadata(from)?;
        return Ok(false);
    }
    let from = CString::new(from.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "source path contains NUL"))?;
    let to = CString::new(to.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "target path contains NUL"))?;
    // SAFETY: both C strings remain valid for the complete native call.
    let result = unsafe { rustd::ffi::native::rustd_rename_noreplace(from.as_ptr(), to.as_ptr()) };
    if result < 0 {
        Err(io::Error::from_raw_os_error(-result))
    } else {
        Ok(true)
    }
}

fn sync_and_finish(root: &Path, target: &Path) -> Result<(), String> {
    if let Some(parent) = target.parent() {
        if let Ok(directory) = File::open(parent) {
            let _ = directory.sync_all();
        }
    }
    if let Ok(filesystem) = File::open(root) {
        // SAFETY: syncfs only borrows the open descriptor.
        let result = unsafe { libc::syncfs(filesystem.as_raw_fd()) };
        if result < 0 {
            let _ = io::Error::last_os_error();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_boot_counter() {
        let counter = parse_boot_counter("/EFI/Linux/example+3-2.efi").unwrap();
        assert_eq!(counter.left, 3);
        assert_eq!(counter.done, 2);
        assert_eq!(good_path(&counter), PathBuf::from("/EFI/Linux/example.efi"));
        assert_eq!(
            bad_path(&counter),
            PathBuf::from("/EFI/Linux/example+0-2.efi")
        );
    }

    #[test]
    fn parses_counter_without_done_component() {
        let counter = parse_boot_counter("/EFI/Linux/example+1.efi").unwrap();
        assert_eq!(counter.left, 1);
        assert_eq!(counter.done, 0);
        assert_eq!(
            bad_path(&counter),
            PathBuf::from("/EFI/Linux/example+0.efi")
        );
    }

    #[test]
    fn rejects_non_normalized_path() {
        assert!(parse_boot_counter("/EFI/../Linux/example+1.efi").is_err());
    }
}
