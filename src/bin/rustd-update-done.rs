// SPDX-License-Identifier: LGPL-2.1-or-later
//! `systemd-update-done` v261 compatibility helper.

use std::collections::VecDeque;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, DirBuilder, FileTimes, OpenOptions};
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::UNIX_EPOCH;

const HELP: &str = concat!(
    "systemd-update-done [OPTIONS...]\n\n",
    "Mark /etc/ and /var/ as fully updated.\n\n",
    "Options:\n",
    "  -h --help      Show this help\n",
    "     --version   Show package version\n",
    "     --root=PATH Operate on root directory PATH\n\n",
    "See the systemd-update-done(8) man page for details.\n"
);
const VERSION: &str = concat!(
    "systemd 261 (261.2-1-arch)\n",
    "+PAM +AUDIT -SELINUX +APPARMOR -IMA +IPE +SMACK +SECCOMP +GCRYPT +GNUTLS +OPENSSL +ACL ",
    "+BLKID +CURL +ELFUTILS +FIDO2 +IDN2 +KMOD +LIBCRYPTSETUP +LIBCRYPTSETUP_PLUGINS +LIBFDISK ",
    "+PCRE2 +PWQUALITY +P11KIT +QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB +ZSTD +BPF_FRAMEWORK +BTF ",
    "+XKBCOMMON +UTMP +LIBARCHIVE\n"
);
static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

enum ParseResult {
    Run(Option<PathBuf>),
    Exit(&'static str),
}

fn main() {
    let arguments: Vec<OsString> = env::args_os().skip(1).collect();
    let result = match parse_options(&arguments) {
        Ok(ParseResult::Exit(output)) => io::stdout()
            .lock()
            .write_all(output.as_bytes())
            .map_err(|error| error.to_string().into_bytes()),
        Ok(ParseResult::Run(root)) => run(root.as_deref()),
        Err(error) => Err(error),
    };
    if let Err(error) = result {
        let mut stderr = io::stderr().lock();
        let _ = stderr.write_all(&error);
        let _ = stderr.write_all(b"\n");
        std::process::exit(1);
    }
}

fn parse_options(arguments: &[OsString]) -> Result<ParseResult, Vec<u8>> {
    let mut root = None;
    let mut positionals = 0_usize;
    let mut parse_options = true;
    let mut index = 0_usize;
    while index < arguments.len() {
        let argument = arguments[index].as_os_str().as_bytes();
        if !parse_options || argument == b"-" || !argument.starts_with(b"-") {
            positionals += 1;
            index += 1;
            continue;
        }
        if argument == b"--" {
            parse_options = false;
            index += 1;
            continue;
        }
        if let Some(long) = argument.strip_prefix(b"--") {
            let (name, attached) = long
                .iter()
                .position(|byte| *byte == b'=')
                .map_or((long, None), |position| {
                    (&long[..position], Some(&long[position + 1..]))
                });
            let matches: Vec<&[u8]> = [
                b"help".as_slice(),
                b"version".as_slice(),
                b"root".as_slice(),
            ]
            .into_iter()
            .filter(|option| option.starts_with(name))
            .collect();
            match matches.as_slice() {
                [b"help" | b"version"] if attached.is_some() => {
                    return Err(option_error(
                        b"option '--",
                        name,
                        b"' doesn't allow an argument",
                    ));
                }
                [b"help"] => return Ok(ParseResult::Exit(HELP)),
                [b"version"] => return Ok(ParseResult::Exit(VERSION)),
                [b"root"] => {
                    let value = if let Some(value) = attached {
                        OsStr::from_bytes(value)
                    } else {
                        index += 1;
                        arguments.get(index).map_or_else(
                            || Err(option_error(b"option '--", name, b"' requires an argument")),
                            |value| Ok(value.as_os_str()),
                        )?
                    };
                    root = parse_root(value)?;
                }
                [] => return Err(option_error(b"unrecognized option '--", name, b"'")),
                _ => {
                    return Err(option_error(
                        b"option '--",
                        name,
                        b"' is ambiguous; possibilities: --help, --version, --root",
                    ));
                }
            }
            index += 1;
            continue;
        }
        if let Some(option) = argument.get(1) {
            if *option == b'h' {
                return Ok(ParseResult::Exit(HELP));
            }
            return Err(option_error(b"unrecognized option '-", &[*option], b"'"));
        }
        index += 1;
    }
    if positionals > 0 {
        return Err(b"This program takes no arguments.".to_vec());
    }
    Ok(ParseResult::Run(root))
}

fn option_error(prefix: &[u8], option: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut error = b"systemd-update-done: ".to_vec();
    error.extend_from_slice(prefix);
    error.extend_from_slice(option);
    error.extend_from_slice(suffix);
    error
}

fn parse_root(value: &OsStr) -> Result<Option<PathBuf>, Vec<u8>> {
    if value.is_empty() {
        return Ok(None);
    }
    let path = Path::new(value);
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .map_err(|error| io_error(b"Failed to determine current directory: ", &error))?
            .join(path)
    };
    let normalized = normalize_absolute(&absolute);
    Ok((normalized != Path::new("/")).then_some(normalized))
}

fn normalize_absolute(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir => normalized = PathBuf::from("/"),
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(name) => normalized.push(name),
            Component::Prefix(_) => unreachable!("Unix paths have no prefix component"),
        }
    }
    normalized
}

fn run(root: Option<&Path>) -> Result<(), Vec<u8>> {
    let root_path = root.unwrap_or_else(|| Path::new("/"));
    let usr = resolve_rooted_directory(root_path, OsStr::new("usr"), false).map_err(|error| {
        path_error(
            b"Failed to stat ",
            &shown_directory(root, OsStr::new("usr")),
            &error,
        )
    })?;
    let metadata = fs::metadata(usr).map_err(|error| {
        path_error(
            b"Failed to stat ",
            &shown_directory(root, OsStr::new("usr")),
            &error,
        )
    })?;
    let timestamp = metadata.modified().map_err(|error| {
        path_error(
            b"Failed to stat ",
            &shown_directory(root, OsStr::new("usr")),
            &error,
        )
    })?;

    let mut errors = Vec::new();
    for directory in [OsStr::new("etc"), OsStr::new("var")] {
        if let Err(error) = save_timestamp(root_path, root, directory, timestamp) {
            errors.push(error);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        let mut combined = Vec::new();
        for (index, error) in errors.into_iter().enumerate() {
            if index > 0 {
                combined.push(b'\n');
            }
            combined.extend_from_slice(&error);
        }
        Err(combined)
    }
}

fn save_timestamp(
    root_path: &Path,
    shown_root: Option<&Path>,
    directory: &OsStr,
    timestamp: std::time::SystemTime,
) -> Result<(), Vec<u8>> {
    let shown = shown_directory(shown_root, directory);
    let resolved = resolve_rooted_directory(root_path, directory, true)
        .map_err(|error| path_error(b"Failed to open ", &shown, &error))?;
    let nanos = timestamp.duration_since(UNIX_EPOCH).map_err(|_| {
        let error = io::Error::new(io::ErrorKind::InvalidData, "Timestamp before UNIX epoch");
        path_error(b"Failed to write \"", &marker_path(&shown), &error)
    })?;
    let logical = if directory.as_bytes() == b"etc" {
        "/etc/"
    } else {
        "/var/"
    };
    let message = format!(
        "# This file was created by systemd-update-done. The timestamp below is the\n\
# modification time of /usr/ for which the most recent updates of {logical} have\n\
# been applied. See man:systemd-update-done.service(8) for details.\n\
TIMESTAMP_NSEC={}\n",
        nanos.as_nanos()
    );
    atomic_write(&resolved, timestamp, message.as_bytes())
        .map_err(|error| path_error(b"Failed to write \"", &marker_path(&shown), &error))
}

fn resolve_rooted_directory(root: &Path, name: &OsStr, create: bool) -> io::Result<PathBuf> {
    let mut pending = VecDeque::from([name.to_os_string()]);
    let mut relative: Vec<OsString> = Vec::new();
    let mut symlinks = 0_u8;
    while let Some(component) = pending.pop_front() {
        match Path::new(&component).components().next() {
            Some(Component::RootDir) => {
                relative.clear();
                continue;
            }
            Some(Component::CurDir) | None => continue,
            Some(Component::ParentDir) => {
                relative.pop();
                continue;
            }
            Some(Component::Normal(_)) => {}
            Some(Component::Prefix(_)) => unreachable!("Unix paths have no prefix component"),
        }

        let candidate = relative
            .iter()
            .fold(root.to_path_buf(), |path, item| path.join(item))
            .join(&component);
        match fs::symlink_metadata(&candidate) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                symlinks = symlinks.saturating_add(1);
                if symlinks > 40 {
                    return Err(io::Error::from_raw_os_error(libc::ELOOP));
                }
                let target = fs::read_link(&candidate)?;
                if target.is_absolute() {
                    relative.clear();
                }
                prepend_components(&mut pending, &target);
            }
            Ok(metadata) => {
                if !metadata.is_dir() {
                    return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
                }
                relative.push(component);
            }
            Err(error)
                if error.kind() == io::ErrorKind::NotFound && pending.is_empty() && create =>
            {
                DirBuilder::new().create(&candidate)?;
                relative.push(component);
            }
            Err(error) => return Err(error),
        }
    }
    Ok(relative
        .iter()
        .fold(root.to_path_buf(), |path, item| path.join(item)))
}

fn prepend_components(pending: &mut VecDeque<OsString>, path: &Path) {
    let components: Vec<OsString> = path
        .components()
        .map(|component| component.as_os_str().to_os_string())
        .collect();
    for component in components.into_iter().rev() {
        pending.push_front(component);
    }
}

fn atomic_write(
    directory: &Path,
    timestamp: std::time::SystemTime,
    bytes: &[u8],
) -> io::Result<()> {
    for _ in 0..128 {
        let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary =
            directory.join(format!(".#updated.rustd-{}-{sequence}", std::process::id()));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&temporary)
        {
            Ok(mut file) => {
                let guard = TemporaryFile::new(temporary.clone());
                file.write_all(bytes)?;
                file.set_times(
                    FileTimes::new()
                        .set_accessed(timestamp)
                        .set_modified(timestamp),
                )?;
                drop(file);
                fs::rename(&temporary, directory.join(".updated"))?;
                guard.keep();
                return Ok(());
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::from(io::ErrorKind::AlreadyExists))
}

fn shown_directory(root: Option<&Path>, directory: &OsStr) -> Vec<u8> {
    let mut shown = root.map_or_else(Vec::new, |path| path.as_os_str().as_bytes().to_vec());
    shown.push(b'/');
    shown.extend_from_slice(directory.as_bytes());
    shown.push(b'/');
    shown
}

fn marker_path(directory: &[u8]) -> Vec<u8> {
    let mut path = directory.to_vec();
    path.extend_from_slice(b".updated\"");
    path
}

fn path_error(prefix: &[u8], path: &[u8], error: &io::Error) -> Vec<u8> {
    let mut message = prefix.to_vec();
    message.extend_from_slice(path);
    message.extend_from_slice(b": ");
    message.extend_from_slice(io_error_text(error).as_bytes());
    message
}

fn io_error(prefix: &[u8], error: &io::Error) -> Vec<u8> {
    let mut message = prefix.to_vec();
    message.extend_from_slice(io_error_text(error).as_bytes());
    message
}

fn io_error_text(error: &io::Error) -> String {
    let text = error.to_string();
    text.rfind(" (os error ").map_or(text.clone(), |index| {
        if text.ends_with(')') {
            text[..index].to_owned()
        } else {
            text
        }
    })
}

struct TemporaryFile {
    path: PathBuf,
}

impl TemporaryFile {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn keep(mut self) {
        self.path.clear();
    }
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        if !self.path.as_os_str().is_empty() {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_normalization_never_traverses_above_root() {
        assert_eq!(
            normalize_absolute(Path::new("/a/../b/./c")),
            Path::new("/b/c")
        );
        assert_eq!(normalize_absolute(Path::new("/../../a")), Path::new("/a"));
    }
}
