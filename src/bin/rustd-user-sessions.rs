// SPDX-License-Identifier: LGPL-2.1-or-later
//! `systemd-user-sessions` v261 compatibility helper.

use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const NOLOGIN_MESSAGE: &[u8] = b"System is going down. Unprivileged users are not permitted to log in anymore. For technical details, see pam_nologin(8).\n";
const EROFS: i32 = 30;
static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn main() {
    let arguments: Vec<OsString> = env::args_os().collect();
    if let Err(error) = run(&arguments) {
        let _ = io::stderr().lock().write_all(&error);
        std::process::exit(1);
    }
}

fn run(arguments: &[OsString]) -> Result<(), Vec<u8>> {
    if arguments.len() != 2 {
        return Err(b"This program requires one argument.\n".to_vec());
    }

    let path = env::var_os("RUSTD_USER_SESSIONS_NOLOGIN")
        .map_or_else(|| PathBuf::from("/run/nologin"), PathBuf::from);
    match arguments[1].as_os_str().as_bytes() {
        b"start" => remove_nologin(&path),
        b"stop" => create_nologin(&path),
        verb => {
            let mut error = b"Unknown verb '".to_vec();
            error.extend_from_slice(verb);
            error.extend_from_slice(b"'.\n");
            Err(error)
        }
    }
}

fn remove_nologin(path: &Path) -> Result<(), Vec<u8>> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) if error.raw_os_error() == Some(EROFS) && !path.exists() => Ok(()),
        Err(error) => {
            let mut message = b"Failed to remove \"".to_vec();
            message.extend_from_slice(path.as_os_str().as_bytes());
            message.extend_from_slice(b"\": ");
            message.extend_from_slice(io_error_text(&error).as_bytes());
            message.push(b'\n');
            Err(message)
        }
    }
}

fn create_nologin(path: &Path) -> Result<(), Vec<u8>> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().unwrap_or_else(|| OsStr::new("nologin"));
    let mut last_error = None;

    for _ in 0..128 {
        let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let mut temporary_name = b".".to_vec();
        temporary_name.extend_from_slice(file_name.as_bytes());
        temporary_name
            .extend_from_slice(format!(".rustd-{}-{sequence}", std::process::id()).as_bytes());
        let temporary = parent.join(OsStr::from_bytes(&temporary_name));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o666)
            .open(&temporary)
        {
            Ok(mut file) => {
                let guard = TemporaryFile::new(temporary.clone());
                let result = (|| {
                    file.set_permissions(fs::Permissions::from_mode(0o644))?;
                    file.write_all(NOLOGIN_MESSAGE)?;
                    drop(file);
                    fs::rename(&temporary, path)
                })();
                if let Err(error) = result {
                    return Err(create_error(path, &error));
                }
                guard.keep();
                return Ok(());
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                last_error = Some(error);
            }
            Err(error) => return Err(create_error(path, &error)),
        }
    }

    Err(create_error(
        path,
        &last_error.unwrap_or_else(|| io::Error::from(io::ErrorKind::AlreadyExists)),
    ))
}

fn create_error(path: &Path, error: &io::Error) -> Vec<u8> {
    let mut message = b"Failed to create ".to_vec();
    message.extend_from_slice(path.as_os_str().as_bytes());
    message.extend_from_slice(b": ");
    message.extend_from_slice(io_error_text(error).as_bytes());
    message.push(b'\n');
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
    fn exact_shutdown_message_includes_a_newline() {
        assert_eq!(NOLOGIN_MESSAGE.len(), 121);
        assert!(NOLOGIN_MESSAGE.ends_with(b"pam_nologin(8).\n"));
    }
}
