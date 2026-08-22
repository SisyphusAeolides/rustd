// SPDX-License-Identifier: LGPL-2.1-or-later
//! Runtime session records used by the `RustD` logind compatibility service.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const RUNTIME_ROOT: &str = "/run/rustd";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Session {
    pub id: String,
    pub uid: u32,
    pub user: String,
    pub gid: u32,
    pub seat: String,
    pub tty: String,
    pub service: String,
    pub session_type: String,
    pub class: String,
    pub desktop: String,
    pub display: String,
    pub remote: bool,
    pub remote_user: String,
    pub remote_host: String,
    pub leader: u32,
    pub state: String,
    pub locked: bool,
}

#[must_use]
pub fn root() -> PathBuf {
    std::env::var_os("RUSTD_LOGIND_RUNTIME")
        .map_or_else(|| PathBuf::from(RUNTIME_ROOT), PathBuf::from)
}

fn directory(kind: &str) -> PathBuf {
    root().join(kind)
}

fn parse(path: &Path) -> BTreeMap<String, String> {
    fs::read_to_string(path).map_or_else(
        |_| BTreeMap::new(),
        |text| {
            text.lines()
                .filter_map(|line| line.split_once('='))
                .map(|(key, value)| (key.trim().to_owned(), value.trim().to_owned()))
                .collect()
        },
    )
}

fn atomic_write(path: &Path, text: &str) -> io::Result<()> {
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    fs::write(&tmp, text)?;
    fs::rename(tmp, path)
}

impl Session {
    fn from_map(id: String, values: BTreeMap<String, String>) -> Self {
        Self {
            uid: values
                .get("UID")
                .and_then(|value| value.parse().ok())
                .unwrap_or(0),
            gid: values
                .get("GID")
                .and_then(|value| value.parse().ok())
                .unwrap_or(0),
            leader: values
                .get("LEADER")
                .and_then(|value| value.parse().ok())
                .unwrap_or(0),
            user: values.get("USER").cloned().unwrap_or_default(),
            seat: values
                .get("SEAT")
                .cloned()
                .unwrap_or_else(|| "seat0".into()),
            tty: values.get("TTY").cloned().unwrap_or_default(),
            service: values.get("SERVICE").cloned().unwrap_or_default(),
            session_type: values
                .get("TYPE")
                .cloned()
                .unwrap_or_else(|| "unspecified".into()),
            class: values
                .get("CLASS")
                .cloned()
                .unwrap_or_else(|| "user".into()),
            desktop: values.get("DESKTOP").cloned().unwrap_or_default(),
            display: values.get("DISPLAY").cloned().unwrap_or_default(),
            remote: values.get("REMOTE").is_some_and(|value| value == "yes"),
            remote_user: values.get("REMOTE_USER").cloned().unwrap_or_default(),
            remote_host: values.get("REMOTE_HOST").cloned().unwrap_or_default(),
            state: values
                .get("STATE")
                .cloned()
                .unwrap_or_else(|| "active".into()),
            locked: values.get("LOCKED").is_some_and(|value| value == "yes"),
            id,
        }
    }

    fn serialize(&self) -> String {
        format!(
            concat!(
                "UID={}\nGID={}\nUSER={}\nSEAT={}\nTTY={}\nSERVICE={}\n",
                "TYPE={}\nCLASS={}\nDESKTOP={}\nDISPLAY={}\nREMOTE={}\n",
                "REMOTE_USER={}\nREMOTE_HOST={}\nLEADER={}\nSTATE={}\nLOCKED={}\n"
            ),
            self.uid,
            self.gid,
            self.user,
            self.seat,
            self.tty,
            self.service,
            self.session_type,
            self.class,
            self.desktop,
            self.display,
            if self.remote { "yes" } else { "no" },
            self.remote_user,
            self.remote_host,
            self.leader,
            self.state,
            if self.locked { "yes" } else { "no" }
        )
    }
}

/// Ensure session/user/seat runtime directories exist.
///
/// # Errors
///
/// Returns an error when a runtime directory cannot be created.
pub fn prepare() -> io::Result<()> {
    for kind in ["sessions", "users", "seats"] {
        fs::create_dir_all(directory(kind))?;
    }
    Ok(())
}

/// Root directory for per-user runtime directories.
#[must_use]
pub fn user_runtime_root() -> PathBuf {
    std::env::var_os("RUSTD_USER_RUNTIME_ROOT")
        .map_or_else(|| PathBuf::from("/run/user"), PathBuf::from)
}

/// Securely create and own the XDG runtime directory for a login session.
///
/// # Errors
///
/// Returns an error when the runtime root cannot be created, either path is a
/// symlink or non-directory, permissions cannot be set, or ownership cannot be
/// established for the requested account.
pub fn prepare_user_runtime(uid: u32, gid: u32) -> io::Result<PathBuf> {
    let root = user_runtime_root();
    fs::create_dir_all(&root)?;
    let root_metadata = fs::symlink_metadata(&root)?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsafe user runtime root",
        ));
    }

    let path = root.join(uid.to_string());
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsafe user runtime path",
                ));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => fs::create_dir(&path)?,
        Err(error) => return Err(error),
    }

    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    let effective_uid = unsafe { libc::geteuid() };
    let effective_gid = unsafe { libc::getegid() };
    if effective_uid == 0 {
        let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "runtime path contains NUL")
        })?;
        if unsafe { libc::chown(c_path.as_ptr(), uid, gid) } != 0 {
            return Err(io::Error::last_os_error());
        }
    } else if uid != effective_uid || gid != effective_gid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unprivileged runtime ownership request",
        ));
    }

    let metadata = fs::symlink_metadata(&path)?;
    if metadata.uid() != uid || metadata.gid() != gid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "user runtime ownership mismatch",
        ));
    }
    Ok(path)
}

/// Load every session record under the logind runtime root.
#[must_use]
pub fn sessions() -> Vec<Session> {
    let mut result = fs::read_dir(directory("sessions"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            entry.file_type().ok().filter(std::fs::FileType::is_file)?;
            Some(Session::from_map(
                entry.file_name().to_string_lossy().into_owned(),
                parse(&entry.path()),
            ))
        })
        .collect::<Vec<_>>();
    result.sort_by(|left, right| left.id.cmp(&right.id));
    result
}

/// Load one session by id, if present.
#[must_use]
pub fn session(id: &str) -> Option<Session> {
    let path = directory("sessions").join(id);
    path.is_file()
        .then(|| Session::from_map(id.to_owned(), parse(&path)))
}

/// Persist a session record and refresh user/seat summaries.
///
/// # Errors
///
/// Returns an error when directories or session files cannot be written.
pub fn save(session: &Session) -> io::Result<()> {
    prepare()?;
    atomic_write(
        &directory("sessions").join(&session.id),
        &session.serialize(),
    )?;
    rebuild_summaries()
}

/// Remove a session record and refresh summaries.
///
/// # Errors
///
/// Returns an error when the session file cannot be removed or summaries
/// cannot be rewritten.
pub fn remove(id: &str) -> io::Result<()> {
    let path = directory("sessions").join(id);
    if path.exists() {
        fs::remove_file(path)?;
    }
    rebuild_summaries()
}

/// Rebuild `/run/rustd/users` and `/run/rustd/seats` from session files.
///
/// # Errors
///
/// Returns an error when summary directories or files cannot be rewritten.
pub fn rebuild_summaries() -> io::Result<()> {
    prepare()?;
    for kind in ["users", "seats"] {
        for entry in fs::read_dir(directory(kind))?.flatten() {
            if entry.file_type()?.is_file() {
                fs::remove_file(entry.path())?;
            }
        }
    }

    let all = sessions();
    let mut users = BTreeMap::<u32, Vec<&Session>>::new();
    let mut seats = BTreeMap::<String, Vec<&Session>>::new();
    for session in &all {
        users.entry(session.uid).or_default().push(session);
        seats.entry(session.seat.clone()).or_default().push(session);
    }

    for (uid, entries) in users {
        let Some(first) = entries.first() else {
            continue;
        };
        let ids = entries
            .iter()
            .map(|session| session.id.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        let runtime = user_runtime_root().join(uid.to_string());
        atomic_write(
            &directory("users").join(uid.to_string()),
            &format!(
                "UID={uid}\nGID={}\nUSER={}\nSTATE=active\nRUNTIME={}\nSESSIONS={ids}\n",
                first.gid,
                first.user,
                runtime.display()
            ),
        )?;
    }

    for (seat, entries) in seats {
        let Some(first) = entries.first() else {
            continue;
        };
        let ids = entries
            .iter()
            .map(|session| session.id.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        atomic_write(
            &directory("seats").join(&seat),
            &format!("ID={seat}\nACTIVE_SESSION={}\nSESSIONS={ids}\n", first.id),
        )?;
    }
    Ok(())
}

/// Escape a value for use in a D-Bus object path component.
#[must_use]
pub fn object_component(value: &str) -> String {
    value.bytes().fold(String::new(), |mut output, byte| {
        if byte.is_ascii_alphanumeric() || byte == b'_' {
            output.push(byte as char);
        } else {
            use std::fmt::Write;
            let _ = write!(output, "_{byte:02x}");
        }
        output
    })
}

/// D-Bus object path for a session id.
#[must_use]
pub fn session_path(id: &str) -> String {
    format!("/io/rustd/Login1/session/{}", object_component(id))
}

/// D-Bus object path for a user id.
#[must_use]
pub fn user_path(uid: u32) -> String {
    format!("/io/rustd/Login1/user/{uid}")
}

/// D-Bus object path for a seat id.
#[must_use]
pub fn seat_path(id: &str) -> String {
    format!("/io/rustd/Login1/seat/{}", object_component(id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENVIRONMENT: Mutex<()> = Mutex::new(());

    #[test]
    fn user_runtime_and_session_metadata_round_trip() {
        let _guard = ENVIRONMENT.lock().expect("environment lock");
        let runtime = tempfile::tempdir().expect("temporary runtime root");
        let user_runtime = runtime.path().join("users");
        std::env::set_var("RUSTD_USER_RUNTIME_ROOT", &user_runtime);
        std::env::set_var("RUSTD_LOGIND_RUNTIME", runtime.path().join("logind"));

        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        let path = prepare_user_runtime(uid, gid).expect("create user runtime");
        assert_eq!(path, user_runtime.join(uid.to_string()));
        assert_eq!(
            fs::metadata(&path)
                .expect("runtime metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );

        let expected = Session {
            id: "r-test".to_owned(),
            uid,
            user: "test-user".to_owned(),
            gid,
            seat: "seat0".to_owned(),
            tty: "tty2".to_owned(),
            service: "login".to_owned(),
            session_type: "tty".to_owned(),
            class: "user".to_owned(),
            desktop: "console".to_owned(),
            display: ":0".to_owned(),
            remote: true,
            remote_user: "remote-user".to_owned(),
            remote_host: "example.test".to_owned(),
            leader: std::process::id(),
            state: "active".to_owned(),
            locked: false,
        };
        save(&expected).expect("save session");
        assert_eq!(session(&expected.id), Some(expected));

        std::env::remove_var("RUSTD_USER_RUNTIME_ROOT");
        std::env::remove_var("RUSTD_LOGIND_RUNTIME");
    }
}
