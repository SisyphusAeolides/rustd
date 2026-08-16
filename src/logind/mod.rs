// SPDX-License-Identifier: LGPL-2.1-or-later
//! Runtime session records used by the RustD logind compatibility service.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub const RUNTIME_ROOT: &str = "/run/rustd";

#[derive(Clone, Debug, Default)]
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
    pub leader: u32,
    pub state: String,
    pub locked: bool,
}

#[must_use]
pub fn root() -> PathBuf {
    std::env::var_os("RUSTD_LOGIND_RUNTIME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(RUNTIME_ROOT))
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
            uid: values.get("UID").and_then(|v| v.parse().ok()).unwrap_or(0),
            gid: values.get("GID").and_then(|v| v.parse().ok()).unwrap_or(0),
            leader: values
                .get("LEADER")
                .and_then(|v| v.parse().ok())
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
            state: values
                .get("STATE")
                .cloned()
                .unwrap_or_else(|| "active".into()),
            locked: values.get("LOCKED").is_some_and(|v| v == "yes"),
            id,
        }
    }

    fn serialize(&self) -> String {
        format!(
            "UID={}\nGID={}\nUSER={}\nSEAT={}\nTTY={}\nSERVICE={}\nTYPE={}\nCLASS={}\nLEADER={}\nSTATE={}\nLOCKED={}\n",
            self.uid, self.gid, self.user, self.seat, self.tty, self.service,
            self.session_type, self.class, self.leader, self.state,
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
        let first = entries[0];
        let ids = entries
            .iter()
            .map(|s| s.id.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        atomic_write(
            &directory("users").join(uid.to_string()),
            &format!(
            "UID={uid}\nGID={}\nUSER={}\nSTATE=active\nRUNTIME=/run/user/{uid}\nSESSIONS={ids}\n",
            first.gid, first.user
        ),
        )?;
    }
    for (seat, entries) in seats {
        let ids = entries
            .iter()
            .map(|s| s.id.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        atomic_write(
            &directory("seats").join(&seat),
            &format!(
                "ID={seat}\nACTIVE_SESSION={}\nSESSIONS={ids}\n",
                entries[0].id
            ),
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
    format!("/org/freedesktop/login1/session/{}", object_component(id))
}

/// D-Bus object path for a user id.
#[must_use]
pub fn user_path(uid: u32) -> String {
    format!("/org/freedesktop/login1/user/{uid}")
}

/// D-Bus object path for a seat id.
#[must_use]
pub fn seat_path(id: &str) -> String {
    format!("/org/freedesktop/login1/seat/{}", object_component(id))
}
