// SPDX-License-Identifier: LGPL-2.1-or-later
//! Login manager daemon: native `io.rustd.Login1` plus `org.freedesktop.login1`
//! bus ownership for desktop stacks.

#![allow(clippy::unused_self, clippy::needless_pass_by_value)]

use std::collections::{HashMap, HashSet};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use rustd::logind::{self, Session};
use zbus::interface;
use zbus::zvariant::OwnedObjectPath;

const NATIVE_BUS_NAME: &str = "io.rustd.Login1";
const COMPAT_BUS_NAME: &str = "org.freedesktop.login1";
const NATIVE_ROOT: &str = "/io/rustd/Login1";
const COMPAT_ROOT: &str = "/org/freedesktop/login1";

fn path(path: String) -> zbus::fdo::Result<OwnedObjectPath> {
    OwnedObjectPath::try_from(path).map_err(|error| zbus::fdo::Error::Failed(error.to_string()))
}

fn dbus_error(error: std::io::Error) -> zbus::fdo::Error {
    zbus::fdo::Error::Failed(error.to_string())
}

struct InhibitorEntry {
    what: String,
    who: String,
    why: String,
    mode: String,
    uid: u32,
    pid: u32,
    watch: OwnedFd,
}

#[derive(Default)]
struct Manager {
    next_inhibitor: AtomicU64,
    inhibitors: Arc<Mutex<HashMap<u64, InhibitorEntry>>>,
}

fn reap_inhibitors(map: &mut HashMap<u64, InhibitorEntry>) {
    map.retain(|_, entry| {
        let mut buffer = [0u8; 1];
        let result = unsafe {
            libc::recv(
                entry.watch.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                1,
                libc::MSG_DONTWAIT | libc::MSG_PEEK,
            )
        };
        !(result == 0
            || (result < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EBADF)))
    });
}

fn set_locked(id: &str, locked: bool) -> zbus::fdo::Result<()> {
    let mut sessions = logind::sessions();
    if let Some(session) = sessions.iter_mut().find(|session| session.id == id) {
        session.locked = locked;
        Ok(())
    } else {
        Err(zbus::fdo::Error::Failed("No such session".into()))
    }
}

impl Manager {
    fn ensure_shutdown_allowed(&self) -> zbus::fdo::Result<()> {
        let mut map = self
            .inhibitors
            .lock()
            .map_err(|_| zbus::fdo::Error::Failed("inhibitor lock poisoned".into()))?;
        reap_inhibitors(&mut map);
        let blockers: Vec<String> = map
            .values()
            .filter(|entry| entry.mode == "block")
            .filter(|entry| {
                entry
                    .what
                    .split(':')
                    .any(|token| token == "shutdown" || token == "handle-power-key")
            })
            .map(|entry| format!("{}:{} ({})", entry.who, entry.why, entry.what))
            .collect();
        if blockers.is_empty() {
            Ok(())
        } else {
            Err(zbus::fdo::Error::Failed(format!(
                "operation inhibited by {}",
                blockers.join("; ")
            )))
        }
    }

    async fn call_manager_method(&self, method: &str) -> zbus::fdo::Result<()> {
        let connection = zbus::Connection::system()
            .await
            .map_err(|error| zbus::fdo::Error::Failed(error.to_string()))?;
        connection
            .call_method(
                Some("io.rustd.Manager1"),
                "/io/rustd/Manager1",
                Some("io.rustd.Manager1.Manager"),
                method,
                &(),
            )
            .await
            .map_err(|error| zbus::fdo::Error::Failed(error.to_string()))?;
        Ok(())
    }
}

#[interface(name = "org.freedesktop.login1.Manager")]
impl Manager {
    fn get_session(&self, id: String) -> zbus::fdo::Result<OwnedObjectPath> {
        if logind::sessions().iter().any(|session| session.id == id) {
            path(logind::session_path(&id))
        } else {
            Err(zbus::fdo::Error::Failed("No such session".into()))
        }
    }

    fn list_sessions(&self) -> Vec<(String, u32, String, String, OwnedObjectPath)> {
        logind::sessions()
            .into_iter()
            .filter_map(|session| {
                path(logind::session_path(&session.id)).ok().map(|object| {
                    (
                        session.id.clone(),
                        session.uid,
                        session.user.clone(),
                        session.seat.clone(),
                        object,
                    )
                })
            })
            .collect()
    }

    fn list_users(&self) -> Vec<(u32, String, OwnedObjectPath)> {
        let mut seen = HashMap::new();
        for session in logind::sessions() {
            seen.entry(session.uid)
                .or_insert_with(|| session.user.clone());
        }
        seen.into_iter()
            .filter_map(|(uid, user)| {
                path(logind::user_path(uid))
                    .ok()
                    .map(|object| (uid, user, object))
            })
            .collect()
    }

    fn list_seats(&self) -> Vec<(String, OwnedObjectPath)> {
        let mut seats = HashSet::new();
        for session in logind::sessions() {
            seats.insert(session.seat.clone());
        }
        seats
            .into_iter()
            .filter_map(|seat| {
                path(logind::seat_path(&seat))
                    .ok()
                    .map(|object| (seat, object))
            })
            .collect()
    }

    fn activate_session(&self, id: String) -> zbus::fdo::Result<()> {
        if logind::sessions().iter().any(|session| session.id == id) {
            Ok(())
        } else {
            Err(zbus::fdo::Error::Failed("No such session".into()))
        }
    }

    fn lock_session(&self, id: String) -> zbus::fdo::Result<()> {
        set_locked(&id, true)
    }
    fn unlock_session(&self, id: String) -> zbus::fdo::Result<()> {
        set_locked(&id, false)
    }

    async fn inhibit(
        &self,
        what: String,
        who: String,
        why: String,
        mode: String,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
    ) -> zbus::fdo::Result<zbus::zvariant::OwnedFd> {
        if what.trim().is_empty() {
            return Err(zbus::fdo::Error::InvalidArgs(
                "inhibitor 'what' must not be empty".into(),
            ));
        }
        if mode != "block" && mode != "delay" {
            return Err(zbus::fdo::Error::InvalidArgs(
                "inhibitor mode must be 'block' or 'delay'".into(),
            ));
        }

        let mut uid = unsafe { libc::getuid() } as u32;
        let mut pid = unsafe { libc::getpid() } as u32;
        if let Some(sender) = header.sender() {
            if let Ok(dbus) = zbus::fdo::DBusProxy::new(connection).await {
                let name = zbus::names::BusName::Unique(sender.clone());
                if let Ok(value) = dbus.get_connection_unix_user(name.clone()).await {
                    uid = value;
                }
                if let Ok(value) = dbus.get_connection_unix_process_id(name).await {
                    pid = value;
                }
            }
        }

        let mut fds = [0i32; 2];
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(dbus_error(std::io::Error::last_os_error()));
        }
        let watch = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let client = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        let id = self.next_inhibitor.fetch_add(1, Ordering::Relaxed);
        let mut map = self
            .inhibitors
            .lock()
            .map_err(|_| zbus::fdo::Error::Failed("inhibitor lock poisoned".into()))?;
        reap_inhibitors(&mut map);
        map.insert(
            id,
            InhibitorEntry {
                what,
                who,
                why,
                mode,
                uid,
                pid,
                watch,
            },
        );
        Ok(zbus::zvariant::OwnedFd::from(client))
    }

    #[allow(clippy::type_complexity)]
    fn list_inhibitors(
        &self,
    ) -> zbus::fdo::Result<Vec<(String, String, String, String, u32, u32)>> {
        let mut map = self
            .inhibitors
            .lock()
            .map_err(|_| zbus::fdo::Error::Failed("inhibitor lock poisoned".into()))?;
        reap_inhibitors(&mut map);
        Ok(map
            .values()
            .map(|entry| {
                (
                    entry.what.clone(),
                    entry.who.clone(),
                    entry.why.clone(),
                    entry.mode.clone(),
                    entry.uid,
                    entry.pid,
                )
            })
            .collect())
    }

    fn can_power_off(&self) -> &'static str {
        "yes"
    }
    fn can_reboot(&self) -> &'static str {
        "yes"
    }
    fn can_suspend(&self) -> &'static str {
        "na"
    }
    fn can_hibernate(&self) -> &'static str {
        "na"
    }

    async fn power_off(&self, interactive: bool) -> zbus::fdo::Result<()> {
        let _ = interactive;
        self.ensure_shutdown_allowed()?;
        self.call_manager_method("PowerOff").await
    }

    async fn reboot(&self, interactive: bool) -> zbus::fdo::Result<()> {
        let _ = interactive;
        self.ensure_shutdown_allowed()?;
        self.call_manager_method("Reboot").await
    }

    fn prepare_for_shutdown(&self, active: bool) {
        let _ = active;
    }
    fn prepare_for_sleep(&self, active: bool) {
        let _ = active;
    }
}

struct SessionObject {
    id: String,
}

#[interface(name = "org.freedesktop.login1.Session")]
impl SessionObject {
    #[zbus(property)]
    fn id(&self) -> &str {
        &self.id
    }
    #[zbus(property)]
    fn user(&self) -> (u32, OwnedObjectPath) {
        let session = logind::sessions()
            .into_iter()
            .find(|session| session.id == self.id);
        match session {
            Some(Session { uid, .. }) => (
                uid,
                path(logind::user_path(uid)).unwrap_or_else(|_| OwnedObjectPath::default()),
            ),
            None => (0, OwnedObjectPath::default()),
        }
    }
    #[zbus(property)]
    fn name(&self) -> String {
        logind::sessions()
            .into_iter()
            .find(|session| session.id == self.id)
            .map(|session| session.user)
            .unwrap_or_default()
    }
    #[zbus(property)]
    fn timestamp(&self) -> u64 {
        0
    }
    #[zbus(property)]
    fn timestamp_monotonic(&self) -> u64 {
        0
    }
    #[zbus(property)]
    fn vt_nr(&self) -> u32 {
        logind::sessions()
            .into_iter()
            .find(|session| session.id == self.id)
            .and_then(|session| {
                session
                    .tty
                    .strip_prefix("tty")
                    .and_then(|value| value.parse().ok())
            })
            .unwrap_or(0)
    }
    #[zbus(property)]
    fn seat(&self) -> (String, OwnedObjectPath) {
        let seat = logind::sessions()
            .into_iter()
            .find(|session| session.id == self.id)
            .map(|session| session.seat)
            .unwrap_or_else(|| "seat0".into());
        (
            seat.clone(),
            path(logind::seat_path(&seat)).unwrap_or_else(|_| OwnedObjectPath::default()),
        )
    }
    #[zbus(property)]
    fn tty(&self) -> String {
        String::new()
    }
    #[zbus(property)]
    fn display(&self) -> String {
        String::new()
    }
    #[zbus(property)]
    fn remote(&self) -> bool {
        false
    }
    #[zbus(property)]
    fn remote_host(&self) -> String {
        String::new()
    }
    #[zbus(property)]
    fn remote_user(&self) -> String {
        String::new()
    }
    #[zbus(property)]
    fn service(&self) -> String {
        String::new()
    }
    #[zbus(property)]
    fn desktop(&self) -> String {
        String::new()
    }
    #[zbus(property)]
    fn scope(&self) -> String {
        String::new()
    }
    #[zbus(property)]
    fn leader(&self) -> u32 {
        0
    }
    #[zbus(property)]
    fn audit(&self) -> u32 {
        0
    }
    #[zbus(property)]
    fn type_(&self) -> String {
        logind::sessions()
            .into_iter()
            .find(|session| session.id == self.id)
            .map(|session| session.session_type)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "tty".into())
    }
    #[zbus(property)]
    fn class(&self) -> String {
        logind::sessions()
            .into_iter()
            .find(|session| session.id == self.id)
            .map(|session| session.class)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "user".into())
    }
    #[zbus(property)]
    fn active(&self) -> bool {
        true
    }
    #[zbus(property)]
    fn state(&self) -> &'static str {
        "active"
    }
    #[zbus(property)]
    fn idle_hint(&self) -> bool {
        false
    }
    #[zbus(property)]
    fn idle_since_hint(&self) -> u64 {
        0
    }
    #[zbus(property)]
    fn idle_since_hint_monotonic(&self) -> u64 {
        0
    }
    #[zbus(property)]
    fn locked_hint(&self) -> bool {
        logind::sessions()
            .into_iter()
            .find(|session| session.id == self.id)
            .map(|session| session.locked)
            .unwrap_or(false)
    }
    fn activate(&self) -> zbus::fdo::Result<()> {
        Ok(())
    }
    fn lock(&self) -> zbus::fdo::Result<()> {
        set_locked(&self.id, true)
    }
    fn unlock(&self) -> zbus::fdo::Result<()> {
        set_locked(&self.id, false)
    }
    fn terminate(&self) -> zbus::fdo::Result<()> {
        Ok(())
    }
}

struct UserObject {
    uid: u32,
}

#[interface(name = "org.freedesktop.login1.User")]
impl UserObject {
    #[zbus(property)]
    fn uid(&self) -> u32 {
        self.uid
    }
    #[zbus(property)]
    fn name(&self) -> String {
        passwd_name(self.uid).unwrap_or_default()
    }
    #[zbus(property)]
    fn runtime_path(&self) -> String {
        format!("/run/user/{}", self.uid)
    }
    #[zbus(property)]
    fn service(&self) -> String {
        format!("user@{}.service", self.uid)
    }
    #[zbus(property)]
    fn slice(&self) -> String {
        format!("user-{}.slice", self.uid)
    }
    #[zbus(property)]
    fn display(&self) -> (String, OwnedObjectPath) {
        (
            String::new(),
            OwnedObjectPath::try_from("/").unwrap_or_default(),
        )
    }
    #[zbus(property)]
    fn state(&self) -> &'static str {
        "active"
    }
    #[zbus(property)]
    fn sessions(&self) -> Vec<(String, OwnedObjectPath)> {
        logind::sessions()
            .into_iter()
            .filter(|session| session.uid == self.uid)
            .filter_map(|session| {
                path(logind::session_path(&session.id))
                    .ok()
                    .map(|object| (session.id, object))
            })
            .collect()
    }
    #[zbus(property)]
    fn idle_hint(&self) -> bool {
        false
    }
    #[zbus(property)]
    fn idle_since_hint(&self) -> u64 {
        0
    }
    #[zbus(property)]
    fn idle_since_hint_monotonic(&self) -> u64 {
        0
    }
    #[zbus(property)]
    fn linger(&self) -> bool {
        false
    }
    fn terminate(&self) -> zbus::fdo::Result<()> {
        Ok(())
    }
    fn kill(&self, signal: i32) -> zbus::fdo::Result<()> {
        let _ = signal;
        Ok(())
    }
}

struct SeatObject {
    id: String,
}

#[interface(name = "org.freedesktop.login1.Seat")]
impl SeatObject {
    #[zbus(property)]
    fn id(&self) -> &str {
        &self.id
    }
    #[zbus(property)]
    fn active_session(&self) -> (String, OwnedObjectPath) {
        (
            String::new(),
            OwnedObjectPath::try_from("/").unwrap_or_default(),
        )
    }
    #[zbus(property)]
    fn can_tty(&self) -> bool {
        true
    }
    #[zbus(property)]
    fn can_graphical(&self) -> bool {
        true
    }
    #[zbus(property)]
    fn sessions(&self) -> Vec<(String, OwnedObjectPath)> {
        logind::sessions()
            .into_iter()
            .filter(|s| s.seat == self.id)
            .filter_map(|s| {
                path(logind::session_path(&s.id))
                    .ok()
                    .map(|object| (s.id, object))
            })
            .collect()
    }
}

fn passwd_name(uid: u32) -> Option<String> {
    std::fs::read_to_string("/etc/passwd")
        .ok()?
        .lines()
        .find_map(|line| {
            let mut fields = line.split(':');
            let name = fields.next()?;
            fields
                .nth(1)?
                .parse::<u32>()
                .ok()
                .filter(|value| *value == uid)
                .map(|_| name.to_owned())
        })
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    logind::prepare()?;
    let connection = zbus::Connection::system().await?;
    let inhibitors = Arc::new(Mutex::new(HashMap::new()));
    let compat_manager = Manager {
        next_inhibitor: AtomicU64::new(0),
        inhibitors: Arc::clone(&inhibitors),
    };
    let native_manager = Manager {
        next_inhibitor: AtomicU64::new(0),
        inhibitors,
    };
    connection
        .object_server()
        .at(COMPAT_ROOT, compat_manager)
        .await?;
    connection
        .object_server()
        .at(NATIVE_ROOT, native_manager)
        .await?;
    for session in logind::sessions() {
        connection
            .object_server()
            .at(
                logind::session_path(&session.id),
                SessionObject {
                    id: session.id.clone(),
                },
            )
            .await?;
        let _ = connection
            .object_server()
            .at(
                logind::user_path(session.uid),
                UserObject { uid: session.uid },
            )
            .await;
        let _ = connection
            .object_server()
            .at(
                logind::seat_path(&session.seat),
                SeatObject {
                    id: session.seat.clone(),
                },
            )
            .await;
    }
    connection.request_name(COMPAT_BUS_NAME).await?;
    connection.request_name(NATIVE_BUS_NAME).await?;
    rustd::native::notify_ready()?;
    std::future::pending::<()>().await;
    Ok(())
}
