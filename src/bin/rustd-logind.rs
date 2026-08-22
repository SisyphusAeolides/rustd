// SPDX-License-Identifier: LGPL-2.1-or-later
//! Login manager daemon: native `io.rustd.Login1` plus `org.freedesktop.login1`
//! bus ownership for desktop stacks.

#![allow(clippy::unused_self, clippy::needless_pass_by_value)]

use std::collections::{HashMap, HashSet};
use std::ffi::CStr;
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
static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);

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

struct Manager {
    next_inhibitor: AtomicU64,
    inhibitors: Arc<Mutex<HashMap<u64, InhibitorEntry>>>,
    session_refs: Arc<Mutex<HashMap<String, OwnedFd>>>,
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
    let mut session =
        logind::session(id).ok_or_else(|| zbus::fdo::Error::Failed("No such session".into()))?;
    session.locked = locked;
    logind::save(&session).map_err(dbus_error)
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
    #[allow(clippy::too_many_arguments)]
    async fn create_session(
        &self,
        uid: u32,
        pid: u32,
        service: String,
        type_: String,
        class: String,
        desktop: String,
        seat_id: String,
        vtnr: u32,
        tty: String,
        display: String,
        remote: bool,
        remote_user: String,
        remote_host: String,
        _properties: Vec<(String, zbus::zvariant::OwnedValue)>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<(
        String,
        OwnedObjectPath,
        String,
        zbus::zvariant::OwnedFd,
        u32,
        String,
        u32,
        bool,
    )> {
        let (user, gid) =
            passwd_record(uid).ok_or_else(|| zbus::fdo::Error::Failed("No such user".into()))?;
        let runtime = logind::prepare_user_runtime(uid, gid).map_err(dbus_error)?;
        let id = loop {
            let candidate = format!("r{}", NEXT_SESSION.fetch_add(1, Ordering::Relaxed));
            if logind::session(&candidate).is_none() {
                break candidate;
            }
        };
        let seat = if seat_id.is_empty() {
            "seat0".to_owned()
        } else {
            seat_id
        };
        let session = Session {
            id: id.clone(),
            uid,
            user,
            gid,
            seat: seat.clone(),
            tty,
            service,
            session_type: if type_.is_empty() {
                "unspecified".into()
            } else {
                type_
            },
            class: if class.is_empty() {
                "user".into()
            } else {
                class
            },
            desktop,
            display,
            remote,
            remote_user,
            remote_host,
            leader: pid,
            state: "active".into(),
            locked: false,
        };
        logind::save(&session).map_err(dbus_error)?;
        let object_path = path(logind::session_path(&id))?;
        connection
            .object_server()
            .at(logind::session_path(&id), SessionObject { id: id.clone() })
            .await
            .map_err(|error| zbus::fdo::Error::Failed(error.to_string()))?;
        let _ = connection
            .object_server()
            .at(logind::user_path(uid), UserObject { uid })
            .await;
        let _ = connection
            .object_server()
            .at(logind::seat_path(&seat), SeatObject { id: seat.clone() })
            .await;

        let mut fds = [0i32; 2];
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            let _ = logind::remove(&id);
            return Err(dbus_error(std::io::Error::last_os_error()));
        }
        let watch = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let client = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        self.session_refs
            .lock()
            .map_err(|_| zbus::fdo::Error::Failed("session reference lock poisoned".into()))?
            .insert(id.clone(), watch);
        Ok((
            id,
            object_path,
            runtime.to_string_lossy().into_owned(),
            zbus::zvariant::OwnedFd::from(client),
            uid,
            seat,
            vtnr,
            false,
        ))
    }

    fn release_session(&self, id: String) -> zbus::fdo::Result<()> {
        self.session_refs
            .lock()
            .map_err(|_| zbus::fdo::Error::Failed("session reference lock poisoned".into()))?
            .remove(&id);
        logind::remove(&id).map_err(dbus_error)
    }

    fn terminate_session(&self, id: String) -> zbus::fdo::Result<()> {
        self.release_session(id)
    }

    fn get_session(&self, id: String) -> zbus::fdo::Result<OwnedObjectPath> {
        if logind::session(&id).is_some() {
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
        if logind::session(&id).is_some() {
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
        match logind::session(&self.id) {
            Some(Session { uid, .. }) => (
                uid,
                path(logind::user_path(uid)).unwrap_or_else(|_| OwnedObjectPath::default()),
            ),
            None => (0, OwnedObjectPath::default()),
        }
    }

    #[zbus(property)]
    fn name(&self) -> String {
        logind::session(&self.id)
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
        logind::session(&self.id)
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
        let seat = logind::session(&self.id)
            .map(|session| session.seat)
            .unwrap_or_else(|| "seat0".into());
        (
            seat.clone(),
            path(logind::seat_path(&seat)).unwrap_or_else(|_| OwnedObjectPath::default()),
        )
    }

    #[zbus(property)]
    fn tty(&self) -> String {
        logind::session(&self.id)
            .map(|session| session.tty)
            .unwrap_or_default()
    }

    #[zbus(property)]
    fn display(&self) -> String {
        logind::session(&self.id)
            .map(|session| session.display)
            .unwrap_or_default()
    }

    #[zbus(property)]
    fn remote(&self) -> bool {
        logind::session(&self.id).is_some_and(|session| session.remote)
    }

    #[zbus(property)]
    fn remote_host(&self) -> String {
        logind::session(&self.id)
            .map(|session| session.remote_host)
            .unwrap_or_default()
    }

    #[zbus(property)]
    fn remote_user(&self) -> String {
        logind::session(&self.id)
            .map(|session| session.remote_user)
            .unwrap_or_default()
    }

    #[zbus(property)]
    fn service(&self) -> String {
        logind::session(&self.id)
            .map(|session| session.service)
            .unwrap_or_default()
    }

    #[zbus(property)]
    fn desktop(&self) -> String {
        logind::session(&self.id)
            .map(|session| session.desktop)
            .unwrap_or_default()
    }

    #[zbus(property)]
    fn scope(&self) -> String {
        format!("session-{}.scope", self.id)
    }

    #[zbus(property)]
    fn leader(&self) -> u32 {
        logind::session(&self.id).map_or(0, |session| session.leader)
    }

    #[zbus(property)]
    fn audit(&self) -> u32 {
        0
    }

    #[zbus(property)]
    fn type_(&self) -> String {
        logind::session(&self.id)
            .map(|session| session.session_type)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "tty".into())
    }

    #[zbus(property)]
    fn class(&self) -> String {
        logind::session(&self.id)
            .map(|session| session.class)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "user".into())
    }

    #[zbus(property)]
    fn active(&self) -> bool {
        logind::session(&self.id).is_some_and(|session| session.state == "active")
    }

    #[zbus(property)]
    fn state(&self) -> String {
        logind::session(&self.id)
            .map(|session| session.state)
            .unwrap_or_else(|| "closing".into())
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
        logind::session(&self.id).is_some_and(|session| session.locked)
    }

    fn activate(&self) -> zbus::fdo::Result<()> {
        if logind::session(&self.id).is_some() {
            Ok(())
        } else {
            Err(zbus::fdo::Error::Failed("No such session".into()))
        }
    }

    fn lock(&self) -> zbus::fdo::Result<()> {
        set_locked(&self.id, true)
    }

    fn unlock(&self) -> zbus::fdo::Result<()> {
        set_locked(&self.id, false)
    }

    fn terminate(&self) -> zbus::fdo::Result<()> {
        logind::remove(&self.id).map_err(dbus_error)
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
        logind::user_runtime_root()
            .join(self.uid.to_string())
            .to_string_lossy()
            .into_owned()
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
        let session = logind::sessions()
            .into_iter()
            .find(|session| session.uid == self.uid && !session.display.is_empty());
        match session {
            Some(session) => (
                session.id.clone(),
                path(logind::session_path(&session.id))
                    .unwrap_or_else(|_| OwnedObjectPath::default()),
            ),
            None => (
                String::new(),
                OwnedObjectPath::try_from("/").unwrap_or_default(),
            ),
        }
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
        for session in logind::sessions()
            .into_iter()
            .filter(|session| session.uid == self.uid)
        {
            logind::remove(&session.id).map_err(dbus_error)?;
        }
        Ok(())
    }

    fn kill(&self, signal: i32) -> zbus::fdo::Result<()> {
        for session in logind::sessions()
            .into_iter()
            .filter(|session| session.uid == self.uid && session.leader > 0)
        {
            if unsafe { libc::kill(session.leader as libc::pid_t, signal) } != 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ESRCH) {
                    return Err(dbus_error(error));
                }
            }
        }
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
        let session = logind::sessions()
            .into_iter()
            .find(|session| session.seat == self.id && session.state == "active");
        match session {
            Some(session) => (
                session.id.clone(),
                path(logind::session_path(&session.id))
                    .unwrap_or_else(|_| OwnedObjectPath::default()),
            ),
            None => (
                String::new(),
                OwnedObjectPath::try_from("/").unwrap_or_default(),
            ),
        }
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
            .filter(|session| session.seat == self.id)
            .filter_map(|session| {
                path(logind::session_path(&session.id))
                    .ok()
                    .map(|object| (session.id, object))
            })
            .collect()
    }
}

fn passwd_record(uid: u32) -> Option<(String, u32)> {
    let configured = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let mut size = usize::try_from(configured)
        .ok()
        .filter(|size| *size > 0)
        .unwrap_or(16 * 1024)
        .max(1024);

    loop {
        let mut record = unsafe { std::mem::zeroed::<libc::passwd>() };
        let mut result = std::ptr::null_mut();
        let mut buffer = vec![0u8; size];
        let status = unsafe {
            libc::getpwuid_r(
                uid,
                &mut record,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status == libc::ERANGE && size < 1024 * 1024 {
            size = size.saturating_mul(2);
            continue;
        }
        if status != 0 || result.is_null() || record.pw_name.is_null() {
            return None;
        }
        let name = unsafe { CStr::from_ptr(record.pw_name) }
            .to_string_lossy()
            .into_owned();
        return Some((name, record.pw_gid));
    }
}

fn passwd_name(uid: u32) -> Option<String> {
    passwd_record(uid).map(|(name, _)| name)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    logind::prepare()?;
    let connection = zbus::Connection::system().await?;
    let inhibitors = Arc::new(Mutex::new(HashMap::new()));
    let session_refs = Arc::new(Mutex::new(HashMap::new()));
    let compat_manager = Manager {
        next_inhibitor: AtomicU64::new(0),
        inhibitors: Arc::clone(&inhibitors),
        session_refs: Arc::clone(&session_refs),
    };
    let native_manager = Manager {
        next_inhibitor: AtomicU64::new(0),
        inhibitors,
        session_refs,
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
