// SPDX-License-Identifier: LGPL-2.1-or-later
//! Login manager daemon: native `io.rustd.Login1` plus `org.freedesktop.login1`
//! bus ownership for desktop stacks.

#![allow(clippy::unused_self, clippy::needless_pass_by_value)]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::CStr;
use std::fs::{self, OpenOptions};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use rustd::logind::{self, Session};
use zbus::interface;
use zbus::zvariant::OwnedObjectPath;

const NATIVE_BUS_NAME: &str = "io.rustd.Login1";
const COMPAT_BUS_NAME: &str = "org.freedesktop.login1";
const NATIVE_ROOT: &str = "/io/rustd/Login1";
const COMPAT_ROOT: &str = "/org/freedesktop/login1";
const CREATE_SESSION_SIGNATURE: &str = "uusssssussbssa(sv)";
static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObjectNamespace {
    Native,
    Compatibility,
}

impl ObjectNamespace {
    const ALL: [Self; 2] = [Self::Native, Self::Compatibility];

    fn session_path(self, id: &str) -> String {
        match self {
            Self::Native => logind::session_path(id),
            Self::Compatibility => {
                format!("{COMPAT_ROOT}/session/{}", logind::object_component(id))
            }
        }
    }

    fn user_path(self, uid: u32) -> String {
        match self {
            Self::Native => logind::user_path(uid),
            Self::Compatibility => format!("{COMPAT_ROOT}/user/{uid}"),
        }
    }

    fn seat_path(self, id: &str) -> String {
        match self {
            Self::Native => logind::seat_path(id),
            Self::Compatibility => format!("{COMPAT_ROOT}/seat/{}", logind::object_component(id)),
        }
    }
}

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
    enable_wall_messages: bool,
    wall_message: String,
    namespace: ObjectNamespace,
}

struct SessionState {
    control_acquired: bool,
    devices: HashMap<(u32, u32), OwnedFd>,
}

impl SessionState {
    fn new() -> Self {
        Self {
            control_acquired: false,
            devices: HashMap::new(),
        }
    }
}

fn no_such_session() -> zbus::fdo::Error {
    zbus::fdo::Error::Failed("No such session".into())
}

fn no_such_user() -> zbus::fdo::Error {
    zbus::fdo::Error::Failed("No such user".into())
}

fn no_such_seat() -> zbus::fdo::Error {
    zbus::fdo::Error::Failed("No such seat".into())
}

fn valid_session_id(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn session_id_from_environment(pid: u32) -> Option<String> {
    let environ = fs::read(format!("/proc/{pid}/environ")).ok()?;
    environ.split(|byte| *byte == 0).find_map(|entry| {
        let value = entry.strip_prefix(b"XDG_SESSION_ID=")?;
        let value = std::str::from_utf8(value).ok()?;
        valid_session_id(value).then_some(value.to_owned())
    })
}

fn session_id_for_pid(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }

    let sessions = logind::sessions();
    if let Some(session) = sessions.iter().find(|session| session.leader == pid) {
        return Some(session.id.clone());
    }

    // RustD keeps the session leader in the record, but a desktop normally
    // asks for a child process.  The standard service resolves those through
    // the session scope cgroup.  Accept the same naming convention when a
    // caller is launched by a compatible service manager.
    if let Ok(cgroup) = fs::read_to_string(format!("/proc/{pid}/cgroup")) {
        if let Some(session) = sessions.iter().find(|session| {
            let scope = format!("session-{}.scope", session.id);
            cgroup.contains(&scope)
        }) {
            return Some(session.id.clone());
        }
    }

    session_id_from_environment(pid).filter(|id| sessions.iter().any(|session| session.id == *id))
}

fn device_node_path(major: u32, minor: u32) -> Option<PathBuf> {
    let canonical = PathBuf::from(format!("/dev/char/{major}:{minor}"));
    if canonical.exists() {
        return Some(canonical);
    }

    // /dev/char is created by devtmpfs, but retain a bounded fallback for
    // initramfs and container environments that expose only named nodes.
    for directory in ["/dev/dri", "/dev/input", "/dev/vc", "/dev"] {
        let Ok(entries) = fs::read_dir(directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let candidate = entry.path();
            let Ok(metadata) = fs::metadata(&candidate) else {
                continue;
            };
            if metadata.rdev() == libc::makedev(major, minor) {
                return Some(candidate);
            }
        }
    }
    None
}

fn open_device(major: u32, minor: u32) -> std::io::Result<OwnedFd> {
    let path = device_node_path(major, minor).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("device node {major}:{minor} does not exist"),
        )
    })?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(&path)
        .or_else(|_| {
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
                .open(&path)
        })?;
    let raw = file.into_raw_fd();
    // Safety: `into_raw_fd` transfers ownership of this newly opened fd.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn duplicate_fd(fd: &OwnedFd) -> std::io::Result<OwnedFd> {
    let raw = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if raw < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        // Safety: fcntl returned a new descriptor owned by this call.
        Ok(unsafe { OwnedFd::from_raw_fd(raw) })
    }
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

/// Return every seat known to the login manager, including the local seat
/// before its first session exists.  A display manager needs to discover the
/// seat in order to create that first greeter session; deriving seats only
/// from existing sessions leaves a freshly booted graphical system with no
/// seat to activate.
fn seat_names<'a>(sessions: impl IntoIterator<Item = &'a Session>) -> HashSet<String> {
    let mut seats = HashSet::from(["seat0".to_owned()]);
    for session in sessions {
        seats.insert(session.seat.clone());
    }
    seats
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

    async fn call_manager_method_bool(
        &self,
        method: &str,
        interactive: bool,
    ) -> zbus::fdo::Result<()> {
        let connection = zbus::Connection::system()
            .await
            .map_err(|error| zbus::fdo::Error::Failed(error.to_string()))?;
        connection
            .call_method(
                Some("io.rustd.Manager1"),
                "/io/rustd/Manager1",
                Some("io.rustd.Manager1.Manager"),
                method,
                &interactive,
            )
            .await
            .map_err(|error| zbus::fdo::Error::Failed(error.to_string()))?;
        Ok(())
    }

    /// Start the per-user RustD manager when the first session for a UID is
    /// created.  This is part of the logind contract consumed by PAM and
    /// desktop stacks: setting XDG_RUNTIME_DIR alone is not sufficient, since
    /// user services, the session bus, and graphical applications expect
    /// `user@UID.service` to own that user's manager scope.
    async fn start_user_manager(
        &self,
        uid: u32,
        connection: &zbus::Connection,
    ) -> zbus::fdo::Result<()> {
        let unit = format!("user@{uid}.service");
        connection
            .call_method(
                Some("io.rustd.Manager1"),
                "/io/rustd/Manager1",
                Some("io.rustd.Manager1.Manager"),
                "StartUnit",
                &(unit, "replace"),
            )
            .await
            .map(|_| ())
            .map_err(|error| {
                zbus::fdo::Error::Failed(format!(
                    "failed to start per-user RustD manager for UID {uid}: {error}"
                ))
            })
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
        properties: Vec<(String, zbus::zvariant::OwnedValue)>,
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
        drop(properties);
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
        self.start_user_manager(uid, connection).await?;
        let object_path = path(self.namespace.session_path(&id))?;
        let session_state = Arc::new(Mutex::new(SessionState::new()));
        for namespace in ObjectNamespace::ALL {
            connection
                .object_server()
                .at(
                    namespace.session_path(&id),
                    SessionObject {
                        id: id.clone(),
                        namespace,
                        state: Arc::clone(&session_state),
                    },
                )
                .await
                .map_err(|error| zbus::fdo::Error::Failed(error.to_string()))?;
            let _ = connection
                .object_server()
                .at(namespace.user_path(uid), UserObject { uid, namespace })
                .await;
            let _ = connection
                .object_server()
                .at(
                    namespace.seat_path(&seat),
                    SeatObject {
                        id: seat.clone(),
                        namespace,
                    },
                )
                .await;
        }

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
        if let Some(session) = logind::session(&id) {
            if session.leader > 0 {
                let _ = unsafe { libc::kill(session.leader as libc::pid_t, libc::SIGTERM) };
            }
        }
        self.release_session(id)
    }

    fn get_session(&self, id: String) -> zbus::fdo::Result<OwnedObjectPath> {
        if logind::session(&id).is_some() {
            path(self.namespace.session_path(&id))
        } else {
            Err(no_such_session())
        }
    }

    #[zbus(name = "GetSessionByPID")]
    fn get_session_by_pid(&self, pid: u32) -> zbus::fdo::Result<OwnedObjectPath> {
        session_id_for_pid(pid)
            .map(|id| path(self.namespace.session_path(&id)))
            .transpose()?
            .ok_or_else(no_such_session)
    }

    fn get_user(&self, uid: u32) -> zbus::fdo::Result<OwnedObjectPath> {
        if passwd_record(uid).is_some()
            || logind::sessions()
                .into_iter()
                .any(|session| session.uid == uid)
        {
            path(self.namespace.user_path(uid))
        } else {
            Err(no_such_user())
        }
    }

    #[zbus(name = "GetUserByPID")]
    fn get_user_by_pid(&self, pid: u32) -> zbus::fdo::Result<OwnedObjectPath> {
        let uid = session_id_for_pid(pid)
            .and_then(|id| logind::session(&id).map(|session| session.uid))
            .or_else(|| {
                let metadata = fs::metadata(format!("/proc/{pid}")).ok()?;
                Some(metadata.uid())
            })
            .ok_or_else(no_such_user)?;
        self.get_user(uid)
    }

    fn get_seat(&self, id: String) -> zbus::fdo::Result<OwnedObjectPath> {
        if seat_names(logind::sessions().iter()).contains(&id) {
            path(self.namespace.seat_path(&id))
        } else {
            Err(no_such_seat())
        }
    }

    fn list_sessions(&self) -> Vec<(String, u32, String, String, OwnedObjectPath)> {
        logind::sessions()
            .into_iter()
            .filter_map(|session| {
                path(self.namespace.session_path(&session.id))
                    .ok()
                    .map(|object| {
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
        let mut seen = BTreeMap::new();
        for session in logind::sessions() {
            seen.entry(session.uid)
                .or_insert_with(|| session.user.clone());
        }
        seen.into_iter()
            .filter_map(|(uid, user)| {
                path(self.namespace.user_path(uid))
                    .ok()
                    .map(|object| (uid, user, object))
            })
            .collect()
    }

    fn list_seats(&self) -> Vec<(String, OwnedObjectPath)> {
        let sessions = logind::sessions();
        seat_names(sessions.iter())
            .into_iter()
            .filter_map(|seat| {
                path(self.namespace.seat_path(&seat))
                    .ok()
                    .map(|object| (seat, object))
            })
            .collect()
    }

    fn activate_session(&self, id: String) -> zbus::fdo::Result<()> {
        if logind::session(&id).is_some() {
            Ok(())
        } else {
            Err(no_such_session())
        }
    }

    fn activate_session_on_seat(&self, seat: String, id: String) -> zbus::fdo::Result<()> {
        let session = logind::session(&id).ok_or_else(no_such_session)?;
        if session.seat == seat {
            Ok(())
        } else {
            Err(zbus::fdo::Error::Failed(format!(
                "session {id} does not belong to seat {seat}"
            )))
        }
    }

    fn kill_session(&self, id: String, who: String, signal: i32) -> zbus::fdo::Result<()> {
        let session = logind::session(&id).ok_or_else(no_such_session)?;
        if who != "leader" && who != "all" {
            return Err(zbus::fdo::Error::InvalidArgs(
                "who must be 'leader' or 'all'".into(),
            ));
        }
        if session.leader > 0 && unsafe { libc::kill(session.leader as libc::pid_t, signal) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(dbus_error(error));
            }
        }
        Ok(())
    }

    fn kill_user(&self, uid: u32, signal: i32) -> zbus::fdo::Result<()> {
        if passwd_record(uid).is_none()
            && !logind::sessions().iter().any(|session| session.uid == uid)
        {
            return Err(no_such_user());
        }
        for session in logind::sessions()
            .into_iter()
            .filter(|session| session.uid == uid && session.leader > 0)
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

    fn terminate_user(&self, uid: u32) -> zbus::fdo::Result<()> {
        self.kill_user(uid, libc::SIGTERM)?;
        for session in logind::sessions()
            .into_iter()
            .filter(|session| session.uid == uid)
        {
            logind::remove(&session.id).map_err(dbus_error)?;
        }
        Ok(())
    }

    fn terminate_seat(&self, seat: String) -> zbus::fdo::Result<()> {
        if !seat_names(logind::sessions().iter()).contains(&seat) {
            return Err(no_such_seat());
        }
        for session in logind::sessions()
            .into_iter()
            .filter(|session| session.seat == seat)
        {
            if session.leader > 0 {
                let _ = unsafe { libc::kill(session.leader as libc::pid_t, libc::SIGTERM) };
            }
            logind::remove(&session.id).map_err(dbus_error)?;
        }
        Ok(())
    }

    fn lock_sessions(&self) -> zbus::fdo::Result<()> {
        for session in logind::sessions() {
            set_locked(&session.id, true)?;
        }
        Ok(())
    }

    fn unlock_sessions(&self) -> zbus::fdo::Result<()> {
        for session in logind::sessions() {
            set_locked(&session.id, false)?;
        }
        Ok(())
    }

    fn attach_device(
        &self,
        seat: String,
        sysfs: String,
        interactive: bool,
    ) -> zbus::fdo::Result<()> {
        let _ = (sysfs, interactive);
        if seat_names(logind::sessions().iter()).contains(&seat) {
            Ok(())
        } else {
            Err(no_such_seat())
        }
    }

    fn flush_devices(&self, reexecute: bool) {
        let _ = reexecute;
    }

    fn set_user_linger(&self, uid: u32, enable: bool, interactive: bool) -> zbus::fdo::Result<()> {
        let _ = (enable, interactive);
        self.get_user(uid).map(|_| ())
    }

    #[zbus(name = "SetWallMessage")]
    fn set_wall_message_method(&self, message: String, enable: bool) {
        let _ = (message, enable);
    }

    #[zbus(property)]
    fn n_current_inhibitors(&self) -> u64 {
        self.inhibitors.lock().map_or(0, |map| map.len() as u64)
    }

    #[zbus(property)]
    fn n_current_sessions(&self) -> u64 {
        logind::sessions().len() as u64
    }

    #[zbus(name = "NAutoVTs", property(emits_changed_signal = "const"))]
    fn n_auto_vts(&self) -> u32 {
        6
    }

    #[zbus(property)]
    fn sessions_max(&self) -> u64 {
        8192
    }

    #[zbus(property)]
    fn inhibitors_max(&self) -> u64 {
        8192
    }

    #[zbus(property)]
    fn kill_user_processes(&self) -> bool {
        false
    }

    #[zbus(property)]
    fn kill_exclude_users(&self) -> Vec<String> {
        Vec::new()
    }

    #[zbus(property)]
    fn kill_only_users(&self) -> Vec<String> {
        Vec::new()
    }

    #[zbus(name = "RemoveIPC", property(emits_changed_signal = "const"))]
    fn remove_ipc(&self) -> bool {
        false
    }

    #[zbus(property)]
    fn enable_wall_messages(&self) -> bool {
        self.enable_wall_messages
    }

    #[zbus(property)]
    fn set_enable_wall_messages(&mut self, value: bool) -> zbus::fdo::Result<()> {
        self.enable_wall_messages = value;
        Ok(())
    }

    #[zbus(property)]
    fn wall_message(&self) -> String {
        self.wall_message.clone()
    }

    #[zbus(property)]
    fn set_wall_message(&mut self, value: String) -> zbus::fdo::Result<()> {
        self.wall_message = value;
        Ok(())
    }

    #[zbus(property)]
    fn block_inhibited(&self) -> String {
        "shutdown:handle-power-key".into()
    }

    #[zbus(property)]
    fn delay_inhibited(&self) -> String {
        "sleep".into()
    }

    #[zbus(property)]
    fn handle_power_key(&self) -> &'static str {
        "poweroff"
    }

    #[zbus(property)]
    fn handle_power_key_long_press(&self) -> &'static str {
        "ignore"
    }

    #[zbus(property)]
    fn handle_reboot_key(&self) -> &'static str {
        "reboot"
    }

    #[zbus(property)]
    fn handle_reboot_key_long_press(&self) -> &'static str {
        "poweroff"
    }

    #[zbus(property)]
    fn handle_suspend_key(&self) -> &'static str {
        "suspend"
    }

    #[zbus(property)]
    fn handle_suspend_key_long_press(&self) -> &'static str {
        "hibernate"
    }

    #[zbus(property)]
    fn handle_hibernate_key(&self) -> &'static str {
        "hibernate"
    }

    #[zbus(property)]
    fn handle_hibernate_key_long_press(&self) -> &'static str {
        "ignore"
    }

    #[zbus(property)]
    fn handle_lid_switch(&self) -> &'static str {
        "suspend"
    }

    #[zbus(property)]
    fn handle_lid_switch_docked(&self) -> &'static str {
        "ignore"
    }

    #[zbus(property)]
    fn handle_lid_switch_external_power(&self) -> &'static str {
        ""
    }

    #[zbus(property)]
    fn idle_action(&self) -> &'static str {
        "ignore"
    }

    #[zbus(name = "IdleActionUSec", property(emits_changed_signal = "const"))]
    fn idle_action_usec(&self) -> u64 {
        1_800_000_000
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

    #[zbus(name = "HoldoffTimeoutUSec", property(emits_changed_signal = "const"))]
    fn holdoff_timeout_usec(&self) -> u64 {
        30_000_000
    }

    #[zbus(name = "InhibitDelayMaxUSec", property(emits_changed_signal = "const"))]
    fn inhibit_delay_max_usec(&self) -> u64 {
        5_000_000
    }

    #[zbus(property)]
    fn runtime_directory_size(&self) -> u64 {
        0
    }

    #[zbus(property)]
    fn runtime_directory_inodes_max(&self) -> u64 {
        0
    }

    #[zbus(name = "StopIdleSessionUSec", property(emits_changed_signal = "const"))]
    fn stop_idle_session_usec(&self) -> u64 {
        u64::MAX
    }

    #[zbus(name = "UserStopDelayUSec", property(emits_changed_signal = "const"))]
    fn user_stop_delay_usec(&self) -> u64 {
        10_000_000
    }

    #[zbus(property)]
    fn boot_loader_entries(&self) -> Vec<String> {
        Vec::new()
    }

    #[zbus(property)]
    fn reboot_parameter(&self) -> String {
        String::new()
    }

    #[zbus(property)]
    fn reboot_to_boot_loader_entry(&self) -> String {
        String::new()
    }

    #[zbus(property)]
    fn reboot_to_boot_loader_menu(&self) -> u64 {
        u64::MAX
    }

    #[zbus(property)]
    fn reboot_to_firmware_setup(&self) -> bool {
        false
    }

    #[zbus(property)]
    fn scheduled_shutdown(&self) -> (String, u64) {
        (String::new(), u64::MAX)
    }

    #[zbus(property)]
    fn docked(&self) -> bool {
        false
    }

    #[zbus(property)]
    fn lid_closed(&self) -> bool {
        false
    }

    #[zbus(property)]
    fn on_external_power(&self) -> bool {
        true
    }

    #[zbus(property)]
    fn preparing_for_shutdown(&self) -> bool {
        false
    }

    #[zbus(property)]
    fn preparing_for_sleep(&self) -> bool {
        false
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

    fn can_halt(&self) -> &'static str {
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

    fn can_hybrid_sleep(&self) -> &'static str {
        "na"
    }

    fn can_suspend_then_hibernate(&self) -> &'static str {
        "na"
    }

    fn can_reboot_parameter(&self) -> &'static str {
        "na"
    }

    fn can_reboot_to_boot_loader_entry(&self) -> &'static str {
        "na"
    }

    fn can_reboot_to_boot_loader_menu(&self) -> &'static str {
        "na"
    }

    fn can_reboot_to_firmware_setup(&self) -> &'static str {
        "na"
    }

    async fn power_off(&self, interactive: bool) -> zbus::fdo::Result<()> {
        self.ensure_shutdown_allowed()?;
        self.call_manager_method_bool("PowerOff", interactive).await
    }

    async fn reboot(&self, interactive: bool) -> zbus::fdo::Result<()> {
        self.ensure_shutdown_allowed()?;
        self.call_manager_method_bool("Reboot", interactive).await
    }

    async fn halt(&self, interactive: bool) -> zbus::fdo::Result<()> {
        self.ensure_shutdown_allowed()?;
        self.call_manager_method_bool("Halt", interactive).await
    }

    async fn suspend(&self, interactive: bool) -> zbus::fdo::Result<()> {
        self.call_manager_method_bool("Suspend", interactive).await
    }

    async fn hibernate(&self, interactive: bool) -> zbus::fdo::Result<()> {
        self.call_manager_method_bool("Hibernate", interactive)
            .await
    }

    async fn hybrid_sleep(&self, interactive: bool) -> zbus::fdo::Result<()> {
        self.call_manager_method_bool("HybridSleep", interactive)
            .await
    }

    async fn suspend_then_hibernate(&self, interactive: bool) -> zbus::fdo::Result<()> {
        self.call_manager_method_bool("SuspendThenHibernate", interactive)
            .await
    }

    async fn power_off_with_flags(&self, flags: u64) -> zbus::fdo::Result<()> {
        let _ = flags;
        self.power_off(false).await
    }

    async fn reboot_with_flags(&self, flags: u64) -> zbus::fdo::Result<()> {
        let _ = flags;
        self.reboot(false).await
    }

    async fn halt_with_flags(&self, flags: u64) -> zbus::fdo::Result<()> {
        let _ = flags;
        self.halt(false).await
    }

    async fn suspend_with_flags(&self, flags: u64) -> zbus::fdo::Result<()> {
        let _ = flags;
        self.suspend(false).await
    }

    async fn hibernate_with_flags(&self, flags: u64) -> zbus::fdo::Result<()> {
        let _ = flags;
        self.hibernate(false).await
    }

    async fn hybrid_sleep_with_flags(&self, flags: u64) -> zbus::fdo::Result<()> {
        let _ = flags;
        self.hybrid_sleep(false).await
    }

    async fn suspend_then_hibernate_with_flags(&self, flags: u64) -> zbus::fdo::Result<()> {
        let _ = flags;
        self.suspend_then_hibernate(false).await
    }

    fn cancel_scheduled_shutdown(&self) -> bool {
        false
    }

    fn set_reboot_parameter(&self, parameter: String) {
        let _ = parameter;
    }

    fn set_reboot_to_boot_loader_entry(&self, entry: String) {
        let _ = entry;
    }

    fn set_reboot_to_boot_loader_menu(&self, timeout: u64) {
        let _ = timeout;
    }

    fn set_reboot_to_firmware_setup(&self, enable: bool) {
        let _ = enable;
    }

    #[zbus(signal)]
    async fn prepare_for_shutdown(ctxt: &zbus::SignalContext<'_>, active: bool)
        -> zbus::Result<()>;

    #[zbus(signal)]
    async fn prepare_for_sleep(ctxt: &zbus::SignalContext<'_>, active: bool) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn seat_new(
        ctxt: &zbus::SignalContext<'_>,
        id: &str,
        seat: zbus::zvariant::ObjectPath<'_>,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn seat_removed(
        ctxt: &zbus::SignalContext<'_>,
        id: &str,
        seat: zbus::zvariant::ObjectPath<'_>,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn session_new(
        ctxt: &zbus::SignalContext<'_>,
        id: &str,
        session: zbus::zvariant::ObjectPath<'_>,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn session_removed(
        ctxt: &zbus::SignalContext<'_>,
        id: &str,
        session: zbus::zvariant::ObjectPath<'_>,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn user_new(
        ctxt: &zbus::SignalContext<'_>,
        uid: u32,
        user: zbus::zvariant::ObjectPath<'_>,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn user_removed(
        ctxt: &zbus::SignalContext<'_>,
        uid: u32,
        user: zbus::zvariant::ObjectPath<'_>,
    ) -> zbus::Result<()>;
}

/// Adapter for the login1 manager's one non-standard zbus dispatch case.
///
/// zbus represents a Rust method with multiple arguments as a tuple internally,
/// but D-Bus puts those values directly in the message body.  Its checked
/// dynamic deserializer therefore expects `(args...)` while a real login1
/// client sends `args...`.  The standard login1 CreateSession call is emitted
/// by PlasmaLogin/libsystemd in the latter form, so decode that one method with
/// the unchecked deserializer and delegate every other method to the generated
/// Manager implementation.  The generated introspection remains unchanged.
struct Login1Manager(Manager);

#[zbus::export::async_trait::async_trait]
impl zbus::object_server::Interface for Login1Manager {
    fn name() -> zbus::names::InterfaceName<'static> {
        <Manager as zbus::object_server::Interface>::name()
    }

    async fn get(
        &self,
        property_name: &str,
    ) -> Option<zbus::fdo::Result<zbus::zvariant::OwnedValue>> {
        <Manager as zbus::object_server::Interface>::get(&self.0, property_name).await
    }

    async fn get_all(&self) -> zbus::fdo::Result<HashMap<String, zbus::zvariant::OwnedValue>> {
        <Manager as zbus::object_server::Interface>::get_all(&self.0).await
    }

    fn set<'call>(
        &'call self,
        property_name: &'call str,
        value: &'call zbus::zvariant::Value<'_>,
        ctxt: &'call zbus::object_server::SignalContext<'_>,
    ) -> zbus::DispatchResult<'call> {
        <Manager as zbus::object_server::Interface>::set(&self.0, property_name, value, ctxt)
    }

    async fn set_mut(
        &mut self,
        property_name: &str,
        value: &zbus::zvariant::Value<'_>,
        ctxt: &zbus::object_server::SignalContext<'_>,
    ) -> Option<zbus::fdo::Result<()>> {
        <Manager as zbus::object_server::Interface>::set_mut(
            &mut self.0,
            property_name,
            value,
            ctxt,
        )
        .await
    }

    fn call<'call>(
        &'call self,
        server: &'call zbus::ObjectServer,
        connection: &'call zbus::Connection,
        msg: &'call zbus::Message,
        name: zbus::names::MemberName<'call>,
    ) -> zbus::DispatchResult<'call> {
        if name.as_str() != "CreateSession" {
            return <Manager as zbus::object_server::Interface>::call(
                &self.0, server, connection, msg, name,
            );
        }

        let body = msg.body();
        let arguments = match body.signature() {
            Some(signature) if signature.as_str() == CREATE_SESSION_SIGNATURE => body
                .deserialize_unchecked::<(
                    u32,
                    u32,
                    String,
                    String,
                    String,
                    String,
                    String,
                    u32,
                    String,
                    String,
                    bool,
                    String,
                    String,
                    Vec<(String, zbus::zvariant::OwnedValue)>,
                )>()
                .map_err(|error| error.to_string()),
            Some(signature) => Err(format!(
                "CreateSession signature `{signature}` does not match `{CREATE_SESSION_SIGNATURE}`"
            )),
            None => Err("CreateSession has no D-Bus body signature".into()),
        };
        let future = async move {
            match arguments {
                Ok((
                    uid,
                    pid,
                    service,
                    type_,
                    class,
                    desktop,
                    seat_id,
                    vtnr,
                    tty,
                    display,
                    remote,
                    remote_user,
                    remote_host,
                    properties,
                )) => {
                    self.0
                        .create_session(
                            uid,
                            pid,
                            service,
                            type_,
                            class,
                            desktop,
                            seat_id,
                            vtnr,
                            tty,
                            display,
                            remote,
                            remote_user,
                            remote_host,
                            properties,
                            connection,
                        )
                        .await
                }
                Err(error) => Err(zbus::fdo::Error::InvalidArgs(error.clone())),
            }
        };
        zbus::DispatchResult::new_async(connection, msg, future)
    }

    fn call_mut<'call>(
        &'call mut self,
        server: &'call zbus::ObjectServer,
        connection: &'call zbus::Connection,
        msg: &'call zbus::Message,
        name: zbus::names::MemberName<'call>,
    ) -> zbus::DispatchResult<'call> {
        <Manager as zbus::object_server::Interface>::call_mut(
            &mut self.0,
            server,
            connection,
            msg,
            name,
        )
    }

    fn introspect_to_writer(&self, writer: &mut dyn std::fmt::Write, level: usize) {
        <Manager as zbus::object_server::Interface>::introspect_to_writer(&self.0, writer, level);
    }
}

struct SessionObject {
    id: String,
    namespace: ObjectNamespace,
    state: Arc<Mutex<SessionState>>,
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
                path(self.namespace.user_path(uid)).unwrap_or_else(|_| OwnedObjectPath::default()),
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

    #[zbus(name = "VTNr", property(emits_changed_signal = "const"))]
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
        let seat = logind::session(&self.id).map_or_else(|| "seat0".into(), |session| session.seat);
        (
            seat.clone(),
            path(self.namespace.seat_path(&seat)).unwrap_or_else(|_| OwnedObjectPath::default()),
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
        logind::session(&self.id).map_or_else(|| "closing".into(), |session| session.state)
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
            Err(no_such_session())
        }
    }

    fn lock(&self) -> zbus::fdo::Result<()> {
        set_locked(&self.id, true)
    }

    fn unlock(&self) -> zbus::fdo::Result<()> {
        set_locked(&self.id, false)
    }

    fn terminate(&self) -> zbus::fdo::Result<()> {
        if let Some(session) = logind::session(&self.id) {
            if session.leader > 0 {
                let _ = unsafe { libc::kill(session.leader as libc::pid_t, libc::SIGTERM) };
            }
        }
        logind::remove(&self.id).map_err(dbus_error)
    }

    fn kill(&self, who: String, signal: i32) -> zbus::fdo::Result<()> {
        let session = logind::session(&self.id).ok_or_else(no_such_session)?;
        if who != "leader" && who != "all" {
            return Err(zbus::fdo::Error::InvalidArgs(
                "who must be 'leader' or 'all'".into(),
            ));
        }
        if session.leader > 0 && unsafe { libc::kill(session.leader as libc::pid_t, signal) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(dbus_error(error));
            }
        }
        Ok(())
    }

    fn take_control(&self, force: bool) -> zbus::fdo::Result<()> {
        let _ = force;
        if logind::session(&self.id).is_none() {
            return Err(no_such_session());
        }
        self.state
            .lock()
            .map_err(|_| zbus::fdo::Error::Failed("session state lock poisoned".into()))?
            .control_acquired = true;
        Ok(())
    }

    fn release_control(&self) -> zbus::fdo::Result<()> {
        self.state
            .lock()
            .map_err(|_| zbus::fdo::Error::Failed("session state lock poisoned".into()))?
            .control_acquired = false;
        Ok(())
    }

    fn take_device(
        &self,
        major: u32,
        minor: u32,
    ) -> zbus::fdo::Result<(zbus::zvariant::OwnedFd, bool)> {
        if logind::session(&self.id).is_none() {
            return Err(no_such_session());
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| zbus::fdo::Error::Failed("session state lock poisoned".into()))?;
        if let std::collections::hash_map::Entry::Vacant(entry) =
            state.devices.entry((major, minor))
        {
            entry.insert(open_device(major, minor).map_err(dbus_error)?);
        }
        let fd = state
            .devices
            .get(&(major, minor))
            .ok_or_else(|| zbus::fdo::Error::Failed("device disappeared".into()))?;
        Ok((
            zbus::zvariant::OwnedFd::from(duplicate_fd(fd).map_err(dbus_error)?),
            false,
        ))
    }

    fn release_device(&self, major: u32, minor: u32) -> zbus::fdo::Result<()> {
        self.state
            .lock()
            .map_err(|_| zbus::fdo::Error::Failed("session state lock poisoned".into()))?
            .devices
            .remove(&(major, minor));
        Ok(())
    }

    fn pause_device_complete(&self, major: u32, minor: u32) {
        let _ = (major, minor);
    }

    fn set_idle_hint(&self, idle: bool) {
        let _ = idle;
    }

    fn set_locked_hint(&self, locked: bool) -> zbus::fdo::Result<()> {
        set_locked(&self.id, locked)
    }

    fn set_type(&self, type_: String) -> zbus::fdo::Result<()> {
        let mut session = logind::session(&self.id).ok_or_else(no_such_session)?;
        if type_.is_empty() {
            return Err(zbus::fdo::Error::InvalidArgs(
                "session type must not be empty".into(),
            ));
        }
        session.session_type = type_;
        logind::save(&session).map_err(dbus_error)
    }

    fn set_display(&self, display: String) -> zbus::fdo::Result<()> {
        let mut session = logind::session(&self.id).ok_or_else(no_such_session)?;
        session.display = display;
        logind::save(&session).map_err(dbus_error)
    }

    fn set_brightness(
        &self,
        subsystem: String,
        device: String,
        brightness: u32,
    ) -> zbus::fdo::Result<()> {
        let _ = (subsystem, device, brightness);
        // Brightness is hardware-specific and is intentionally handled by
        // the desktop's backlight service.  Accept the standard call so a
        // desktop does not fail its session setup on RustD-only systems.
        Ok(())
    }
}

struct UserObject {
    uid: u32,
    namespace: ObjectNamespace,
}

#[interface(name = "org.freedesktop.login1.User")]
impl UserObject {
    #[zbus(name = "UID", property(emits_changed_signal = "const"))]
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
                path(self.namespace.session_path(&session.id))
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
                path(self.namespace.session_path(&session.id))
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

    #[zbus(name = "GID", property(emits_changed_signal = "const"))]
    fn gid(&self) -> u32 {
        passwd_record(self.uid).map_or(self.uid, |(_, gid)| gid)
    }

    #[zbus(property)]
    fn timestamp(&self) -> u64 {
        0
    }

    #[zbus(property)]
    fn timestamp_monotonic(&self) -> u64 {
        0
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
    namespace: ObjectNamespace,
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
                path(self.namespace.session_path(&session.id))
                    .unwrap_or_else(|_| OwnedObjectPath::default()),
            ),
            None => (
                String::new(),
                OwnedObjectPath::try_from("/").unwrap_or_default(),
            ),
        }
    }

    #[zbus(name = "CanTTY", property(emits_changed_signal = "const"))]
    fn can_tty(&self) -> bool {
        true
    }

    #[zbus(property)]
    fn can_graphical(&self) -> bool {
        true
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
    fn sessions(&self) -> Vec<(String, OwnedObjectPath)> {
        logind::sessions()
            .into_iter()
            .filter(|session| session.seat == self.id)
            .filter_map(|session| {
                path(self.namespace.session_path(&session.id))
                    .ok()
                    .map(|object| (session.id, object))
            })
            .collect()
    }

    fn activate_session(&self, session: String) -> zbus::fdo::Result<()> {
        let record = logind::session(&session).ok_or_else(no_such_session)?;
        if record.seat == self.id {
            Ok(())
        } else {
            Err(zbus::fdo::Error::Failed(format!(
                "session {session} does not belong to seat {}",
                self.id
            )))
        }
    }

    fn switch_to(&self, vtnr: u32) -> zbus::fdo::Result<()> {
        let _ = vtnr;
        Ok(())
    }

    fn switch_to_next(&self) -> zbus::fdo::Result<()> {
        Ok(())
    }

    fn switch_to_previous(&self) -> zbus::fdo::Result<()> {
        Ok(())
    }

    fn terminate(&self) -> zbus::fdo::Result<()> {
        for session in logind::sessions()
            .into_iter()
            .filter(|session| session.seat == self.id)
        {
            if session.leader > 0 {
                let _ = unsafe { libc::kill(session.leader as libc::pid_t, libc::SIGTERM) };
            }
            logind::remove(&session.id).map_err(dbus_error)?;
        }
        Ok(())
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
    let compat_manager = Login1Manager(Manager {
        next_inhibitor: AtomicU64::new(0),
        inhibitors: Arc::clone(&inhibitors),
        session_refs: Arc::clone(&session_refs),
        enable_wall_messages: true,
        wall_message: String::new(),
        namespace: ObjectNamespace::Compatibility,
    });
    let native_manager = Login1Manager(Manager {
        next_inhibitor: AtomicU64::new(0),
        inhibitors,
        session_refs,
        enable_wall_messages: true,
        wall_message: String::new(),
        namespace: ObjectNamespace::Native,
    });
    connection
        .object_server()
        .at(COMPAT_ROOT, compat_manager)
        .await?;
    connection
        .object_server()
        .at(NATIVE_ROOT, native_manager)
        .await?;
    let sessions = logind::sessions();
    for session in &sessions {
        let session_state = Arc::new(Mutex::new(SessionState::new()));
        for namespace in ObjectNamespace::ALL {
            connection
                .object_server()
                .at(
                    namespace.session_path(&session.id),
                    SessionObject {
                        id: session.id.clone(),
                        namespace,
                        state: Arc::clone(&session_state),
                    },
                )
                .await?;
            let _ = connection
                .object_server()
                .at(
                    namespace.user_path(session.uid),
                    UserObject {
                        uid: session.uid,
                        namespace,
                    },
                )
                .await;
            let _ = connection
                .object_server()
                .at(
                    namespace.seat_path(&session.seat),
                    SeatObject {
                        id: session.seat.clone(),
                        namespace,
                    },
                )
                .await;
        }
    }
    for seat in seat_names(sessions.iter()) {
        for namespace in ObjectNamespace::ALL {
            connection
                .object_server()
                .at(
                    namespace.seat_path(&seat),
                    SeatObject {
                        id: seat.clone(),
                        namespace,
                    },
                )
                .await?;
        }
    }
    connection.request_name(COMPAT_BUS_NAME).await?;
    connection.request_name(NATIVE_BUS_NAME).await?;
    rustd::native::notify_ready()?;
    std::future::pending::<()>().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::seat_names;
    use rustd::logind::Session;

    #[test]
    fn local_seat_is_published_before_any_session_exists() {
        let sessions = Vec::<Session>::new();
        let seats = seat_names(sessions.iter());
        assert!(seats.contains("seat0"));
    }

    #[test]
    fn session_seats_are_retained_alongside_the_local_seat() {
        let sessions = [Session {
            seat: "seat1".into(),
            ..Session::default()
        }];
        let seats = seat_names(sessions.iter());
        assert!(seats.contains("seat0"));
        assert!(seats.contains("seat1"));
    }
}
