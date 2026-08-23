// SPDX-License-Identifier: LGPL-2.1-or-later
//! `rustd_notify` server and authenticated notification event queue.
//!
//! The manager binds a Unix datagram socket, enables `SO_PASSCRED`, and
//! registers the socket with the event loop. Datagrams are associated with a
//! unit through the sender credentials and the unit's effective
//! `NotifyAccess=` policy.
//!
//! Upstream reference: `src/core/manager.c manager_setup_notify()`,
//!   `src/core/service.c service_notify_message()` (v261)

use std::collections::{HashMap, VecDeque};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

const NOTIFY_EVENTS_PER_WAKE: usize = 256;
const NOTIFY_BUFFER_SIZE: usize = 65_536;
const DEFERRED_NOTIFY_LIMIT: usize = 256;

use crate::event::loop_::IoHandler;
use crate::unit::section_service::NotifyAccess;

/// Default filesystem notification socket.
pub const RUSTD_NOTIFY_SOCKET_PATH: &str = "/run/rustd/notify";

/// A parsed `rustd_notify` message.
#[derive(Debug, Default, Clone)]
pub struct NotifyMessage {
    /// Service reports readiness.
    pub ready: bool,
    /// Service is about to stop.
    pub stopping: bool,
    /// Watchdog keepalive.
    pub watchdog: bool,
    /// Human-readable status string.
    pub status: Option<String>,
    /// Error number reported by the service.
    pub errno: Option<i32>,
    /// Main PID replacement.
    pub main_pid: Option<libc::pid_t>,
}

impl NotifyMessage {
    /// Parse a datagram body into a notification message.
    #[must_use]
    pub fn parse(data: &[u8]) -> Self {
        let mut message = Self::default();
        let text = String::from_utf8_lossy(data);
        for line in text.lines() {
            if let Some((key, value)) = line.split_once('=') {
                match key {
                    "READY" => message.ready = value == "1",
                    "STOPPING" => message.stopping = value == "1",
                    "WATCHDOG" => message.watchdog = value == "1",
                    "STATUS" => message.status = Some(value.to_owned()),
                    "ERRNO" => message.errno = value.parse().ok(),
                    "MAINPID" => message.main_pid = value.parse().ok(),
                    _ => {}
                }
            }
        }
        message
    }
}

/// One authenticated notification delivered to the manager.
#[derive(Debug, Clone)]
pub struct NotifyEvent {
    /// Unit whose registered process sent the datagram.
    pub unit_name: String,
    /// Credential PID attached by the kernel.
    pub sender_pid: libc::pid_t,
    /// Parsed message body.
    pub message: NotifyMessage,
}

#[derive(Debug, Clone)]
struct Registration {
    unit_name: String,
    access: NotifyAccess,
    main_pid: libc::pid_t,
}

#[derive(Debug, Default)]
struct NotifyState {
    registrations: HashMap<libc::pid_t, Registration>,
    pending: Vec<NotifyEvent>,
    deferred: VecDeque<(libc::pid_t, NotifyMessage)>,
}

/// The manager-side notification socket.
pub struct NotifyServer {
    fd: OwnedFd,
    state: Arc<Mutex<NotifyState>>,
    filesystem_path: Option<PathBuf>,
}

impl NotifyServer {
    /// Create and bind the configured notification socket.
    ///
    /// `RUSTD_NOTIFY_SOCKET` may override the default. Values beginning
    /// with `@` use the Linux abstract namespace; other values are filesystem
    /// socket paths.
    ///
    /// # Errors
    /// Returns an error if the socket cannot be created, configured, or bound.
    pub fn new() -> anyhow::Result<Self> {
        let path = std::env::var("RUSTD_NOTIFY_SOCKET")
            .unwrap_or_else(|_| RUSTD_NOTIFY_SOCKET_PATH.to_owned());
        Self::new_at(&path)
    }

    fn new_at(path: &str) -> anyhow::Result<Self> {
        let (fd, filesystem_path) = create_notify_socket(path)?;
        Ok(Self {
            fd,
            state: Arc::new(Mutex::new(NotifyState::default())),
            filesystem_path,
        })
    }

    /// Raw descriptor registered with the manager event loop.
    #[must_use]
    pub fn raw_fd(&self) -> libc::c_int {
        self.fd.as_raw_fd()
    }

    /// Build an event-loop handler sharing this server's registration state.
    #[must_use]
    pub fn io_handler(&self) -> Box<dyn IoHandler> {
        Box::new(NotifyIoHandler {
            state: Arc::clone(&self.state),
            buffer: vec![0u8; NOTIFY_BUFFER_SIZE],
        })
    }

    /// Register the main process for one unit.
    pub fn register_pid(
        &self,
        pid: libc::pid_t,
        unit_name: impl Into<String>,
        access: NotifyAccess,
    ) {
        if pid <= 0 || access == NotifyAccess::None {
            return;
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let unit_name = unit_name.into();
        state.registrations.insert(
            pid,
            Registration {
                unit_name: unit_name.clone(),
                access,
                main_pid: pid,
            },
        );
        // A daemon can exec and call sd_notify() before its parent returns
        // from rustd_spawn().  Preserve that authenticated datagram until the
        // manager has associated the child PID with its unit.
        let mut retained = VecDeque::with_capacity(state.deferred.len());
        while let Some((sender_pid, message)) = state.deferred.pop_front() {
            if sender_pid == pid {
                state.pending.push(NotifyEvent {
                    unit_name: unit_name.clone(),
                    sender_pid,
                    message,
                });
            } else {
                retained.push_back((sender_pid, message));
            }
        }
        state.deferred = retained;
    }

    /// Replace a registered main PID after an authenticated `MAINPID=` update.
    pub fn replace_pid(&self, old_pid: libc::pid_t, new_pid: libc::pid_t) {
        if old_pid == new_pid || new_pid <= 0 {
            return;
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(mut registration) = state.registrations.remove(&old_pid) {
            registration.main_pid = new_pid;
            state.registrations.insert(new_pid, registration);
        }
    }

    /// Unregister a main PID after the unit exits.
    pub fn unregister_pid(&self, pid: libc::pid_t) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.registrations.remove(&pid);
    }

    /// Drain all authenticated events received by the I/O handler.
    pub fn drain_events(&self) -> Vec<NotifyEvent> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::mem::take(&mut state.pending)
    }
}

impl Drop for NotifyServer {
    fn drop(&mut self) {
        if let Some(path) = &self.filesystem_path {
            let _ = std::fs::remove_file(path);
        }
    }
}

struct NotifyIoHandler {
    state: Arc<Mutex<NotifyState>>,
    buffer: Vec<u8>,
}

impl IoHandler for NotifyIoHandler {
    fn on_io(&mut self, fd: i32, _events: u32) {
        // Bound work per epoll wake. The notify socket is level-triggered, so
        // any datagrams left queued will wake the manager again after it has
        // applied this batch, preserving readiness/watchdog semantics while
        // preventing one service from monopolizing PID1's event loop.
        for _ in 0..NOTIFY_EVENTS_PER_WAKE {
            let received = match receive_datagram(fd, &mut self.buffer) {
                Ok(Some(received)) => received,
                Ok(None) => break,
                Err(error) => {
                    eprintln!("rustd: notification receive failed: {error}");
                    break;
                }
            };
            let (sender_pid, message) = received;
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(unit_name) = authorized_unit(&state, sender_pid) {
                state.pending.push(NotifyEvent {
                    unit_name,
                    sender_pid,
                    message,
                });
            } else {
                if state.deferred.len() == DEFERRED_NOTIFY_LIMIT {
                    state.deferred.pop_front();
                }
                state.deferred.push_back((sender_pid, message));
            }
        }
    }
}

fn authorized_unit(state: &NotifyState, sender_pid: libc::pid_t) -> Option<String> {
    if let Some(registration) = state.registrations.get(&sender_pid) {
        return Some(registration.unit_name.clone());
    }

    state
        .registrations
        .values()
        .find(|registration| {
            matches!(registration.access, NotifyAccess::Exec | NotifyAccess::All)
                && is_descendant_of(sender_pid, registration.main_pid)
        })
        .map(|registration| registration.unit_name.clone())
}

fn is_descendant_of(mut pid: libc::pid_t, ancestor: libc::pid_t) -> bool {
    if pid <= 0 || ancestor <= 0 {
        return false;
    }
    for _ in 0..128 {
        if pid == ancestor {
            return true;
        }
        let Some(parent) = parent_pid(pid) else {
            return false;
        };
        if parent <= 0 || parent == pid {
            return false;
        }
        pid = parent;
    }
    false
}

fn parent_pid(pid: libc::pid_t) -> Option<libc::pid_t> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let close = stat.rfind(')')?;
    stat.get(close + 1..)?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

fn receive_datagram(
    fd: libc::c_int,
    buffer: &mut [u8],
) -> anyhow::Result<Option<(libc::pid_t, NotifyMessage)>> {
    let mut control: [libc::c_long; 32] = [0; 32];
    let mut iovec = libc::iovec {
        iov_base: buffer.as_mut_ptr().cast(),
        iov_len: buffer.len(),
    };
    let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
    header.msg_iov = std::ptr::addr_of_mut!(iovec);
    header.msg_iovlen = 1;
    header.msg_control = control.as_mut_ptr().cast();
    header.msg_controllen = std::mem::size_of_val(&control);

    // Safety: all receive buffers remain valid for the duration of recvmsg.
    let length = unsafe { libc::recvmsg(fd, &mut header, libc::MSG_DONTWAIT) };
    if length < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EAGAIN)
            || error.raw_os_error() == Some(libc::EWOULDBLOCK)
        {
            return Ok(None);
        }
        return Err(error.into());
    }
    if length == 0 {
        return Ok(None);
    }
    if header.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "truncated notification datagram or credentials",
        )
        .into());
    }
    let Some(sender_pid) = extract_sender_pid(&header) else {
        return Ok(None);
    };
    #[allow(clippy::cast_sign_loss)]
    let message = NotifyMessage::parse(&buffer[..length as usize]);
    Ok(Some((sender_pid, message)))
}

fn create_notify_socket(path: &str) -> anyhow::Result<(OwnedFd, Option<PathBuf>)> {
    // Safety: socket returns a new owned descriptor or -1.
    let raw_fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if raw_fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // Safety: raw_fd was returned by socket and is uniquely owned here.
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

    let pass_credentials: libc::c_int = 1;
    #[allow(clippy::cast_possible_truncation)]
    let option_length = std::mem::size_of_val(&pass_credentials) as libc::socklen_t;
    // Safety: the option value and length match SO_PASSCRED's integer type.
    let option_result = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PASSCRED,
            std::ptr::addr_of!(pass_credentials).cast(),
            option_length,
        )
    };
    if option_result < 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    let (address, address_length, filesystem_path) = build_socket_address(path)?;
    // Safety: address is initialized for AF_UNIX and address_length is exact.
    let bind_result = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            std::ptr::addr_of!(address).cast(),
            address_length,
        )
    };
    if bind_result < 0 {
        if let Some(socket_path) = &filesystem_path {
            let _ = std::fs::remove_file(socket_path);
        }
        return Err(std::io::Error::last_os_error().into());
    }

    Ok((fd, filesystem_path))
}

fn build_socket_address(
    path: &str,
) -> anyhow::Result<(libc::sockaddr_un, libc::socklen_t, Option<PathBuf>)> {
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    #[allow(clippy::cast_possible_truncation)]
    {
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    }

    let (address_length, filesystem_path) = if let Some(name) = path.strip_prefix('@') {
        let bytes = name.as_bytes();
        if bytes.is_empty() || bytes.len() + 1 > address.sun_path.len() {
            return Err(anyhow::anyhow!(
                "invalid abstract notify socket path: {path}"
            ));
        }
        address.sun_path[0] = 0;
        for (index, byte) in bytes.iter().copied().enumerate() {
            #[allow(clippy::cast_possible_wrap)]
            {
                address.sun_path[index + 1] = byte as libc::c_char;
            }
        }
        (
            std::mem::size_of::<libc::sa_family_t>() + 1 + bytes.len(),
            None,
        )
    } else {
        let socket_path = PathBuf::from(path);
        if let Some(parent) = socket_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let _ = std::fs::remove_file(&socket_path);
        let bytes = path.as_bytes();
        if bytes.is_empty() || bytes.len() + 1 > address.sun_path.len() {
            return Err(anyhow::anyhow!("invalid notify socket path: {path}"));
        }
        for (index, byte) in bytes.iter().copied().enumerate() {
            #[allow(clippy::cast_possible_wrap)]
            {
                address.sun_path[index] = byte as libc::c_char;
            }
        }
        (
            std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1,
            Some(socket_path),
        )
    };

    #[allow(clippy::cast_possible_truncation)]
    let address_length = address_length as libc::socklen_t;
    Ok((address, address_length, filesystem_path))
}

/// Extract the sender PID from `SCM_CREDENTIALS` ancillary data, if present.
fn extract_sender_pid(message: &libc::msghdr) -> Option<libc::pid_t> {
    // Safety: control-message iteration follows the libc CMSG contract.
    let mut control_message = unsafe { libc::CMSG_FIRSTHDR(message) };
    while !control_message.is_null() {
        let header = unsafe { &*control_message };
        if header.cmsg_level == libc::SOL_SOCKET && header.cmsg_type == libc::SCM_CREDENTIALS {
            let credentials: libc::ucred = unsafe {
                let data = libc::CMSG_DATA(control_message);
                std::ptr::read_unaligned(data.cast())
            };
            return Some(credentials.pid);
        }
        control_message = unsafe { libc::CMSG_NXTHDR(message, control_message) };
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ready_and_status() {
        let message = NotifyMessage::parse(b"READY=1\nSTATUS=running\nERRNO=0\n");
        assert!(message.ready);
        assert_eq!(message.status.as_deref(), Some("running"));
        assert_eq!(message.errno, Some(0));
    }

    #[test]
    fn parse_watchdog_and_main_pid() {
        let message = NotifyMessage::parse(b"WATCHDOG=1\nMAINPID=1234\n");
        assert!(message.watchdog);
        assert_eq!(message.main_pid, Some(1234));
    }

    #[test]
    fn main_access_rejects_descendant() {
        // Safety: getpid and getppid have no preconditions.
        let (parent, current) = unsafe { (libc::getppid(), libc::getpid()) };
        let mut state = NotifyState::default();
        state.registrations.insert(
            parent,
            Registration {
                unit_name: "main.service".into(),
                access: NotifyAccess::Main,
                main_pid: parent,
            },
        );
        assert_eq!(authorized_unit(&state, current), None);
    }

    #[test]
    fn all_access_accepts_descendant() {
        // Safety: getpid and getppid have no preconditions.
        let (parent, current) = unsafe { (libc::getppid(), libc::getpid()) };
        let mut state = NotifyState::default();
        state.registrations.insert(
            parent,
            Registration {
                unit_name: "all.service".into(),
                access: NotifyAccess::All,
                main_pid: parent,
            },
        );
        assert_eq!(
            authorized_unit(&state, current).as_deref(),
            Some("all.service")
        );
    }

    #[test]
    fn notify_handler_limits_work_per_wake() {
        use std::os::unix::net::UnixDatagram;
        use std::time::{Duration, Instant};

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("notify-budget.sock");
        let server = NotifyServer::new_at(path.to_str().unwrap()).unwrap();
        // Safety: getpid has no preconditions.
        let pid = unsafe { libc::getpid() };
        server.register_pid(pid, "budget.service", NotifyAccess::Main);

        let sender = UnixDatagram::unbound().unwrap();
        sender.connect(&path).unwrap();
        let total_events = NOTIFY_EVENTS_PER_WAKE + 5;
        let producer = std::thread::spawn(move || {
            for _ in 0..total_events {
                sender.send(b"WATCHDOG=1").unwrap();
            }
        });

        let mut handler = server.io_handler();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut received_events = 0;
        while received_events < total_events && Instant::now() < deadline {
            handler.on_io(server.raw_fd(), libc::EPOLLIN as u32);
            let batch = server.drain_events().len();
            assert!(
                batch <= NOTIFY_EVENTS_PER_WAKE,
                "notify handler exceeded per-wake budget: {batch}"
            );
            received_events += batch;
            if batch == 0 {
                std::thread::yield_now();
            }
        }

        producer.join().unwrap();
        assert_eq!(received_events, total_events);
    }

    #[test]
    fn notification_sent_before_pid_registration_is_delivered() {
        use std::os::unix::net::UnixDatagram;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("notify-early.sock");
        let server = NotifyServer::new_at(path.to_str().unwrap()).unwrap();
        let sender = UnixDatagram::unbound().unwrap();
        sender.connect(&path).unwrap();
        sender.send(b"READY=1").unwrap();

        let mut handler = server.io_handler();
        handler.on_io(server.raw_fd(), libc::EPOLLIN as u32);
        assert!(server.drain_events().is_empty());

        // Safety: getpid has no preconditions and is the credential PID the
        // kernel attached to the datagram sent above.
        let pid = unsafe { libc::getpid() };
        server.register_pid(pid, "early.service", NotifyAccess::Main);
        let events = server.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].unit_name, "early.service");
        assert!(events[0].message.ready);
    }

    #[test]
    fn oversized_notify_datagram_is_rejected() {
        use std::os::unix::net::UnixDatagram;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("notify-truncated.sock");
        let server = NotifyServer::new_at(path.to_str().unwrap()).unwrap();
        let sender = UnixDatagram::unbound().unwrap();
        sender.connect(&path).unwrap();
        sender
            .send(&vec![b'x'; NOTIFY_BUFFER_SIZE + 1])
            .expect("send oversized notification");

        let mut buffer = vec![0u8; NOTIFY_BUFFER_SIZE];
        let error = receive_datagram(server.raw_fd(), &mut buffer)
            .expect_err("oversized notification must be rejected");
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .map(std::io::Error::kind),
            Some(std::io::ErrorKind::InvalidData)
        );
    }

    #[test]
    fn socket_enables_passcred() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("notify.sock");
        let server = NotifyServer::new_at(path.to_str().unwrap()).unwrap();
        let mut enabled: libc::c_int = 0;
        #[allow(clippy::cast_possible_truncation)]
        let mut length = std::mem::size_of_val(&enabled) as libc::socklen_t;
        // Safety: enabled and length point to writable values of the expected type.
        let result = unsafe {
            libc::getsockopt(
                server.raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PASSCRED,
                std::ptr::addr_of_mut!(enabled).cast(),
                &mut length,
            )
        };
        assert_eq!(result, 0);
        assert_eq!(enabled, 1);
    }
}
