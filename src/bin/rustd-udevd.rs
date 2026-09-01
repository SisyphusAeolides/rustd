// SPDX-License-Identifier: LGPL-2.1-or-later
//! Native uevent daemon for `RustD`.

use clap::{Parser, ValueEnum};
use rustd::udev::{
    add_persistent_storage_links, apply_rules, load_rules, persist_device,
    populate_device_mapper_metadata, probe_block_metadata, Device, Rule,
};
use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::fs;
use std::io::{self, Read, Write};
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const CONTROL_SOCKET: &str = "/run/udev/control";
const QUEUE_FILE: &str = "/run/udev/queue";
const LAST_SEQNUM_FILE: &str = "/run/udev/last-seqnum";
const UEVENT_RECEIVE_BUFFER_SIZE: libc::c_int = 128 * 1024 * 1024;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ResolveNames {
    Early,
    Late,
    Never,
}

#[derive(Parser)]
#[command(name = "rustd-udevd", about = "RustD device event daemon")]
struct Arguments {
    /// Fork into the background after argument validation.
    #[arg(long)]
    daemon: bool,
    /// Compatibility option used by dracut's udev startup path.
    #[arg(long, value_enum, value_name = "MODE")]
    resolve_names: Option<ResolveNames>,
    /// Do not create nodes or execute RUN rules.
    #[arg(long)]
    dry_run: bool,
}

fn main() -> anyhow::Result<()> {
    let arguments = Arguments::parse();
    // RustD's native rule engine does not resolve owner/group names while
    // handling kernel events, so every accepted compatibility mode is safe.
    let _ = arguments.resolve_names;
    let readiness = if arguments.daemon { daemonize()? } else { None };

    fs::create_dir_all("/run/udev/data")?;
    let listener = bind_control_socket()?;
    let netlink = open_uevent_socket()?;
    let mut rules = load_rules().unwrap_or_else(|error| {
        eprintln!("rustd-udevd: failed to load rules: {error}");
        Vec::new()
    });
    if let Some(readiness) = readiness {
        let mut readiness = fs::File::from(readiness);
        readiness.write_all(b"1")?;
    }
    let mut global_properties = BTreeMap::new();
    let running = AtomicBool::new(true);
    let stopped = AtomicBool::new(false);
    while running.load(Ordering::Relaxed) {
        let mut fds = [
            libc::pollfd {
                fd: netlink.as_raw_fd(),
                events: if stopped.load(Ordering::Relaxed) {
                    0
                } else {
                    libc::POLLIN
                },
                revents: 0,
            },
            libc::pollfd {
                fd: listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
        if ready < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(io::Error::last_os_error().into());
        }
        if fds[1].revents & libc::POLLIN != 0 {
            if let Ok((stream, _)) = listener.accept() {
                handle_control(
                    stream,
                    &mut rules,
                    &mut global_properties,
                    &running,
                    &stopped,
                    arguments.dry_run,
                    netlink.as_raw_fd(),
                );
            }
        }
        if fds[0].revents & libc::POLLIN != 0 && !stopped.load(Ordering::Relaxed) {
            process_pending_events(
                netlink.as_raw_fd(),
                &rules,
                &global_properties,
                arguments.dry_run,
            )?;
        }
    }
    let _ = fs::remove_file(CONTROL_SOCKET);
    Ok(())
}

/// Drain and process every kernel event currently available to the daemon.
///
/// The queue marker is created before the first event is handled and removed
/// only after a final non-blocking receive. This gives `rustudevadm settle`
/// one authoritative state transition to wait for instead of racing the
/// kernel's asynchronous netlink delivery.
fn process_pending_events(
    netlink_fd: libc::c_int,
    rules: &[Rule],
    global_properties: &BTreeMap<String, String>,
    dry_run: bool,
) -> io::Result<bool> {
    let mut events = VecDeque::new();
    receive_pending_events(netlink_fd, &mut events)?;
    if events.is_empty() {
        return Ok(false);
    }

    fs::write(QUEUE_FILE, b"1\n")?;
    while let Some(event) = events.pop_front() {
        let sequence = uevent_sequence(&event);
        if let Some(mut device) = Device::from_uevent(&event) {
            process_device(rules, global_properties, &mut device, dry_run);
        }
        if let Some(sequence) = sequence {
            if let Err(error) = mark_processed_sequence(sequence) {
                eprintln!(
                    "rustd-udevd: failed to publish processed uevent sequence {sequence}: {error}"
                );
            }
        }
        // Coldplug can produce more events while a RUN rule is being handled.
        // Keep the queue marker present until the socket and userspace
        // backlog are both empty.
        receive_pending_events(netlink_fd, &mut events)?;
    }
    let _ = fs::remove_file(QUEUE_FILE);
    Ok(true)
}

fn daemonize() -> io::Result<Option<OwnedFd>> {
    let mut readiness = [0; 2];
    if unsafe { libc::pipe2(readiness.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let read_end = unsafe { OwnedFd::from_raw_fd(readiness[0]) };
    let write_end = unsafe { OwnedFd::from_raw_fd(readiness[1]) };

    let first = unsafe { libc::fork() };
    if first < 0 {
        return Err(io::Error::last_os_error());
    }
    if first > 0 {
        drop(write_end);
        let mut ready = 0_u8;
        let count = unsafe {
            libc::read(
                read_end.as_raw_fd(),
                std::ptr::addr_of_mut!(ready).cast(),
                1,
            )
        };
        unsafe { libc::_exit(i32::from(count != 1 || ready != b'1')) };
    }
    drop(read_end);

    if unsafe { libc::setsid() } < 0 {
        return Err(io::Error::last_os_error());
    }

    let second = unsafe { libc::fork() };
    if second < 0 {
        return Err(io::Error::last_os_error());
    }
    if second > 0 {
        drop(write_end);
        unsafe { libc::_exit(0) };
    }

    std::env::set_current_dir("/")?;
    let null = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")?;
    for fd in libc::STDIN_FILENO..=libc::STDERR_FILENO {
        if unsafe { libc::dup2(null.as_raw_fd(), fd) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(Some(write_end))
}

fn process_device(
    rules: &[Rule],
    global_properties: &BTreeMap<String, String>,
    device: &mut Device,
    dry_run: bool,
) {
    for (key, value) in global_properties {
        device.properties.insert(key.clone(), value.clone());
    }
    probe_block_metadata(device);
    populate_device_mapper_metadata(device);
    // Persistent links must be available while rules are evaluated. Dracut's
    // live-root rule matches the by-label link and queues the squashfs mount
    // from that event; adding the links after rule evaluation leaves a
    // CDLABEL/USBLABEL root waiting forever in early userspace.
    add_persistent_storage_links(device);
    apply_rules(rules, device);
    if !dry_run {
        if let Err(error) = persist_device(device) {
            eprintln!("rustd-udevd: failed to persist {}: {error}", device.devpath);
        }
    }
}

fn receive_pending_events(fd: libc::c_int, events: &mut VecDeque<Vec<u8>>) -> io::Result<()> {
    loop {
        let mut buffer = [0_u8; 8192];
        let mut sender: libc::sockaddr_nl = unsafe { mem::zeroed() };
        let mut sender_len = mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
        let count = unsafe {
            libc::recvfrom(
                fd,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                libc::MSG_DONTWAIT,
                std::ptr::addr_of_mut!(sender).cast(),
                &mut sender_len,
            )
        };
        if count < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock {
                return Ok(());
            }
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if count == 0 {
            return Ok(());
        }
        // Kernel-originated uevents are sent by the netlink kernel peer. Do
        // not let another process on the netlink bus manufacture /dev.
        if sender.nl_pid == 0 {
            events.push_back(buffer[..count as usize].to_vec());
        }
    }
}

fn uevent_sequence(bytes: &[u8]) -> Option<u64> {
    bytes
        .split(|byte| *byte == 0)
        .filter_map(|field| std::str::from_utf8(field).ok())
        .find_map(|field| field.strip_prefix("SEQNUM=")?.parse().ok())
}

fn mark_processed_sequence(sequence: u64) -> io::Result<()> {
    let temporary = format!("{LAST_SEQNUM_FILE}.tmp");
    fs::write(&temporary, format!("{sequence}\n"))?;
    fs::rename(temporary, LAST_SEQNUM_FILE)
}

fn bind_control_socket() -> io::Result<UnixListener> {
    fs::create_dir_all("/run/udev")?;
    let _ = fs::remove_file(CONTROL_SOCKET);
    let listener = UnixListener::bind(CONTROL_SOCKET)?;
    // udev's control channel is a privileged interface.  In addition to
    // matching the standard socket mode, this prevents an unprivileged
    // process from injecting synthetic device events into RustD.
    fs::set_permissions(CONTROL_SOCKET, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

fn open_uevent_socket() -> io::Result<OwnedFd> {
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_KOBJECT_UEVENT,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let receive_buffer = UEVENT_RECEIVE_BUFFER_SIZE;
    let receive_buffer_result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUFFORCE,
            std::ptr::addr_of!(receive_buffer).cast(),
            mem::size_of_val(&receive_buffer) as libc::socklen_t,
        )
    };
    if receive_buffer_result < 0 {
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                std::ptr::addr_of!(receive_buffer).cast(),
                mem::size_of_val(&receive_buffer) as libc::socklen_t,
            )
        };
    }
    let mut address: libc::sockaddr_nl = unsafe { mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    address.nl_pid = 0;
    address.nl_groups = 1;
    let result = unsafe {
        libc::bind(
            fd,
            std::ptr::addr_of!(address).cast(),
            mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if result < 0 {
        let error = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(error);
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn handle_control(
    mut stream: UnixStream,
    rules: &mut Vec<Rule>,
    global_properties: &mut BTreeMap<String, String>,
    running: &AtomicBool,
    stopped: &AtomicBool,
    dry_run: bool,
    netlink_fd: libc::c_int,
) {
    let mut bytes = [0_u8; 4096];
    let count = stream.read(&mut bytes).unwrap_or(0);
    let raw = String::from_utf8_lossy(&bytes[..count]);
    let message = raw.trim();
    let command = message.to_ascii_lowercase();

    if let Some(timeout) = message.strip_prefix("settle=") {
        let timeout = timeout.parse::<u64>().unwrap_or(120).min(24 * 60 * 60);
        let result = settle_events(
            netlink_fd,
            rules,
            global_properties,
            dry_run,
            Duration::from_secs(timeout),
        );
        let reply = if let Err(error) = result {
            eprintln!("rustd-udevd: settle failed: {error}");
            b"ERR\n".as_slice()
        } else {
            b"OK\n".as_slice()
        };
        let _ = std::io::Write::write_all(&mut stream, reply);
        return;
    }

    if let Some(payload) = message.strip_prefix("trigger=") {
        let reply = match process_synthetic_trigger(payload, rules, global_properties, dry_run) {
            Ok(()) => b"OK\n".as_slice(),
            Err(error) => {
                eprintln!("rustd-udevd: synthetic trigger rejected: {error}");
                b"ERR\n"
            }
        };
        let _ = std::io::Write::write_all(&mut stream, reply);
        return;
    }

    if let Some(property) = message.strip_prefix("property=") {
        let Some((key, value)) = property.split_once('=') else {
            let _ = std::io::Write::write_all(&mut stream, b"ERR\n");
            return;
        };
        if key.is_empty() {
            let _ = std::io::Write::write_all(&mut stream, b"ERR\n");
            return;
        }
        if value.is_empty() {
            global_properties.remove(key);
        } else {
            global_properties.insert(key.to_string(), value.to_string());
        }
    } else if command == "exit" {
        running.store(false, Ordering::Relaxed);
    } else if command == "reload" {
        match load_rules() {
            Ok(new_rules) => *rules = new_rules,
            Err(error) => eprintln!("rustd-udevd: reload failed: {error}"),
        }
    } else if command == "stop" {
        stopped.store(true, Ordering::Relaxed);
    } else if command == "start" {
        stopped.store(false, Ordering::Relaxed);
    }
    // Unknown compatibility control commands are acknowledged as no-ops. That
    // keeps synchronous RustD processing honest while allowing harmless
    // log-level/ping tuning requests used by early userspace.
    let _ = std::io::Write::write_all(&mut stream, b"OK\n");
}

/// Wait until the daemon has observed and processed all currently pending
/// kernel events, including events that arrive shortly after a trigger write.
///
/// The short quiet period mirrors udev's queue-settle behavior while keeping
/// the implementation single-threaded: the control request itself services
/// the netlink fd, so a settle request cannot be acknowledged ahead of an
/// event already queued in the kernel.
fn settle_events(
    netlink_fd: libc::c_int,
    rules: &[Rule],
    global_properties: &BTreeMap<String, String>,
    dry_run: bool,
    timeout: Duration,
) -> io::Result<()> {
    let start = std::time::Instant::now();
    let quiet_period = Duration::from_millis(100);

    loop {
        if process_pending_events(netlink_fd, rules, global_properties, dry_run)? {
            continue;
        }

        if start.elapsed() >= timeout {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "udev event queue did not become idle",
            ));
        }

        let remaining = timeout.saturating_sub(start.elapsed());
        let wait = remaining.min(quiet_period);
        let timeout_ms = i32::try_from(wait.as_millis()).unwrap_or(i32::MAX).max(1);
        let mut pollfd = libc::pollfd {
            fd: netlink_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut pollfd, 1, timeout_ms) };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if result == 0 {
            // Confirm that no event arrived during the quiet interval. A
            // final receive closes the small poll-to-return race.
            if !process_pending_events(netlink_fd, rules, global_properties, dry_run)? {
                return Ok(());
            }
        }
    }
}

fn process_synthetic_trigger(
    payload: &str,
    rules: &[Rule],
    global_properties: &BTreeMap<String, String>,
    dry_run: bool,
) -> io::Result<()> {
    let (action, raw_path) = payload.split_once('\t').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "trigger command must contain action and sysfs path",
        )
    })?;
    if !matches!(action, "add" | "change" | "remove" | "bind" | "unbind") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsupported uevent action",
        ));
    }

    let path = Path::new(raw_path);
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "synthetic uevent path is not absolute",
        ));
    }
    let path = path.canonicalize()?;
    if path == Path::new("/sys") || !path.starts_with("/sys") {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "synthetic uevent path is outside sysfs",
        ));
    }
    if !path.join("uevent").is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "sysfs device has no uevent file",
        ));
    }

    let mut device = Device::from_syspath(action, &path)?;
    process_device(rules, global_properties, &mut device, dry_run);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_dracut_daemon_arguments() {
        let args = Arguments::try_parse_from(["rustd-udevd", "--daemon", "--resolve-names=never"])
            .expect("dracut udev daemon arguments must parse");
        assert!(args.daemon);
        assert!(matches!(args.resolve_names, Some(ResolveNames::Never)));
    }

    #[test]
    fn extracts_kernel_uevent_sequence() {
        let event = b"add@/devices/test\0ACTION=add\0DEVPATH=/devices/test\0SEQNUM=4242\0";
        assert_eq!(uevent_sequence(event), Some(4242));
    }
}
