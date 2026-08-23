// SPDX-License-Identifier: LGPL-2.1-or-later
//! Native uevent daemon for `RustD`.

use clap::{Parser, ValueEnum};
use rustd::udev::{
    add_persistent_storage_links, apply_rules, load_rules, persist_device, probe_block_metadata,
    Device, Rule,
};
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, Ordering};

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
                );
            }
        }
        if fds[0].revents & libc::POLLIN != 0 && !stopped.load(Ordering::Relaxed) {
            let mut buffer = [0_u8; 8192];
            let mut sender: libc::sockaddr_nl = unsafe { mem::zeroed() };
            let mut sender_len = mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
            let count = unsafe {
                libc::recvfrom(
                    netlink.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    0,
                    std::ptr::addr_of_mut!(sender).cast(),
                    &mut sender_len,
                )
            };
            // Kernel-originated uevents are sent by the netlink kernel peer.
            // Do not let another process on the netlink bus manufacture /dev.
            if count > 0 && sender.nl_pid == 0 {
                let event = &buffer[..count as usize];
                let sequence = uevent_sequence(event);
                if let Some(mut device) = Device::from_uevent(event) {
                    process_device(&rules, &global_properties, &mut device, arguments.dry_run);
                }
                // Publish the watermark only after this event has either been
                // fully processed or deliberately rejected by the parser.
                if let Some(sequence) = sequence {
                    if let Err(error) = mark_processed_sequence(sequence) {
                        eprintln!(
                            "rustd-udevd: failed to publish processed uevent sequence {sequence}: {error}"
                        );
                    }
                }
            }
        }
    }
    let _ = fs::remove_file(CONTROL_SOCKET);
    Ok(())
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
    // Keep the traditional queue marker for compatibility/debugging, but
    // udevadm settle uses sequence watermarks so a gap between two events
    // cannot be mistaken for an empty queue.
    let queue_written = fs::write(QUEUE_FILE, device.devpath.as_bytes()).is_ok();
    for (key, value) in global_properties {
        device.properties.insert(key.clone(), value.clone());
    }
    probe_block_metadata(device);
    apply_rules(rules, device);
    add_persistent_storage_links(device);
    if !dry_run {
        if let Err(error) = persist_device(device) {
            eprintln!("rustd-udevd: failed to persist {}: {error}", device.devpath);
        }
    }
    if queue_written {
        let _ = fs::remove_file(QUEUE_FILE);
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
    UnixListener::bind(CONTROL_SOCKET)
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
) {
    let mut bytes = [0_u8; 256];
    let count = stream.read(&mut bytes).unwrap_or(0);
    let raw = String::from_utf8_lossy(&bytes[..count]);
    let message = raw.trim();
    let command = message.to_ascii_lowercase();

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
