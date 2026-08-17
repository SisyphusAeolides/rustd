// SPDX-License-Identifier: LGPL-2.1-or-later
//! Native uevent daemon for `RustD`.

use clap::Parser;
use rustd::udev::{apply_rules, load_rules, persist_device, Device, Rule};
use std::fs;
use std::io::{self, Read};
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, Ordering};

const CONTROL_SOCKET: &str = "/run/udev/control";

#[derive(Parser)]
#[command(name = "rustd-udevd", about = "RustD device event daemon")]
struct Arguments {
    /// Do not daemonize; `RustD` services always use this mode.
    #[arg(long)]
    daemon: bool,
    /// Do not create nodes or execute RUN rules.
    #[arg(long)]
    dry_run: bool,
}

fn main() -> anyhow::Result<()> {
    let arguments = Arguments::parse();
    let _ = arguments.daemon;
    fs::create_dir_all("/run/udev/data")?;
    let listener = bind_control_socket()?;
    let netlink = open_uevent_socket()?;
    let mut rules = load_rules().unwrap_or_else(|error| {
        eprintln!("rustd-udevd: failed to load rules: {error}");
        Vec::new()
    });
    let running = AtomicBool::new(true);
    let stopped = AtomicBool::new(false);
    while running.load(Ordering::Relaxed) {
        let mut fds = [
            libc::pollfd {
                fd: netlink.as_raw_fd(),
                events: libc::POLLIN,
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
                handle_control(stream, &mut rules, &running, &stopped);
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
                if let Some(mut device) = Device::from_uevent(&buffer[..count as usize]) {
                    process_device(&rules, &mut device, arguments.dry_run);
                }
            }
        }
    }
    let _ = fs::remove_file(CONTROL_SOCKET);
    Ok(())
}

fn process_device(rules: &[Rule], device: &mut Device, dry_run: bool) {
    // The queue file is the compatibility contract used by udevadm settle.
    if fs::write("/run/udev/queue", device.devpath.as_bytes()).is_err() {
        return;
    }
    apply_rules(rules, device);
    if !dry_run {
        if let Err(error) = persist_device(device) {
            eprintln!("rustd-udevd: failed to persist {}: {error}", device.devpath);
        }
    }
    let _ = fs::remove_file("/run/udev/queue");
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
    running: &AtomicBool,
    stopped: &AtomicBool,
) {
    let mut bytes = [0_u8; 256];
    let count = stream.read(&mut bytes).unwrap_or(0);
    let message = String::from_utf8_lossy(&bytes[..count]).to_ascii_lowercase();
    // rustudevadm sends these newline commands. Also recognize words in the
    // fixed-size systemd control packet to make the socket safely useful to
    // simple third-party clients.
    if message.contains("exit") {
        running.store(false, Ordering::Relaxed);
    } else if message.contains("reload") {
        match load_rules() {
            Ok(new_rules) => *rules = new_rules,
            Err(error) => eprintln!("rustd-udevd: reload failed: {error}"),
        }
    } else if message.contains("stop") {
        stopped.store(true, Ordering::Relaxed);
    } else if message.contains("start") {
        stopped.store(false, Ordering::Relaxed);
    }
    let _ = std::io::Write::write_all(&mut stream, b"OK\n");
}
