// SPDX-License-Identifier: LGPL-2.1-or-later

use std::env;
use std::fs::File;
use std::io::{self, Read};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::os::fd::{FromRawFd, IntoRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::process::exit;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const VERSION: &str = concat!("RustD ", env!("CARGO_PKG_VERSION"));
const DEFAULT_CONNECTIONS_MAX: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProxyProtocol {
    None,
    V1,
}

#[derive(Debug)]
struct Config {
    remote: String,
    connections_max: usize,
    exit_idle_time: Option<Duration>,
    proxy_protocol: ProxyProtocol,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("rustd-socket-proxyd: {error}");
        exit(1);
    }
}

fn run() -> Result<(), String> {
    let Some(config) = parse_args(env::args().skip(1).collect())? else {
        return Ok(());
    };
    let inherited = rustd::native::listen_fds(true)
        .map_err(|error| format!("Failed to receive sockets from parent: {error}"))?;
    if inherited == 0 {
        return Err(String::from("Didn't get any sockets passed in."));
    }

    let listeners: Vec<RawFd> = (0..inherited)
        .map(|offset| 3 + i32::try_from(offset).expect("socket descriptor offset fits i32"))
        .collect();
    for &fd in &listeners {
        validate_listener(fd)?;
        set_nonblocking(fd)?;
    }

    let active = Arc::new(AtomicUsize::new(0));
    let mut idle_since = Instant::now();
    let _ = rustd::native::notify_ready();

    loop {
        let mut pollfds: Vec<libc::pollfd> = listeners
            .iter()
            .map(|&fd| libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        let timeout_ms = poll_timeout_ms(
            config.exit_idle_time,
            idle_since,
            active.load(Ordering::Acquire),
        );
        // SAFETY: pollfds points to a valid writable array for the duration of poll().
        let result = unsafe {
            libc::poll(
                pollfds.as_mut_ptr(),
                libc::nfds_t::try_from(pollfds.len()).expect("listener count fits nfds_t"),
                timeout_ms,
            )
        };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("Failed to poll listening sockets: {error}"));
        }

        if result == 0 {
            if config.exit_idle_time.is_some() && active.load(Ordering::Acquire) == 0 {
                break;
            }
            continue;
        }

        for pollfd in &pollfds {
            if pollfd.revents & libc::POLLIN == 0 {
                continue;
            }
            loop {
                match accept_connection(pollfd.fd) {
                    Ok(Some(server_fd)) => {
                        let current = active.load(Ordering::Acquire);
                        if current >= config.connections_max {
                            close_fd(server_fd);
                            continue;
                        }
                        active.fetch_add(1, Ordering::AcqRel);
                        idle_since = Instant::now();
                        let remote = config.remote.clone();
                        let proxy = config.proxy_protocol;
                        let active_for_thread = Arc::clone(&active);
                        thread::spawn(move || {
                            if let Err(error) = proxy_one(server_fd, &remote, proxy) {
                                eprintln!("rustd-socket-proxyd: {error}");
                            }
                            active_for_thread.fetch_sub(1, Ordering::AcqRel);
                        });
                    }
                    Ok(None) => break,
                    Err(error) => {
                        eprintln!("rustd-socket-proxyd: Failed to accept socket: {error}");
                        break;
                    }
                }
            }
        }
        if active.load(Ordering::Acquire) == 0 {
            idle_since = Instant::now();
        }
    }

    let _ = rustd::native::notify_stopping();
    Ok(())
}

fn parse_args(args: Vec<String>) -> Result<Option<Config>, String> {
    let mut connections_max = DEFAULT_CONNECTIONS_MAX;
    let mut exit_idle_time = None;
    let mut proxy_protocol = ProxyProtocol::None;
    let mut positional = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        match arg.as_str() {
            "-h" | "--help" => {
                print_help();
                return Ok(None);
            }
            "--version" => {
                println!("{VERSION}");
                return Ok(None);
            }
            "-c" | "--connections-max" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| format!("Missing value for {arg}."))?;
                connections_max = parse_connections(value)?;
            }
            "--exit-idle-time" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| format!("Missing value for {arg}."))?;
                exit_idle_time = Some(parse_duration(value)?);
            }
            "--proxy-protocol" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| format!("Missing value for {arg}."))?;
                proxy_protocol = parse_proxy_protocol(value)?;
            }
            _ if arg.starts_with("--connections-max=") => {
                connections_max = parse_connections(arg.trim_start_matches("--connections-max="))?;
            }
            _ if arg.starts_with("--exit-idle-time=") => {
                exit_idle_time = Some(parse_duration(arg.trim_start_matches("--exit-idle-time="))?);
            }
            _ if arg.starts_with("--proxy-protocol=") => {
                proxy_protocol = parse_proxy_protocol(arg.trim_start_matches("--proxy-protocol="))?;
            }
            _ if arg.starts_with('-') => return Err(format!("Unknown option '{arg}'.")),
            _ => positional.push(arg.clone()),
        }
        index += 1;
    }
    if positional.is_empty() {
        return Err(String::from("Not enough parameters."));
    }
    if positional.len() > 1 {
        return Err(String::from("Too many parameters."));
    }
    Ok(Some(Config {
        remote: positional.remove(0),
        connections_max,
        exit_idle_time,
        proxy_protocol,
    }))
}

fn print_help() {
    println!("rustd-socket-proxyd [OPTIONS...] HOST:PORT");
    println!("rustd-socket-proxyd [OPTIONS...] SOCKET");
    println!();
    println!("Bidirectionally proxy local sockets to another socket.");
    println!();
    println!("  -c --connections-max=NUMBER  Maximum simultaneous connections");
    println!("     --exit-idle-time=TIME     Exit after being idle for TIME");
    println!("     --proxy-protocol=v1       Send PROXY protocol v1 header");
    println!("  -h --help                    Show this help");
    println!("     --version                 Show package version");
}

fn parse_connections(value: &str) -> Result<usize, String> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| format!("Failed to parse --connections-max= argument: {value}"))?;
    if parsed == 0 {
        return Err(String::from("Connection limit is too low."));
    }
    Ok(parsed)
}

fn parse_proxy_protocol(value: &str) -> Result<ProxyProtocol, String> {
    match value {
        "v1" => Ok(ProxyProtocol::V1),
        _ => Err(format!(
            "Failed to parse --proxy-protocol= argument: {value}"
        )),
    }
}

fn parse_duration(value: &str) -> Result<Duration, String> {
    let value = value.trim();
    if value == "infinity" || value == "infinite" {
        return Ok(Duration::MAX);
    }
    let (number, multiplier) = if let Some(number) = value.strip_suffix("ms") {
        (number, 0.001)
    } else if let Some(number) = value.strip_suffix("min") {
        (number, 60.0)
    } else if let Some(number) = value.strip_suffix('h') {
        (number, 3600.0)
    } else if let Some(number) = value.strip_suffix('s') {
        (number, 1.0)
    } else {
        (value, 1.0)
    };
    let number = number
        .trim()
        .parse::<f64>()
        .map_err(|_| format!("Failed to parse --exit-idle-time= argument: {value}"))?;
    if !number.is_finite() || number < 0.0 {
        return Err(format!(
            "Failed to parse --exit-idle-time= argument: {value}"
        ));
    }
    Ok(Duration::from_secs_f64(number * multiplier))
}

fn poll_timeout_ms(idle: Option<Duration>, since: Instant, active: usize) -> i32 {
    let Some(idle) = idle else {
        return -1;
    };
    if idle == Duration::MAX || active > 0 {
        return -1;
    }
    let remaining = idle.saturating_sub(since.elapsed());
    i32::try_from(remaining.as_millis().min(i32::MAX as u128)).unwrap_or(i32::MAX)
}

fn validate_listener(fd: RawFd) -> Result<(), String> {
    let mut socket_type: libc::c_int = 0;
    let mut type_len = libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>())
        .expect("socket type length fits socklen_t");
    // SAFETY: pointers reference valid writable storage and fd is supplied by rustd_listen_fds().
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            std::ptr::addr_of_mut!(socket_type).cast(),
            std::ptr::addr_of_mut!(type_len),
        )
    };
    if result < 0 {
        return Err(format!(
            "Failed to determine socket type: {}",
            io::Error::last_os_error()
        ));
    }
    if socket_type != libc::SOCK_STREAM {
        return Err(String::from("Passed in socket is not a stream socket."));
    }
    let mut accepting: libc::c_int = 0;
    let mut accepting_len = libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>())
        .expect("accepting length fits socklen_t");
    // SAFETY: pointers reference valid writable storage.
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ACCEPTCONN,
            std::ptr::addr_of_mut!(accepting).cast(),
            std::ptr::addr_of_mut!(accepting_len),
        )
    };
    if result < 0 || accepting == 0 {
        return Err(String::from(
            "Passed in socket is not a listening stream socket.",
        ));
    }
    Ok(())
}

fn set_nonblocking(fd: RawFd) -> Result<(), String> {
    // SAFETY: fcntl operates on the caller-owned descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(format!(
            "Failed to read descriptor flags: {}",
            io::Error::last_os_error()
        ));
    }
    // SAFETY: fcntl operates on the caller-owned descriptor.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(format!(
            "Failed to mark descriptor nonblocking: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn accept_connection(fd: RawFd) -> Result<Option<RawFd>, io::Error> {
    // SAFETY: accept4 receives no address and creates a new descriptor on success.
    let accepted = unsafe {
        libc::accept4(
            fd,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_CLOEXEC,
        )
    };
    if accepted >= 0 {
        return Ok(Some(accepted));
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::WouldBlock {
        Ok(None)
    } else {
        Err(error)
    }
}

fn proxy_one(server_fd: RawFd, remote: &str, protocol: ProxyProtocol) -> Result<(), String> {
    let client_fd = connect_remote(remote)?;
    if protocol == ProxyProtocol::V1 {
        let header = proxy_v1_header(server_fd);
        write_all_fd(client_fd, header.as_bytes())?;
    }

    // SAFETY: these descriptors are uniquely owned by this connection thread.
    let server = unsafe { File::from_raw_fd(server_fd) };
    // SAFETY: connect_remote returns a newly owned descriptor.
    let client = unsafe { File::from_raw_fd(client_fd) };
    forward_bidirectional(server, client)
}

fn connect_remote(remote: &str) -> Result<RawFd, String> {
    if remote.starts_with('/') {
        return UnixStream::connect(remote)
            .map(IntoRawFd::into_raw_fd)
            .map_err(|error| format!("Failed to connect to remote UNIX socket: {error}"));
    }
    if let Some(name) = remote.strip_prefix('@') {
        return connect_abstract_unix(name);
    }

    let target = if remote.contains(':') {
        remote.to_owned()
    } else {
        format!("{remote}:80")
    };
    let mut last_error = None;
    let addresses = target
        .to_socket_addrs()
        .map_err(|error| format!("Failed to resolve remote host: {error}"))?;
    for address in addresses {
        match TcpStream::connect(address) {
            Ok(stream) => return Ok(stream.into_raw_fd()),
            Err(error) => last_error = Some(error),
        }
    }
    Err(format!(
        "Failed to connect to remote host: {}",
        last_error.map_or_else(
            || "no addresses returned".to_owned(),
            |error| error.to_string()
        )
    ))
}

fn connect_abstract_unix(name: &str) -> Result<RawFd, String> {
    if name.len() + 1 >= 108 {
        return Err(String::from("Specified AF_UNIX address is too long."));
    }
    // SAFETY: socket() has no Rust memory preconditions.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(format!(
            "Failed to create UNIX socket: {}",
            io::Error::last_os_error()
        ));
    }
    // SAFETY: zero is a valid initialization for sockaddr_un.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (index, byte) in name.as_bytes().iter().enumerate() {
        address.sun_path[index + 1] = *byte as libc::c_char;
    }
    let length = std::mem::size_of::<libc::sa_family_t>() + 1 + name.len();
    // SAFETY: address points to an initialized sockaddr_un and length covers its active prefix.
    let result = unsafe {
        libc::connect(
            fd,
            std::ptr::addr_of!(address).cast(),
            libc::socklen_t::try_from(length).expect("UNIX address length fits socklen_t"),
        )
    };
    if result < 0 {
        let error = io::Error::last_os_error();
        close_fd(fd);
        return Err(format!("Failed to connect to remote UNIX socket: {error}"));
    }
    Ok(fd)
}

fn proxy_v1_header(server_fd: RawFd) -> String {
    let Some(remote) = socket_address(server_fd, false) else {
        return String::from("PROXY UNKNOWN\r\n");
    };
    let Some(local) = socket_address(server_fd, true) else {
        return String::from("PROXY UNKNOWN\r\n");
    };
    match (remote, local) {
        (SocketAddr::V4(remote), SocketAddr::V4(local)) => format!(
            "PROXY TCP4 {} {} {} {}\r\n",
            remote.ip(),
            local.ip(),
            remote.port(),
            local.port()
        ),
        (SocketAddr::V6(remote), SocketAddr::V6(local)) => format!(
            "PROXY TCP6 {} {} {} {}\r\n",
            remote.ip(),
            local.ip(),
            remote.port(),
            local.port()
        ),
        _ => String::from("PROXY UNKNOWN\r\n"),
    }
}

fn socket_address(fd: RawFd, local: bool) -> Option<SocketAddr> {
    // SAFETY: zeroed sockaddr_storage is valid output storage for getsockname/getpeername.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut length =
        libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_storage>()).ok()?;
    // SAFETY: storage and length are valid writable outputs.
    let result = unsafe {
        if local {
            libc::getsockname(fd, std::ptr::addr_of_mut!(storage).cast(), &mut length)
        } else {
            libc::getpeername(fd, std::ptr::addr_of_mut!(storage).cast(), &mut length)
        }
    };
    if result < 0 {
        return None;
    }
    match i32::from(storage.ss_family) {
        libc::AF_INET => {
            // SAFETY: family identifies sockaddr_in layout.
            let address = unsafe { &*std::ptr::addr_of!(storage).cast::<libc::sockaddr_in>() };
            let ip = std::net::Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes());
            Some(SocketAddr::new(ip.into(), u16::from_be(address.sin_port)))
        }
        libc::AF_INET6 => {
            // SAFETY: family identifies sockaddr_in6 layout.
            let address = unsafe { &*std::ptr::addr_of!(storage).cast::<libc::sockaddr_in6>() };
            let ip = std::net::Ipv6Addr::from(address.sin6_addr.s6_addr);
            Some(SocketAddr::new(ip.into(), u16::from_be(address.sin6_port)))
        }
        _ => None,
    }
}

fn write_all_fd(fd: RawFd, data: &[u8]) -> Result<(), String> {
    let mut offset = 0;
    while offset < data.len() {
        // SAFETY: data[offset..] is valid readable memory; fd is an open socket.
        let written =
            unsafe { libc::write(fd, data[offset..].as_ptr().cast(), data.len() - offset) };
        if written < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("Failed to write to backend host: {error}"));
        }
        offset += usize::try_from(written).expect("write result is nonnegative");
    }
    Ok(())
}

fn forward_bidirectional(server: File, client: File) -> Result<(), String> {
    let mut server_read = server
        .try_clone()
        .map_err(|error| format!("Failed to duplicate incoming socket: {error}"))?;
    let server_write_fd = server.into_raw_fd();
    let mut client_read = client
        .try_clone()
        .map_err(|error| format!("Failed to duplicate backend socket: {error}"))?;
    let client_write_fd = client.into_raw_fd();

    let outbound = thread::spawn(move || copy_and_shutdown(&mut server_read, client_write_fd));
    let inbound = copy_and_shutdown(&mut client_read, server_write_fd);
    let outbound = outbound
        .join()
        .map_err(|_| String::from("Socket forwarding thread panicked."))?;
    inbound?;
    outbound
}

fn copy_and_shutdown(source: &mut File, destination_fd: RawFd) -> Result<(), String> {
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let length = source
            .read(&mut buffer)
            .map_err(|error| format!("Forwarding failed while reading: {error}"))?;
        if length == 0 {
            break;
        }
        write_all_fd(destination_fd, &buffer[..length])?;
    }
    // SAFETY: destination_fd is an open socket; SHUT_WR is valid.
    unsafe {
        libc::shutdown(destination_fd, libc::SHUT_WR);
        libc::close(destination_fd);
    }
    Ok(())
}

fn close_fd(fd: RawFd) {
    // SAFETY: caller transfers ownership of fd for closure.
    unsafe {
        libc::close(fd);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_connection_limit() {
        assert_eq!(parse_connections("256").unwrap(), 256);
        assert!(parse_connections("0").is_err());
    }

    #[test]
    fn parses_proxy_v1_only() {
        assert_eq!(parse_proxy_protocol("v1").unwrap(), ProxyProtocol::V1);
        assert!(parse_proxy_protocol("v2").is_err());
    }

    #[test]
    fn parses_idle_times() {
        assert_eq!(parse_duration("5s").unwrap(), Duration::from_secs(5));
        assert_eq!(parse_duration("2min").unwrap(), Duration::from_secs(120));
        assert_eq!(parse_duration("250ms").unwrap(), Duration::from_millis(250));
    }
}
