// SPDX-License-Identifier: LGPL-2.1-or-later
//! `systemd-socket-activate` v261 compatibility utility.
//!
//! Upstream reference: systemd v261
//! `src/socket-activate/socket-activate.c`.

use std::env;
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::mem::{self, MaybeUninit};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use rustd::ffi::native::rustd_listen_fds;
use rustd::ffi::notify::rustd_notify_send;

const LISTEN_FDS_START: RawFd = 3;
const FDNAME_MAX: usize = 255;

const VERSION_OUTPUT: &[u8] = concat!(
    "systemd 261 (261.2-1-arch)\n",
    "+PAM +AUDIT -SELINUX +APPARMOR -IMA +IPE +SMACK +SECCOMP +GCRYPT +GNUTLS +OPENSSL +ACL ",
    "+BLKID +CURL +ELFUTILS +FIDO2 +IDN2 +KMOD +LIBCRYPTSETUP +LIBCRYPTSETUP_PLUGINS +LIBFDISK ",
    "+PCRE2 +PWQUALITY +P11KIT +QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB +ZSTD +BPF_FRAMEWORK +BTF ",
    "+XKBCOMMON +UTMP +LIBARCHIVE\n"
)
.as_bytes();

const HELP: &[u8] = concat!(
    "systemd-socket-activate [OPTIONS...] COMMAND ...\n\n",
    "Listen on sockets and launch child on connection.\n\n",
    "Options:\n",
    "  -h --help                  Show this help\n",
    "     --version               Show package version\n",
    "  -l --listen=ADDR           Listen for raw connections at ADDR\n",
    "  -d --datagram              Listen on datagram instead of stream socket\n",
    "     --seqpacket             Listen on SOCK_SEQPACKET instead of stream socket\n",
    "  -a --accept                Spawn separate child for each connection\n",
    "  -E --setenv=NAME[=VALUE]   Pass an environment variable to children\n",
    "     --fdname=NAME[:NAME...] Specify names for file descriptors\n",
    "     --inetd                 Enable inetd file descriptor passing protocol\n",
    "     --now                   Start instantly instead of waiting for connection\n\n",
    "Note: file descriptors from sd_listen_fds() will be passed through.\n\n",
    "See the systemd-socket-activate(1) man page for details.\n"
)
.as_bytes();

fn help_output() -> Vec<u8> {
    let colors = colors_enabled();
    let urlify = environment_boolean("SYSTEMD_URLIFY", false).unwrap_or(colors);
    if !colors && !urlify {
        return HELP.to_vec();
    }

    let mut output = HELP.to_vec();
    if colors {
        decorate_help_fragment(
            &mut output,
            b"Listen on sockets and launch child on connection.",
            b"\x1b[0;1;39m",
            b"\x1b[0m",
        );
        decorate_help_fragment(&mut output, b"Options:", b"\x1b[0;4m", b"\x1b[0m");
    }
    if urlify {
        decorate_help_fragment(
            &mut output,
            b"systemd-socket-activate(1) man page",
            b"\x1b]8;;man:systemd-socket-activate(1)\x1b\\",
            b"\x1b]8;;\x1b\\",
        );
    }
    output
}

fn decorate_help_fragment(output: &mut Vec<u8>, fragment: &[u8], before: &[u8], after: &[u8]) {
    let position = output
        .windows(fragment.len())
        .position(|candidate| candidate == fragment)
        .expect("static help fragment must be present");
    output.splice(
        position..position + fragment.len(),
        before.iter().chain(fragment).chain(after).copied(),
    );
}

fn colors_enabled() -> bool {
    if let Some(value) = environment_boolean("SYSTEMD_COLORS", true) {
        return value;
    }
    if env::var_os("NO_COLOR").is_some() {
        return false;
    }
    // SAFETY: isatty only examines the descriptor number.
    let stdout_is_terminal = unsafe { libc::isatty(libc::STDOUT_FILENO) > 0 };
    stdout_is_terminal && env::var_os("TERM").as_deref() != Some(OsStr::new("dumb"))
}

fn environment_boolean(name: &str, color_depths: bool) -> Option<bool> {
    let value = env::var_os(name)?;
    let value = value.as_os_str().as_bytes().to_ascii_lowercase();
    match value.as_slice() {
        b"1" | b"yes" | b"y" | b"true" | b"t" | b"on" => Some(true),
        b"0" | b"no" | b"n" | b"false" | b"f" | b"off" => Some(false),
        b"16" | b"256" if color_depths => Some(true),
        _ => None,
    }
}

const LONG_OPTIONS: &[&[u8]] = &[
    b"help",
    b"version",
    b"listen",
    b"datagram",
    b"seqpacket",
    b"accept",
    b"setenv",
    b"environment",
    b"fdname",
    b"inetd",
    b"now",
];

#[derive(Debug)]
struct Options {
    listen: Vec<OsString>,
    accept: bool,
    socket_type: libc::c_int,
    environment: Vec<(OsString, OsString)>,
    fdnames: Vec<OsString>,
    inetd: bool,
    now: bool,
    command: Vec<OsString>,
}

#[derive(Debug)]
enum ParseResult {
    Run(Options),
    Exit(Vec<u8>),
}

#[derive(Debug)]
struct Failure {
    message: Vec<u8>,
    errno: libc::c_int,
}

impl Failure {
    fn fixed(value: &'static [u8]) -> Self {
        Self::with_errno(value.to_vec(), libc::EINVAL)
    }

    fn with_errno(message: Vec<u8>, errno: libc::c_int) -> Self {
        Self { message, errno }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Address {
    Unix {
        path: Vec<u8>,
        abstract_namespace: bool,
    },
    Inet4 {
        address: Ipv4Addr,
        port: u16,
    },
    Inet6 {
        address: Ipv6Addr,
        port: u16,
        scope_id: u32,
    },
    Vsock {
        cid: u32,
        port: u32,
    },
}

struct OpenSockets {
    listeners: Vec<OwnedFd>,
    epoll: Option<OwnedFd>,
}

struct NotifyGuard;

impl NotifyGuard {
    fn start() -> Self {
        notify(b"READY=1\nSTATUS=Processing requests...");
        Self
    }
}

impl Drop for NotifyGuard {
    fn drop(&mut self) {
        notify(b"STOPPING=1\nSTATUS=Shutting down...");
    }
}

static LOG_INFO_ENABLED: AtomicBool = AtomicBool::new(true);

fn main() {
    initialize_logging();
    let arguments: Vec<OsString> = env::args_os().skip(1).collect();
    let result = match parse_options(&arguments) {
        Ok(ParseResult::Exit(output)) => io::stdout().lock().write_all(&output).map_err(|error| {
            let errno = error.raw_os_error().unwrap_or(libc::EIO);
            Failure::with_errno(error.to_string().into_bytes(), errno)
        }),
        Ok(ParseResult::Run(options)) => run(&options),
        Err(error) => Err(error),
    };

    if let Err(error) = result {
        log_error(&error.message);
        notify(format!("ERRNO={}", error.errno).as_bytes());
        notify(b"EXIT_STATUS=1");
        std::process::exit(1);
    }
    notify(b"EXIT_STATUS=0");
}

#[allow(clippy::too_many_lines)]
fn parse_options(arguments: &[OsString]) -> Result<ParseResult, Failure> {
    let mut options = Options {
        listen: Vec::new(),
        accept: false,
        socket_type: libc::SOCK_STREAM,
        environment: Vec::new(),
        fdnames: Vec::new(),
        inetd: false,
        now: false,
        command: Vec::new(),
    };
    let mut index = 0_usize;

    while index < arguments.len() {
        let raw = arguments[index].as_os_str().as_bytes();
        if raw == b"--" {
            options.command.extend_from_slice(&arguments[index + 1..]);
            break;
        }
        if raw == b"-" || !raw.starts_with(b"-") {
            options.command.extend_from_slice(&arguments[index..]);
            break;
        }
        if !raw.starts_with(b"--") {
            if let Some(output) = parse_short(arguments, &mut index, &mut options)? {
                return Ok(ParseResult::Exit(output));
            }
            index += 1;
            continue;
        }

        let long = &raw[2..];
        let (spelling, attached) = long
            .iter()
            .position(|byte| *byte == b'=')
            .map_or((long, None), |position| {
                (&long[..position], Some(&long[position + 1..]))
            });
        let name = resolve_long_option(spelling)?;
        match name {
            b"help" | b"version" => {
                reject_attached(name, attached)?;
                return Ok(ParseResult::Exit(if name == b"help" {
                    help_output()
                } else {
                    VERSION_OUTPUT.to_vec()
                }));
            }
            b"listen" | b"setenv" | b"environment" | b"fdname" => {
                let value = take_value(arguments, &mut index, name, attached)?;
                match name {
                    b"listen" => options.listen.push(OsString::from_vec(value.to_vec())),
                    b"setenv" | b"environment" => {
                        add_environment(&mut options.environment, value)?;
                    }
                    b"fdname" => add_fdnames(&mut options.fdnames, value),
                    _ => unreachable!("complete value option"),
                }
            }
            b"datagram" => {
                reject_attached(name, attached)?;
                if options.socket_type == libc::SOCK_SEQPACKET {
                    return Err(Failure::fixed(
                        b"--datagram may not be combined with --seqpacket.",
                    ));
                }
                options.socket_type = libc::SOCK_DGRAM;
            }
            b"seqpacket" => {
                reject_attached(name, attached)?;
                if options.socket_type == libc::SOCK_DGRAM {
                    return Err(Failure::fixed(
                        b"--seqpacket may not be combined with --datagram.",
                    ));
                }
                options.socket_type = libc::SOCK_SEQPACKET;
            }
            b"accept" => {
                reject_attached(name, attached)?;
                options.accept = true;
            }
            b"inetd" => {
                reject_attached(name, attached)?;
                options.inetd = true;
            }
            b"now" => {
                reject_attached(name, attached)?;
                options.now = true;
            }
            _ => unreachable!("complete long option"),
        }
        index += 1;
    }

    if options.command.is_empty() {
        return Err(Failure::fixed(
            b"systemd-socket-activate: command to execute is missing.",
        ));
    }
    if options.socket_type == libc::SOCK_DGRAM && options.accept {
        return Err(Failure::fixed(
            concat!(
                "Datagram sockets do not accept connections. ",
                "The --datagram and --accept options may not be combined."
            )
            .as_bytes(),
        ));
    }
    if options.accept && options.now {
        return Err(Failure::fixed(
            b"--now cannot be used in conjunction with --accept.",
        ));
    }
    if !options.fdnames.is_empty() && options.inetd {
        log_warning(b"--fdname= has no effect with --inetd present.");
    }

    Ok(ParseResult::Run(options))
}

fn parse_short(
    arguments: &[OsString],
    index: &mut usize,
    options: &mut Options,
) -> Result<Option<Vec<u8>>, Failure> {
    let raw = arguments[*index].as_os_str().as_bytes();
    let mut position = 1_usize;
    while position < raw.len() {
        match raw[position] {
            b'h' => return Ok(Some(help_output())),
            b'a' => options.accept = true,
            b'd' => {
                if options.socket_type == libc::SOCK_SEQPACKET {
                    return Err(Failure::fixed(
                        b"--datagram may not be combined with --seqpacket.",
                    ));
                }
                options.socket_type = libc::SOCK_DGRAM;
            }
            option @ (b'l' | b'E') => {
                let value = if position + 1 < raw.len() {
                    &raw[position + 1..]
                } else {
                    *index += 1;
                    let Some(next) = arguments.get(*index) else {
                        return Err(missing_short_argument(option));
                    };
                    next.as_os_str().as_bytes()
                };
                if option == b'l' {
                    options.listen.push(OsString::from_vec(value.to_vec()));
                } else {
                    add_environment(&mut options.environment, value)?;
                }
                return Ok(None);
            }
            unknown => return Err(unrecognized_short(unknown)),
        }
        position += 1;
    }
    Ok(None)
}

fn resolve_long_option(spelling: &[u8]) -> Result<&'static [u8], Failure> {
    let matches: Vec<&[u8]> = LONG_OPTIONS
        .iter()
        .copied()
        .filter(|option| option.starts_with(spelling))
        .collect();
    match matches.as_slice() {
        [single] => Ok(*single),
        [] => {
            let mut message = b"systemd-socket-activate: unrecognized option '--".to_vec();
            message.extend_from_slice(spelling);
            message.push(b'\'');
            Err(Failure::with_errno(message, libc::EINVAL))
        }
        ambiguous => {
            let mut message = b"systemd-socket-activate: option '--".to_vec();
            message.extend_from_slice(spelling);
            message.extend_from_slice(b"' is ambiguous; possibilities:");
            for option in ambiguous {
                message.extend_from_slice(b" --");
                message.extend_from_slice(option);
                message.push(b',');
            }
            message.pop();
            Err(Failure::with_errno(message, libc::EINVAL))
        }
    }
}

fn reject_attached(name: &[u8], attached: Option<&[u8]>) -> Result<(), Failure> {
    if attached.is_none() {
        return Ok(());
    }
    let mut message = b"systemd-socket-activate: option '--".to_vec();
    message.extend_from_slice(name);
    message.extend_from_slice(b"' doesn't allow an argument");
    Err(Failure::with_errno(message, libc::EINVAL))
}

fn take_value<'a>(
    arguments: &'a [OsString],
    index: &mut usize,
    name: &[u8],
    attached: Option<&'a [u8]>,
) -> Result<&'a [u8], Failure> {
    if let Some(value) = attached {
        return Ok(value);
    }
    *index += 1;
    arguments
        .get(*index)
        .map(|value| value.as_os_str().as_bytes())
        .ok_or_else(|| {
            let mut message = b"systemd-socket-activate: option '--".to_vec();
            message.extend_from_slice(name);
            message.extend_from_slice(b"' requires an argument");
            Failure::with_errno(message, libc::EINVAL)
        })
}

fn missing_short_argument(option: u8) -> Failure {
    let mut message = b"systemd-socket-activate: option '-".to_vec();
    message.push(option);
    message.extend_from_slice(b"' requires an argument");
    Failure::with_errno(message, libc::EINVAL)
}

fn unrecognized_short(option: u8) -> Failure {
    let mut message = b"systemd-socket-activate: unrecognized option '-".to_vec();
    message.push(option);
    message.push(b'\'');
    Failure::with_errno(message, libc::EINVAL)
}

fn add_environment(assignments: &mut Vec<(OsString, OsString)>, raw: &[u8]) -> Result<(), Failure> {
    let (name, value) = if let Some(position) = raw.iter().position(|byte| *byte == b'=') {
        (
            &raw[..position],
            OsString::from_vec(raw[position + 1..].to_vec()),
        )
    } else {
        let name = OsStr::from_bytes(raw);
        // SAFETY: getauxval has no pointer arguments. In secure-execution mode
        // secure_getenv() would hide the caller's environment.
        let secure_execution = unsafe { libc::getauxval(libc::AT_SECURE) } != 0;
        (
            raw,
            if secure_execution {
                OsString::new()
            } else {
                env::var_os(name).unwrap_or_default()
            },
        )
    };
    let value_bytes = value.as_os_str().as_bytes();
    let argument_maximum = argument_maximum();
    if !valid_environment_name(name)
        || value_bytes.contains(&0)
        || value_bytes.len() > argument_maximum.saturating_sub(3)
        || name
            .len()
            .saturating_add(value_bytes.len())
            .saturating_add(1)
            > argument_maximum.saturating_sub(1)
    {
        let mut message = b"Cannot assign environment variable ".to_vec();
        message.extend_from_slice(raw);
        message.extend_from_slice(b": Invalid argument");
        return Err(Failure::with_errno(message, libc::EINVAL));
    }
    if std::str::from_utf8(value.as_os_str().as_bytes()).is_err() {
        let mut message = b"Cannot assign environment variable ".to_vec();
        message.extend_from_slice(raw);
        message.extend_from_slice(b": Invalid argument");
        return Err(Failure::with_errno(message, libc::EINVAL));
    }

    let name = OsString::from_vec(name.to_vec());
    if let Some(existing) = assignments
        .iter_mut()
        .find(|(candidate, _)| candidate == &name)
    {
        existing.1 = value;
    } else {
        assignments.push((name, value));
    }
    Ok(())
}

fn valid_environment_name(name: &[u8]) -> bool {
    !name.is_empty()
        && !name[0].is_ascii_digit()
        && name.len() <= argument_maximum().saturating_sub(2)
        && name
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
}

fn argument_maximum() -> usize {
    // SAFETY: sysconf has no pointer arguments.
    let value = unsafe { libc::sysconf(libc::_SC_ARG_MAX) };
    usize::try_from(value).unwrap_or(2_097_152)
}

fn add_fdnames(fdnames: &mut Vec<OsString>, value: &[u8]) {
    for name in value.split(|byte| *byte == b':') {
        if !valid_fdname(name) {
            let mut message = b"File descriptor name \"".to_vec();
            append_cescaped(&mut message, name);
            message.extend_from_slice(b"\" is not valid.");
            log_warning(&message);
        }
        fdnames.push(OsString::from_vec(name.to_vec()));
    }
}

fn valid_fdname(name: &[u8]) -> bool {
    name.len() <= FDNAME_MAX
        && name
            .iter()
            .all(|byte| (b' '..=b'~').contains(byte) && *byte != b':')
}

fn append_cescaped(output: &mut Vec<u8>, value: &[u8]) {
    for byte in value {
        match *byte {
            b'\x07' => output.extend_from_slice(b"\\a"),
            b'\x08' => output.extend_from_slice(b"\\b"),
            b'\x0c' => output.extend_from_slice(b"\\f"),
            b'\\' => output.extend_from_slice(b"\\\\"),
            b'\"' => output.extend_from_slice(b"\\\""),
            b'\'' => output.extend_from_slice(b"\\'"),
            b'\n' => output.extend_from_slice(b"\\n"),
            b'\r' => output.extend_from_slice(b"\\r"),
            b'\t' => output.extend_from_slice(b"\\t"),
            b'\x0b' => output.extend_from_slice(b"\\v"),
            b' '..=b'~' => output.push(*byte),
            other => {
                output.push(b'\\');
                output.push(b'0' + ((other >> 6) & 7));
                output.push(b'0' + ((other >> 3) & 7));
                output.push(b'0' + (other & 7));
            }
        }
    }
}

fn run(options: &Options) -> Result<(), Failure> {
    LOG_INFO_ENABLED.store(info_logging_enabled(), Ordering::Relaxed);
    let sockets = open_sockets(options)?;
    if sockets.listeners.is_empty() {
        return Err(Failure::with_errno(
            b"No sockets to listen on specified or passed in.".to_vec(),
            libc::ENOENT,
        ));
    }
    if options.accept {
        install_sigchld_handler()?;
    }
    let _notify = NotifyGuard::start();

    loop {
        let event_fd = if let Some(epoll) = &sockets.epoll {
            wait_for_event(epoll.as_raw_fd())?
        } else {
            -1
        };
        if !options.accept {
            return exec_process(
                options,
                &sockets.listeners,
                LISTEN_FDS_START,
                sockets.listeners.len(),
            );
        }
        do_accept(options, event_fd)?;
    }
}

fn open_sockets(options: &Options) -> Result<OpenSockets, Failure> {
    // SAFETY: the helper reads the activation environment and descriptor flags.
    let inherited = unsafe { rustd_listen_fds(1) };
    if inherited < 0 {
        let mut message = b"Failed to read listening file descriptors from environment: ".to_vec();
        message.extend_from_slice(errno_text(-inherited).as_bytes());
        return Err(Failure::with_errno(message, -inherited));
    }
    if inherited > 0 {
        log_info(format!("Received {inherited} descriptors via the environment.").as_bytes());
    }

    let mut listeners = Vec::new();
    for offset in 0..inherited {
        let fd = LISTEN_FDS_START + offset;
        set_cloexec(fd, options.accept)
            .map_err(|errno| Failure::with_errno(errno_text(errno).into_bytes(), errno))?;
        // SAFETY: rustd_listen_fds() verified that each descriptor is open, and
        // ownership remains with this process until exec or exit.
        listeners.push(unsafe { OwnedFd::from_raw_fd(fd) });
    }

    if !options.listen.is_empty() {
        let preserved: Vec<RawFd> = listeners.iter().map(AsRawFd::as_raw_fd).collect();
        close_other_fds(&preserved);
    }

    for raw in &options.listen {
        let expected = LISTEN_FDS_START
            + i32::try_from(listeners.len()).map_err(|_| Failure::fixed(b"Too many sockets."))?;
        let opened = open_address(raw.as_os_str(), options.socket_type, options.accept)?;
        let opened = move_to_fd(opened, expected, options.accept)?;
        listeners.push(opened);
    }

    if listeners.len() > 1 && !options.accept && options.inetd {
        return Err(Failure::fixed(
            b"--inetd only supported with a single file descriptor, or with --accept.",
        ));
    }
    if !options.fdnames.is_empty() && !options.inetd {
        if !options.accept && options.fdnames.len() != listeners.len() {
            log_warning(
                format!(
                    "The number of fd names is different from the number of fds: {} vs {}",
                    options.fdnames.len(),
                    listeners.len()
                )
                .as_bytes(),
            );
        }
        if options.accept && options.fdnames.len() > 1 {
            log_warning(b"More than one fd name specified with --accept.");
        }
    }

    let epoll = if options.now {
        None
    } else {
        // SAFETY: epoll_create1 has no pointer arguments.
        let fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if fd < 0 {
            return Err(last_errno_failure(b"Failed to create epoll object: "));
        }
        // SAFETY: fd was returned by epoll_create1 and is uniquely owned here.
        Some(unsafe { OwnedFd::from_raw_fd(fd) })
    };

    for listener in &listeners {
        let fd = listener.as_raw_fd();
        let name = socket_name(fd).unwrap_or_else(|| b"n/a".to_vec());
        let mut message = b"Listening on ".to_vec();
        message.extend_from_slice(&name);
        message.extend_from_slice(format!(" as {fd}.").as_bytes());
        log_info(&message);
        if let Some(epoll) = &epoll {
            add_epoll(epoll.as_raw_fd(), fd)?;
        }
    }

    Ok(OpenSockets { listeners, epoll })
}

fn close_other_fds(preserved: &[RawFd]) {
    let mut preserved = preserved.to_vec();
    preserved.sort_unstable();
    let mut first = LISTEN_FDS_START;
    for fd in preserved {
        if fd < first {
            continue;
        }
        if fd > first {
            close_descriptor_range(
                first,
                libc::c_uint::try_from(fd - 1).expect("nonnegative descriptor"),
            );
        }
        first = fd.saturating_add(1);
    }
    close_descriptor_range(first, libc::c_uint::MAX);
}

fn close_descriptor_range(first: RawFd, last: libc::c_uint) {
    if libc::c_uint::try_from(first).is_ok_and(|value| value > last) {
        return;
    }
    // SAFETY: close_range has no pointer arguments and affects only descriptors
    // in this process. The caller excludes every inherited activation fd.
    if unsafe {
        libc::syscall(
            libc::SYS_close_range,
            libc::c_uint::try_from(first).expect("nonnegative descriptor"),
            last,
            0_u32,
        )
    } == 0
    {
        return;
    }
    if last == libc::c_uint::MAX {
        if let Ok(entries) = fs::read_dir("/proc/self/fd") {
            let descriptors: Vec<RawFd> = entries
                .filter_map(Result::ok)
                .filter_map(|entry| {
                    let name = entry.file_name();
                    std::str::from_utf8(name.as_bytes())
                        .ok()
                        .and_then(|value| value.parse::<RawFd>().ok())
                })
                .filter(|fd| *fd >= first)
                .collect();
            for fd in descriptors {
                // SAFETY: fd was found in this process's /proc descriptor table.
                unsafe { libc::close(fd) };
            }
            return;
        }
    }
    let fallback_last = RawFd::try_from(last).unwrap_or_else(|_| maximum_open_descriptor());
    for fd in first..=fallback_last {
        // SAFETY: closing an unused descriptor is harmless and yields EBADF.
        unsafe { libc::close(fd) };
    }
}

fn maximum_open_descriptor() -> RawFd {
    // SAFETY: rlimit is plain-old-data and the pointer is writable.
    let mut limit = unsafe { mem::zeroed::<libc::rlimit>() };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, std::ptr::addr_of_mut!(limit)) } == 0 {
        let maximum = limit.rlim_cur.saturating_sub(1);
        return RawFd::try_from(maximum).unwrap_or(i32::MAX);
    }
    1_048_575
}

fn move_to_fd(fd: OwnedFd, target: RawFd, cloexec: bool) -> Result<OwnedFd, Failure> {
    if fd.as_raw_fd() == target {
        return Ok(fd);
    }
    let flags = if cloexec { libc::O_CLOEXEC } else { 0 };
    // SAFETY: both descriptor numbers are process-local integers; dup3 makes
    // target a duplicate without transferring ownership of fd.
    if unsafe { libc::dup3(fd.as_raw_fd(), target, flags) } < 0 {
        return Err(last_errno_failure(b"Failed to move socket descriptor: "));
    }
    drop(fd);
    // SAFETY: dup3 created a new descriptor at target, now uniquely owned.
    Ok(unsafe { OwnedFd::from_raw_fd(target) })
}

fn add_epoll(epoll_fd: RawFd, fd: RawFd) -> Result<(), Failure> {
    let mut event = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: u64::try_from(fd).expect("file descriptors are nonnegative"),
    };
    // SAFETY: event points to initialized storage for EPOLL_CTL_ADD.
    if unsafe { libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, fd, &mut event) } < 0 {
        let errno = last_errno();
        let mut message = format!("Failed to add event on epoll fd:{epoll_fd} for fd:{fd}: ");
        message.push_str(&errno_text(errno));
        return Err(Failure::with_errno(message.into_bytes(), errno));
    }
    Ok(())
}

fn wait_for_event(epoll_fd: RawFd) -> Result<RawFd, Failure> {
    loop {
        let mut event = MaybeUninit::<libc::epoll_event>::zeroed();
        // SAFETY: event is writable storage for one epoll event.
        let result = unsafe { libc::epoll_wait(epoll_fd, event.as_mut_ptr(), 1, -1) };
        if result > 0 {
            // SAFETY: epoll_wait initialized one event when it returned 1.
            let event = unsafe { event.assume_init() };
            let fd = event.u64 as RawFd;
            log_info(format!("Communication attempt on fd {fd}.").as_bytes());
            return Ok(fd);
        }
        let errno = last_errno();
        if errno == libc::EINTR {
            continue;
        }
        let mut message = b"epoll_wait() failed: ".to_vec();
        message.extend_from_slice(errno_text(errno).as_bytes());
        return Err(Failure::with_errno(message, errno));
    }
}

fn open_address(raw: &OsStr, socket_type: libc::c_int, cloexec: bool) -> Result<OwnedFd, Failure> {
    let address = match parse_address(raw.as_bytes()) {
        Ok(address) => address,
        Err(errno) => {
            let mut message = b"Failed to parse socket address \"".to_vec();
            message.extend_from_slice(raw.as_bytes());
            message.extend_from_slice(b"\": ");
            message.extend_from_slice(errno_text(errno).as_bytes());
            log_error(&message);
            let mut outer = b"Failed to open '".to_vec();
            outer.extend_from_slice(raw.as_bytes());
            outer.extend_from_slice(b"': ");
            outer.extend_from_slice(errno_text(errno).as_bytes());
            return Err(Failure::with_errno(outer, errno));
        }
    };
    match listen_address(&address, socket_type, cloexec) {
        Ok(fd) => {
            if debug_logging_enabled() {
                let mut message = b"Listening on ".to_vec();
                message.extend_from_slice(&pretty_address(&address));
                log_debug(&message);
            }
            Ok(fd)
        }
        Err(errno) => {
            let mut message = if socket_type_is_valid(&address, socket_type) {
                let mut message = b"Failed to listen on ".to_vec();
                message.extend_from_slice(&pretty_address(&address));
                message.extend_from_slice(b": ");
                message
            } else {
                b"socket_address_print(): ".to_vec()
            };
            message.extend_from_slice(errno_text(errno).as_bytes());
            log_error(&message);
            let mut outer = b"Failed to open '".to_vec();
            outer.extend_from_slice(raw.as_bytes());
            outer.extend_from_slice(b"': ");
            outer.extend_from_slice(errno_text(errno).as_bytes());
            Err(Failure::with_errno(outer, errno))
        }
    }
}

fn parse_address(raw: &[u8]) -> Result<Address, libc::c_int> {
    if raw.first().is_some_and(|byte| matches!(*byte, b'/' | b'@')) {
        if raw.len() < 2 {
            return Err(libc::EINVAL);
        }
        // SAFETY: sockaddr_un is a plain-old-data kernel ABI structure.
        let address = unsafe { mem::zeroed::<libc::sockaddr_un>() };
        let maximum = address.sun_path.len();
        if raw.len() + 1 > maximum {
            return Err(if raw[0] == b'@' {
                libc::EINVAL
            } else {
                libc::ENAMETOOLONG
            });
        }
        return Ok(Address::Unix {
            path: raw.to_vec(),
            abstract_namespace: raw[0] == b'@',
        });
    }

    if let Some(rest) = [
        b"vsock:".as_slice(),
        b"vsock-dgram:".as_slice(),
        b"vsock-seqpacket:".as_slice(),
        b"vsock-stream:".as_slice(),
    ]
    .into_iter()
    .find_map(|prefix| raw.strip_prefix(prefix))
    {
        let Some(separator) = rest.iter().position(|byte| *byte == b':') else {
            return Err(libc::EINVAL);
        };
        let port = parse_u32(&rest[separator + 1..])?;
        if port == u32::MAX {
            return Err(libc::EINVAL);
        }
        let cid = parse_vsock_cid(&rest[..separator])?;
        return Ok(Address::Vsock { cid, port });
    }

    match parse_port(raw) {
        Ok(port) => {
            if ipv6_supported() {
                return Ok(Address::Inet6 {
                    address: Ipv6Addr::UNSPECIFIED,
                    port,
                    scope_id: 0,
                });
            }
            return Ok(Address::Inet4 {
                address: Ipv4Addr::UNSPECIFIED,
                port,
            });
        }
        Err(libc::ERANGE) => return Err(libc::ERANGE),
        Err(_) => {}
    }

    let (without_scope, scope_id) = parse_scope(raw)?;
    if without_scope.starts_with(b"[") {
        let Some(close) = without_scope.iter().rposition(|byte| *byte == b']') else {
            return Err(libc::EINVAL);
        };
        if close + 1 >= without_scope.len() || without_scope[close + 1] != b':' {
            return Err(libc::EINVAL);
        }
        let address = std::str::from_utf8(&without_scope[1..close])
            .ok()
            .and_then(|value| Ipv6Addr::from_str(value).ok())
            .ok_or(libc::EINVAL)?;
        let port = parse_port(&without_scope[close + 2..])?;
        return Ok(Address::Inet6 {
            address,
            port,
            scope_id,
        });
    }

    let Some(colon) = without_scope.iter().rposition(|byte| *byte == b':') else {
        return Err(libc::EINVAL);
    };
    let address = std::str::from_utf8(&without_scope[..colon])
        .ok()
        .and_then(|value| Ipv4Addr::from_str(value).ok())
        .ok_or(libc::EINVAL)?;
    let port = parse_port(&without_scope[colon + 1..])?;
    Ok(Address::Inet4 { address, port })
}

fn parse_scope(raw: &[u8]) -> Result<(&[u8], u32), libc::c_int> {
    let Some(percent) = raw.iter().position(|byte| *byte == b'%') else {
        return Ok((raw, 0));
    };
    let name = &raw[percent + 1..];
    if name.is_empty()
        || name.contains(&b'%')
        || name
            .iter()
            .any(|byte| *byte <= b' ' || *byte >= 127 || matches!(*byte, b':' | b'/'))
    {
        return Err(libc::EINVAL);
    }
    let index = if name.iter().all(u8::is_ascii_digit) {
        parse_u32(name).and_then(|value| {
            if value == 0 || value > i32::MAX as u32 {
                Err(libc::EINVAL)
            } else {
                Ok(value)
            }
        })?
    } else {
        let name = CString::new(name).map_err(|_| libc::EINVAL)?;
        // SAFETY: name is a valid NUL-terminated interface name.
        let value = unsafe { libc::if_nametoindex(name.as_ptr()) };
        if value == 0 {
            let errno = last_errno();
            return Err(if errno == 0 { libc::ENODEV } else { errno });
        }
        value
    };
    Ok((&raw[..percent], index))
}

fn parse_port(raw: &[u8]) -> Result<u16, libc::c_int> {
    let value = parse_systemd_u32(raw, true)?;
    if value == 0 {
        return Err(libc::EINVAL);
    }
    u16::try_from(value).map_err(|_| libc::ERANGE)
}

fn parse_u32(raw: &[u8]) -> Result<u32, libc::c_int> {
    parse_systemd_u32(raw, false)
}

fn parse_systemd_u32(raw: &[u8], refuse_leading_whitespace: bool) -> Result<u32, libc::c_int> {
    const WHITESPACE: &[u8] = b" \t\n\r\x0b\x0c";
    if raw.is_empty() || (refuse_leading_whitespace && WHITESPACE.contains(&raw[0])) {
        return Err(libc::EINVAL);
    }
    let mut start = 0_usize;
    if !refuse_leading_whitespace {
        while raw.get(start).is_some_and(|byte| WHITESPACE.contains(byte)) {
            start += 1;
        }
    }
    let mut input = &raw[start..];
    if input.is_empty() {
        return Err(libc::EINVAL);
    }
    let had_sign = matches!(input[0], b'+' | b'-');
    let negative = input[0] == b'-';
    if had_sign {
        input = &input[1..];
    }
    if input.is_empty() {
        return Err(libc::EINVAL);
    }
    let binary = if had_sign {
        None
    } else {
        input
            .strip_prefix(b"0b")
            .or_else(|| input.strip_prefix(b"0B"))
    };
    let octal = if had_sign {
        None
    } else {
        input
            .strip_prefix(b"0o")
            .or_else(|| input.strip_prefix(b"0O"))
    };
    let (base, digits) = if let Some(rest) = binary {
        (2_u32, rest)
    } else if let Some(rest) = octal {
        (8, rest)
    } else if let Some(rest) = input
        .strip_prefix(b"0x")
        .or_else(|| input.strip_prefix(b"0X"))
    {
        (16, rest)
    } else if input.len() > 1 && input[0] == b'0' {
        (8, input)
    } else {
        (10, input)
    };
    if digits.is_empty() {
        return Err(libc::EINVAL);
    }
    let mut value = 0_u32;
    for digit in digits {
        let digit = match *digit {
            b'0'..=b'9' => u32::from(*digit - b'0'),
            b'a'..=b'f' => u32::from(*digit - b'a') + 10,
            b'A'..=b'F' => u32::from(*digit - b'A') + 10,
            _ => return Err(libc::EINVAL),
        };
        if digit >= base {
            return Err(libc::EINVAL);
        }
        value = value
            .checked_mul(base)
            .and_then(|current| current.checked_add(digit))
            .ok_or(libc::ERANGE)?;
    }
    if negative && value != 0 {
        return Err(libc::ERANGE);
    }
    Ok(value)
}

fn parse_vsock_cid(raw: &[u8]) -> Result<u32, libc::c_int> {
    match raw {
        b"" => Ok(u32::MAX),
        b"hypervisor" => Ok(0),
        b"local" => Ok(1),
        b"host" => Ok(2),
        _ => parse_u32(raw),
    }
}

fn ipv6_supported() -> bool {
    // SAFETY: socket has no pointer arguments.
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        false
    } else {
        // SAFETY: fd was returned by socket and is no longer used afterward.
        unsafe { libc::close(fd) };
        true
    }
}

fn socket_type_is_valid(address: &Address, socket_type: libc::c_int) -> bool {
    match address {
        Address::Unix { .. } => matches!(
            socket_type,
            libc::SOCK_STREAM | libc::SOCK_DGRAM | libc::SOCK_SEQPACKET
        ),
        Address::Inet4 { .. } | Address::Inet6 { .. } | Address::Vsock { .. } => {
            matches!(socket_type, libc::SOCK_STREAM | libc::SOCK_DGRAM)
        }
    }
}

#[allow(clippy::too_many_lines)]
fn listen_address(
    address: &Address,
    socket_type: libc::c_int,
    cloexec: bool,
) -> Result<OwnedFd, libc::c_int> {
    if !socket_type_is_valid(address, socket_type) {
        return Err(libc::EINVAL);
    }
    let family = match address {
        Address::Unix { .. } => libc::AF_UNIX,
        Address::Inet4 { .. } => libc::AF_INET,
        Address::Inet6 { .. } => libc::AF_INET6,
        Address::Vsock { .. } => libc::AF_VSOCK,
    };
    let flags = socket_type | if cloexec { libc::SOCK_CLOEXEC } else { 0 };
    // SAFETY: socket has no pointer arguments.
    let fd = unsafe { libc::socket(family, flags, 0) };
    if fd < 0 {
        return Err(last_errno());
    }
    // SAFETY: fd was just returned by socket and is uniquely owned.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let reuse = 1_i32;
    // SAFETY: reuse points to an initialized integer of the advertised size.
    if unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            std::ptr::addr_of!(reuse).cast(),
            socket_length(&reuse),
        )
    } < 0
    {
        return Err(last_errno());
    }

    match address {
        Address::Unix {
            path,
            abstract_namespace,
        } => bind_unix(fd.as_raw_fd(), path, *abstract_namespace)?,
        Address::Inet4 { address, port } => {
            let socket_address = libc::sockaddr_in {
                sin_family: socket_family(libc::AF_INET),
                sin_port: port.to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(address.octets()),
                },
                sin_zero: [0; 8],
            };
            bind_socket(
                fd.as_raw_fd(),
                std::ptr::addr_of!(socket_address).cast(),
                socket_length(&socket_address),
            )?;
        }
        Address::Inet6 {
            address,
            port,
            scope_id,
        } => {
            let socket_address = libc::sockaddr_in6 {
                sin6_family: socket_family(libc::AF_INET6),
                sin6_port: port.to_be(),
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr {
                    s6_addr: address.octets(),
                },
                sin6_scope_id: *scope_id,
            };
            bind_socket(
                fd.as_raw_fd(),
                std::ptr::addr_of!(socket_address).cast(),
                socket_length(&socket_address),
            )?;
        }
        Address::Vsock { cid, port } => {
            let socket_address = SockAddrVm {
                family: socket_family(libc::AF_VSOCK),
                reserved1: 0,
                port: *port,
                cid: *cid,
                zero: [0; 4],
            };
            bind_socket(
                fd.as_raw_fd(),
                std::ptr::addr_of!(socket_address).cast(),
                socket_length(&socket_address),
            )?;
        }
    }

    if matches!(socket_type, libc::SOCK_STREAM | libc::SOCK_SEQPACKET) {
        // SAFETY: fd is a bound socket and the backlog is a valid integer.
        if unsafe { libc::listen(fd.as_raw_fd(), i32::MAX) } < 0 {
            return Err(last_errno());
        }
    }
    if let Address::Unix {
        path,
        abstract_namespace: false,
    } = address
    {
        touch_unix_path(path);
    }
    Ok(fd)
}

#[repr(C)]
struct SockAddrVm {
    family: libc::sa_family_t,
    reserved1: u16,
    port: u32,
    cid: u32,
    zero: [u8; 4],
}

fn socket_family(family: libc::c_int) -> libc::sa_family_t {
    libc::sa_family_t::try_from(family).expect("Linux address families fit sa_family_t")
}

fn socket_length<T>(value: &T) -> libc::socklen_t {
    libc::socklen_t::try_from(mem::size_of_val(value))
        .expect("Linux socket structures fit socklen_t")
}

fn bind_unix(fd: RawFd, path: &[u8], abstract_namespace: bool) -> Result<(), libc::c_int> {
    // SAFETY: sockaddr_un is a plain-old-data kernel ABI structure.
    let mut address = unsafe { mem::zeroed::<libc::sockaddr_un>() };
    address.sun_family = socket_family(libc::AF_UNIX);
    let offset = mem::size_of::<libc::sockaddr_un>() - mem::size_of_val(&address.sun_path);
    let length = if abstract_namespace {
        for (target, source) in address.sun_path[1..].iter_mut().zip(path[1..].iter()) {
            *target = libc::c_char::from_ne_bytes([*source]);
        }
        offset + path.len()
    } else {
        for (target, source) in address.sun_path.iter_mut().zip(path.iter()) {
            *target = libc::c_char::from_ne_bytes([*source]);
        }
        let filesystem_path = Path::new(OsStr::from_bytes(path));
        if let Some(parent) = filesystem_path.parent() {
            // SAFETY: socket setup is single-threaded. mkdir_parents_label()
            // creates requested parents with the supplied 0755 mode regardless
            // of the caller's umask.
            let previous = unsafe { libc::umask(0) };
            let _ = fs::DirBuilder::new()
                .recursive(true)
                .mode(0o755)
                .create(parent);
            // SAFETY: restore the caller's umask immediately after mkdir.
            unsafe { libc::umask(previous) };
        }
        offset + path.len() + 1
    };

    let previous_umask = if abstract_namespace {
        None
    } else {
        // SAFETY: this process is single-threaded before activation.
        Some(unsafe { libc::umask(0o133) })
    };
    // SAFETY: address is initialized for the given byte length.
    let mut result = unsafe {
        libc::bind(
            fd,
            std::ptr::addr_of!(address).cast(),
            libc::socklen_t::try_from(length).expect("sockaddr_un length fits socklen_t"),
        )
    };
    let mut errno = last_errno();
    if result < 0
        && errno == libc::EADDRINUSE
        && !abstract_namespace
        && fs::remove_file(Path::new(OsStr::from_bytes(path))).is_ok()
    {
        // SAFETY: same initialized address as the first bind attempt.
        result = unsafe {
            libc::bind(
                fd,
                std::ptr::addr_of!(address).cast(),
                libc::socklen_t::try_from(length).expect("sockaddr_un length fits socklen_t"),
            )
        };
        errno = last_errno();
    }
    if let Some(mask) = previous_umask {
        // SAFETY: restores the process umask saved immediately above.
        unsafe { libc::umask(mask) };
    }
    if result < 0 {
        return Err(errno);
    }
    Ok(())
}

fn touch_unix_path(path: &[u8]) {
    let Ok(path) = CString::new(path) else {
        return;
    };
    // SAFETY: path is NUL-terminated. A null timestamp pointer requests the
    // current time, and failures are intentionally ignored like upstream.
    unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            path.as_ptr(),
            std::ptr::null(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
}

fn bind_socket(
    fd: RawFd,
    address: *const libc::sockaddr,
    length: libc::socklen_t,
) -> Result<(), libc::c_int> {
    // SAFETY: caller supplies an initialized sockaddr and matching length.
    if unsafe { libc::bind(fd, address, length) } < 0 {
        Err(last_errno())
    } else {
        Ok(())
    }
}

fn pretty_address(address: &Address) -> Vec<u8> {
    match address {
        Address::Unix {
            path,
            abstract_namespace,
        } => escaped_unix_path(path, *abstract_namespace),
        Address::Inet4 { address, port } => format!("{address}:{port}").into_bytes(),
        Address::Inet6 {
            address,
            port,
            scope_id,
        } => format_ipv6(*address, *port, *scope_id, true),
        Address::Vsock { cid, port } => {
            if *cid == u32::MAX {
                format!("vsock::{port}").into_bytes()
            } else {
                format!("vsock:{cid}:{port}").into_bytes()
            }
        }
    }
}

fn escaped_unix_path(path: &[u8], abstract_namespace: bool) -> Vec<u8> {
    let mut result = Vec::with_capacity(path.len());
    if abstract_namespace {
        result.push(b'@');
        append_cescaped(&mut result, &path[1..]);
    } else {
        append_cescaped(&mut result, path);
    }
    result
}

fn format_ipv6(address: Ipv6Addr, port: u16, scope_id: u32, include_port: bool) -> Vec<u8> {
    let mut result = if include_port {
        format!("[{address}]:{port}").into_bytes()
    } else {
        address.to_string().into_bytes()
    };
    if scope_id != 0 {
        result.push(b'%');
        result.extend_from_slice(&interface_name_or_index(scope_id));
    }
    result
}

fn interface_name_or_index(index: u32) -> Vec<u8> {
    let mut buffer = [0 as libc::c_char; libc::IF_NAMESIZE];
    // SAFETY: buffer is writable IF_NAMESIZE storage and index is passed by value.
    let result = unsafe { libc::if_indextoname(index, buffer.as_mut_ptr()) };
    if result.is_null() {
        return index.to_string().into_bytes();
    }
    // SAFETY: if_indextoname returned buffer and guarantees NUL termination.
    unsafe { CStr::from_ptr(buffer.as_ptr()) }
        .to_bytes()
        .to_vec()
}

fn socket_name(fd: RawFd) -> Option<Vec<u8>> {
    // SAFETY: sockaddr_storage is plain-old-data and zero is valid initialization.
    let mut storage = unsafe { mem::zeroed::<libc::sockaddr_storage>() };
    let mut length = socket_length(&storage);
    // SAFETY: storage and length are writable buffers of matching size.
    if unsafe {
        libc::getsockname(
            fd,
            std::ptr::addr_of_mut!(storage).cast(),
            std::ptr::addr_of_mut!(length),
        )
    } < 0
    {
        return None;
    }
    sockaddr_pretty(&storage, length, false, true)
}

fn peer_name(fd: RawFd) -> Option<Vec<u8>> {
    // SAFETY: sockaddr_storage is plain-old-data and zero is valid initialization.
    let mut storage = unsafe { mem::zeroed::<libc::sockaddr_storage>() };
    let mut length = socket_length(&storage);
    // SAFETY: storage and length are writable buffers of matching size.
    if unsafe {
        libc::getpeername(
            fd,
            std::ptr::addr_of_mut!(storage).cast(),
            std::ptr::addr_of_mut!(length),
        )
    } < 0
    {
        return None;
    }
    if i32::from(storage.ss_family) == libc::AF_UNIX {
        // SAFETY: ucred is a plain-old-data kernel ABI structure.
        let mut credentials = unsafe { mem::zeroed::<libc::ucred>() };
        let mut credentials_length = socket_length(&credentials);
        // SAFETY: credentials and its size are valid output buffers.
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                std::ptr::addr_of_mut!(credentials).cast(),
                std::ptr::addr_of_mut!(credentials_length),
            )
        } == 0
        {
            return Some(format!("PID {}/UID {}", credentials.pid, credentials.uid).into_bytes());
        }
    }
    sockaddr_pretty(&storage, length, true, true)
}

fn sockaddr_pretty(
    storage: &libc::sockaddr_storage,
    length: libc::socklen_t,
    translate_ipv6: bool,
    include_port: bool,
) -> Option<Vec<u8>> {
    match i32::from(storage.ss_family) {
        libc::AF_UNIX => {
            // SAFETY: family identifies the storage as sockaddr_un.
            let address =
                unsafe { &*(storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_un>() };
            let offset = mem::size_of::<libc::sockaddr_un>() - mem::size_of_val(&address.sun_path);
            let path_length = usize::try_from(length)
                .ok()?
                .saturating_sub(offset)
                .min(address.sun_path.len());
            if path_length == 0 || (path_length == 1 && address.sun_path[0] == 0) {
                return Some(b"<unnamed>".to_vec());
            }
            if address.sun_path[0] == 0 {
                let bytes: Vec<u8> = address.sun_path[1..path_length]
                    .iter()
                    .map(|value| value.to_ne_bytes()[0])
                    .collect();
                let mut marked = Vec::with_capacity(bytes.len() + 1);
                marked.push(b'@');
                marked.extend_from_slice(&bytes);
                Some(escaped_unix_path(&marked, true))
            } else {
                let mut bytes: Vec<u8> = address.sun_path[..path_length]
                    .iter()
                    .map(|value| value.to_ne_bytes()[0])
                    .collect();
                if bytes.last() == Some(&0) {
                    bytes.pop();
                }
                Some(escaped_unix_path(&bytes, false))
            }
        }
        libc::AF_INET => {
            // SAFETY: family identifies the storage as sockaddr_in.
            let address =
                unsafe { &*(storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>() };
            let ip = Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes());
            let port = u16::from_be(address.sin_port);
            Some(if include_port {
                format!("{ip}:{port}").into_bytes()
            } else {
                ip.to_string().into_bytes()
            })
        }
        libc::AF_INET6 => {
            // SAFETY: family identifies the storage as sockaddr_in6.
            let address = unsafe {
                &*(storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>()
            };
            let ip = Ipv6Addr::from(address.sin6_addr.s6_addr);
            let port = u16::from_be(address.sin6_port);
            if translate_ipv6 {
                let octets = ip.octets();
                if octets[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff] {
                    let ipv4 = Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]);
                    return Some(if include_port {
                        format!("{ipv4}:{port}").into_bytes()
                    } else {
                        ipv4.to_string().into_bytes()
                    });
                }
            }
            Some(format_ipv6(ip, port, address.sin6_scope_id, include_port))
        }
        libc::AF_VSOCK => {
            // SAFETY: family identifies the storage as SockAddrVm.
            let address =
                unsafe { &*(storage as *const libc::sockaddr_storage).cast::<SockAddrVm>() };
            Some(if include_port {
                if address.cid == u32::MAX {
                    format!("vsock::{}", address.port).into_bytes()
                } else {
                    format!("vsock:{}:{}", address.cid, address.port).into_bytes()
                }
            } else {
                format!("vsock:{}", address.cid).into_bytes()
            })
        }
        _ => None,
    }
}

fn do_accept(options: &Options, listener: RawFd) -> Result<(), Failure> {
    // SAFETY: listener is an active listening descriptor.
    let accepted =
        unsafe { libc::accept4(listener, std::ptr::null_mut(), std::ptr::null_mut(), 0) };
    if accepted < 0 {
        let errno = last_errno();
        if accept_again(errno) {
            return Ok(());
        }
        let mut message = format!("Failed to accept connection on fd:{listener}: ");
        message.push_str(&errno_text(errno));
        return Err(Failure::with_errno(message.into_bytes(), errno));
    }
    // SAFETY: accept4 returned a new descriptor uniquely owned here.
    let accepted = unsafe { OwnedFd::from_raw_fd(accepted) };
    let local = socket_name(accepted.as_raw_fd()).unwrap_or_else(|| b"n/a".to_vec());
    let peer = peer_name(accepted.as_raw_fd()).unwrap_or_else(|| b"n/a".to_vec());
    let mut message = b"Connection from ".to_vec();
    message.extend_from_slice(&peer);
    message.extend_from_slice(b" to ");
    message.extend_from_slice(&local);
    log_info(&message);
    fork_and_exec_process(options, &accepted)
}

fn accept_again(errno: libc::c_int) -> bool {
    matches!(
        errno,
        libc::EAGAIN
            | libc::EINTR
            | libc::ECONNABORTED
            | libc::EPROTO
            | libc::ENETDOWN
            | libc::ENOPROTOOPT
            | libc::EHOSTDOWN
            | libc::ENONET
            | libc::EHOSTUNREACH
            | libc::ENETUNREACH
    )
}

fn fork_and_exec_process(options: &Options, accepted: &OwnedFd) -> Result<(), Failure> {
    // SAFETY: getpid has no pointer arguments and cannot fail.
    let original_parent = unsafe { libc::getpid() };
    // SAFETY: fork is called by this single-threaded utility before any Rust
    // worker threads exist.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(last_errno_failure(b"Failed to fork: "));
    }
    if child == 0 {
        const CHILD_NAME: &[u8] = b"(activate)\0";
        // SAFETY: CHILD_NAME is a static NUL-terminated Linux task name.
        unsafe { libc::prctl(libc::PR_SET_NAME, CHILD_NAME.as_ptr()) };
        reset_child_signals();
        // SAFETY: requests a standard parent-death signal for this child.
        if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) } < 0 {
            child_fatal(b"Failed to set death signal: ", last_errno());
        }
        // SAFETY: getppid has no pointer arguments and cannot fail.
        let current_parent = unsafe { libc::getppid() };
        if current_parent != 0 && current_parent != original_parent {
            // SAFETY: the parent died before PR_SET_PDEATHSIG was installed;
            // raising SIGTERM reproduces the missed kernel notification.
            unsafe { libc::raise(libc::SIGTERM) };
            // SAFETY: raise normally terminates; this covers a blocked signal.
            unsafe { libc::_exit(1) };
        }
        if let Err(errno) = lower_nofile_limit() {
            child_fatal(b"Failed to lower RLIMIT_NOFILE's soft limit to 1K: ", errno);
        }
        let result = exec_process(options, &[], accepted.as_raw_fd(), 1);
        if let Err(error) = result {
            log_error(&error.message);
        }
        // SAFETY: the fork child must not run Rust destructors after exec fails.
        unsafe { libc::_exit(1) };
    }
    let joined = join_command(&options.command);
    let mut message = b"Spawned '".to_vec();
    message.extend_from_slice(&joined);
    message.extend_from_slice(format!("' as PID {child}.").as_bytes());
    log_info(&message);
    Ok(())
}

fn lower_nofile_limit() -> Result<(), libc::c_int> {
    const SELECT_LIMIT: libc::rlim_t = 1024;
    // SAFETY: rlimit is plain-old-data and the pointer is writable.
    let mut limit = unsafe { mem::zeroed::<libc::rlimit>() };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, std::ptr::addr_of_mut!(limit)) } < 0 {
        return Err(last_errno());
    }
    if limit.rlim_cur <= SELECT_LIMIT {
        return Ok(());
    }
    let kernel_maximum = fs::read_to_string("/proc/sys/fs/nr_open")
        .ok()
        .and_then(|value| value.trim().parse::<libc::rlim_t>().ok())
        .unwrap_or(1_048_576);
    limit.rlim_max = limit.rlim_max.min(kernel_maximum);
    limit.rlim_cur = SELECT_LIMIT.min(limit.rlim_max);
    // SAFETY: limit contains a soft limit no greater than its hard limit.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, std::ptr::addr_of!(limit)) } < 0 {
        Err(last_errno())
    } else {
        Ok(())
    }
}

fn child_fatal(prefix: &[u8], errno: libc::c_int) -> ! {
    let mut message = prefix.to_vec();
    message.extend_from_slice(errno_text(errno).as_bytes());
    message.push(b'\n');
    let _ = io::stderr().write_all(&message);
    // SAFETY: fork children must not run Rust destructors on setup failures.
    unsafe { libc::_exit(1) }
}

#[allow(clippy::too_many_lines)]
fn exec_process(
    options: &Options,
    _listeners: &[OwnedFd],
    start_fd: RawFd,
    descriptor_count: usize,
) -> Result<(), Failure> {
    if options.inetd {
        if descriptor_count != 1 {
            return Err(Failure::fixed(
                b"--inetd only supported with a single file descriptor, or with --accept.",
            ));
        }
        rearrange_inetd_stdio(start_fd)?;
    } else if start_fd != LISTEN_FDS_START {
        if descriptor_count != 1 {
            return Err(Failure::fixed(b"Invalid activation descriptor layout."));
        }
        // SAFETY: start_fd is open and fd 3 is the protocol destination.
        if unsafe { libc::dup2(start_fd, LISTEN_FDS_START) } < 0 {
            return Err(last_errno_failure(b"Failed to dup connection: "));
        }
        // SAFETY: the source is no longer needed after dup2.
        unsafe { libc::close(start_fd) };
    }

    let mut child_environment: Vec<(OsString, OsString)> = Vec::new();
    for name in ["TERM", "COLORTERM", "NO_COLOR", "PATH", "USER", "HOME"] {
        if let Some(value) = env::var_os(name) {
            child_environment.push((OsString::from(name), value));
        }
    }
    if !options.inetd {
        child_environment.push((
            OsString::from("LISTEN_FDS"),
            OsString::from(descriptor_count.to_string()),
        ));
        child_environment.push((
            OsString::from("LISTEN_PID"),
            OsString::from(std::process::id().to_string()),
        ));
        if let Some(identifier) = own_pidfd_inode() {
            child_environment.push((
                OsString::from("LISTEN_PIDFDID"),
                OsString::from(identifier.to_string()),
            ));
        }
        if !options.fdnames.is_empty() {
            let names = if options.fdnames.len() == 1 {
                vec![options.fdnames[0].clone(); descriptor_count]
            } else {
                options.fdnames.clone()
            };
            let mut joined = Vec::new();
            for (index, name) in names.iter().enumerate() {
                if index > 0 {
                    joined.push(b':');
                }
                joined.extend_from_slice(name.as_os_str().as_bytes());
            }
            child_environment.push((OsString::from("LISTEN_FDNAMES"), OsString::from_vec(joined)));
        }
    }
    for (name, value) in &options.environment {
        if let Some(existing) = child_environment
            .iter_mut()
            .find(|(candidate, _)| candidate == name)
        {
            existing.1 = value.clone();
        } else {
            child_environment.push((name.clone(), value.clone()));
        }
    }

    let joined = join_command(&options.command);
    let mut message = b"Executing: ".to_vec();
    message.extend_from_slice(&joined);
    log_info(&message);

    let arguments: Vec<CString> = options
        .command
        .iter()
        .map(|argument| {
            CString::new(argument.as_os_str().as_bytes())
                .expect("process arguments cannot contain NUL bytes")
        })
        .collect();
    let environment: Vec<CString> = child_environment
        .iter()
        .map(|(name, value)| {
            let mut assignment = name.as_os_str().as_bytes().to_vec();
            assignment.push(b'=');
            assignment.extend_from_slice(value.as_os_str().as_bytes());
            CString::new(assignment).expect("environment entries cannot contain NUL bytes")
        })
        .collect();
    let mut argument_pointers: Vec<*const libc::c_char> =
        arguments.iter().map(|value| value.as_ptr()).collect();
    argument_pointers.push(std::ptr::null());
    let mut environment_pointers: Vec<*const libc::c_char> =
        environment.iter().map(|value| value.as_ptr()).collect();
    environment_pointers.push(std::ptr::null());
    // SAFETY: every pointer refers to a live NUL-terminated CString and each
    // vector has the terminating null pointer required by execvpe. execvpe's
    // PATH lookup intentionally uses this process's original environment.
    unsafe {
        libc::execvpe(
            arguments[0].as_ptr(),
            argument_pointers.as_ptr(),
            environment_pointers.as_ptr(),
        )
    };
    let errno = last_errno();
    let mut message = b"Failed to execute '".to_vec();
    message.extend_from_slice(&joined);
    message.extend_from_slice(b"': ");
    message.extend_from_slice(errno_text(errno).as_bytes());
    Err(Failure::with_errno(message, errno))
}

fn rearrange_inetd_stdio(fd: RawFd) -> Result<(), Failure> {
    // SAFETY: fd is open; dup2 atomically replaces the standard descriptors.
    if unsafe { libc::dup2(fd, libc::STDIN_FILENO) } < 0
        || unsafe { libc::dup2(fd, libc::STDOUT_FILENO) } < 0
    {
        return Err(last_errno_failure(b"Failed to move fd to stdin+stdout: "));
    }
    if fd > libc::STDERR_FILENO {
        // SAFETY: fd has been duplicated to stdin and stdout.
        unsafe { libc::close(fd) };
    }
    Ok(())
}

fn join_command(command: &[OsString]) -> Vec<u8> {
    let mut joined = Vec::new();
    for (index, argument) in command.iter().enumerate() {
        if index > 0 {
            joined.push(b' ');
        }
        joined.extend_from_slice(argument.as_os_str().as_bytes());
    }
    joined
}

fn own_pidfd_inode() -> Option<u64> {
    // SAFETY: pidfd_open receives the current PID and no pointer arguments.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) } as RawFd;
    if fd < 0 {
        return None;
    }
    // SAFETY: stat is plain-old-data and zero is a valid initialization.
    let mut stat = unsafe { mem::zeroed::<libc::stat>() };
    // SAFETY: stat is a valid output buffer for this open pidfd.
    let result = unsafe { libc::fstat(fd, std::ptr::addr_of_mut!(stat)) };
    // SAFETY: fd is no longer needed.
    unsafe { libc::close(fd) };
    (result == 0).then_some(stat.st_ino)
}

fn set_cloexec(fd: RawFd, enabled: bool) -> Result<(), libc::c_int> {
    // SAFETY: fcntl reads flags for an open descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(last_errno());
    }
    let desired = if enabled {
        flags | libc::FD_CLOEXEC
    } else {
        flags & !libc::FD_CLOEXEC
    };
    // SAFETY: desired contains only descriptor flag bits.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, desired) } < 0 {
        Err(last_errno())
    } else {
        Ok(())
    }
}

fn install_sigchld_handler() -> Result<(), Failure> {
    // SAFETY: sigaction is a plain-old-data kernel ABI structure.
    let mut action = unsafe { mem::zeroed::<libc::sigaction>() };
    action.sa_sigaction = sigchld_handler as *const () as usize;
    action.sa_flags = libc::SA_NOCLDSTOP | libc::SA_RESTART;
    // SAFETY: action owns a valid signal set.
    unsafe { libc::sigemptyset(std::ptr::addr_of_mut!(action.sa_mask)) };
    // SAFETY: installs a process-local handler with static lifetime.
    if unsafe {
        libc::sigaction(
            libc::SIGCHLD,
            std::ptr::addr_of!(action),
            std::ptr::null_mut(),
        )
    } < 0
    {
        return Err(last_errno_failure(b"Failed to install SIGCHLD handler: "));
    }
    Ok(())
}

extern "C" fn sigchld_handler(_signal: libc::c_int) {
    loop {
        let mut status = 0_i32;
        // SAFETY: status is writable and WNOHANG never blocks.
        let child = unsafe { libc::waitpid(-1, std::ptr::addr_of_mut!(status), libc::WNOHANG) };
        if child <= 0 {
            return;
        }
        if LOG_INFO_ENABLED.load(Ordering::Relaxed) {
            let code = if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else {
                libc::WTERMSIG(status)
            };
            write_child_status(child, code);
        }
    }
}

fn write_child_status(child: libc::pid_t, code: libc::c_int) {
    let mut buffer = [0_u8; 96];
    let mut length = 0_usize;
    append_signal_bytes(&mut buffer, &mut length, b"Child ");
    append_signal_number(&mut buffer, &mut length, i64::from(child));
    append_signal_bytes(&mut buffer, &mut length, b" died with code ");
    append_signal_number(&mut buffer, &mut length, i64::from(code));
    append_signal_bytes(&mut buffer, &mut length, b"\n");
    // SAFETY: write is async-signal-safe and buffer is initialized through length.
    unsafe {
        libc::write(
            libc::STDERR_FILENO,
            buffer.as_ptr().cast(),
            length as libc::size_t,
        )
    };
}

fn append_signal_bytes(buffer: &mut [u8], length: &mut usize, value: &[u8]) {
    for byte in value {
        if *length < buffer.len() {
            buffer[*length] = *byte;
            *length += 1;
        }
    }
}

fn append_signal_number(buffer: &mut [u8], length: &mut usize, value: i64) {
    let mut digits = [0_u8; 20];
    let mut count = 0_usize;
    let mut value = value.unsigned_abs();
    if value == 0 {
        digits[0] = b'0';
        count = 1;
    } else {
        while value > 0 {
            digits[count] = b'0' + (value % 10) as u8;
            value /= 10;
            count += 1;
        }
    }
    for digit in digits[..count].iter().rev() {
        append_signal_bytes(buffer, length, &[*digit]);
    }
}

fn reset_child_signals() {
    for signal in 1..=64 {
        if matches!(signal, libc::SIGKILL | libc::SIGSTOP) {
            continue;
        }
        // SAFETY: SIG_DFL is valid for every catchable signal.
        unsafe { libc::signal(signal, libc::SIG_DFL) };
    }
    // SAFETY: an empty mask is valid for SIG_SETMASK.
    let mut mask = unsafe { mem::zeroed::<libc::sigset_t>() };
    // SAFETY: mask is writable process-local storage.
    unsafe {
        libc::sigemptyset(std::ptr::addr_of_mut!(mask));
        libc::sigprocmask(
            libc::SIG_SETMASK,
            std::ptr::addr_of!(mask),
            std::ptr::null_mut(),
        );
    }
}

fn notify(state: &[u8]) {
    let Ok(state) = CString::new(state) else {
        return;
    };
    // SAFETY: state is a valid NUL-terminated string and no descriptors are passed.
    let _ = unsafe { rustd_notify_send(0, state.as_ptr(), std::ptr::null(), 0) };
}

fn info_logging_enabled() -> bool {
    log_level() >= 6 && !matches!(log_target(), LogTarget::Null)
}

fn debug_logging_enabled() -> bool {
    log_level() >= 7
}

fn log_level() -> u8 {
    static LEVEL: OnceLock<u8> = OnceLock::new();
    *LEVEL.get_or_init(configured_log_level)
}

fn configured_log_level() -> u8 {
    let Some(value) = env::var("SYSTEMD_LOG_LEVEL").ok() else {
        return 6;
    };
    let mut global = 6_u8;
    let mut target_maximum = 7_u8;
    let selected_target = env::var("SYSTEMD_LOG_TARGET").unwrap_or_else(|_| "auto".to_owned());
    for word in value.split(',') {
        if let Some((target, level)) = word.split_once(':') {
            let Some(level) = parse_log_level(level) else {
                warn_invalid_log_level(&value);
                return global.min(target_maximum);
            };
            if !matches!(
                target,
                "console"
                    | "console-prefixed"
                    | "kmsg"
                    | "journal"
                    | "journal-or-kmsg"
                    | "syslog"
                    | "syslog-or-kmsg"
                    | "auto"
                    | "null"
            ) {
                warn_invalid_log_level(&value);
                return global.min(target_maximum);
            }
            if target == selected_target {
                target_maximum = level;
            }
        } else if let Some(level) = parse_log_level(word) {
            global = level;
        } else {
            warn_invalid_log_level(&value);
            return global.min(target_maximum);
        }
    }
    global.min(target_maximum)
}

fn parse_log_level(value: &str) -> Option<u8> {
    match value {
        "0" | "emerg" => Some(0),
        "1" | "alert" => Some(1),
        "2" | "crit" => Some(2),
        "3" | "err" => Some(3),
        "4" | "warning" => Some(4),
        "5" | "notice" => Some(5),
        "6" | "info" => Some(6),
        "7" | "debug" => Some(7),
        _ => None,
    }
}

fn warn_invalid_log_level(value: &str) {
    write_log(
        format!("Failed to parse log level '{value}', ignoring: Invalid argument").as_bytes(),
        4,
    );
}

fn log_info(message: &[u8]) {
    if info_logging_enabled() {
        write_log(message, 6);
    }
}

fn log_debug(message: &[u8]) {
    if debug_logging_enabled() {
        write_log(message, 7);
    }
}

fn log_warning(message: &[u8]) {
    if log_level() >= 4 {
        write_log(message, 4);
    }
}

fn log_error(message: &[u8]) {
    if log_level() >= 3 {
        write_log(message, 3);
    }
}

#[derive(Clone, Copy)]
enum LogTarget {
    Console,
    ConsolePrefixed,
    Kmsg,
    Null,
    Other,
}

fn initialize_logging() {
    let _ = log_target();
    let _ = log_level();
}

fn log_target() -> LogTarget {
    static TARGET: OnceLock<LogTarget> = OnceLock::new();
    *TARGET.get_or_init(|| match env::var("SYSTEMD_LOG_TARGET").ok().as_deref() {
        None | Some("auto" | "console") => LogTarget::Console,
        Some("console-prefixed") => LogTarget::ConsolePrefixed,
        Some("kmsg") => LogTarget::Kmsg,
        Some("null") => LogTarget::Null,
        Some("journal" | "journal-or-kmsg" | "syslog" | "syslog-or-kmsg") => LogTarget::Other,
        Some(value) => {
            let mut stderr = io::stderr().lock();
            let _ = writeln!(stderr, "Failed to parse log target '{value}', ignoring.");
            LogTarget::Console
        }
    })
}

fn write_log(message: &[u8], priority: u8) {
    let target = log_target();
    if matches!(target, LogTarget::Null | LogTarget::Other) {
        return;
    }
    if matches!(target, LogTarget::Kmsg) && write_kmsg(message, priority) {
        return;
    }
    let mut stderr = io::stderr().lock();
    if matches!(target, LogTarget::ConsolePrefixed) {
        let _ = write!(stderr, "<{}>", 24 + priority);
    }
    let _ = stderr.write_all(message);
    let _ = stderr.write_all(b"\n");
}

fn write_kmsg(message: &[u8], priority: u8) -> bool {
    let Ok(mut kmsg) = OpenOptions::new().write(true).open("/dev/kmsg") else {
        return false;
    };
    write!(
        kmsg,
        "<{}>systemd-socket-activate[{}]: ",
        24 + priority,
        std::process::id()
    )
    .and_then(|()| kmsg.write_all(message))
    .and_then(|()| kmsg.write_all(b"\n"))
    .is_ok()
}

fn last_errno() -> libc::c_int {
    io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

fn errno_text(errno: libc::c_int) -> String {
    // SAFETY: strerror returns a process-owned NUL-terminated description.
    let pointer = unsafe { libc::strerror(errno) };
    if pointer.is_null() {
        return format!("Unknown error {errno}");
    }
    // SAFETY: non-null strerror results are NUL-terminated.
    unsafe { CStr::from_ptr(pointer) }
        .to_string_lossy()
        .into_owned()
}

fn last_errno_failure(prefix: &[u8]) -> Failure {
    let errno = last_errno();
    let mut message = prefix.to_vec();
    message.extend_from_slice(errno_text(errno).as_bytes());
    Failure::with_errno(message, errno)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_address_families() {
        assert_eq!(
            parse_address(b"127.0.0.1:2000"),
            Ok(Address::Inet4 {
                address: Ipv4Addr::LOCALHOST,
                port: 2000,
            })
        );
        assert_eq!(
            parse_address(b"[::1]:2001"),
            Ok(Address::Inet6 {
                address: Ipv6Addr::LOCALHOST,
                port: 2001,
                scope_id: 0,
            })
        );
        assert_eq!(
            parse_address(b"@activate"),
            Ok(Address::Unix {
                path: b"@activate".to_vec(),
                abstract_namespace: true,
            })
        );
        assert_eq!(
            parse_address(b"vsock:host:7"),
            Ok(Address::Vsock { cid: 2, port: 7 })
        );
    }

    #[test]
    fn rejects_invalid_ports_and_addresses() {
        assert_eq!(parse_port(b"+45971"), Ok(45971));
        assert_eq!(parse_address(b"0"), Err(libc::EINVAL));
        assert_eq!(parse_address(b"65536"), Err(libc::ERANGE));
        assert_eq!(parse_address(b"relative/path"), Err(libc::EINVAL));
        assert_eq!(parse_address(b"[::1]2000"), Err(libc::EINVAL));
        assert_eq!(parse_address(b"vsock:host"), Err(libc::EINVAL));
    }

    #[test]
    fn environment_assignment_validation_matches_bash_names() {
        let mut assignments = Vec::new();
        add_environment(&mut assignments, b"VALID_NAME=value").unwrap();
        assert_eq!(assignments[0].0, "VALID_NAME");
        assert_eq!(assignments[0].1, "value");
        assert!(add_environment(&mut assignments, b"1INVALID=value").is_err());
        assert!(add_environment(&mut assignments, b"INVALID-NAME=value").is_err());
    }

    #[test]
    fn fdnames_preserve_empty_fields() {
        let mut names = Vec::new();
        add_fdnames(&mut names, b"one::three");
        assert_eq!(names, ["one", "", "three"]);
    }
}
