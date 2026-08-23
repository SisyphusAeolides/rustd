// SPDX-License-Identifier: LGPL-2.1-or-later
//! `systemd-notify` compatibility utility.
//!
//! Upstream reference: systemd v261 `src/notify/notify.c` and
//! `src/libsystemd/sd-daemon/sd-daemon.c`.

use std::collections::HashSet;
use std::env;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixDatagram;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use rustd::ffi::notify::{
    rustd_dup_cloexec, rustd_monotonic_usec, rustd_notify_autobind, rustd_notify_barrier,
    rustd_notify_enable_passcred, rustd_notify_forward_pending,
    rustd_notify_install_forward_signals, rustd_notify_recv, rustd_notify_send,
    rustd_pidfd_inode_id, rustd_set_notify_gid, rustd_set_notify_uid,
};

const VERSION_OUTPUT: &str = concat!(
    "systemd 261 (261.2-1-arch)\n",
    "+PAM +AUDIT -SELINUX +APPARMOR -IMA +IPE +SMACK +SECCOMP +GCRYPT +GNUTLS +OPENSSL +ACL ",
    "+BLKID +CURL +ELFUTILS +FIDO2 +IDN2 +KMOD +LIBCRYPTSETUP +LIBCRYPTSETUP_PLUGINS +LIBFDISK ",
    "+PCRE2 +PWQUALITY +P11KIT +QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB +ZSTD +BPF_FRAMEWORK +BTF ",
    "+XKBCOMMON +UTMP +LIBARCHIVE\n"
);

const HELP: &str = concat!(
    "> systemd-notify [OPTIONS...] [VARIABLE=VALUE...]\n",
    "> systemd-notify [OPTIONS...] --exec [VARIABLE=VALUE...] ; -- CMDLINE...\n",
    "> systemd-notify [OPTIONS...] --fork -- CMDLINE...\n\n",
    "Notify the service manager about service status updates.\n\n",
    "Options:\n",
    "  -h --help        Show this help\n",
    "     --version     Show package version\n",
    "     --ready       Inform the service manager about service start-up/reload\n",
    "                   completion\n",
    "     --reloading   Inform the service manager about configuration reloading\n",
    "     --stopping    Inform the service manager about service shutdown\n",
    "     --pid[=PID]   Set main PID of daemon\n",
    "     --uid=USER    Set user to send from\n",
    "     --status=TEXT Set status text\n",
    "     --booted      Check if the system was booted up with systemd\n",
    "     --no-block    Do not wait until operation finished\n",
    "     --exec        Execute command line separated by ';' once done\n",
    "     --fd=FD       Pass specified file descriptor along with the message\n",
    "     --fdname=NAME Name to assign to passed file descriptors\n",
    "     --fork        Receive notifications from child rather than sending them\n",
    "  -q --quiet       Do not show PID of child when forking\n\n",
    "See the systemd-notify(1) man page for details.\n"
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Action {
    Notify,
    Booted,
    Fork,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PidMode {
    Auto,
    Parent,
    SelfProcess,
    Exact(i32),
}

#[allow(clippy::struct_excessive_bools)] // These are independent upstream command-line switches.
struct Options {
    action: Action,
    ready: bool,
    reloading: bool,
    stopping: bool,
    pid: Option<PidMode>,
    status: Option<String>,
    uid: Option<(u32, u32)>,
    no_block: bool,
    do_exec: bool,
    fds: Vec<File>,
    fdname: Option<String>,
    quiet: bool,
    args: Vec<String>,
}

enum ParseResult {
    Run(Options),
    Exit(&'static str),
}

fn main() {
    let arguments: Vec<String> = env::args().skip(1).collect();
    let result = match parse_options(&arguments) {
        Ok(ParseResult::Exit(output)) => write_stdout(output.as_bytes()).map(|()| 0),
        Ok(ParseResult::Run(options)) => run(options),
        Err(error) => {
            if !error.is_empty() {
                eprintln!("{error}");
            }
            Err(())
        }
    };
    match result {
        Ok(0) => {}
        Ok(code) => std::process::exit(code),
        Err(()) => std::process::exit(1),
    }
}

fn write_stdout(bytes: &[u8]) -> Result<(), ()> {
    io::stdout().lock().write_all(bytes).map_err(|_| ())
}

#[allow(clippy::too_many_lines)] // Keep the v261 option state machine in declaration order.
fn parse_options(arguments: &[String]) -> Result<ParseResult, String> {
    let mut options = Options {
        action: Action::Notify,
        ready: false,
        reloading: false,
        stopping: false,
        pid: None,
        status: None,
        uid: None,
        no_block: false,
        do_exec: false,
        fds: Vec::new(),
        fdname: None,
        quiet: false,
        args: Vec::new(),
    };
    let mut seen_fds = HashSet::new();
    let mut index = 0_usize;
    let mut positional_only = false;
    while index < arguments.len() {
        let argument = &arguments[index];
        if positional_only || argument == "-" || !argument.starts_with('-') {
            options.args.push(argument.clone());
            index += 1;
            continue;
        }
        if argument == "--" {
            positional_only = true;
            index += 1;
            continue;
        }
        if let Some(long) = argument.strip_prefix("--") {
            let (spelling, attached) = long
                .split_once('=')
                .map_or((long, None), |(name, value)| (name, Some(value)));
            let name = resolve_long_option(spelling)?;
            match name {
                "help" => {
                    reject_attached(name, attached)?;
                    return Ok(ParseResult::Exit(HELP));
                }
                "version" => {
                    reject_attached(name, attached)?;
                    return Ok(ParseResult::Exit(VERSION_OUTPUT));
                }
                "ready" => {
                    reject_attached(name, attached)?;
                    options.ready = true;
                }
                "reloading" => {
                    reject_attached(name, attached)?;
                    options.reloading = true;
                }
                "stopping" => {
                    reject_attached(name, attached)?;
                    options.stopping = true;
                }
                "pid" => options.pid = Some(parse_pid_mode(attached)?),
                "uid" | "status" | "fd" | "fdname" => {
                    let value = if let Some(value) = attached {
                        value
                    } else {
                        index += 1;
                        arguments.get(index).map(String::as_str).ok_or_else(|| {
                            format!("systemd-notify: option '--{name}' requires an argument")
                        })?
                    };
                    match name {
                        "uid" => options.uid = Some(resolve_user(value)?),
                        "status" => options.status = Some(value.to_owned()),
                        "fd" => add_fd(value, &mut seen_fds, &mut options.fds)?,
                        "fdname" => {
                            if !valid_fdname(value) {
                                return Err(format!("File descriptor name invalid: {value}"));
                            }
                            options.fdname = Some(value.to_owned());
                        }
                        _ => unreachable!(),
                    }
                }
                "booted" => {
                    reject_attached(name, attached)?;
                    options.action = Action::Booted;
                }
                "no-block" => {
                    reject_attached(name, attached)?;
                    options.no_block = true;
                }
                "exec" => {
                    reject_attached(name, attached)?;
                    options.do_exec = true;
                }
                "fork" => {
                    reject_attached(name, attached)?;
                    options.action = Action::Fork;
                }
                "quiet" => {
                    reject_attached(name, attached)?;
                    options.quiet = true;
                }
                _ => unreachable!("complete option match"),
            }
            index += 1;
            continue;
        }
        for short in argument[1..].chars() {
            match short {
                'h' => return Ok(ParseResult::Exit(HELP)),
                'q' => options.quiet = true,
                _ => return Err(format!("systemd-notify: unrecognized option '-{short}'")),
            }
        }
        index += 1;
    }

    let have_env = options.ready
        || options.reloading
        || options.stopping
        || options.status.is_some()
        || options.pid.is_some()
        || !options.fds.is_empty();
    match options.action {
        Action::Notify => {
            if options.fdname.is_some() && options.fds.is_empty() {
                return Err("No file descriptors passed, but --fdname= set, refusing.".to_owned());
            }
            if options.do_exec {
                let Some(separator) = options.args.iter().position(|argument| argument == ";")
                else {
                    return Err(
                        "If --exec is used, argument list must contain ';' separator, refusing."
                            .to_owned(),
                    );
                };
                if separator + 1 == options.args.len() {
                    return Err(
                        "Empty command line specified after ';' separator, refusing.".to_owned(),
                    );
                }
                if !have_env && separator == 0 {
                    return Err("No notify message specified while --exec, refusing.".to_owned());
                }
            } else if !have_env && options.args.is_empty() {
                write_stdout(HELP.as_bytes()).map_err(|()| String::new())?;
                return Err(String::new());
            }
        }
        Action::Booted => {
            if !options.args.is_empty() {
                return Err("--booted takes no parameters, refusing.".to_owned());
            }
        }
        Action::Fork => {
            if options.args.is_empty() {
                return Err("--fork requires a command to be specified, refusing.".to_owned());
            }
        }
    }
    if have_env && options.action != Action::Notify {
        return Err(concat!(
            "--ready, --reloading, --stopping, --pid=, --status=, --fd= may not be combined ",
            "with --fork or --booted, refusing."
        )
        .to_owned());
    }
    Ok(ParseResult::Run(options))
}

fn resolve_long_option(value: &str) -> Result<&'static str, String> {
    const OPTIONS: &[&str] = &[
        "help",
        "version",
        "ready",
        "reloading",
        "stopping",
        "pid",
        "uid",
        "status",
        "booted",
        "no-block",
        "exec",
        "fd",
        "fdname",
        "fork",
        "quiet",
    ];
    if let Some(exact) = OPTIONS.iter().copied().find(|option| *option == value) {
        return Ok(exact);
    }
    let matches: Vec<&str> = OPTIONS
        .iter()
        .copied()
        .filter(|option| option.starts_with(value))
        .collect();
    match matches.as_slice() {
        [single] => Ok(single),
        [] => Err(format!("systemd-notify: unrecognized option '--{value}'")),
        _ => Err(format!(
            "systemd-notify: option '--{value}' is ambiguous; possibilities: {}",
            matches
                .iter()
                .map(|option| format!("--{option}"))
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

fn reject_attached(name: &str, attached: Option<&str>) -> Result<(), String> {
    if attached.is_some() {
        return Err(format!(
            "systemd-notify: option '--{name}' doesn't allow an argument"
        ));
    }
    Ok(())
}

fn parse_pid_mode(value: Option<&str>) -> Result<PidMode, String> {
    match value.unwrap_or("auto") {
        "" | "auto" => Ok(PidMode::Auto),
        "parent" => Ok(PidMode::Parent),
        "self" => Ok(PidMode::SelfProcess),
        value => {
            let pid = value.parse::<i32>().ok().filter(|pid| *pid > 0);
            if let Some(pid) = pid {
                if Path::new(&format!("/proc/{pid}")).exists() {
                    return Ok(PidMode::Exact(pid));
                }
            }
            Err(format!(
                "Failed to refer to --pid='{value}': No such process"
            ))
        }
    }
}

fn resolve_user(value: &str) -> Result<(u32, u32), String> {
    if let Ok(uid) = value.parse::<u32>() {
        if uid != u32::MAX {
            return Ok((uid, u32::MAX));
        }
    }
    if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() >= 4 && fields[0] == value {
                if let (Ok(uid), Ok(gid)) = (fields[2].parse(), fields[3].parse()) {
                    return Ok((uid, gid));
                }
            }
        }
    }
    Err(format!("Can't resolve user {value}: Invalid argument"))
}

fn valid_fdname(value: &str) -> bool {
    value.len() <= 255
        && value
            .bytes()
            .all(|byte| (b' '..=b'~').contains(&byte) && byte != b':')
}

fn add_fd(value: &str, seen: &mut HashSet<i32>, output: &mut Vec<File>) -> Result<(), String> {
    let fd = value
        .parse::<i32>()
        .ok()
        .filter(|fd| *fd >= 0)
        .ok_or_else(|| format!("Failed to parse file descriptor: {value}"))?;
    if !seen.insert(fd) {
        return Err(format!(
            "Specified file descriptor '{fd}' not passed or specified more than once: No such file or directory"
        ));
    }
    let owned = if fd < 3 {
        // SAFETY: the native helper returns a new descriptor owned by this process.
        let copy = unsafe { rustd_dup_cloexec(fd) };
        if copy < 0 {
            return Err(format!(
                "Failed to duplicate file descriptor: {}",
                errno_text(copy)
            ));
        }
        copy
    } else {
        if !Path::new(&format!("/proc/self/fd/{fd}")).exists() {
            return Err(format!(
                "Specified file descriptor '{fd}' not passed or specified more than once: No such file or directory"
            ));
        }
        fd
    };
    // SAFETY: `owned` is valid and ownership has been transferred to this vector.
    output.push(unsafe { File::from_raw_fd(owned) });
    Ok(())
}

fn parent_pid() -> i32 {
    let Ok(stat) = fs::read_to_string("/proc/self/stat") else {
        return i32::try_from(std::process::id()).unwrap_or(i32::MAX);
    };
    stat.rsplit_once(')')
        .and_then(|(_, fields)| fields.split_whitespace().nth(1))
        .and_then(|pid| pid.parse().ok())
        .unwrap_or_else(|| i32::try_from(std::process::id()).unwrap_or(i32::MAX))
}

fn auto_pid() -> i32 {
    let parent = parent_pid();
    let manager = env::var("MANAGERPID").ok().and_then(|pid| pid.parse().ok());
    if parent == 1 || manager == Some(parent) {
        i32::try_from(std::process::id()).unwrap_or(i32::MAX)
    } else {
        parent
    }
}

fn selected_pid(mode: PidMode) -> i32 {
    match mode {
        PidMode::Auto => auto_pid(),
        PidMode::Parent => parent_pid(),
        PidMode::SelfProcess => i32::try_from(std::process::id()).unwrap_or(i32::MAX),
        PidMode::Exact(pid) => pid,
    }
}

fn merge_fields(mut generated: Vec<String>, supplied: &[String]) -> Vec<String> {
    for (position, item) in supplied.iter().enumerate() {
        let key = item.split_once('=').map(|(key, _)| key);
        if let Some(key) = key {
            if let Some(index) = generated.iter().position(|old| {
                old.split_once('=')
                    .is_some_and(|(old_key, _)| old_key == key)
            }) {
                generated[index].clone_from(item);
                continue;
            }
            if let Some(index) = supplied.iter().rposition(|candidate| {
                candidate
                    .split_once('=')
                    .is_some_and(|(candidate_key, _)| candidate_key == key)
            }) {
                if index != position {
                    continue;
                }
            }
        } else if generated.contains(item) {
            continue;
        }
        generated.push(item.clone());
    }
    generated
}

#[allow(clippy::too_many_lines)] // Message construction mirrors the ordered v261 protocol fields.
fn run(mut options: Options) -> Result<i32, ()> {
    match options.action {
        Action::Booted => return Ok(i32::from(!Path::new("/run/systemd/system").exists())),
        Action::Fork => return action_fork(&options.args, options.quiet),
        Action::Notify => {}
    }

    let (notify_args, exec_args) = if options.do_exec {
        let separator = options
            .args
            .iter()
            .position(|argument| argument == ";")
            .expect("validated exec separator");
        (
            &options.args[..separator],
            Some(options.args[separator + 1..].to_vec()),
        )
    } else {
        (&options.args[..], None)
    };
    let mut generated = Vec::new();
    if options.reloading {
        generated.push("RELOADING=1".to_owned());
        // SAFETY: the helper only reads CLOCK_MONOTONIC.
        generated.push(format!("MONOTONIC_USEC={}", unsafe {
            rustd_monotonic_usec()
        }));
    }
    if options.ready {
        generated.push("READY=1".to_owned());
    }
    if options.stopping {
        generated.push("STOPPING=1".to_owned());
    }
    if let Some(status) = &options.status {
        generated.push(format!("STATUS={status}"));
    }
    let explicit_pid = options.pid.map(selected_pid);
    if let Some(pid) = explicit_pid {
        generated.push(format!("MAINPID={pid}"));
        let mut id = 0_u64;
        // SAFETY: `id` is a valid output pointer.
        if unsafe { rustd_pidfd_inode_id(pid, &mut id) } >= 0 {
            generated.push(format!("MAINPIDFDID={id}"));
        }
    }
    if !options.fds.is_empty() {
        generated.push("FDSTORE=1".to_owned());
        if let Some(name) = &options.fdname {
            generated.push(format!("FDNAME={name}"));
        }
    }
    let fields = merge_fields(generated, notify_args);
    let message = CString::new(fields.join("\n")).map_err(|_| {
        eprintln!("Failed to notify service manager: Invalid argument");
    })?;

    if let Some((uid, gid)) = options.uid {
        if gid != u32::MAX {
            // SAFETY: the credential change is process-local and the GID was validated.
            let result = unsafe { rustd_set_notify_gid(gid) };
            if result < 0 {
                eprintln!("Failed to change GID: {}", errno_text(result));
                return Err(());
            }
        }
        // SAFETY: the credential change is process-local and the UID was validated.
        let result = unsafe { rustd_set_notify_uid(uid) };
        if result < 0 {
            eprintln!("Failed to change UID: {}", errno_text(result));
            return Err(());
        }
    }
    let source_pid = explicit_pid.unwrap_or_else(auto_pid);
    let fds: Vec<i32> = options.fds.iter().map(AsRawFd::as_raw_fd).collect();
    // SAFETY: CString and descriptor slice remain valid for the duration of the call.
    let result =
        unsafe { rustd_notify_send(source_pid, message.as_ptr(), fds.as_ptr(), fds.len()) };
    if result == -libc::E2BIG {
        eprintln!("Too many file descriptors passed.");
        return Err(());
    }
    if result < 0 {
        eprintln!("Failed to notify service manager: {}", errno_text(result));
        return Err(());
    }
    if result == 0 {
        eprintln!("No status data could be sent: $RUSTD_NOTIFY_SOCKET was not set");
        return Err(());
    }
    options.fds.clear();
    if !options.no_block {
        // SAFETY: the helper owns its temporary pipe and uses the validated environment address.
        let barrier = unsafe { rustd_notify_barrier(source_pid, 5_000_000) };
        if barrier < 0 {
            eprintln!("Failed to invoke barrier: {}", errno_text(barrier));
            return Err(());
        }
        if barrier == 0 {
            eprintln!("No status data could be sent: $RUSTD_NOTIFY_SOCKET was not set");
            return Err(());
        }
    }
    if let Some(command) = exec_args {
        let error = Command::new(&command[0]).args(&command[1..]).exec();
        eprintln!(
            "Failed to execute command line: {}: {}",
            command.join(" "),
            concise_io_error(&error)
        );
        return Err(());
    }
    Ok(0)
}

#[allow(clippy::similar_names)] // PID/UID/GID are the canonical SCM_CREDENTIALS field names.
fn action_fork(command: &[String], quiet: bool) -> Result<i32, ()> {
    let mut notify_address = [0 as libc::c_char; 128];
    // SAFETY: the address buffer is writable and the returned descriptor is newly owned.
    let socket_fd =
        unsafe { rustd_notify_autobind(notify_address.as_mut_ptr(), notify_address.len()) };
    if socket_fd < 0 {
        eprintln!("Failed to prepare notify socket: {}", errno_text(socket_fd));
        return Err(());
    }
    // SAFETY: ownership of the newly created datagram descriptor is transferred here.
    let socket = unsafe { UnixDatagram::from_raw_fd(socket_fd) };
    // SAFETY: native helper wrote a NUL-terminated address on successful return.
    let notify_address = unsafe { std::ffi::CStr::from_ptr(notify_address.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    // SAFETY: the descriptor is a valid AF_UNIX datagram socket.
    let passcred = unsafe { rustd_notify_enable_passcred(socket.as_raw_fd()) };
    if passcred < 0 {
        eprintln!("Failed to prepare notify socket: {}", errno_text(passcred));
        return Err(());
    }
    socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .map_err(|_| ())?;
    let mut child = Command::new(&command[0])
        .args(&command[1..])
        .env("RUSTD_NOTIFY_SOCKET", &notify_address)
        .env("NOTIFY_SOCKET", &notify_address)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| {
            eprintln!(
                "Failed to execute '{}': {}",
                command.join(" "),
                concise_io_error(&error)
            );
        })?;
    // SAFETY: installs simple process-local handlers for the v261 forwarding set.
    let signal_result = unsafe { rustd_notify_install_forward_signals() };
    if signal_result < 0 {
        eprintln!(
            "Failed to set up signal forwarding: {}",
            errno_text(signal_result)
        );
        return Err(());
    }
    if !quiet {
        write_stdout(format!("{}\n", child.id()).as_bytes())?;
    }
    let expected_pid = i32::try_from(child.id()).unwrap_or(i32::MAX);
    let mut buffer = [0_u8; 65_536];
    loop {
        // SAFETY: the child PID is live or has just exited; ESRCH is handled below by wait.
        let forwarded = unsafe { rustd_notify_forward_pending(expected_pid) };
        if forwarded < 0 && forwarded != -libc::ESRCH {
            eprintln!("Failed to run event loop: {}", errno_text(forwarded));
            return Err(());
        }
        let mut sender_pid = 0_i32;
        let mut sender_uid = 0_u32;
        let mut sender_gid = 0_u32;
        let mut received_fds = [-1_i32; 253];
        let mut n_fds = 0_usize;
        // SAFETY: all buffers and output pointers are valid for the call.
        let received = unsafe {
            rustd_notify_recv(
                socket.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut sender_pid,
                &mut sender_uid,
                &mut sender_gid,
                received_fds.as_mut_ptr(),
                received_fds.len(),
                &mut n_fds,
            )
        };
        for fd in received_fds.iter().take(n_fds).copied() {
            // SAFETY: every received descriptor is newly owned by this process.
            drop(unsafe { File::from_raw_fd(fd) });
        }
        if received >= 0 && sender_pid == expected_pid {
            let text = &buffer[..usize::try_from(received).unwrap_or(0)];
            if text
                .split(|byte| *byte == b'\n')
                .any(|line| line == b"READY=1")
            {
                return Ok(0);
            }
        }
        if let Some(status) = child.try_wait().map_err(|_| ())? {
            return Ok(status.code().unwrap_or(1));
        }
        if received < 0
            && received != -libc::EAGAIN
            && received != -libc::EWOULDBLOCK
            && received != -libc::EINTR
        {
            eprintln!("Failed to run event loop: {}", errno_text(received));
            return Err(());
        }
    }
}

fn errno_text(result: i32) -> String {
    concise_io_error(&io::Error::from_raw_os_error(-result))
}

fn concise_io_error(error: &io::Error) -> String {
    let rendered = error.to_string();
    rendered
        .split(" (os error ")
        .next()
        .unwrap_or(&rendered)
        .to_owned()
}
