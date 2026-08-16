// SPDX-License-Identifier: LGPL-2.1-or-later
//! `systemd-mute-console` v261 compatibility utility.

use std::env;
use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use rustd::ffi::mute_console::{
    rustd_mute_console_install_signals, rustd_mute_console_peer_uid,
    rustd_mute_console_socket_accepts, rustd_mute_console_termination_requested,
    rustd_mute_console_uid,
};
use rustd::ffi::notify::rustd_notify_send;
use serde_json::{json, Value};

const VERSION_OUTPUT: &str = concat!(
    "systemd 261 (261.2-1-arch)\n",
    "+PAM +AUDIT -SELINUX +APPARMOR -IMA +IPE +SMACK +SECCOMP +GCRYPT +GNUTLS +OPENSSL +ACL ",
    "+BLKID +CURL +ELFUTILS +FIDO2 +IDN2 +KMOD +LIBCRYPTSETUP +LIBCRYPTSETUP_PLUGINS +LIBFDISK ",
    "+PCRE2 +PWQUALITY +P11KIT +QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB +ZSTD +BPF_FRAMEWORK +BTF ",
    "+XKBCOMMON +UTMP +LIBARCHIVE\n"
);

const HELP: &str = concat!(
    "systemd-mute-console [OPTIONS...]\n\n",
    "Mute status output to the console.\n\n",
    "  -h --help        Show this help\n",
    "     --version     Show package version\n",
    "     --kernel=BOOL Mute kernel log output\n",
    "     --pid1=BOOL   Mute PID 1 status output\n\n",
    "See the systemd-mute-console(1) man page for details.\n"
);

const MUTE_INTERFACE: &str = concat!(
    "# API for temporarily muting noisy output to the main kernel console\n",
    "interface io.systemd.MuteConsole\n\n",
    "# Mute kernel and PID 1 output to the main kernel console\n",
    "# [Requires 'more' flag]\n",
    "method Mute(\n",
    "\t# Whether to mute the kernel's output to the console (defaults to true).\n",
    "\tkernel: ?bool,\n",
    "\t# Whether to mute PID1's output to the console (defaults to true).\n",
    "\tpid1: ?bool\n",
    ") -> ()\n"
);

const IO_SYSTEMD_INTERFACE: &str = concat!(
    "interface io.systemd\n\n",
    "# Local error if a Varlink connection is disconnected (this never crosses the wire and is synthesized locally only).\n",
    "error Disconnected()\n\n",
    "# A method call time-out has been reached (also synthesized locally, does not cross wire)\n",
    "error TimedOut()\n\n",
    "# Some form of protocol error (also synthesized locally, does not cross wire)\n",
    "error Protocol()\n\n",
    "# A generic Linux system error (\"errno\"s).\n",
    "error System(\n",
    "\t# The origin of this system error, typically 'linux' to indicate Linux error numbers.\n",
    "\torigin: ?string,\n",
    "\t# The Linux error name, i.e. ENOENT, EHWPOISON or similar.\n",
    "\terrnoName: ?string,\n",
    "\t# The numeric Linux error number. Typically the name is preferable, if specified.\n",
    "\terrno: ?int\n",
    ")\n"
);

const SERVICE_INTERFACE: &str = concat!(
    "# General Varlink service interface\ninterface org.varlink.service\n\n",
    "# Get service meta information\nmethod GetInfo() -> (\n",
    "\t# String identifying the vendor of this service\n\tvendor: string,\n",
    "\t# String identifying the product implementing this service\n\tproduct: string,\n",
    "\t# Version string of this product\n\tversion: string,\n",
    "\t# Web URL pointing to additional information about this service\n\turl: string,\n",
    "\t# List of interfaces implemented by this service\n\tinterfaces: []string\n)\n\n",
    "# Get description of an implemented interface in Varlink IDL format\n",
    "method GetInterfaceDescription(\n\t# Name of interface to query interface description of\n",
    "\tinterface: string\n) -> (\n\t# Interface description in Varlink IDL format\n",
    "\tdescription: string\n)\n\n",
    "# Error returned if a method is called on an unknown interface\n",
    "error InterfaceNotFound(\n\t# Name of interface that was called but does not exist\n",
    "\tinterface: string\n)\n\n",
    "# Error returned if an unknown method is called on an known interface\n",
    "error MethodNotFound(\n\t# Name of method that was called but does not exist\n",
    "\tmethod: string\n)\n\n",
    "# Error returned if a method is called that is known but not implemented\n",
    "error MethodNotImplemented(\n\t# Name of method that was called but is not implemented\n",
    "\tmethod: string\n)\n\n",
    "# Error returned if a method is called with an invalid parameter\n",
    "error InvalidParameter(\n\t# Name of the invalid parameter\n\tparameter: string\n)\n\n",
    "# General permission error\nerror PermissionDenied()\n\n",
    "# A method was called with the 'more' flag off, but it may only be called with the flag turned on\n",
    "error ExpectedMore()\n"
);

struct Options {
    kernel: bool,
    pid1: bool,
}

enum ParseResult {
    Run(Options),
    Exit(&'static str),
}

struct MuteContext {
    mute_pid1: bool,
    mute_kernel: bool,
    muted_pid1: bool,
    saved_kernel: Option<u8>,
}

impl MuteContext {
    fn new(mute_pid1: bool, mute_kernel: bool) -> Self {
        Self {
            mute_pid1,
            mute_kernel,
            muted_pid1: false,
            saved_kernel: None,
        }
    }

    fn mute(&mut self) -> Result<(), String> {
        let mut first_error = None;
        if self.mute_pid1 {
            if let Err(error) = set_show_status("no") {
                first_error = Some(error);
            } else {
                self.muted_pid1 = true;
            }
        }
        if self.mute_kernel && !running_in_container() {
            match printk_read() {
                Ok(0) => {}
                Ok(level) => match printk_write(0, false) {
                    Ok(()) => self.saved_kernel = Some(level),
                    Err(error) if first_error.is_none() => first_error = Some(error),
                    Err(_) => {}
                },
                Err(error) if first_error.is_none() => first_error = Some(error),
                Err(_) => {}
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    fn unmute(&mut self) -> Result<(), String> {
        let mut first_error = None;
        if self.muted_pid1 {
            if let Err(error) = set_show_status("") {
                first_error = Some(error);
            } else {
                self.muted_pid1 = false;
            }
        }
        if let Some(saved) = self.saved_kernel {
            if let Err(error) = match printk_read() {
                Ok(0) => match printk_write(saved, true) {
                    Ok(()) => {
                        self.saved_kernel = None;
                        Ok(())
                    }
                    Err(error) => Err(error),
                },
                Ok(_) => Ok(()),
                Err(error) => Err(error),
            } {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

fn main() {
    let arguments: Vec<String> = env::args().skip(1).collect();
    let result = match parse_options(&arguments) {
        Ok(ParseResult::Exit(output)) => io::stdout()
            .lock()
            .write_all(output.as_bytes())
            .map_err(|error| error.to_string()),
        Ok(ParseResult::Run(options)) => run(&options),
        Err(error) => Err(error),
    };
    if let Err(error) = result {
        if !error.is_empty() {
            eprintln!("{error}");
        }
        std::process::exit(1);
    }
}

fn parse_options(arguments: &[String]) -> Result<ParseResult, String> {
    let mut options = Options {
        kernel: true,
        pid1: true,
    };
    let mut index = 0_usize;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "--" {
            break;
        }
        if argument.starts_with("-h") && !argument.starts_with("--") {
            return Ok(ParseResult::Exit(HELP));
        }
        let Some(long) = argument.strip_prefix("--") else {
            if argument.starts_with('-') && argument != "-" {
                return Err(format!(
                    "systemd-mute-console: unrecognized option '-{}'",
                    argument.as_bytes().get(1).copied().map_or('?', char::from)
                ));
            }
            index += 1;
            continue;
        };
        let (spelling, attached) = long
            .split_once('=')
            .map_or((long, None), |(name, value)| (name, Some(value)));
        let name = resolve_long_option(spelling)?;
        match name {
            "help" | "version" => {
                if attached.is_some() {
                    return Err(format!(
                        "systemd-mute-console: option '--{name}' doesn't allow an argument"
                    ));
                }
                return Ok(ParseResult::Exit(if name == "help" {
                    HELP
                } else {
                    VERSION_OUTPUT
                }));
            }
            "kernel" | "pid1" => {
                let value = if let Some(value) = attached {
                    value
                } else {
                    index += 1;
                    arguments.get(index).map(String::as_str).ok_or_else(|| {
                        format!("systemd-mute-console: option '--{name}' requires an argument")
                    })?
                };
                let parsed = parse_boolean(value).ok_or_else(|| {
                    format!("Failed to parse boolean argument to '--{name}=': {value}")
                })?;
                if name == "kernel" {
                    options.kernel = parsed;
                } else {
                    options.pid1 = parsed;
                }
            }
            _ => unreachable!(),
        }
        index += 1;
    }
    Ok(ParseResult::Run(options))
}

fn resolve_long_option(spelling: &str) -> Result<&'static str, String> {
    let all = ["help", "version", "kernel", "pid1"];
    let matches: Vec<&str> = all
        .into_iter()
        .filter(|name| name.starts_with(spelling))
        .collect();
    match matches.as_slice() {
        [name] => Ok(name),
        [] => Err(format!(
            "systemd-mute-console: unrecognized option '--{spelling}'"
        )),
        _ => Err(format!(
            "systemd-mute-console: option '--{spelling}' is ambiguous; possibilities: {}",
            matches
                .iter()
                .map(|name| format!("--{name}"))
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

fn parse_boolean(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "yes" | "y" | "true" | "t" | "on" => Some(true),
        "0" | "no" | "n" | "false" | "f" | "off" => Some(false),
        _ => None,
    }
}

fn run(options: &Options) -> Result<(), String> {
    if varlink_invocation()? {
        return run_varlink_server();
    }
    if !options.kernel && !options.pid1 {
        return Err(String::from("Not asked to mute anything, refusing."));
    }
    install_signal_handlers()?;
    let mut context = MuteContext::new(options.pid1, options.kernel);
    let mute_result = context.mute();
    notify("READY=1\nSTATUS=Console status output muted temporarily.");
    while !termination_requested() {
        thread::sleep(Duration::from_millis(20));
    }
    notify("STOPPING=1\nSTATUS=Console status output unmuted.");
    let unmute_result = context.unmute();
    mute_result.and(unmute_result)
}

fn install_signal_handlers() -> Result<(), String> {
    // SAFETY: installs handlers that only update a process-local sig_atomic_t.
    let result = unsafe { rustd_mute_console_install_signals() };
    if result < 0 {
        return Err(format!(
            "Failed to get default event source: {}",
            errno_text(result)
        ));
    }
    Ok(())
}

fn termination_requested() -> bool {
    // SAFETY: reads the process-local sig_atomic_t flag.
    unsafe { rustd_mute_console_termination_requested() != 0 }
}

fn notify(message: &str) {
    let state = CString::new(message).expect("fixed notification has no NUL");
    // SAFETY: state is a valid NUL-terminated string and no descriptors are passed.
    // Upstream's notify_start()/notify_on_cleanup() deliberately discard errors.
    let _ = unsafe { rustd_notify_send(0, state.as_ptr(), std::ptr::null(), 0) };
}

fn set_show_status(value: &str) -> Result<(), String> {
    if let Some(log) = env::var_os("RUSTD_MUTE_CONSOLE_PID1_LOG") {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log)
            .map_err(|error| format!("Failed to connect to systemd: {error}"))?;
        writeln!(file, "{}", if value.is_empty() { "<empty>" } else { value })
            .map_err(|error| format!("Failed to issue SetShowStatus() method call: {error}"))?;
        return Ok(());
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .map_err(|error| format!("Failed to connect to systemd: {error}"))?;
    runtime.block_on(async {
        let connection = zbus::Connection::system()
            .await
            .map_err(|error| format!("Failed to connect to systemd: {error}"))?;
        let proxy = zbus::Proxy::new(
            &connection,
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
        )
        .await
        .map_err(|error| format!("Failed to connect to systemd: {error}"))?;
        proxy
            .call::<_, _, ()>("SetShowStatus", &(value,))
            .await
            .map_err(|error| format!("Failed to issue SetShowStatus() method call: {error}"))?;
        Ok(())
    })
}

fn printk_path() -> PathBuf {
    env::var_os("RUSTD_MUTE_CONSOLE_PRINTK")
        .map_or_else(|| PathBuf::from("/proc/sys/kernel/printk"), PathBuf::from)
}

fn printk_read() -> Result<u8, String> {
    fs::read_to_string(printk_path())
        .map_err(|error| format!("Failed to read kernel printk() console output level: {error}"))?
        .split_whitespace()
        .next()
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| {
            String::from("Failed to read kernel printk() console output level: Invalid argument")
        })
}

fn printk_write(level: u8, restoring: bool) -> Result<(), String> {
    fs::write(printk_path(), format!("{level}\n")).map_err(|error| {
        if restoring {
            format!("Failed to unmute kernel printk() console output level: {error}")
        } else {
            format!("Failed to change kernel printk() console output level: {error}")
        }
    })
}

fn running_in_container() -> bool {
    if let Some(value) = env::var_os("RUSTD_MUTE_CONSOLE_CONTAINER") {
        return value != "0" && value != "no" && value != "false";
    }
    Path::new("/run/.containerenv").exists()
        || Path::new("/.dockerenv").exists()
        || fs::read_to_string("/run/systemd/container").is_ok_and(|value| !value.trim().is_empty())
        || fs::read("/proc/1/environ").is_ok_and(|value| {
            value
                .split(|byte| *byte == 0)
                .any(|item| item.starts_with(b"container=") && item.len() > 10)
        })
}

fn varlink_invocation() -> Result<bool, String> {
    if env::var_os("SYSTEMD_VARLINK_LISTEN").is_some() {
        return Ok(true);
    }
    let pid_matches = env::var("LISTEN_PID")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        == Some(std::process::id());
    if !pid_matches {
        return Ok(false);
    }
    let fds = env::var("LISTEN_FDS")
        .ok()
        .and_then(|value| value.parse::<u32>().ok());
    if fds.is_none() || fds == Some(0) {
        return Ok(false);
    }
    if fds != Some(1) {
        return Err(String::from(
            "Failed to check if invoked in Varlink mode: Too many references: cannot splice",
        ));
    }
    Ok(env::var("LISTEN_FDNAMES").ok().as_deref() == Some("varlink"))
}

fn run_varlink_server() -> Result<(), String> {
    install_signal_handlers()?;
    if let Some(address) = env::var_os("SYSTEMD_VARLINK_LISTEN") {
        let listener = UnixListener::bind(address)
            .map_err(|error| format!("Failed to run Varlink event loop: {error}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| format!("Failed to run Varlink event loop: {error}"))?;
        loop {
            match listener.accept() {
                Ok((stream, _)) => return serve_varlink(stream),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if termination_requested() {
                        return Ok(());
                    }
                    thread::sleep(Duration::from_millis(20));
                }
                Err(error) => return Err(format!("Failed to run Varlink event loop: {error}")),
            }
        }
    }
    // SAFETY: socket activation transfers ownership of descriptor 3 to this process.
    let accepts = unsafe { rustd_mute_console_socket_accepts(3) };
    if accepts < 0 {
        return Err(format!(
            "Failed to run Varlink event loop: {}",
            errno_text(accepts)
        ));
    }
    if accepts > 0 {
        // SAFETY: descriptor 3 is the single inherited listening UNIX socket.
        let listener = unsafe { UnixListener::from_raw_fd(3) };
        let (stream, _) = listener
            .accept()
            .map_err(|error| format!("Failed to run Varlink event loop: {error}"))?;
        serve_varlink(stream)
    } else {
        // SAFETY: descriptor 3 is the single inherited connected UNIX socket.
        serve_varlink(unsafe { UnixStream::from_raw_fd(3) })
    }
}

fn serve_varlink(mut stream: UnixStream) -> Result<(), String> {
    let mut peer_uid = u32::MAX;
    // SAFETY: output pointer is valid and stream owns an AF_UNIX descriptor.
    let result = unsafe { rustd_mute_console_peer_uid(stream.as_raw_fd(), &mut peer_uid) };
    if result < 0 {
        return Err(format!(
            "Failed to run Varlink event loop: {}",
            errno_text(result)
        ));
    }
    // SAFETY: reads the real UID of this process.
    let own_uid = unsafe { rustd_mute_console_uid() };
    if peer_uid != 0 && peer_uid != own_uid {
        return Ok(());
    }
    let reader = stream
        .try_clone()
        .map_err(|error| format!("Failed to run Varlink event loop: {error}"))?;
    let mut reader = BufReader::new(reader);
    let mut muted = None;
    let service_result = (|| {
        loop {
            let mut request = Vec::new();
            let length = reader
                .read_until(0, &mut request)
                .map_err(|error| format!("Failed to run Varlink event loop: {error}"))?;
            if length == 0 {
                break;
            }
            request.pop();
            let value: Value = if let Ok(value) = serde_json::from_slice(&request) {
                value
            } else {
                write_varlink(
                    &mut stream,
                    &json!({"error":"org.varlink.service.InvalidParameter","parameters":{"parameter":"request"}}),
                )?;
                continue;
            };
            match dispatch_varlink(&value, &mut stream, &mut muted)? {
                Dispatch::Continue => {}
                Dispatch::MutePending => {
                    while !termination_requested() {
                        let mut probe = [0_u8; 1];
                        stream
                            .set_nonblocking(true)
                            .map_err(|error| error.to_string())?;
                        match std::io::Read::read(&mut stream, &mut probe) {
                            Ok(0) => break,
                            Ok(_) => {}
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                                thread::sleep(Duration::from_millis(20));
                            }
                            Err(_) => break,
                        }
                    }
                    break;
                }
            }
        }
        Ok(())
    })();
    let unmute_result = muted.map_or(Ok(()), |mut context| context.unmute());
    service_result.and(unmute_result)
}

enum Dispatch {
    Continue,
    MutePending,
}

fn dispatch_varlink(
    request: &Value,
    stream: &mut UnixStream,
    muted: &mut Option<MuteContext>,
) -> Result<Dispatch, String> {
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    let parameters = request
        .get("parameters")
        .cloned()
        .unwrap_or_else(|| json!({}));
    match method {
        "org.varlink.service.GetInfo" => write_varlink(
            stream,
            &json!({"parameters":{"vendor":"The systemd Project","product":"systemd (systemd-mute-console)","version":"261.2 (261.2-1-arch)","url":"https://systemd.io/","interfaces":["io.systemd","io.systemd.MuteConsole","org.varlink.service"]}}),
        )?,
        "org.varlink.service.GetInterfaceDescription" => {
            let Some(interface) = parameters.get("interface").and_then(Value::as_str) else {
                write_varlink_error(
                    stream,
                    "InvalidParameter",
                    &json!({"parameter":"interface"}),
                )?;
                return Ok(Dispatch::Continue);
            };
            let description = match interface {
                "io.systemd" => IO_SYSTEMD_INTERFACE,
                "io.systemd.MuteConsole" => MUTE_INTERFACE,
                "org.varlink.service" => SERVICE_INTERFACE,
                _ => {
                    write_varlink_error(
                        stream,
                        "InterfaceNotFound",
                        &json!({"interface":interface}),
                    )?;
                    return Ok(Dispatch::Continue);
                }
            };
            write_varlink(stream, &json!({"parameters":{"description":description}}))?;
        }
        "io.systemd.MuteConsole.Mute" => {
            if request.get("more").and_then(Value::as_bool) != Some(true) {
                write_varlink_error(stream, "ExpectedMore", &json!({}))?;
                return Ok(Dispatch::Continue);
            }
            let Some(object) = parameters.as_object() else {
                write_varlink_error(
                    stream,
                    "InvalidParameter",
                    &json!({"parameter":"parameters"}),
                )?;
                return Ok(Dispatch::Continue);
            };
            if let Some(field) = object
                .keys()
                .find(|field| !matches!(field.as_str(), "kernel" | "pid1"))
            {
                write_varlink_error(stream, "InvalidParameter", &json!({"parameter":field}))?;
                return Ok(Dispatch::Continue);
            }
            let Some(kernel) = nullable_bool(object.get("kernel")) else {
                write_varlink_error(stream, "InvalidParameter", &json!({"parameter":"kernel"}))?;
                return Ok(Dispatch::Continue);
            };
            let Some(pid1) = nullable_bool(object.get("pid1")) else {
                write_varlink_error(stream, "InvalidParameter", &json!({"parameter":"pid1"}))?;
                return Ok(Dispatch::Continue);
            };
            let mut context = MuteContext::new(pid1, kernel);
            let mute_result = context.mute();
            *muted = Some(context);
            mute_result?;
            write_varlink(stream, &json!({"continues":true}))?;
            return Ok(Dispatch::MutePending);
        }
        _ if method.starts_with("io.systemd.MuteConsole.")
            || method.starts_with("org.varlink.service.") =>
        {
            write_varlink_error(stream, "MethodNotFound", &json!({"method":method}))?;
        }
        _ => {
            let interface = method
                .rsplit_once('.')
                .map_or(method, |(interface, _)| interface);
            write_varlink_error(stream, "InterfaceNotFound", &json!({"interface":interface}))?;
        }
    }
    Ok(Dispatch::Continue)
}

fn nullable_bool(value: Option<&Value>) -> Option<bool> {
    match value {
        None | Some(Value::Null) => Some(true),
        Some(Value::Bool(value)) => Some(*value),
        Some(_) => None,
    }
}

fn write_varlink_error(
    stream: &mut UnixStream,
    name: &str,
    parameters: &Value,
) -> Result<(), String> {
    let error = format!("org.varlink.service.{name}");
    if parameters
        .as_object()
        .is_some_and(serde_json::Map::is_empty)
    {
        write_varlink(stream, &json!({"error":error}))
    } else {
        write_varlink(stream, &json!({"error":error,"parameters":parameters}))
    }
}

fn write_varlink(stream: &mut UnixStream, value: &Value) -> Result<(), String> {
    serde_json::to_writer(&mut *stream, value).map_err(|error| error.to_string())?;
    stream.write_all(&[0]).map_err(|error| error.to_string())?;
    stream.flush().map_err(|error| error.to_string())
}

fn errno_text(result: i32) -> String {
    let rendered = io::Error::from_raw_os_error(-result).to_string();
    rendered
        .split(" (os error ")
        .next()
        .unwrap_or(&rendered)
        .to_owned()
}
