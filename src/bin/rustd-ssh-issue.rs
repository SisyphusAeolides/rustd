// SPDX-License-Identifier: LGPL-2.1-or-later
//! `systemd-ssh-issue` v261 compatibility utility.
//!
//! Upstream reference: systemd v261 `src/ssh-generator/ssh-issue.c`,
//! `src/ssh-generator/ssh-util.c`, and `src/shared/vsock-util.c`.

use std::env;
use std::ffi::{CStr, OsStr, OsString};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, IsTerminal, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

use rustd::unit::condition::detect_virtualization;

const DEFAULT_ISSUE_PATH: &str = "/run/issue.d/50-ssh-vsock.issue";
const IOCTL_VM_SOCKETS_GET_LOCAL_CID: libc::c_ulong = 0x7b9;
const VMADDR_CID_ANY: u32 = u32::MAX;
const VMADDR_CID_LOCAL: u32 = 1;
const VMADDR_CID_HOST: u32 = 2;

const VERSION_OUTPUT: &[u8] = concat!(
    "systemd 261 (261.2-1-arch)\n",
    "+PAM +AUDIT -SELINUX +APPARMOR -IMA +IPE +SMACK +SECCOMP +GCRYPT +GNUTLS +OPENSSL +ACL ",
    "+BLKID +CURL +ELFUTILS +FIDO2 +IDN2 +KMOD +LIBCRYPTSETUP +LIBCRYPTSETUP_PLUGINS +LIBFDISK ",
    "+PCRE2 +PWQUALITY +P11KIT +QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB +ZSTD +BPF_FRAMEWORK +BTF ",
    "+XKBCOMMON +UTMP +LIBARCHIVE\n"
)
.as_bytes();

const HELP_SUFFIX: &[u8] = concat!(
    " [OPTIONS...] COMMAND\n\n",
    "Create/remove ssh /run/issue.d/ file reporting VSOCK address.\n\n",
    "Commands:\n",
    "  make-vsock           Generate the issue file\n",
    "  rm-vsock             Remove the issue file\n\n",
    "Options:\n",
    "  -h --help            Show this help\n",
    "     --version         Show package version\n",
    "     --issue-path=PATH Change path to /run/issue.d/50-ssh-vsock.issue\n\n",
    "See the systemd-ssh-issue(1) man page for details.\n"
)
.as_bytes();

const LONG_OPTIONS: &[&[u8]] = &[
    b"help",
    b"version",
    b"make-vsock",
    b"rm-vsock",
    b"issue-path",
];

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Verb {
    MakeVsock,
    RemoveVsock,
}

#[derive(Debug, Eq, PartialEq)]
enum IssueTarget {
    Path(PathBuf),
    Stdout,
}

#[derive(Debug, Eq, PartialEq)]
struct Options {
    verb: Verb,
    issue: IssueTarget,
}

#[derive(Debug)]
enum ParseResult {
    Run(Options),
    Exit(Vec<u8>),
}

#[derive(Debug)]
struct Failure {
    message: Vec<u8>,
}

impl Failure {
    fn fixed(message: &'static [u8]) -> Self {
        Self {
            message: message.to_vec(),
        }
    }

    fn bytes(message: Vec<u8>) -> Self {
        Self { message }
    }
}

fn main() {
    initialize_logging();
    let program = program_name();
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    let result = match parse_arguments(&program, &arguments) {
        Ok(ParseResult::Exit(output)) => io::stdout().lock().write_all(&output).map_err(|error| {
            Failure::bytes(
                format!("Failed to write output: {}", concise_io_error(&error)).into_bytes(),
            )
        }),
        Ok(ParseResult::Run(options)) => run(&options),
        Err(error) => Err(error),
    };
    if let Err(error) = result {
        log_error(&error.message);
        std::process::exit(1);
    }
}

fn program_name() -> OsString {
    env::args_os()
        .next()
        .and_then(|argument| PathBuf::from(argument).file_name().map(OsStr::to_owned))
        .unwrap_or_else(|| OsString::from("systemd-ssh-issue"))
}

fn parse_arguments(program: &OsStr, arguments: &[OsString]) -> Result<ParseResult, Failure> {
    let mut positionals = Vec::<OsString>::new();
    let mut issue = None;
    let mut compat_verb = None;
    let mut positional_only = false;
    let mut index = 0;

    while index < arguments.len() {
        let argument = arguments[index].as_os_str().as_bytes();
        if positional_only || argument == b"-" || !argument.starts_with(b"-") {
            positionals.push(arguments[index].clone());
            index += 1;
            continue;
        }
        if argument == b"--" {
            positional_only = true;
            index += 1;
            continue;
        }
        if let Some(long) = argument.strip_prefix(b"--") {
            let (name, attached) = split_long_option(long);
            let option = resolve_long_option(program, name)?;
            match option {
                b"help" => {
                    reject_attached_argument(program, name, attached)?;
                    return Ok(ParseResult::Exit(help_output(program)));
                }
                b"version" => {
                    reject_attached_argument(program, name, attached)?;
                    return Ok(ParseResult::Exit(VERSION_OUTPUT.to_vec()));
                }
                b"make-vsock" => {
                    reject_attached_argument(program, name, attached)?;
                    compat_verb = Some(Verb::MakeVsock);
                }
                b"rm-vsock" => {
                    reject_attached_argument(program, name, attached)?;
                    compat_verb = Some(Verb::RemoveVsock);
                }
                b"issue-path" => {
                    let value = if let Some(value) = attached {
                        OsString::from_vec(value.to_vec())
                    } else {
                        index += 1;
                        let Some(value) = arguments.get(index) else {
                            return Err(option_error(
                                program,
                                b"option '--",
                                name,
                                b"' requires an argument",
                            ));
                        };
                        value.clone()
                    };
                    issue = Some(parse_issue_target(value)?);
                }
                _ => unreachable!("complete long-option match"),
            }
            index += 1;
            continue;
        }

        let short = argument[1];
        if short == b'h' {
            return Ok(ParseResult::Exit(help_output(program)));
        }
        return Err(option_error(
            program,
            b"unrecognized option '-",
            &[short],
            b"'",
        ));
    }

    let verb = if let Some(verb) = compat_verb {
        if !positionals.is_empty() {
            return Err(Failure::fixed(
                b"Invalid use of compat option --make-vsock/--rm-vsock.",
            ));
        }
        log_warning(
            b"Options --make-vsock/--rm-vsock have been replaced by make-vsock/rm-vsock verbs.",
        );
        verb
    } else {
        dispatch_verb(&positionals)?
    };

    Ok(ParseResult::Run(Options {
        verb,
        issue: issue.unwrap_or_else(|| IssueTarget::Path(PathBuf::from(DEFAULT_ISSUE_PATH))),
    }))
}

fn split_long_option(long: &[u8]) -> (&[u8], Option<&[u8]>) {
    long.iter()
        .position(|byte| *byte == b'=')
        .map_or((long, None), |position| {
            (&long[..position], Some(&long[position + 1..]))
        })
}

fn resolve_long_option(program: &OsStr, name: &[u8]) -> Result<&'static [u8], Failure> {
    if let Some(exact) = LONG_OPTIONS.iter().copied().find(|option| *option == name) {
        return Ok(exact);
    }
    let matches = LONG_OPTIONS
        .iter()
        .copied()
        .filter(|option| option.starts_with(name))
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [single] => Ok(*single),
        [] => Err(option_error(
            program,
            b"unrecognized option '--",
            name,
            b"'",
        )),
        _ => {
            let mut message = prefixed(program, b": option '--");
            message.extend_from_slice(name);
            message.extend_from_slice(b"' is ambiguous; possibilities:");
            for (index, option) in matches.into_iter().enumerate() {
                if index > 0 {
                    message.extend_from_slice(b",");
                }
                message.extend_from_slice(b" --");
                message.extend_from_slice(option);
            }
            Err(Failure::bytes(message))
        }
    }
}

fn reject_attached_argument(
    program: &OsStr,
    name: &[u8],
    attached: Option<&[u8]>,
) -> Result<(), Failure> {
    if attached.is_none() {
        return Ok(());
    }
    Err(option_error(
        program,
        b"option '--",
        name,
        b"' doesn't allow an argument",
    ))
}

fn option_error(program: &OsStr, before: &[u8], value: &[u8], after: &[u8]) -> Failure {
    let mut message = prefixed(program, b": ");
    message.extend_from_slice(before);
    message.extend_from_slice(value);
    message.extend_from_slice(after);
    Failure::bytes(message)
}

fn prefixed(program: &OsStr, suffix: &[u8]) -> Vec<u8> {
    let mut message = program.as_bytes().to_vec();
    message.extend_from_slice(suffix);
    message
}

fn parse_issue_target(value: OsString) -> Result<IssueTarget, Failure> {
    if value.is_empty() || value.as_os_str().as_bytes() == b"-" {
        return Ok(IssueTarget::Stdout);
    }
    let path = PathBuf::from(value);
    let absolute = if path.is_absolute() {
        path
    } else {
        env::current_dir()
            .map_err(|error| {
                Failure::bytes(
                    format!(
                        "Failed to make issue path absolute: {}",
                        concise_io_error(&error)
                    )
                    .into_bytes(),
                )
            })?
            .join(path)
    };
    Ok(IssueTarget::Path(simplify_path(&absolute)))
}

fn simplify_path(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::RootDir => result.push(Path::new("/")),
            Component::ParentDir => result.push(".."),
            Component::Normal(value) => result.push(value),
            Component::Prefix(_) => unreachable!("Unix paths have no prefix component"),
        }
    }
    result
}

fn dispatch_verb(arguments: &[OsString]) -> Result<Verb, Failure> {
    let Some(name) = arguments.first() else {
        return Err(Failure::fixed(
            b"Command verb required (one of make-vsock, rm-vsock).",
        ));
    };
    let name_bytes = name.as_os_str().as_bytes();
    let verb = match name_bytes {
        b"make-vsock" => Verb::MakeVsock,
        b"rm-vsock" => Verb::RemoveVsock,
        _ => return Err(unknown_verb(name_bytes)),
    };
    if arguments.len() > 1 {
        return Err(Failure::fixed(b"Too many arguments."));
    }
    Ok(verb)
}

fn unknown_verb(name: &[u8]) -> Failure {
    let suggestion = closest_verb(name);
    let mut message = b"Unknown command verb '".to_vec();
    message.extend_from_slice(name);
    if let Some(suggestion) = suggestion {
        message.extend_from_slice(b"', did you mean '");
        message.extend_from_slice(suggestion);
        message.extend_from_slice(b"'?");
    } else {
        message.extend_from_slice(b"'.");
    }
    Failure::bytes(message)
}

fn closest_verb(name: &[u8]) -> Option<&'static [u8]> {
    const VERBS: &[&[u8]] = &[b"make-vsock", b"rm-vsock"];
    let mut prefix = None;
    let mut prefix_distance = usize::MAX;
    for verb in VERBS {
        if verb.starts_with(name) && verb.len() - name.len() < prefix_distance {
            prefix = Some(*verb);
            prefix_distance = verb.len() - name.len();
        }
    }
    if prefix.is_some() {
        return prefix;
    }
    VERBS
        .iter()
        .copied()
        .filter_map(|verb| {
            let distance = levenshtein(verb, name);
            (distance <= 5).then_some((distance, verb))
        })
        .min_by_key(|(distance, _)| *distance)
        .map(|(_, verb)| verb)
}

fn levenshtein(left: &[u8], right: &[u8]) -> usize {
    let mut previous = (0..=right.len()).collect::<Vec<_>>();
    let mut current = vec![0; right.len() + 1];
    for (left_index, left_byte) in left.iter().enumerate() {
        current[0] = left_index + 1;
        for (right_index, right_byte) in right.iter().enumerate() {
            current[right_index + 1] = (previous[right_index + 1] + 1)
                .min(current[right_index] + 1)
                .min(previous[right_index] + usize::from(left_byte != right_byte));
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous[right.len()]
}

fn run(options: &Options) -> Result<(), Failure> {
    match options.verb {
        Verb::MakeVsock => make_vsock(&options.issue),
        Verb::RemoveVsock => remove_vsock(&options.issue),
    }
}

fn make_vsock(issue: &IssueTarget) -> Result<(), Failure> {
    let Some(cid) = acquire_cid()? else {
        log_debug(b"Not running in a VSOCK enabled VM, skipping.");
        return Ok(());
    };
    write_issue(issue, cid)
}

fn acquire_cid() -> Result<Option<u32>, Failure> {
    let virtualization = detect_virtualization();
    if !is_vm_virtualization(&virtualization) {
        log_debug(b"Not running in a VM, not creating issue file.");
        return Ok(None);
    }

    // SAFETY: socket has no pointer arguments and returns a new descriptor.
    let socket = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if socket < 0 {
        let errno = last_errno();
        if matches!(
            errno,
            libc::EAFNOSUPPORT | libc::EPROTONOSUPPORT | libc::ESOCKTNOSUPPORT | libc::EPFNOSUPPORT
        ) {
            return Ok(None);
        }
        return Err(errno_failure(
            b"Unable to test if AF_VSOCK is available: ",
            errno,
        ));
    }
    // SAFETY: socket is a fresh owned descriptor after the successful call above.
    let _socket = unsafe { OwnedFd::from_raw_fd(socket) };

    let device = match OpenOptions::new().read(true).open("/dev/vsock") {
        Ok(device) => device,
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(libc::ENOENT | libc::ENODEV | libc::ENXIO)
            ) =>
        {
            return Ok(None)
        }
        Err(error) => return Err(io_failure(b"Failed to query host's AF_VSOCK CID: ", &error)),
    };
    let mut cid = 0_u32;
    // SAFETY: the request writes one u32 to the valid pointer and the descriptor is open.
    if unsafe { libc::ioctl(device.as_raw_fd(), IOCTL_VM_SOCKETS_GET_LOCAL_CID, &mut cid) } < 0 {
        let errno = last_errno();
        if matches!(
            errno,
            libc::ENOENT | libc::ENODEV | libc::ENXIO | libc::EADDRNOTAVAIL
        ) {
            return Ok(None);
        }
        return Err(errno_failure(
            b"Failed to query host's AF_VSOCK CID: ",
            errno,
        ));
    }
    if matches!(cid, VMADDR_CID_LOCAL | VMADDR_CID_HOST | VMADDR_CID_ANY) {
        return Ok(None);
    }
    Ok(Some(cid))
}

fn is_vm_virtualization(value: &str) -> bool {
    !matches!(
        value,
        "none"
            | "systemd-nspawn"
            | "lxc-libvirt"
            | "lxc"
            | "openvz"
            | "docker"
            | "podman"
            | "rkt"
            | "wsl"
            | "proot"
            | "pouch"
            | "container"
            | "container-other"
    )
}

fn write_issue(issue: &IssueTarget, cid: u32) -> Result<(), Failure> {
    let contents =
        format!("Try contacting this VM's SSH server via 'ssh vsock%{cid}' from host.\n\n");
    match issue {
        IssueTarget::Stdout => io::stdout()
            .lock()
            .write_all(contents.as_bytes())
            .map_err(|error| io_failure(b"Failed to write issue file: ", &error)),
        IssueTarget::Path(path) => write_issue_file(path, contents.as_bytes()),
    }
}

fn write_issue_file(path: &Path, contents: &[u8]) -> Result<(), Failure> {
    let parent = path.parent().unwrap_or_else(|| Path::new("/"));
    DirBuilder::new()
        .recursive(true)
        .mode(0o755)
        .create(parent)
        .map_err(|error| {
            path_failure(
                b"Failed to create parent directories of '",
                path,
                b"': ",
                &error,
            )
        })?;

    let (temporary, mut file) = create_temporary(parent)
        .map_err(|error| path_failure(b"Failed to create '", path, b"': ", &error))?;
    let mut guard = TemporaryPath::new(temporary);
    file.write_all(contents)
        .and_then(|()| file.flush())
        .map_err(|error| path_failure(b"Failed to write '", path, b"': ", &error))?;
    file.set_permissions(fs::Permissions::from_mode(0o644))
        .map_err(|error| {
            path_failure(b"Failed to adjust access mode of '", path, b"': ", &error)
        })?;
    drop(file);
    fs::rename(guard.path(), path)
        .map_err(|error| path_failure(b"Failed to move issue file into '", path, b"': ", &error))?;
    guard.disarm();
    Ok(())
}

fn create_temporary(parent: &Path) -> io::Result<(PathBuf, File)> {
    for _ in 0..128 {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!(
            ".#systemd-ssh-issue-{}-{sequence}",
            std::process::id()
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::from_raw_os_error(libc::EEXIST))
}

struct TemporaryPath {
    path: Option<PathBuf>,
}

impl TemporaryPath {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn path(&self) -> &Path {
        self.path.as_deref().expect("temporary path is armed")
    }

    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for TemporaryPath {
    fn drop(&mut self) {
        if let Some(path) = self.path.as_deref() {
            let _ = fs::remove_file(path);
        }
    }
}

fn remove_vsock(issue: &IssueTarget) -> Result<(), Failure> {
    let IssueTarget::Path(path) = issue else {
        log_notice(b"STDOUT selected for issue file, not removing.");
        return Ok(());
    };
    match fs::remove_file(path) {
        Ok(()) => {
            let mut message = b"Successfully removed '".to_vec();
            message.extend_from_slice(path.as_os_str().as_bytes());
            message.extend_from_slice(b"'.");
            log_debug(&message);
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut message = b"File '".to_vec();
            message.extend_from_slice(path.as_os_str().as_bytes());
            message.extend_from_slice(b"' does not exist, no operation executed.");
            log_debug(&message);
            Ok(())
        }
        Err(error) => Err(path_failure(b"Failed to remove '", path, b"': ", &error)),
    }
}

fn path_failure(before: &[u8], path: &Path, after: &[u8], error: &io::Error) -> Failure {
    let mut message = before.to_vec();
    message.extend_from_slice(path.as_os_str().as_bytes());
    message.extend_from_slice(after);
    message.extend_from_slice(io_error_text(error).as_bytes());
    Failure::bytes(message)
}

fn io_failure(prefix: &[u8], error: &io::Error) -> Failure {
    let mut message = prefix.to_vec();
    message.extend_from_slice(io_error_text(error).as_bytes());
    Failure::bytes(message)
}

fn errno_failure(prefix: &[u8], errno: libc::c_int) -> Failure {
    let mut message = prefix.to_vec();
    message.extend_from_slice(errno_text(errno).as_bytes());
    Failure::bytes(message)
}

fn io_error_text(error: &io::Error) -> String {
    error
        .raw_os_error()
        .map_or_else(|| concise_io_error(error), errno_text)
}

fn concise_io_error(error: &io::Error) -> String {
    let rendered = error.to_string();
    rendered
        .split(" (os error ")
        .next()
        .unwrap_or(&rendered)
        .to_owned()
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

fn help_output(program: &OsStr) -> Vec<u8> {
    let mut output = program.as_bytes().to_vec();
    output.extend_from_slice(HELP_SUFFIX);
    let colors = colors_enabled();
    let urlify = environment_boolean("SYSTEMD_URLIFY", false).unwrap_or(colors);
    if colors {
        decorate_help_fragment(
            &mut output,
            b"Create/remove ssh /run/issue.d/ file reporting VSOCK address.",
            b"\x1b[0;1;39m",
            b"\x1b[0m",
        );
        for heading in [b"Commands:".as_slice(), b"Options:".as_slice()] {
            decorate_help_fragment(&mut output, heading, b"\x1b[0;4m", b"\x1b[0m");
        }
    }
    if urlify {
        decorate_help_fragment(
            &mut output,
            b"systemd-ssh-issue(1) man page",
            b"\x1b]8;;man:systemd-ssh-issue(1)\x1b\\",
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
    io::stdout().is_terminal() && env::var_os("TERM").as_deref() != Some(OsStr::new("dumb"))
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

#[derive(Clone, Copy, Eq, PartialEq)]
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
        Some("kmsg") => {
            if OpenOptions::new().write(true).open("/dev/kmsg").is_ok() {
                LogTarget::Kmsg
            } else {
                LogTarget::Console
            }
        }
        Some("null") => LogTarget::Null,
        Some("journal" | "journal-or-kmsg" | "syslog" | "syslog-or-kmsg") => LogTarget::Other,
        Some(value) => {
            let _ = writeln!(
                io::stderr().lock(),
                "Failed to parse log target '{value}', ignoring."
            );
            LogTarget::Console
        }
    })
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
    for word in value.split(',') {
        if let Some((target, level)) = word.split_once(':') {
            let Some(level) = parse_log_level(level) else {
                warn_invalid_log_level(&value);
                return global.min(target_maximum);
            };
            if !matches!(
                target,
                "console"
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
            if log_filter_applies(target) {
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

fn log_filter_applies(filter: &str) -> bool {
    match log_target() {
        LogTarget::Console => matches!(filter, "auto" | "console"),
        LogTarget::ConsolePrefixed => matches!(filter, "console" | "console-prefixed"),
        LogTarget::Kmsg => filter == "kmsg",
        LogTarget::Null => filter == "null",
        LogTarget::Other => matches!(
            (env::var("SYSTEMD_LOG_TARGET").ok().as_deref(), filter),
            (Some("journal"), "journal")
                | (Some("journal-or-kmsg"), "journal-or-kmsg")
                | (Some("syslog"), "syslog")
                | (Some("syslog-or-kmsg"), "syslog-or-kmsg")
        ),
    }
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
    let message = format!("Failed to parse log level '{value}', ignoring: Invalid argument");
    match log_target() {
        LogTarget::Null => {}
        LogTarget::Other => {
            let _ = writeln!(io::stderr().lock(), "{message}");
        }
        _ => write_log(message.as_bytes(), 4),
    }
}

fn log_debug(message: &[u8]) {
    if log_level() >= 7 {
        write_log(message, 7);
    }
}

fn log_notice(message: &[u8]) {
    if log_level() >= 5 {
        write_log(message, 5);
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

fn write_log(message: &[u8], priority: u8) {
    let target = log_target();
    if matches!(target, LogTarget::Null | LogTarget::Other) {
        return;
    }
    if target == LogTarget::Kmsg && write_kmsg(message, priority) {
        return;
    }
    let mut stderr = io::stderr().lock();
    if target == LogTarget::ConsolePrefixed {
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
        "<{}>systemd-ssh-issue[{}]: ",
        24 + priority,
        std::process::id()
    )
    .and_then(|()| kmsg.write_all(message))
    .and_then(|()| kmsg.write_all(b"\n"))
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_compatibility_options_and_paths() {
        let program = OsStr::new("systemd-ssh-issue");
        let parsed = parse_arguments(
            program,
            &[
                OsString::from("--issue-path=-"),
                OsString::from("--make-vsock"),
            ],
        )
        .expect("parse compatibility option");
        let ParseResult::Run(options) = parsed else {
            panic!("expected run result");
        };
        assert_eq!(options.verb, Verb::MakeVsock);
        assert_eq!(options.issue, IssueTarget::Stdout);
    }

    #[test]
    fn closest_verbs_match_upstream_threshold() {
        assert_eq!(closest_verb(b""), Some(b"rm-vsock".as_slice()));
        assert_eq!(closest_verb(b"make-vsoc"), Some(b"make-vsock".as_slice()));
        assert_eq!(closest_verb(b"x"), None);
    }

    #[test]
    fn issue_file_is_atomic_and_replaces_a_symlink() {
        let fixture = tempfile::tempdir().expect("create issue fixture");
        let path = fixture.path().join("nested/issue");
        let outside = fixture.path().join("outside");
        fs::write(&outside, b"outside").expect("write symlink target");
        fs::create_dir(path.parent().expect("issue parent")).expect("create issue parent");
        std::os::unix::fs::symlink(&outside, &path).expect("create issue symlink");
        write_issue(&IssueTarget::Path(path.clone()), 42).expect("write issue file");
        assert_eq!(fs::read(&outside).expect("read target"), b"outside");
        assert_eq!(
            fs::read(&path).expect("read issue"),
            b"Try contacting this VM's SSH server via 'ssh vsock%42' from host.\n\n"
        );
        assert_eq!(
            fs::metadata(&path)
                .expect("stat issue")
                .permissions()
                .mode()
                & 0o7777,
            0o644
        );
    }

    #[test]
    fn container_names_are_not_vms() {
        for value in [
            "none",
            "docker",
            "podman",
            "systemd-nspawn",
            "container-other",
        ] {
            assert!(!is_vm_virtualization(value));
        }
        for value in ["kvm", "qemu", "vmware", "microsoft", "vm-other"] {
            assert!(is_vm_virtualization(value));
        }
    }
}
