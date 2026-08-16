// SPDX-License-Identifier: LGPL-2.1-or-later
//! `systemd-cgls` v261 compatibility utility.

use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

const HELP: &str = concat!(
    "systemd-cgls [OPTIONS...] [CGROUP...]\n\n",
    "Recursively show control group contents.\n\n",
    "  -h --help              Show this help\n",
    "     --version           Show package version\n",
    "     --no-pager          Do not start a pager\n",
    "  -a --all               Show all groups, including empty\n",
    "  -u --unit[=UNIT]       Show the subtrees of specified system units\n",
    "     --user-unit[=UNIT]  Show the subtrees of specified user units\n",
    "     --xattr[=BOOL]      Show cgroup extended attributes\n",
    "  -x                     Same as --xattr=true\n",
    "     --cgroup-id[=BOOL]  Show cgroup ID\n",
    "  -c                     Same as --cgroup-id=true\n",
    "  -l --full              Do not ellipsize output\n",
    "  -k                     Include kernel threads in output\n",
    "  -M --machine=CONTAINER Operate on local container\n\n",
    "See the systemd-cgls(1) man page for details.\n"
);
const VERSION: &str = concat!(
    "systemd 261 (261.2-1-arch)\n",
    "+PAM +AUDIT -SELINUX +APPARMOR -IMA +IPE +SMACK +SECCOMP +GCRYPT +GNUTLS +OPENSSL +ACL ",
    "+BLKID +CURL +ELFUTILS +FIDO2 +IDN2 +KMOD +LIBCRYPTSETUP +LIBCRYPTSETUP_PLUGINS +LIBFDISK ",
    "+PCRE2 +PWQUALITY +P11KIT +QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB +ZSTD +BPF_FRAMEWORK +BTF ",
    "+XKBCOMMON +UTMP +LIBARCHIVE\n"
);

#[derive(Clone, Copy, Eq, PartialEq)]
enum UnitMode {
    None,
    System,
    User,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ColorMode {
    Off,
    Basic,
    Extended,
    Rich,
}

#[allow(clippy::struct_excessive_bools)] // Each switch independently mirrors one v261 output flag.
struct Options {
    all: bool,
    full: bool,
    kernel_threads: bool,
    xattrs: bool,
    cgroup_id: bool,
    no_pager: bool,
    unit_mode: UnitMode,
    machine: Option<OsString>,
    names: Vec<OsString>,
}

enum ParseResult {
    Run(Options),
    Exit(&'static str),
}

fn main() {
    let arguments: Vec<OsString> = env::args_os().skip(1).collect();
    let result = match parse_options(&arguments) {
        Ok(ParseResult::Exit(output)) => io::stdout()
            .lock()
            .write_all(output.as_bytes())
            .map_err(|error| error.to_string().into_bytes()),
        Ok(ParseResult::Run(options)) => run(&options).map_err(String::into_bytes),
        Err(error) => Err(error),
    };
    match result {
        Ok(()) => {}
        Err(error) => {
            let mut stderr = io::stderr().lock();
            let _ = stderr.write_all(&error);
            let _ = stderr.write_all(b"\n");
            std::process::exit(1);
        }
    }
}

#[allow(clippy::too_many_lines)] // Keep the v261 option table and ordering auditable in one place.
fn parse_options(arguments: &[OsString]) -> Result<ParseResult, Vec<u8>> {
    let mut options = Options {
        all: false,
        full: false,
        kernel_threads: false,
        xattrs: false,
        cgroup_id: false,
        no_pager: false,
        unit_mode: UnitMode::None,
        machine: None,
        names: Vec::new(),
    };
    let mut positional = false;
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_os_str().as_bytes();
        if positional || argument == b"-" || !argument.starts_with(b"-") {
            options.names.push(arguments[index].clone());
            index += 1;
            continue;
        }
        if argument == b"--" {
            positional = true;
            index += 1;
            continue;
        }
        if let Some(long) = argument.strip_prefix(b"--") {
            let (name, value) = split_once(long, b'=');
            let canonical = resolve_long(name)?;
            match canonical {
                "help" => return Ok(ParseResult::Exit(HELP)),
                "version" => return Ok(ParseResult::Exit(VERSION)),
                "no-pager" => reject_value(canonical, value, || options.no_pager = true)
                    .map_err(String::into_bytes)?,
                "all" => reject_value(canonical, value, || options.all = true)
                    .map_err(String::into_bytes)?,
                "full" => reject_value(canonical, value, || options.full = true)
                    .map_err(String::into_bytes)?,
                "unit" => {
                    select_unit_mode(&mut options, UnitMode::System).map_err(String::into_bytes)?;
                    if let Some(value) = value {
                        options.names.push(OsString::from_vec(value.to_vec()));
                    }
                }
                "user-unit" => {
                    select_unit_mode(&mut options, UnitMode::User).map_err(String::into_bytes)?;
                    if let Some(value) = value {
                        options.names.push(OsString::from_vec(value.to_vec()));
                    }
                }
                "xattr" => {
                    options.xattrs = value
                        .map_or(Ok(true), |value| {
                            parse_boolean(value).map_err(|_| {
                                format!(
                                    "Failed to parse --xattr= value: {}",
                                    String::from_utf8_lossy(value)
                                )
                            })
                        })
                        .map_err(String::into_bytes)?;
                }
                "cgroup-id" => {
                    options.cgroup_id = value
                        .map_or(Ok(true), |value| {
                            parse_boolean(value).map_err(|_| {
                                format!(
                                    "Failed to parse --cgroup-id= value: {}",
                                    String::from_utf8_lossy(value)
                                )
                            })
                        })
                        .map_err(String::into_bytes)?;
                }
                "machine" => {
                    let value = value.ok_or_else(|| {
                        b"systemd-cgls: option '--machine' requires an argument".to_vec()
                    })?;
                    options.machine = Some(OsString::from_vec(value.to_vec()));
                }
                _ => unreachable!(),
            }
            index += 1;
            continue;
        }
        let mut offset = 1;
        while offset < argument.len() {
            match argument[offset] {
                b'h' => return Ok(ParseResult::Exit(HELP)),
                b'a' => options.all = true,
                b'l' => options.full = true,
                b'k' => options.kernel_threads = true,
                b'x' => options.xattrs = true,
                b'c' => options.cgroup_id = true,
                b'u' => {
                    select_unit_mode(&mut options, UnitMode::System).map_err(String::into_bytes)?;
                    if offset + 1 < argument.len() {
                        options
                            .names
                            .push(OsString::from_vec(argument[offset + 1..].to_vec()));
                    }
                    break;
                }
                b'M' => {
                    let value = if offset + 1 < argument.len() {
                        argument[offset + 1..].to_vec()
                    } else {
                        index += 1;
                        arguments
                            .get(index)
                            .ok_or_else(|| {
                                b"systemd-cgls: option '-M' requires an argument".to_vec()
                            })?
                            .as_os_str()
                            .as_bytes()
                            .to_vec()
                    };
                    options.machine = Some(OsString::from_vec(value));
                    break;
                }
                option => {
                    let mut error = b"systemd-cgls: unrecognized option '-".to_vec();
                    error.push(option);
                    error.push(b'\'');
                    return Err(error);
                }
            }
            offset += 1;
        }
        index += 1;
    }
    if options.machine.is_some() && options.unit_mode != UnitMode::None {
        return Err(b"Cannot combine --unit or --user-unit with --machine=.".to_vec());
    }
    Ok(ParseResult::Run(options))
}

fn run(options: &Options) -> Result<(), String> {
    let renderer = Renderer::new(options);
    let mut output = Vec::new();
    let result = run_into(options, &renderer, &mut output);
    emit_output(options, &output)?;
    result
}

fn run_into(
    options: &Options,
    renderer: &Renderer<'_>,
    output: &mut impl Write,
) -> Result<(), String> {
    let names = if options.names.is_empty() {
        None
    } else {
        Some(options.names.as_slice())
    };
    if let Some(names) = names {
        let mut first_error = None;
        for name in names {
            let result = renderer.show_argument(name, output);
            if first_error.is_none() {
                first_error = result.err();
            }
        }
        if let Some(error) = first_error {
            return Err(tree_error(&error));
        }
        return Ok(());
    }

    let cwd = env::current_dir()
        .map_err(|error| format!("Cannot determine current working directory: {error}"))?;
    if cwd.starts_with("/sys/fs/cgroup") {
        writeln!(output, "Working directory {}:", cwd.display())
            .map_err(|error| error.to_string())?;
        return renderer
            .show_path(&renderer.map_physical_path(&cwd), b"", output)
            .map_err(|error| format!("Failed to list cgroup tree: {error}"));
    }

    let root = renderer.root_cgroup()?;
    write_bytes(output, b"CGroup ")?;
    write_bytes(output, display_logical(&root))?;
    write_bytes(output, b":\n-.slice\n")?;
    renderer
        .show_path(&renderer.logical_path(&root), b"", output)
        .map_err(|error| format!("Failed to list cgroup tree: {error}"))
}

struct Renderer<'a> {
    options: &'a Options,
    cgroup_root: PathBuf,
    columns: usize,
    utf8: bool,
    color: ColorMode,
    full: bool,
}

impl<'a> Renderer<'a> {
    fn new(options: &'a Options) -> Self {
        let cgroup_root = env::var_os("RUSTD_CGROUP_ROOT")
            .map_or_else(|| PathBuf::from("/sys/fs/cgroup"), PathBuf::from);
        let columns = env::var("COLUMNS")
            .ok()
            .and_then(|value| value.parse().ok())
            .filter(|value| *value > 0)
            .unwrap_or(80);
        let utf8 = env::var("LC_ALL")
            .or_else(|_| env::var("LC_CTYPE"))
            .or_else(|_| env::var("LANG"))
            .map_or(true, |locale| !matches!(locale.as_str(), "C" | "POSIX"));
        let color = color_mode();
        Self {
            options,
            cgroup_root,
            columns,
            utf8,
            color,
            full: options.full || pager_wanted(options),
        }
    }

    fn show_argument(&self, name: &OsStr, output: &mut impl Write) -> Result<(), String> {
        if self.options.unit_mode != UnitMode::None {
            return self.show_unit(name, output);
        }
        let bytes = name.as_bytes();
        if bytes.starts_with(b"/sys/fs/cgroup")
            && (bytes.len() == 14 || bytes.get(14) == Some(&b'/'))
        {
            write_bytes(output, b"Directory ")?;
            write_bytes(output, bytes)?;
            write_bytes(output, b":\n")?;
            return self.show_path(&self.map_physical_path(Path::new(name)), b"", output);
        }
        let (controller, path) = split_cgroup_spec(bytes).map_err(|_| {
            let mut message = b"@logged@Failed to split argument ".to_vec();
            message.extend_from_slice(bytes);
            message.extend_from_slice(b": Invalid argument\nInvalid argument");
            String::from_utf8_lossy(&message).into_owned()
        })?;
        if let Some(controller) = controller {
            if controller != b"name=systemd" {
                let mut message = b"Legacy cgroup v1 controller '".to_vec();
                message.extend_from_slice(controller);
                message.extend_from_slice(b"' was specified, ignoring.");
                log_bytes(&message);
            }
        }
        let root = self.root_cgroup()?;
        let logical = path.map_or(root.clone(), |path| join_logical(&root, path));
        write_bytes(output, b"CGroup ")?;
        write_bytes(output, display_logical(&logical))?;
        write_bytes(output, b":\n")?;
        self.show_path(&self.logical_path(&logical), b"", output)
    }

    fn show_unit(&self, name: &OsStr, output: &mut impl Write) -> Result<(), String> {
        let unit = mangle_unit_name(name)?;
        let cgroup = query_unit_cgroup(&unit, self.options.unit_mode).map_err(|error| {
            if error.contains("NoSuchUnit") {
                format!("@logged@Unit {unit} not found.\nNo such file or directory")
            } else {
                error
            }
        })?;
        if cgroup.is_empty() {
            return Err(format!(
                "@logged@Unit {unit} not found.\nNo such file or directory"
            ));
        }
        writeln!(output, "Unit {unit} ({cgroup}):").map_err(|error| error.to_string())?;
        self.show_path(&self.logical_path(Path::new(&cgroup)), b"", output)
    }

    fn show_path(&self, path: &Path, prefix: &[u8], output: &mut impl Write) -> Result<(), String> {
        let directory = fs::read_dir(path).map_err(io_error_text)?;
        let mut children = Vec::new();
        for entry in directory {
            let entry = entry.map_err(io_error_text)?;
            if entry.file_type().map_err(io_error_text)?.is_dir()
                && (self.options.all || !Self::cgroup_is_empty(&entry.path()))
            {
                children.push(entry.path());
            }
        }
        self.show_pids(path, prefix, !children.is_empty(), output)?;
        let child_count = children.len();
        for (index, child) in children.into_iter().enumerate() {
            let more = index + 1 < child_count;
            self.show_group_name(&child, prefix, more, output)?;
            let mut child_prefix = prefix.to_vec();
            child_prefix.extend_from_slice(if more {
                self.glyph("│ ", "| ")
            } else {
                b"  "
            });
            let _ = self.show_path(&child, &child_prefix, output);
        }
        Ok(())
    }

    fn show_pids(
        &self,
        path: &Path,
        prefix: &[u8],
        more: bool,
        output: &mut impl Write,
    ) -> Result<(), String> {
        let file = match File::open(path.join("cgroup.procs")) {
            Ok(file) => file,
            Err(error) => return Err(io_error_text(error)),
        };
        let mut pids = Vec::new();
        for line in BufReader::new(file).lines() {
            let line = line.map_err(io_error_text)?;
            let pid = line
                .trim()
                .parse::<u32>()
                .map_err(|_| String::from("Input/output error"))?;
            if pid != 0 && (self.options.kernel_threads || !is_kernel_thread(pid)) {
                pids.push(pid);
            }
        }
        pids.sort_unstable();
        pids.dedup();
        let width = pids.last().map_or(1, |pid| pid.to_string().len());
        let command_width = if self.full {
            usize::MAX
        } else {
            // Account for prefix, glyph (2 cols), pid width, space
            let prefix_width = prefix.len();
            let glyph_width = 2;
            let needed = prefix_width + glyph_width + width + 1;
            if self.columns > needed {
                self.columns - needed
            } else {
                20
            }
        };
        let count = pids.len();
        for (index, pid) in pids.into_iter().enumerate() {
            write_bytes(output, prefix)?;
            write_bytes(
                output,
                self.glyph(
                    if more || index + 1 < count {
                        "├─"
                    } else {
                        "└─"
                    },
                    if more || index + 1 < count {
                        "|-"
                    } else {
                        "`-"
                    },
                ),
            )?;
            if self.color != ColorMode::Off {
                write_bytes(output, grey_code(self.color))?;
            }
            write!(output, "{pid:>width$} ").map_err(|error| error.to_string())?;
            let command = process_command(pid, command_width, self.utf8);
            write_bytes(output, &command)?;
            if self.color != ColorMode::Off {
                write_bytes(output, b"\x1b[0m")?;
            }
            write_bytes(output, b"\n")?;
        }
        Ok(())
    }

    fn show_group_name(
        &self,
        path: &Path,
        prefix: &[u8],
        more: bool,
        output: &mut impl Write,
    ) -> Result<(), String> {
        let file = File::open(path).map_err(io_error_text)?;
        let delegated = delegated(file.as_raw_fd());
        write_bytes(output, prefix)?;
        write_bytes(
            output,
            self.glyph(
                if more { "├─" } else { "└─" },
                if more { "|-" } else { "`-" },
            ),
        )?;
        let name = path.file_name().unwrap_or_default().as_bytes();
        if delegated && self.color != ColorMode::Off {
            write_bytes(output, b"\x1b[0;4m")?;
        }
        write_bytes(output, name.strip_prefix(b"_").unwrap_or(name))?;
        if delegated && self.color != ColorMode::Off {
            write_bytes(output, b"\x1b[0m")?;
        }
        if delegated {
            write_bytes(output, b" ")?;
            if self.color != ColorMode::Off {
                write_bytes(output, b"\x1b[0;1;39m")?;
            }
            write_bytes(output, self.glyph("…", "..."))?;
            if self.color != ColorMode::Off {
                write_bytes(output, b"\x1b[0m")?;
            }
        }
        if self.options.cgroup_id {
            if let Some(id) = cgroup_id(file.as_raw_fd()) {
                write_bytes(output, b" ")?;
                if self.color != ColorMode::Off {
                    write_bytes(output, grey_code(self.color))?;
                }
                write!(output, "(#{id})").map_err(|error| error.to_string())?;
                if self.color != ColorMode::Off {
                    write_bytes(output, b"\x1b[0m")?;
                }
            }
        }
        write_bytes(output, b"\n")?;
        if self.options.xattrs {
            self.show_xattrs(path, prefix, more, output)?;
        }
        Ok(())
    }

    fn show_xattrs(
        &self,
        path: &Path,
        prefix: &[u8],
        more: bool,
        output: &mut impl Write,
    ) -> Result<(), String> {
        for (name, value) in list_xattrs(path) {
            if !name.starts_with(b"user.") && !name.starts_with(b"trusted.") {
                continue;
            }
            write_bytes(output, prefix)?;
            write_bytes(
                output,
                if more {
                    self.glyph("│ ", "| ")
                } else {
                    b"  "
                },
            )?;
            write_bytes(output, self.glyph("→ ", "-> "))?;
            if self.color != ColorMode::Off {
                write_bytes(output, b"\x1b[0;34m")?;
            }
            write_bytes(output, &c_escape(&name))?;
            if self.color != ColorMode::Off {
                write_bytes(output, b"\x1b[0m")?;
            }
            write_bytes(output, b": ")?;
            write_bytes(output, &c_escape(&value))?;
            write_bytes(output, b"\n")?;
        }
        Ok(())
    }

    fn cgroup_is_empty(path: &Path) -> bool {
        match fs::read_to_string(path.join("cgroup.events")) {
            Ok(contents) => contents
                .lines()
                .find_map(|line| {
                    line.strip_prefix("populated ")
                        .map(|value| value.trim() == "0")
                })
                .unwrap_or(false),
            Err(error) => error.kind() == io::ErrorKind::NotFound,
        }
    }

    fn root_cgroup(&self) -> Result<PathBuf, String> {
        if self.options.machine.is_some() {
            return machine_cgroup(self.options.machine.as_deref().unwrap_or_default());
        }
        let contents = fs::read_to_string("/proc/1/cgroup").map_err(io_error_text)?;
        let path = contents
            .lines()
            .find_map(|line| line.strip_prefix("0::"))
            .ok_or_else(|| String::from("Failed to get root control group path."))?;
        let path = path.strip_suffix("/init.scope").unwrap_or(path);
        Ok(PathBuf::from(if path.is_empty() { "/" } else { path }))
    }

    fn logical_path(&self, logical: &Path) -> PathBuf {
        self.cgroup_root
            .join(logical.strip_prefix("/").unwrap_or(logical))
    }

    fn map_physical_path(&self, physical: &Path) -> PathBuf {
        physical.strip_prefix("/sys/fs/cgroup").map_or_else(
            |_| physical.to_path_buf(),
            |relative| self.cgroup_root.join(relative),
        )
    }

    fn glyph<'b>(&self, utf8: &'b str, ascii: &'b str) -> &'b [u8] {
        if self.utf8 {
            utf8.as_bytes()
        } else {
            ascii.as_bytes()
        }
    }
}

fn stdout_is_terminal() -> bool {
    // SAFETY: STDOUT_FILENO always denotes an integer descriptor; isatty does not retain it.
    unsafe { libc::isatty(libc::STDOUT_FILENO) > 0 }
}

fn color_mode() -> ColorMode {
    if let Ok(value) = env::var("SYSTEMD_COLORS") {
        return match value.as_str() {
            "16" | "auto-16" => ColorMode::Basic,
            "24bit" | "auto-24bit" => ColorMode::Rich,
            "1" | "yes" | "true" | "on" | "256" | "auto-256" => ColorMode::Extended,
            _ => ColorMode::Off,
        };
    }
    if stdout_is_terminal() && env::var("TERM").ok().as_deref() != Some("dumb") {
        ColorMode::Extended
    } else {
        ColorMode::Off
    }
}

fn grey_code(mode: ColorMode) -> &'static [u8] {
    match mode {
        ColorMode::Basic => b"\x1b[0;90m",
        ColorMode::Extended => b"\x1b[0;90m\x1b[0;38:5:245m",
        ColorMode::Rich => b"\x1b[0;38:5:245m",
        ColorMode::Off => b"",
    }
}

fn pager_wanted(options: &Options) -> bool {
    if options.no_pager || !stdout_is_terminal() || env::var("TERM").ok().as_deref() == Some("dumb")
    {
        return false;
    }
    let pager = env::var("SYSTEMD_PAGER")
        .ok()
        .or_else(|| env::var("PAGER").ok());
    !pager.as_deref().is_some_and(|value| {
        value
            .split_ascii_whitespace()
            .collect::<Vec<_>>()
            .as_slice()
            == ["cat"]
            || value.trim().is_empty()
    })
}

fn emit_output(options: &Options, output: &[u8]) -> Result<(), String> {
    if !pager_wanted(options) {
        return io::stdout()
            .lock()
            .write_all(output)
            .map_err(|error| error.to_string());
    }
    let pager = env::var("SYSTEMD_PAGER")
        .ok()
        .or_else(|| env::var("PAGER").ok())
        .unwrap_or_else(|| String::from("less"));
    let mut child = Command::new("sh")
        .args(["-c", &format!("exec {pager}")])
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|error| format!("Failed to create pager: {error}"))?;
    if let Some(mut input) = child.stdin.take() {
        input.write_all(output).map_err(|error| error.to_string())?;
    }
    child
        .wait()
        .map_err(|error| format!("Failed to wait for pager: {error}"))?;
    Ok(())
}

fn resolve_long(name: &[u8]) -> Result<&'static str, Vec<u8>> {
    const OPTIONS: [&str; 10] = [
        "help",
        "version",
        "no-pager",
        "all",
        "unit",
        "user-unit",
        "xattr",
        "cgroup-id",
        "full",
        "machine",
    ];
    let matches: Vec<&str> = OPTIONS
        .iter()
        .copied()
        .filter(|option| option.as_bytes().starts_with(name))
        .collect();
    if let [option] = matches.as_slice() {
        Ok(option)
    } else {
        let mut error = b"systemd-cgls: unrecognized option '--".to_vec();
        error.extend_from_slice(name);
        error.push(b'\'');
        Err(error)
    }
}

fn split_once(bytes: &[u8], delimiter: u8) -> (&[u8], Option<&[u8]>) {
    bytes
        .iter()
        .position(|byte| *byte == delimiter)
        .map_or((bytes, None), |index| {
            (&bytes[..index], Some(&bytes[index + 1..]))
        })
}

fn reject_value(name: &str, value: Option<&[u8]>, apply: impl FnOnce()) -> Result<(), String> {
    if value.is_some() {
        return Err(format!(
            "systemd-cgls: option '--{name}' doesn't allow an argument"
        ));
    }
    apply();
    Ok(())
}

fn select_unit_mode(options: &mut Options, mode: UnitMode) -> Result<(), String> {
    if options.unit_mode != UnitMode::None && options.unit_mode != mode {
        return Err(String::from("Cannot combine --user-unit with --unit."));
    }
    options.unit_mode = mode;
    Ok(())
}

fn parse_boolean(value: &[u8]) -> Result<bool, String> {
    match value {
        b"1" | b"yes" | b"y" | b"true" | b"t" | b"on" => Ok(true),
        b"0" | b"no" | b"n" | b"false" | b"f" | b"off" => Ok(false),
        _ => Err(String::from("Invalid argument")),
    }
}

fn tree_error(error: &str) -> String {
    if let Some(logged) = error.strip_prefix("@logged@") {
        if let Some((message, reason)) = logged.rsplit_once('\n') {
            return format!("{message}\nFailed to list cgroup tree: {reason}");
        }
    }
    format!("Failed to list cgroup tree: {error}")
}

type CgroupSpec<'a> = (Option<&'a [u8]>, Option<&'a [u8]>);

fn split_cgroup_spec(spec: &[u8]) -> Result<CgroupSpec<'_>, String> {
    if spec.is_empty() || spec.starts_with(b"/") {
        validate_logical(spec)?;
        return Ok((None, (!spec.is_empty()).then_some(spec)));
    }
    if let Some(index) = spec.iter().position(|byte| *byte == b':') {
        let path = &spec[index + 1..];
        if !path.is_empty() {
            validate_logical(path)?;
        }
        Ok((Some(&spec[..index]), (!path.is_empty()).then_some(path)))
    } else {
        Ok((Some(spec), None))
    }
}

fn validate_logical(path: &[u8]) -> Result<(), String> {
    let path = Path::new(OsStr::from_bytes(path));
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(String::from("Failed to split argument: Invalid argument"));
    }
    Ok(())
}

fn join_logical(root: &Path, path: &[u8]) -> PathBuf {
    let path = Path::new(OsStr::from_bytes(path));
    root.join(path.strip_prefix("/").unwrap_or(path))
}

fn display_logical(path: &Path) -> &[u8] {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() {
        b"/"
    } else {
        bytes
    }
}

fn mangle_unit_name(name: &OsStr) -> Result<String, String> {
    let bytes = name.as_bytes();
    if bytes.is_empty() {
        return Err(String::from("Failed to mangle unit name: Invalid argument"));
    }
    if bytes.starts_with(b"/") {
        let mut escaped = Vec::new();
        for component in Path::new(name).components() {
            match component {
                Component::RootDir | Component::CurDir => {}
                Component::ParentDir => {
                    return Err(String::from("Failed to mangle unit name: Invalid argument"));
                }
                Component::Normal(component) => {
                    if !escaped.is_empty() {
                        escaped.push(b'-');
                    }
                    escape_unit_component(component.as_bytes(), &mut escaped);
                }
                Component::Prefix(_) => unreachable!(),
            }
        }
        if escaped.is_empty() {
            escaped.push(b'-');
        }
        escaped.extend_from_slice(b".mount");
        return String::from_utf8(escaped)
            .map_err(|_| String::from("Failed to mangle unit name: Invalid argument"));
    }

    let mut escaped = Vec::new();
    escape_unit_component(bytes, &mut escaped);
    if escaped != bytes {
        let mut warning = b"Invalid unit name \"".to_vec();
        warning.extend_from_slice(bytes);
        warning.extend_from_slice(b"\" escaped as \"");
        warning.extend_from_slice(&escaped);
        warning.extend_from_slice(b"\" (maybe you should use systemd-escape?).");
        log_bytes(&warning);
    }
    if !escaped.contains(&b'.') {
        escaped.extend_from_slice(b".service");
    }
    String::from_utf8(escaped)
        .map_err(|_| String::from("Failed to mangle unit name: Invalid argument"))
}

fn escape_unit_component(input: &[u8], output: &mut Vec<u8>) {
    for byte in input {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b':' | b'_' | b'.' | b'-' | b'@') {
            output.push(*byte);
        } else if *byte == b'/' {
            output.push(b'-');
        } else {
            output.extend_from_slice(format!("\\x{byte:02x}").as_bytes());
        }
    }
}

fn unit_interface(unit: &str) -> &'static str {
    match unit.rsplit_once('.').map(|(_, suffix)| suffix) {
        Some("automount") => "org.freedesktop.systemd1.Automount",
        Some("device") => "org.freedesktop.systemd1.Device",
        Some("mount") => "org.freedesktop.systemd1.Mount",
        Some("path") => "org.freedesktop.systemd1.Path",
        Some("scope") => "org.freedesktop.systemd1.Scope",
        Some("slice") => "org.freedesktop.systemd1.Slice",
        Some("socket") => "org.freedesktop.systemd1.Socket",
        Some("swap") => "org.freedesktop.systemd1.Swap",
        Some("target") => "org.freedesktop.systemd1.Target",
        Some("timer") => "org.freedesktop.systemd1.Timer",
        _ => "org.freedesktop.systemd1.Service",
    }
}

fn query_unit_cgroup(unit: &str, mode: UnitMode) -> Result<String, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .map_err(|error| format!("Failed to connect to bus: {error}"))?;
    runtime.block_on(async {
        let connection = if mode == UnitMode::User {
            zbus::Connection::session().await
        } else {
            zbus::Connection::system().await
        }
        .map_err(|error| format!("Failed to connect to bus: {error}"))?;
        let manager = zbus::Proxy::new(
            &connection,
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
        )
        .await
        .map_err(|error| format!("Failed to query unit control group path: {error}"))?;
        let path: zbus::zvariant::OwnedObjectPath = manager
            .call("GetUnit", &(unit))
            .await
            .map_err(|error| format!("Failed to query unit control group path: {error}"))?;
        let interface = unit_interface(unit);
        let unit_proxy = zbus::Proxy::new(
            &connection,
            "org.freedesktop.systemd1",
            path.as_str(),
            interface,
        )
        .await
        .map_err(|error| format!("Failed to query unit control group path: {error}"))?;
        unit_proxy
            .get_property::<String>("ControlGroup")
            .await
            .map_err(|error| format!("Failed to query unit control group path: {error}"))
    })
}

fn machine_cgroup(machine: &OsStr) -> Result<PathBuf, String> {
    let name = machine.to_str().ok_or_else(|| {
        String::from("Machine name is not valid\nFailed to list cgroup tree: Invalid argument")
    })?;
    if name.is_empty()
        || name.starts_with('-')
        || name
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(format!(
            "Machine name is not valid: {name}\nFailed to list cgroup tree: Invalid argument"
        ));
    }
    let contents =
        fs::read_to_string(Path::new("/run/systemd/machines").join(name)).map_err(|error| {
            let error = io_error_text(error);
            format!("Failed to load machine data: {error}\nFailed to list cgroup tree: {error}")
        })?;
    let scope = contents
        .lines()
        .find_map(|line| line.strip_prefix("SCOPE="))
        .map(|value| value.trim_matches('"'))
        .ok_or_else(|| String::from("Failed to load machine data: Invalid argument"))?;
    query_unit_cgroup(scope, UnitMode::System).map(PathBuf::from)
}

fn process_command(pid: u32, width: usize, utf8: bool) -> Vec<u8> {
    let mut command = fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
    if command.is_empty() {
        command = fs::read(format!("/proc/{pid}/comm")).map_or_else(
            |_| b"n/a".to_vec(),
            |mut name| {
                while name.last().is_some_and(u8::is_ascii_whitespace) {
                    name.pop();
                }
                let mut result = vec![b'['];
                result.extend(name);
                result.push(b']');
                result
            },
        );
    } else {
        for byte in &mut command {
            if *byte == 0 {
                *byte = b' ';
            }
        }
        while command.last() == Some(&b' ') {
            command.pop();
        }
    }
    let command = String::from_utf8_lossy(&command).into_owned();
    ellipsize(command.as_bytes(), width, utf8)
}

fn ellipsize(value: &[u8], width: usize, utf8: bool) -> Vec<u8> {
    if width == usize::MAX || String::from_utf8_lossy(value).chars().count() <= width {
        return value.to_vec();
    }
    if width == 0 {
        return Vec::new();
    }
    if utf8 {
        let mut result: String = String::from_utf8_lossy(value)
            .chars()
            .take(width.saturating_sub(1))
            .collect();
        result.push('…');
        result.into_bytes()
    } else {
        let mut result: String = String::from_utf8_lossy(value)
            .chars()
            .take(width.saturating_sub(3))
            .collect();
        result.push_str("...");
        result.into_bytes()
    }
}

fn is_kernel_thread(pid: u32) -> bool {
    if pid == 1 || pid == std::process::id() {
        return false;
    }
    fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|line| {
            let end = line.rfind(')')?;
            line[end + 1..]
                .split_whitespace()
                .nth(6)?
                .parse::<u64>()
                .ok()
        })
        .is_some_and(|flags| flags & 0x0020_0000 != 0)
}

fn delegated(fd: i32) -> bool {
    xattr_at(fd, b"trusted.delegate\0")
        .or_else(|| xattr_at(fd, b"user.delegate\0"))
        .is_some_and(|value| matches!(value.as_slice(), b"1" | b"yes" | b"true" | b"on"))
}

fn xattr_at(fd: i32, name: &[u8]) -> Option<Vec<u8>> {
    let name = name.as_ptr().cast();
    // SAFETY: fd is live and name is NUL terminated.
    let length = unsafe { libc::fgetxattr(fd, name, std::ptr::null_mut(), 0) };
    if length < 0 {
        return None;
    }
    let mut value = vec![0; usize::try_from(length).ok()?];
    // SAFETY: value has exactly the capacity reported by the kernel.
    let read = unsafe { libc::fgetxattr(fd, name, value.as_mut_ptr().cast(), value.len()) };
    (read >= 0).then_some(value)
}

fn list_xattrs(path: &Path) -> Vec<(Vec<u8>, Vec<u8>)> {
    let Ok(file) = File::open(path) else {
        return Vec::new();
    };
    // SAFETY: a null buffer asks only for the required length.
    let length = unsafe { libc::flistxattr(file.as_raw_fd(), std::ptr::null_mut(), 0) };
    if length <= 0 {
        return Vec::new();
    }
    let mut names = vec![0_u8; usize::try_from(length).unwrap_or(0)];
    // SAFETY: names has the capacity reported by flistxattr.
    if unsafe { libc::flistxattr(file.as_raw_fd(), names.as_mut_ptr().cast(), names.len()) } < 0 {
        return Vec::new();
    }
    names
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
        .filter_map(|name| {
            let mut terminated = name.to_vec();
            terminated.push(0);
            xattr_at(file.as_raw_fd(), &terminated).map(|value| (name.to_vec(), value))
        })
        .collect()
}

fn cgroup_id(fd: i32) -> Option<u64> {
    #[repr(C)]
    struct Handle {
        bytes: u32,
        kind: i32,
        value: [u8; 128],
    }
    let mut handle = Handle {
        bytes: 128,
        kind: 0,
        value: [0; 128],
    };
    let mut mount_id = 0;
    // SAFETY: handle matches the file_handle header and provides eight writable bytes.
    let result = unsafe {
        libc::name_to_handle_at(
            fd,
            b"\0".as_ptr().cast(),
            std::ptr::addr_of_mut!(handle).cast(),
            std::ptr::addr_of_mut!(mount_id),
            libc::AT_EMPTY_PATH,
        )
    };
    (result == 0 && handle.bytes >= 8).then(|| {
        u64::from_ne_bytes(
            handle.value[..8]
                .try_into()
                .expect("eight-byte file handle"),
        )
    })
}

fn c_escape(value: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    for byte in value {
        match *byte {
            b'\\' => output.extend_from_slice(b"\\\\"),
            b'\n' => output.extend_from_slice(b"\\n"),
            b'\r' => output.extend_from_slice(b"\\r"),
            b'\t' => output.extend_from_slice(b"\\t"),
            0x20..=0x7e => output.push(*byte),
            byte => output.extend_from_slice(format!("\\x{byte:02x}").as_bytes()),
        }
    }
    output
}

fn write_bytes(output: &mut impl Write, bytes: &[u8]) -> Result<(), String> {
    output.write_all(bytes).map_err(|error| error.to_string())
}

fn log_bytes(message: &[u8]) {
    let mut stderr = io::stderr().lock();
    let _ = stderr.write_all(message);
    let _ = stderr.write_all(b"\n");
}

fn io_error_text(error: impl std::fmt::Display) -> String {
    let text = error.to_string();
    text.rfind(" (os error ").map_or(text.clone(), |index| {
        if text.ends_with(')') {
            text[..index].to_owned()
        } else {
            text
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controller_spec_rejects_parent_components() {
        assert!(split_cgroup_spec(b"cpu:/../bad").is_err());
        assert_eq!(
            split_cgroup_spec(b"name=systemd:/").unwrap().1,
            Some(&b"/"[..])
        );
    }
}
