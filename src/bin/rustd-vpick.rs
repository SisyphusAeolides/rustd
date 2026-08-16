// SPDX-License-Identifier: LGPL-2.1-or-later
//! `systemd-vpick` v261 compatibility utility.
//!
//! Upstream references: systemd v261 `src/vpick/vpick-tool.c` and
//! `src/shared/vpick.c`.

use std::cmp::Ordering;
use std::collections::VecDeque;
use std::env;
use std::ffi::{CStr, OsStr, OsString};
use std::fs::{self, Metadata, OpenOptions};
use std::io::{self, IsTerminal, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::FileTypeExt;
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

const VERSION: &[u8] = concat!(
    "systemd 261 (261.2-1-arch)\n",
    "+PAM +AUDIT -SELINUX +APPARMOR -IMA +IPE +SMACK +SECCOMP +GCRYPT +GNUTLS +OPENSSL +ACL ",
    "+BLKID +CURL +ELFUTILS +FIDO2 +IDN2 +KMOD +LIBCRYPTSETUP +LIBCRYPTSETUP_PLUGINS +LIBFDISK ",
    "+PCRE2 +PWQUALITY +P11KIT +QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB +ZSTD +BPF_FRAMEWORK +BTF ",
    "+XKBCOMMON +UTMP +LIBARCHIVE\n"
)
.as_bytes();

const HELP: &[u8] = concat!(
    "systemd-vpick [OPTIONS...] PATH...\n\n",
    "Pick entry from versioned directory.\n\n",
    "Lookup Keys:\n",
    "  -B --basename=BASENAME Look for specified basename\n",
    "  -V VERSION             Look for specified version\n",
    "  -A ARCH                Look for specified architecture\n",
    "  -S --suffix=SUFFIX     Look for specified suffix\n",
    "  -t --type=TYPE         Look for specified inode type\n\n",
    "Output:\n",
    "  -h --help              Show this help\n",
    "     --version           Show package version\n",
    "  -p --print=WHAT        Print selected WHAT rather than path\n",
    "     --print=filename    ... print selected filename\n",
    "     --print=version     ... print selected version\n",
    "     --print=type        ... print selected inode type\n",
    "     --print=arch        ... print selected architecture\n",
    "     --print=tries       ... print selected tries left/tries done\n",
    "     --print=all         ... print all of the above\n",
    "     --resolve=BOOL      Canonicalize the result path\n\n",
    "See the systemd-vpick(1) man page for details.\n"
)
.as_bytes();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Architecture {
    Alpha,
    Arc,
    ArcBe,
    Arm,
    Arm64,
    Arm64Be,
    ArmBe,
    Cris,
    Ia64,
    LoongArch64,
    M68k,
    Mips,
    Mips64,
    Mips64Le,
    MipsLe,
    Nios2,
    Parisc,
    Parisc64,
    Ppc,
    Ppc64,
    Ppc64Le,
    PpcLe,
    Riscv32,
    Riscv64,
    S390,
    S390x,
    Sh,
    Sh64,
    Sparc,
    Sparc64,
    Tilegx,
    X86,
    X86_64,
}

impl Architecture {
    fn parse(value: &[u8]) -> Option<Self> {
        Some(match value {
            b"alpha" => Self::Alpha,
            b"arc" => Self::Arc,
            b"arc-be" => Self::ArcBe,
            b"arm" => Self::Arm,
            b"arm64" => Self::Arm64,
            b"arm64-be" => Self::Arm64Be,
            b"arm-be" => Self::ArmBe,
            b"cris" => Self::Cris,
            b"ia64" => Self::Ia64,
            b"loongarch64" => Self::LoongArch64,
            b"m68k" => Self::M68k,
            b"mips" => Self::Mips,
            b"mips64" => Self::Mips64,
            b"mips64-le" => Self::Mips64Le,
            b"mips-le" => Self::MipsLe,
            b"nios2" => Self::Nios2,
            b"parisc" => Self::Parisc,
            b"parisc64" => Self::Parisc64,
            b"ppc" => Self::Ppc,
            b"ppc64" => Self::Ppc64,
            b"ppc64-le" => Self::Ppc64Le,
            b"ppc-le" => Self::PpcLe,
            b"riscv32" => Self::Riscv32,
            b"riscv64" => Self::Riscv64,
            b"s390" => Self::S390,
            b"s390x" => Self::S390x,
            b"sh" => Self::Sh,
            b"sh64" => Self::Sh64,
            b"sparc" => Self::Sparc,
            b"sparc64" => Self::Sparc64,
            b"tilegx" => Self::Tilegx,
            b"x86" => Self::X86,
            b"x86-64" => Self::X86_64,
            _ => return None,
        })
    }

    const fn name(self) -> &'static [u8] {
        match self {
            Self::Alpha => b"alpha",
            Self::Arc => b"arc",
            Self::ArcBe => b"arc-be",
            Self::Arm => b"arm",
            Self::Arm64 => b"arm64",
            Self::Arm64Be => b"arm64-be",
            Self::ArmBe => b"arm-be",
            Self::Cris => b"cris",
            Self::Ia64 => b"ia64",
            Self::LoongArch64 => b"loongarch64",
            Self::M68k => b"m68k",
            Self::Mips => b"mips",
            Self::Mips64 => b"mips64",
            Self::Mips64Le => b"mips64-le",
            Self::MipsLe => b"mips-le",
            Self::Nios2 => b"nios2",
            Self::Parisc => b"parisc",
            Self::Parisc64 => b"parisc64",
            Self::Ppc => b"ppc",
            Self::Ppc64 => b"ppc64",
            Self::Ppc64Le => b"ppc64-le",
            Self::PpcLe => b"ppc-le",
            Self::Riscv32 => b"riscv32",
            Self::Riscv64 => b"riscv64",
            Self::S390 => b"s390",
            Self::S390x => b"s390x",
            Self::Sh => b"sh",
            Self::Sh64 => b"sh64",
            Self::Sparc => b"sparc",
            Self::Sparc64 => b"sparc64",
            Self::Tilegx => b"tilegx",
            Self::X86 => b"x86",
            Self::X86_64 => b"x86-64",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InodeType {
    Regular,
    Directory,
    Symlink,
    Character,
    Block,
    Fifo,
    Socket,
}

impl InodeType {
    const fn bit(self) -> u8 {
        match self {
            Self::Regular => 1 << 0,
            Self::Directory => 1 << 1,
            Self::Symlink => 1 << 2,
            Self::Character => 1 << 3,
            Self::Block => 1 << 4,
            Self::Fifo => 1 << 5,
            Self::Socket => 1 << 6,
        }
    }

    const fn name(self) -> &'static [u8] {
        match self {
            Self::Regular => b"reg",
            Self::Directory => b"dir",
            Self::Symlink => b"lnk",
            Self::Character => b"chr",
            Self::Block => b"blk",
            Self::Fifo => b"fifo",
            Self::Socket => b"sock",
        }
    }

    fn parse(value: &[u8]) -> Option<Self> {
        Some(match value {
            b"reg" => Self::Regular,
            b"dir" => Self::Directory,
            b"lnk" => Self::Symlink,
            b"chr" => Self::Character,
            b"blk" => Self::Block,
            b"fifo" => Self::Fifo,
            b"sock" => Self::Socket,
            _ => return None,
        })
    }

    fn from_metadata(metadata: &Metadata) -> Option<Self> {
        let kind = metadata.file_type();
        if kind.is_file() {
            Some(Self::Regular)
        } else if kind.is_dir() {
            Some(Self::Directory)
        } else if kind.is_symlink() {
            Some(Self::Symlink)
        } else if kind.is_char_device() {
            Some(Self::Character)
        } else if kind.is_block_device() {
            Some(Self::Block)
        } else if kind.is_fifo() {
            Some(Self::Fifo)
        } else if kind.is_socket() {
            Some(Self::Socket)
        } else {
            None
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrintMode {
    Path,
    Filename,
    Version,
    Type,
    Architecture,
    Tries,
    All,
}

#[derive(Debug)]
struct Options {
    basename: Option<Vec<u8>>,
    version: Option<Vec<u8>>,
    architecture: Option<Architecture>,
    suffix: Option<Vec<u8>>,
    type_mask: u8,
    print: PrintMode,
    resolve: bool,
    paths: Vec<OsString>,
}

#[derive(Debug)]
enum ParseResult {
    Run(Options),
    Exit(Vec<u8>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ColorMode {
    Disabled,
    Ansi16,
    Ansi256,
}

#[derive(Debug)]
struct PickResult {
    path: PathBuf,
    version: Option<Vec<u8>>,
    architecture: Option<Architecture>,
    tries_left: u32,
    tries_done: u32,
    inode_type: InodeType,
}

#[derive(Debug)]
struct CliError(Vec<u8>);

fn main() {
    let _ = locale_is_utf8();
    initialize_logging();
    let arguments: Vec<OsString> = env::args_os().skip(1).collect();
    let result = match parse_options(&arguments) {
        Ok(ParseResult::Exit(output)) => io::stdout().write_all(&output).map_err(io_error_message),
        Ok(ParseResult::Run(options)) => run(&options),
        Err(error) => Err(error),
    };

    if let Err(error) = result {
        log_error(&error.0);
        std::process::exit(1);
    }
}

#[allow(clippy::too_many_lines)] // Keep the v261 getopt state machine in option order.
fn parse_options(arguments: &[OsString]) -> Result<ParseResult, CliError> {
    let mut basename = None;
    let mut version = None;
    let mut architecture = None;
    let mut suffix = None;
    let mut type_mask = 0u8;
    let mut print = PrintMode::Path;
    let mut resolve = false;
    let mut paths = Vec::new();
    let mut index = 0usize;

    while index < arguments.len() {
        let raw = arguments[index].as_os_str().as_bytes();
        if raw == b"--" {
            paths.extend(arguments[index + 1..].iter().cloned());
            break;
        }
        if raw == b"-" || !raw.starts_with(b"-") {
            paths.push(arguments[index].clone());
            index += 1;
            continue;
        }

        if raw.starts_with(b"--") {
            let equals = raw.iter().position(|byte| *byte == b'=');
            let option_name = equals.map_or(raw, |offset| &raw[..offset]);
            let joined_value = equals.map(|offset| &raw[offset + 1..]);
            let canonical = match_long_option(option_name)?;
            match canonical {
                b"help" => {
                    reject_joined_value(option_name, joined_value)?;
                    return Ok(ParseResult::Exit(help_output()));
                }
                b"version" => {
                    reject_joined_value(option_name, joined_value)?;
                    return Ok(ParseResult::Exit(VERSION.to_vec()));
                }
                name => {
                    let (value, consumed) =
                        required_value(option_name, joined_value, arguments.get(index + 1))?;
                    apply_option(
                        name,
                        value,
                        &mut basename,
                        &mut version,
                        &mut architecture,
                        &mut suffix,
                        &mut type_mask,
                        &mut print,
                        &mut resolve,
                    )?;
                    index += usize::from(consumed);
                }
            }
            index += 1;
            continue;
        }

        let offset = 1usize;
        {
            let short = raw[offset];
            let option_name = [b'-', short];
            match short {
                b'h' => return Ok(ParseResult::Exit(help_output())),
                b'B' | b'V' | b'A' | b'S' | b't' | b'p' => {
                    let remainder = &raw[offset + 1..];
                    let (value, consumed) = if remainder.is_empty() {
                        required_value(&option_name, None, arguments.get(index + 1))?
                    } else {
                        (remainder, false)
                    };
                    let canonical = match short {
                        b'B' => b"basename".as_slice(),
                        b'V' => b"V".as_slice(),
                        b'A' => b"A".as_slice(),
                        b'S' => b"suffix".as_slice(),
                        b't' => b"type".as_slice(),
                        b'p' => b"print".as_slice(),
                        _ => unreachable!(),
                    };
                    apply_option(
                        canonical,
                        value,
                        &mut basename,
                        &mut version,
                        &mut architecture,
                        &mut suffix,
                        &mut type_mask,
                        &mut print,
                        &mut resolve,
                    )?;
                    index += usize::from(consumed);
                }
                _ => return Err(unrecognized_option(&option_name)),
            }
        }
        index += 1;
    }

    if paths.is_empty() {
        return Err(CliError(b"Path to resolve must be specified.".to_vec()));
    }

    Ok(ParseResult::Run(Options {
        basename,
        version,
        architecture,
        suffix,
        type_mask,
        print,
        resolve,
        paths,
    }))
}

#[allow(clippy::too_many_arguments)]
fn apply_option(
    name: &[u8],
    value: &[u8],
    basename: &mut Option<Vec<u8>>,
    version: &mut Option<Vec<u8>>,
    architecture: &mut Option<Architecture>,
    suffix: &mut Option<Vec<u8>>,
    type_mask: &mut u8,
    print: &mut PrintMode,
    resolve: &mut bool,
) -> Result<(), CliError> {
    match name {
        b"basename" => {
            if !filename_part_is_valid(value) {
                return Err(message_with_value(b"Invalid basename string: ", value));
            }
            *basename = Some(value.to_vec());
        }
        b"V" => {
            if !version_is_valid(value) {
                return Err(message_with_value(b"Invalid version string: ", value));
            }
            *version = Some(value.to_vec());
        }
        b"A" => {
            *architecture = match value {
                b"auto" => None,
                b"native" => Some(native_architecture()),
                b"secondary" => Some(secondary_architecture().ok_or_else(|| {
                    CliError(b"Local architecture has no secondary architecture.".to_vec())
                })?),
                b"uname" => Some(uname_architecture()),
                _ => Some(
                    Architecture::parse(value)
                        .ok_or_else(|| message_with_value(b"Unknown architecture: ", value))?,
                ),
            };
        }
        b"suffix" => {
            if !filename_part_is_valid(value) {
                return Err(message_with_value(b"Invalid suffix string: ", value));
            }
            *suffix = Some(value.to_vec());
        }
        b"type" => {
            if value.is_empty() {
                *type_mask = 0;
            } else {
                let inode_type = InodeType::parse(value)
                    .ok_or_else(|| message_with_value(b"Unknown inode type: ", value))?;
                *type_mask |= inode_type.bit();
            }
        }
        b"print" => {
            *print = match value {
                b"path" => PrintMode::Path,
                b"filename" => PrintMode::Filename,
                b"version" => PrintMode::Version,
                b"type" => PrintMode::Type,
                b"arch" | b"architecture" => PrintMode::Architecture,
                b"tries" => PrintMode::Tries,
                b"all" => PrintMode::All,
                _ => return Err(message_with_value(b"Unknown --print= argument: ", value)),
            };
        }
        b"resolve" => {
            *resolve = parse_boolean(value).ok_or_else(|| {
                CliError(b"Failed to parse --resolve= value: Invalid argument".to_vec())
            })?;
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn match_long_option(option_name: &[u8]) -> Result<&'static [u8], CliError> {
    const LONG_OPTIONS: [&[u8]; 7] = [
        b"basename",
        b"suffix",
        b"type",
        b"help",
        b"version",
        b"print",
        b"resolve",
    ];
    let name = option_name.strip_prefix(b"--").unwrap_or(option_name);
    let mut matches = LONG_OPTIONS
        .iter()
        .copied()
        .filter(|candidate| candidate.starts_with(name));
    let first = matches.next();
    let second = matches.next();
    match (first, second) {
        (Some(candidate), None) => Ok(candidate),
        (None, _) => Err(unrecognized_option(option_name)),
        _ => {
            let mut error = program_name();
            error.extend_from_slice(b": option '");
            error.extend_from_slice(option_name);
            error.extend_from_slice(b"' is ambiguous; possibilities: ");
            let possibilities: Vec<&[u8]> = LONG_OPTIONS
                .iter()
                .copied()
                .filter(|candidate| candidate.starts_with(name))
                .collect();
            for (index, possibility) in possibilities.iter().enumerate() {
                if index > 0 {
                    error.extend_from_slice(b", ");
                }
                error.extend_from_slice(b"--");
                error.extend_from_slice(possibility);
            }
            Err(CliError(error))
        }
    }
}

fn reject_joined_value(option_name: &[u8], value: Option<&[u8]>) -> Result<(), CliError> {
    if value.is_none() {
        return Ok(());
    }
    let mut error = program_name();
    error.extend_from_slice(b": option '");
    error.extend_from_slice(option_name);
    error.extend_from_slice(b"' doesn't allow an argument");
    Err(CliError(error))
}

fn required_value<'a>(
    option_name: &[u8],
    joined: Option<&'a [u8]>,
    next: Option<&'a OsString>,
) -> Result<(&'a [u8], bool), CliError> {
    if let Some(value) = joined {
        return Ok((value, false));
    }
    if let Some(value) = next {
        return Ok((value.as_os_str().as_bytes(), true));
    }
    let mut error = program_name();
    error.extend_from_slice(b": option '");
    error.extend_from_slice(option_name);
    error.extend_from_slice(b"' requires an argument");
    Err(CliError(error))
}

fn run(options: &Options) -> Result<(), CliError> {
    let mut stdout = io::stdout().lock();
    for path in &options.paths {
        let absolute = make_absolute(path)?;
        let result = pick(&absolute, options).map_err(|error| {
            let mut message = b"Failed to pick version for '".to_vec();
            message.extend_from_slice(absolute.as_os_str().as_bytes());
            message.extend_from_slice(b"': ");
            message.extend_from_slice(&io_error_text(&error));
            CliError(message)
        })?;
        let Some(result) = result else {
            let mut message = b"No matching version for '".to_vec();
            message.extend_from_slice(absolute.as_os_str().as_bytes());
            message.extend_from_slice(b"' found.");
            return Err(CliError(message));
        };
        print_result(&mut stdout, &result, options.print)?;
    }
    Ok(())
}

fn make_absolute(path: &OsStr) -> Result<PathBuf, CliError> {
    let candidate = Path::new(path);
    if candidate.is_absolute() {
        Ok(candidate.to_path_buf())
    } else {
        env::current_dir()
            .map(|cwd| cwd.join(candidate))
            .map_err(|error| {
                let mut message = b"Failed to make path '".to_vec();
                message.extend_from_slice(path.as_bytes());
                message.extend_from_slice(b"' absolute: ");
                message.extend_from_slice(&io_error_text(&error));
                CliError(message)
            })
    }
}

fn pick(path: &Path, options: &Options) -> io::Result<Option<PickResult>> {
    if options.basename.is_some() {
        return enumerate(
            path,
            options.basename.as_deref(),
            options.suffix.as_deref(),
            options,
        );
    }
    if path.components().next_back() == Some(Component::ParentDir) {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }

    let Some(filename) = path.file_name().map(OsStr::as_bytes) else {
        return pin(
            path,
            options.version.clone(),
            options.architecture,
            u32::MAX,
            u32::MAX,
            options,
        );
    };

    if let Some(base) = filename.strip_suffix(b".v") {
        let mut base = base.to_vec();
        if let Some(suffix) = nonempty(options.suffix.as_deref()) {
            if base.ends_with(suffix) {
                base.truncate(base.len() - suffix.len());
            }
        }
        return enumerate(path, Some(&base), options.suffix.as_deref(), options);
    }

    let Some(wildcard) = rfind_bytes(filename, b"___") else {
        return pin(
            path,
            options.version.clone(),
            options.architecture,
            u32::MAX,
            u32::MAX,
            options,
        );
    };
    let Some(parent) = path.parent() else {
        return pin(
            path,
            options.version.clone(),
            options.architecture,
            u32::MAX,
            u32::MAX,
            options,
        );
    };
    let parent = simplify_path(parent);
    let Some(parent_name) = parent.file_name().map(OsStr::as_bytes) else {
        return pin(
            path,
            options.version.clone(),
            options.architecture,
            u32::MAX,
            u32::MAX,
            options,
        );
    };
    if !parent_name.ends_with(b".v") {
        return pin(
            path,
            options.version.clone(),
            options.architecture,
            u32::MAX,
            u32::MAX,
            options,
        );
    }

    let base = &filename[..wildcard];
    let suffix = &filename[wildcard + 3..];
    let mut adjusted = Options {
        basename: options.basename.clone(),
        version: options.version.clone(),
        architecture: options.architecture,
        suffix: options.suffix.clone(),
        type_mask: options.type_mask,
        print: options.print,
        resolve: options.resolve,
        paths: Vec::new(),
    };
    if path.as_os_str().as_bytes().ends_with(b"/") {
        let directory = InodeType::Directory.bit();
        if adjusted.type_mask != 0 && adjusted.type_mask & directory == 0 {
            let errno = if adjusted.type_mask == InodeType::Block.bit() {
                libc::ENOTBLK
            } else if adjusted.type_mask == InodeType::Socket.bit() {
                libc::ENOTSOCK
            } else {
                libc::EISDIR
            };
            return Err(io::Error::from_raw_os_error(errno));
        }
        adjusted.type_mask = directory;
    }
    enumerate(&parent, Some(base), Some(suffix), &adjusted)
}

fn simplify_path(path: &Path) -> PathBuf {
    let bytes = path.as_os_str().as_bytes();
    let absolute = bytes.starts_with(b"/");
    let mut components: Vec<&[u8]> = Vec::new();
    let mut beginning = true;
    for component in bytes.split(|byte| *byte == b'/') {
        if component.is_empty() || component == b"." {
            continue;
        }
        if absolute && beginning && component == b".." {
            continue;
        }
        beginning = false;
        components.push(component);
    }

    let mut simplified = Vec::new();
    if absolute {
        simplified.push(b'/');
    }
    for (index, component) in components.iter().enumerate() {
        if index > 0 {
            simplified.push(b'/');
        }
        simplified.extend_from_slice(component);
    }
    if simplified.is_empty() {
        simplified.extend_from_slice(if absolute { b"/" } else { b"." });
    }
    PathBuf::from(OsString::from_vec(simplified))
}

fn enumerate(
    directory: &Path,
    basename: Option<&[u8]>,
    suffix: Option<&[u8]>,
    options: &Options,
) -> io::Result<Option<PickResult>> {
    let basename = nonempty(basename);
    let suffix = nonempty(suffix);
    let mut best: Option<PickResult> = None;

    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let original_name = entry.file_name();
        let mut variable = original_name.as_os_str().as_bytes().to_vec();

        if let Some(base) = basename {
            let Some(remainder) = variable.strip_prefix(base) else {
                continue;
            };
            let Some(remainder) = remainder.strip_prefix(b"_") else {
                continue;
            };
            variable = remainder.to_vec();
        }

        if let Some(required_suffix) = suffix {
            if !variable.ends_with(required_suffix) {
                continue;
            }
            variable.truncate(variable.len() - required_suffix.len());
        }

        let (tries_left, tries_done) =
            if let Some(plus) = variable.iter().rposition(|byte| *byte == b'+') {
                if let Some((left, done)) = parse_tries(&variable[plus..]) {
                    variable.truncate(plus);
                    (left, done)
                } else {
                    (u32::MAX, u32::MAX)
                }
            } else {
                (u32::MAX, u32::MAX)
            };

        let found_architecture =
            if let Some(underscore) = variable.iter().rposition(|byte| *byte == b'_') {
                let architecture = Architecture::parse(&variable[underscore + 1..]);
                if !architecture_matches(options.architecture, architecture) {
                    continue;
                }
                variable.truncate(underscore);
                architecture
            } else {
                if !architecture_matches(options.architecture, None) {
                    continue;
                }
                None
            };

        if !version_is_valid(&variable) {
            continue;
        }
        if options
            .version
            .as_deref()
            .is_some_and(|required| required != variable)
        {
            continue;
        }

        let entry_path = directory.join(&original_name);
        let Some(found) = pin(
            &entry_path,
            Some(variable),
            found_architecture,
            tries_left,
            tries_done,
            options,
        )?
        else {
            continue;
        };

        if best.as_ref().map_or(true, |previous| {
            pick_compare(&found, previous) == Ordering::Greater
        }) {
            best = Some(found);
        }
    }
    Ok(best)
}

fn pin(
    path: &Path,
    version: Option<Vec<u8>>,
    architecture: Option<Architecture>,
    tries_left: u32,
    tries_done: u32,
    options: &Options,
) -> io::Result<Option<PickResult>> {
    let selected_path = if options.resolve {
        canonicalize_chase(path)?
    } else {
        path.to_path_buf()
    };
    let metadata = fs::metadata(&selected_path)?;
    let Some(inode_type) = InodeType::from_metadata(&metadata) else {
        return Ok(None);
    };
    if options.type_mask != 0 && options.type_mask & inode_type.bit() == 0 {
        return Ok(None);
    }
    Ok(Some(PickResult {
        path: selected_path,
        version,
        architecture,
        tries_left,
        tries_done,
        inode_type,
    }))
}

#[derive(Debug)]
enum ChaseComponent {
    Root,
    Parent,
    Normal(OsString),
}

fn canonicalize_chase(path: &Path) -> io::Result<PathBuf> {
    let mut pending = chase_components(path);
    let mut resolved = PathBuf::new();
    let mut steps = 0u32;

    while let Some(component) = pending.pop_front() {
        match component {
            ChaseComponent::Root => {
                resolved = PathBuf::from("/");
            }
            ChaseComponent::Parent => {
                steps += 1;
                if steps > 128 {
                    return Err(io::Error::from_raw_os_error(libc::ELOOP));
                }
                if !fs::metadata(&resolved)?.is_dir() {
                    return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
                }
                resolved.pop();
                if resolved.as_os_str().is_empty() {
                    resolved.push("/");
                }
            }
            ChaseComponent::Normal(component) => {
                steps += 1;
                if steps > 128 {
                    return Err(io::Error::from_raw_os_error(libc::ELOOP));
                }
                resolved.push(&component);
                let metadata = fs::symlink_metadata(&resolved)?;
                if !metadata.file_type().is_symlink() {
                    continue;
                }

                let target = fs::read_link(&resolved)?;
                resolved.pop();
                for target_component in chase_components(&target).into_iter().rev() {
                    pending.push_front(target_component);
                }
            }
        }
    }

    if resolved.as_os_str().is_empty() {
        resolved.push("/");
    }
    let metadata = fs::metadata(&resolved)?;
    if path_requires_directory(path) && !metadata.is_dir() {
        return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
    }
    Ok(resolved)
}

fn path_requires_directory(path: &Path) -> bool {
    let path = path.as_os_str().as_bytes();
    path == b"."
        || path == b".."
        || path.ends_with(b"/")
        || path.ends_with(b"/.")
        || path.ends_with(b"/..")
}

fn chase_components(path: &Path) -> VecDeque<ChaseComponent> {
    path.components()
        .filter_map(|component| match component {
            Component::RootDir => Some(ChaseComponent::Root),
            Component::ParentDir => Some(ChaseComponent::Parent),
            Component::Normal(component) => Some(ChaseComponent::Normal(component.to_owned())),
            Component::CurDir | Component::Prefix(_) => None,
        })
        .collect()
}

fn pick_compare(left: &PickResult, right: &PickResult) -> Ordering {
    let mut ordering = (left.tries_left != 0).cmp(&(right.tries_left != 0));
    if ordering == Ordering::Equal {
        ordering = version_compare(
            left.version.as_deref().unwrap_or_default(),
            right.version.as_deref().unwrap_or_default(),
        );
    }
    if ordering == Ordering::Equal {
        ordering = (left.architecture == Some(native_architecture()))
            .cmp(&(right.architecture == Some(native_architecture())));
    }
    if ordering == Ordering::Equal {
        if let Some(secondary) = secondary_architecture() {
            ordering = (left.architecture == Some(secondary))
                .cmp(&(right.architecture == Some(secondary)));
        }
    }
    if ordering == Ordering::Equal {
        ordering = left.tries_left.cmp(&right.tries_left);
    }
    if ordering == Ordering::Equal {
        ordering = right.tries_done.cmp(&left.tries_done);
    }
    if ordering == Ordering::Equal {
        ordering = filename_bytes(&left.path).cmp(filename_bytes(&right.path));
    }
    ordering
}

#[allow(clippy::too_many_lines)] // Preserve the v261 print-mode order and exact diagnostics.
fn print_result(
    output: &mut impl Write,
    result: &PickResult,
    mode: PrintMode,
) -> Result<(), CliError> {
    match mode {
        PrintMode::Path => {
            output
                .write_all(result.path.as_os_str().as_bytes())
                .map_err(io_error_message)?;
            if result.inode_type == InodeType::Directory
                && !result.path.as_os_str().as_bytes().ends_with(b"/")
            {
                output.write_all(b"/").map_err(io_error_message)?;
            }
            output.write_all(b"\n").map_err(io_error_message)?;
        }
        PrintMode::Filename => {
            let filename = result.path.file_name().ok_or_else(|| {
                let mut message = b"Failed to extract filename from path '".to_vec();
                message.extend_from_slice(result.path.as_os_str().as_bytes());
                message.extend_from_slice(b"': Address not available");
                CliError(message)
            })?;
            output
                .write_all(filename.as_bytes())
                .and_then(|()| output.write_all(b"\n"))
                .map_err(io_error_message)?;
        }
        PrintMode::Version => {
            let value = result
                .version
                .as_deref()
                .ok_or_else(|| CliError(b"No version information discovered.".to_vec()))?;
            output
                .write_all(value)
                .and_then(|()| output.write_all(b"\n"))
                .map_err(io_error_message)?;
        }
        PrintMode::Type => {
            output
                .write_all(result.inode_type.name())
                .and_then(|()| output.write_all(b"\n"))
                .map_err(io_error_message)?;
        }
        PrintMode::Architecture => {
            let value = result
                .architecture
                .ok_or_else(|| CliError(b"No architecture information discovered.".to_vec()))?;
            output
                .write_all(value.name())
                .and_then(|()| output.write_all(b"\n"))
                .map_err(io_error_message)?;
        }
        PrintMode::Tries => {
            if result.tries_left == u32::MAX {
                return Err(CliError(
                    b"No tries left/tries done information discovered.".to_vec(),
                ));
            }
            write!(output, "+{}-{}", result.tries_left, result.tries_done)
                .map_err(io_error_message)?;
        }
        PrintMode::All => {
            let mut rows = vec![
                (
                    b"Path".to_vec(),
                    result.path.as_os_str().as_bytes().to_vec(),
                    false,
                ),
                (
                    b"Version".to_vec(),
                    result.version.as_deref().unwrap_or(b"n/a").to_vec(),
                    result.version.is_none(),
                ),
                (b"Type".to_vec(), result.inode_type.name().to_vec(), false),
                (
                    b"Architecture".to_vec(),
                    result
                        .architecture
                        .map_or(b"n/a".as_slice(), Architecture::name)
                        .to_vec(),
                    result.architecture.is_none(),
                ),
            ];
            if result.tries_left != u32::MAX {
                rows.push((
                    b"Tries left".to_vec(),
                    result.tries_left.to_string().into_bytes(),
                    false,
                ));
                rows.push((
                    b"Tries done".to_vec(),
                    result.tries_done.to_string().into_bytes(),
                    false,
                ));
            }
            if rows
                .iter()
                .any(|(_, value, _)| std::str::from_utf8(value).is_err())
            {
                return Err(CliError(
                    b"Failed to print table: Invalid argument".to_vec(),
                ));
            }
            write_table(output, &rows)?;
        }
    }
    Ok(())
}

fn write_table(output: &mut impl Write, rows: &[(Vec<u8>, Vec<u8>, bool)]) -> Result<(), CliError> {
    let colors = color_mode();
    let natural_label_width = rows
        .iter()
        .map(|(label, _, _)| console_width(label) + 1)
        .max()
        .unwrap_or_default();
    let natural_value_width = rows
        .iter()
        .map(|(_, value, _)| console_width(value))
        .max()
        .unwrap_or_default();
    let (label_width, value_width) = terminal_columns()
        .map_or((natural_label_width, natural_value_width), |columns| {
            table_column_widths(columns, natural_label_width, natural_value_width)
        });

    for (label, value, ersatz) in rows {
        let mut label_with_colon = label.clone();
        label_with_colon.push(b':');
        let visible_label = ellipsize(&label_with_colon, label_width, locale_is_utf8());
        let visible_value = ellipsize(value, value_width, locale_is_utf8());
        let visible_label_width = console_width(&visible_label);
        let visible_value_width = console_width(&visible_value);

        if colors == ColorMode::Disabled {
            for _ in visible_label_width..label_width {
                output.write_all(b" ").map_err(io_error_message)?;
            }
            output.write_all(&visible_label).map_err(io_error_message)?;
            output.write_all(b" ").map_err(io_error_message)?;
            output.write_all(&visible_value).map_err(io_error_message)?;
        } else {
            output.write_all(b"\x1b[0;94m").map_err(io_error_message)?;
            for _ in visible_label_width..label_width {
                output.write_all(b" ").map_err(io_error_message)?;
            }
            output.write_all(&visible_label).map_err(io_error_message)?;
            output.write_all(b"\x1b[0m ").map_err(io_error_message)?;
            if *ersatz {
                let is_one = env::var_os("SYSTEMD_COLORS")
                    .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"1"));
                if is_one && colors == ColorMode::Ansi256 {
                    output
                        .write_all(b"\x1b[0;38:5:245m")
                        .map_err(io_error_message)?;
                } else {
                    output.write_all(b"\x1b[0;90m").map_err(io_error_message)?;
                    if colors == ColorMode::Ansi256 {
                        output
                            .write_all(b"\x1b[0;38:5:245m")
                            .map_err(io_error_message)?;
                    }
                }
                output.write_all(&visible_value).map_err(io_error_message)?;
                for _ in visible_value_width..value_width {
                    output.write_all(b" ").map_err(io_error_message)?;
                }
                output.write_all(b"\x1b[0m").map_err(io_error_message)?;
            } else {
                output.write_all(&visible_value).map_err(io_error_message)?;
            }
        }
        output.write_all(b"\n").map_err(io_error_message)?;
    }
    Ok(())
}

fn terminal_columns() -> Option<usize> {
    if !io::stdout().is_terminal() {
        return None;
    }
    if let Some(columns) = env::var_os("COLUMNS").and_then(|value| {
        std::str::from_utf8(value.as_os_str().as_bytes())
            .ok()?
            .parse::<u16>()
            .ok()
            .filter(|columns| *columns > 0)
    }) {
        return Some(usize::from(columns));
    }
    // SAFETY: `winsize` is writable for the duration of this ioctl call.
    let mut winsize = unsafe { std::mem::zeroed::<libc::winsize>() };
    // SAFETY: stdout is an open terminal and the pointer refers to `winsize`.
    if unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut winsize) } < 0
        || winsize.ws_col == 0
    {
        Some(80)
    } else {
        Some(usize::from(winsize.ws_col))
    }
}

fn table_column_widths(columns: usize, label: usize, value: usize) -> (usize, usize) {
    let available = columns.max(3) - 1;
    if label.saturating_add(value) <= available {
        return (label, value);
    }

    let mut label_width = available / 2;
    let mut value_width = available - label_width;
    if label < label_width {
        label_width = label;
        value_width = available - label_width;
    }
    if value < value_width {
        value_width = value;
        label_width = available - value_width;
    }
    (label_width.min(label), value_width.min(value))
}

fn ellipsize(value: &[u8], width: usize, locale_utf8: bool) -> Vec<u8> {
    if console_width(value) <= width {
        return value.to_vec();
    }

    let is_ascii = value.is_ascii();
    if is_ascii && !locale_utf8 {
        if width <= 3 {
            return vec![b'.'; width];
        }
        let mut result = value[..width - 3].to_vec();
        result.extend_from_slice(b"...");
        return result;
    }

    if width == 0 {
        return Vec::new();
    }
    let available = width - 1;
    let text = std::str::from_utf8(value).expect("table input was validated as UTF-8");
    let mut used = 0usize;
    let mut end = 0usize;
    for (offset, character) in text.char_indices() {
        let character_width = character_console_width(character);
        if used + character_width > available {
            break;
        }
        used += character_width;
        end = offset + character.len_utf8();
    }
    let mut result = value[..end].to_vec();
    result.extend_from_slice("…".as_bytes());
    result
}

fn console_width(value: &[u8]) -> usize {
    std::str::from_utf8(value).map_or(value.len(), |text| {
        text.chars().map(character_console_width).sum()
    })
}

fn character_console_width(character: char) -> usize {
    if character == '\t' {
        8
    } else if unicode_character_is_wide(u32::from(character)) {
        2
    } else {
        1
    }
}

fn unicode_character_is_wide(character: u32) -> bool {
    matches!(
        character,
        0x1100..=0x115f
            | 0x2329..=0x232a
            | 0x2e80..=0x2e99
            | 0x2e9b..=0x2ef3
            | 0x2f00..=0x2fd5
            | 0x2ff0..=0x2ffb
            | 0x3000..=0x303e
            | 0x3041..=0x3096
            | 0x3099..=0x30ff
            | 0x3105..=0x312d
            | 0x3131..=0x318e
            | 0x3190..=0x31ba
            | 0x31c0..=0x31e3
            | 0x31f0..=0x321e
            | 0x3220..=0x3247
            | 0x3250..=0x32fe
            | 0x3300..=0x4dbf
            | 0x4e00..=0xa48c
            | 0xa490..=0xa4c6
            | 0xa960..=0xa97c
            | 0xac00..=0xd7a3
            | 0xf900..=0xfaff
            | 0xfe10..=0xfe19
            | 0xfe30..=0xfe52
            | 0xfe54..=0xfe66
            | 0xfe68..=0xfe6b
            | 0xff01..=0xff60
            | 0xffe0..=0xffe6
            | 0x1b000..=0x1b001
            | 0x1f200..=0x1f202
            | 0x1f210..=0x1f23a
            | 0x1f240..=0x1f248
            | 0x1f250..=0x1f251
            | 0x1f300..=0x1f567
            | 0x20000..=0x2fffd
            | 0x30000..=0x3fffd
    )
}

fn locale_is_utf8() -> bool {
    static UTF8: OnceLock<bool> = OnceLock::new();
    *UTF8.get_or_init(|| {
        if let Some(value) = environment_boolean("SYSTEMD_UTF8", false) {
            return value;
        }
        // SAFETY: the empty C string asks libc to apply the process environment locale.
        if unsafe { libc::setlocale(libc::LC_ALL, b"\0".as_ptr().cast()) }.is_null() {
            return true;
        }
        // SAFETY: `nl_langinfo` returns process-owned storage for the active locale.
        let codeset = unsafe { libc::nl_langinfo(libc::CODESET) };
        if codeset.is_null() {
            return true;
        }
        // SAFETY: a non-null `nl_langinfo` result is NUL terminated.
        if unsafe { CStr::from_ptr(codeset) }
            .to_bytes()
            .eq_ignore_ascii_case(b"UTF-8")
        {
            return true;
        }
        // SAFETY: a null locale query returns process-owned, NUL-terminated storage.
        let locale = unsafe { libc::setlocale(libc::LC_CTYPE, std::ptr::null()) };
        if locale.is_null() {
            return true;
        }
        // SAFETY: a non-null `setlocale` query result is NUL terminated.
        let locale = unsafe { CStr::from_ptr(locale) }.to_bytes();
        matches!(locale, b"C" | b"POSIX")
            && env::var_os("LC_ALL").is_none()
            && env::var_os("LC_CTYPE").is_none()
            && env::var_os("LANG").is_none()
    })
}

fn version_compare(left: &[u8], right: &[u8]) -> Ordering {
    let mut left_index = 0usize;
    let mut right_index = 0usize;
    loop {
        while left_index < left.len() && !is_comparison_character(left[left_index]) {
            left_index += 1;
        }
        while right_index < right.len() && !is_comparison_character(right[right_index]) {
            right_index += 1;
        }

        let left_byte = left.get(left_index).copied().unwrap_or_default();
        let right_byte = right.get(right_index).copied().unwrap_or_default();
        if left_byte == b'~' || right_byte == b'~' {
            let ordering = (left_byte != b'~').cmp(&(right_byte != b'~'));
            if ordering != Ordering::Equal {
                return ordering;
            }
            left_index += 1;
            right_index += 1;
        }

        let left_byte = left.get(left_index).copied().unwrap_or_default();
        let right_byte = right.get(right_index).copied().unwrap_or_default();
        if left_byte == 0 || right_byte == 0 {
            return left_byte.cmp(&right_byte);
        }

        for separator in *b"-^." {
            let left_byte = left.get(left_index).copied().unwrap_or_default();
            let right_byte = right.get(right_index).copied().unwrap_or_default();
            if left_byte == separator || right_byte == separator {
                let ordering = (left_byte != separator).cmp(&(right_byte != separator));
                if ordering != Ordering::Equal {
                    return ordering;
                }
                left_index += 1;
                right_index += 1;
            }
        }

        let left_digit = left.get(left_index).is_some_and(u8::is_ascii_digit);
        let right_digit = right.get(right_index).is_some_and(u8::is_ascii_digit);
        if left_digit || right_digit {
            let left_end = segment_end(left, left_index, u8::is_ascii_digit);
            let right_end = segment_end(right, right_index, u8::is_ascii_digit);
            let ordering = left_digit.cmp(&right_digit);
            if ordering != Ordering::Equal {
                return ordering;
            }
            let left_number = trim_leading_zeroes(&left[left_index..left_end]);
            let right_number = trim_leading_zeroes(&right[right_index..right_end]);
            let ordering = left_number.len().cmp(&right_number.len());
            if ordering != Ordering::Equal {
                return ordering;
            }
            let ordering = left_number.cmp(right_number);
            if ordering != Ordering::Equal {
                return ordering;
            }
            left_index = left_end;
            right_index = right_end;
        } else {
            let left_end = segment_end(left, left_index, u8::is_ascii_alphabetic);
            let right_end = segment_end(right, right_index, u8::is_ascii_alphabetic);
            let left_segment = &left[left_index..left_end];
            let right_segment = &right[right_index..right_end];
            let shared = left_segment.len().min(right_segment.len());
            let ordering = left_segment[..shared].cmp(&right_segment[..shared]);
            if ordering != Ordering::Equal {
                return ordering;
            }
            let ordering = left_segment.len().cmp(&right_segment.len());
            if ordering != Ordering::Equal {
                return ordering;
            }
            left_index = left_end;
            right_index = right_end;
        }
    }
}

fn segment_end(value: &[u8], start: usize, predicate: fn(&u8) -> bool) -> usize {
    let mut end = start;
    while end < value.len() && predicate(&value[end]) {
        end += 1;
    }
    end
}

fn trim_leading_zeroes(mut value: &[u8]) -> &[u8] {
    while value.first() == Some(&b'0') {
        value = &value[1..];
    }
    value
}

fn parse_tries(value: &[u8]) -> Option<(u32, u32)> {
    let value = value.strip_prefix(b"+")?;
    let digit_count = value
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    if digit_count == 0 {
        return None;
    }
    let left = parse_decimal(&value[..digit_count])?;
    if digit_count == value.len() {
        return Some((left, 0));
    }
    let done = value[digit_count..].strip_prefix(b"-")?;
    if done.is_empty() || !done.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some((left, parse_decimal(done)?))
}

fn parse_decimal(value: &[u8]) -> Option<u32> {
    value.iter().try_fold(0u32, |number, byte| {
        number
            .checked_mul(10)?
            .checked_add(u32::from(byte.checked_sub(b'0')?))
    })
}

fn version_is_valid(value: &[u8]) -> bool {
    !value.is_empty()
        && filename_part_is_valid(value)
        && value.iter().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b',' | b'_' | b'-' | b'+')
        })
}

fn filename_part_is_valid(value: &[u8]) -> bool {
    value.len() <= libc::NAME_MAX as usize && !value.contains(&b'/')
}

fn architecture_matches(requested: Option<Architecture>, found: Option<Architecture>) -> bool {
    if let Some(requested) = requested {
        return found == Some(requested);
    }
    found.is_none()
        || found == Some(native_architecture())
        || secondary_architecture().is_some_and(|secondary| found == Some(secondary))
}

#[cfg(target_arch = "x86_64")]
const fn native_architecture() -> Architecture {
    Architecture::X86_64
}
#[cfg(target_arch = "x86")]
const fn native_architecture() -> Architecture {
    Architecture::X86
}
#[cfg(target_arch = "aarch64")]
const fn native_architecture() -> Architecture {
    Architecture::Arm64
}
#[cfg(target_arch = "arm")]
const fn native_architecture() -> Architecture {
    Architecture::Arm
}
#[cfg(target_arch = "powerpc64")]
const fn native_architecture() -> Architecture {
    if cfg!(target_endian = "little") {
        Architecture::Ppc64Le
    } else {
        Architecture::Ppc64
    }
}
#[cfg(target_arch = "powerpc")]
const fn native_architecture() -> Architecture {
    if cfg!(target_endian = "little") {
        Architecture::PpcLe
    } else {
        Architecture::Ppc
    }
}
#[cfg(target_arch = "s390x")]
const fn native_architecture() -> Architecture {
    Architecture::S390x
}
#[cfg(target_arch = "riscv64")]
const fn native_architecture() -> Architecture {
    Architecture::Riscv64
}
#[cfg(target_arch = "loongarch64")]
const fn native_architecture() -> Architecture {
    Architecture::LoongArch64
}
#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "x86",
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "powerpc64",
    target_arch = "powerpc",
    target_arch = "s390x",
    target_arch = "riscv64",
    target_arch = "loongarch64"
)))]
const fn native_architecture() -> Architecture {
    Architecture::X86_64
}

const fn secondary_architecture() -> Option<Architecture> {
    #[cfg(target_arch = "x86_64")]
    return Some(Architecture::X86);
    #[cfg(all(target_arch = "powerpc64", target_endian = "big"))]
    return Some(Architecture::Ppc);
    #[cfg(all(target_arch = "powerpc64", target_endian = "little"))]
    return Some(Architecture::PpcLe);
    #[cfg(target_arch = "s390x")]
    return Some(Architecture::S390);
    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    return Some(Architecture::Arm);
    #[allow(unreachable_code)]
    None
}

fn uname_architecture() -> Architecture {
    let mut value = std::mem::MaybeUninit::<libc::utsname>::uninit();
    // SAFETY: `uname` initializes the complete `utsname` object on success.
    if unsafe { libc::uname(value.as_mut_ptr()) } != 0 {
        return native_architecture();
    }
    // SAFETY: the successful call above initialized `value`.
    let value = unsafe { value.assume_init() };
    // SAFETY: Linux guarantees that `machine` is NUL terminated.
    let machine = unsafe { CStr::from_ptr(value.machine.as_ptr()) }.to_bytes();
    match machine {
        b"x86_64" => Architecture::X86_64,
        b"i386" | b"i486" | b"i586" | b"i686" => Architecture::X86,
        b"aarch64" => Architecture::Arm64,
        b"aarch64_be" => Architecture::Arm64Be,
        value if value.starts_with(b"arm") && value.ends_with(b"b") => Architecture::ArmBe,
        value if value.starts_with(b"arm") => Architecture::Arm,
        b"ppc64le" => Architecture::Ppc64Le,
        b"ppc64" => Architecture::Ppc64,
        b"ppcle" => Architecture::PpcLe,
        b"ppc" => Architecture::Ppc,
        b"s390x" => Architecture::S390x,
        b"s390" => Architecture::S390,
        b"riscv64" => Architecture::Riscv64,
        b"riscv32" => Architecture::Riscv32,
        b"loongarch64" => Architecture::LoongArch64,
        _ => native_architecture(),
    }
}

fn help_output() -> Vec<u8> {
    let mut output = program_name();
    output.extend_from_slice(&HELP[b"systemd-vpick".len()..]);
    let colors = color_mode() != ColorMode::Disabled;
    let urlify = environment_boolean("SYSTEMD_URLIFY", false).unwrap_or(colors);
    if colors {
        decorate_help_fragment(
            &mut output,
            b"Pick entry from versioned directory.",
            b"\x1b[0;1;39m",
            b"\x1b[0m",
        );
        for heading in [b"Lookup Keys:".as_slice(), b"Output:".as_slice()] {
            decorate_help_fragment(&mut output, heading, b"\x1b[0;4m", b"\x1b[0m");
        }
    }
    if urlify {
        decorate_help_fragment(
            &mut output,
            b"systemd-vpick(1) man page",
            b"\x1b]8;;man:systemd-vpick(1)\x1b\\",
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

fn color_mode() -> ColorMode {
    if let Some(value) = env::var_os("SYSTEMD_COLORS") {
        let value = value.as_os_str().as_bytes().to_ascii_lowercase();
        match value.as_slice() {
            b"16" => return ColorMode::Ansi16,
            b"256" => return ColorMode::Ansi256,
            b"1" | b"yes" | b"y" | b"true" | b"t" | b"on" => {
                return ColorMode::Ansi256;
            }
            b"0" | b"no" | b"n" | b"false" | b"f" | b"off" => {
                return ColorMode::Disabled;
            }
            _ => {}
        }
    }
    if env::var_os("NO_COLOR").is_some() {
        return ColorMode::Disabled;
    }
    if !io::stdout().is_terminal()
        || !io::stderr().is_terminal()
        || env::var_os("TERM").as_deref() == Some(OsStr::new("dumb"))
    {
        return ColorMode::Disabled;
    }
    terminal_color_mode()
}

fn terminal_color_mode() -> ColorMode {
    ColorMode::Ansi256
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

fn parse_boolean(value: &[u8]) -> Option<bool> {
    if [b"1".as_slice(), b"yes", b"y", b"true", b"t", b"on"]
        .iter()
        .any(|candidate| value.eq_ignore_ascii_case(candidate))
    {
        Some(true)
    } else if [b"0".as_slice(), b"no", b"n", b"false", b"f", b"off"]
        .iter()
        .any(|candidate| value.eq_ignore_ascii_case(candidate))
    {
        Some(false)
    } else {
        None
    }
}

fn is_comparison_character(value: u8) -> bool {
    value.is_ascii_alphanumeric() || matches!(value, b'~' | b'-' | b'^' | b'.')
}

fn rfind_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .rposition(|window| window == needle)
}

fn nonempty(value: Option<&[u8]>) -> Option<&[u8]> {
    value.filter(|value| !value.is_empty())
}

fn filename_bytes(path: &Path) -> &[u8] {
    path.file_name()
        .map_or_else(|| path.as_os_str().as_bytes(), OsStr::as_bytes)
}

fn program_name() -> Vec<u8> {
    env::args_os()
        .next()
        .as_deref()
        .and_then(|name| Path::new(name).file_name())
        .map_or_else(
            || b"systemd-vpick".to_vec(),
            |name| name.as_bytes().to_vec(),
        )
}

fn unrecognized_option(option: &[u8]) -> CliError {
    let mut message = program_name();
    message.extend_from_slice(b": unrecognized option '");
    message.extend_from_slice(option);
    message.extend_from_slice(b"'");
    CliError(message)
}

fn message_with_value(prefix: &[u8], value: &[u8]) -> CliError {
    let mut message = prefix.to_vec();
    message.extend_from_slice(value);
    CliError(message)
}

#[allow(clippy::needless_pass_by_value)] // `Result::map_err` transfers ownership here.
fn io_error_message(error: io::Error) -> CliError {
    CliError(io_error_text(&error))
}

fn io_error_text(error: &io::Error) -> Vec<u8> {
    if let Some(code) = error.raw_os_error() {
        // SAFETY: `strerror` returns a process-owned NUL-terminated string.
        let description = unsafe { libc::strerror(code) };
        if !description.is_null() {
            // SAFETY: the non-null pointer returned by `strerror` is NUL terminated.
            return unsafe { CStr::from_ptr(description) }.to_bytes().to_vec();
        }
    }
    error.to_string().into_bytes()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
    for (name, label) in [
        ("SYSTEMD_LOG_COLOR", "color"),
        ("SYSTEMD_LOG_LOCATION", "location"),
        ("SYSTEMD_LOG_TIME", "time"),
        ("SYSTEMD_LOG_TID", "tid"),
        ("SYSTEMD_LOG_RATELIMIT_KMSG", "ratelimit kmsg boolean"),
    ] {
        let Some(value) = env::var_os(name) else {
            continue;
        };
        if parse_boolean(value.as_os_str().as_bytes()).is_none() {
            let mut message = format!("Failed to parse log {label} '").into_bytes();
            message.extend_from_slice(value.as_os_str().as_bytes());
            message.extend_from_slice(b"', ignoring.");
            log_warning(&message);
        }
    }
}

fn log_target() -> LogTarget {
    static TARGET: OnceLock<LogTarget> = OnceLock::new();
    *TARGET.get_or_init(|| match env::var_os("SYSTEMD_LOG_TARGET") {
        None => LogTarget::Console,
        Some(value) => match value.as_os_str().as_bytes() {
            b"auto" | b"console" => LogTarget::Console,
            b"console-prefixed" => LogTarget::ConsolePrefixed,
            b"kmsg" => {
                if OpenOptions::new().write(true).open("/dev/kmsg").is_ok() {
                    LogTarget::Kmsg
                } else {
                    LogTarget::Console
                }
            }
            b"null" => LogTarget::Null,
            b"journal" | b"journal-or-kmsg" | b"syslog" | b"syslog-or-kmsg" => LogTarget::Other,
            invalid => {
                let mut message = b"Failed to parse log target '".to_vec();
                message.extend_from_slice(invalid);
                message.extend_from_slice(b"', ignoring.\n");
                let _ = io::stderr().lock().write_all(&message);
                LogTarget::Console
            }
        },
    })
}

fn log_level() -> u8 {
    static LEVEL: OnceLock<u8> = OnceLock::new();
    *LEVEL.get_or_init(configured_log_level)
}

fn configured_log_level() -> u8 {
    let Some(value) = env::var_os("SYSTEMD_LOG_LEVEL") else {
        return debug_invocation_level();
    };
    let raw = value.as_os_str().as_bytes();
    let Ok(value) = std::str::from_utf8(raw) else {
        warn_invalid_log_level(raw);
        return 6;
    };
    let mut global = 6u8;
    let mut target_maximum = 7u8;
    for word in value.split(',') {
        if let Some((target, level)) = word.split_once(':') {
            let Some(level) = parse_log_level(level) else {
                warn_invalid_log_level(raw);
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
                warn_invalid_log_level(raw);
                return global.min(target_maximum);
            }
            if log_filter_applies(target) {
                target_maximum = level;
            }
        } else if let Some(level) = parse_log_level(word) {
            global = level;
        } else {
            warn_invalid_log_level(raw);
            return global.min(target_maximum);
        }
    }
    global.min(target_maximum)
}

fn debug_invocation_level() -> u8 {
    let Some(value) = env::var_os("DEBUG_INVOCATION") else {
        return 6;
    };
    match parse_boolean(value.as_os_str().as_bytes()) {
        Some(true) => 7,
        Some(false) => 6,
        None => {
            startup_warning(b"Failed to parse $DEBUG_INVOCATION value, ignoring: Invalid argument");
            6
        }
    }
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

fn warn_invalid_log_level(value: &[u8]) {
    let mut message = b"Failed to parse log level '".to_vec();
    message.extend_from_slice(value);
    message.extend_from_slice(b"', ignoring: Invalid argument");
    match log_target() {
        LogTarget::Null => {}
        LogTarget::Other => {
            let _ = io::stderr().lock().write_all(&message);
            let _ = io::stderr().lock().write_all(b"\n");
        }
        _ => write_log(&message, 4),
    }
}

fn startup_warning(message: &[u8]) {
    match log_target() {
        LogTarget::Null => {}
        LogTarget::Other => {
            let mut stderr = io::stderr().lock();
            let _ = stderr.write_all(message);
            let _ = stderr.write_all(b"\n");
        }
        _ => write_log(message, 4),
    }
}

fn log_warning(message: &[u8]) {
    if log_level() >= 4 {
        if log_target() == LogTarget::Other {
            let mut stderr = io::stderr().lock();
            let _ = stderr.write_all(message);
            let _ = stderr.write_all(b"\n");
        } else {
            write_log(message, 4);
        }
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
        "<{}>systemd-vpick[{}]: ",
        24 + priority,
        std::process::id()
    )
    .and_then(|()| kmsg.write_all(message))
    .and_then(|()| kmsg.write_all(b"\n"))
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::{ellipsize, parse_tries, table_column_widths, version_compare, Architecture};
    use std::cmp::Ordering;

    #[test]
    fn improved_version_order_matches_upstream_examples() {
        let ordered: &[&[u8]] = &[
            b"~1",
            b"",
            b"ab",
            b"abb",
            b"abc",
            b"0001",
            b"002",
            b"12",
            b"122",
            b"122.9",
            b"123~rc1",
            b"123",
            b"123-a",
            b"123-a.1",
            b"123-a1",
            b"123-a1.1",
            b"123-3",
            b"123-3.1",
            b"123^patch1",
            b"123^1",
            b"123.a-1",
            b"123.1-1",
            b"123a-1",
            b"124",
        ];
        for (index, older) in ordered.iter().enumerate() {
            for newer in &ordered[index + 1..] {
                assert_eq!(version_compare(older, newer), Ordering::Less);
                assert_eq!(version_compare(newer, older), Ordering::Greater);
            }
        }
        assert_eq!(
            version_compare(b"123_aa2-67.89", b"123aa+2-67.89"),
            Ordering::Equal
        );
        assert_eq!(version_compare(b"0___", b"0"), Ordering::Equal);
    }

    #[test]
    fn attempt_suffix_parser_is_strict_and_bounded() {
        assert_eq!(parse_tries(b"+4"), Some((4, 0)));
        assert_eq!(parse_tries(b"+4-6"), Some((4, 6)));
        assert_eq!(parse_tries(b"+0-10"), Some((0, 10)));
        assert_eq!(parse_tries(b"+4294967295-0"), Some((u32::MAX, 0)));
        assert_eq!(parse_tries(b"+4294967296-0"), None);
        assert_eq!(parse_tries(b"+"), None);
        assert_eq!(parse_tries(b"+1-"), None);
        assert_eq!(parse_tries(b"1-2"), None);
    }

    #[test]
    fn architecture_names_round_trip() {
        for name in [b"x86-64".as_slice(), b"x86", b"arm64", b"s390", b"sparc64"] {
            let architecture = Architecture::parse(name).expect("known architecture");
            assert_eq!(architecture.name(), name);
        }
        assert!(Architecture::parse(b"x86_64").is_none());
    }

    #[test]
    fn table_widths_and_ellipsis_follow_vertical_table_allocation() {
        assert_eq!(table_column_widths(1, 13, 40), (1, 1));
        assert_eq!(table_column_widths(12, 13, 40), (5, 6));
        assert_eq!(table_column_widths(20, 13, 40), (9, 10));
        assert_eq!(table_column_widths(30, 13, 40), (13, 16));
        assert_eq!(table_column_widths(10, 13, 3), (6, 3));
        assert_eq!(ellipsize(b"Architecture:", 1, false), b".");
        assert_eq!(ellipsize(b"Architecture:", 4, false), b"A...");
        assert_eq!(ellipsize(b"Architecture:", 9, false), b"Archit...");
        assert_eq!(ellipsize(b"Path:", 5, false), b"Path:");
        assert_eq!(
            ellipsize("你好文件".as_bytes(), 5, false),
            "你好…".as_bytes()
        );
        assert_eq!(ellipsize(b"Architecture:", 9, true), "Architec…".as_bytes());
    }
}
