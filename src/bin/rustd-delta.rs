// SPDX-License-Identifier: LGPL-2.1-or-later
//! `systemd-delta` v261 compatibility utility.
//!
//! The scanner deliberately keeps the upstream path hierarchy and byte-wise
//! directory ordering.  The only process it starts is `diff -us -- ...`,
//! matching systemd-delta's `--diff` behavior.

use std::collections::BTreeMap;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

const VERSION: &str = concat!(
    "systemd 261 (261.2-1-arch)\n",
    "+PAM +AUDIT -SELINUX +APPARMOR -IMA +IPE +SMACK +SECCOMP +GCRYPT +GNUTLS +OPENSSL +ACL ",
    "+BLKID +CURL +ELFUTILS +FIDO2 +IDN2 +KMOD +LIBCRYPTSETUP +LIBCRYPTSETUP_PLUGINS +LIBFDISK ",
    "+PCRE2 +PWQUALITY +P11KIT +QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB +ZSTD +BPF_FRAMEWORK +BTF ",
    "+XKBCOMMON +UTMP +LIBARCHIVE\n"
);

const HELP: &str = concat!(
    "systemd-delta [OPTIONS...] [SUFFIX...]\n\n",
    "Find overridden configuration files.\n\n",
    "  -h --help          Show this help\n",
    "     --version       Show package version\n",
    "     --no-pager      Do not start a pager\n",
    "  -t --type=TYPE...  Only display a selected set of override types\n",
    "     --diff[=yes|no] Show a diff when overridden files differ\n\n",
    "See the systemd-delta(1) man page for details.\n"
);

const PREFIXES: &[&[u8]] = &[
    b"/etc",
    b"/run",
    b"/usr/local/lib",
    b"/usr/local/share",
    b"/usr/lib",
    b"/usr/share",
];

const SUFFIXES: &[&[u8]] = &[
    b"sysctl.d",
    b"tmpfiles.d",
    b"modules-load.d",
    b"binfmt.d",
    b"systemd/system",
    b"systemd/user",
    b"systemd/system-preset",
    b"systemd/user-preset",
    b"udev/rules.d",
    b"modprobe.d",
];

const DROPIN_SUFFIXES: &[&[u8]] = &[b"systemd/system", b"systemd/user"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Types(u8);

impl Types {
    const MASKED: Self = Self(1 << 0);
    const EQUIVALENT: Self = Self(1 << 1);
    const REDIRECTED: Self = Self(1 << 2);
    const OVERRIDDEN: Self = Self(1 << 3);
    const UNCHANGED: Self = Self(1 << 4);
    const EXTENDED: Self = Self(1 << 5);
    const DEFAULT: Self = Self(
        Self::MASKED.0
            | Self::EQUIVALENT.0
            | Self::REDIRECTED.0
            | Self::OVERRIDDEN.0
            | Self::EXTENDED.0,
    );

    const fn empty() -> Self {
        Self(0)
    }

    const fn contains(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }
}

#[derive(Debug)]
struct Options {
    types: Types,
    diff: Option<bool>,
    no_pager: bool,
    args: Vec<OsString>,
}

#[derive(Debug)]
enum ParseResult {
    Run(Options),
    Exit(&'static [u8]),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Masked,
    Equivalent,
    Redirected,
    Overridden,
}

#[derive(Debug)]
struct Scan {
    entries: Vec<ScanEntry>,
    entry_indices: BTreeMap<Vec<u8>, usize>,
    drops: Vec<DropGroup>,
    drop_indices: BTreeMap<Vec<u8>, usize>,
}

#[derive(Debug)]
struct ScanEntry {
    key: Vec<u8>,
    top: PathBuf,
    bottom: PathBuf,
}

#[derive(Debug)]
struct DropGroup {
    entries: Vec<(Vec<u8>, PathBuf)>,
}

impl Scan {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            entry_indices: BTreeMap::new(),
            drops: Vec::new(),
            drop_indices: BTreeMap::new(),
        }
    }

    fn put_top(&mut self, directory: &Path, name: &OsStr) {
        let key = name.as_bytes().to_vec();
        if self.entry_indices.contains_key(&key) {
            return;
        }
        self.entry_indices.insert(key.clone(), self.entries.len());
        let path = directory.join(name);
        self.entries.push(ScanEntry {
            key,
            top: path.clone(),
            bottom: path,
        });
    }

    fn put_bottom(&mut self, directory: &Path, name: &OsStr) {
        let index = self.entry_indices[name.as_bytes()];
        self.entries[index].bottom = directory.join(name);
    }

    fn put_drop(&mut self, unit: &[u8], directory: &Path, name: &OsStr) {
        let index = if let Some(index) = self.drop_indices.get(unit) {
            *index
        } else {
            let index = self.drops.len();
            self.drop_indices.insert(unit.to_vec(), index);
            self.drops.push(DropGroup {
                entries: Vec::new(),
            });
            index
        };
        let key = name.as_bytes();
        if self.drops[index]
            .entries
            .iter()
            .any(|(existing, _)| existing == key)
        {
            return;
        }
        self.drops[index]
            .entries
            .push((key.to_vec(), directory.join(name)));
    }
}

fn main() {
    let arguments: Vec<OsString> = env::args_os().skip(1).collect();
    match parse_options(&arguments) {
        Ok(ParseResult::Exit(output)) => {
            let _ = io::stdout().write_all(output);
        }
        Ok(ParseResult::Run(options)) => {
            if let Err(error) = run(&options) {
                let _ = io::stderr().write_all(&error);
                let _ = io::stderr().write_all(b"\n");
                std::process::exit(1);
            }
        }
        Err(error) => {
            let _ = io::stderr().write_all(&error);
            let _ = io::stderr().write_all(b"\n");
            std::process::exit(1);
        }
    }
}

fn parse_options(arguments: &[OsString]) -> Result<ParseResult, Vec<u8>> {
    let mut types = Types::empty();
    let mut diff = None;
    let mut no_pager = false;
    let mut args = Vec::new();
    let mut index = 0usize;
    let mut positional = false;

    while index < arguments.len() {
        let raw = arguments[index].as_os_str().as_bytes();
        if positional || raw == b"-" || !raw.starts_with(b"-") {
            args.push(arguments[index].clone());
            index += 1;
            continue;
        }
        if raw == b"--" {
            positional = true;
            index += 1;
            continue;
        }
        if raw.starts_with(b"-") && !raw.starts_with(b"--") {
            if let Some(result) = parse_short(raw, arguments, &mut index, &mut types)? {
                return Ok(result);
            }
            index += 1;
            continue;
        }

        let Some(long) = raw.strip_prefix(b"--") else {
            return Err(unrecognized_option(raw));
        };
        let (name, value) = long
            .iter()
            .position(|byte| *byte == b'=')
            .map_or((long, None), |position| {
                (&long[..position], Some(&long[position + 1..]))
            });
        let resolved = resolve_long(name)?;
        match resolved {
            b"help" => {
                if value.is_some() {
                    return Err(unexpected_argument(name));
                }
                return Ok(ParseResult::Exit(HELP.as_bytes()));
            }
            b"version" => {
                if value.is_some() {
                    return Err(unexpected_argument(name));
                }
                return Ok(ParseResult::Exit(VERSION.as_bytes()));
            }
            b"no-pager" => {
                if value.is_some() {
                    return Err(unexpected_argument(name));
                }
                no_pager = true;
            }
            b"type" => {
                let value = if let Some(value) = value {
                    value
                } else {
                    index += 1;
                    let Some(next) = arguments.get(index) else {
                        let mut display = b"--".to_vec();
                        display.extend_from_slice(name);
                        return Err(missing_argument(&display));
                    };
                    next.as_os_str().as_bytes()
                };
                add_types(&mut types, value)?;
            }
            b"diff" => {
                diff = Some(value.map_or(Ok(true), |value| {
                    parse_bool(value).map_err(|()| {
                        let mut error = b"Failed to parse boolean argument to '--diff': ".to_vec();
                        error.extend_from_slice(value);
                        error
                    })
                })?);
            }
            _ => unreachable!("resolved long option"),
        }
        index += 1;
    }

    Ok(ParseResult::Run(Options {
        types,
        diff,
        no_pager,
        args,
    }))
}

fn parse_short(
    raw: &[u8],
    arguments: &[OsString],
    index: &mut usize,
    types: &mut Types,
) -> Result<Option<ParseResult>, Vec<u8>> {
    let Some((&option, rest)) = raw[1..].split_first() else {
        return Ok(None);
    };
    match option {
        b'h' => Ok(Some(ParseResult::Exit(HELP.as_bytes()))),
        b't' => {
            let value = if rest.is_empty() {
                *index += 1;
                let Some(next) = arguments.get(*index) else {
                    return Err(missing_argument(b"-t"));
                };
                next.as_os_str().as_bytes()
            } else {
                rest
            };
            add_types(types, value)?;
            Ok(None)
        }
        unknown => Err(unrecognized_short(unknown)),
    }
}

fn unrecognized_option(raw: &[u8]) -> Vec<u8> {
    let mut error = b"systemd-delta: unrecognized option '".to_vec();
    error.extend_from_slice(raw);
    error.extend_from_slice(b"'");
    error
}

fn unrecognized_short(option: u8) -> Vec<u8> {
    unrecognized_option(&[b'-', option])
}

fn missing_argument(option: &[u8]) -> Vec<u8> {
    let mut error = b"systemd-delta: option '".to_vec();
    error.extend_from_slice(option);
    error.extend_from_slice(b"' requires an argument");
    error
}

fn unexpected_argument(name: &[u8]) -> Vec<u8> {
    let mut error = b"systemd-delta: option '--".to_vec();
    error.extend_from_slice(name);
    error.extend_from_slice(b"' doesn't allow an argument");
    error
}

fn resolve_long(name: &[u8]) -> Result<&'static [u8], Vec<u8>> {
    const OPTIONS: [&[u8]; 5] = [b"help", b"version", b"no-pager", b"type", b"diff"];
    let matching: Vec<_> = OPTIONS
        .iter()
        .copied()
        .filter(|candidate| candidate.starts_with(name))
        .collect();
    match matching.as_slice() {
        [resolved] => Ok(*resolved),
        [] => {
            let mut raw = b"--".to_vec();
            raw.extend_from_slice(name);
            Err(unrecognized_option(&raw))
        }
        options => {
            let mut error = b"systemd-delta: option '--".to_vec();
            error.extend_from_slice(name);
            error.extend_from_slice(b"' is ambiguous; possibilities:");
            for option in options {
                error.extend_from_slice(b" --");
                error.extend_from_slice(option);
                error.push(b',');
            }
            error.pop();
            Err(error)
        }
    }
}

fn parse_bool(value: &[u8]) -> Result<bool, ()> {
    match value {
        b"1" | b"yes" | b"y" | b"true" | b"t" | b"on" => Ok(true),
        b"0" | b"no" | b"n" | b"false" | b"f" | b"off" => Ok(false),
        _ => Err(()),
    }
}

fn add_types(result: &mut Types, value: &[u8]) -> Result<(), Vec<u8>> {
    for word in value.split(|byte| *byte == b',') {
        let flag = match word {
            b"masked" => Types::MASKED,
            b"equivalent" => Types::EQUIVALENT,
            b"redirected" => Types::REDIRECTED,
            b"overridden" => Types::OVERRIDDEN,
            b"unchanged" => Types::UNCHANGED,
            b"extended" => Types::EXTENDED,
            b"default" => Types::DEFAULT,
            _ => return Err(b"Failed to parse flags field.".to_vec()),
        };
        result.insert(flag);
    }
    Ok(())
}

fn run(options: &Options) -> Result<(), Vec<u8>> {
    let mut types = options.types;
    if types == Types::empty() {
        types = Types::DEFAULT;
    }
    let diff = options.diff.unwrap_or(types.contains(Types::OVERRIDDEN));
    if diff {
        types.insert(Types::OVERRIDDEN);
    }

    let mut output = Vec::new();
    let mut found = 0usize;
    let mut deferred_errors = Vec::new();
    if options.args.is_empty() {
        for suffix in SUFFIXES {
            match process_suffix(suffix, None, types, diff, &mut output) {
                Ok(count) => found = found.saturating_add(count),
                Err(error) => deferred_errors.push(error),
            }
        }
    } else {
        for argument in &options.args {
            let simplified = simplify_path(argument.as_os_str());
            match process_selector(simplified.as_os_str(), types, diff, &mut output) {
                Ok(count) => found = found.saturating_add(count),
                Err(error) => deferred_errors.push(error),
            }
        }
    }

    if deferred_errors.is_empty() {
        if found > 0 {
            output.push(b'\n');
        }
        output.extend_from_slice(found.to_string().as_bytes());
        output.extend_from_slice(b" overridden configuration files found.\n");
    }
    emit_output(options.no_pager, &output)?;
    combine_errors(deferred_errors).map_or(Ok(()), Err)
}

fn process_selector(
    argument: &OsStr,
    types: Types,
    diff: bool,
    output: &mut Vec<u8>,
) -> Result<usize, Vec<u8>> {
    let bytes = argument.as_bytes();
    if !bytes.starts_with(b"/") {
        return process_suffix(bytes, None, types, diff, output);
    }

    for prefix in PREFIXES {
        if bytes.starts_with(prefix) {
            let mut suffix = &bytes[prefix.len()..];
            while suffix.starts_with(b"/") {
                suffix = &suffix[1..];
            }
            if suffix.is_empty() {
                let mut found = 0usize;
                let mut errors = Vec::new();
                for candidate in SUFFIXES {
                    match process_suffix(candidate, Some(prefix), types, diff, output) {
                        Ok(count) => found = found.saturating_add(count),
                        Err(error) => errors.push(error),
                    }
                }
                return combine_errors(errors).map_or(Ok(found), Err);
            }
            return process_suffix(suffix, Some(prefix), types, diff, output);
        }
    }

    let mut error = b"Invalid suffix specification ".to_vec();
    error.extend_from_slice(bytes);
    error.push(b'.');
    Err(error)
}

fn process_suffix(
    suffix: &[u8],
    only_prefix: Option<&[u8]>,
    types: Types,
    diff: bool,
    output: &mut Vec<u8>,
) -> Result<usize, Vec<u8>> {
    let mut scan = Scan::new();
    let mut deferred_errors = Vec::new();
    let dropins = DROPIN_SUFFIXES.contains(&suffix);

    for prefix in PREFIXES {
        let path = join_bytes(prefix, suffix);
        if let Err(error) = enumerate_directory(&mut scan, &path, dropins) {
            deferred_errors.push(error);
        }
    }

    let mut found = 0usize;
    for entry in &scan.entries {
        let top = &entry.top;
        let bottom = &entry.bottom;
        if only_prefix.is_some_and(|prefix| !path_starts_with(bottom, prefix)) {
            continue;
        }

        if same_path(top, bottom) {
            if types.contains(Types::UNCHANGED) {
                emit_unchanged(output, top);
            }
        } else {
            let kind = classify(top, bottom);
            if emit_kind(kind, top, bottom, types, output) {
                found += 1;
            }
            if kind == Kind::Overridden && types.contains(Types::OVERRIDDEN) && diff {
                emit_diff(top, bottom, output);
            }
        }

        if let Some(index) = scan.drop_indices.get(&entry.key) {
            for (_, dropin) in &scan.drops[*index].entries {
                if only_prefix.map_or(true, |prefix| path_starts_with(dropin, prefix))
                    && types.contains(Types::EXTENDED)
                {
                    emit_extended(output, top, dropin);
                    found += 1;
                }
            }
        }
    }
    combine_errors(deferred_errors).map_or(Ok(found), Err)
}

fn combine_errors(errors: Vec<Vec<u8>>) -> Option<Vec<u8>> {
    if errors.is_empty() {
        return None;
    }
    let total = errors.iter().map(Vec::len).sum::<usize>() + errors.len() - 1;
    let mut combined = Vec::with_capacity(total);
    for (index, error) in errors.into_iter().enumerate() {
        if index > 0 {
            combined.push(b'\n');
        }
        combined.extend_from_slice(&error);
    }
    Some(combined)
}

fn enumerate_directory(scan: &mut Scan, path: &Path, dropins: bool) -> Result<(), Vec<u8>> {
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(io_error(path, &error)),
    };
    let mut files = Vec::new();
    let mut directories = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| io_error(path, &error))?;
        let name = entry.file_name();
        let file_type = entry
            .file_type()
            .map_err(|error| io_error(&entry.path(), &error))?;
        if dropins && file_type.is_dir() && name.as_bytes().ends_with(b".d") {
            directories.push(name.clone());
        }
        if file_type.is_file() || file_type.is_symlink() {
            if !visible_name(name.as_bytes()) {
                continue;
            }
            files.push(name);
        }
    }
    files.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    directories.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

    for directory in directories {
        let drop_path = path.join(&directory);
        let mut unit = directory.as_bytes().to_vec();
        let Some(dot) = unit.iter().rposition(|byte| *byte == b'.') else {
            return Err(b"Invalid drop-in directory.".to_vec());
        };
        unit.truncate(dot);
        let drop_entries =
            fs::read_dir(&drop_path).map_err(|error| io_error(&drop_path, &error))?;
        let mut drop_files = Vec::new();
        for entry in drop_entries {
            let entry = entry.map_err(|error| io_error(&drop_path, &error))?;
            let name = entry.file_name();
            let file_type = entry
                .file_type()
                .map_err(|error| io_error(&entry.path(), &error))?;
            if (file_type.is_file() || file_type.is_symlink())
                && visible_name(name.as_bytes())
                && name.as_bytes().ends_with(b".conf")
            {
                drop_files.push(name);
            }
        }
        drop_files.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        for file in drop_files {
            scan.put_top(&drop_path, &file);
            scan.put_bottom(&drop_path, &file);
            scan.put_drop(&unit, &drop_path, &file);
        }
    }

    for file in files {
        scan.put_top(path, &file);
        scan.put_bottom(path, &file);
    }
    Ok(())
}

fn visible_name(name: &[u8]) -> bool {
    if name.first() == Some(&b'.')
        || name == b"lost+found"
        || name == b"aquota.user"
        || name == b"aquota.group"
        || name.ends_with(b"~")
    {
        return false;
    }
    let Some(dot) = name.iter().rposition(|byte| *byte == b'.') else {
        return true;
    };
    !matches!(
        &name[dot + 1..],
        b"ignore"
            | b"rpmnew"
            | b"rpmsave"
            | b"rpmorig"
            | b"dpkg-old"
            | b"dpkg-new"
            | b"dpkg-tmp"
            | b"dpkg-dist"
            | b"dpkg-bak"
            | b"dpkg-backup"
            | b"dpkg-remove"
            | b"ucf-new"
            | b"ucf-old"
            | b"ucf-dist"
            | b"swp"
            | b"bak"
            | b"old"
            | b"new"
    )
}

fn classify(top: &Path, bottom: &Path) -> Kind {
    if null_or_empty(top) {
        return Kind::Masked;
    }
    if let Ok(target) = fs::read_link(top) {
        // Upstream intentionally compares the raw readlink() payload here.
        // Relative targets are therefore resolved against the process cwd,
        // not against the directory containing `top`.
        if equivalent(&target, bottom) {
            Kind::Equivalent
        } else {
            Kind::Redirected
        }
    } else {
        Kind::Overridden
    }
}

fn null_or_empty(path: &Path) -> bool {
    if path.is_symlink() {
        let Ok(target) = fs::read_link(path) else {
            return false;
        };
        return equivalent(&resolve_link(path, &target), Path::new("/dev/null"));
    }
    fs::metadata(path).is_ok_and(|metadata| metadata.is_file() && metadata.len() == 0)
}

fn resolve_link(path: &Path, target: &Path) -> PathBuf {
    if target.is_absolute() {
        target.to_path_buf()
    } else {
        path.parent().unwrap_or_else(|| Path::new("/")).join(target)
    }
}

fn equivalent(left: &Path, right: &Path) -> bool {
    let left = fs::canonicalize(left);
    let right = fs::canonicalize(right);
    match (left, right) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

fn same_path(left: &Path, right: &Path) -> bool {
    left == right
}

fn path_starts_with(path: &Path, prefix: &[u8]) -> bool {
    path.as_os_str().as_bytes().starts_with(prefix)
}

fn join_bytes(left: &[u8], right: &[u8]) -> PathBuf {
    let mut bytes = left.to_vec();
    if !bytes.ends_with(b"/") {
        bytes.push(b'/');
    }
    bytes.extend_from_slice(right);
    PathBuf::from(OsString::from_vec(bytes))
}

fn simplify_path(path: &OsStr) -> OsString {
    let bytes = path.as_bytes();
    let absolute = bytes.starts_with(b"/");
    let mut components: Vec<Vec<u8>> = Vec::new();
    for component in Path::new(path).components() {
        match component {
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
            Component::ParentDir => {
                if components
                    .last()
                    .is_some_and(|part| part.as_slice() != b"..")
                {
                    components.pop();
                } else if !absolute {
                    components.push(b"..".to_vec());
                }
            }
            Component::Normal(value) => components.push(value.as_bytes().to_vec()),
        }
    }
    let mut result = Vec::new();
    if absolute {
        result.push(b'/');
    }
    for (index, component) in components.iter().enumerate() {
        if index > 0 {
            result.push(b'/');
        }
        result.extend_from_slice(component);
    }
    if result.is_empty() {
        result.push(if absolute { b'/' } else { b'.' });
    }
    OsString::from_vec(result)
}

fn emit_kind(kind: Kind, top: &Path, bottom: &Path, types: Types, output: &mut Vec<u8>) -> bool {
    let (flag, label, spaces, color) = match kind {
        Kind::Masked => (Types::MASKED, b"[MASKED]".as_slice(), 5, Color::Red),
        Kind::Equivalent => (
            Types::EQUIVALENT,
            b"[EQUIVALENT]".as_slice(),
            1,
            Color::Green,
        ),
        Kind::Redirected => (
            Types::REDIRECTED,
            b"[REDIRECTED]".as_slice(),
            1,
            Color::Highlight,
        ),
        Kind::Overridden => (
            Types::OVERRIDDEN,
            b"[OVERRIDDEN]".as_slice(),
            1,
            Color::Highlight,
        ),
    };
    if !types.contains(flag) {
        return false;
    }
    emit_label(output, label, spaces, color);
    emit_path(output, top);
    output.extend_from_slice(glyph_arrow());
    emit_path(output, bottom);
    output.push(b'\n');
    true
}

fn emit_extended(output: &mut Vec<u8>, top: &Path, dropin: &Path) {
    emit_label(output, b"[EXTENDED]", 3, Color::Highlight);
    emit_path(output, top);
    output.extend_from_slice(glyph_arrow());
    emit_path(output, dropin);
    output.push(b'\n');
}

fn emit_unchanged(output: &mut Vec<u8>, path: &Path) {
    output.extend_from_slice(b"[UNCHANGED]  ");
    emit_path(output, path);
    output.push(b'\n');
}

#[derive(Clone, Copy)]
enum Color {
    Red,
    Green,
    Highlight,
}

fn emit_label(output: &mut Vec<u8>, label: &[u8], spaces: usize, color: Color) {
    let (start, end) = color_codes(color);
    if color_enabled() {
        output.extend_from_slice(start);
    }
    output.extend_from_slice(label);
    if color_enabled() {
        output.extend_from_slice(end);
    }
    output.extend(std::iter::repeat(b' ').take(spaces));
}

fn emit_path(output: &mut Vec<u8>, path: &Path) {
    output.extend_from_slice(path.as_os_str().as_bytes());
}

fn emit_diff(top: &Path, bottom: &Path, output: &mut Vec<u8>) {
    output.push(b'\n');
    let result = Command::new("diff")
        .args([
            OsStr::new("-us"),
            OsStr::new("--"),
            bottom.as_os_str(),
            top.as_os_str(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();
    match result {
        Ok(result) => {
            output.extend_from_slice(&result.stdout);
            if !result.stderr.is_empty() {
                let _ = io::stderr().write_all(&result.stderr);
            }
        }
        Err(error) => {
            let _ = writeln!(io::stderr(), "Failed to execute diff: {error}");
        }
    }
    output.push(b'\n');
}

fn color_enabled() -> bool {
    match env::var("SYSTEMD_COLORS").ok().as_deref() {
        Some("0" | "no" | "false" | "off") => false,
        Some(_) => true,
        None => io::stdout().is_terminal() && env::var("TERM").ok().as_deref() != Some("dumb"),
    }
}

fn color_codes(color: Color) -> (&'static [u8], &'static [u8]) {
    match color {
        Color::Red => (b"\x1b[0;1;31m", b"\x1b[0m"),
        Color::Green => (b"\x1b[0;1;32m", b"\x1b[0m"),
        Color::Highlight => (b"\x1b[0;1;39m", b"\x1b[0m"),
    }
}

fn glyph_arrow() -> &'static [u8] {
    if utf8_locale() {
        b" \xE2\x86\x92 "
    } else {
        b" -> "
    }
}

fn utf8_locale() -> bool {
    env::var_os("LC_ALL")
        .or_else(|| env::var_os("LC_CTYPE"))
        .or_else(|| env::var_os("LANG"))
        .is_some_and(|value| {
            let bytes = value.as_bytes();
            bytes
                .windows(5)
                .any(|window| window.eq_ignore_ascii_case(b"utf-8"))
                || bytes
                    .windows(4)
                    .any(|window| window.eq_ignore_ascii_case(b"utf8"))
        })
}

fn emit_output(no_pager: bool, output: &[u8]) -> Result<(), Vec<u8>> {
    if no_pager || !io::stdout().is_terminal() || env::var("TERM").ok().as_deref() == Some("dumb") {
        return io::stdout()
            .write_all(output)
            .map_err(|error| error.to_string().into_bytes());
    }
    let pager = env::var("SYSTEMD_PAGER")
        .ok()
        .or_else(|| env::var("PAGER").ok())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| String::from("less"));
    if pager.split_ascii_whitespace().eq(["cat"]) {
        return io::stdout()
            .write_all(output)
            .map_err(|error| error.to_string().into_bytes());
    }
    let mut child = Command::new("sh")
        .args(["-c", &format!("exec {pager}")])
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|error| format!("Failed to create pager: {error}").into_bytes())?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(output)
            .map_err(|error| error.to_string().into_bytes())?;
    }
    child
        .wait()
        .map_err(|error| format!("Failed to wait for pager: {error}").into_bytes())?;
    Ok(())
}

fn io_error(path: &Path, error: &io::Error) -> Vec<u8> {
    let mut message = b"Failed to open ".to_vec();
    message.extend_from_slice(path.as_os_str().as_bytes());
    message.extend_from_slice(b": ");
    message.extend_from_slice(error.to_string().as_bytes());
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use tempfile::tempdir;

    #[test]
    fn parses_all_types_and_defaults() {
        let mut types = Types::empty();
        add_types(&mut types, b"default,unchanged").unwrap();
        assert_eq!(types, Types(0x3f));
        assert!(add_types(&mut types, b"unknown").is_err());
    }

    #[test]
    fn classifies_empty_mask_and_equivalent_link() {
        let root = tempdir().unwrap();
        let lower = root.path().join("lower");
        let upper = root.path().join("upper");
        fs::create_dir_all(&lower).unwrap();
        fs::create_dir_all(&upper).unwrap();
        fs::write(lower.join("unit"), b"unit").unwrap();
        fs::write(upper.join("masked"), b"").unwrap();
        symlink(lower.join("unit"), upper.join("equivalent")).unwrap();
        assert_eq!(
            classify(&upper.join("masked"), &lower.join("unit")),
            Kind::Masked
        );
        assert_eq!(
            classify(&upper.join("equivalent"), &lower.join("unit")),
            Kind::Equivalent
        );
    }

    #[test]
    fn hidden_and_backup_names_match_upstream_filter() {
        assert!(!visible_name(b".hidden"));
        assert!(!visible_name(b"unit.rpmnew"));
        assert!(!visible_name(b"unit~"));
        assert!(visible_name(b"unit.service"));
    }
}
