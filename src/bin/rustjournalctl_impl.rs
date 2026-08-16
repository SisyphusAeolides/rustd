// SPDX-License-Identifier: LGPL-2.1-or-later
// rustjournalctl — query and display the system journal.
//
// Historical reference: journal query behavior originated from the v261 implementation.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustd::journal::catalog::{
    database_path as catalog_database_path, expand_fields as expand_catalog_fields,
    format_id as format_catalog_id, header_value as catalog_header_value,
    output_prefix as catalog_output_prefix, parse_id as parse_catalog_id,
    source_directories as catalog_source_directories, update_database as update_catalog_database,
    CatalogDatabase,
};
use rustd::journal::compression::decompress_payload;
use rustd::journal::entry::{current_boot_id, priority, EntryRing, JournalEntry};
use rustd::journal::receiver::JournalReceiver;

const VERSION_OUTPUT: &str = concat!(
    "systemd 261 (261.2-1-arch)\n",
    "+PAM +AUDIT -SELINUX +APPARMOR -IMA +IPE +SMACK +SECCOMP +GCRYPT +GNUTLS +OPENSSL +ACL ",
    "+BLKID +CURL +ELFUTILS +FIDO2 +IDN2 +KMOD +LIBCRYPTSETUP +LIBCRYPTSETUP_PLUGINS +LIBFDISK ",
    "+PCRE2 +PWQUALITY +P11KIT +QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB +ZSTD +BPF_FRAMEWORK +BTF ",
    "+XKBCOMMON +UTMP +LIBARCHIVE\n"
);

// ── Entry point ───────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "--version") {
        print!("{VERSION_OUTPUT}");
        return;
    }
    let opts = match Options::parse(&args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("rustjournalctl: {e}");
            std::process::exit(1);
        }
    };

    if opts.help {
        print_help();
        std::process::exit(0);
    }

    if opts.catalog_action != CatalogAction::Show {
        if let Err(error) = run_catalog_action(&opts) {
            eprintln!("rustjournalctl: {error}");
            std::process::exit(1);
        }
        std::process::exit(0);
    }

    let catalog = if opts.catalog {
        CatalogDatabase::open(&catalog_database_path()).ok()
    } else {
        None
    };

    let entries = match load_entries(&opts) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("rustjournalctl: {e}");
            std::process::exit(1);
        }
    };

    let boot_id = match resolve_boot_id(&entries, &opts.boot) {
        Ok(boot_id) => boot_id,
        Err(error) => {
            eprintln!("rustjournalctl: {error}");
            std::process::exit(1);
        }
    };
    let filtered = filter_entries(&entries, &opts, boot_id.as_deref());

    let limited: Vec<&JournalEntry> = if let Some(n) = opts.last_n {
        filtered.iter().rev().take(n).rev().copied().collect()
    } else {
        filtered
    };

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for entry in &limited {
        print_entry(&mut out, entry, &opts.output);
        print_catalog_for_entry(&mut out, entry, catalog.as_ref());
    }

    if opts.follow {
        follow_mode(&mut out, &opts, boot_id.as_deref(), catalog.as_ref());
    }

    std::process::exit(0);
}

// ── Options ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
enum BootSelection {
    All,
    Current,
    Offset(i64),
    Id { id: String, offset: i64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CatalogAction {
    Show,
    Update,
    List,
    Dump,
}

#[derive(Debug)]
struct Options {
    unit: Option<String>,
    boot: BootSelection,
    output: String,
    last_n: Option<usize>,
    follow: bool,
    file: Option<PathBuf>,
    help: bool,
    matches: Vec<(String, String)>,
    priority_max: u8,
    catalog: bool,
    catalog_action: CatalogAction,
    catalog_ids: Vec<String>,
}

impl Options {
    fn parse(args: &[String]) -> anyhow::Result<Self> {
        let mut opts = Self {
            unit: None,
            boot: BootSelection::All,
            output: "short".into(),
            last_n: None,
            follow: false,
            file: None,
            help: false,
            matches: Vec::new(),
            priority_max: priority::DEBUG,
            catalog: false,
            catalog_action: CatalogAction::Show,
            catalog_ids: Vec::new(),
        };
        let mut index = 0;
        while index < args.len() {
            let argument = &args[index];
            match argument.as_str() {
                "--help" | "-h" => opts.help = true,
                "--follow" | "-f" => opts.follow = true,
                "--catalog" | "-x" => opts.catalog = true,
                "--update-catalog" => opts.catalog_action = CatalogAction::Update,
                "--list-catalog" => opts.catalog_action = CatalogAction::List,
                "--dump-catalog" => opts.catalog_action = CatalogAction::Dump,
                "--boot" | "-b" => {
                    let candidate = args.get(index + 1).map(String::as_str);
                    if candidate.is_some_and(is_boot_selector) {
                        opts.boot = parse_boot_selection(candidate)?;
                        index += 1;
                    } else {
                        opts.boot = BootSelection::Current;
                    }
                }
                "-u" | "--unit" => {
                    index += 1;
                    opts.unit = args.get(index).cloned();
                }
                "-n" | "--lines" => {
                    index += 1;
                    let n = args
                        .get(index)
                        .and_then(|value| value.parse().ok())
                        .ok_or_else(|| anyhow::anyhow!("-n requires a number"))?;
                    opts.last_n = Some(n);
                }
                "-o" | "--output" => {
                    index += 1;
                    opts.output = args
                        .get(index)
                        .cloned()
                        .ok_or_else(|| anyhow::anyhow!("-o requires an argument"))?;
                }
                "--file" => {
                    index += 1;
                    opts.file = args.get(index).map(PathBuf::from);
                }
                "-p" | "--priority" => {
                    index += 1;
                    let p: u8 = args
                        .get(index)
                        .and_then(|value| parse_priority(value))
                        .ok_or_else(|| anyhow::anyhow!("-p requires a priority"))?;
                    opts.priority_max = p;
                }
                _ if argument.starts_with("--boot=") => {
                    opts.boot = parse_boot_selection(argument.strip_prefix("--boot="))?;
                }
                _ if argument.starts_with("-b") && argument.len() > 2 => {
                    opts.boot = parse_boot_selection(Some(&argument[2..]))?;
                }
                _ if argument.starts_with('-') => {}
                _ if argument.contains('=') => {
                    let (key, value) = argument.split_once('=').expect("contains '='");
                    opts.matches
                        .push((key.to_ascii_uppercase(), value.to_owned()));
                }
                _ => opts.catalog_ids.push(argument.clone()),
            }
            index += 1;
        }
        Ok(opts)
    }
}

fn is_boot_selector(value: &str) -> bool {
    parse_boot_selection(Some(value)).is_ok()
}

fn parse_boot_selection(value: Option<&str>) -> anyhow::Result<BootSelection> {
    let value = value.unwrap_or_default();
    if value.is_empty() {
        return Ok(BootSelection::Current);
    }
    if value == "all" {
        return Ok(BootSelection::All);
    }

    if value.len() >= 32 {
        let (id, remainder) = value.split_at(32);
        if let Some(id) = normalize_boot_id(id) {
            let offset = if remainder.is_empty() {
                0
            } else if remainder.starts_with('+') || remainder.starts_with('-') {
                remainder
                    .parse::<i64>()
                    .map_err(|_| anyhow::anyhow!("invalid boot offset '{remainder}'"))?
            } else {
                return Err(anyhow::anyhow!("invalid boot selector '{value}'"));
            };
            return Ok(BootSelection::Id { id, offset });
        }
    }

    value
        .parse::<i64>()
        .map(BootSelection::Offset)
        .map_err(|_| anyhow::anyhow!("invalid boot selector '{value}'"))
}

fn parse_priority(s: &str) -> Option<u8> {
    match s {
        "0" | "emerg" => Some(0),
        "1" | "alert" => Some(1),
        "2" | "crit" => Some(2),
        "3" | "err" | "error" => Some(3),
        "4" | "warning" | "warn" => Some(4),
        "5" | "notice" => Some(5),
        "6" | "info" => Some(6),
        "7" | "debug" => Some(7),
        _ => s.parse().ok(),
    }
}

fn run_catalog_action(opts: &Options) -> anyhow::Result<()> {
    let database_path = catalog_database_path();
    match opts.catalog_action {
        CatalogAction::Show => Ok(()),
        CatalogAction::Update => {
            update_catalog_database(&database_path, &catalog_source_directories())?;
            Ok(())
        }
        CatalogAction::List | CatalogAction::Dump => {
            let database = CatalogDatabase::open(&database_path)?;
            let ids = if opts.catalog_ids.is_empty() {
                database.ids()
            } else {
                opts.catalog_ids
                    .iter()
                    .map(|value| parse_catalog_id(value))
                    .collect::<anyhow::Result<Vec<_>>>()?
            };
            let stdout = std::io::stdout();
            let mut output = stdout.lock();
            for id in ids {
                let text = database.lookup(&id).ok_or_else(|| {
                    anyhow::anyhow!("catalog entry {} not found", format_catalog_id(&id))
                })?;
                if opts.catalog_action == CatalogAction::List {
                    let defined_by = catalog_header_value(text, "Defined-By:").unwrap_or("n/a");
                    let subject = catalog_header_value(text, "Subject:").unwrap_or("n/a");
                    writeln!(output, "{} {defined_by}: {subject}", format_catalog_id(&id))?;
                } else {
                    write!(output, "-- {}\n{text}\n", format_catalog_id(&id))?;
                }
            }
            Ok(())
        }
    }
}

// ── Entry loading ───────────────────────────────────────────────────────────

fn load_entries(opts: &Options) -> anyhow::Result<Vec<JournalEntry>> {
    if let Some(ref path) = opts.file {
        return load_from_file(path);
    }
    if let Ok(entries) = load_from_ipc() {
        return Ok(entries);
    }
    Ok(load_from_journal_dir())
}

fn load_from_ipc() -> anyhow::Result<Vec<JournalEntry>> {
    use std::os::unix::net::UnixStream;
    use rustd::ipc::{decode_response, encode_request, IpcRequest};
    const IPC_SOCK: &str = "/run/rustd/ctl.sock";
    let mut stream = UnixStream::connect(IPC_SOCK).map_err(|e| anyhow::anyhow!("connect: {e}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(&encode_request(&IpcRequest::ListUnits)?)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    let _resp = decode_response(&buf)?;
    Err(anyhow::anyhow!("IPC does not serve journal entries yet"))
}

fn load_from_journal_dir() -> Vec<JournalEntry> {
    let machine_id = read_machine_id();
    let dir = if machine_id.is_empty() {
        PathBuf::from("/var/log/journal")
    } else {
        PathBuf::from(format!("/var/log/journal/{machine_id}"))
    };
    let mut all = Vec::new();
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) == Some("journal") {
                candidates.push(p);
            }
        }
    }
    for path in candidates {
        if let Ok(mut entries) = load_from_file(&path) {
            all.append(&mut entries);
        }
    }
    all.sort_by_key(|e| e.seqnum);
    all
}

/// Read entries from a binary systemd journal file.
///
/// The current writer emits the upstream regular object layout. The reader
/// also accepts upstream compact entry/data layouts and retains a migration
/// path for journal files produced by the repository's earlier private
/// 264-byte format.
fn load_from_file(path: &Path) -> anyhow::Result<Vec<JournalEntry>> {
    let data =
        std::fs::read(path).map_err(|error| anyhow::anyhow!("read {}: {error}", path.display()))?;
    if data.len() < 8 || &data[..8] != b"LPKSHHRH" {
        return Err(anyhow::anyhow!("{}: not a journal file", path.display()));
    }

    if data.len() >= 88 && matches!(journal_u64(&data, 80), Ok(264)) {
        return load_legacy_private_journal(&data);
    }
    load_upstream_journal(path, &data)
}

const JOURNAL_HEADER_MIN_SIZE: usize = 104;
const JOURNAL_INCOMPATIBLE_COMPACT: u32 = 1 << 4;
const JOURNAL_OBJECT_DATA: u8 = 1;
const JOURNAL_OBJECT_ENTRY: u8 = 3;
const JOURNAL_OBJECT_HEADER_SIZE: usize = 16;
const JOURNAL_DATA_REGULAR_BASE: usize = 64;
const JOURNAL_DATA_COMPACT_BASE: usize = 72;
const JOURNAL_ENTRY_BASE: usize = 64;

fn load_upstream_journal(path: &Path, data: &[u8]) -> anyhow::Result<Vec<JournalEntry>> {
    if data.len() < JOURNAL_HEADER_MIN_SIZE {
        return Err(anyhow::anyhow!(
            "{}: truncated journal header",
            path.display()
        ));
    }

    let incompatible_flags = journal_u32(data, 12)?;
    let compact = incompatible_flags & JOURNAL_INCOMPATIBLE_COMPACT != 0;
    let header_size = journal_usize(journal_u64(data, 88)?, "header size")?;
    let arena_size = journal_usize(journal_u64(data, 96)?, "arena size")?;
    if header_size < JOURNAL_HEADER_MIN_SIZE || header_size > data.len() {
        return Err(anyhow::anyhow!(
            "{}: invalid journal header size",
            path.display()
        ));
    }
    let arena_end = header_size
        .checked_add(arena_size)
        .ok_or_else(|| anyhow::anyhow!("{}: journal arena overflows", path.display()))?;
    if arena_end > data.len() {
        return Err(anyhow::anyhow!(
            "{}: truncated journal arena",
            path.display()
        ));
    }

    let mut entries = Vec::new();
    let mut pos = journal_align8(header_size)?;
    while pos
        .checked_add(JOURNAL_OBJECT_HEADER_SIZE)
        .is_some_and(|end| end <= arena_end)
    {
        let Some((object_type, size, object_end)) =
            upstream_object_bounds(path, data, pos, arena_end)?
        else {
            break;
        };
        if object_type == JOURNAL_OBJECT_ENTRY {
            entries.push(parse_upstream_entry(
                path, data, pos, size, arena_end, compact,
            )?);
        }
        pos = journal_align8(object_end)?;
    }
    Ok(entries)
}

fn upstream_object_bounds(
    path: &Path,
    data: &[u8],
    pos: usize,
    arena_end: usize,
) -> anyhow::Result<Option<(u8, usize, usize)>> {
    let object_type = data[pos];
    let size = journal_usize(journal_u64(data, pos + 8)?, "object size")?;
    if object_type == 0 && size == 0 {
        return Ok(None);
    }
    if size < JOURNAL_OBJECT_HEADER_SIZE {
        return Err(anyhow::anyhow!(
            "{}: invalid object size at {pos}",
            path.display()
        ));
    }
    let object_end = pos
        .checked_add(size)
        .ok_or_else(|| anyhow::anyhow!("{}: object offset overflows", path.display()))?;
    if object_end > arena_end {
        return Err(anyhow::anyhow!(
            "{}: object at {pos} exceeds arena",
            path.display()
        ));
    }
    Ok(Some((object_type, size, object_end)))
}

fn parse_upstream_entry(
    path: &Path,
    data: &[u8],
    pos: usize,
    size: usize,
    arena_end: usize,
    compact: bool,
) -> anyhow::Result<JournalEntry> {
    if size < JOURNAL_ENTRY_BASE {
        return Err(anyhow::anyhow!(
            "{}: short entry object at {pos}",
            path.display()
        ));
    }
    let item_size = if compact { 4 } else { 16 };
    let item_bytes = size - JOURNAL_ENTRY_BASE;
    if item_bytes % item_size != 0 {
        return Err(anyhow::anyhow!(
            "{}: malformed entry item array at {pos}",
            path.display()
        ));
    }

    let seqnum = journal_u64(data, pos + 16)?;
    let realtime = journal_u64(data, pos + 24)?;
    let boot_id = data
        .get(pos + 40..pos + 56)
        .ok_or_else(|| anyhow::anyhow!("{}: truncated entry boot ID", path.display()))?;
    let mut fields = HashMap::new();
    for index in 0..(item_bytes / item_size) {
        let item_offset = pos + JOURNAL_ENTRY_BASE + index * item_size;
        let (key, value) = read_upstream_data_field(path, data, item_offset, arena_end, compact)?;
        fields.entry(key).or_insert(value);
    }

    fields.insert("_BOOT_ID".into(), id128_to_hex(boot_id).into_bytes());
    let mut entry = JournalEntry::new(fields);
    entry.realtime_usec = realtime;
    entry.seqnum = seqnum;
    Ok(entry)
}

fn read_upstream_data_field(
    path: &Path,
    data: &[u8],
    item_offset: usize,
    arena_end: usize,
    compact: bool,
) -> anyhow::Result<(String, Vec<u8>)> {
    let data_offset = if compact {
        u64::from(journal_u32(data, item_offset)?)
    } else {
        journal_u64(data, item_offset)?
    };
    let data_pos = journal_usize(data_offset, "data object offset")?;
    if !data_pos
        .checked_add(JOURNAL_OBJECT_HEADER_SIZE)
        .is_some_and(|end| end <= arena_end)
        || data.get(data_pos).copied() != Some(JOURNAL_OBJECT_DATA)
    {
        return Err(anyhow::anyhow!(
            "{}: entry references invalid DATA object {data_pos}",
            path.display()
        ));
    }

    let data_flags = data[data_pos + 1];
    let data_size = journal_usize(journal_u64(data, data_pos + 8)?, "data object size")?;
    let payload_base = if compact {
        JOURNAL_DATA_COMPACT_BASE
    } else {
        JOURNAL_DATA_REGULAR_BASE
    };
    if data_size < payload_base {
        return Err(anyhow::anyhow!(
            "{}: short DATA object at {data_pos}",
            path.display()
        ));
    }
    let payload_start = data_pos
        .checked_add(payload_base)
        .ok_or_else(|| anyhow::anyhow!("{}: DATA payload offset overflows", path.display()))?;
    let payload_end = data_pos
        .checked_add(data_size)
        .ok_or_else(|| anyhow::anyhow!("{}: DATA object overflows", path.display()))?;
    if payload_end > arena_end {
        return Err(anyhow::anyhow!(
            "{}: DATA object exceeds arena",
            path.display()
        ));
    }
    let stored_payload = data
        .get(payload_start..payload_end)
        .ok_or_else(|| anyhow::anyhow!("{}: truncated DATA payload", path.display()))?;
    let decoded_payload = if data_flags == 0 {
        None
    } else {
        Some(
            decompress_payload(data_flags, stored_payload).map_err(|error| {
                anyhow::anyhow!(
                    "{}: failed to decompress DATA object at {data_pos}: {error}",
                    path.display()
                )
            })?,
        )
    };
    parse_upstream_data_payload(path, decoded_payload.as_deref().unwrap_or(stored_payload))
}

fn parse_upstream_data_payload(path: &Path, payload: &[u8]) -> anyhow::Result<(String, Vec<u8>)> {
    let equals = payload
        .iter()
        .position(|byte| *byte == b'=')
        .ok_or_else(|| {
            anyhow::anyhow!("{}: DATA payload has no field separator", path.display())
        })?;
    if equals == 0 {
        return Err(anyhow::anyhow!(
            "{}: DATA payload has an empty field name",
            path.display()
        ));
    }
    let key = std::str::from_utf8(&payload[..equals])
        .map_err(|error| anyhow::anyhow!("{}: invalid field name: {error}", path.display()))?;
    Ok((key.to_owned(), payload[equals + 1..].to_vec()))
}

fn load_legacy_private_journal(data: &[u8]) -> anyhow::Result<Vec<JournalEntry>> {
    const LEGACY_HEADER_SIZE: usize = 264;
    const LEGACY_ENTRY_TYPE: u8 = 2;

    if data.len() < 128 {
        return Ok(Vec::new());
    }
    let header_size = journal_usize(journal_u64(data, 80)?, "legacy header size")?;
    let data_hash_table_size = journal_usize(journal_u64(data, 104)?, "legacy data hash size")?;
    let field_hash_table_size = journal_usize(journal_u64(data, 120)?, "legacy field hash size")?;
    if header_size != LEGACY_HEADER_SIZE {
        return Ok(Vec::new());
    }
    let Some(object_start) = header_size
        .checked_add(data_hash_table_size)
        .and_then(|value| value.checked_add(field_hash_table_size))
    else {
        return Ok(Vec::new());
    };
    if object_start > data.len() {
        return Ok(Vec::new());
    }

    let mut entries = Vec::new();
    let mut pos = object_start;
    while pos.checked_add(64).is_some_and(|end| end <= data.len()) {
        let object_type = data[pos];
        let size = journal_usize(journal_u64(data, pos + 8)?, "legacy object size")?;
        if size < 16 || size > data.len() - pos {
            break;
        }
        if object_type == LEGACY_ENTRY_TYPE && size >= 64 {
            let realtime = journal_u64(data, pos + 16)?;
            let seqnum = journal_u64(data, pos + 24)?;
            let boot_id = data
                .get(pos + 32..pos + 48)
                .ok_or_else(|| anyhow::anyhow!("truncated legacy entry boot ID"))?;
            let mut fields = HashMap::new();
            fields.insert(
                "MESSAGE".into(),
                format!("<legacy journal entry seqnum={seqnum}>").into_bytes(),
            );
            fields.insert("_BOOT_ID".into(), id128_to_hex(boot_id).into_bytes());
            let mut entry = JournalEntry::new(fields);
            entry.realtime_usec = realtime;
            entry.seqnum = seqnum;
            entries.push(entry);
        }
        pos += size;
    }
    Ok(entries)
}

fn journal_u32(data: &[u8], offset: usize) -> anyhow::Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| anyhow::anyhow!("journal offset overflows"))?;
    let bytes = data
        .get(offset..end)
        .ok_or_else(|| anyhow::anyhow!("truncated 32-bit journal value"))?;
    Ok(u32::from_le_bytes(
        bytes.try_into().expect("four-byte slice"),
    ))
}

fn journal_u64(data: &[u8], offset: usize) -> anyhow::Result<u64> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| anyhow::anyhow!("journal offset overflows"))?;
    let bytes = data
        .get(offset..end)
        .ok_or_else(|| anyhow::anyhow!("truncated 64-bit journal value"))?;
    Ok(u64::from_le_bytes(
        bytes.try_into().expect("eight-byte slice"),
    ))
}

fn journal_usize(value: u64, label: &str) -> anyhow::Result<usize> {
    usize::try_from(value).map_err(|_| anyhow::anyhow!("{label} does not fit in usize"))
}

fn journal_align8(value: usize) -> anyhow::Result<usize> {
    value
        .checked_add(7)
        .map(|aligned| aligned & !7)
        .ok_or_else(|| anyhow::anyhow!("journal alignment overflows"))
}

fn id128_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        value.push(char::from(HEX[usize::from(byte >> 4)]));
        value.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    value
}

fn read_machine_id() -> String {
    std::fs::read_to_string("/etc/machine-id")
        .unwrap_or_default()
        .trim()
        .to_owned()
}

// ── Boot selection and filtering ──────────────────────────────────────────
fn normalize_boot_id(value: &str) -> Option<String> {
    let compact: String = value
        .trim()
        .chars()
        .filter(|character| *character != '-')
        .collect();
    if compact.len() != 32
        || !compact
            .chars()
            .all(|character| character.is_ascii_hexdigit())
        || compact.chars().all(|character| character == '0')
    {
        return None;
    }
    Some(compact.to_ascii_lowercase())
}

fn entry_boot_id(entry: &JournalEntry) -> Option<String> {
    entry
        .fields
        .get("_BOOT_ID")
        .and_then(|value| std::str::from_utf8(value).ok())
        .and_then(normalize_boot_id)
}

fn available_boots(entries: &[JournalEntry]) -> Vec<String> {
    let mut boots: HashMap<String, u64> = HashMap::new();
    for entry in entries {
        let Some(id) = entry_boot_id(entry) else {
            continue;
        };
        boots
            .entry(id)
            .and_modify(|first| *first = (*first).min(entry.realtime_usec))
            .or_insert(entry.realtime_usec);
    }
    let mut boots: Vec<(String, u64)> = boots.into_iter().collect();
    boots.sort_by(|left, right| left.1.cmp(&right.1).then_with(|| left.0.cmp(&right.0)));
    boots.into_iter().map(|(id, _)| id).collect()
}

fn resolve_boot_id(
    entries: &[JournalEntry],
    selection: &BootSelection,
) -> anyhow::Result<Option<String>> {
    match selection {
        BootSelection::All => Ok(None),
        BootSelection::Current => current_boot_id()
            .map(str::to_owned)
            .map(Some)
            .ok_or_else(|| anyhow::anyhow!("current boot ID is unavailable")),
        BootSelection::Offset(0) => current_boot_id()
            .map(str::to_owned)
            .map(Some)
            .ok_or_else(|| anyhow::anyhow!("current boot ID is unavailable")),
        BootSelection::Offset(offset) => {
            let boots = available_boots(entries);
            let len = i64::try_from(boots.len())?;
            let index = if *offset > 0 {
                offset
                    .checked_sub(1)
                    .ok_or_else(|| anyhow::anyhow!("boot offset overflow"))?
            } else {
                len.checked_sub(1)
                    .and_then(|last| last.checked_add(*offset))
                    .ok_or_else(|| anyhow::anyhow!("boot offset {offset} is outside the journal"))?
            };
            if index < 0 || index >= len {
                return Err(anyhow::anyhow!(
                    "boot offset {offset} is outside the journal"
                ));
            }
            Ok(Some(boots[usize::try_from(index)?].clone()))
        }
        BootSelection::Id { id, offset } => {
            if *offset == 0 {
                return Ok(Some(id.clone()));
            }
            let boots = available_boots(entries);
            let base = boots
                .iter()
                .position(|candidate| candidate == id)
                .ok_or_else(|| anyhow::anyhow!("boot ID {id} is not present in the journal"))?;
            let target = i64::try_from(base)?
                .checked_add(*offset)
                .and_then(|index| usize::try_from(index).ok())
                .filter(|index| *index < boots.len())
                .ok_or_else(|| {
                    anyhow::anyhow!("boot offset {offset} relative to {id} is outside the journal")
                })?;
            Ok(Some(boots[target].clone()))
        }
    }
}

fn entry_matches(entry: &JournalEntry, opts: &Options, boot_id: Option<&str>) -> bool {
    if let Some(boot_id) = boot_id {
        if entry_boot_id(entry).as_deref() != Some(boot_id) {
            return false;
        }
    }
    if entry.priority() > opts.priority_max {
        return false;
    }
    if let Some(ref unit) = opts.unit {
        if entry.unit() != unit {
            return false;
        }
    }
    for (key, value) in &opts.matches {
        match entry.fields.get(key) {
            Some(field) if field.as_slice() == value.as_bytes() => {}
            _ => return false,
        }
    }
    true
}

fn filter_entries<'a>(
    entries: &'a [JournalEntry],
    opts: &Options,
    boot_id: Option<&str>,
) -> Vec<&'a JournalEntry> {
    entries
        .iter()
        .filter(|entry| entry_matches(entry, opts, boot_id))
        .collect()
}

// ── Output formatting ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShortTimestampMode {
    Short,
    Full,
    Precise,
    Iso,
    IsoPrecise,
    Unix,
}

fn print_entry(out: &mut impl Write, entry: &JournalEntry, format: &str) {
    match format {
        "short-full" => print_short(out, entry, ShortTimestampMode::Full),
        "short-precise" => print_short(out, entry, ShortTimestampMode::Precise),
        "short-iso" => print_short(out, entry, ShortTimestampMode::Iso),
        "short-iso-precise" => print_short(out, entry, ShortTimestampMode::IsoPrecise),
        "short-unix" => print_short(out, entry, ShortTimestampMode::Unix),
        "verbose" => print_verbose(out, entry),
        "json" | "json-pretty" => print_json(out, entry, format == "json-pretty"),
        "cat" => print_cat(out, entry),
        "export" => print_export(out, entry),
        _ => print_short(out, entry, ShortTimestampMode::Short),
    }
}

fn print_catalog_for_entry(
    out: &mut impl Write,
    entry: &JournalEntry,
    catalog: Option<&CatalogDatabase>,
) {
    let Some(catalog) = catalog else {
        return;
    };
    let Some(message_id) = entry.fields.get("MESSAGE_ID") else {
        return;
    };
    let Ok(message_id) = std::str::from_utf8(message_id) else {
        return;
    };
    let Ok(id) = parse_catalog_id(message_id) else {
        return;
    };
    let Some(text) = catalog.lookup(&id) else {
        return;
    };
    let expanded = expand_catalog_fields(text, &entry.fields);
    let prefix = catalog_output_prefix();
    for line in expanded.trim().lines() {
        let _ = writeln!(out, "{prefix} {line}");
    }
}

fn print_short(out: &mut impl Write, entry: &JournalEntry, mode: ShortTimestampMode) {
    let ts = format_realtime(entry.realtime_usec, mode);
    let unit = entry.unit();
    let pid = entry.pid_str();
    let ident = entry
        .fields
        .get("SYSLOG_IDENTIFIER")
        .and_then(|v| std::str::from_utf8(v).ok())
        .unwrap_or(unit);
    let msg = entry.message_str();
    if pid.is_empty() {
        let _ = writeln!(out, "{ts} {ident}: {msg}");
    } else {
        let _ = writeln!(out, "{ts} {ident}[{pid}]: {msg}");
    }
}

fn print_verbose(out: &mut impl Write, entry: &JournalEntry) {
    let _ = writeln!(out, "-- Journal entry --");
    let _ = writeln!(out, "    REALTIME={}", entry.realtime_usec);
    let _ = writeln!(out, "    SEQNUM={}", entry.seqnum);
    for (k, v) in &entry.fields {
        let val = std::str::from_utf8(v).unwrap_or("<binary>");
        let _ = writeln!(out, "    {k}={val}");
    }
    let _ = writeln!(out);
}

fn print_json(out: &mut impl Write, entry: &JournalEntry, pretty: bool) {
    let mut map = serde_json::Map::new();
    map.insert(
        "__REALTIME_TIMESTAMP".into(),
        serde_json::Value::String(entry.realtime_usec.to_string()),
    );
    map.insert(
        "__SEQNUM".into(),
        serde_json::Value::String(entry.seqnum.to_string()),
    );
    for (k, v) in &entry.fields {
        let val = std::str::from_utf8(v).map_or_else(
            |_| {
                serde_json::Value::Array(
                    v.iter()
                        .map(|b| serde_json::Value::Number((*b).into()))
                        .collect(),
                )
            },
            |s| serde_json::Value::String(s.to_owned()),
        );
        map.insert(k.clone(), val);
    }
    let obj = serde_json::Value::Object(map);
    if let Ok(s) = if pretty {
        serde_json::to_string_pretty(&obj)
    } else {
        serde_json::to_string(&obj)
    } {
        let _ = writeln!(out, "{s}");
    }
}

fn print_cat(out: &mut impl Write, entry: &JournalEntry) {
    let _ = writeln!(out, "{}", entry.message_str());
}

fn print_export(out: &mut impl Write, entry: &JournalEntry) {
    let _ = writeln!(out, "__REALTIME_TIMESTAMP={}", entry.realtime_usec);
    let _ = writeln!(out, "__SEQNUM={}", entry.seqnum);
    for (k, v) in &entry.fields {
        if let Ok(s) = std::str::from_utf8(v) {
            let _ = writeln!(out, "{k}={s}");
        } else {
            let _ = writeln!(out, "{k}");
            let len = v.len() as u64;
            let _ = out.write_all(&len.to_le_bytes());
            let _ = out.write_all(v);
            let _ = writeln!(out);
        }
    }
    let _ = writeln!(out);
}

fn format_realtime(usec: u64, mode: ShortTimestampMode) -> String {
    if mode == ShortTimestampMode::Unix {
        return format!("{:>10}.{:06}", usec / 1_000_000, usec % 1_000_000);
    }

    let Some(tm) = local_calendar_time(usec) else {
        return timestamp_fallback(mode).to_owned();
    };
    let micros = usec % 1_000_000;
    match mode {
        ShortTimestampMode::Short => strftime_value(&tm, b"%b %d %H:%M:%S\0")
            .unwrap_or_else(|| timestamp_fallback(mode).to_owned()),
        ShortTimestampMode::Precise => strftime_value(&tm, b"%b %d %H:%M:%S\0").map_or_else(
            || timestamp_fallback(mode).to_owned(),
            |base| format!("{base}.{micros:06}"),
        ),
        ShortTimestampMode::Iso => strftime_value(&tm, b"%Y-%m-%dT%H:%M:%S\0").map_or_else(
            || timestamp_fallback(mode).to_owned(),
            |base| format!("{base}{}", timezone_offset(&tm)),
        ),
        ShortTimestampMode::IsoPrecise => strftime_value(&tm, b"%Y-%m-%dT%H:%M:%S\0").map_or_else(
            || timestamp_fallback(mode).to_owned(),
            |base| format!("{base}.{micros:06}{}", timezone_offset(&tm)),
        ),
        ShortTimestampMode::Full => format_full_timestamp(&tm),
        ShortTimestampMode::Unix => unreachable!("unix handled above"),
    }
}

fn local_calendar_time(usec: u64) -> Option<libc::tm> {
    let seconds = libc::time_t::try_from(usec / 1_000_000).ok()?;
    let mut tm = std::mem::MaybeUninit::<libc::tm>::uninit();
    // Safety: `seconds` and `tm` are valid for the duration of localtime_r.
    let converted = unsafe { libc::localtime_r(&seconds, tm.as_mut_ptr()) };
    if converted.is_null() {
        None
    } else {
        // Safety: localtime_r initialized `tm` when it returned non-null.
        Some(unsafe { tm.assume_init() })
    }
}

fn strftime_value(tm: &libc::tm, format: &'static [u8]) -> Option<String> {
    let format = std::ffi::CStr::from_bytes_with_nul(format).ok()?;
    let mut buffer = [0 as libc::c_char; 96];
    // Safety: buffer is writable, format is NUL terminated, and tm is valid.
    let length = unsafe {
        libc::strftime(
            buffer.as_mut_ptr(),
            buffer.len(),
            format.as_ptr(),
            tm as *const libc::tm,
        )
    };
    if length == 0 {
        return None;
    }
    // Safety: strftime NUL terminates successful output in `buffer`.
    Some(
        unsafe { std::ffi::CStr::from_ptr(buffer.as_ptr()) }
            .to_string_lossy()
            .into_owned(),
    )
}

fn timezone_offset(tm: &libc::tm) -> String {
    let total_minutes = tm.tm_gmtoff / 60;
    let hours = total_minutes / 60;
    let minutes = (total_minutes % 60).abs();
    format!("{hours:+03}:{minutes:02}")
}

fn format_full_timestamp(tm: &libc::tm) -> String {
    const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    let weekday = usize::try_from(tm.tm_wday)
        .ok()
        .and_then(|index| WEEKDAYS.get(index))
        .copied()
        .unwrap_or("---");
    let Some(base) = strftime_value(tm, b"%Y-%m-%d %H:%M:%S\0") else {
        return timestamp_fallback(ShortTimestampMode::Full).to_owned();
    };
    let zone = if tm.tm_zone.is_null() {
        timezone_offset(tm)
    } else {
        // Safety: tm_zone is supplied by libc and remains valid with this tm.
        unsafe { std::ffi::CStr::from_ptr(tm.tm_zone) }
            .to_string_lossy()
            .into_owned()
    };
    if zone.is_empty() {
        format!("{weekday} {base} {}", timezone_offset(tm))
    } else {
        format!("{weekday} {base} {zone}")
    }
}

fn timestamp_fallback(mode: ShortTimestampMode) -> &'static str {
    match mode {
        ShortTimestampMode::Short => "XXX XX XX:XX:XX",
        ShortTimestampMode::Precise => "XXX XX XX:XX:XX.XXXXXX",
        ShortTimestampMode::Iso => "XXXX-XX-XXTXX:XX:XX+XX:XX",
        ShortTimestampMode::IsoPrecise => "XXXX-XX-XXTXX:XX:XX.XXXXXX+XX:XX",
        ShortTimestampMode::Full => "--- XXXX-XX-XX XX:XX:XX",
        ShortTimestampMode::Unix => "",
    }
}

// ── Follow mode ───────────────────────────────────────────────────────────

fn follow_mode(
    out: &mut impl Write,
    opts: &Options,
    boot_id: Option<&str>,
    catalog: Option<&CatalogDatabase>,
) {
    let ring = Arc::new(Mutex::new(EntryRing::new(4096)));
    let mut cursor = 0u64;
    let receiver = JournalReceiver::new(Arc::clone(&ring));
    loop {
        if receiver.is_ok() {
            if let Ok(ring) = ring.lock() {
                let new: Vec<JournalEntry> = ring
                    .drain_since(cursor)
                    .iter()
                    .map(|entry| (*entry).clone())
                    .collect();
                let filtered = filter_entries(&new, opts, boot_id);
                for entry in &filtered {
                    print_entry(out, entry, &opts.output);
                    print_catalog_for_entry(out, entry, catalog);
                }
                if let Some(last) = new.last() {
                    cursor = last.seqnum;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

// ── Help ──────────────────────────────────────────────────────────────────

fn print_help() {
    println!("Usage: rustjournalctl [OPTIONS] [MATCHES...]");
    println!();
    println!("Options:");
    println!("  -u, --unit UNIT         Show entries for unit");
    println!("  -b, --boot[=ID±OFFSET]  Show entries from a specific boot");
    println!("  -f, --follow            Follow journal (tail -f style)");
    println!("  -x, --catalog           Add catalog explanations for MESSAGE_ID entries");
    println!("      --update-catalog    Rebuild the binary message catalog database");
    println!("      --list-catalog      List message catalog entries");
    println!("      --dump-catalog      Dump message catalog entries");
    println!("  -n, --lines N           Show last N lines");
    println!("  -p, --priority LEVEL    Filter by priority (0=emerg..7=debug)");
    println!("  -o, --output FORMAT     Output format: short, short-full, short-precise,");
    println!("                           short-iso, short-iso-precise, short-unix,");
    println!("                           verbose, json, json-pretty, cat, export");
    println!("      --file PATH         Read from specific journal file");
    println!("  -h, --help              Show this help");
    println!();
    println!("Matches: KEY=VALUE pairs to filter entries.");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn options(boot: BootSelection) -> Options {
        Options {
            unit: None,
            boot,
            output: "short".into(),
            last_n: None,
            follow: false,
            file: None,
            help: false,
            matches: Vec::new(),
            priority_max: priority::DEBUG,
            catalog: false,
            catalog_action: CatalogAction::Show,
            catalog_ids: Vec::new(),
        }
    }

    fn entry(id: &str, realtime_usec: u64, message: &str) -> JournalEntry {
        let mut fields = HashMap::new();
        fields.insert("_BOOT_ID".into(), id.as_bytes().to_vec());
        fields.insert("MESSAGE".into(), message.as_bytes().to_vec());
        let mut entry = JournalEntry::new(fields);
        entry.realtime_usec = realtime_usec;
        entry
    }

    #[test]
    fn catalog_options_select_actions_and_ids() {
        let parsed = Options::parse(&args(&[
            "-x",
            "--dump-catalog",
            "00112233445566778899aabbccddeeff",
        ]))
        .unwrap();
        assert!(parsed.catalog);
        assert_eq!(parsed.catalog_action, CatalogAction::Dump);
        assert_eq!(parsed.catalog_ids, ["00112233445566778899aabbccddeeff"]);
    }

    #[test]
    fn boot_option_accepts_current_offsets_ids_and_all() {
        assert_eq!(
            Options::parse(&args(&["-b"])).unwrap().boot,
            BootSelection::Current
        );
        assert_eq!(
            Options::parse(&args(&["-b", "-1"])).unwrap().boot,
            BootSelection::Offset(-1)
        );
        assert_eq!(
            Options::parse(&args(&["-b2"])).unwrap().boot,
            BootSelection::Offset(2)
        );
        assert_eq!(
            Options::parse(&args(&["--boot=all"])).unwrap().boot,
            BootSelection::All
        );
        let id = "0123456789abcdef0123456789abcdef";
        let selector = format!("--boot={id}-2");
        assert_eq!(
            Options::parse(&args(&[selector.as_str()])).unwrap().boot,
            BootSelection::Id {
                id: id.into(),
                offset: -2,
            }
        );
    }

    #[test]
    fn boot_offsets_follow_chronological_order() {
        let first = "11111111111111111111111111111111";
        let second = "22222222222222222222222222222222";
        let third = "33333333333333333333333333333333";
        let entries = vec![
            entry(third, 30, "third"),
            entry(first, 10, "first"),
            entry(second, 20, "second"),
        ];
        assert_eq!(
            resolve_boot_id(&entries, &BootSelection::Offset(1)).unwrap(),
            Some(first.into())
        );
        assert_eq!(
            resolve_boot_id(&entries, &BootSelection::Offset(-1)).unwrap(),
            Some(second.into())
        );
        assert_eq!(
            resolve_boot_id(
                &entries,
                &BootSelection::Id {
                    id: second.into(),
                    offset: 1,
                },
            )
            .unwrap(),
            Some(third.into())
        );
    }

    #[test]
    fn explicit_boot_id_filters_historical_entries() {
        let selected = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let other = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let entries = vec![entry(selected, 10, "selected"), entry(other, 20, "other")];
        let opts = options(BootSelection::Id {
            id: selected.into(),
            offset: 0,
        });
        let boot_id = resolve_boot_id(&entries, &opts.boot).unwrap();
        let filtered = filter_entries(&entries, &opts, boot_id.as_deref());
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].message_str(), "selected");
    }

    #[test]
    fn all_boots_disables_boot_filtering() {
        let first = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let second = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let entries = vec![entry(first, 10, "first"), entry(second, 20, "second")];
        let opts = options(BootSelection::All);
        let filtered = filter_entries(&entries, &opts, None);
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn current_boot_filter_rejects_historical_entries() {
        let Some(current) = current_boot_id() else {
            return;
        };
        let old = if current == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        } else {
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        };
        let entries = vec![entry(current, 20, "current"), entry(old, 10, "old")];
        let opts = options(BootSelection::Current);
        let boot_id = resolve_boot_id(&entries, &opts.boot).unwrap();
        let filtered = filter_entries(&entries, &opts, boot_id.as_deref());
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].message_str(), "current");
    }

    #[test]
    fn disk_reader_round_trips_upstream_object_graph() {
        use std::time::{SystemTime, UNIX_EPOCH};
        use rustd::journal::writer::JournalWriter;

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "rustd-journal-reader-{}-{unique}.journal",
            std::process::id()
        ));

        let first = JournalEntry::message("reader.service", 5, "first persisted message");
        let second = JournalEntry::message("reader.service", 6, "second persisted message");
        let expected_boot = first.fields.get("_BOOT_ID").cloned();
        let mut writer = JournalWriter::open(&path).expect("open journal writer");
        writer.append(&first).expect("append first entry");
        writer.append(&second).expect("append second entry");
        writer.close().expect("close journal writer");

        let loaded = load_from_file(&path).expect("read journal file");
        std::fs::remove_file(&path).expect("remove journal fixture");
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].message_str(), "first persisted message");
        assert_eq!(loaded[0].unit(), "reader.service");
        assert_eq!(loaded[0].priority(), 5);
        assert_eq!(loaded[1].message_str(), "second persisted message");
        assert_eq!(loaded[1].unit(), "reader.service");
        assert_eq!(loaded[1].priority(), 6);
        assert_eq!(loaded[0].fields.get("_BOOT_ID").cloned(), expected_boot);
    }

    #[test]
    fn short_unix_preserves_microseconds() {
        assert_eq!(
            format_realtime(1_704_067_200_123_456, ShortTimestampMode::Unix),
            "1704067200.123456"
        );
        assert_eq!(
            format_realtime(123_456, ShortTimestampMode::Unix),
            "         0.123456"
        );
    }

    #[test]
    fn id128_bytes_use_compact_lowercase_hex() {
        let bytes = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        assert_eq!(id128_to_hex(&bytes), "0123456789abcdeffedcba9876543210");
    }
}
