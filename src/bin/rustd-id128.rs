// SPDX-License-Identifier: LGPL-2.1-or-later
//! `systemd-id128` compatibility utility.
//!
//! Upstream reference: systemd v261 `src/id128/id128.c`,
//! `src/shared/id128-print.c`, `src/shared/gpt.c`, and `sd-id128.c`.

use std::env;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

const VERSION_OUTPUT: &str = concat!(
    "systemd 261 (261.2-1-arch)\n",
    "+PAM +AUDIT -SELINUX +APPARMOR -IMA +IPE +SMACK +SECCOMP +GCRYPT +GNUTLS +OPENSSL +ACL ",
    "+BLKID +CURL +ELFUTILS +FIDO2 +IDN2 +KMOD +LIBCRYPTSETUP +LIBCRYPTSETUP_PLUGINS +LIBFDISK ",
    "+PCRE2 +PWQUALITY +P11KIT +QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB +ZSTD +BPF_FRAMEWORK +BTF ",
    "+XKBCOMMON +UTMP +LIBARCHIVE\n"
);

const HELP: &str = concat!(
    "systemd-id128 [OPTIONS...] COMMAND\n\n",
    "Generate and print 128-bit identifiers.\n\n",
    "Commands:\n",
    "  new                  Generate a new ID\n",
    "  machine-id           Print the ID of current machine\n",
    "  boot-id              Print the ID of current boot\n",
    "  invocation-id        Print the ID of current invocation\n",
    "  var-partition-uuid   Print the UUID for the /var/ partition\n",
    "  show [NAME|UUID]     Print one or more UUIDs\n",
    "  help                 Show this help\n\n",
    "Options:\n",
    "  -h --help            Show this help\n",
    "     --version         Show package version\n",
    "     --no-pager        Do not start a pager\n",
    "     --no-legend       Do not show headers and footers\n",
    "     --json=FORMAT     Output inspection data in JSON (takes one of pretty,\n",
    "                       short, off)\n",
    "  -j                   Equivalent to --json=pretty (on TTY) or --json=short\n",
    "                       (otherwise)\n",
    "  -p --pretty          Generate samples of program code\n",
    "  -P --value           Only print the value\n",
    "  -a --app-specific=ID Generate app-specific IDs\n",
    "  -u --uuid            Output in UUID format\n\n",
    "See the systemd-id128(1) man page for details.\n"
);

const GPT_TYPES: &str = include_str!("systemd-id128-gpt.txt");
const VAR_PARTITION_TYPE: &str = "4d21b016b53445c2a9fb5c16e091fd2d";

const MACHINE_PATH_OVERRIDE: &str = "SYSTEMD_ID128_MACHINE_ID_PATH";
const BOOT_PATH_OVERRIDE: &str = "SYSTEMD_ID128_BOOT_ID_PATH";
const RANDOM_PATH_OVERRIDE: &str = "SYSTEMD_ID128_RANDOM_PATH";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Id128([u8; 16]);

impl Id128 {
    const NULL: Self = Self([0; 16]);

    fn parse(value: &str) -> Option<Self> {
        let mut compact = [0_u8; 32];
        let bytes = value.as_bytes();
        match bytes.len() {
            32 => compact.copy_from_slice(bytes),
            36 if bytes[8] == b'-'
                && bytes[13] == b'-'
                && bytes[18] == b'-'
                && bytes[23] == b'-' =>
            {
                let mut output = 0;
                for (index, byte) in bytes.iter().copied().enumerate() {
                    if matches!(index, 8 | 13 | 18 | 23) {
                        continue;
                    }
                    compact[output] = byte;
                    output += 1;
                }
            }
            _ => return None,
        }
        let mut id = [0_u8; 16];
        for (index, pair) in compact.chunks_exact(2).enumerate() {
            id[index] = (unhex(pair[0])? << 4) | unhex(pair[1])?;
        }
        Some(Self(id))
    }

    fn plain(self) -> String {
        let mut output = String::with_capacity(32);
        for byte in self.0 {
            output.push(hex(byte >> 4));
            output.push(hex(byte & 0x0f));
        }
        output
    }

    fn uuid(self) -> String {
        let plain = self.plain();
        format!(
            "{}-{}-{}-{}-{}",
            &plain[..8],
            &plain[8..12],
            &plain[12..16],
            &plain[16..20],
            &plain[20..]
        )
    }

    fn make_v4(mut self) -> Self {
        self.0[6] = (self.0[6] & 0x0f) | 0x40;
        self.0[8] = (self.0[8] & 0x3f) | 0x80;
        self
    }

    fn app_specific(self, app: Self) -> Self {
        let digest = hmac_sha256(&self.0, &app.0);
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        Self(bytes).make_v4()
    }
}

fn unhex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn hex(value: u8) -> char {
    char::from(if value < 10 {
        b'0' + value
    } else {
        b'a' + value - 10
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrintMode {
    Plain,
    Uuid,
    Pretty,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JsonMode {
    Off,
    Short,
    Pretty,
}

#[derive(Debug, Eq, PartialEq)]
struct Options {
    mode: PrintMode,
    app: Option<Id128>,
    value: bool,
    legend: bool,
    json: JsonMode,
    arguments: Vec<String>,
}

enum ParseResult {
    Run(Options),
    Exit(&'static str),
}

fn main() {
    let arguments: Vec<String> = env::args().skip(1).collect();
    let result = match parse_options(&arguments) {
        Ok(ParseResult::Exit(output)) => write_stdout(output.as_bytes()),
        Ok(ParseResult::Run(options)) => run(&options),
        Err(error) => {
            if !error.is_empty() {
                eprintln!("{error}");
            }
            Err(())
        }
    };
    if result.is_err() {
        std::process::exit(1);
    }
}

fn write_stdout(bytes: &[u8]) -> Result<(), ()> {
    io::stdout().lock().write_all(bytes).map_err(|_| ())
}

fn parse_options(arguments: &[String]) -> Result<ParseResult, String> {
    let mut options = Options {
        mode: PrintMode::Plain,
        app: None,
        value: false,
        legend: true,
        json: JsonMode::Off,
        arguments: Vec::new(),
    };
    let mut index = 0;
    let mut positional_only = false;

    while index < arguments.len() {
        let argument = &arguments[index];
        if positional_only || argument == "-" || !argument.starts_with('-') {
            options.arguments.push(argument.clone());
            index += 1;
            continue;
        }
        if argument == "--" {
            positional_only = true;
            index += 1;
            continue;
        }
        if let Some(long) = argument.strip_prefix("--") {
            let (name, attached) = long
                .split_once('=')
                .map_or((long, None), |(name, value)| (name, Some(value)));
            let canonical = resolve_long_option(name)?;
            match canonical {
                "help" => {
                    reject_attached(name, attached)?;
                    return Ok(ParseResult::Exit(HELP));
                }
                "version" => {
                    reject_attached(name, attached)?;
                    return Ok(ParseResult::Exit(VERSION_OUTPUT));
                }
                "no-pager" => reject_attached(name, attached)?,
                "no-legend" => {
                    reject_attached(name, attached)?;
                    options.legend = false;
                }
                "json" => {
                    let value = required_long_argument(name, attached, arguments, &mut index)?;
                    if value == "help" {
                        return Ok(ParseResult::Exit("pretty\nshort\noff\n"));
                    }
                    options.json = parse_json(&value)?;
                }
                "pretty" => {
                    reject_attached(name, attached)?;
                    options.mode = PrintMode::Pretty;
                    options.value = false;
                }
                "value" => {
                    reject_attached(name, attached)?;
                    options.value = true;
                    if options.mode == PrintMode::Pretty {
                        options.mode = PrintMode::Plain;
                    }
                }
                "app-specific" => {
                    let value = required_long_argument(name, attached, arguments, &mut index)?;
                    options.app = Some(parse_app_id(&value)?);
                }
                "uuid" => {
                    reject_attached(name, attached)?;
                    options.mode = PrintMode::Uuid;
                }
                _ => unreachable!("complete option set"),
            }
            index += 1;
            continue;
        }

        if let Some(result) =
            parse_short_options(&argument[1..], arguments, &mut index, &mut options)?
        {
            return Ok(result);
        }
        index += 1;
    }
    Ok(ParseResult::Run(options))
}

fn parse_short_options(
    short: &str,
    arguments: &[String],
    index: &mut usize,
    options: &mut Options,
) -> Result<Option<ParseResult>, String> {
    let mut chars = short.char_indices().peekable();
    while let Some((_, option)) = chars.next() {
        match option {
            'h' => return Ok(Some(ParseResult::Exit(HELP))),
            'j' => options.json = JsonMode::Short,
            'p' => {
                options.mode = PrintMode::Pretty;
                options.value = false;
            }
            'P' => {
                options.value = true;
                if options.mode == PrintMode::Pretty {
                    options.mode = PrintMode::Plain;
                }
            }
            'u' => options.mode = PrintMode::Uuid,
            'a' => {
                let value = if let Some((next_offset, _)) = chars.peek().copied() {
                    short[next_offset..].to_owned()
                } else {
                    *index += 1;
                    arguments.get(*index).cloned().ok_or_else(|| {
                        "systemd-id128: option '-a' requires an argument".to_owned()
                    })?
                };
                options.app = Some(parse_app_id(&value)?);
                break;
            }
            _ => return Err(format!("systemd-id128: unrecognized option '-{option}'")),
        }
    }
    Ok(None)
}

fn resolve_long_option(value: &str) -> Result<&'static str, String> {
    const LONG: &[&str] = &[
        "help",
        "version",
        "no-pager",
        "no-legend",
        "json",
        "pretty",
        "value",
        "app-specific",
        "uuid",
    ];
    let matches: Vec<&str> = LONG
        .iter()
        .copied()
        .filter(|option| option.starts_with(value))
        .collect();
    match matches.as_slice() {
        [one] => Ok(one),
        [] => Err(format!("systemd-id128: unrecognized option '--{value}'")),
        _ => Err(format!(
            "systemd-id128: option '--{value}' is ambiguous; possibilities: {}",
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
            "systemd-id128: option '--{name}' doesn't allow an argument"
        ));
    }
    Ok(())
}

fn required_long_argument(
    name: &str,
    attached: Option<&str>,
    arguments: &[String],
    index: &mut usize,
) -> Result<String, String> {
    if let Some(value) = attached {
        return Ok(value.to_owned());
    }
    *index += 1;
    arguments
        .get(*index)
        .cloned()
        .ok_or_else(|| format!("systemd-id128: option '--{name}' requires an argument"))
}

fn parse_app_id(value: &str) -> Result<Id128, String> {
    let id = Id128::parse(value).ok_or_else(|| {
        format!("Failed to parse \"{value}\" as application ID: Invalid argument")
    })?;
    if id == Id128::NULL {
        return Err("Application ID cannot be all zeros.".to_owned());
    }
    Ok(id)
}

fn parse_json(value: &str) -> Result<JsonMode, String> {
    match value {
        "pretty" => Ok(JsonMode::Pretty),
        "short" => Ok(JsonMode::Short),
        "off" => Ok(JsonMode::Off),
        _ => Err(format!("Unknown argument to --json= switch: {value}")),
    }
}

fn run(options: &Options) -> Result<(), ()> {
    let Some((verb, arguments)) = options.arguments.split_first() else {
        return fail(
            "Command verb required (one of new, machine-id, boot-id, invocation-id, var-partition-uuid, show, help).",
        );
    };
    match verb.as_str() {
        "help" => write_stdout(HELP.as_bytes()),
        "new" => {
            require_no_arguments(arguments)?;
            if options.app.is_some() {
                return fail("Verb \"new\" cannot be combined with --app-specific=.");
            }
            let id = random_id().map_err(|error| {
                eprintln!("Failed to generate ID: {error}");
            })?;
            print_id(id, options.mode)
        }
        "machine-id" => {
            require_no_arguments(arguments)?;
            let mut id = read_machine_id().map_err(|error| {
                eprintln!("Failed to get machine-ID: {error}");
            })?;
            if let Some(app) = options.app {
                id = id.app_specific(app);
            }
            print_id(id, options.mode)
        }
        "boot-id" => {
            require_no_arguments(arguments)?;
            let mut id = read_boot_id().map_err(|error| {
                eprintln!("Failed to get boot-ID: {error}");
            })?;
            if let Some(app) = options.app {
                id = id.app_specific(app);
            }
            print_id(id, options.mode)
        }
        "invocation-id" => {
            require_no_arguments(arguments)?;
            if options.app.is_some() {
                return fail("Verb \"invocation-id\" cannot be combined with --app-specific=.");
            }
            let id = read_invocation_id().map_err(|error| {
                eprintln!("Failed to get invocation-ID: {error}");
            })?;
            print_id(id, options.mode)
        }
        "var-partition-uuid" => {
            require_no_arguments(arguments)?;
            if options.app.is_some() {
                return fail(
                    "Verb \"var-partition-uuid\" cannot be combined with --app-specific=.",
                );
            }
            let machine = read_machine_id().map_err(|error| {
                eprintln!("Failed to generate machine-specific /var/ UUID: {error}");
            })?;
            let var = Id128::parse(VAR_PARTITION_TYPE).expect("valid /var/ type UUID");
            print_id(machine.app_specific(var), options.mode)
        }
        "show" => show(arguments, options),
        unknown => fail(&unknown_verb_error(unknown)),
    }
}

fn require_no_arguments(arguments: &[String]) -> Result<(), ()> {
    if arguments.is_empty() {
        Ok(())
    } else {
        fail("Too many arguments.")
    }
}

fn fail(message: &str) -> Result<(), ()> {
    eprintln!("{message}");
    Err(())
}

fn unknown_verb_error(verb: &str) -> String {
    const VERBS: &[&str] = &[
        "new",
        "machine-id",
        "boot-id",
        "invocation-id",
        "var-partition-uuid",
        "show",
        "help",
    ];
    let suggestion = VERBS
        .iter()
        .min_by_key(|candidate| edit_distance(verb, candidate));
    if let Some(candidate) = suggestion.filter(|candidate| edit_distance(verb, candidate) <= 5) {
        format!("Unknown command verb '{verb}', did you mean '{candidate}'?")
    } else {
        format!("Unknown command verb '{verb}'.")
    }
}

fn edit_distance(left: &str, right: &str) -> usize {
    let mut row: Vec<usize> = (0..=right.len()).collect();
    for (left_index, left_byte) in left.bytes().enumerate() {
        let mut previous = row[0];
        row[0] = left_index + 1;
        for (right_index, right_byte) in right.bytes().enumerate() {
            let old = row[right_index + 1];
            row[right_index + 1] = if left_byte == right_byte {
                previous
            } else {
                1 + previous.min(row[right_index]).min(old)
            };
            previous = old;
        }
    }
    row[right.len()]
}

fn read_id_file(path: &Path, uuid_format: bool) -> Result<Id128, String> {
    let value = fs::read_to_string(path).map_err(|error| io_error(&error))?;
    let trimmed = value.strip_suffix('\n').unwrap_or(&value);
    if trimmed == "uninitialized" {
        return Err("Package not installed".to_owned());
    }
    let expected_length = if uuid_format { 36 } else { 32 };
    if trimmed.len() != expected_length {
        return Err("Structure needs cleaning".to_owned());
    }
    let id = Id128::parse(trimmed).ok_or_else(|| "Structure needs cleaning".to_owned())?;
    if id == Id128::NULL {
        return Err("No medium found".to_owned());
    }
    Ok(id)
}

fn read_machine_id() -> Result<Id128, String> {
    let path = env::var_os(MACHINE_PATH_OVERRIDE)
        .map_or_else(|| PathBuf::from("/etc/machine-id"), PathBuf::from);
    read_id_file(&path, false)
}

fn read_boot_id() -> Result<Id128, String> {
    let path = env::var_os(BOOT_PATH_OVERRIDE).map_or_else(
        || PathBuf::from("/proc/sys/kernel/random/boot_id"),
        PathBuf::from,
    );
    read_id_file(&path, true)
}

fn read_invocation_id() -> Result<Id128, String> {
    let Some(value) = env::var_os("INVOCATION_ID") else {
        return Err("No such device or address".to_owned());
    };
    let value = value.to_string_lossy();
    let id = Id128::parse(&value).ok_or_else(|| "Structure needs cleaning".to_owned())?;
    if id == Id128::NULL {
        return Err("No medium found".to_owned());
    }
    Ok(id)
}

fn random_id() -> Result<Id128, String> {
    let path = env::var_os(RANDOM_PATH_OVERRIDE)
        .map_or_else(|| PathBuf::from("/dev/urandom"), PathBuf::from);
    let mut file = File::open(path).map_err(|error| io_error(&error))?;
    let mut bytes = [0_u8; 16];
    file.read_exact(&mut bytes)
        .map_err(|error| io_error(&error))?;
    Ok(Id128(bytes).make_v4())
}

fn io_error(error: &io::Error) -> String {
    match error.kind() {
        io::ErrorKind::NotFound => "No such file or directory".to_owned(),
        io::ErrorKind::PermissionDenied => "Permission denied".to_owned(),
        io::ErrorKind::UnexpectedEof => "Input/output error".to_owned(),
        _ => error
            .to_string()
            .split(" (os error")
            .next()
            .unwrap_or("Input/output error")
            .to_owned(),
    }
}

fn print_id(id: Id128, mode: PrintMode) -> Result<(), ()> {
    match mode {
        PrintMode::Plain => write_stdout(format!("{}\n", id.plain()).as_bytes()),
        PrintMode::Uuid => write_stdout(format!("{}\n", id.uuid()).as_bytes()),
        PrintMode::Pretty => write_stdout(pretty_sample("XYZ", id).as_bytes()),
    }
}

fn pretty_sample(name: &str, id: Id128) -> String {
    let identifier = name.replace('-', "_").to_ascii_uppercase();
    let bytes =
        id.0.iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(",");
    format!(
        "As string:\n{}\n\nAs UUID:\n{}\n\nAs systemd-id128(1) macro:\n#define {} SD_ID128_MAKE({})\n\nAs Python constant:\n>>> import uuid\n>>> {} = uuid.UUID('{}')\n",
        id.plain(),
        id.uuid(),
        identifier,
        bytes,
        identifier,
        id.plain()
    )
}

#[derive(Clone)]
struct GptType {
    name: &'static str,
    id: Id128,
}

fn gpt_types() -> Vec<GptType> {
    GPT_TYPES
        .lines()
        .map(|line| {
            let (name, value) = line.split_once(' ').expect("valid GPT type row");
            GptType {
                name,
                id: Id128::parse(value).expect("valid GPT type UUID"),
            }
        })
        .collect()
}

fn show(arguments: &[String], options: &Options) -> Result<(), ()> {
    let all = gpt_types();
    if arguments.is_empty() && options.app.is_some() {
        return fail("'show --app-specific=' can only be used with explicit UUID input.");
    }
    let mut rows = Vec::new();
    if arguments.is_empty() {
        rows = all.clone();
    } else {
        for argument in arguments {
            let (name, mut id) = if let Some(id) = Id128::parse(argument) {
                let name = all
                    .iter()
                    .find(|entry| entry.id == id)
                    .map_or("XYZ", |entry| entry.name);
                (name, id)
            } else if let Some(entry) = all.iter().find(|entry| entry.name == argument) {
                (entry.name, entry.id)
            } else {
                return fail(&format!("Unknown identifier \"{argument}\"."));
            };
            if let Some(app) = options.app {
                id = id.app_specific(app);
            }
            rows.push(GptType { name, id });
        }
    }

    if options.mode == PrintMode::Pretty && options.json != JsonMode::Off {
        return fail("--pretty cannot be combined with --json=.");
    }
    if options.value && options.json != JsonMode::Off && rows.len() != 1 {
        return fail("'show --value --json=' requires exactly one argument.");
    }
    if options.mode == PrintMode::Pretty {
        let mut output = String::new();
        for (index, row) in rows.iter().enumerate() {
            output.push_str(&pretty_sample(row.name, row.id));
            if index > 0 {
                output.push('\n');
            }
        }
        return write_stdout(output.as_bytes());
    }
    if options.json != JsonMode::Off {
        return print_json(&rows, options);
    }
    if options.value {
        let mut output = String::new();
        for row in &rows {
            output.push_str(&format_id(row.id, options.mode));
            output.push('\n');
        }
        return write_stdout(output.as_bytes());
    }
    print_table(&rows, options)
}

fn format_id(id: Id128, mode: PrintMode) -> String {
    match mode {
        PrintMode::Uuid => id.uuid(),
        PrintMode::Plain | PrintMode::Pretty => id.plain(),
    }
}

fn print_table(rows: &[GptType], options: &Options) -> Result<(), ()> {
    let width = rows
        .iter()
        .map(|row| row.name.len())
        .chain(options.legend.then_some(4))
        .max()
        .unwrap_or(4);
    let mut output = String::new();
    if options.legend {
        output.push_str(&format!("{:<width$} ID\n", "NAME"));
    }
    for row in rows {
        output.push_str(&format!(
            "{:<width$} {}\n",
            row.name,
            format_id(row.id, options.mode)
        ));
    }
    write_stdout(output.as_bytes())
}

fn print_json(rows: &[GptType], options: &Options) -> Result<(), ()> {
    if options.value {
        let id = format_id(rows[0].id, options.mode);
        return write_stdout(format!("{{\"id\":\"{id}\"}}\n").as_bytes());
    }
    match options.json {
        JsonMode::Short => {
            let values = rows
                .iter()
                .map(|row| {
                    format!(
                        "{{\"name\":\"{}\",\"id\":\"{}\"}}",
                        row.name,
                        format_id(row.id, options.mode)
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            write_stdout(format!("[{values}]\n").as_bytes())
        }
        JsonMode::Pretty => {
            let mut output = String::from("[\n");
            for (index, row) in rows.iter().enumerate() {
                output.push_str("\t{\n");
                output.push_str(&format!("\t\t\"name\" : \"{}\",\n", row.name));
                output.push_str(&format!(
                    "\t\t\"id\" : \"{}\"\n",
                    format_id(row.id, options.mode)
                ));
                output.push_str(if index + 1 == rows.len() {
                    "\t}\n"
                } else {
                    "\t},\n"
                });
            }
            output.push_str("]\n");
            write_stdout(output.as_bytes())
        }
        JsonMode::Off => unreachable!("JSON printer requires JSON mode"),
    }
}

const SHA256_CONSTANTS: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

fn sha256(input: &[u8]) -> [u8; 32] {
    let mut state = [
        0x6a09_e667_u32,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    let bit_length = (input.len() as u64).wrapping_mul(8);
    let mut padded = input.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_length.to_be_bytes());
    for block in padded.chunks_exact(64) {
        sha256_transform(&mut state, block);
    }
    let mut output = [0_u8; 32];
    for (chunk, word) in output.chunks_exact_mut(4).zip(state) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    output
}

#[allow(clippy::many_single_char_names)] // Standard SHA-256 working-variable names.
fn sha256_transform(state: &mut [u32; 8], block: &[u8]) {
    let mut words = [0_u32; 64];
    for (word, bytes) in words.iter_mut().take(16).zip(block.chunks_exact(4)) {
        *word = u32::from_be_bytes(bytes.try_into().expect("four-byte chunk"));
    }
    for index in 16..64 {
        let s0 = words[index - 15].rotate_right(7)
            ^ words[index - 15].rotate_right(18)
            ^ (words[index - 15] >> 3);
        let s1 = words[index - 2].rotate_right(17)
            ^ words[index - 2].rotate_right(19)
            ^ (words[index - 2] >> 10);
        words[index] = words[index - 16]
            .wrapping_add(s0)
            .wrapping_add(words[index - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for index in 0..64 {
        let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let choose = (e & f) ^ ((!e) & g);
        let temporary1 = h
            .wrapping_add(sum1)
            .wrapping_add(choose)
            .wrapping_add(SHA256_CONSTANTS[index])
            .wrapping_add(words[index]);
        let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let temporary2 = sum0.wrapping_add(majority);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temporary1);
        d = c;
        c = b;
        b = a;
        a = temporary1.wrapping_add(temporary2);
    }
    for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *slot = slot.wrapping_add(value);
    }
}

fn hmac_sha256(key: &[u8], input: &[u8]) -> [u8; 32] {
    let mut inner = [0_u8; 64];
    let mut outer = [0_u8; 64];
    inner[..key.len()].copy_from_slice(key);
    outer[..key.len()].copy_from_slice(key);
    for index in 0..64 {
        inner[index] ^= 0x36;
        outer[index] ^= 0x5c;
    }
    let mut inner_input = inner.to_vec();
    inner_input.extend_from_slice(input);
    let inner_digest = sha256(&inner_input);
    let mut outer_input = outer.to_vec();
    outer_input.extend_from_slice(&inner_digest);
    sha256(&outer_input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_both_id128_formats() {
        let compact = Id128::parse("000102030405060708090a0b0c0d0e0f").unwrap();
        let uuid = Id128::parse("00010203-0405-0607-0809-0a0b0c0d0e0f").unwrap();
        assert_eq!(compact, uuid);
        assert_eq!(compact.plain(), "000102030405060708090a0b0c0d0e0f");
        assert_eq!(compact.uuid(), "00010203-0405-0607-0809-0a0b0c0d0e0f");
    }

    #[test]
    fn app_specific_matches_v261_oracle() {
        let base = Id128::parse("000102030405060708090a0b0c0d0e0f").unwrap();
        let app = Id128::parse("f0e0d0c0b0a090807060504030201000").unwrap();
        assert_eq!(
            base.app_specific(app).plain(),
            "1a3c2557f70642cfa12514db12ae2a1d"
        );
    }

    #[test]
    fn gpt_inventory_matches_v261() {
        let entries = gpt_types();
        assert_eq!(entries.len(), 231);
        assert_eq!(entries.first().unwrap().name, "root-alpha");
        assert_eq!(entries.last().unwrap().name, "linux-generic");
    }
}
