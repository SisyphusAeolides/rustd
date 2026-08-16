// SPDX-License-Identifier: LGPL-2.1-or-later
//! `systemd-random-seed` v261 compatibility helper.

use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::raw::{c_int, c_ulong};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const DEFAULT_SEED: &str = "/var/lib/systemd/random-seed";
const DEFAULT_RANDOM: &str = "/dev/urandom";
const DEFAULT_MACHINE_ID: &str = "/etc/machine-id";
const DEFAULT_FIRST_BOOT: &str = "/run/systemd/first-boot";
const DEFAULT_POOL_SIZE: &str = "/proc/sys/kernel/random/poolsize";
const POOL_SIZE_MIN: usize = 32;
const POOL_SIZE_MAX: usize = 10 * 1024 * 1024;
const RNDADDENTROPY: c_ulong = 0x4004_5203;
const CREDIT_XATTR: &[u8] = b"user.random-seed-creditable\0";

const HELP: &str = concat!(
    "systemd-random-seed [OPTIONS...] COMMAND\n\n",
    "Load and save the system random seed at boot and shutdown.\n\n",
    "Commands:\n",
    "  load         Load a random seed saved on disk into the kernel entropy pool\n",
    "  save         Save a new random seed on disk\n\n",
    "Options:\n",
    "  -h --help    Show this help\n",
    "     --version Show package version\n\n",
    "See the systemd-random-seed(8) man page for details.\n"
);
const VERSION: &str = concat!(
    "systemd 261 (261.2-1-arch)\n",
    "+PAM +AUDIT -SELINUX +APPARMOR -IMA +IPE +SMACK +SECCOMP +GCRYPT +GNUTLS +OPENSSL +ACL ",
    "+BLKID +CURL +ELFUTILS +FIDO2 +IDN2 +KMOD +LIBCRYPTSETUP +LIBCRYPTSETUP_PLUGINS +LIBFDISK ",
    "+PCRE2 +PWQUALITY +P11KIT +QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB +ZSTD +BPF_FRAMEWORK +BTF ",
    "+XKBCOMMON +UTMP +LIBARCHIVE\n"
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Action {
    Load,
    Save,
}

enum ParseResult {
    Run(Action),
    Exit(&'static str),
}

fn main() {
    let arguments: Vec<OsString> = env::args_os().skip(1).collect();
    let result = match parse_arguments(&arguments) {
        Ok(ParseResult::Exit(output)) => io::stdout()
            .lock()
            .write_all(output.as_bytes())
            .map_err(|error| error_message(b"Failed to write output: ", &error)),
        Ok(ParseResult::Run(action)) => run(action),
        Err(error) => Err(error),
    };
    if let Err(error) = result {
        let mut stderr = io::stderr().lock();
        let _ = stderr.write_all(&error);
        let _ = stderr.write_all(b"\n");
        std::process::exit(1);
    }
}

fn parse_arguments(arguments: &[OsString]) -> Result<ParseResult, Vec<u8>> {
    let mut positionals: Vec<&[u8]> = Vec::new();
    let mut options = true;
    for argument in arguments {
        let bytes = argument.as_os_str().as_bytes();
        if options && bytes == b"--" {
            options = false;
        } else if options && bytes.starts_with(b"--") {
            let long = &bytes[2..];
            let (option, attached) = long
                .iter()
                .position(|byte| *byte == b'=')
                .map_or((long, None), |position| {
                    (&long[..position], Some(&long[position + 1..]))
                });
            if option.is_empty() {
                return Err(option_error(
                    b"option '--",
                    option,
                    b"' is ambiguous; possibilities: --help, --version",
                ));
            }
            if b"help".starts_with(option) {
                if attached.is_some() {
                    return Err(option_error(
                        b"option '--",
                        option,
                        b"' doesn't allow an argument",
                    ));
                }
                return Ok(ParseResult::Exit(HELP));
            }
            if b"version".starts_with(option) {
                if attached.is_some() {
                    return Err(option_error(
                        b"option '--",
                        option,
                        b"' doesn't allow an argument",
                    ));
                }
                return Ok(ParseResult::Exit(VERSION));
            }
            return Err(option_error(b"unrecognized option '--", option, b"'"));
        } else if options && bytes.starts_with(b"-") && bytes.len() > 1 {
            if bytes[1] == b'h' {
                return Ok(ParseResult::Exit(HELP));
            }
            return Err(option_error(b"unrecognized option '-", &bytes[1..2], b"'"));
        } else {
            positionals.push(bytes);
        }
    }
    let Some(verb) = positionals.first().copied() else {
        return Err(b"Command verb required (one of load, save).".to_vec());
    };
    let action = match verb {
        b"load" => Action::Load,
        b"save" => Action::Save,
        unknown => return Err(unknown_verb_error(unknown)),
    };
    if positionals.len() > 1 {
        return Err(b"Too many arguments.".to_vec());
    }
    Ok(ParseResult::Run(action))
}

fn option_error(prefix: &[u8], option: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut error = b"systemd-random-seed: ".to_vec();
    error.extend_from_slice(prefix);
    error.extend_from_slice(option);
    error.extend_from_slice(suffix);
    error
}

fn unknown_verb_error(unknown: &[u8]) -> Vec<u8> {
    let mut error = b"Unknown command verb '".to_vec();
    error.extend_from_slice(unknown);
    error.push(b'\'');
    if let Some(suggestion) = closest_verb(unknown) {
        error.extend_from_slice(b", did you mean '");
        error.extend_from_slice(suggestion);
        error.extend_from_slice(b"'?");
    } else {
        error.push(b'.');
    }
    error
}

fn closest_verb(value: &[u8]) -> Option<&'static [u8]> {
    let candidates = [b"load".as_slice(), b"save".as_slice()];
    if let Some(prefix) = candidates
        .into_iter()
        .filter(|candidate| candidate.starts_with(value))
        .min_by_key(|candidate| candidate.len() - value.len())
    {
        return Some(prefix);
    }
    let (candidate, distance) = candidates
        .into_iter()
        .map(|candidate| (candidate, edit_distance(value, candidate)))
        .min_by_key(|(_, distance)| *distance)?;
    (distance <= 5).then_some(candidate)
}

fn edit_distance(left: &[u8], right: &[u8]) -> usize {
    let mut previous: Vec<usize> = (0..=right.len()).collect();
    for (row, left_byte) in left.iter().enumerate() {
        let mut current = vec![row + 1; right.len() + 1];
        for (column, right_byte) in right.iter().enumerate() {
            current[column + 1] = (previous[column + 1] + 1)
                .min(current[column] + 1)
                .min(previous[column] + usize::from(left_byte != right_byte));
        }
        previous = current;
    }
    previous[right.len()]
}

fn run(action: Action) -> Result<(), Vec<u8>> {
    unsafe { libc::umask(0o022) };
    let seed_path = configured_path("RUSTD_RANDOM_SEED_FILE", DEFAULT_SEED);
    let random_path = configured_path("RUSTD_RANDOM_DEVICE", DEFAULT_RANDOM);
    if let Some(parent) = seed_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| path_error(b"Failed to create directory ", &seed_path, &error))?;
    }
    let mut random = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOCTTY)
        .open(&random_path)
        .map_err(|error| path_error(b"Failed to open ", &random_path, &error))?;

    let (mut seed, read_seed, write_seed, synchronous) = match action {
        Action::Load => {
            load_machine_id(&mut random);
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOCTTY)
                .open(&seed_path)
            {
                Ok(file) => (file, true, true, true),
                Err(write_error) => match OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_CLOEXEC | libc::O_NOCTTY)
                    .open(&seed_path)
                {
                    Ok(file) => (file, true, false, true),
                    Err(read_error) if read_error.kind() == io::ErrorKind::NotFound => {
                        return Ok(())
                    }
                    Err(read_error) => {
                        log_message(&format!(
                            "Failed to open {} for writing: {}",
                            seed_path.display(),
                            io_error_text(&write_error)
                        ));
                        return Err(path_error(b"Failed to open ", &seed_path, &read_error));
                    }
                },
            }
        }
        Action::Save => {
            let file = OpenOptions::new()
                .write(true)
                .create(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOCTTY)
                .open(&seed_path)
                .map_err(|error| path_error(b"Failed to open ", &seed_path, &error))?;
            (file, false, true, false)
        }
    };
    let size = random_seed_size(&seed)?;
    let old_seed = if read_seed {
        load_seed_file(&mut seed, &mut random, size)?
    } else {
        None
    };
    if write_seed {
        save_seed_file(
            &mut seed,
            &mut random,
            size,
            synchronous,
            old_seed.as_deref(),
        )?;
    }
    Ok(())
}

fn configured_path(variable: &str, default: &str) -> PathBuf {
    env::var_os(variable).map_or_else(|| PathBuf::from(default), PathBuf::from)
}

fn random_seed_size(seed: &File) -> Result<usize, Vec<u8>> {
    let existing = usize::try_from(
        seed.metadata()
            .map_err(|error| error_message(b"Failed to stat seed file: ", &error))?
            .size(),
    )
    .unwrap_or(POOL_SIZE_MAX);
    let kernel = env::var("RUSTD_RANDOM_POOL_SIZE")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .or_else(|| {
            fs::read_to_string(configured_path(
                "RUSTD_RANDOM_POOL_SIZE_FILE",
                DEFAULT_POOL_SIZE,
            ))
            .ok()
            .and_then(|value| value.trim().parse::<usize>().ok())
            .map(|bits| bits / 8)
        })
        .unwrap_or(POOL_SIZE_MIN)
        .clamp(POOL_SIZE_MIN, POOL_SIZE_MAX);
    Ok(existing.clamp(kernel, POOL_SIZE_MAX))
}

fn load_machine_id(random: &mut File) {
    let path = configured_path("RUSTD_MACHINE_ID_FILE", DEFAULT_MACHINE_ID);
    let Ok(value) = fs::read(path) else { return };
    let compact: Vec<u8> = value.into_iter().filter(u8::is_ascii_hexdigit).collect();
    if compact.len() != 32 {
        return;
    }
    let mut id = [0_u8; 16];
    for (slot, pair) in id.iter_mut().zip(compact.chunks_exact(2)) {
        let Ok(text) = std::str::from_utf8(pair) else {
            return;
        };
        let Ok(value) = u8::from_str_radix(text, 16) else {
            return;
        };
        *slot = value;
    }
    let _ = random.write_all(&id);
}

fn load_seed_file(
    seed: &mut File,
    random: &mut File,
    size: usize,
) -> Result<Option<Vec<u8>>, Vec<u8>> {
    let mut buffer = vec![0_u8; size];
    let count = match seed.read(&mut buffer) {
        Ok(count) => count,
        Err(error) => {
            log_message(&format!("Failed to read seed: {}", io_error_text(&error)));
            return Ok(None);
        }
    };
    if count == 0 {
        return Ok(None);
    }
    buffer.truncate(count);
    seed.seek(SeekFrom::Start(0))
        .map_err(|error| error_message(b"Failed to seek seed file: ", &error))?;
    let credit = remove_credit_xattr(seed, may_credit(seed));
    if let Err(error) = write_entropy(random, &buffer, credit) {
        log_message(&format!(
            "Failed to write seed to /dev/urandom: {}",
            io_error_text(&error)
        ));
    }
    Ok(Some(buffer))
}

fn may_credit(seed: &File) -> Credit {
    let Some(value) = env::var_os("SYSTEMD_RANDOM_SEED_CREDIT") else {
        return Credit::No;
    };
    if value.as_os_str().as_bytes() == b"force" {
        return Credit::Forced;
    }
    match parse_boolean(value.as_os_str().as_bytes()) {
        Some(false) | None => return Credit::No,
        Some(true) => {}
    }
    if get_credit_xattr(seed) != Some(true) {
        return Credit::No;
    }
    let first_boot = configured_path("RUSTD_FIRST_BOOT_FILE", DEFAULT_FIRST_BOOT);
    if first_boot.exists() {
        Credit::No
    } else {
        Credit::Please
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Credit {
    No,
    Please,
    Forced,
}

fn parse_boolean(value: &[u8]) -> Option<bool> {
    let lower: Vec<u8> = value.iter().map(u8::to_ascii_lowercase).collect();
    match lower.as_slice() {
        b"1" | b"yes" | b"y" | b"true" | b"t" | b"on" => Some(true),
        b"0" | b"no" | b"n" | b"false" | b"f" | b"off" => Some(false),
        _ => None,
    }
}

fn get_credit_xattr(file: &File) -> Option<bool> {
    let mut value = [0_u8; 16];
    let count = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            CREDIT_XATTR.as_ptr().cast(),
            value.as_mut_ptr().cast(),
            value.len(),
        )
    };
    if count < 0 {
        return None;
    }
    parse_boolean(&value[..usize::try_from(count).ok()?])
}

fn remove_credit_xattr(file: &File, mut credit: Credit) -> Credit {
    if unsafe { libc::fremovexattr(file.as_raw_fd(), CREDIT_XATTR.as_ptr().cast()) } < 0 {
        return credit;
    }
    if let Err(error) = file.sync_all() {
        log_message(&format!(
            "Failed to synchronize seed to disk, not crediting entropy: {}",
            io_error_text(&error)
        ));
        if credit == Credit::Please {
            credit = Credit::No;
        }
    }
    credit
}

fn write_entropy(random: &mut File, bytes: &[u8], credit: Credit) -> io::Result<()> {
    if matches!(credit, Credit::Please | Credit::Forced) {
        if let Some(path) = env::var_os("RUSTD_RANDOM_CREDIT_LOG") {
            let mut log = OpenOptions::new().create(true).append(true).open(path)?;
            writeln!(log, "{}", bytes.len() * 8)?;
            log.write_all(bytes)?;
            return Ok(());
        }
        let mut info = Vec::with_capacity(8 + bytes.len());
        info.extend_from_slice(
            &c_int::try_from(bytes.len() * 8)
                .unwrap_or(c_int::MAX)
                .to_ne_bytes(),
        );
        info.extend_from_slice(
            &c_int::try_from(bytes.len())
                .unwrap_or(c_int::MAX)
                .to_ne_bytes(),
        );
        info.extend_from_slice(bytes);
        if unsafe { libc::ioctl(random.as_raw_fd(), RNDADDENTROPY, info.as_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    } else {
        random.write_all(bytes)
    }
}

fn save_seed_file(
    seed: &mut File,
    random: &mut File,
    size: usize,
    synchronous: bool,
    old_seed: Option<&[u8]>,
) -> Result<(), Vec<u8>> {
    let ownership_failed = unsafe { libc::fchmod(seed.as_raw_fd(), 0o600) } < 0
        || unsafe { libc::fchown(seed.as_raw_fd(), 0, 0) } < 0;
    if ownership_failed {
        return Err(error_message(
            b"Failed to adjust seed file ownership and access mode: ",
            &io::Error::last_os_error(),
        ));
    }
    let (mut bytes, getrandom_worked) = random_bytes(random, size, synchronous)?;
    if let Some(old) = old_seed {
        let mut input = Vec::with_capacity(16 + old.len() + bytes.len());
        input.extend_from_slice(&old.len().to_ne_bytes());
        input.extend_from_slice(old);
        input.extend_from_slice(&bytes.len().to_ne_bytes());
        input.extend_from_slice(&bytes);
        let digest = sha256(&input);
        let count = bytes.len().min(digest.len());
        let start = bytes.len() - count;
        bytes[start..].copy_from_slice(&digest[..count]);
    }
    seed.write_all(&bytes)
        .map_err(|error| error_message(b"Failed to write new random seed file: ", &error))?;
    seed.set_len(bytes.len() as u64)
        .map_err(|error| error_message(b"Failed to truncate random seed file: ", &error))?;
    seed.sync_all()
        .map_err(|error| error_message(b"Failed to synchronize seed file: ", &error))?;
    if getrandom_worked
        && unsafe {
            libc::fsetxattr(
                seed.as_raw_fd(),
                CREDIT_XATTR.as_ptr().cast(),
                b"1".as_ptr().cast(),
                1,
                0,
            )
        } < 0
    {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EOPNOTSUPP) {
            log_message(&format!(
                "Failed to mark seed file as creditable, ignoring: {}",
                io_error_text(&error)
            ));
        }
    }
    Ok(())
}

fn random_bytes(
    random: &mut File,
    size: usize,
    synchronous: bool,
) -> Result<(Vec<u8>, bool), Vec<u8>> {
    let fixture = env::var_os("RUSTD_GETRANDOM_HEX")
        .and_then(|value| decode_hex(value.as_os_str().as_bytes()));
    let eagain_once = env::var_os("RUSTD_GETRANDOM_EAGAIN_ONCE").is_some();
    let mut bytes = vec![0_u8; size];
    let mut count = if eagain_once {
        Err(io::Error::from_raw_os_error(libc::EAGAIN))
    } else if let Some(value) = fixture.as_ref() {
        fill_fixture(&mut bytes, value);
        Ok(size)
    } else {
        syscall_getrandom(&mut bytes, libc::GRND_NONBLOCK)
    };
    if count
        .as_ref()
        .is_err_and(|error| error.raw_os_error() == Some(libc::EAGAIN))
        && synchronous
    {
        if let Some(value) = fixture.as_ref() {
            fill_fixture(&mut bytes, value);
            count = Ok(size);
        } else {
            count = syscall_getrandom(&mut bytes, 0);
        }
    }
    if matches!(count, Ok(value) if value == size) {
        Ok((bytes, true))
    } else {
        let read = random.read(&mut bytes).map_err(|error| {
            error_message(b"Failed to read new seed from /dev/urandom: ", &error)
        })?;
        if read == 0 {
            return Err(b"Got EOF while reading from /dev/urandom: Input/output error".to_vec());
        }
        bytes.truncate(read);
        Ok((bytes, false))
    }
}

fn syscall_getrandom(buffer: &mut [u8], flags: u32) -> io::Result<usize> {
    let result = unsafe { libc::getrandom(buffer.as_mut_ptr().cast(), buffer.len(), flags) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(usize::try_from(result).unwrap_or(0))
    }
}

fn decode_hex(value: &[u8]) -> Option<Vec<u8>> {
    if value.is_empty() || value.len() % 2 != 0 {
        return None;
    }
    value
        .chunks_exact(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|text| u8::from_str_radix(text, 16).ok())
        })
        .collect()
}

fn fill_fixture(destination: &mut [u8], fixture: &[u8]) {
    for (index, byte) in destination.iter_mut().enumerate() {
        *byte = fixture[index % fixture.len()];
    }
}

fn path_error(prefix: &[u8], path: &Path, error: &io::Error) -> Vec<u8> {
    let mut message = prefix.to_vec();
    message.extend_from_slice(path.as_os_str().as_bytes());
    message.extend_from_slice(b": ");
    message.extend_from_slice(io_error_text(error).as_bytes());
    message
}

fn error_message(prefix: &[u8], error: &io::Error) -> Vec<u8> {
    let mut message = prefix.to_vec();
    message.extend_from_slice(io_error_text(error).as_bytes());
    message
}

fn io_error_text(error: &io::Error) -> String {
    let text = error.to_string();
    text.rfind(" (os error ")
        .map_or(text.clone(), |index| text[..index].to_owned())
}

fn log_message(message: &str) {
    if env::var("SYSTEMD_LOG_TARGET").ok().as_deref() != Some("null") {
        eprintln!("{message}");
    }
}

#[allow(clippy::unreadable_literal)] // Exact constants from FIPS 180-4.
const SHA256_CONSTANTS: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[allow(clippy::unreadable_literal)] // Exact SHA-256 initialization vector.
fn sha256(input: &[u8]) -> [u8; 32] {
    let mut state = [
        0x6a09e667_u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut padded = input.to_vec();
    let bit_length = (input.len() as u64).wrapping_mul(8);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_length.to_be_bytes());
    for block in padded.chunks_exact(64) {
        sha256_transform(&mut state, block);
    }
    let mut result = [0_u8; 32];
    for (chunk, word) in result.chunks_exact_mut(4).zip(state) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    result
}

#[allow(clippy::many_single_char_names)]
fn sha256_transform(state: &mut [u32; 8], block: &[u8]) {
    let mut words = [0_u32; 64];
    for (word, bytes) in words.iter_mut().take(16).zip(block.chunks_exact(4)) {
        *word = u32::from_be_bytes(bytes.try_into().unwrap());
    }
    for i in 16..64 {
        let s0 =
            words[i - 15].rotate_right(7) ^ words[i - 15].rotate_right(18) ^ (words[i - 15] >> 3);
        let s1 =
            words[i - 2].rotate_right(17) ^ words[i - 2].rotate_right(19) ^ (words[i - 2] >> 10);
        words[i] = words[i - 16]
            .wrapping_add(s0)
            .wrapping_add(words[i - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(SHA256_CONSTANTS[i])
            .wrapping_add(words[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *slot = slot.wrapping_add(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;

    #[test]
    fn sha256_known_vector_and_size_tagging() {
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let mut tagged = 3_usize.to_ne_bytes().to_vec();
        tagged.extend_from_slice(b"abc");
        assert_ne!(sha256(b"abc"), sha256(&tagged));
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().fold(String::new(), |mut output, byte| {
            write!(output, "{byte:02x}").unwrap();
            output
        })
    }
}
