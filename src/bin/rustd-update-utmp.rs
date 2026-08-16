// SPDX-License-Identifier: LGPL-2.1-or-later
//! `systemd-update-utmp` v261 compatibility helper.

use std::env;
use std::ffi::{CStr, CString, OsString};
use std::io::{self, Write};
use std::mem::{self, size_of};
use std::os::raw::{c_char, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::time::{SystemTime, UNIX_EPOCH};

const AUDIT_SYSTEM_BOOT: c_int = 1127;
const AUDIT_SYSTEM_SHUTDOWN: c_int = 1128;
const USEC_PER_SEC: u64 = 1_000_000;
const _: [(); 384] = [(); size_of::<libc::utmpx>()];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Verb {
    Reboot,
    Shutdown,
}

fn main() {
    let arguments: Vec<OsString> = env::args_os().skip(1).collect();
    if let Err(error) = run(&arguments) {
        let mut stderr = io::stderr().lock();
        let _ = stderr.write_all(&error);
        let _ = stderr.write_all(b"\n");
        std::process::exit(1);
    }
}

fn run(arguments: &[OsString]) -> Result<(), Vec<u8>> {
    unsafe { libc::umask(0o022) };
    let verb = parse_verb(arguments)?;
    let audit_result = send_audit(verb);
    let timestamp = if let Some(value) = env::var_os("RUSTD_UPDATE_UTMP_TIMESTAMP_USEC") {
        value
            .to_string_lossy()
            .parse()
            .map_err(|_| b"Failed to determine current time: Invalid argument".to_vec())?
    } else {
        match verb {
            Verb::Shutdown => realtime_usec()?,
            Verb::Reboot => reboot_timestamp_usec(),
        }
    };
    write_utmp_wtmp(verb, timestamp)?;
    audit_result
}

fn parse_verb(arguments: &[OsString]) -> Result<Verb, Vec<u8>> {
    let Some(first) = arguments.first() else {
        return Err(b"Command verb required (one of reboot, shutdown).".to_vec());
    };
    let verb = match first.as_os_str().as_bytes() {
        b"reboot" => Verb::Reboot,
        b"shutdown" => Verb::Shutdown,
        unknown => return Err(unknown_verb_error(unknown)),
    };
    if arguments.len() > 1 {
        return Err(b"Too many arguments.".to_vec());
    }
    Ok(verb)
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
    let candidates = [b"reboot".as_slice(), b"shutdown".as_slice()];
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

fn reboot_timestamp_usec() -> u64 {
    if let Some(value) = env::var_os("RUSTD_UPDATE_UTMP_REBOOT_USEC") {
        return value.to_string_lossy().parse().unwrap_or_else(|_| {
            log_message("Failed to get timestamp, ignoring: Invalid argument");
            realtime_usec().unwrap_or(0)
        });
    }
    let monotonic = match manager_userspace_timestamp() {
        Ok(monotonic) => monotonic,
        Err(ManagerTimestampError::Connection(error)) => {
            log_message(&format!(
                "Failed to get D-Bus connection, ignoring: {error}"
            ));
            0
        }
        Err(ManagerTimestampError::Property(error)) => {
            log_message(&format!("Failed to get timestamp, ignoring: {error}"));
            0
        }
    };
    map_monotonic_to_realtime(monotonic).unwrap_or_else(|error| {
        log_message(&format!("Failed to get timestamp, ignoring: {error}"));
        realtime_usec().unwrap_or(0)
    })
}

enum ManagerTimestampError {
    Connection(String),
    Property(String),
}

fn manager_userspace_timestamp() -> Result<u64, ManagerTimestampError> {
    if let Some(error) = env::var_os("RUSTD_UPDATE_UTMP_MANAGER_ERROR") {
        return match error.as_os_str().as_bytes() {
            b"connection" => Err(ManagerTimestampError::Connection(String::from(
                "fixture connection failure",
            ))),
            _ => Err(ManagerTimestampError::Property(String::from(
                "fixture property failure",
            ))),
        };
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .map_err(|error| ManagerTimestampError::Connection(error.to_string()))?;
    runtime.block_on(async {
        let connection = zbus::Connection::system()
            .await
            .map_err(|error| ManagerTimestampError::Connection(error.to_string()))?;
        let proxy = zbus::Proxy::new(
            &connection,
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
        )
        .await
        .map_err(|error| ManagerTimestampError::Property(error.to_string()))?;
        proxy
            .get_property::<u64>("UserspaceTimestampMonotonic")
            .await
            .map_err(|error| ManagerTimestampError::Property(error.to_string()))
    })
}

fn map_monotonic_to_realtime(monotonic_usec: u64) -> Result<u64, String> {
    if let (Some(monotonic_now), Some(realtime_now)) = (
        env::var_os("RUSTD_UPDATE_UTMP_MONOTONIC_NOW_USEC"),
        env::var_os("RUSTD_UPDATE_UTMP_REALTIME_NOW_USEC"),
    ) {
        let monotonic_now = monotonic_now
            .to_string_lossy()
            .parse()
            .map_err(|_| String::from("Invalid argument"))?;
        let realtime_now = realtime_now
            .to_string_lossy()
            .parse()
            .map_err(|_| String::from("Invalid argument"))?;
        return Ok(map_clock_usec(monotonic_usec, monotonic_now, realtime_now));
    }
    let mut monotonic = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let mut realtime = monotonic;
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut monotonic) } < 0
        || unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut realtime) } < 0
    {
        return Err(io_error_text(&io::Error::last_os_error()));
    }
    let monotonic_now = timespec_usec(monotonic)?;
    let realtime_now = timespec_usec(realtime)?;
    Ok(map_clock_usec(monotonic_usec, monotonic_now, realtime_now))
}

fn map_clock_usec(monotonic_usec: u64, monotonic_now: u64, realtime_now: u64) -> u64 {
    if monotonic_usec >= monotonic_now {
        realtime_now.saturating_add(monotonic_usec - monotonic_now)
    } else {
        realtime_now.saturating_sub(monotonic_now - monotonic_usec)
    }
}

fn timespec_usec(value: libc::timespec) -> Result<u64, String> {
    let seconds = u64::try_from(value.tv_sec).map_err(|_| String::from("Invalid argument"))?;
    let nanos = u64::try_from(value.tv_nsec).map_err(|_| String::from("Invalid argument"))?;
    Ok(seconds
        .saturating_mul(USEC_PER_SEC)
        .saturating_add(nanos / 1_000))
}

fn realtime_usec() -> Result<u64, Vec<u8>> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() * USEC_PER_SEC + u64::from(duration.subsec_micros()))
        .map_err(|_| b"Failed to determine current time: Invalid argument".to_vec())
}

fn write_utmp_wtmp(verb: Verb, timestamp_usec: u64) -> Result<(), Vec<u8>> {
    let mut entry: libc::utmpx = unsafe { mem::zeroed() };
    entry.ut_type = match verb {
        Verb::Reboot => libc::BOOT_TIME,
        Verb::Shutdown => libc::RUN_LVL,
    };
    copy_c_chars(&mut entry.ut_line, b"~");
    copy_c_chars(&mut entry.ut_id, b"~~");
    copy_c_chars(
        &mut entry.ut_user,
        match verb {
            Verb::Reboot => b"reboot",
            Verb::Shutdown => b"shutdown",
        },
    );
    let mut uts: libc::utsname = unsafe { mem::zeroed() };
    if unsafe { libc::uname(&mut uts) } >= 0 {
        let release = unsafe { CStr::from_ptr(uts.release.as_ptr()) };
        copy_c_chars(&mut entry.ut_host, release.to_bytes());
    }
    entry.ut_tv.tv_sec = (timestamp_usec / USEC_PER_SEC).try_into().map_err(|_| {
        b"Failed to write utmp record: Value too large for defined data type".to_vec()
    })?;
    entry.ut_tv.tv_usec = (timestamp_usec % USEC_PER_SEC).try_into().map_err(|_| {
        b"Failed to write utmp record: Value too large for defined data type".to_vec()
    })?;

    let accounting_path = env::var_os("RUSTD_UPDATE_UTMP_UTMP")
        .map_or_else(|| PathBuf::from("/run/utmp"), PathBuf::from);
    let history_path = env::var_os("RUSTD_UPDATE_UTMP_WTMP")
        .map_or_else(|| PathBuf::from("/var/log/wtmp"), PathBuf::from);
    let accounting_result = write_utmp(&accounting_path, &entry);
    let history_result = write_wtmp(&history_path, &entry);
    accounting_result.and(history_result)
}

fn copy_c_chars<const N: usize>(destination: &mut [c_char; N], source: &[u8]) {
    for (destination, source) in destination.iter_mut().zip(source.iter().copied()) {
        *destination = c_char::try_from(source).unwrap_or(63_i8);
    }
}

fn write_utmp(path: &Path, entry: &libc::utmpx) -> Result<(), Vec<u8>> {
    let path = path_cstring(path)?;
    if unsafe { libc::utmpxname(path.as_ptr()) } < 0 {
        return utmp_error();
    }
    unsafe { libc::setutxent() };
    set_errno(0);
    let result = unsafe { libc::pututxline(entry) };
    let error = io::Error::last_os_error();
    unsafe { libc::endutxent() };
    if result.is_null() {
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(());
        }
        return Err(prefix_error(b"Failed to write utmp record: ", &error));
    }
    Ok(())
}

fn write_wtmp(path: &Path, entry: &libc::utmpx) -> Result<(), Vec<u8>> {
    let path = path_cstring(path)?;
    set_errno(0);
    unsafe { updwtmpx(path.as_ptr(), entry) };
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        None | Some(0 | libc::ENOENT | libc::EROFS) => Ok(()),
        _ => Err(prefix_error(b"Failed to write utmp record: ", &error)),
    }
}

fn path_cstring(path: &Path) -> Result<CString, Vec<u8>> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| b"Failed to write utmp record: Invalid argument".to_vec())
}

fn utmp_error() -> Result<(), Vec<u8>> {
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::NotFound {
        Ok(())
    } else {
        Err(prefix_error(b"Failed to write utmp record: ", &error))
    }
}

fn send_audit(verb: Verb) -> Result<(), Vec<u8>> {
    if let Some(path) = env::var_os("RUSTD_UPDATE_UTMP_AUDIT_LOG") {
        let line = match verb {
            Verb::Reboot => b"AUDIT_SYSTEM_BOOT systemd-update-utmp success=1\n".as_slice(),
            Verb::Shutdown => b"AUDIT_SYSTEM_SHUTDOWN systemd-update-utmp success=1\n".as_slice(),
        };
        return std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .and_then(|mut file| file.write_all(line))
            .map_err(|error| prefix_error(b"Failed to send audit message: ", &error));
    }
    unsafe { AuditLibrary::open() }.map_or(Ok(()), |library| library.send(verb))
}

struct AuditLibrary {
    handle: *mut c_void,
    fd: c_int,
    close: unsafe extern "C" fn(c_int) -> c_int,
    log: unsafe extern "C" fn(
        c_int,
        c_int,
        *const c_char,
        *const c_char,
        *const c_char,
        *const c_char,
        *const c_char,
        c_int,
    ) -> c_int,
}

impl AuditLibrary {
    unsafe fn open() -> Option<Self> {
        let handle = unsafe { libc::dlopen(b"libaudit.so.1\0".as_ptr().cast(), libc::RTLD_LAZY) };
        if handle.is_null() {
            return None;
        }
        let open = unsafe { libc::dlsym(handle, b"audit_open\0".as_ptr().cast()) };
        let close = unsafe { libc::dlsym(handle, b"audit_close\0".as_ptr().cast()) };
        let log = unsafe { libc::dlsym(handle, b"audit_log_user_comm_message\0".as_ptr().cast()) };
        if open.is_null() || close.is_null() || log.is_null() {
            unsafe { libc::dlclose(handle) };
            return None;
        }
        let open: unsafe extern "C" fn() -> c_int = unsafe { mem::transmute(open) };
        set_errno(0);
        let fd = unsafe { open() };
        if fd < 0 {
            let error = io::Error::last_os_error();
            unsafe { libc::dlclose(handle) };
            if !is_not_supported(&error) {
                log_message(&format!(
                    "Failed to connect to audit log, ignoring: {}",
                    io_error_text(&error)
                ));
            }
            return None;
        }
        let close: unsafe extern "C" fn(c_int) -> c_int = unsafe { mem::transmute(close) };
        let log: unsafe extern "C" fn(
            c_int,
            c_int,
            *const c_char,
            *const c_char,
            *const c_char,
            *const c_char,
            *const c_char,
            c_int,
        ) -> c_int = unsafe { mem::transmute(log) };
        Some(Self {
            handle,
            fd,
            close,
            log,
        })
    }

    fn send(&self, verb: Verb) -> Result<(), Vec<u8>> {
        set_errno(0);
        let result = unsafe {
            (self.log)(
                self.fd,
                match verb {
                    Verb::Reboot => AUDIT_SYSTEM_BOOT,
                    Verb::Shutdown => AUDIT_SYSTEM_SHUTDOWN,
                },
                b"\0".as_ptr().cast(),
                b"systemd-update-utmp\0".as_ptr().cast(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                1,
            )
        };
        let error = io::Error::last_os_error();
        if result < 0 && error.raw_os_error() != Some(libc::EPERM) {
            Err(prefix_error(b"Failed to send audit message: ", &error))
        } else {
            Ok(())
        }
    }
}

impl Drop for AuditLibrary {
    fn drop(&mut self) {
        unsafe {
            (self.close)(self.fd);
            libc::dlclose(self.handle);
        }
    }
}

fn set_errno(value: c_int) {
    unsafe { *libc::__errno_location() = value };
}

fn prefix_error(prefix: &[u8], error: &io::Error) -> Vec<u8> {
    let mut message = prefix.to_vec();
    message.extend_from_slice(io_error_text(error).as_bytes());
    message
}

fn io_error_text(error: &io::Error) -> String {
    let text = error.to_string();
    text.rfind(" (os error ").map_or(text.clone(), |index| {
        if text.ends_with(')') {
            text[..index].to_owned()
        } else {
            text
        }
    })
}

fn is_not_supported(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(
            libc::EOPNOTSUPP
                | libc::ENOSYS
                | libc::ENOTTY
                | libc::EPROTONOSUPPORT
                | libc::ESOCKTNOSUPPORT
                | libc::EPFNOSUPPORT
                | libc::EAFNOSUPPORT
                | libc::EPROTOTYPE
        )
    )
}

fn log_message(message: &str) {
    if env::var("SYSTEMD_LOG_TARGET").ok().as_deref() != Some("null") {
        eprintln!("{message}");
    }
}

extern "C" {
    fn updwtmpx(path: *const c_char, entry: *const libc::utmpx);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glibc_utmpx_abi_matches_v261_host() {
        let entry: libc::utmpx = unsafe { mem::zeroed() };
        let base = ptr::addr_of!(entry).cast::<u8>() as usize;
        assert_eq!(size_of::<libc::utmpx>(), 384);
        assert_eq!(ptr::addr_of!(entry.ut_type).cast::<u8>() as usize - base, 0);
        assert_eq!(ptr::addr_of!(entry.ut_pid).cast::<u8>() as usize - base, 4);
        assert_eq!(ptr::addr_of!(entry.ut_line).cast::<u8>() as usize - base, 8);
        assert_eq!(ptr::addr_of!(entry.ut_id).cast::<u8>() as usize - base, 40);
        assert_eq!(
            ptr::addr_of!(entry.ut_user).cast::<u8>() as usize - base,
            44
        );
        assert_eq!(
            ptr::addr_of!(entry.ut_host).cast::<u8>() as usize - base,
            76
        );
        assert_eq!(ptr::addr_of!(entry.ut_tv).cast::<u8>() as usize - base, 340);
    }

    #[test]
    fn monotonic_mapping_is_saturating() {
        assert_eq!(map_clock_usec(20, 10, 100), 110);
        assert_eq!(map_clock_usec(5, 10, 100), 95);
        assert_eq!(map_clock_usec(u64::MAX, 0, 1), u64::MAX);
        assert_eq!(map_clock_usec(0, 100, 1), 0);
    }

    #[test]
    fn verb_suggestions_match_v261_threshold() {
        assert_eq!(edit_distance(b"reboo", b"reboot"), 1);
        assert_eq!(closest_verb(b"shutdow"), Some(b"shutdown".as_slice()));
    }
}
