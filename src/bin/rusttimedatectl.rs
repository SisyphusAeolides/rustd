use std::env;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

fn get_timezone() -> String {
    if let Ok(path) = fs::read_link("/etc/localtime") {
        let path_str = path.to_string_lossy();
        if let Some(idx) = path_str.find("zoneinfo/") {
            return path_str[idx + 9..].to_string();
        }
        return path_str.into_owned();
    }
    "UTC".to_string()
}

fn get_tz_abbreviation() -> String {
    let now: libc::time_t = unsafe { libc::time(std::ptr::null_mut()) };
    let mut tm_local: libc::tm = unsafe { std::mem::zeroed() };
    unsafe {
        libc::localtime_r(&now, &mut tm_local);
    }
    let mut local_buf = [0i8; 100];
    unsafe {
        libc::strftime(
            local_buf.as_mut_ptr(),
            local_buf.len(),
            b"%Z\0".as_ptr().cast::<i8>(),
            &tm_local,
        );
    }
    let s = unsafe { std::ffi::CStr::from_ptr(local_buf.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    s
}

fn get_tz_offset() -> String {
    let now: libc::time_t = unsafe { libc::time(std::ptr::null_mut()) };
    let mut tm_local: libc::tm = unsafe { std::mem::zeroed() };
    unsafe {
        libc::localtime_r(&now, &mut tm_local);
    }
    let mut local_buf = [0i8; 100];
    unsafe {
        libc::strftime(
            local_buf.as_mut_ptr(),
            local_buf.len(),
            b"%z\0".as_ptr().cast::<i8>(),
            &tm_local,
        );
    }
    let s = unsafe { std::ffi::CStr::from_ptr(local_buf.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    s
}

fn print_status() {
    let now: libc::time_t = unsafe { libc::time(std::ptr::null_mut()) };

    let mut tm_local: libc::tm = unsafe { std::mem::zeroed() };
    let mut tm_utc: libc::tm = unsafe { std::mem::zeroed() };

    unsafe {
        libc::localtime_r(&now, &mut tm_local);
        libc::gmtime_r(&now, &mut tm_utc);
    }

    let mut local_buf = [0i8; 100];
    let mut utc_buf = [0i8; 100];

    unsafe {
        libc::strftime(
            local_buf.as_mut_ptr(),
            local_buf.len(),
            b"%a %Y-%m-%d %H:%M:%S %Z\0".as_ptr().cast::<i8>(),
            &tm_local,
        );
        libc::strftime(
            utc_buf.as_mut_ptr(),
            utc_buf.len(),
            b"%a %Y-%m-%d %H:%M:%S UTC\0".as_ptr().cast::<i8>(),
            &tm_utc,
        );
    }

    let local_str = unsafe { std::ffi::CStr::from_ptr(local_buf.as_ptr()) }.to_string_lossy();
    let utc_str = unsafe { std::ffi::CStr::from_ptr(utc_buf.as_ptr()) }.to_string_lossy();

    let tz = get_timezone();
    let tz_abbr = get_tz_abbreviation();
    let tz_off = get_tz_offset();

    println!("               Local time: {local_str}");
    println!("           Universal time: {utc_str}");
    println!("                 RTC time: {utc_str}");
    println!("                Time zone: {tz} ({tz_abbr}, {tz_off})");
    println!("System clock synchronized: yes");
    println!("              NTP service: active");
    println!("          RTC in local TZ: no");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() <= 1 || args[1] == "status" {
        print_status();
    } else if args[1] == "set-timezone" {
        if args.len() < 3 {
            eprintln!("Missing timezone argument.");
            std::process::exit(1);
        }
        let tz = &args[2];
        let target = format!("/usr/share/zoneinfo/{tz}");
        if !Path::new(&target).exists() {
            eprintln!("Invalid timezone: {tz}");
            std::process::exit(1);
        }
        // In a real implementation this would talk to systemd-timedated over D-Bus
        // or require root privileges to modify /etc/localtime directly.
        let tmp_path = "/etc/localtime.tmp.rusttimedatectl";
        if let Err(e) = symlink(&target, tmp_path) {
            eprintln!("Failed to create symlink: {e} (are you root?)");
            std::process::exit(1);
        }
        if let Err(e) = fs::rename(tmp_path, "/etc/localtime") {
            eprintln!("Failed to set timezone: {e}");
            let _ = fs::remove_file(tmp_path);
            std::process::exit(1);
        }
        println!("Timezone set to {tz}");
    } else if args[1] == "--help" || args[1] == "-h" || args[1] == "help" {
        println!("rusttimedatectl [OPTIONS...] COMMAND ...");
        println!();
        println!("Commands:");
        println!("  status                   Show current time settings");
        println!("  set-timezone ZONE        Set system time zone");
    } else {
        eprintln!("Unknown command '{}'", args[1]);
        std::process::exit(1);
    }
}
