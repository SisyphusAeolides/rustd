// SPDX-License-Identifier: LGPL-2.1-or-later

use std::collections::HashMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

const KDGKBMODE: libc::c_ulong = 0x4B44;
const KDSKBMODE: libc::c_ulong = 0x4B45;
const KDGETMODE: libc::c_ulong = 0x4B3B;
const K_XLATE: libc::c_int = 0;
const K_UNICODE: libc::c_int = 3;
const KD_TEXT: libc::c_int = 0;
const DEFAULT_KEYMAP: &str = "us";
const EX_OSERR: i32 = 71;

#[derive(Default, Debug, Clone, PartialEq, Eq)]
struct Context {
    keymap: Option<String>,
    keymap_toggle: Option<String>,
    font: Option<String>,
    font_map: Option<String>,
    font_unimap: Option<String>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("rustd-vconsole-setup: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() > 1 {
        return Err(String::from("Too many arguments."));
    }

    let (vc, fd, discovered) = if let Some(vc) = args.first() {
        let fd = open_verified_vc(Path::new(vc), false)?;
        (PathBuf::from(vc), fd, false)
    } else {
        match find_source_vc()? {
            Some((vc, fd)) => (vc, fd, true),
            None => {
                eprintln!("rustd-vconsole-setup: All allocated virtual consoles are busy, will not configure key mapping and font.");
                return Ok(());
            }
        }
    };

    let utf8 = locale_is_utf8();
    toggle_utf8_sysfs(utf8);
    toggle_utf8_vc(&vc, &fd, utf8);

    let context = load_context();
    let font_status = load_font(&vc, &context)?;
    let keymap_status = load_keymap(&vc, &context, utf8)?;

    if discovered && font_status {
        setup_remaining_vcs(&vc, &context, utf8);
    }

    if !font_status && !keymap_status {
        return Ok(());
    }
    Ok(())
}

fn load_context() -> Context {
    let mut context = Context::default();
    merge_credentials(&mut context);
    merge_env_file(&mut context, &config_path());
    merge_cmdline(&mut context, &cmdline_path());
    context
}

fn config_path() -> PathBuf {
    env::var_os("RUSTD_VCONSOLE_CONF")
        .map_or_else(|| PathBuf::from("/etc/vconsole.conf"), PathBuf::from)
}

fn cmdline_path() -> PathBuf {
    env::var_os("RUSTD_PROC_CMDLINE").map_or_else(|| PathBuf::from("/proc/cmdline"), PathBuf::from)
}

fn merge_credentials(context: &mut Context) {
    let Some(directory) = env::var_os("CREDENTIALS_DIRECTORY").map(PathBuf::from) else {
        return;
    };
    for (name, field) in [
        ("vconsole.keymap", &mut context.keymap),
        ("vconsole.keymap_toggle", &mut context.keymap_toggle),
        ("vconsole.font", &mut context.font),
        ("vconsole.font_map", &mut context.font_map),
        ("vconsole.font_unimap", &mut context.font_unimap),
    ] {
        if let Ok(value) = fs::read_to_string(directory.join(name)) {
            let value = value.trim_end_matches(['\n', '\r']).to_owned();
            *field = Some(value);
        }
    }
}

fn merge_env_file(context: &mut Context, path: &Path) {
    let Ok(text) = fs::read_to_string(path) else {
        return;
    };
    let values = parse_env(&text);
    set_if_present(&mut context.keymap, values.get("KEYMAP"));
    set_if_present(&mut context.keymap_toggle, values.get("KEYMAP_TOGGLE"));
    set_if_present(&mut context.font, values.get("FONT"));
    set_if_present(&mut context.font_map, values.get("FONT_MAP"));
    set_if_present(&mut context.font_unimap, values.get("FONT_UNIMAP"));
}

fn merge_cmdline(context: &mut Context, path: &Path) {
    let Ok(text) = fs::read_to_string(path) else {
        return;
    };
    let mut values = HashMap::new();
    for token in text.split_whitespace() {
        if let Some((key, value)) = token.split_once('=') {
            let key = key.strip_prefix("rd.").unwrap_or(key);
            values.insert(key.to_owned(), value.to_owned());
        }
    }
    set_if_present(&mut context.keymap, values.get("vconsole.keymap"));
    set_if_present(
        &mut context.keymap_toggle,
        values
            .get("vconsole.keymap_toggle")
            .or_else(|| values.get("vconsole.keymap.toggle")),
    );
    set_if_present(&mut context.font, values.get("vconsole.font"));
    set_if_present(
        &mut context.font_map,
        values
            .get("vconsole.font_map")
            .or_else(|| values.get("vconsole.font.map")),
    );
    set_if_present(
        &mut context.font_unimap,
        values
            .get("vconsole.font_unimap")
            .or_else(|| values.get("vconsole.font.unimap")),
    );
}

fn set_if_present(target: &mut Option<String>, value: Option<&String>) {
    if let Some(value) = value {
        *target = Some(value.clone());
    }
}

fn parse_env(text: &str) -> HashMap<String, String> {
    let mut result = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, raw)) = line.split_once('=') else {
            continue;
        };
        let value = raw.trim().trim_matches(|c| c == '\'' || c == '"');
        result.insert(key.trim().to_owned(), value.to_owned());
    }
    result
}

fn find_source_vc() -> Result<Option<(PathBuf, fs::File)>, String> {
    let dev = env::var_os("RUSTD_DEV_ROOT").map_or_else(|| PathBuf::from("/dev"), PathBuf::from);
    let mut found_allocated = false;
    for index in 1..=63 {
        if !dev.join(format!("vcs{index}")).exists() {
            continue;
        }
        found_allocated = true;
        let path = dev.join(format!("tty{index}"));
        if let Ok(fd) = open_verified_vc(&path, true) {
            return Ok(Some((path, fd)));
        }
    }
    if found_allocated {
        Ok(None)
    } else {
        Err(String::from(
            "No virtual console that can be configured found.",
        ))
    }
}

fn open_verified_vc(path: &Path, strict_display: bool) -> Result<fs::File, String> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|error| format!("Failed to open {}: {error}", path.display()))?;
    let fd = file.as_raw_fd();
    let mut kbmode: libc::c_int = 0;
    // SAFETY: ioctl writes an integer to a valid pointer for this open terminal descriptor.
    if unsafe { libc::ioctl(fd, KDGKBMODE, &mut kbmode) } < 0 {
        return Err(format!(
            "Device {} is not a usable virtual console: {}",
            path.display(),
            io::Error::last_os_error()
        ));
    }
    if kbmode != K_XLATE && kbmode != K_UNICODE {
        return Err(format!("Virtual console {} is busy.", path.display()));
    }
    let mut mode: libc::c_int = 0;
    // SAFETY: ioctl writes an integer to a valid pointer for this open terminal descriptor.
    if unsafe { libc::ioctl(fd, KDGETMODE, &mut mode) } < 0 {
        return Err(format!(
            "Failed to query display mode for {}: {}",
            path.display(),
            io::Error::last_os_error()
        ));
    }
    if strict_display && mode != KD_TEXT {
        return Err(format!("Virtual console {} is busy.", path.display()));
    }
    if !strict_display && mode != KD_TEXT {
        eprintln!("rustd-vconsole-setup: Virtual console {} is not in KD_TEXT, font settings likely won't be applied.", path.display());
    }
    Ok(file)
}

fn locale_is_utf8() -> bool {
    ["LC_ALL", "LC_CTYPE", "LANG"]
        .iter()
        .find_map(|name| env::var(name).ok())
        .map_or(true, |locale| {
            let upper = locale.to_ascii_uppercase();
            upper.contains("UTF-8") || upper.contains("UTF8") || upper == "C.UTF-8"
        })
}

fn toggle_utf8_sysfs(utf8: bool) {
    let path = env::var_os("RUSTD_VT_UTF8_PATH").map_or_else(
        || PathBuf::from("/sys/module/vt/parameters/default_utf8"),
        PathBuf::from,
    );
    if let Err(error) = fs::write(&path, if utf8 { "1\n" } else { "0\n" }) {
        eprintln!(
            "rustd-vconsole-setup: Failed to set {}: {error}",
            path.display()
        );
    }
}

fn toggle_utf8_vc(path: &Path, file: &fs::File, utf8: bool) {
    let fd = file.as_raw_fd();
    let mode = if utf8 { K_UNICODE } else { K_XLATE };
    // SAFETY: ioctl consumes the integer keyboard mode for this terminal descriptor.
    if unsafe { libc::ioctl(fd, KDSKBMODE, mode) } < 0 {
        eprintln!(
            "rustd-vconsole-setup: Failed to set keyboard mode on {}: {}",
            path.display(),
            io::Error::last_os_error()
        );
    }
    if let Ok(mut output) = file.try_clone() {
        let _ = output.write_all(if utf8 { b"\x1b%G" } else { b"\x1b%@" });
    }
    // SAFETY: tcgetattr/tcsetattr operate on an open terminal descriptor and initialized termios storage.
    unsafe {
        let mut termios: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut termios) == 0 {
            if utf8 {
                termios.c_iflag |= libc::IUTF8;
            } else {
                termios.c_iflag &= !libc::IUTF8;
            }
            let _ = libc::tcsetattr(fd, libc::TCSANOW, &termios);
        }
    }
}

fn command_path(variable: &str, fallback: &str) -> PathBuf {
    env::var_os(variable).map_or_else(|| PathBuf::from(fallback), PathBuf::from)
}

fn load_keymap(vc: &Path, context: &Context, utf8: bool) -> Result<bool, String> {
    let keymap = context
        .keymap
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_KEYMAP);
    if keymap == "@kernel" {
        return Ok(false);
    }
    let loadkeys = command_path("RUSTD_LOADKEYS", "/usr/bin/loadkeys");
    if !loadkeys.exists() {
        return Ok(false);
    }
    let mut command = Command::new(loadkeys);
    command.arg("-q").arg("-C").arg(vc);
    if utf8 {
        command.arg("-u");
    }
    command.arg(keymap);
    if let Some(toggle) = context.keymap_toggle.as_deref().filter(|v| !v.is_empty()) {
        command.arg(toggle);
    }
    let status = command
        .status()
        .map_err(|error| format!("Failed to execute loadkeys: {error}"))?;
    require_success("loadkeys", status)?;
    Ok(true)
}

fn load_font(vc: &Path, context: &Context) -> Result<bool, String> {
    if context.font.as_deref().unwrap_or("").is_empty()
        && context.font_map.as_deref().unwrap_or("").is_empty()
        && context.font_unimap.as_deref().unwrap_or("").is_empty()
    {
        return Ok(false);
    }
    let setfont = command_path("RUSTD_SETFONT", "/usr/bin/setfont");
    if !setfont.exists() {
        return Ok(false);
    }
    let status = run_setfont(&setfont, vc, context)
        .map_err(|error| format!("Failed to execute setfont: {error}"))?;
    if status.code() == Some(EX_OSERR) {
        return Ok(false);
    }
    require_success("setfont", status)?;
    Ok(true)
}

fn run_setfont(setfont: &Path, vc: &Path, context: &Context) -> io::Result<ExitStatus> {
    let mut command = Command::new(setfont);
    command.arg("-C").arg(vc);
    if let Some(map) = context.font_map.as_deref().filter(|v| !v.is_empty()) {
        command.arg("-m").arg(map);
    }
    if let Some(unimap) = context.font_unimap.as_deref().filter(|v| !v.is_empty()) {
        command.arg("-u").arg(unimap);
    }
    if let Some(font) = context.font.as_deref().filter(|v| !v.is_empty()) {
        command.arg(font);
    }
    command.status()
}

fn require_success(name: &str, status: ExitStatus) -> Result<(), String> {
    if status.success() {
        Ok(())
    } else {
        Err(format!("{name} failed with exit status {status}."))
    }
}

fn setup_remaining_vcs(source: &Path, context: &Context, utf8: bool) {
    let dev = env::var_os("RUSTD_DEV_ROOT").map_or_else(|| PathBuf::from("/dev"), PathBuf::from);
    let setfont = command_path("RUSTD_SETFONT", "/usr/bin/setfont");
    for index in 1..=63 {
        let path = dev.join(format!("tty{index}"));
        if path == source || !dev.join(format!("vcs{index}")).exists() {
            continue;
        }
        let Ok(file) = open_verified_vc(&path, true) else {
            continue;
        };
        toggle_utf8_vc(&path, &file, utf8);
        if setfont.exists() {
            let _ = run_setfont(&setfont, &path, context);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_parser_handles_quotes_and_comments() {
        let values = parse_env("# comment\nKEYMAP=us\nFONT=\"ter-v16n\"\n");
        assert_eq!(values.get("KEYMAP").map(String::as_str), Some("us"));
        assert_eq!(values.get("FONT").map(String::as_str), Some("ter-v16n"));
    }

    #[test]
    fn cmdline_new_names_override_legacy_names() {
        let mut context = Context::default();
        let path =
            std::env::temp_dir().join(format!("rustd-vconsole-cmdline-{}", std::process::id()));
        fs::write(&path, "vconsole.font.map=old vconsole.font_map=new").unwrap();
        let old = env::var_os("RUSTD_PROC_CMDLINE");
        env::set_var("RUSTD_PROC_CMDLINE", &path);
        merge_cmdline(&mut context, &cmdline_path());
        match old {
            Some(value) => env::set_var("RUSTD_PROC_CMDLINE", value),
            None => env::remove_var("RUSTD_PROC_CMDLINE"),
        }
        let _ = fs::remove_file(path);
        assert_eq!(context.font_map.as_deref(), Some("new"));
    }
}
