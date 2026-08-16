from pathlib import Path


source = r'''// SPDX-License-Identifier: LGPL-2.1-or-later
//! XDG desktop autostart generator compatible with the v261 unit surface.

use std::collections::HashSet;
use std::env;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};

const DESKTOP_CONDITION: &str = "/usr/lib/systemd/systemd-xdg-autostart-condition";
const DEFAULT_CONFIG_DIR: &str = "/etc/xdg";
const DEFAULT_EXEC_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin";

#[derive(Debug, Default, PartialEq, Eq)]
struct DesktopEntry {
    path: PathBuf,
    description: Option<String>,
    entry_type: Option<String>,
    exec: Option<String>,
    working_directory: Option<String>,
    only_show_in: Option<Vec<String>>,
    not_show_in: Option<Vec<String>>,
    hidden: bool,
    skip_generator: bool,
    try_exec: Option<String>,
    autostart_condition: Option<String>,
    kde_autostart_condition: Option<String>,
    gnome_autostart_phase: Option<String>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("rustd-xdg-autostart-generator: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let arguments: Vec<OsString> = env::args_os().collect();
    if arguments.len() != 4 {
        return Err(String::from(
            "Generator expects normal, early, and late output directories.",
        ));
    }

    let home = home_directory()?;
    let autostart_dirs = autostart_directories(&home);
    let destination = PathBuf::from(&arguments[3]);
    generate_units(&destination, &autostart_dirs, &home, &lookup_executable)
}

fn home_directory() -> Result<PathBuf, String> {
    env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| String::from("HOME is not set to an absolute path"))
}

fn autostart_directories(home: &Path) -> Vec<PathBuf> {
    let user_config = env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or_else(|| home.join(".config"));
    let mut directories = vec![user_config.join("autostart")];

    let config_dirs = env::var_os("XDG_CONFIG_DIRS").map_or_else(
        || vec![PathBuf::from(DEFAULT_CONFIG_DIR)],
        |value| {
            env::split_paths(&value)
                .filter(|path| !path.as_os_str().is_empty())
                .collect()
        },
    );
    directories.extend(config_dirs.into_iter().map(|path| path.join("autostart")));
    directories
}

fn generate_units<F>(
    destination: &Path,
    autostart_dirs: &[PathBuf],
    home: &Path,
    lookup: &F,
) -> Result<(), String>
where
    F: Fn(&str) -> Option<PathBuf>,
{
    fs::create_dir_all(destination)
        .map_err(|error| format!("Failed to create {}: {error}", destination.display()))?;

    let mut seen = HashSet::new();
    for directory in autostart_dirs {
        let entries = match fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                eprintln!(
                    "rustd-xdg-autostart-generator: opening {} failed, ignoring: {error}",
                    directory.display()
                );
                continue;
            }
        };
        let mut entries = entries.filter_map(Result::ok).collect::<Vec<_>>();
        entries.sort_by_key(std::fs::DirEntry::file_name);

        for directory_entry in entries {
            let path = directory_entry.path();
            let metadata = match fs::metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) => {
                    eprintln!(
                        "rustd-xdg-autostart-generator: {}: stat failed, ignoring: {error}",
                        path.display()
                    );
                    continue;
                }
            };
            if !metadata.is_file() {
                continue;
            }

            let file_name = directory_entry.file_name();
            let file_name = file_name.to_string_lossy();
            let unit_name = translate_name(&file_name);
            if !seen.insert(unit_name.clone()) {
                continue;
            }

            let text = match fs::read_to_string(&path) {
                Ok(text) => text,
                Err(error) => {
                    eprintln!(
                        "rustd-xdg-autostart-generator: failed to read {}, masking lower-priority entries: {error}",
                        path.display()
                    );
                    continue;
                }
            };
            let desktop = match parse_desktop(&path, &text) {
                Ok(desktop) => desktop,
                Err(error) => {
                    eprintln!(
                        "rustd-xdg-autostart-generator: failed to parse {}, masking lower-priority entries: {error}",
                        path.display()
                    );
                    continue;
                }
            };
            let Some(unit) = render_unit(&desktop, home, lookup)? else {
                continue;
            };

            write_generated_unit(destination, &unit_name, &unit)?;
        }
    }
    Ok(())
}

fn write_generated_unit(destination: &Path, unit_name: &str, contents: &str) -> Result<(), String> {
    let unit_path = destination.join(unit_name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&unit_path)
        .map_err(|error| format!("Failed to create {}: {error}", unit_path.display()))?;
    file.write_all(contents.as_bytes())
        .and_then(|()| file.flush())
        .map_err(|error| format!("Failed to write {}: {error}", unit_path.display()))?;

    let wants = destination.join("xdg-desktop-autostart.target.wants");
    fs::create_dir_all(&wants)
        .map_err(|error| format!("Failed to create {}: {error}", wants.display()))?;
    let link = wants.join(unit_name);
    if fs::symlink_metadata(&link).is_ok() {
        fs::remove_file(&link)
            .map_err(|error| format!("Failed to replace {}: {error}", link.display()))?;
    }
    symlink(Path::new("..").join(unit_name), &link)
        .map_err(|error| format!("Failed to create {}: {error}", link.display()))?;
    Ok(())
}

fn translate_name(file_name: &str) -> String {
    let base = file_name.strip_suffix(".desktop").unwrap_or(file_name);
    format!("app-{}@autostart.service", unit_name_escape(base))
}

fn valid_unit_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'.')
}

fn unit_name_escape(value: &str) -> String {
    let mut result = String::with_capacity(value.len().saturating_mul(4));
    for (index, byte) in value.bytes().enumerate() {
        if byte == b'/' {
            result.push('-');
        } else if (index == 0 && byte == b'.')
            || byte == b'-'
            || byte == b'\\'
            || !valid_unit_byte(byte)
        {
            use std::fmt::Write as _;
            let _ = write!(result, "\\x{byte:02x}");
        } else {
            result.push(char::from(byte));
        }
    }
    result
}

fn parse_desktop(path: &Path, text: &str) -> Result<DesktopEntry, String> {
    let mut desktop = DesktopEntry {
        path: path.to_path_buf(),
        ..DesktopEntry::default()
    };
    let mut section = String::new();

    for (line_number, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section.clear();
            section.push_str(&line[1..line.len() - 1]);
            continue;
        }
        if section != "Desktop Entry" {
            continue;
        }
        let Some((raw_key, raw_value)) = raw_line.split_once('=') else {
            continue;
        };
        let key = raw_key.trim();
        if key.contains('[') {
            continue;
        }
        let value = raw_value.trim();
        let line_number = line_number + 1;

        match key {
            "Name" => set_string_once(&mut desktop.description, value, line_number)?,
            "Exec" => set_string_once(&mut desktop.exec, value, line_number)?,
            "Path" => set_string_once(&mut desktop.working_directory, value, line_number)?,
            "TryExec" => set_string_once(&mut desktop.try_exec, value, line_number)?,
            "Type" => set_string_once(&mut desktop.entry_type, value, line_number)?,
            "OnlyShowIn" if desktop.only_show_in.is_none() => {
                if let Ok(values) = parse_string_list(value) {
                    desktop.only_show_in = Some(values);
                }
            }
            "NotShowIn" if desktop.not_show_in.is_none() => {
                if let Ok(values) = parse_string_list(value) {
                    desktop.not_show_in = Some(values);
                }
            }
            "Hidden" => {
                desktop.hidden = parse_boolean(value)
                    .ok_or_else(|| format!("line {line_number}: invalid Hidden= boolean"))?;
            }
            "AutostartCondition" => {
                set_string_once(&mut desktop.autostart_condition, value, line_number)?;
            }
            "X-KDE-autostart-condition" => {
                set_string_once(&mut desktop.kde_autostart_condition, value, line_number)?;
            }
            "X-GNOME-Autostart-Phase" => {
                set_string_once(&mut desktop.gnome_autostart_phase, value, line_number)?;
            }
            "X-systemd-skip" | "X-rustd-skip" => {
                desktop.skip_generator = parse_boolean(value).ok_or_else(|| {
                    format!("line {line_number}: invalid generator skip boolean")
                })?;
            }
            _ => {}
        }
    }

    Ok(desktop)
}

fn set_string_once(slot: &mut Option<String>, value: &str, line: usize) -> Result<(), String> {
    if slot.is_none() {
        *slot = Some(unescape_desktop(value).map_err(|error| format!("line {line}: {error}"))?);
    }
    Ok(())
}

fn parse_boolean(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "yes" | "true" | "on" => Some(true),
        "0" | "no" | "false" | "off" => Some(false),
        _ => None,
    }
}

fn parse_string_list(value: &str) -> Result<Vec<String>, String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut characters = value.chars();
    while let Some(character) = characters.next() {
        if character == '\\' {
            let escaped = characters
                .next()
                .ok_or_else(|| String::from("trailing backslash in string list"))?;
            if !matches!(escaped, 's' | 'n' | 't' | 'r' | '\\' | ';') {
                return Err(format!("undefined escape sequence \\{escaped}"));
            }
            current.push('\\');
            current.push(escaped);
        } else if character == ';' {
            if !current.is_empty() {
                fields.push(unescape_desktop(&current)?);
                current.clear();
            }
        } else {
            current.push(character);
        }
    }
    if !current.is_empty() {
        fields.push(unescape_desktop(&current)?);
    }
    Ok(fields)
}

fn unescape_desktop(value: &str) -> Result<String, String> {
    let mut result = String::with_capacity(value.len());
    let mut characters = value.chars();
    while let Some(character) = characters.next() {
        if character != '\\' {
            result.push(character);
            continue;
        }
        let escaped = characters
            .next()
            .ok_or_else(|| String::from("trailing backslash"))?;
        result.push(match escaped {
            's' => ' ',
            'n' => '\n',
            't' => '\t',
            'r' => '\r',
            '\\' => '\\',
            ';' => ';',
            other => return Err(format!("undefined escape sequence \\{other}")),
        });
    }
    Ok(result)
}

fn split_exec(value: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut characters = value.chars().peekable();

    while let Some(character) = characters.next() {
        match (quote, character) {
            (Some(active), candidate) if candidate == active => quote = None,
            (None, '\'' | '"') => quote = Some(character),
            (_, '\\') => {
                if let Some(next) = characters.next() {
                    current.push(next);
                } else {
                    current.push('\\');
                }
            }
            (None, candidate) if candidate.is_whitespace() => {
                if !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(character),
        }
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

fn format_exec_start<F>(exec: &str, home: &Path, lookup: &F) -> Result<String, String>
where
    F: Fn(&str) -> Option<PathBuf>,
{
    let words = split_exec(exec);
    let Some(executable) = words.first() else {
        return Err(String::from("Exec line is empty"));
    };
    let executable = lookup(executable)
        .ok_or_else(|| format!("Exec binary '{executable}' does not exist"))?;
    let mut output = vec![executable.to_string_lossy().into_owned()];

    for argument in words.iter().skip(1) {
        if matches!(
            argument.as_str(),
            "%f" | "%F" | "%u" | "%U" | "%d" | "%D" | "%n" | "%N" | "%i"
                | "%c" | "%k" | "%v" | "%m"
        ) {
            continue;
        }
        let collapsed = argument.replace("%%", "%");
        let escaped_percent = collapsed.replace('%', "%%");
        let expanded = if escaped_percent == "~" {
            home.to_string_lossy().into_owned()
        } else if let Some(rest) = escaped_percent.strip_prefix("~/") {
            home.join(rest).to_string_lossy().into_owned()
        } else {
            escaped_percent
        };
        output.push(expanded);
    }

    Ok(output
        .iter()
        .map(|argument| quote_command_argument(argument))
        .collect::<Vec<_>>()
        .join(" "))
}

fn quote_command_argument(argument: &str) -> String {
    if argument.is_empty() {
        return String::from("\"\"");
    }
    let safe = argument.chars().all(|character| {
        character.is_ascii_alphanumeric()
            || matches!(
                character,
                '/' | '_' | '-' | '.' | ':' | '%' | '+' | '=' | ',' | '@' | '~'
            )
    });
    if safe {
        return argument.to_owned();
    }
    format!("\"{}\"", c_escape(argument))
}

fn c_escape(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            _ => result.push(character),
        }
    }
    result
}

fn specifier_escape(value: &str) -> String {
    value.replace('%', "%%")
}

#[allow(clippy::too_many_lines)]
fn render_unit<F>(desktop: &DesktopEntry, home: &Path, lookup: &F) -> Result<Option<String>, String>
where
    F: Fn(&str) -> Option<PathBuf>,
{
    if desktop.hidden || desktop.skip_generator {
        return Ok(None);
    }
    if desktop.entry_type.as_deref() != Some("Application") {
        return Ok(None);
    }
    let Some(exec) = desktop.exec.as_deref() else {
        return Ok(None);
    };
    if desktop
        .try_exec
        .as_deref()
        .is_some_and(|try_exec| lookup(try_exec).is_none())
    {
        return Ok(None);
    }

    let exec_start = match format_exec_start(exec, home, lookup) {
        Ok(exec_start) => exec_start,
        Err(error) if error.contains("does not exist") => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut only_show_in = desktop.only_show_in.clone().unwrap_or_default();
    let mut not_show_in = desktop.not_show_in.clone().unwrap_or_default();
    if desktop.gnome_autostart_phase.is_some() {
        if let Some(position) = only_show_in.iter().position(|desktop| desktop == "GNOME") {
            only_show_in.remove(position);
            if only_show_in.is_empty() {
                return Ok(None);
            }
        }
        not_show_in.push(String::from("GNOME"));
    }

    let mut unit = String::new();
    unit.push_str("[Unit]\n");
    unit.push_str("Documentation=man:systemd-xdg-autostart-generator(8)\n");
    unit.push_str(&format!(
        "SourcePath={}\n",
        specifier_escape(&desktop.path.to_string_lossy())
    ));
    unit.push_str("PartOf=graphical-session.target\n\n");
    if let Some(description) = &desktop.description {
        unit.push_str(&format!("Description={}\n", specifier_escape(description)));
    }
    unit.push_str("After=graphical-session.target\n\n");
    unit.push_str("[Service]\n");
    unit.push_str("Type=exec\n");
    unit.push_str("ExitType=cgroup\n");
    unit.push_str(&format!("ExecStart=:{exec_start}\n"));
    unit.push_str("Restart=no\n");
    unit.push_str("TimeoutStopSec=5s\n");
    unit.push_str("Slice=app.slice\n");

    if let Some(directory) = &desktop.working_directory {
        unit.push_str(&format!("WorkingDirectory=-{}\n", c_escape(directory)));
    }
    if !only_show_in.is_empty() || !not_show_in.is_empty() {
        unit.push_str(&format!(
            "ExecCondition={DESKTOP_CONDITION} \"{}\" \"{}\"\n",
            c_escape(&only_show_in.join(":")),
            c_escape(&not_show_in.join(":"))
        ));
    }
    append_external_condition(
        &mut unit,
        "gnome-systemd-autostart-condition",
        desktop.autostart_condition.as_deref(),
        lookup,
    );
    append_external_condition(
        &mut unit,
        "kde-systemd-start-condition",
        desktop.kde_autostart_condition.as_deref(),
        lookup,
    );
    Ok(Some(unit))
}

fn append_external_condition<F>(
    unit: &mut String,
    binary: &str,
    condition: Option<&str>,
    lookup: &F,
) where
    F: Fn(&str) -> Option<PathBuf>,
{
    let Some(condition) = condition.filter(|condition| !condition.is_empty()) else {
        return;
    };
    if let Some(executable) = lookup(binary) {
        unit.push_str(&format!(
            "ExecCondition={} --condition \"{}\"\n",
            executable.display(),
            c_escape(condition)
        ));
    } else {
        unit.push_str(&format!(
            "# ExecCondition using {binary} skipped due to missing binary.\n"
        ));
    }
}

fn lookup_executable(program: &str) -> Option<PathBuf> {
    if program.contains('/') {
        let path = PathBuf::from(program);
        return is_executable(&path).then_some(path);
    }

    let path = env::var_os("PATH").unwrap_or_else(|| OsString::from(DEFAULT_EXEC_PATH));
    for directory in env::split_paths(&path) {
        let candidate = directory.join(program);
        if is_executable(&candidate) {
            return if candidate.is_absolute() {
                Some(candidate)
            } else {
                env::current_dir().ok().map(|cwd| cwd.join(candidate))
            };
        }
    }
    None
}

fn is_executable(path: &Path) -> bool {
    fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup(program: &str) -> Option<PathBuf> {
        match program {
            "/bin/sleep" | "/bin/echo" | "/bin/ls" => Some(PathBuf::from(program)),
            "present" => Some(PathBuf::from("/usr/bin/present")),
            "gnome-systemd-autostart-condition" => {
                Some(PathBuf::from("/usr/bin/gnome-systemd-autostart-condition"))
            }
            _ => None,
        }
    }

    #[test]
    fn translate_name_matches_v261() {
        assert_eq!(
            translate_name("a-b.blub.desktop"),
            "app-a\\x2db.blub@autostart.service"
        );
    }

    #[test]
    fn format_exec_start_matches_v261_field_codes() {
        let home = Path::new("/home/example");
        assert_eq!(
            format_exec_start("/bin/sleep 100", home, &lookup).unwrap(),
            "/bin/sleep 100"
        );
        assert_eq!(
            format_exec_start(
                "/bin/sleep %f \"%F\" %u %U %d %D %n %N %i %c %k %v %m",
                home,
                &lookup,
            )
            .unwrap(),
            "/bin/sleep"
        );
        assert_eq!(
            format_exec_start("/bin/sleep %X \"%Y\"", home, &lookup).unwrap(),
            "/bin/sleep %%X %%Y"
        );
        assert_eq!(
            format_exec_start("/bin/ls ~ \"~/foo\" ~foo foo~", home, &lookup).unwrap(),
            "/bin/ls /home/example /home/example/foo ~foo foo~"
        );
    }

    #[test]
    fn desktop_parser_uses_first_string_definition_and_unescapes_lists() {
        let text = "[Desktop Entry]\nExec = /bin/sleep 100\nExec=/bin/false\nOnlyShowIn=A;B;\nNotShowIn=C;;D\\;;E\nHidden=True\n";
        let desktop = parse_desktop(Path::new("/tmp/test.desktop"), text).unwrap();
        assert_eq!(desktop.exec.as_deref(), Some("/bin/sleep 100"));
        assert_eq!(desktop.only_show_in, Some(vec![String::from("A"), String::from("B")]));
        assert_eq!(
            desktop.not_show_in,
            Some(vec![String::from("C"), String::from("D;"), String::from("E")])
        );
        assert!(desktop.hidden);
    }

    #[test]
    fn generated_application_unit_has_v261_lifecycle_contract() {
        let desktop = DesktopEntry {
            path: PathBuf::from("/home/example/.config/autostart/demo.desktop"),
            description: Some(String::from("Demo % app")),
            entry_type: Some(String::from("Application")),
            exec: Some(String::from("/bin/echo hello")),
            working_directory: Some(String::from("/tmp/demo")),
            only_show_in: Some(vec![String::from("GNOME"), String::from("KDE")]),
            not_show_in: Some(vec![String::from("XFCE")]),
            try_exec: Some(String::from("present")),
            autostart_condition: Some(String::from("if-session gnome")),
            ..DesktopEntry::default()
        };
        let unit = render_unit(&desktop, Path::new("/home/example"), &lookup)
            .unwrap()
            .unwrap();
        assert!(unit.contains("Type=exec\nExitType=cgroup\n"));
        assert!(unit.contains("ExecStart=:/bin/echo hello\n"));
        assert!(unit.contains("Restart=no\nTimeoutStopSec=5s\nSlice=app.slice\n"));
        assert!(unit.contains(
            "ExecCondition=/usr/lib/systemd/systemd-xdg-autostart-condition \"GNOME:KDE\" \"XFCE\"\n"
        ));
        assert!(unit.contains("Description=Demo %% app\n"));
        assert!(unit.contains("WorkingDirectory=-/tmp/demo\n"));
    }

    #[test]
    fn gnome_phase_removes_gnome_only_entries() {
        let desktop = DesktopEntry {
            path: PathBuf::from("/tmp/demo.desktop"),
            entry_type: Some(String::from("Application")),
            exec: Some(String::from("/bin/echo hello")),
            only_show_in: Some(vec![String::from("GNOME")]),
            gnome_autostart_phase: Some(String::from("Initialization")),
            ..DesktopEntry::default()
        };
        assert!(render_unit(&desktop, Path::new("/home/example"), &lookup)
            .unwrap()
            .is_none());
    }
}
'''

Path("src/bin/rustd-xdg-autostart-generator.rs").write_text(source, encoding="utf-8")

cargo = Path("Cargo.toml")
text = cargo.read_text(encoding="utf-8")
native_anchor = '''[[bin]]
name = "rustd-xdg-autostart-condition"
path = "src/bin/rustd-xdg-autostart-condition.rs"
'''
native_new = '''[[bin]]
name = "rustd-xdg-autostart-generator"
path = "src/bin/rustd-xdg-autostart-generator.rs"

''' + native_anchor
if text.count(native_anchor) != 1:
    raise SystemExit(f"native XDG condition Cargo anchor matches: {text.count(native_anchor)}")
text = text.replace(native_anchor, native_new, 1)
compat_anchor = '''[[bin]]
name = "systemd-xdg-autostart-condition"
path = "src/bin/rustd-xdg-autostart-condition.rs"
'''
compat_new = '''[[bin]]
name = "systemd-xdg-autostart-generator"
path = "src/bin/rustd-xdg-autostart-generator.rs"

''' + compat_anchor
if text.count(compat_anchor) != 1:
    raise SystemExit(f"compatibility XDG condition Cargo anchor matches: {text.count(compat_anchor)}")
text = text.replace(compat_anchor, compat_new, 1)
cargo.write_text(text, encoding="utf-8")

contract = Path("scripts/executable_contract.py")
text = contract.read_text(encoding="utf-8")
text = text.replace(
    '        "rustd-xdg-autostart-condition",\n',
    '        "rustd-xdg-autostart-generator",\n        "rustd-xdg-autostart-condition",\n',
    1,
)
text = text.replace(
    '    "xdg-autostart-condition",\n',
    '    "xdg-autostart-generator",\n    "xdg-autostart-condition",\n',
    1,
)
libexec_anchor = '        "rustd-xdg-autostart-condition",\n'
libexec_position = text.find(libexec_anchor, text.find("NATIVE_LIBEXEC"))
if libexec_position < 0:
    raise SystemExit("native libexec XDG condition anchor missing")
text = text[:libexec_position] + '        "rustd-xdg-autostart-generator",\n' + text[libexec_position:]
text = text.replace("assert len(NATIVE_EXECUTABLES) == 107", "assert len(NATIVE_EXECUTABLES) == 108")
text = text.replace("assert len(COMPATIBILITY_EXECUTABLES) == 102", "assert len(COMPATIBILITY_EXECUTABLES) == 103")
text = text.replace("assert EXPECTED_EXECUTABLE_COUNT == 209", "assert EXPECTED_EXECUTABLE_COUNT == 211")
text = text.replace("assert len(NATIVE_BUILD_EXECUTABLES) == 104", "assert len(NATIVE_BUILD_EXECUTABLES) == 105")
text = text.replace("assert len(COMPATIBILITY_BUILD_EXECUTABLES) == 99", "assert len(COMPATIBILITY_BUILD_EXECUTABLES) == 100")
text = text.replace("assert EXPECTED_BUILD_EXECUTABLE_COUNT == 203", "assert EXPECTED_BUILD_EXECUTABLE_COUNT == 205")
contract.write_text(text, encoding="utf-8")

parity_workflow = r'''name: RustD v261 parity inventory

on:
  push:
    branches: [main]
    paths:
      - Cargo.toml
      - src/bin/**
      - scripts/audit-upstream-v261-executables.py
      - scripts/executable_contract.py
      - scripts/rustd-resolved-revision.txt
      - docs/COMPATIBILITY.md
      - .github/workflows/rustd-v261-parity.yml
  workflow_dispatch:

permissions:
  contents: read
  statuses: write

concurrency:
  group: rustd-v261-parity-${{ github.ref }}
  cancel-in-progress: true

jobs:
  inventory:
    runs-on: ubuntu-24.04
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@v6
      - name: Measure pinned v261 parity surface
        id: parity
        shell: bash
        run: |
          set +e
          python3 scripts/audit-upstream-v261-executables.py --json --fail-on-missing | tee rustd-v261-executables.json
          inventory_rc=${PIPESTATUS[0]}
          grep '^- \[ \]' docs/COMPATIBILITY.md > rustd-open-compatibility-gates.txt
          ledger_rc=$?
          echo "inventory_rc=$inventory_rc" >> "$GITHUB_OUTPUT"
          echo "ledger_rc=$ledger_rc" >> "$GITHUB_OUTPUT"
          exit 0
      - name: Upload parity evidence
        if: always()
        uses: actions/upload-artifact@v7
        with:
          name: rustd-v261-parity-${{ github.sha }}
          path: |
            rustd-v261-executables.json
            rustd-open-compatibility-gates.txt
          if-no-files-found: warn
          retention-days: 30
      - name: Publish exact-source parity status
        if: always()
        env:
          GH_TOKEN: ${{ github.token }}
          INVENTORY_RC: ${{ steps.parity.outputs.inventory_rc }}
          LEDGER_RC: ${{ steps.parity.outputs.ledger_rc }}
        shell: bash
        run: |
          state=failure
          description='Pinned v261 parity gaps remain'
          if [ "${INVENTORY_RC:-1}" -eq 0 ] && [ "${LEDGER_RC:-0}" -ne 0 ]; then
            state=success
            description='Pinned v261 executable and compatibility surfaces are complete'
          fi
          payload=$(printf '{"state":"%s","context":"rustd/v261-parity","description":"%s","target_url":"%s"}' \
            "$state" "$description" "${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}")
          curl --fail-with-body --silent --show-error -X POST \
            -H "Accept: application/vnd.github+json" \
            -H "Authorization: Bearer $GH_TOKEN" \
            -H "X-GitHub-Api-Version: 2022-11-28" \
            "${GITHUB_API_URL}/repos/${GITHUB_REPOSITORY}/statuses/${GITHUB_SHA}" \
            --data "$payload" >/dev/null
          if [ "$state" = success ]; then exit 0; else exit 1; fi
'''
Path(".github/workflows/rustd-v261-parity.yml").write_text(parity_workflow, encoding="utf-8")
