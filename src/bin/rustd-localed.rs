// SPDX-License-Identifier: LGPL-2.1-or-later
//! `io.rustd.Locale1` service compatible with systemd v261.

#![allow(clippy::unused_self)]

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use zbus::interface;

const BUS_NAME: &str = "io.rustd.Locale1";
const OBJECT_PATH: &str = "/io/rustd/Locale1";
const LOCALE_VARIABLES: &[&str] = &[
    "LANG",
    "LANGUAGE",
    "LC_CTYPE",
    "LC_NUMERIC",
    "LC_TIME",
    "LC_COLLATE",
    "LC_MONETARY",
    "LC_MESSAGES",
    "LC_PAPER",
    "LC_NAME",
    "LC_ADDRESS",
    "LC_TELEPHONE",
    "LC_MEASUREMENT",
    "LC_IDENTIFICATION",
];

fn configured_path(variable: &str, fallback: &str) -> PathBuf {
    std::env::var_os(variable).map_or_else(|| PathBuf::from(fallback), PathBuf::from)
}

fn locale_path() -> PathBuf {
    configured_path("SYSTEMD_ETC_LOCALE_CONF", "/etc/locale.conf")
}

fn vconsole_path() -> PathBuf {
    configured_path("SYSTEMD_ETC_VCONSOLE_CONF", "/etc/vconsole.conf")
}

fn x11_path() -> PathBuf {
    configured_path(
        "SYSTEMD_X11_KEYBOARD_CONF",
        "/etc/X11/xorg.conf.d/00-keyboard.conf",
    )
}

fn kbd_model_map_path() -> PathBuf {
    configured_path("SYSTEMD_KBD_MODEL_MAP", "/usr/share/systemd/kbd-model-map")
}

fn read_env(path: &Path) -> BTreeMap<String, String> {
    let Ok(text) = fs::read_to_string(path) else {
        return BTreeMap::new();
    };
    text.lines()
        .filter_map(|raw| {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (key, value) = line.split_once('=')?;
            Some((
                key.trim().to_owned(),
                value.trim().trim_matches('"').to_owned(),
            ))
        })
        .collect()
}

fn quote_env(value: &str) -> String {
    if value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'/')
    }) {
        value.to_owned()
    } else {
        format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
    }
}

fn write_env(path: &Path, values: &BTreeMap<String, String>) -> io::Result<()> {
    if values.is_empty() {
        return match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        };
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut output = String::new();
    for (key, value) in values {
        output.push_str(key);
        output.push('=');
        output.push_str(&quote_env(value));
        output.push('\n');
    }
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    fs::write(&tmp, output)?;
    fs::rename(tmp, path)
}

fn valid_locale_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && !value
            .bytes()
            .any(|byte| byte == 0 || byte == b'\n' || byte == b'\r' || byte.is_ascii_whitespace())
}

fn parse_locale_assignments(assignments: &[String]) -> io::Result<BTreeMap<String, String>> {
    let mut parsed = BTreeMap::new();
    if assignments.len() == 1 && !assignments[0].contains('=') {
        if !valid_locale_value(&assignments[0]) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid locale",
            ));
        }
        parsed.insert("LANG".to_owned(), assignments[0].clone());
        return Ok(parsed);
    }
    for assignment in assignments {
        let Some((name, value)) = assignment.split_once('=') else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "locale assignment is missing '='",
            ));
        };
        if !LOCALE_VARIABLES.contains(&name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported locale variable {name}"),
            ));
        }
        if !valid_locale_value(value) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid locale value for {name}"),
            ));
        }
        if parsed.insert(name.to_owned(), value.to_owned()).is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("locale variable {name} specified twice"),
            ));
        }
    }
    Ok(parsed)
}

fn locale_environment() -> Vec<String> {
    let values = read_env(&locale_path());
    LOCALE_VARIABLES
        .iter()
        .filter_map(|name| values.get(*name).map(|value| format!("{name}={value}")))
        .collect()
}

fn set_locale_environment(assignments: &[String]) -> io::Result<()> {
    let parsed = parse_locale_assignments(assignments)?;
    write_env(&locale_path(), &parsed)
}

#[derive(Clone, Default, Debug, PartialEq, Eq)]
struct X11Keyboard {
    layout: String,
    model: String,
    variant: String,
    options: String,
}

fn unquote_xorg_fields(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for ch in line.chars() {
        match ch {
            '"' => {
                quoted = !quoted;
                if !quoted {
                    fields.push(std::mem::take(&mut current));
                }
            }
            _ if quoted => current.push(ch),
            _ => {}
        }
    }
    fields
}

fn read_x11() -> X11Keyboard {
    let Ok(text) = fs::read_to_string(x11_path()) else {
        return X11Keyboard::default();
    };
    let mut result = X11Keyboard::default();
    let mut in_input_class = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with("Section") && line.contains("\"InputClass\"") {
            in_input_class = true;
            continue;
        }
        if line.starts_with("EndSection") {
            in_input_class = false;
            continue;
        }
        if !in_input_class || !line.starts_with("Option") {
            continue;
        }
        let fields = unquote_xorg_fields(line);
        if fields.len() < 2 {
            continue;
        }
        match fields[0].as_str() {
            "XkbLayout" => result.layout.clone_from(&fields[1]),
            "XkbModel" => result.model.clone_from(&fields[1]),
            "XkbVariant" => result.variant.clone_from(&fields[1]),
            "XkbOptions" => result.options.clone_from(&fields[1]),
            _ => {}
        }
    }
    result
}

fn validate_x11(value: &str) -> bool {
    value.len() <= 4096
        && !value
            .bytes()
            .any(|byte| matches!(byte, 0 | b'\n' | b'\r' | b'"'))
}

fn write_x11(x11: &X11Keyboard) -> io::Result<()> {
    if [&x11.layout, &x11.model, &x11.variant, &x11.options]
        .iter()
        .all(|value| value.is_empty())
    {
        return match fs::remove_file(x11_path()) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        };
    }
    if ![&x11.layout, &x11.model, &x11.variant, &x11.options]
        .iter()
        .all(|value| validate_x11(value))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid X11 keymap",
        ));
    }
    let path = x11_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut output = String::from(
        "# Written by systemd-localed(8), read by systemd-localed and Xorg. It's\n\
# probably wise not to edit this file manually. Use localectl(1) to\n\
# update this file.\n\
Section \"InputClass\"\n\
        Identifier \"system-keyboard\"\n\
        MatchIsKeyboard \"on\"\n",
    );
    for (name, value) in [
        ("XkbLayout", &x11.layout),
        ("XkbModel", &x11.model),
        ("XkbVariant", &x11.variant),
        ("XkbOptions", &x11.options),
    ] {
        if !value.is_empty() {
            output.push_str(&format!("        Option \"{name}\" \"{value}\"\n"));
        }
    }
    output.push_str("EndSection\n");
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    fs::write(&tmp, output)?;
    fs::rename(tmp, path)
}

fn vconsole_keyboard() -> (String, String) {
    let values = read_env(&vconsole_path());
    (
        values.get("KEYMAP").cloned().unwrap_or_default(),
        values.get("KEYMAP_TOGGLE").cloned().unwrap_or_default(),
    )
}

fn validate_keymap(value: &str) -> bool {
    value.len() <= 255
        && !value.bytes().any(|byte| {
            byte == 0
                || byte == b'/'
                || byte == b'\n'
                || byte == b'\r'
                || byte.is_ascii_whitespace()
        })
}

fn write_vconsole(keymap: &str, toggle: &str, x11: Option<&X11Keyboard>) -> io::Result<()> {
    if (!keymap.is_empty() && !validate_keymap(keymap))
        || (!toggle.is_empty() && !validate_keymap(toggle))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid console keymap",
        ));
    }
    let path = vconsole_path();
    let mut values = read_env(&path);
    for (name, value) in [("KEYMAP", keymap), ("KEYMAP_TOGGLE", toggle)] {
        if value.is_empty() {
            values.remove(name);
        } else {
            values.insert(name.to_owned(), value.to_owned());
        }
    }
    if let Some(x11) = x11 {
        for (name, value) in [
            ("XKBLAYOUT", &x11.layout),
            ("XKBMODEL", &x11.model),
            ("XKBVARIANT", &x11.variant),
            ("XKBOPTIONS", &x11.options),
        ] {
            if value.is_empty() {
                values.remove(name);
            } else {
                values.insert(name.to_owned(), value.clone());
            }
        }
    }
    write_env(&path, &values)
}

fn decode_map_field(value: &str) -> String {
    if value == "-" {
        String::new()
    } else {
        value.to_owned()
    }
}

fn console_to_x11(keymap: &str) -> Option<X11Keyboard> {
    let text = fs::read_to_string(kbd_model_map_path()).ok()?;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 5 && fields[0] == keymap {
            return Some(X11Keyboard {
                layout: decode_map_field(fields[1]),
                model: decode_map_field(fields[2]),
                variant: decode_map_field(fields[3]),
                options: decode_map_field(fields[4]),
            });
        }
    }
    None
}

fn x11_to_console(x11: &X11Keyboard) -> Option<String> {
    let text = fs::read_to_string(kbd_model_map_path()).ok()?;
    let mut fallback = None;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 5 || decode_map_field(fields[1]) != x11.layout {
            continue;
        }
        if fallback.is_none() {
            fallback = Some(fields[0].to_owned());
        }
        if decode_map_field(fields[2]) == x11.model
            && decode_map_field(fields[3]) == x11.variant
            && decode_map_field(fields[4]) == x11.options
        {
            return Some(fields[0].to_owned());
        }
    }
    fallback
}

async fn authorize(
    connection: &zbus::Connection,
    header: &zbus::MessageHeader<'_>,
    action: &str,
    interactive: bool,
) -> zbus::fdo::Result<()> {
    let uid = rustd::dbus::auth::caller_uid(connection, header).await?;
    if uid == 0 {
        return Ok(());
    }
    let sender = header.sender().ok_or_else(|| {
        zbus::fdo::Error::AccessDenied("unable to determine D-Bus caller identity".into())
    })?;
    let proxy = zbus::Proxy::new(
        connection,
        "org.freedesktop.PolicyKit1",
        "/org/freedesktop/PolicyKit1/Authority",
        "org.freedesktop.PolicyKit1.Authority",
    )
    .await
    .map_err(|_| zbus::fdo::Error::AccessDenied("polkit service unavailable".into()))?;
    let mut subject_details = HashMap::new();
    subject_details.insert("name", zbus::zvariant::Value::from(sender.as_str()));
    let details: HashMap<&str, &str> = HashMap::new();
    let flags = u32::from(interactive);
    let (authorized, challenge, _returned): (bool, bool, HashMap<String, String>) = proxy
        .call(
            "CheckAuthorization",
            &(
                ("system-bus-name", subject_details),
                action,
                details,
                flags,
                "",
            ),
        )
        .await
        .map_err(|_| zbus::fdo::Error::AccessDenied("polkit authorization failed".into()))?;
    if authorized {
        Ok(())
    } else if challenge {
        Err(zbus::fdo::Error::AccessDenied(
            "polkit authorization challenge was not satisfied".into(),
        ))
    } else {
        Err(zbus::fdo::Error::AccessDenied(
            "polkit authorization denied".into(),
        ))
    }
}

fn io_to_dbus(error: io::Error) -> zbus::fdo::Error {
    if error.kind() == io::ErrorKind::InvalidInput {
        zbus::fdo::Error::InvalidArgs(error.to_string())
    } else {
        zbus::fdo::Error::Failed(error.to_string())
    }
}

async fn restart_vconsole(connection: &zbus::Connection) -> zbus::fdo::Result<()> {
    let proxy = zbus::Proxy::new(
        connection,
        "io.rustd.Manager1",
        "/io/rustd/Manager1",
        "io.rustd.Manager1.Manager",
    )
    .await
    .map_err(|error| zbus::fdo::Error::Failed(error.to_string()))?;
    let _: zbus::zvariant::OwnedObjectPath = proxy
        .call(
            "RestartUnit",
            &("systemd-vconsole-setup.service", "replace"),
        )
        .await
        .map_err(|error| zbus::fdo::Error::Failed(error.to_string()))?;
    Ok(())
}

#[derive(Default)]
struct LocaleService;

#[interface(name = "io.rustd.Locale1")]
impl LocaleService {
    async fn set_locale(
        &self,
        locale: Vec<String>,
        interactive: bool,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<()> {
        authorize(
            connection,
            &header,
            "io.rustd.Locale1.set-locale",
            interactive,
        )
        .await?;
        set_locale_environment(&locale).map_err(io_to_dbus)
    }

    async fn set_v_console_keyboard(
        &self,
        keymap: String,
        keymap_toggle: String,
        convert: bool,
        interactive: bool,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<()> {
        authorize(
            connection,
            &header,
            "io.rustd.Locale1.set-keyboard",
            interactive,
        )
        .await?;
        let converted = convert.then(|| console_to_x11(&keymap)).flatten();
        write_vconsole(&keymap, &keymap_toggle, converted.as_ref()).map_err(io_to_dbus)?;
        if let Some(x11) = converted.as_ref() {
            write_x11(x11).map_err(io_to_dbus)?;
        }
        restart_vconsole(connection).await
    }

    #[allow(clippy::too_many_arguments)]
    async fn set_x11_keyboard(
        &self,
        layout: String,
        model: String,
        variant: String,
        options: String,
        convert: bool,
        interactive: bool,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<()> {
        authorize(
            connection,
            &header,
            "io.rustd.Locale1.set-keyboard",
            interactive,
        )
        .await?;
        let x11 = X11Keyboard {
            layout,
            model,
            variant,
            options,
        };
        write_x11(&x11).map_err(io_to_dbus)?;
        if convert {
            if let Some(keymap) = x11_to_console(&x11) {
                write_vconsole(&keymap, "", Some(&x11)).map_err(io_to_dbus)?;
                restart_vconsole(connection).await?;
            }
        }
        Ok(())
    }

    #[zbus(property)]
    fn locale(&self) -> Vec<String> {
        locale_environment()
    }

    #[zbus(property)]
    fn x11_layout(&self) -> String {
        read_x11().layout
    }

    #[zbus(property)]
    fn x11_model(&self) -> String {
        read_x11().model
    }

    #[zbus(property)]
    fn x11_variant(&self) -> String {
        read_x11().variant
    }

    #[zbus(property)]
    fn x11_options(&self) -> String {
        read_x11().options
    }

    #[zbus(property)]
    fn v_console_keymap(&self) -> String {
        vconsole_keyboard().0
    }

    #[zbus(property)]
    fn v_console_keymap_toggle(&self) -> String {
        vconsole_keyboard().1
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let connection = zbus::Connection::system().await?;
    connection
        .object_server()
        .at(OBJECT_PATH, LocaleService)
        .await?;
    connection.request_name(BUS_NAME).await?;
    let _ = rustd::native::notify_ready();
    std::future::pending::<()>().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[test]
    fn single_locale_is_lang() {
        let parsed = parse_locale_assignments(&["en_US.UTF-8".into()]).unwrap();
        assert_eq!(parsed.get("LANG").map(String::as_str), Some("en_US.UTF-8"));
    }

    #[test]
    fn duplicate_locale_variable_is_rejected() {
        let error =
            parse_locale_assignments(&["LANG=C".into(), "LANG=en_US.UTF-8".into()]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn vconsole_conversion_uses_systemd_map_format() {
        let _guard = env_lock();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kbd-model-map");
        fs::write(&path, "us us pc105 - terminate:ctrl_alt_bksp\n").unwrap();
        std::env::set_var("SYSTEMD_KBD_MODEL_MAP", &path);
        let x11 = console_to_x11("us").unwrap();
        assert_eq!(x11.layout, "us");
        assert_eq!(x11.model, "pc105");
        assert_eq!(x11.variant, "");
        assert_eq!(x11.options, "terminate:ctrl_alt_bksp");
        std::env::remove_var("SYSTEMD_KBD_MODEL_MAP");
    }

    #[test]
    fn x11_writer_round_trips() {
        let _guard = env_lock();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("00-keyboard.conf");
        std::env::set_var("SYSTEMD_X11_KEYBOARD_CONF", &path);
        let expected = X11Keyboard {
            layout: "us".into(),
            model: "pc105".into(),
            variant: "intl".into(),
            options: "compose:ralt".into(),
        };
        write_x11(&expected).unwrap();
        assert_eq!(read_x11(), expected);
        std::env::remove_var("SYSTEMD_X11_KEYBOARD_CONF");
    }
}
