// SPDX-License-Identifier: LGPL-2.1-or-later
//! `systemd-xdg-autostart-condition` v261 compatibility helper.

use std::env;
use std::ffi::OsString;
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;

const ARGUMENT_ERROR: &[u8] =
    b"Wrong argument count. Expected the OnlyShowIn= and NotShowIn= sets, each colon separated.\n";

fn main() {
    let arguments: Vec<OsString> = env::args_os().collect();
    match evaluate(&arguments, env::var_os("XDG_CURRENT_DESKTOP").as_ref()) {
        Ok(true) => {}
        Ok(false) => std::process::exit(1),
        Err(error) => {
            let _ = io::stderr().lock().write_all(error);
            std::process::exit(1);
        }
    }
}

fn evaluate(
    arguments: &[OsString],
    current_desktop: Option<&OsString>,
) -> Result<bool, &'static [u8]> {
    if arguments.len() != 3 {
        return Err(ARGUMENT_ERROR);
    }

    let only_show_in = split_set(arguments[1].as_os_str().as_bytes());
    let not_show_in = split_set(arguments[2].as_os_str().as_bytes());
    let desktops =
        current_desktop.map_or_else(Vec::new, |value| split_set(value.as_os_str().as_bytes()));

    for desktop in desktops {
        if only_show_in.contains(&desktop) {
            return Ok(true);
        }
        if not_show_in.contains(&desktop) {
            return Ok(false);
        }
    }

    Ok(only_show_in.is_empty())
}

fn split_set(value: &[u8]) -> Vec<&[u8]> {
    value
        .split(|byte| *byte == b':')
        .filter(|field| !field.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(only: &str, not: &str) -> Vec<OsString> {
        vec![
            OsString::from("condition"),
            OsString::from(only),
            OsString::from(not),
        ]
    }

    #[test]
    fn ordered_desktop_precedence_matches_v261() {
        let first_allowed = OsString::from("GNOME:KDE");
        let first_denied = OsString::from("KDE:GNOME");
        let sets = arguments("GNOME", "KDE");
        assert_eq!(evaluate(&sets, Some(&first_allowed)), Ok(true));
        assert_eq!(evaluate(&sets, Some(&first_denied)), Ok(false));
    }

    #[test]
    fn empty_fields_are_not_set_members() {
        assert!(split_set(b"::").is_empty());
        assert_eq!(
            split_set(b":GNOME::KDE:"),
            [b"GNOME".as_slice(), b"KDE".as_slice()]
        );
    }
}
