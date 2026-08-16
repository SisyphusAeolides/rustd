// SPDX-License-Identifier: LGPL-2.1-or-later
//! rustd-journald — collect `RustD` journal datagrams and stdout streams.
//!
//! Compatibility reference: systemd v261 `src/journald/journald.c`.

use std::path::PathBuf;

use rustd::journal::daemon::{JournalDaemon, JournalDaemonConfig};

fn main() {
    let config = match parse_args(std::env::args().skip(1)) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("rustd-journald: {error}");
            print_usage();
            std::process::exit(1);
        }
    };

    match JournalDaemon::new(&config).and_then(JournalDaemon::run) {
        Ok(_) => {}
        Err(error) => {
            eprintln!("rustd-journald: {error}");
            std::process::exit(1);
        }
    }
}

fn parse_args(arguments: impl Iterator<Item = String>) -> anyhow::Result<JournalDaemonConfig> {
    let mut config = JournalDaemonConfig::default();
    let mut arguments = arguments.peekable();

    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--runtime-directory" => {
                config.runtime_directory =
                    PathBuf::from(required_value(&mut arguments, &argument)?);
            }
            "--journal-directory" => {
                config.journal_directory =
                    PathBuf::from(required_value(&mut arguments, &argument)?);
            }
            "--journal-file" => {
                config.journal_file =
                    Some(PathBuf::from(required_value(&mut arguments, &argument)?));
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            _ => return Err(anyhow::anyhow!("unknown option {argument}")),
        }
    }

    Ok(config)
}

fn required_value(
    arguments: &mut std::iter::Peekable<impl Iterator<Item = String>>,
    option: &str,
) -> anyhow::Result<String> {
    arguments
        .next()
        .ok_or_else(|| anyhow::anyhow!("{option} requires a path"))
}

fn print_usage() {
    println!("Usage: rustd-journald [OPTIONS]");
    println!("  --runtime-directory PATH  socket directory (default: /run/rustd/journal)");
    println!(
        "  --journal-directory PATH  persistent journal directory (default: /var/log/journal)"
    );
    println!("  --journal-file PATH       explicit persistent journal file");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_private_paths() {
        let config = parse_args(
            [
                "--runtime-directory",
                "/tmp/runtime",
                "--journal-directory",
                "/tmp/journal",
                "--journal-file",
                "/tmp/journal/test.journal",
            ]
            .into_iter()
            .map(str::to_owned),
        )
        .unwrap();
        assert_eq!(config.runtime_directory, PathBuf::from("/tmp/runtime"));
        assert_eq!(config.journal_directory, PathBuf::from("/tmp/journal"));
        assert_eq!(
            config.journal_path(),
            PathBuf::from("/tmp/journal/test.journal")
        );
    }

    #[test]
    fn default_runtime_is_native_rustd() {
        let config = parse_args(std::iter::empty()).unwrap();
        assert_eq!(
            config.runtime_directory,
            PathBuf::from("/run/rustd/journal")
        );
    }
}
