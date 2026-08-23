// SPDX-License-Identifier: LGPL-2.1-or-later
//! `rustd-cat` connects command output to the `RustD` journal stream.

use std::env;
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsFd, FromRawFd, IntoRawFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const VERSION_OUTPUT: &str = concat!("RustD ", env!("CARGO_PKG_VERSION"), "\n");
const HELP: &str = concat!(
    "rustd-cat [OPTIONS...] COMMAND ...\n\n",
    "Execute a process with stdout/stderr connected to the RustD journal.\n\n",
    "  -h --help                     Show this help\n",
    "     --version                  Show package version\n",
    "  -t --identifier=STRING        Set journal identifier\n",
    "  -p --priority=PRIORITY        Set stdout priority (0..7)\n",
    "     --stderr-priority=PRIORITY Set stderr priority (0..7)\n",
    "     --level-prefix=BOOL        Parse level prefixes\n",
    "     --namespace=NAMESPACE      Connect to a RustD journal namespace\n"
);
const LONG_OPTIONS: &[&str] = &[
    "help",
    "version",
    "identifier",
    "priority",
    "stderr-priority",
    "level-prefix",
    "namespace",
];

struct Options {
    identifier: String,
    namespace: Option<String>,
    priority: u8,
    stderr_priority: Option<u8>,
    level_prefix: bool,
    command: Vec<String>,
}

enum ParseResult {
    Run(Options),
    Exit(&'static str),
}

enum ShortParse {
    Continue,
    Exit,
}

fn main() {
    let arguments: Vec<String> = env::args().skip(1).collect();
    let result = match parse_options(&arguments) {
        Ok(ParseResult::Exit(output)) => {
            io::stdout().lock().write_all(output.as_bytes()).map(|()| 0)
        }
        Ok(ParseResult::Run(options)) => run(&options),
        Err(error) => {
            if !error.is_empty() {
                eprintln!("{error}");
            }
            Err(io::Error::from_raw_os_error(libc::EINVAL))
        }
    };
    match result {
        Ok(0) => {}
        Ok(code) => std::process::exit(code),
        Err(_) => std::process::exit(1),
    }
}

fn parse_options(arguments: &[String]) -> Result<ParseResult, String> {
    let mut options = Options {
        identifier: String::new(),
        namespace: None,
        priority: 6,
        stderr_priority: None,
        level_prefix: true,
        command: Vec::new(),
    };
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "--" {
            options.command.extend_from_slice(&arguments[index + 1..]);
            break;
        }
        if argument == "-" || !argument.starts_with('-') {
            options.command.extend_from_slice(&arguments[index..]);
            break;
        }
        if let Some(long) = argument.strip_prefix("--") {
            let (spelling, attached) = long
                .split_once('=')
                .map_or((long, None), |(name, value)| (name, Some(value)));
            let name = resolve_long_option(spelling)?;
            match name {
                "help" => {
                    reject_attached(name, attached)?;
                    return Ok(ParseResult::Exit(HELP));
                }
                "version" => {
                    reject_attached(name, attached)?;
                    return Ok(ParseResult::Exit(VERSION_OUTPUT));
                }
                "identifier" | "priority" | "stderr-priority" | "level-prefix" | "namespace" => {
                    let value = take_value(arguments, &mut index, name, attached)?;
                    apply_value(&mut options, name, value)?;
                }
                _ => unreachable!(),
            }
            index += 1;
            continue;
        }
        if matches!(
            parse_short_options(arguments, &mut index, &mut options)?,
            ShortParse::Exit
        ) {
            return Ok(ParseResult::Exit(HELP));
        }
        index += 1;
    }
    Ok(ParseResult::Run(options))
}

fn parse_short_options(
    arguments: &[String],
    index: &mut usize,
    options: &mut Options,
) -> Result<ShortParse, String> {
    let argument = &arguments[*index];
    let bytes = argument.as_bytes();
    let Some(option) = bytes.get(1).copied() else {
        return Ok(ShortParse::Continue);
    };
    match option {
        b'h' => Ok(ShortParse::Exit),
        b't' | b'p' => {
            let name = if option == b't' {
                "identifier"
            } else {
                "priority"
            };
            let value = if bytes.len() > 2 {
                &argument[2..]
            } else {
                *index += 1;
                arguments.get(*index).map(String::as_str).ok_or_else(|| {
                    format!(
                        "rustd-cat: option '-{}' requires an argument",
                        char::from(option)
                    )
                })?
            };
            apply_value(options, name, value)?;
            Ok(ShortParse::Continue)
        }
        other => Err(format!(
            "rustd-cat: unrecognized option '-{}'",
            char::from(other)
        )),
    }
}

fn resolve_long_option(spelling: &str) -> Result<&'static str, String> {
    let matches: Vec<&str> = LONG_OPTIONS
        .iter()
        .copied()
        .filter(|name| name.starts_with(spelling))
        .collect();
    match matches.as_slice() {
        [name] => Ok(name),
        [] => Err(format!("rustd-cat: unrecognized option '--{spelling}'")),
        _ => Err(format!(
            "rustd-cat: option '--{spelling}' is ambiguous; possibilities: {}",
            matches
                .iter()
                .map(|name| format!("--{name}"))
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

fn reject_attached(name: &str, attached: Option<&str>) -> Result<(), String> {
    if attached.is_some() {
        return Err(format!(
            "rustd-cat: option '--{name}' doesn't allow an argument"
        ));
    }
    Ok(())
}

fn take_value<'a>(
    arguments: &'a [String],
    index: &mut usize,
    name: &str,
    attached: Option<&'a str>,
) -> Result<&'a str, String> {
    if let Some(value) = attached {
        return Ok(value);
    }
    *index += 1;
    arguments
        .get(*index)
        .map(String::as_str)
        .ok_or_else(|| format!("rustd-cat: option '--{name}' requires an argument"))
}

fn apply_value(options: &mut Options, name: &str, value: &str) -> Result<(), String> {
    match name {
        "identifier" => value.clone_into(&mut options.identifier),
        "priority" => {
            options.priority = parse_priority(value)
                .ok_or_else(|| String::from("Failed to parse priority value."))?;
        }
        "stderr-priority" => {
            options.stderr_priority = Some(
                parse_priority(value)
                    .ok_or_else(|| String::from("Failed to parse stderr priority value."))?,
            );
        }
        "level-prefix" => {
            options.level_prefix = parse_boolean(value).ok_or_else(|| {
                format!("Failed to parse boolean argument to '--level-prefix=': {value}")
            })?;
        }
        "namespace" => {
            options.namespace = if value.is_empty() {
                None
            } else {
                Some(value.to_owned())
            };
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn parse_priority(value: &str) -> Option<u8> {
    match value {
        "emerg" => Some(0),
        "alert" => Some(1),
        "crit" => Some(2),
        "err" | "error" => Some(3),
        "warning" | "warn" => Some(4),
        "notice" => Some(5),
        "info" => Some(6),
        "debug" => Some(7),
        _ => value
            .strip_prefix('+')
            .unwrap_or(value)
            .parse::<u8>()
            .ok()
            .filter(|priority| *priority <= 7),
    }
}

fn parse_boolean(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "yes" | "y" | "true" | "t" | "on" => Some(true),
        "0" | "no" | "n" | "false" | "f" | "off" => Some(false),
        _ => None,
    }
}

fn run(options: &Options) -> Result<i32, io::Error> {
    let out = journal_stream(
        options.namespace.as_deref(),
        &options.identifier,
        options.priority,
        options.level_prefix,
    )
    .map_err(|error| report_error("Failed to create RustD journal stream", error))?;
    let err = if options
        .stderr_priority
        .is_some_and(|priority| priority != options.priority)
    {
        Some(
            journal_stream(
                options.namespace.as_deref(),
                &options.identifier,
                options.stderr_priority.expect("checked stderr priority"),
                options.level_prefix,
            )
            .map_err(|error| report_error("Failed to create RustD journal stream", error))?,
        )
    } else {
        None
    };

    let stderr_stream = err.as_ref().unwrap_or(&out);
    let metadata_file = unsafe { File::from_raw_fd(stderr_stream.try_clone()?.into_raw_fd()) };
    let metadata = metadata_file.metadata()?;
    let stream_id = format!("{}:{}", metadata.dev(), metadata.ino());
    let saved_stderr = io::stderr()
        .as_fd()
        .try_clone_to_owned()
        .ok()
        .map(File::from);

    let stdout = unsafe { File::from_raw_fd(out.into_raw_fd()) };
    let stderr = match err {
        Some(stream) => unsafe { File::from_raw_fd(stream.into_raw_fd()) },
        None => stdout.try_clone()?,
    };
    let (program, arguments, set_stream_id) = if options.command.is_empty() {
        ("cat", &[][..], false)
    } else {
        (options.command[0].as_str(), &options.command[1..], true)
    };
    let mut command = Command::new(program);
    command
        .args(arguments)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .env_remove("RUSTD_CAT_RUNTIME_DIR");
    if set_stream_id {
        command.env("RUSTD_JOURNAL_STREAM", stream_id);
    }
    let error = command.exec();
    if let Some(mut saved) = saved_stderr {
        let _ = writeln!(
            saved,
            "Failed to execute process: {}",
            concise_io_error(&error)
        );
    }
    Err(error)
}

fn journal_stream(
    namespace: Option<&str>,
    identifier: &str,
    priority: u8,
    level_prefix: bool,
) -> io::Result<UnixStream> {
    let path = journal_stream_path(namespace)?;
    let mut stream = UnixStream::connect(path)?;
    stream.shutdown(std::net::Shutdown::Read)?;
    write!(
        stream,
        "{identifier}\n\n{priority}\n{}\n0\n0\n0\n",
        u8::from(level_prefix)
    )?;
    Ok(stream)
}

fn journal_stream_path(namespace: Option<&str>) -> io::Result<PathBuf> {
    let namespace = match (namespace, env::var_os("RUSTD_LOG_NAMESPACE")) {
        (Some(requested), Some(active)) if active != requested => {
            return Err(io::Error::from_raw_os_error(libc::EREMOTE));
        }
        (Some(_), Some(_)) => None,
        (other, _) => other,
    };
    if namespace.is_some_and(|name| !valid_namespace(name)) {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    let root = env::var_os("RUSTD_CAT_RUNTIME_DIR")
        .map_or_else(|| PathBuf::from("/run/rustd"), PathBuf::from);
    Ok(match namespace {
        Some(name) => root.join(format!("journal.{name}/stdout")),
        None => root.join("journal/stdout"),
    })
}

fn valid_namespace(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 222
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b":-_.@".contains(&byte))
}

fn report_error(context: &str, error: io::Error) -> io::Error {
    eprintln!("{context}: {}", concise_io_error(&error));
    error
}

fn concise_io_error(error: &io::Error) -> String {
    let rendered = error.to_string();
    rendered
        .split(" (os error ")
        .next()
        .unwrap_or(&rendered)
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn priorities_and_booleans_are_native_and_bounded() {
        assert_eq!(parse_priority("debug"), Some(7));
        assert_eq!(parse_priority("8"), None);
        assert_eq!(parse_boolean("yes"), Some(true));
        assert_eq!(parse_boolean("off"), Some(false));
    }

    #[test]
    fn namespace_validation_is_bounded() {
        assert!(valid_namespace("build.worker-1"));
        assert!(!valid_namespace("."));
        assert!(!valid_namespace("a/b"));
    }
}
