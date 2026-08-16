// SPDX-License-Identifier: LGPL-2.1-or-later
//! `systemd-path` compatibility utility.
//!
//! Upstream reference: `src/path/path-tool.c`, `src/libsystemd/sd-path/sd-path.c`,
//! and `src/libsystemd/sd-path/path-lookup.c` from systemd v261.

use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

const VERSION_OUTPUT: &str = concat!(
    "systemd 261 (261.2-1-arch)\n",
    "+PAM +AUDIT -SELINUX +APPARMOR -IMA +IPE +SMACK +SECCOMP +GCRYPT +GNUTLS +OPENSSL +ACL ",
    "+BLKID +CURL +ELFUTILS +FIDO2 +IDN2 +KMOD +LIBCRYPTSETUP +LIBCRYPTSETUP_PLUGINS +LIBFDISK ",
    "+PCRE2 +PWQUALITY +P11KIT +QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB +ZSTD +BPF_FRAMEWORK +BTF ",
    "+XKBCOMMON +UTMP +LIBARCHIVE\n"
);

const KEYS: &[&str] = &[
    "temporary",
    "temporary-large",
    "system-search-configuration",
    "system-binaries",
    "system-include",
    "system-library-private",
    "system-library-arch",
    "system-shared",
    "system-configuration-factory",
    "system-state-factory",
    "system-configuration",
    "system-runtime",
    "system-runtime-logs",
    "system-state-private",
    "system-state-logs",
    "system-state-cache",
    "system-state-spool",
    "user-binaries",
    "user-library-private",
    "user-library-arch",
    "user-shared",
    "user-configuration",
    "user-runtime",
    "user-state-cache",
    "user-state-private",
    "user",
    "user-documents",
    "user-music",
    "user-pictures",
    "user-videos",
    "user-download",
    "user-public",
    "user-templates",
    "user-desktop",
    "user-projects",
    "search-binaries",
    "search-binaries-default",
    "search-library-private",
    "search-library-arch",
    "search-shared",
    "search-configuration-factory",
    "search-state-factory",
    "search-configuration",
    "systemd-util",
    "systemd-system-unit",
    "systemd-system-preset",
    "systemd-system-conf",
    "systemd-user-unit",
    "systemd-user-preset",
    "systemd-user-conf",
    "systemd-initrd-preset",
    "systemd-search-system-unit",
    "systemd-search-user-unit",
    "systemd-system-generator",
    "systemd-user-generator",
    "systemd-search-system-generator",
    "systemd-search-user-generator",
    "systemd-sleep",
    "systemd-shutdown",
    "tmpfiles",
    "sysusers",
    "sysctl",
    "binfmt",
    "modules-load",
    "catalog",
    "systemd-search-network",
    "systemd-system-environment-generator",
    "systemd-user-environment-generator",
    "systemd-search-system-environment-generator",
    "systemd-search-user-environment-generator",
    "system-credential-store",
    "system-search-credential-store",
    "system-credential-store-encrypted",
    "system-search-credential-store-encrypted",
    "user-credential-store",
    "user-search-credential-store",
    "user-credential-store-encrypted",
    "user-search-credential-store-encrypted",
];

#[derive(Debug)]
struct LookupError(String);

enum ParseResult {
    Run(Options),
    Exit(&'static str),
}

struct Options {
    suffix: Option<String>,
    names: Vec<String>,
}

fn main() {
    let arguments: Vec<String> = env::args().skip(1).collect();
    let result = match parse_options(&arguments) {
        Ok(ParseResult::Exit(output)) => write_stdout(output.as_bytes()),
        Ok(ParseResult::Run(options)) => run(&options),
        Err(error) => {
            eprintln!("{error}");
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
    let mut suffix = None;
    let mut names = Vec::new();
    let mut index = 0;
    let mut positional_only = false;

    while index < arguments.len() {
        let argument = &arguments[index];
        if positional_only || argument == "-" || !argument.starts_with('-') {
            names.push(argument.clone());
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
            let canonical = resolve_long_option(name)
                .ok_or_else(|| format!("systemd-path: unrecognized option '--{name}'"))?;
            match canonical {
                "help" => {
                    reject_attached_argument(name, attached)?;
                    return Ok(ParseResult::Exit(help()));
                }
                "version" => {
                    reject_attached_argument(name, attached)?;
                    return Ok(ParseResult::Exit(VERSION_OUTPUT));
                }
                "no-pager" => reject_attached_argument(name, attached)?,
                "suffix" => {
                    if let Some(value) = attached {
                        suffix = Some(value.to_owned());
                    } else {
                        index += 1;
                        suffix = Some(arguments.get(index).cloned().ok_or_else(|| {
                            format!("systemd-path: option '--{name}' requires an argument")
                        })?);
                    }
                }
                _ => unreachable!("complete long-option match"),
            }
            index += 1;
            continue;
        }

        if let Some(short) = argument[1..].chars().next() {
            if short == 'h' {
                return Ok(ParseResult::Exit(help()));
            }
            return Err(format!("systemd-path: unrecognized option '-{short}'"));
        }
        index += 1;
    }

    Ok(ParseResult::Run(Options { suffix, names }))
}

fn resolve_long_option(value: &str) -> Option<&'static str> {
    const OPTIONS: &[&str] = &["help", "version", "suffix", "no-pager"];
    let mut matches = OPTIONS
        .iter()
        .copied()
        .filter(|option| option.starts_with(value));
    let first = matches.next()?;
    matches.next().is_none().then_some(first)
}

fn reject_attached_argument(name: &str, attached: Option<&str>) -> Result<(), String> {
    if attached.is_some() {
        return Err(format!(
            "systemd-path: option '--{name}' doesn't allow an argument"
        ));
    }
    Ok(())
}

fn help() -> &'static str {
    concat!(
        "systemd-path [OPTIONS...] [NAME...]\n\n",
        "Show system and user paths.\n\n",
        "  -h --help          Show this help\n",
        "     --version       Show package version\n",
        "     --suffix=SUFFIX Suffix to append to paths\n",
        "     --no-pager      Do not start a pager\n\n",
        "See the systemd-path(1) man page for details.\n"
    )
}

fn run(options: &Options) -> Result<(), ()> {
    let mut failed = false;
    let suffix = options.suffix.as_deref();
    let mut stdout = io::stdout().lock();

    if options.names.is_empty() {
        let mut names = KEYS.to_vec();
        names.sort_unstable();
        for name in names {
            match lookup(name, suffix) {
                Ok(value) => {
                    if writeln!(stdout, "{name}: {value}").is_err() {
                        return Err(());
                    }
                }
                Err(error) if error.0 == "No such device or address" => {}
                Err(error) => {
                    eprintln!("Failed to query {name}, proceeding: {}", error.0);
                    failed = true;
                }
            }
        }
    } else {
        for name in &options.names {
            if !KEYS.contains(&name.as_str()) {
                eprintln!("Path {name} not known.");
                failed = true;
                continue;
            }
            match lookup(name, suffix) {
                Ok(value) => {
                    if writeln!(stdout, "{value}").is_err() {
                        return Err(());
                    }
                }
                Err(error) => {
                    eprintln!("Failed to query {name}: {}", error.0);
                    failed = true;
                }
            }
        }
    }

    if failed {
        Err(())
    } else {
        Ok(())
    }
}

fn lookup(name: &str, suffix: Option<&str>) -> Result<String, LookupError> {
    let mut paths = lookup_paths(name)?;
    if let Some(suffix) = suffix {
        for path in &mut paths {
            *path = path_join(path, suffix);
        }
    }
    Ok(paths.join(":"))
}

#[allow(clippy::too_many_lines)]
fn lookup_paths(name: &str) -> Result<Vec<String>, LookupError> {
    let fixed = |value: &str| Ok(vec![value.to_owned()]);
    match name {
        "temporary" => fixed(&temporary_directory("/tmp")),
        "temporary-large" => fixed(&temporary_directory("/var/tmp")),
        "system-search-configuration" => {
            Ok(strings(&["/etc/", "/run/", "/usr/local/lib/", "/usr/lib/"]))
        }
        "system-binaries" => fixed("/usr/bin"),
        "system-include" => fixed("/usr/include"),
        "system-library-private" | "system-library-arch" => fixed(system_library_dir()),
        "system-shared" => fixed("/usr/share"),
        "system-configuration-factory" => fixed("/usr/share/factory/etc"),
        "system-state-factory" => fixed("/usr/share/factory/var"),
        "system-configuration" => fixed("/etc"),
        "system-runtime" => fixed("/run"),
        "system-runtime-logs" => fixed("/run/log"),
        "system-state-private" => fixed("/var/lib"),
        "system-state-logs" => fixed("/var/log"),
        "system-state-cache" => fixed("/var/cache"),
        "system-state-spool" => fixed("/var/spool"),
        "user-binaries" => fixed(&home_relative(".local/bin")?),
        "user-library-private" => fixed(&home_relative(".local/lib")?),
        "user-library-arch" => fixed(&home_relative(&format!(
            ".local/lib/{}",
            library_architecture()
        ))?),
        "user-shared" => fixed(&xdg_home("XDG_DATA_HOME", ".local/share")?),
        "user-configuration" => fixed(&xdg_home("XDG_CONFIG_HOME", ".config")?),
        "user-runtime" => absolute_environment("XDG_RUNTIME_DIR")
            .map(|value| vec![value])
            .ok_or_else(no_device),
        "user-state-cache" => fixed(&xdg_home("XDG_CACHE_HOME", ".cache")?),
        "user-state-private" => fixed(&xdg_home("XDG_STATE_HOME", ".local/state")?),
        "user" => fixed(&home_directory()?),
        "user-documents" => fixed(&user_directory("XDG_DOCUMENTS_DIR", None)?),
        "user-music" => fixed(&user_directory("XDG_MUSIC_DIR", None)?),
        "user-pictures" => fixed(&user_directory("XDG_PICTURES_DIR", None)?),
        "user-videos" => fixed(&user_directory("XDG_VIDEOS_DIR", None)?),
        "user-download" => fixed(&user_directory("XDG_DOWNLOAD_DIR", None)?),
        "user-public" => fixed(&user_directory("XDG_PUBLICSHARE_DIR", None)?),
        "user-templates" => fixed(&user_directory("XDG_TEMPLATES_DIR", None)?),
        "user-desktop" => fixed(&user_directory("XDG_DESKTOP_DIR", Some("Desktop"))?),
        "user-projects" => fixed(&user_directory("XDG_PROJECTS_DIR", None)?),
        "search-binaries" => Ok(environment_search(
            None,
            Some(".local/bin"),
            Some("PATH"),
            true,
            &default_binary_search(),
        )),
        "search-binaries-default" => Ok(default_binary_search()),
        "search-library-private" => Ok(environment_search(
            None,
            Some(".local/lib"),
            None,
            false,
            &["/usr/local/lib".to_owned(), system_library_dir().to_owned()],
        )),
        "search-library-arch" => Ok(environment_search(
            None,
            Some(&format!(".local/lib/{}", library_architecture())),
            Some("LD_LIBRARY_PATH"),
            true,
            &[system_library_dir().to_owned()],
        )),
        "search-shared" => Ok(environment_search(
            Some("XDG_DATA_HOME"),
            Some(".local/share"),
            Some("XDG_DATA_DIRS"),
            false,
            &["/usr/local/share".to_owned(), "/usr/share".to_owned()],
        )),
        "search-configuration-factory" => Ok(strings(&[
            "/usr/local/share/factory/etc",
            "/usr/share/factory/etc",
        ])),
        "search-state-factory" => Ok(strings(&[
            "/usr/local/share/factory/var",
            "/usr/share/factory/var",
        ])),
        "search-configuration" => Ok(environment_search(
            Some("XDG_CONFIG_HOME"),
            Some(".config"),
            Some("XDG_CONFIG_DIRS"),
            false,
            &["/etc".to_owned()],
        )),
        "systemd-util" => fixed("/usr/lib/systemd"),
        "systemd-system-unit" => fixed("/usr/lib/systemd/system"),
        "systemd-system-preset" => fixed("/usr/lib/systemd/system-preset"),
        "systemd-system-conf" => fixed("/etc/systemd/system"),
        "systemd-user-unit" => fixed("/usr/lib/systemd/user"),
        "systemd-user-preset" => fixed("/usr/lib/systemd/user-preset"),
        "systemd-user-conf" => fixed("/etc/systemd/user"),
        "systemd-initrd-preset" => fixed("/usr/lib/systemd/initrd-preset"),
        "systemd-search-system-unit" => system_unit_search(false),
        "systemd-search-user-unit" => system_unit_search(true),
        "systemd-system-generator" => fixed("/usr/lib/systemd/system-generators"),
        "systemd-user-generator" => fixed("/usr/lib/systemd/user-generators"),
        "systemd-search-system-generator" => Ok(generator_search(false, false)),
        "systemd-search-user-generator" => Ok(generator_search(true, false)),
        "systemd-sleep" => fixed("/usr/lib/systemd/system-sleep"),
        "systemd-shutdown" => fixed("/usr/lib/systemd/system-shutdown"),
        "tmpfiles" => fixed("/usr/lib/tmpfiles.d"),
        "sysusers" => fixed("/usr/lib/sysusers.d"),
        "sysctl" => fixed("/usr/lib/sysctl.d"),
        "binfmt" => fixed("/usr/lib/binfmt.d"),
        "modules-load" => fixed("/usr/lib/modules-load.d"),
        "catalog" => fixed("/usr/lib/systemd/catalog"),
        "systemd-search-network" => Ok(strings(&[
            "/etc/systemd/network",
            "/run/systemd/network",
            "/usr/local/lib/systemd/network",
            "/usr/lib/systemd/network",
        ])),
        "systemd-system-environment-generator" => {
            fixed("/usr/lib/systemd/system-environment-generators")
        }
        "systemd-user-environment-generator" => {
            fixed("/usr/lib/systemd/user-environment-generators")
        }
        "systemd-search-system-environment-generator" => Ok(generator_search(false, true)),
        "systemd-search-user-environment-generator" => Ok(generator_search(true, true)),
        "system-credential-store" => fixed("/etc/credstore"),
        "system-search-credential-store" => Ok(strings(&[
            "/etc/credstore",
            "/run/credstore",
            "/usr/local/lib/credstore",
            "/usr/lib/credstore",
        ])),
        "system-credential-store-encrypted" => fixed("/etc/credstore.encrypted"),
        "system-search-credential-store-encrypted" => Ok(strings(&[
            "/etc/credstore.encrypted",
            "/run/credstore.encrypted",
            "/usr/local/lib/credstore.encrypted",
            "/usr/lib/credstore.encrypted",
        ])),
        "user-credential-store" => fixed(&path_join(
            &xdg_home("XDG_CONFIG_HOME", ".config")?,
            "credstore",
        )),
        "user-search-credential-store" => user_credential_search(false),
        "user-credential-store-encrypted" => fixed(&path_join(
            &xdg_home("XDG_CONFIG_HOME", ".config")?,
            "credstore.encrypted",
        )),
        "user-search-credential-store-encrypted" => user_credential_search(true),
        _ => Err(LookupError("Operation not supported".to_owned())),
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn temporary_directory(fallback: &str) -> String {
    for variable in ["TMPDIR", "TEMP", "TMP"] {
        let Some(value) = environment(variable) else {
            continue;
        };
        if !is_normalized_absolute(&value) {
            continue;
        }
        if fs::metadata(&value).is_ok_and(|metadata| metadata.is_dir()) {
            return value;
        }
    }
    fallback.to_owned()
}

fn environment(name: &str) -> Option<String> {
    env::var(name).ok()
}

fn absolute_environment(name: &str) -> Option<String> {
    environment(name).filter(|value| value.starts_with('/'))
}

fn home_directory() -> Result<String, LookupError> {
    if let Some(home) = absolute_environment("HOME") {
        return Ok(home);
    }

    let status = fs::read_to_string("/proc/self/status")
        .map_err(|error| LookupError(io_error_message(&error)))?;
    let uid = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|line| line.split_whitespace().next())
        .ok_or_else(no_device)?;
    let passwd =
        fs::read_to_string("/etc/passwd").map_err(|error| LookupError(io_error_message(&error)))?;
    passwd
        .lines()
        .find_map(|line| {
            let mut fields = line.split(':');
            let _name = fields.next()?;
            let _password = fields.next()?;
            let entry_uid = fields.next()?;
            let _gid = fields.next()?;
            let _gecos = fields.next()?;
            let home = fields.next()?;
            (entry_uid == uid && home.starts_with('/')).then(|| home.to_owned())
        })
        .ok_or_else(no_device)
}

fn home_relative(suffix: &str) -> Result<String, LookupError> {
    Ok(path_join(&home_directory()?, suffix))
}

fn xdg_home(variable: &str, fallback: &str) -> Result<String, LookupError> {
    if let Some(value) = absolute_environment(variable) {
        return Ok(value);
    }
    home_relative(fallback)
}

fn user_directory(field: &str, desktop_fallback: Option<&str>) -> Result<String, LookupError> {
    let home = home_directory()?;
    let configuration = path_join(&xdg_home("XDG_CONFIG_HOME", ".config")?, "user-dirs.dirs");
    let contents = match fs::read_to_string(configuration) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(LookupError(io_error_message(&error))),
    };

    for line in contents.lines() {
        let Some(mut value) = line.strip_prefix(field) else {
            continue;
        };
        value = value.trim_start_matches([' ', '\t']);
        let Some(after_equals) = value.strip_prefix('=') else {
            continue;
        };
        value = after_equals.trim_start_matches([' ', '\t']);
        let Some(quoted) = value.strip_prefix('"') else {
            continue;
        };
        let Some(end) = quoted.rfind('"') else {
            continue;
        };
        let configured = &quoted[..end];
        if configured == "$HOME" {
            return Ok(home);
        }
        if let Some(relative) = configured.strip_prefix("$HOME/") {
            return Ok(path_join(&home, relative));
        }
        if configured.starts_with('/') {
            return Ok(configured.to_owned());
        }
    }

    Ok(desktop_fallback.map_or(home.clone(), |suffix| path_join(&home, suffix)))
}

fn environment_search(
    environment_home: Option<&str>,
    home_suffix: Option<&str>,
    environment_search: Option<&str>,
    search_is_sufficient: bool,
    defaults: &[String],
) -> Vec<String> {
    let from_search = environment_search.and_then(environment);
    let mut paths = from_search
        .as_deref()
        .map_or_else(|| defaults.to_vec(), split_colon);
    if from_search.is_some() && search_is_sufficient {
        return paths;
    }

    let home = environment_home.and_then(absolute_environment).or_else(|| {
        home_suffix
            .and_then(|suffix| absolute_environment("HOME").map(|home| path_join(&home, suffix)))
    });
    if let Some(home) = home {
        paths.insert(0, home);
    }
    paths
}

fn default_binary_search() -> Vec<String> {
    // The pinned v261 Arch build is configured without split /usr. This is a
    // build-time contract, not a runtime filesystem probe.
    strings(&["/usr/local/bin", "/usr/bin"])
}

fn split_colon(value: &str) -> Vec<String> {
    value
        .split(':')
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect()
}

fn environment_override(variable: &str) -> Option<(Vec<String>, bool)> {
    environment(variable).map(|value| {
        let append_defaults = value.ends_with(':');
        let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
        let paths = split_colon(&value)
            .into_iter()
            .map(|path| {
                if path.starts_with('/') {
                    simplify_path(&path)
                } else {
                    simplify_path(&path_join(&cwd.to_string_lossy(), &path))
                }
            })
            .collect();
        (paths, append_defaults)
    })
}

fn system_unit_search(user: bool) -> Result<Vec<String>, LookupError> {
    let mut paths = Vec::new();
    if let Some((overrides, append_defaults)) = environment_override("SYSTEMD_UNIT_PATH") {
        paths.extend(overrides);
        if !append_defaults {
            deduplicate(&mut paths);
            return Ok(paths);
        }
    }

    if !user {
        paths.extend(strings(&[
            "/etc/systemd/system.control",
            "/run/systemd/system.control",
            "/run/systemd/transient",
            "/run/systemd/generator.early",
            "/etc/systemd/system",
            "/etc/systemd/system.attached",
            "/run/systemd/system",
            "/run/systemd/system.attached",
            "/run/systemd/generator",
            "/usr/local/lib/systemd/system",
            "/usr/lib/systemd/system",
            "/run/systemd/generator.late",
        ]));
        deduplicate(&mut paths);
        return Ok(paths);
    }

    let configuration = xdg_home("XDG_CONFIG_HOME", ".config")?;
    let runtime = absolute_environment("XDG_RUNTIME_DIR");
    paths.push(path_join(&configuration, "systemd/user.control"));
    if let Some(runtime) = &runtime {
        paths.push(path_join(runtime, "systemd/user.control"));
        paths.push(path_join(runtime, "systemd/transient"));
        paths.push(path_join(runtime, "systemd/generator.early"));
    }
    paths.push(path_join(&configuration, "systemd/user"));
    paths.push(path_join(&configuration, "systemd/user.attached"));
    paths.extend(
        environment_search(
            Some("XDG_CONFIG_HOME"),
            Some(".config"),
            Some("XDG_CONFIG_DIRS"),
            false,
            &["/etc".to_owned()],
        )
        .into_iter()
        .map(|path| path_join(&path, "systemd/user")),
    );
    paths.push("/etc/systemd/user".to_owned());
    if let Some(runtime) = &runtime {
        paths.push(path_join(runtime, "systemd/user"));
        paths.push(path_join(runtime, "systemd/user.attached"));
    }
    paths.push("/run/systemd/user".to_owned());
    if let Some(runtime) = &runtime {
        paths.push(path_join(runtime, "systemd/generator"));
    }
    paths.extend(
        environment_search(
            Some("XDG_DATA_HOME"),
            Some(".local/share"),
            Some("XDG_DATA_DIRS"),
            false,
            &["/usr/local/share".to_owned(), "/usr/share".to_owned()],
        )
        .into_iter()
        .map(|path| path_join(&path, "systemd/user")),
    );
    paths.extend(strings(&[
        "/usr/local/lib/systemd/user",
        "/usr/local/share/systemd/user",
        "/usr/lib/systemd/user",
        "/usr/share/systemd/user",
    ]));
    if let Some(runtime) = &runtime {
        paths.push(path_join(runtime, "systemd/generator.late"));
    }
    deduplicate(&mut paths);
    Ok(paths)
}

fn generator_search(user: bool, environment_generator: bool) -> Vec<String> {
    let variable = if environment_generator {
        "SYSTEMD_ENVIRONMENT_GENERATOR_PATH"
    } else {
        "SYSTEMD_GENERATOR_PATH"
    };
    let leaf = match (user, environment_generator) {
        (false, false) => "system-generators",
        (true, false) => "user-generators",
        (false, true) => "system-environment-generators",
        (true, true) => "user-environment-generators",
    };
    let mut paths = Vec::new();
    if let Some((overrides, append_defaults)) = environment_override(variable) {
        paths.extend(overrides);
        if !append_defaults {
            deduplicate(&mut paths);
            return paths;
        }
    }
    for base in [
        "/run/systemd",
        "/etc/systemd",
        "/usr/local/lib/systemd",
        "/usr/lib/systemd",
    ] {
        paths.push(path_join(base, leaf));
    }
    deduplicate(&mut paths);
    paths
}

fn user_credential_search(encrypted: bool) -> Result<Vec<String>, LookupError> {
    let leaf = if encrypted {
        "credstore.encrypted"
    } else {
        "credstore"
    };
    let mut paths = vec![path_join(&xdg_home("XDG_CONFIG_HOME", ".config")?, leaf)];
    if let Some(runtime) = absolute_environment("XDG_RUNTIME_DIR") {
        paths.push(path_join(&runtime, leaf));
    }
    paths.push(home_relative(&format!(".local/lib/{leaf}"))?);
    Ok(paths)
}

fn deduplicate(paths: &mut Vec<String>) {
    let mut seen = HashSet::new();
    paths.retain(|path| seen.insert(path.clone()));
}

fn path_join(base: &str, suffix: &str) -> String {
    if suffix.is_empty() {
        return base.to_owned();
    }
    let trailing_slash = suffix.ends_with('/');
    let tail = suffix.trim_start_matches('/');
    let raw = if base.ends_with('/') {
        format!("{base}{tail}")
    } else {
        format!("{base}/{tail}")
    };
    let mut simplified = simplify_path(&raw);
    if trailing_slash && !simplified.ends_with('/') {
        simplified.push('/');
    }
    simplified
}

fn simplify_path(path: &str) -> String {
    let absolute = path.starts_with('/');
    let components: Vec<&str> = path
        .split('/')
        .filter(|component| !component.is_empty() && *component != ".")
        .collect();
    if components.is_empty() {
        return if absolute { "/" } else { "." }.to_owned();
    }
    let joined = components.join("/");
    if absolute {
        format!("/{joined}")
    } else {
        joined
    }
}

fn is_normalized_absolute(path: &str) -> bool {
    if !path.starts_with('/') {
        return false;
    }
    let simplified = simplify_path(path);
    simplified == path || (path.ends_with('/') && format!("{simplified}/") == path)
}

fn no_device() -> LookupError {
    LookupError("No such device or address".to_owned())
}

fn io_error_message(error: &io::Error) -> String {
    if error.raw_os_error() == Some(20) {
        return "Not a directory".to_owned();
    }
    match error.kind() {
        io::ErrorKind::NotFound => "No such file or directory".to_owned(),
        io::ErrorKind::PermissionDenied => "Permission denied".to_owned(),
        _ => error
            .to_string()
            .split(" (os error")
            .next()
            .unwrap_or("I/O error")
            .to_owned(),
    }
}

const fn system_library_dir() -> &'static str {
    "/usr/lib"
}

const fn library_architecture() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        "x86_64-linux-gnu"
    }
    #[cfg(target_arch = "aarch64")]
    {
        "aarch64-linux-gnu"
    }
    #[cfg(target_arch = "riscv64")]
    {
        "riscv64-linux-gnu"
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    )))]
    {
        "unknown-linux-gnu"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_inventory_is_complete_and_unique() {
        assert_eq!(KEYS.len(), 78);
        let unique: HashSet<_> = KEYS.iter().collect();
        assert_eq!(unique.len(), KEYS.len());
        for key in KEYS {
            assert!(lookup_paths(key).is_ok() || *key == "user-runtime");
        }
    }

    #[test]
    fn suffix_join_matches_sd_path_lexical_rules() {
        assert_eq!(path_join("/tmp", "/one//./two/"), "/tmp/one/two/");
        assert_eq!(path_join("/tmp", "../one"), "/tmp/../one");
        assert_eq!(path_join("/tmp", ""), "/tmp");
    }

    #[test]
    fn long_options_accept_unambiguous_abbreviations() {
        let parsed = parse_options(&["--suff=x".to_owned(), "temporary".to_owned()]);
        let Ok(ParseResult::Run(options)) = parsed else {
            panic!("suffix abbreviation must parse");
        };
        assert_eq!(options.suffix.as_deref(), Some("x"));
        assert_eq!(options.names, ["temporary"]);
    }

    #[test]
    fn scope_options_are_rejected_like_v261() {
        for option in ["--user", "--system", "--global"] {
            assert_eq!(
                parse_options(&[option.to_owned()]).err().as_deref(),
                Some(format!("systemd-path: unrecognized option '{option}'").as_str())
            );
        }
    }
}
