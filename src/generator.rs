// SPDX-License-Identifier: LGPL-2.1-or-later
//! Boot-time unit generator runner.
//!
//! Generators are short-lived executables invoked before the unit graph is
//! loaded. They materialize transient units and dependency links beneath
//! `/run/rustd/generator{,.early,.late}`.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, Context};

const SYSTEM_GENERATOR_DIRS: &[&str] = &[
    "/etc/rustd/system-generators",
    "/run/rustd/system-generators",
    "/usr/local/lib/rustd/system-generators",
    "/usr/lib/rustd/system-generators",
];

/// Run all visible system generators in deterministic basename order.
///
/// Higher-priority directories shadow generators with the same basename in
/// lower-priority directories. A failing generator aborts manager startup:
/// silently booting without generated mounts/gettys is not a safe fallback.
///
/// # Errors
/// Returns an error when output directories cannot be prepared, a generator
/// cannot be executed, or a generator exits unsuccessfully.
pub fn run_system_generators() -> anyhow::Result<()> {
    let search_dirs = std::env::var_os("RUSTD_GENERATOR_PATH").map_or_else(
        || {
            SYSTEM_GENERATOR_DIRS
                .iter()
                .map(PathBuf::from)
                .collect::<Vec<_>>()
        },
        |value| std::env::split_paths(&value).collect(),
    );
    let runtime_root = std::env::var_os("RUSTD_GENERATOR_OUTPUT_ROOT")
        .map_or_else(|| PathBuf::from("/run/rustd"), PathBuf::from);
    run_generators(&search_dirs, &runtime_root)
}

fn run_generators(search_dirs: &[PathBuf], runtime_root: &Path) -> anyhow::Result<()> {
    let early = runtime_root.join("generator.early");
    let normal = runtime_root.join("generator");
    let late = runtime_root.join("generator.late");
    for directory in [&early, &normal, &late] {
        if directory.exists() {
            fs::remove_dir_all(directory).with_context(|| {
                format!("remove stale generator output {}", directory.display())
            })?;
        }
        fs::create_dir_all(directory)
            .with_context(|| format!("create generator output {}", directory.display()))?;
    }

    let mut visible = BTreeMap::<OsString, PathBuf>::new();
    for directory in search_dirs {
        let Ok(entries) = fs::read_dir(directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(metadata) = fs::metadata(&path) else {
                continue;
            };
            if metadata.is_file() && metadata.permissions().mode() & 0o111 != 0 {
                visible.entry(entry.file_name()).or_insert(path);
            }
        }
    }

    for (name, executable) in visible {
        let status = Command::new(&executable)
            .args([&early, &normal, &late])
            .status()
            .with_context(|| format!("execute generator {}", executable.display()))?;
        if !status.success() {
            return Err(anyhow!(
                "generator {} ({}) failed with {status}",
                name.to_string_lossy(),
                executable.display()
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn generator(path: &Path, marker: &str) {
        fs::write(
            path,
            format!("#!/bin/sh\nprintf '%s' '{marker}' >\"$2/result\"\n"),
        )
        .unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn higher_priority_generator_shadows_same_basename() {
        let root = tempfile::tempdir().unwrap();
        let high = root.path().join("high");
        let low = root.path().join("low");
        fs::create_dir_all(&high).unwrap();
        fs::create_dir_all(&low).unwrap();
        generator(&high.join("same-generator"), "high");
        generator(&low.join("same-generator"), "low");

        let output = root.path().join("run");
        run_generators(&[high, low], &output).unwrap();
        assert_eq!(
            fs::read_to_string(output.join("generator/result")).unwrap(),
            "high"
        );
    }

    #[test]
    fn generator_failure_is_fatal() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("generators");
        fs::create_dir_all(&directory).unwrap();
        let script = directory.join("bad-generator");
        fs::write(&script, "#!/bin/sh\nexit 23\n").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();

        let error = run_generators(&[directory], &root.path().join("run")).unwrap_err();
        assert!(error.to_string().contains("failed with"));
    }
}
