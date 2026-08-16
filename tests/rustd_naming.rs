// SPDX-License-Identifier: LGPL-2.1-or-later

use std::collections::HashSet;

fn declared_bin_paths(manifest: &str) -> Vec<(String, String)> {
    manifest
        .split("[[bin]]")
        .skip(1)
        .filter_map(|section| {
            let mut name = None;
            let mut path = None;
            for line in section.lines() {
                let line = line.trim();
                if let Some(value) = line
                    .strip_prefix("name = \"")
                    .and_then(|value| value.strip_suffix('"'))
                {
                    name = Some(value.to_owned());
                } else if let Some(value) = line
                    .strip_prefix("path = \"")
                    .and_then(|value| value.strip_suffix('"'))
                {
                    path = Some(value.to_owned());
                } else if line.starts_with('[') {
                    break;
                }
            }
            Some((name?, path?))
        })
        .collect()
}

#[test]
fn native_rustd_targets_are_declared() {
    let targets = declared_bin_paths(include_str!("../Cargo.toml"));

    for expected in [
        ("rustd", "src/main.rs"),
        ("rustctl", "src/bin/rustctl.rs"),
        ("rustjournalctl", "src/bin/rustjournalctl.rs"),
        ("rustd-journald", "src/bin/rustd-journald.rs"),
    ] {
        assert!(
            targets
                .iter()
                .any(|target| target.0 == expected.0 && target.1 == expected.1),
            "Cargo manifest is missing native target {} at {}",
            expected.0,
            expected.1
        );
    }

    let unique_names: HashSet<_> = targets.iter().map(|target| target.0.as_str()).collect();
    assert_eq!(
        unique_names.len(),
        targets.len(),
        "Cargo manifest contains duplicate executable names"
    );

    let contract = include_str!("../scripts/executable_contract.py");
    assert!(
        contract.contains("EXPECTED_EXECUTABLE_COUNT = len(NATIVE_EXECUTABLES)"),
        "executable count must be derived from the native RustD contract"
    );
    assert!(!contract.contains("COMPATIBILITY_TO_NATIVE"));
    assert!(!contract.contains("COMPATIBILITY_EXECUTABLES"));
}

#[test]
fn staging_installer_is_native_only() {
    let installer = include_str!("../scripts/install-rustd-names.sh");
    let contract = include_str!("../scripts/executable_contract.py");

    for required in [
        "install-executable-surfaces.py",
        "${prefix}/lib/rustd",
        "\"rustd\"",
        "\"rustctl\"",
        "\"rustd-journald\"",
    ] {
        assert!(
            installer.contains(required) || contract.contains(required),
            "native staging contract is missing {required}"
        );
    }

    for forbidden in [
        "${prefix}/lib/systemd",
        "COMPATIBILITY_TO_NATIVE",
        "COMPATIBILITY_EXECUTABLES",
    ] {
        assert!(
            !installer.contains(forbidden) && !contract.contains(forbidden),
            "legacy compatibility installation contract remains: {forbidden}"
        );
    }
}
