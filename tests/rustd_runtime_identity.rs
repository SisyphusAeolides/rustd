// SPDX-License-Identifier: LGPL-2.1-or-later

use std::fs;
use std::path::{Path, PathBuf};

fn source_files(root: &Path, files: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(root).unwrap_or_else(|error| {
        panic!("failed to read {}: {error}", root.display());
    });
    for entry in entries {
        let path = entry
            .expect("source directory entry must be readable")
            .path();
        if path.is_dir() {
            source_files(&path, files);
        } else if matches!(
            path.extension().and_then(|value| value.to_str()),
            Some("rs" | "c" | "h")
        ) {
            files.push(path);
        }
    }
}

#[test]
fn rustd_owned_runtime_identity_is_native() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    source_files(&manifest.join("src"), &mut files);
    source_files(&manifest.join("ffi"), &mut files);

    let mut legacy_notify = Vec::new();
    let mut legacy_prefix = Vec::new();
    for path in files {
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        if text.contains("@systemd/notify") {
            legacy_notify.push(path.clone());
        }
        if text.contains("\"systemd:") {
            legacy_prefix.push(path);
        }
    }

    assert!(
        legacy_notify.is_empty(),
        "RustD-owned notify endpoint must be native; legacy endpoint remains in {legacy_notify:?}"
    );
    assert!(
        legacy_prefix.is_empty(),
        "RustD runtime diagnostics must use RustD identity; legacy prefixes remain in {legacy_prefix:?}"
    );

    let notify =
        fs::read_to_string(manifest.join("src/notify.rs")).expect("notify source must exist");
    let spawn = fs::read_to_string(manifest.join("ffi/spawn.c")).expect("spawn source must exist");
    assert!(notify.contains("pub const RUSTD_NOTIFY_SOCKET_PATH: &str = \"/run/rustd/notify\";"));
    assert!(spawn.contains("notify_socket = \"/run/rustd/notify\";"));
}
