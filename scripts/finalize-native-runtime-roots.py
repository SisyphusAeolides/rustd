#!/usr/bin/env python3
from pathlib import Path

PREFIXES = (
    ("/usr/local/lib/systemd", "/usr/local/lib/rustd"),
    ("/usr/lib/systemd", "/usr/lib/rustd"),
    ("/etc/systemd", "/etc/rustd"),
    ("/run/systemd", "/run/rustd"),
    ("/var/lib/systemd", "/var/lib/rustd"),
    ("/lib/systemd", "/lib/rustd"),
)

# These files own RustD state or expose RustD-native path semantics. Files that
# intentionally talk to an external compatibility service are not included.
NATIVE_FILES = [
    "ffi/journal.c",
    "ffi/journal.h",
    "src/ffi/journal.rs",
    "src/journal/catalog.rs",
    "src/unit/condition.rs",
    "src/unit/enable_state.rs",
    "src/dbus/manager_iface.rs",
    "src/event/inotify.rs",
    "src/bin/rustd-ask-password.rs",
    "src/bin/rustd-tty-ask-password-agent.rs",
    "src/bin/rustd-random-seed.rs",
    "src/bin/rustd-notify.rs",
    "src/bin/rustd-path.rs",
    "src/bin/rustd-analyze.rs",
    "src/bin/rustd-system-update-generator.rs",
    "src/bin/rustd-dissect.rs",
    "src/bin/rustcoredumpctl.rs",
    "src/bin/rustd-rfkill.rs",
    "src/bin/rusthomectl.rs",
    "src/bin/rustportablectl.rs",
    "src/bin/rustmachinectl.rs",
    "src/bin/rustloginctl.rs",
    "src/bin/rustd-cgls.rs",
]

# rustresolvectl intentionally still has networkd compatibility reads, but its
# resolver-owned runtime files must use RustD-resolved's native root.
TARGETED = {
    "src/bin/rustresolvectl.rs": [
        ("/run/systemd/resolve", "/run/rustd/resolve"),
    ],
    # The stdio bridge can still speak a compatibility manager D-Bus endpoint,
    # but machine state owned by RustD must live under the RustD root.
    "src/bin/rustd-stdio-bridge.rs": [
        ("/run/systemd/machines", "/run/rustd/machines"),
    ],
    # Container identification keeps its Linux/environment probes; RustD's own
    # marker is native.
    "src/bin/rustd-mute-console.rs": [
        ("/run/systemd/container", "/run/rustd/container"),
    ],
    "src/bin/rustd-detect-virt.rs": [
        ("/run/systemd/detect-virt", "/run/rustd/detect-virt"),
        ("/run/systemd/container", "/run/rustd/container"),
    ],
}

changed = []
replacements = 0

for name in NATIVE_FILES:
    path = Path(name)
    text = path.read_text()
    original = text
    for old, new in PREFIXES:
        count = text.count(old)
        if count:
            replacements += count
            text = text.replace(old, new)
    if name == "src/bin/rustd-path.rs":
        count = text.count('"systemd-')
        if count:
            replacements += count
            text = text.replace('"systemd-', '"rustd-')
    if name == "src/unit/enable_state.rs":
        text = text.replace("&[config.clone()]", "std::slice::from_ref(&config)")
    if text != original:
        path.write_text(text)
        changed.append(name)

for name, mappings in TARGETED.items():
    path = Path(name)
    text = path.read_text()
    original = text
    for old, new in mappings:
        count = text.count(old)
        if count:
            replacements += count
            text = text.replace(old, new)
    if text != original:
        path.write_text(text)
        changed.append(name)

# Make the partition-image open mode explicit. set_len() below owns the final
# image size, so creation must not implicitly truncate an existing image first.
repart = Path("src/bin/rustd-repart.rs")
text = repart.read_text()
needle = ".create(true)\n        .open(image_path)?;"
replacement = ".create(true)\n        .truncate(false)\n        .open(image_path)?;"
if needle not in text:
    raise SystemExit("rustd-repart image open sequence not found")
repart.write_text(text.replace(needle, replacement, 1))
changed.append(str(repart))

# Dynamic libaudit symbols are deliberately loaded as untyped pointers. Make
# the ABI conversion explicit so stable Clippy can verify the exact signatures.
utmp = Path("src/bin/rustd-update-utmp.rs")
text = utmp.read_text()
close_old = "close: unsafe { mem::transmute(close) },"
close_new = (
    'close: unsafe { mem::transmute::<*mut c_void, unsafe extern "C" fn(c_int) -> c_int>(close) },'
)
log_old = "log: unsafe { mem::transmute(log) },"
log_new = '''log: unsafe {
                mem::transmute::<
                    *mut c_void,
                    unsafe extern "C" fn(
                        c_int,
                        c_int,
                        *const c_char,
                        *const c_char,
                        *const c_char,
                        *const c_char,
                        *const c_char,
                        c_int,
                    ) -> c_int,
                >(log)
            },'''
if close_old not in text or log_old not in text:
    raise SystemExit("rustd-update-utmp audit ABI conversion points not found")
text = text.replace(close_old, close_new, 1).replace(log_old, log_new, 1)
utmp.write_text(text)
changed.append(str(utmp))

if replacements < 25:
    raise SystemExit(f"native runtime migration unexpectedly small: {replacements} replacements")

# Keep the permanent identity regression test focused on RustD-owned state.
test = Path("tests/rustd_runtime_identity.rs")
text = test.read_text()
marker = '    let spawn = fs::read_to_string(manifest.join("ffi/spawn.c")).expect("spawn source must exist");'
insert = r'''    let native_root_files = [
        "ffi/journal.c",
        "src/journal/catalog.rs",
        "src/unit/enable_state.rs",
        "src/dbus/manager_iface.rs",
        "src/bin/rustd-ask-password.rs",
        "src/bin/rustd-tty-ask-password-agent.rs",
        "src/bin/rustd-random-seed.rs",
        "src/bin/rustd-notify.rs",
        "src/bin/rustd-path.rs",
        "src/bin/rustd-analyze.rs",
        "src/bin/rustd-system-update-generator.rs",
    ];
    for relative in native_root_files {
        let source = fs::read_to_string(manifest.join(relative))
            .unwrap_or_else(|error| panic!("failed to read {relative}: {error}"));
        for legacy in [
            "/run/systemd",
            "/etc/systemd",
            "/usr/local/lib/systemd",
            "/usr/lib/systemd",
            "/var/lib/systemd",
        ] {
            assert!(
                !source.contains(legacy),
                "RustD-owned runtime path {legacy} remains in {relative}"
            );
        }
    }

'''
if marker not in text:
    raise SystemExit("runtime identity test insertion point not found")
text = text.replace(marker, insert + marker, 1)
test.write_text(text)

print(f"migrated {replacements} native runtime references across {len(set(changed))} files")
