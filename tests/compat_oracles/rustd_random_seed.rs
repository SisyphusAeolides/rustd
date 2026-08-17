// SPDX-License-Identifier: LGPL-2.1-or-later

use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::{Command, Output};
use std::sync::OnceLock;

const HOST: &str = "/usr/lib/systemd/systemd-random-seed";
const MACHINE_ID: &str = "00112233445566778899aabbccddeeff\n";

fn live_oracle_enabled() -> bool {
    // Exclusive RustD keeps native branding/IPC. Opt into live systemd byte-parity
    // oracles only when explicitly certifying against a pinned host binary.
    host_is_pinned_v261() && std::env::var_os("RUSTD_LIVE_SYSTEMD_ORACLE").is_some()
}

fn host_is_pinned_v261() -> bool {
    Path::new(HOST).is_file()
        && Command::new(HOST)
            .arg("--version")
            .output()
            .is_ok_and(|output| output.stdout.starts_with(b"systemd 261 "))
}

fn unprivileged_user_namespaces_available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        Command::new("unshare")
            .args(["--user", "--map-root-user", "true"])
            .output()
            .is_ok_and(|output| output.status.success())
    })
}

fn skip_without_user_namespaces() -> bool {
    if unprivileged_user_namespaces_available() {
        false
    } else {
        eprintln!("skipping random-seed fixture: unprivileged user namespaces unavailable");
        true
    }
}

fn plain(binary: &str, arguments: &[&OsStr]) -> Output {
    Command::new(binary)
        .args(arguments)
        .env("LC_ALL", "C")
        .env("SYSTEMD_COLORS", "0")
        .env("SYSTEMD_URLIFY", "0")
        .output()
        .expect("execute systemd-random-seed")
}

fn assert_success(output: &Output, context: &str) {
    assert_eq!(
        output.status.code(),
        Some(0),
        "{context}: status={:?} stdout={:?} stderr={:?}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_same(host: &Output, candidate: &Output, context: &str) {
    assert_eq!(
        candidate.status.code(),
        host.status.code(),
        "status: {context}"
    );
    assert_eq!(candidate.stdout, host.stdout, "stdout: {context}");
    assert_eq!(candidate.stderr, host.stderr, "stderr: {context}");
}

fn run_fixture(
    action: &str,
    seed: &Path,
    random: &Path,
    machine_id: &Path,
    extra: &[(&str, &str)],
) -> Output {
    let mut command = Command::new("unshare");
    command
        .args(["--user", "--map-root-user"])
        .arg(env!("CARGO_BIN_EXE_systemd-random-seed"))
        .arg(action)
        .env("LC_ALL", "C")
        .env("SYSTEMD_LOG_TARGET", "null")
        .env("RUSTD_RANDOM_SEED_FILE", seed)
        .env("RUSTD_RANDOM_DEVICE", random)
        .env("RUSTD_MACHINE_ID_FILE", machine_id)
        .env("RUSTD_RANDOM_POOL_SIZE", "32")
        .env_remove("SYSTEMD_RANDOM_SEED_CREDIT");
    for (name, value) in extra {
        command.env(name, value);
    }
    command.output().expect("execute random-seed fixture")
}

#[test]
fn complete_option_verb_and_raw_byte_surface_matches_live_v261() {
    if !live_oracle_enabled() {
        eprintln!("skipping live comparison: systemd package is not v261");
        return;
    }
    let candidate = env!("CARGO_BIN_EXE_systemd-random-seed");
    let cases: Vec<Vec<OsString>> = vec![
        vec![],
        vec![OsString::from("foo")],
        vec![OsString::from("loa")],
        vec![OsString::from("sav")],
        vec![OsString::from("load"), OsString::from("extra")],
        vec![OsString::from("save"), OsString::from("extra")],
        vec![OsString::from("--help")],
        vec![OsString::from("--h")],
        vec![OsString::from("--version")],
        vec![OsString::from("--v")],
        vec![OsString::from("--help=x")],
        vec![OsString::from("--=x")],
        vec![OsString::from("--bogus")],
        vec![OsString::from("-x")],
        vec![OsString::from_vec(vec![0xff])],
        vec![OsString::from_vec(vec![b'-', b'-', 0xff])],
    ];
    for arguments in cases {
        let references: Vec<&OsStr> = arguments.iter().map(OsString::as_os_str).collect();
        assert_same(
            &plain(HOST, &references),
            &plain(candidate, &references),
            &format!("{arguments:?}"),
        );
    }
}

#[test]
fn deterministic_save_enforces_size_mode_and_creditable_xattr() {
    if skip_without_user_namespaces() {
        return;
    }
    let temporary = tempfile::tempdir().expect("create save fixture");
    let seed = temporary.path().join("state/random-seed");
    let random = temporary.path().join("urandom");
    let machine_id = temporary.path().join("machine-id");
    fs::create_dir_all(seed.parent().unwrap()).expect("create seed directory");
    fs::write(&random, vec![0x55; 128]).expect("seed random fixture");
    fs::write(&machine_id, MACHINE_ID).expect("seed machine ID");
    let entropy = (0_u8..32).fold(String::new(), |mut output, byte| {
        write!(output, "{byte:02x}").unwrap();
        output
    });
    let output = run_fixture(
        "save",
        &seed,
        &random,
        &machine_id,
        &[("RUSTD_GETRANDOM_HEX", &entropy)],
    );
    assert_success(&output, "deterministic save");
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    assert_eq!(
        fs::read(&seed).expect("read saved seed"),
        (0_u8..32).collect::<Vec<_>>()
    );
    let metadata = fs::metadata(&seed).expect("stat saved seed");
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
    assert_eq!(metadata.gid(), unsafe { libc::getegid() });
    assert_eq!(get_xattr(&seed), Some(b"1".to_vec()));
}

#[test]
fn load_consumes_xattr_mixes_machine_id_and_hashes_old_and_new_seed() {
    if skip_without_user_namespaces() {
        return;
    }
    let temporary = tempfile::tempdir().expect("create load fixture");
    let seed = temporary.path().join("random-seed");
    let random = temporary.path().join("urandom");
    let machine_id = temporary.path().join("machine-id");
    let credit = temporary.path().join("credit.log");
    fs::write(&seed, (0xa0_u8..0xc0).collect::<Vec<_>>()).expect("write old seed");
    fs::set_permissions(&seed, fs::Permissions::from_mode(0o644)).expect("set old mode");
    set_xattr(&seed, b"1");
    fs::write(&random, vec![0x55; 128]).expect("seed random fixture");
    fs::write(&machine_id, MACHINE_ID).expect("seed machine ID");
    let new_hex = "1111111111111111111111111111111111111111111111111111111111111111";
    let output = run_fixture(
        "load",
        &seed,
        &random,
        &machine_id,
        &[
            ("RUSTD_GETRANDOM_HEX", new_hex),
            ("SYSTEMD_RANDOM_SEED_CREDIT", "yes"),
            ("RUSTD_RANDOM_CREDIT_LOG", credit.to_str().unwrap()),
        ],
    );
    assert_success(&output, "load consume xattr");
    assert_eq!(
        fs::metadata(&seed).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(get_xattr(&seed), Some(b"1".to_vec()));
    let random_bytes = fs::read(&random).expect("read random device log");
    assert_eq!(
        &random_bytes[..16],
        &[
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ]
    );
    let credit_bytes = fs::read(&credit).expect("read credit log");
    assert!(credit_bytes.starts_with(b"256\n"));
    assert_eq!(&credit_bytes[4..], &(0xa0_u8..0xc0).collect::<Vec<_>>());
    assert_ne!(fs::read(&seed).unwrap(), vec![0x11; 32]);
}

#[test]
fn load_first_boot_suppresses_credit_and_fallback_random_is_not_creditable() {
    if skip_without_user_namespaces() {
        return;
    }
    let temporary = tempfile::tempdir().expect("create fallback fixture");
    let seed = temporary.path().join("random-seed");
    let random = temporary.path().join("urandom");
    let machine_id = temporary.path().join("machine-id");
    let first_boot = temporary.path().join("first-boot");
    let credit = temporary.path().join("credit.log");
    fs::write(&seed, vec![0x22; 32]).expect("write old seed");
    set_xattr(&seed, b"1");
    fs::write(&random, vec![0x33; 128]).expect("seed fallback bytes");
    fs::write(&machine_id, MACHINE_ID).expect("seed machine ID");
    fs::write(&first_boot, b"").expect("mark first boot");
    let output = run_fixture(
        "load",
        &seed,
        &random,
        &machine_id,
        &[
            ("SYSTEMD_RANDOM_SEED_CREDIT", "yes"),
            ("RUSTD_RANDOM_CREDIT_LOG", credit.to_str().unwrap()),
            ("RUSTD_FIRST_BOOT_FILE", first_boot.to_str().unwrap()),
            ("RUSTD_GETRANDOM_HEX", "44"),
            ("RUSTD_GETRANDOM_EAGAIN_ONCE", "1"),
        ],
    );
    assert_success(&output, "load first boot");
    assert!(!credit.exists());
    assert_eq!(get_xattr(&seed), Some(b"1".to_vec()));
}

#[test]
fn isolated_live_load_matches_v261_size_mode_xattr_and_entropy_injection() {
    if !live_oracle_enabled() {
        eprintln!("skipping live comparison: systemd package is not v261");
        return;
    }
    if skip_without_user_namespaces() {
        return;
    }
    let old_seed: Vec<u8> = (0x40_u8..0x80).collect();
    let host_temp = tempfile::tempdir().expect("create host runtime fixture");
    let host_seed = host_temp.path().join("random-seed");
    let host_random = host_temp.path().join("urandom");
    fs::write(&host_seed, &old_seed).expect("write host seed");
    fs::write(&host_random, vec![0xaa; 256]).expect("write host random fixture");
    let host = Command::new("unshare")
        .args(["--user", "--map-root-user", "--mount", "sh", "-ceu"])
        .arg("mount --bind \"$1\" /var/lib/systemd/random-seed; mount --bind \"$2\" /dev/urandom; exec \"$3\" load")
        .arg("random-seed-live-oracle")
        .arg(&host_seed)
        .arg(&host_random)
        .arg(HOST)
        .env("SYSTEMD_RANDOM_SEED_CREDIT", "no")
        .env("SYSTEMD_LOG_TARGET", "null")
        .output()
        .expect("execute isolated live random-seed");
    assert_eq!(
        host.status.code(),
        Some(0),
        "host stderr: {:?}",
        host.stderr
    );

    let candidate_temp = tempfile::tempdir().expect("create candidate runtime fixture");
    let candidate_seed = candidate_temp.path().join("random-seed");
    let candidate_random = candidate_temp.path().join("urandom");
    fs::write(&candidate_seed, &old_seed).expect("write candidate seed");
    fs::write(&candidate_random, vec![0xaa; 256]).expect("write candidate random fixture");
    let candidate = Command::new("unshare")
        .args(["--user", "--map-root-user"])
        .arg(env!("CARGO_BIN_EXE_systemd-random-seed"))
        .arg("load")
        .env("SYSTEMD_LOG_TARGET", "null")
        .env("RUSTD_RANDOM_SEED_FILE", &candidate_seed)
        .env("RUSTD_RANDOM_DEVICE", &candidate_random)
        .env("RUSTD_RANDOM_POOL_SIZE", "32")
        .env("RUSTD_GETRANDOM_HEX", "cc")
        .env("SYSTEMD_RANDOM_SEED_CREDIT", "no")
        .output()
        .expect("execute isolated candidate random-seed");
    assert_eq!(
        candidate.status.code(),
        Some(0),
        "candidate stderr: {:?}",
        String::from_utf8_lossy(&candidate.stderr)
    );

    for seed in [&host_seed, &candidate_seed] {
        let metadata = fs::metadata(seed).expect("stat resulting seed");
        assert_eq!(metadata.len(), 64);
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(get_xattr(seed), Some(b"1".to_vec()));
    }
    assert_eq!(
        &fs::read(&host_random).unwrap()[..80],
        &fs::read(&candidate_random).unwrap()[..80],
        "machine ID and old seed injection must match live v261"
    );
}

fn get_xattr(path: &Path) -> Option<Vec<u8>> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    let name = b"user.random-seed-creditable\0";
    let mut value = vec![0_u8; 32];
    let count = unsafe {
        libc::getxattr(
            c_path.as_ptr(),
            name.as_ptr().cast(),
            value.as_mut_ptr().cast(),
            value.len(),
        )
    };
    if count < 0 {
        None
    } else {
        value.truncate(usize::try_from(count).unwrap());
        Some(value)
    }
}

fn set_xattr(path: &Path, value: &[u8]) {
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    let name = b"user.random-seed-creditable\0";
    assert_eq!(
        unsafe {
            libc::setxattr(
                c_path.as_ptr(),
                name.as_ptr().cast(),
                value.as_ptr().cast(),
                value.len(),
                0,
            )
        },
        0
    );
}
