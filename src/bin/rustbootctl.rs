use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::exit;

struct Config {
    esp_path: Option<PathBuf>,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let mut config = Config { esp_path: None };
    let mut commands = Vec::new();

    let mut i = 1;
    while i < args.len() {
        let arg = &args[i];
        if arg == "-h" || arg == "--help" {
            print_help(&program);
            exit(0);
        } else if arg == "--version" {
            println!("RustD {}", env!("CARGO_PKG_VERSION"));
            exit(0);
        } else if arg == "--path" || arg == "--esp-path" {
            if i + 1 >= args.len() {
                eprintln!("Missing argument for {arg}");
                exit(1);
            }
            config.esp_path = Some(PathBuf::from(&args[i + 1]));
            i += 1;
        } else if let Some(path) = arg.strip_prefix("--esp-path=") {
            config.esp_path = Some(PathBuf::from(path));
        } else if let Some(path) = arg.strip_prefix("--path=") {
            config.esp_path = Some(PathBuf::from(path));
        } else if arg.starts_with('-') {
            eprintln!("Unknown option '{arg}'");
            exit(1);
        } else {
            commands.push(arg.clone());
        }
        i += 1;
    }

    let command = commands.first().map_or("status", String::as_str);
    match command {
        "status" => status(&config),
        "install" => install(&config),
        "update" => update(&config),
        "remove" => remove(&config),
        "is-installed" => is_installed(&config),
        "set-default" => set_loader_value(&config, "default", commands.get(1)),
        "set-timeout" => set_loader_value(&config, "timeout", commands.get(1)),
        cmd => {
            eprintln!("Unknown command '{cmd}'.");
            print_help(&program);
            exit(1);
        }
    }
}

fn print_help(program: &str) {
    println!("Usage: {program} [OPTIONS...] COMMAND ...");
    println!();
    println!("Commands:");
    println!("  status          Show status of installed boot loader and EFI variables");
    println!("  install         Install the RustD boot loader to the ESP");
    println!("  update          Update the RustD boot loader in the ESP");
    println!("  remove          Remove the RustD boot loader from the ESP");
    println!("  is-installed    Test whether the RustD boot loader is installed in the ESP");
    println!("  set-default ID  Set default boot entry in loader.conf");
    println!("  set-timeout SEC Set boot menu timeout in loader.conf");
    println!();
    println!("Options:");
    println!("  -h, --help      Show this help");
    println!("      --version   Show package version");
    println!("      --esp-path=PATH  Override the path to the ESP");
}

fn find_esp(config: &Config) -> Option<PathBuf> {
    if let Some(ref path) = config.esp_path {
        return Some(path.clone());
    }

    for candidate in ["/efi", "/boot", "/boot/efi"] {
        let path = Path::new(candidate);
        if path.is_dir() && (path.join("EFI").exists() || path.join("loader").exists()) {
            return Some(path.to_path_buf());
        }
    }
    for candidate in ["/efi", "/boot", "/boot/efi"] {
        let path = Path::new(candidate);
        if path.is_dir() {
            return Some(path.to_path_buf());
        }
    }
    None
}

fn is_secure_boot_enabled() -> bool {
    let path =
        Path::new("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c");
    fs::read(path)
        .ok()
        .filter(|data| data.len() >= 5)
        .is_some_and(|data| data[4] == 1)
}

fn installed_image(esp: &Path) -> PathBuf {
    esp.join("EFI/RustD/rustd-bootx64.efi")
}

fn fallback_image(esp: &Path) -> PathBuf {
    esp.join("EFI/BOOT/BOOTX64.EFI")
}

fn source_image() -> Result<PathBuf, String> {
    let candidates: Vec<PathBuf> = env::var_os("RUSTD_BOOT_EFI_SOURCE")
        .map(PathBuf::from)
        .into_iter()
        .chain([
            PathBuf::from("/usr/lib/rustd/boot/efi/rustd-bootx64.efi"),
            PathBuf::from("/usr/lib/rustd/boot/efi/rustd-boot.efi"),
        ])
        .collect();

    for path in candidates {
        if path.is_file() {
            validate_efi_image(&path)?;
            return Ok(path);
        }
    }
    Err(String::from(
        "No RustD EFI boot loader image is installed; refusing to fabricate a bootable image.",
    ))
}

fn validate_efi_image(path: &Path) -> Result<(), String> {
    let data = fs::read(path).map_err(|error| {
        format!(
            "Failed to read boot loader image {}: {error}",
            path.display()
        )
    })?;
    if data.len() < 64 || !data.starts_with(b"MZ") {
        return Err(format!(
            "Boot loader image {} is not a valid PE/COFF image.",
            path.display()
        ));
    }
    Ok(())
}

fn copy_image(source: &Path, destination: &Path) -> Result<(), String> {
    let parent = destination
        .parent()
        .ok_or_else(|| format!("Invalid boot loader destination {}", destination.display()))?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("Failed to create {}: {error}", parent.display()))?;

    let file_name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("boot.efi");
    let temporary = parent.join(format!(".{file_name}.rustd-new"));
    if temporary.exists() {
        fs::remove_file(&temporary)
            .map_err(|error| format!("Failed to remove stale {}: {error}", temporary.display()))?;
    }
    fs::copy(source, &temporary).map_err(|error| {
        format!(
            "Failed to copy {} to {}: {error}",
            source.display(),
            temporary.display()
        )
    })?;
    validate_efi_image(&temporary)?;
    fs::rename(&temporary, destination).map_err(|error| {
        format!(
            "Failed to install {} as {}: {error}",
            temporary.display(),
            destination.display()
        )
    })?;
    Ok(())
}

fn status(config: &Config) {
    println!("System:");
    if Path::new("/sys/firmware/efi/efivars").exists() {
        println!("     Firmware: UEFI");
        println!(
            "  Secure Boot: {}",
            if is_secure_boot_enabled() {
                "enabled"
            } else {
                "disabled"
            }
        );
    } else {
        println!("     Firmware: BIOS (or EFI vars not accessible)");
    }

    let Some(esp) = find_esp(config) else {
        println!("          ESP: <not found>");
        return;
    };
    println!("          ESP: {}", esp.display());
    if installed_image(&esp).exists() {
        println!("   Boot Loader: RustD boot loader (installed)");
    } else if fallback_image(&esp).exists() {
        println!("   Boot Loader: fallback EFI image present");
    } else {
        println!("   Boot Loader: not installed");
    }

    let entries_dir = esp.join("loader/entries");
    let mut entries = Vec::new();
    if let Ok(read_dir) = fs::read_dir(entries_dir) {
        for entry in read_dir.flatten() {
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|value| value.to_str()) == Some("conf") {
                if let Some(name) = path.file_stem().and_then(|value| value.to_str()) {
                    entries.push(name.to_owned());
                }
            }
        }
    }
    entries.sort();
    println!();
    println!("Boot Loader Entries:");
    if entries.is_empty() {
        println!("  No entries found.");
    } else {
        for entry in entries {
            println!("    {entry}");
        }
    }
}

fn install(config: &Config) {
    let esp = require_esp(config);
    let source = match source_image() {
        Ok(source) => source,
        Err(error) => fail(error),
    };
    if let Err(error) = copy_image(&source, &installed_image(&esp))
        .and_then(|()| copy_image(&source, &fallback_image(&esp)))
    {
        fail(error);
    }
    if let Err(error) = fs::create_dir_all(esp.join("loader/entries")) {
        fail(format!("Failed to create loader entry directory: {error}"));
    }
    println!("Installed {} to {}.", source.display(), esp.display());
}

fn update(config: &Config) {
    let esp = require_esp(config);
    if !installed_image(&esp).exists() {
        fail(String::from(
            "RustD boot loader is not installed; use 'install' first.",
        ));
    }
    let source = match source_image() {
        Ok(source) => source,
        Err(error) => fail(error),
    };
    if let Err(error) = copy_image(&source, &installed_image(&esp))
        .and_then(|()| copy_image(&source, &fallback_image(&esp)))
    {
        fail(error);
    }
    println!("Updated RustD boot loader on {}.", esp.display());
}

fn remove(config: &Config) {
    let esp = require_esp(config);
    let mut removed = false;
    for path in [installed_image(&esp), fallback_image(&esp)] {
        match fs::remove_file(&path) {
            Ok(()) => removed = true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => fail(format!("Failed to remove {}: {error}", path.display())),
        }
    }
    if removed {
        println!("Removed RustD boot loader images from {}.", esp.display());
    }
}

fn is_installed(config: &Config) {
    let Some(esp) = find_esp(config) else {
        exit(1);
    };
    if installed_image(&esp).is_file() && validate_efi_image(&installed_image(&esp)).is_ok() {
        exit(0);
    }
    exit(1);
}

fn set_loader_value(config: &Config, key: &str, value: Option<&String>) {
    let Some(value) = value else {
        eprintln!("Missing value for set-{key}");
        exit(1);
    };
    let esp = require_esp(config);
    let loader_conf = esp.join("loader/loader.conf");
    let mut lines = Vec::new();
    if let Ok(content) = fs::read_to_string(&loader_conf) {
        for line in content.lines() {
            if line.split_whitespace().next() != Some(key) {
                lines.push(line.to_owned());
            }
        }
    }
    if let Some(parent) = loader_conf.parent() {
        if let Err(error) = fs::create_dir_all(parent) {
            fail(format!("Failed to create {}: {error}", parent.display()));
        }
    }
    lines.push(format!("{key} {value}"));
    if let Err(error) = fs::write(&loader_conf, lines.join("\n") + "\n") {
        fail(format!(
            "Failed to write {}: {error}",
            loader_conf.display()
        ));
    }
}

fn require_esp(config: &Config) -> PathBuf {
    find_esp(config).unwrap_or_else(|| {
        eprintln!("Couldn't find EFI system partition.");
        exit(1);
    })
}

fn fail(message: String) -> ! {
    eprintln!("{message}");
    exit(1)
}
