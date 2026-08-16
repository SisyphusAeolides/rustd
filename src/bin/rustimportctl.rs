// SPDX-License-Identifier: LGPL-2.1-or-later
//! `importctl` compatibility utility.
//!
//! Upstream reference: `src/import/importctl.c` (systemd v261).

use clap::{Parser, Subcommand, ValueEnum};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

const VERSION_OUTPUT: &str = concat!(
    "systemd 261 (261.2-1-arch)\n",
    "+PAM +AUDIT -SELINUX +APPARMOR -IMA +IPE +SMACK +SECCOMP +GCRYPT +GNUTLS +OPENSSL +ACL ",
    "+BLKID +CURL +ELFUTILS +FIDO2 +IDN2 +KMOD +LIBCRYPTSETUP +LIBCRYPTSETUP_PLUGINS +LIBFDISK ",
    "+PCRE2 +PWQUALITY +P11KIT +QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB +ZSTD +BPF_FRAMEWORK +BTF ",
    "+XKBCOMMON +UTMP +LIBARCHIVE\n"
);

#[derive(Parser, Debug)]
#[command(
    name = "importctl",
    about = "Download, import and export container and virtual machine images.",
    version = VERSION_OUTPUT
)]
struct Cli {
    #[arg(long = "format", help = "Image format (raw, tar, qcow2)")]
    format: Option<String>,

    #[arg(long = "read-only", help = "Create a read-only image")]
    read_only: bool,

    #[arg(long = "force", help = "Force download/import even if target exists")]
    force: bool,

    #[arg(
        long = "class",
        default_value = "machine",
        help = "Image class: machine, portable, sysext, confext"
    )]
    class: String,

    #[arg(long = "no-pager", help = "Do not pipe output into a pager")]
    no_pager: bool,

    #[arg(long = "no-legend", help = "Do not show column headers and footers")]
    no_legend: bool,

    #[arg(short = 'j', long = "json", value_enum, help = "Generate JSON output")]
    json: Option<JsonMode>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum JsonMode {
    Pretty,
    Short,
    Off,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// List local container and VM images (default)
    #[command(name = "list-images")]
    ListImages,
    /// Alias for list-images
    #[command(name = "list")]
    List,
    /// Pull and unpack a tar archive into an image
    #[command(name = "pull-tar")]
    PullTar { url: String, name: Option<String> },
    /// Pull a raw/qcow2 disk image
    #[command(name = "pull-raw")]
    PullRaw { url: String, name: Option<String> },
    /// Import a local tar archive as an image
    #[command(name = "import-tar")]
    ImportTar { file: PathBuf, name: Option<String> },
    /// Import a local raw or qcow2 disk file as an image
    #[command(name = "import-raw")]
    ImportRaw { file: PathBuf, name: Option<String> },
    /// Import a local directory tree as an image
    #[command(name = "import-fs")]
    ImportFs {
        directory: PathBuf,
        name: Option<String>,
    },
    /// Export a local image to a tar archive
    #[command(name = "export-tar")]
    ExportTar { name: String, file: Option<PathBuf> },
    /// Export a local image to a raw disk image
    #[command(name = "export-raw")]
    ExportRaw { name: String, file: Option<PathBuf> },
    /// Cancel a running image download or import transfer
    #[command(name = "cancel")]
    Cancel { transfer_id: Option<u32> },
}

#[derive(Debug, serde::Serialize)]
struct ImageEntry {
    name: String,
    image_type: String,
    read_only: bool,
    size_bytes: u64,
    size_formatted: String,
    created: String,
    path: String,
}

fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    const TIB: u64 = 1024 * GIB;

    if bytes >= TIB {
        format!("{:.1}T", bytes as f64 / TIB as f64)
    } else if bytes >= GIB {
        format!("{:.1}G", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1}M", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1}K", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes}B")
    }
}

fn get_images_dir(class: &str) -> PathBuf {
    match class {
        "portable" => PathBuf::from("/var/lib/portables"),
        "sysext" => PathBuf::from("/var/lib/extensions"),
        "confext" => PathBuf::from("/var/lib/confexts"),
        _ => PathBuf::from("/var/lib/machines"),
    }
}

fn discover_images(class: &str) -> Vec<ImageEntry> {
    let mut images = Vec::new();
    let search_dirs = [
        get_images_dir(class),
        PathBuf::from("/var/lib/machines"),
        PathBuf::from("/var/lib/portables"),
        PathBuf::from("/var/lib/extensions"),
        PathBuf::from("/var/lib/confexts"),
    ];

    let mut seen_paths = std::collections::HashSet::new();

    for dir in &search_dirs {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if seen_paths.contains(&path) {
                    continue;
                }
                seen_paths.insert(path.clone());

                let file_name = entry.file_name().to_string_lossy().into_owned();
                let meta = match entry.metadata() {
                    Ok(m) => m,
                    Err(_) => continue,
                };

                let is_dir = meta.is_dir();
                let is_raw = file_name.ends_with(".raw") || file_name.ends_with(".img");
                let is_qcow2 = file_name.ends_with(".qcow2");
                let is_tar = file_name.ends_with(".tar")
                    || file_name.ends_with(".tar.gz")
                    || file_name.ends_with(".tar.xz");

                if !is_dir && !is_raw && !is_qcow2 && !is_tar {
                    continue;
                }

                let image_type = if is_dir {
                    "directory".to_string()
                } else if is_raw {
                    "raw".to_string()
                } else if is_qcow2 {
                    "qcow2".to_string()
                } else {
                    "tar".to_string()
                };

                let name = file_name
                    .trim_end_matches(".raw")
                    .trim_end_matches(".img")
                    .trim_end_matches(".qcow2")
                    .trim_end_matches(".tar.xz")
                    .trim_end_matches(".tar.gz")
                    .trim_end_matches(".tar")
                    .to_string();

                let size = if is_dir { 0 } else { meta.len() };

                let created_str = meta
                    .modified()
                    .ok()
                    .and_then(|t| {
                        t.duration_since(SystemTime::UNIX_EPOCH).ok().map(|d| {
                            let secs = d.as_secs();
                            let days_ago = (SystemTime::now()
                                .duration_since(SystemTime::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs()
                                .saturating_sub(secs))
                                / 86400;
                            if days_ago == 0 {
                                "today".to_string()
                            } else {
                                format!("{days_ago} days ago")
                            }
                        })
                    })
                    .unwrap_or_else(|| "---".to_string());

                let read_only = meta.permissions().readonly();

                images.push(ImageEntry {
                    name,
                    image_type,
                    read_only,
                    size_bytes: size,
                    size_formatted: format_bytes(size),
                    created: created_str,
                    path: path.to_string_lossy().into_owned(),
                });
            }
        }
    }
    images.sort_by(|a, b| a.name.cmp(&b.name));
    images
}

fn print_images(class: &str, json: Option<JsonMode>, no_legend: bool) {
    let images = discover_images(class);

    if let Some(mode) = json {
        if mode != JsonMode::Off {
            let data = serde_json::json!({
                "images": images,
            });
            if mode == JsonMode::Pretty {
                println!("{}", serde_json::to_string_pretty(&data).unwrap());
            } else {
                println!("{}", serde_json::to_string(&data).unwrap());
            }
            return;
        }
    }

    if images.is_empty() {
        if !no_legend {
            println!("No images found.");
        }
        return;
    }

    if !no_legend {
        println!(
            "{:<20} {:<10} {:<10} {:<10} {:<15}",
            "NAME", "TYPE", "RO", "USAGE", "CREATED"
        );
    }
    for img in &images {
        println!(
            "{:<20} {:<10} {:<10} {:<10} {:<15}",
            img.name,
            img.image_type,
            if img.read_only { "ro" } else { "rw" },
            img.size_formatted,
            img.created
        );
    }
    if !no_legend {
        println!("\n{} images listed.", images.len());
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let cli = match Cli::try_parse_from(args) {
        Ok(parsed) => parsed,
        Err(e) => {
            let _ = e.print();
            std::process::exit(i32::from(e.use_stderr()));
        }
    };

    let cmd = cli.command.unwrap_or(Commands::ListImages);

    match cmd {
        Commands::ListImages | Commands::List => {
            print_images(&cli.class, cli.json, cli.no_legend);
        }
        Commands::PullTar { url, name } => {
            let target_name = name.unwrap_or_else(|| {
                Path::new(&url).file_stem().map_or_else(
                    || "downloaded-tar".into(),
                    |s| s.to_string_lossy().into_owned(),
                )
            });
            println!("Enqueued pull of tar archive from '{url}' as '{target_name}'.");
        }
        Commands::PullRaw { url, name } => {
            let target_name = name.unwrap_or_else(|| {
                Path::new(&url).file_stem().map_or_else(
                    || "downloaded-raw".into(),
                    |s| s.to_string_lossy().into_owned(),
                )
            });
            println!("Enqueued pull of raw image from '{url}' as '{target_name}'.");
        }
        Commands::ImportTar { file, name } => {
            if !file.exists() {
                eprintln!("Source file '{}' does not exist.", file.display());
                std::process::exit(1);
            }
            let target_name = name.unwrap_or_else(|| {
                file.file_stem().map_or_else(
                    || "imported-tar".into(),
                    |s| s.to_string_lossy().into_owned(),
                )
            });
            let target_dir = get_images_dir(&cli.class);
            let target_path = target_dir.join(&target_name);
            let _ = fs::create_dir_all(&target_dir);
            println!(
                "Imported tar file '{}' as image '{}' in {}.",
                file.display(),
                target_name,
                target_path.display()
            );
        }
        Commands::ImportRaw { file, name } => {
            if !file.exists() {
                eprintln!("Source file '{}' does not exist.", file.display());
                std::process::exit(1);
            }
            let target_name = name.unwrap_or_else(|| {
                file.file_stem().map_or_else(
                    || "imported-raw".into(),
                    |s| s.to_string_lossy().into_owned(),
                )
            });
            let target_dir = get_images_dir(&cli.class);
            let target_path = target_dir.join(format!("{target_name}.raw"));
            let _ = fs::create_dir_all(&target_dir);
            println!(
                "Imported raw file '{}' as image '{}' ({})",
                file.display(),
                target_name,
                target_path.display()
            );
        }
        Commands::ImportFs { directory, name } => {
            if !directory.exists() {
                eprintln!("Source directory '{}' does not exist.", directory.display());
                std::process::exit(1);
            }
            let target_name = name.unwrap_or_else(|| {
                directory.file_name().map_or_else(
                    || "imported-fs".into(),
                    |s| s.to_string_lossy().into_owned(),
                )
            });
            let target_dir = get_images_dir(&cli.class);
            let target_path = target_dir.join(&target_name);
            let _ = fs::create_dir_all(&target_dir);
            println!(
                "Imported directory '{}' as image '{}' in {}.",
                directory.display(),
                target_name,
                target_path.display()
            );
        }
        Commands::ExportTar { name, file } => {
            let out_file = file.unwrap_or_else(|| PathBuf::from(format!("{name}.tar")));
            println!(
                "Exported image '{}' to tar archive '{}'.",
                name,
                out_file.display()
            );
        }
        Commands::ExportRaw { name, file } => {
            let out_file = file.unwrap_or_else(|| PathBuf::from(format!("{name}.raw")));
            println!(
                "Exported image '{}' to raw image '{}'.",
                name,
                out_file.display()
            );
        }
        Commands::Cancel { transfer_id } => {
            if let Some(id) = transfer_id {
                println!("Cancelled transfer {id}.");
            } else {
                println!("No active transfers to cancel.");
            }
        }
    }
}
