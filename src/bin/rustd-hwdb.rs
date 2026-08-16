use clap::{Parser, Subcommand};
use rustd::glob::matches_no_escape;
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "rustd-hwdb",
    version,
    about = "Hardware database tool",
    long_about = "systemd-hwdb is used to compile hardware database files into binary form or to query the hardware database."
)]
struct Cli {
    /// Look in /usr/lib/udev/hwdb.d only
    #[arg(long = "usr", global = true)]
    usr: bool,

    /// Alternative root path
    #[arg(short = 'r', long = "root", global = true)]
    root: Option<PathBuf>,

    /// Fail on syntax errors in hwdb files
    #[arg(short = 's', long = "strict", global = true)]
    strict: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Update binary hardware database
    Update,
    /// Query hardware database for a given modalias
    Query {
        /// Modalias string (e.g. 'usb:v046DpC52B*', 'pci:v00008086d00001234*')
        modalias: String,
    },
    /// Test hardware database matching
    Test {
        /// Modalias string
        modalias: String,
    },
}

#[derive(Debug, Clone)]
struct HwdbRule {
    source_file: PathBuf,
    line_number: usize,
    patterns: Vec<String>,
    properties: Vec<(String, String)>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Update => handle_update(&cli),
        Commands::Query { modalias } => handle_query(&cli, modalias, false),
        Commands::Test { modalias } => handle_query(&cli, modalias, true),
    }
}

fn get_hwdb_search_dirs(cli: &Cli) -> Vec<PathBuf> {
    let root = cli.root.as_deref().unwrap_or_else(|| Path::new("/"));

    let rel_dirs = if cli.usr {
        vec!["usr/lib/udev/hwdb.d"]
    } else {
        vec![
            "etc/udev/hwdb.d",
            "run/udev/hwdb.d",
            "usr/lib/udev/hwdb.d",
            "lib/udev/hwdb.d",
        ]
    };

    let mut result = Vec::new();
    for dir in rel_dirs {
        let p = if root == Path::new("/") {
            PathBuf::from(format!("/{dir}"))
        } else {
            root.join(dir)
        };
        if p.exists() {
            result.push(p);
        }
    }
    result
}

fn get_hwdb_bin_path(cli: &Cli) -> PathBuf {
    let root = cli.root.as_deref().unwrap_or_else(|| Path::new("/"));
    let rel_file = if cli.usr {
        "usr/lib/udev/hwdb.bin"
    } else {
        "etc/udev/hwdb.bin"
    };

    if root == Path::new("/") {
        PathBuf::from(format!("/{rel_file}"))
    } else {
        root.join(rel_file)
    }
}

fn collect_hwdb_files(cli: &Cli) -> Vec<PathBuf> {
    let dirs = get_hwdb_search_dirs(cli);
    let mut files = BTreeMap::new();

    for dir in dirs {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() && path.extension().is_some_and(|ext| ext == "hwdb") {
                    if let Some(filename) = path.file_name() {
                        // Higher priority directories override lower ones with the same filename
                        files.entry(filename.to_os_string()).or_insert(path);
                    }
                }
            }
        }
    }

    files.into_values().collect()
}

fn parse_hwdb_file(path: &Path, strict: bool) -> anyhow::Result<Vec<HwdbRule>> {
    let file = fs::File::open(path)?;
    let reader = BufReader::new(file);

    let mut rules = Vec::new();
    let mut current_patterns = Vec::new();
    let mut current_properties = Vec::new();
    let mut current_line = 0;
    let mut block_start_line = 1;

    for (idx, line_res) in reader.lines().enumerate() {
        let line_num = idx + 1;
        current_line = line_num;
        let line = line_res?;

        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            // Blank line or comment ends the current rule block if properties exist
            if !current_patterns.is_empty() && !current_properties.is_empty() {
                rules.push(HwdbRule {
                    source_file: path.to_path_buf(),
                    line_number: block_start_line,
                    patterns: std::mem::take(&mut current_patterns),
                    properties: std::mem::take(&mut current_properties),
                });
            }
            continue;
        }

        // Check if line starts with whitespace (property line)
        if line.starts_with(' ') || line.starts_with('\t') {
            if current_patterns.is_empty() {
                if strict {
                    return Err(anyhow::anyhow!(
                        "Syntax error in {}:{}: Property line without preceding match pattern",
                        path.display(),
                        line_num
                    ));
                }
                continue;
            }

            if let Some((k, v)) = trimmed.split_once('=') {
                current_properties.push((k.trim().to_string(), v.trim().to_string()));
            } else if strict {
                return Err(anyhow::anyhow!(
                    "Syntax error in {}:{}: Missing '=' in property assignment '{}'",
                    path.display(),
                    line_num,
                    trimmed
                ));
            }
        } else {
            // Match pattern line (starts at column 0)
            if !current_properties.is_empty() {
                // Starting a new block
                rules.push(HwdbRule {
                    source_file: path.to_path_buf(),
                    line_number: block_start_line,
                    patterns: std::mem::take(&mut current_patterns),
                    properties: std::mem::take(&mut current_properties),
                });
                block_start_line = line_num;
            }
            if current_patterns.is_empty() {
                block_start_line = line_num;
            }
            current_patterns.push(trimmed.to_string());
        }
    }

    if !current_patterns.is_empty() && !current_properties.is_empty() {
        rules.push(HwdbRule {
            source_file: path.to_path_buf(),
            line_number: block_start_line,
            patterns: current_patterns,
            properties: current_properties,
        });
    } else if !current_patterns.is_empty() && strict {
        return Err(anyhow::anyhow!(
            "Syntax error in {}:{}: Match pattern with no properties at end of file",
            path.display(),
            current_line
        ));
    }

    Ok(rules)
}

fn load_all_rules(cli: &Cli) -> anyhow::Result<(Vec<HwdbRule>, usize)> {
    let files = collect_hwdb_files(cli);
    let num_files = files.len();
    let mut all_rules = Vec::new();

    for file in &files {
        match parse_hwdb_file(file, cli.strict) {
            Ok(rules) => all_rules.extend(rules),
            Err(e) => {
                if cli.strict {
                    return Err(e);
                }
                eprintln!("Warning: Failed to parse {}: {}", file.display(), e);
            }
        }
    }

    Ok((all_rules, num_files))
}

fn handle_update(cli: &Cli) -> anyhow::Result<()> {
    let (rules, num_files) = load_all_rules(cli)?;
    let bin_path = get_hwdb_bin_path(cli);

    if let Some(parent) = bin_path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    let mut pattern_count = 0;
    for rule in &rules {
        pattern_count += rule.patterns.len();
    }

    // Serialize database into binary format with header
    // Format:
    // [0..4]: b"HWDB"
    // [4..8]: version 1 (u32 LE)
    // [8..16]: number of rules (u64 LE)
    // Text records follow with patterns and properties.
    let mut buffer = Vec::new();
    buffer.extend_from_slice(b"HWDB");
    buffer.extend_from_slice(&1u32.to_le_bytes());
    buffer.extend_from_slice(&(rules.len() as u64).to_le_bytes());

    for rule in &rules {
        let rule_repr = serde_json::json!({
            "source": rule.source_file.to_string_lossy(),
            "line": rule.line_number,
            "patterns": rule.patterns,
            "properties": rule.properties,
        });
        let bytes = serde_json::to_vec(&rule_repr)?;
        buffer.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        buffer.extend_from_slice(&bytes);
    }

    // Atomic write via temp file
    let tmp_path = bin_path.with_extension("tmp");
    match fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp_path)
    {
        Ok(mut f) => {
            f.write_all(&buffer)?;
            f.sync_all()?;
            fs::rename(&tmp_path, &bin_path)?;
            println!(
                "Compiled {} match patterns from {} files to {}.",
                pattern_count,
                num_files,
                bin_path.display()
            );
        }
        Err(err) => {
            eprintln!(
                "Failed to write hardware database to {}: {} (are you root?)",
                bin_path.display(),
                err
            );
            std::process::exit(1);
        }
    }

    Ok(())
}

fn query_rules(
    rules: &[HwdbRule],
    modalias: &str,
    verbose: bool,
) -> (BTreeMap<String, String>, usize) {
    let mut matched_properties = BTreeMap::new();
    let mut match_count = 0;

    for rule in rules {
        let mut rule_matched = false;
        for pattern in &rule.patterns {
            if matches_no_escape(pattern, modalias) {
                rule_matched = true;
                if verbose {
                    println!(
                        "Matched pattern '{}' from {}:{}",
                        pattern,
                        rule.source_file.display(),
                        rule.line_number
                    );
                }
                break;
            }
        }

        if rule_matched {
            match_count += 1;
            for (k, v) in &rule.properties {
                if verbose {
                    println!("  Property: {k}={v}");
                }
                matched_properties.insert(k.clone(), v.clone());
            }
        }
    }

    (matched_properties, match_count)
}

fn load_rules_from_bin_or_sources(cli: &Cli) -> anyhow::Result<Vec<HwdbRule>> {
    let bin_path = get_hwdb_bin_path(cli);

    if bin_path.exists() {
        if let Ok(data) = fs::read(&bin_path) {
            if data.len() >= 16 && &data[0..4] == b"HWDB" {
                let mut cursor = 16;
                let mut rules = Vec::new();
                while cursor + 4 <= data.len() {
                    let len =
                        u32::from_le_bytes(data[cursor..cursor + 4].try_into().unwrap()) as usize;
                    cursor += 4;
                    if cursor + len > data.len() {
                        break;
                    }
                    if let Ok(val) =
                        serde_json::from_slice::<serde_json::Value>(&data[cursor..cursor + len])
                    {
                        let source = val["source"].as_str().unwrap_or("").to_string();
                        let line = val["line"].as_u64().unwrap_or(1) as usize;
                        let patterns: Vec<String> = val["patterns"]
                            .as_array()
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|v| v.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default();
                        let properties: Vec<(String, String)> = val["properties"]
                            .as_array()
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|pair| {
                                        let p = pair.as_array()?;
                                        Some((
                                            p.first()?.as_str()?.to_string(),
                                            p.get(1)?.as_str()?.to_string(),
                                        ))
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();

                        rules.push(HwdbRule {
                            source_file: PathBuf::from(source),
                            line_number: line,
                            patterns,
                            properties,
                        });
                    }
                    cursor += len;
                }
                if !rules.is_empty() {
                    return Ok(rules);
                }
            }
        }
    }

    // Fallback: parse raw files directly
    let (rules, _) = load_all_rules(cli)?;
    Ok(rules)
}

fn handle_query(cli: &Cli, modalias: &str, verbose: bool) -> anyhow::Result<()> {
    let rules = load_rules_from_bin_or_sources(cli)?;
    let (properties, matches) = query_rules(&rules, modalias, verbose);

    if matches == 0 || properties.is_empty() {
        if verbose {
            println!("No matching entries found for modalias '{modalias}'.");
        }
        std::process::exit(1);
    }

    for (k, v) in properties {
        println!("{k}={v}");
    }

    Ok(())
}
