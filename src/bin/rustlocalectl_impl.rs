use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use std::process::{exit, Command};

const LOCALE_CONF: &str = "/etc/locale.conf";
const VCONSOLE_CONF: &str = "/etc/vconsole.conf";
const X11_CONF: &str = "/etc/X11/xorg.conf.d/00-keyboard.conf";

fn read_env_file<P: AsRef<Path>>(path: P) -> io::Result<HashMap<String, String>> {
    let mut map = HashMap::new();
    let file = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(map),
        Err(e) => return Err(e),
    };
    let reader = BufReader::new(file);
    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let key = k.trim().to_string();
            let value = v.trim().trim_matches('"').to_string();
            map.insert(key, value);
        }
    }
    Ok(map)
}

fn write_env_file<P: AsRef<Path>>(path: P, map: &HashMap<String, String>) -> io::Result<()> {
    let mut final_lines = Vec::new();
    let mut to_write = map.clone();

    if let Ok(file) = fs::File::open(&path) {
        let reader = BufReader::new(file);
        for line in reader.lines() {
            if let Ok(line) = line {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    final_lines.push(line);
                    continue;
                }
                if let Some((k, _)) = trimmed.split_once('=') {
                    let key = k.trim();
                    if let Some(val) = to_write.remove(key) {
                        final_lines.push(format!("{key}={val}"));
                    }
                } else {
                    final_lines.push(line);
                }
            }
        }
    }

    for (k, v) in to_write {
        final_lines.push(format!("{k}={v}"));
    }

    let mut file = fs::File::create(&path)?;
    for line in final_lines {
        writeln!(file, "{line}")?;
    }

    Ok(())
}

fn status() {
    let locale_map = read_env_file(LOCALE_CONF).unwrap_or_default();
    let vconsole_map = read_env_file(VCONSOLE_CONF).unwrap_or_default();

    let lang = locale_map
        .get("LANG")
        .cloned()
        .unwrap_or_else(|| "n/a".to_string());
    println!("   System Locale: LANG={lang}");
    for (k, v) in &locale_map {
        if k != "LANG" {
            println!("                  {k}={v}");
        }
    }

    let keymap = vconsole_map
        .get("KEYMAP")
        .cloned()
        .unwrap_or_else(|| "n/a".to_string());
    println!("       VC Keymap: {keymap}");

    let mut x11_layout = "n/a".to_string();
    let mut x11_model = "n/a".to_string();
    let mut x11_variant = "n/a".to_string();
    let mut x11_options = "n/a".to_string();

    if let Ok(file) = fs::File::open(X11_CONF) {
        let reader = BufReader::new(file);
        for line in reader.lines() {
            if let Ok(line) = line {
                if line.contains("Option") && line.contains("XkbLayout") {
                    let parts: Vec<&str> = line.split('"').collect();
                    if parts.len() >= 4 {
                        x11_layout = parts[3].to_string();
                    }
                }
                if line.contains("Option") && line.contains("XkbModel") {
                    let parts: Vec<&str> = line.split('"').collect();
                    if parts.len() >= 4 {
                        x11_model = parts[3].to_string();
                    }
                }
                if line.contains("Option") && line.contains("XkbVariant") {
                    let parts: Vec<&str> = line.split('"').collect();
                    if parts.len() >= 4 {
                        x11_variant = parts[3].to_string();
                    }
                }
                if line.contains("Option") && line.contains("XkbOptions") {
                    let parts: Vec<&str> = line.split('"').collect();
                    if parts.len() >= 4 {
                        x11_options = parts[3].to_string();
                    }
                }
            }
        }
    }

    println!("      X11 Layout: {x11_layout}");
    if x11_model != "n/a" {
        println!("       X11 Model: {x11_model}");
    }
    if x11_variant != "n/a" {
        println!("     X11 Variant: {x11_variant}");
    }
    if x11_options != "n/a" {
        println!("     X11 Options: {x11_options}");
    }
}

fn set_locale(args: &[String]) {
    let mut map = read_env_file(LOCALE_CONF).unwrap_or_default();
    for arg in args {
        if let Some((k, v)) = arg.split_once('=') {
            map.insert(k.to_string(), v.to_string());
        } else {
            map.insert("LANG".to_string(), arg.clone());
        }
    }
    if let Err(e) = write_env_file(LOCALE_CONF, &map) {
        eprintln!("Failed to write {LOCALE_CONF}: {e}");
        exit(1);
    }
}

fn list_locales() {
    match Command::new("locale").arg("-a").output() {
        Ok(out) => print!("{}", String::from_utf8_lossy(&out.stdout)),
        Err(e) => eprintln!("Failed to run locale -a: {e}"),
    }
}

fn set_keymap(map: &str) {
    let mut env_map = read_env_file(VCONSOLE_CONF).unwrap_or_default();
    env_map.insert("KEYMAP".to_string(), map.to_string());
    if let Err(e) = write_env_file(VCONSOLE_CONF, &env_map) {
        eprintln!("Failed to write {VCONSOLE_CONF}: {e}");
        exit(1);
    }
}

fn list_keymaps() {
    let output = Command::new("find")
        .args(["/usr/share/kbd/keymaps", "/lib/kbd/keymaps"])
        .arg("-type")
        .arg("f")
        .arg("-name")
        .arg("*.map.gz")
        .output();

    match output {
        Ok(out) => {
            let s = String::from_utf8_lossy(&out.stdout);
            let mut maps: Vec<&str> = s
                .lines()
                .filter_map(|line| {
                    Path::new(line)
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .map(|s| s.trim_end_matches(".map"))
                })
                .collect();
            maps.sort_unstable();
            maps.dedup();
            for map in maps {
                if !map.is_empty() {
                    println!("{map}");
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to list keymaps: {e}");
        }
    }
}

fn set_x11_keymap(args: &[String]) {
    if args.is_empty() {
        eprintln!("Too few arguments.");
        exit(1);
    }
    let layout = &args[0];
    let model = args.get(1).map_or("", std::string::String::as_str);
    let variant = args.get(2).map_or("", std::string::String::as_str);
    let options = args.get(3).map_or("", std::string::String::as_str);

    let dir = "/etc/X11/xorg.conf.d";
    if let Err(e) = fs::create_dir_all(dir) {
        eprintln!("Failed to create directory {dir}: {e}");
    }

    let mut content = format!(
        "# Written by rustlocalectl
Section \"InputClass\"
        Identifier \"system-keyboard\"
        MatchIsKeyboard \"on\"
        Option \"XkbLayout\" \"{layout}\"\n"
    );

    if !model.is_empty() {
        content.push_str(&format!("        Option \"XkbModel\" \"{model}\"\n"));
    }
    if !variant.is_empty() {
        content.push_str(&format!("        Option \"XkbVariant\" \"{variant}\"\n"));
    }
    if !options.is_empty() {
        content.push_str(&format!("        Option \"XkbOptions\" \"{options}\"\n"));
    }
    content.push_str("EndSection\n");

    if let Err(e) = fs::write(X11_CONF, content) {
        eprintln!("Failed to write {X11_CONF}: {e}");
        exit(1);
    }
}

fn list_x11_keymaps(kind: &str, layout_filter: Option<&str>) {
    let path = env::var("SYSTEMD_XKB_DIRECTORY")
        .map(|p| Path::new(&p).join("rules/base.lst"))
        .unwrap_or_else(|_| Path::new("/usr/share/X11/xkb").join("rules/base.lst"));
    let file = match fs::File::open(&path) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("Failed to open keyboard mapping list {}: {error}", path.display());
            exit(1);
        }
    };
    let wanted = match kind {
        "models" => "model",
        "layouts" => "layout",
        "variants" => "variant",
        "options" => "option",
        _ => unreachable!(),
    };
    let mut section = String::new();
    let mut values = Vec::new();
    for line in BufReader::new(file).lines().map_while(Result::ok) {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix('!') {
            section = rest.split_whitespace().next().unwrap_or("").to_owned();
            continue;
        }
        if section != wanted || line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(name) = parts.next() else { continue };
        if kind == "variants" {
            let description = parts.collect::<Vec<_>>().join(" ");
            let layout = description.split(':').next().unwrap_or("").trim();
            if layout_filter.is_some_and(|wanted_layout| layout != wanted_layout) {
                continue;
            }
        }
        values.push(name.to_owned());
    }
    values.sort();
    values.dedup();
    if values.is_empty() {
        eprintln!("Couldn't find any entries in keyboard mapping list {}.", path.display());
        exit(1);
    }
    for value in values {
        println!("{value}");
    }
}

fn print_help() {
    println!("rustlocalectl [OPTIONS...] COMMAND ...");
    println!();
    println!("Query or change system locale and keyboard settings.");
    println!();
    println!("Commands:");
    println!("  status                                Show current locale settings");
    println!("  set-locale LOCALE...                  Set system locale");
    println!("  list-locales                          Show known locales");
    println!("  set-keymap MAP                        Set console keyboard mapping");
    println!(
        "  list-keymaps                          Show known virtual console keyboard mappings"
    );
    println!("  set-x11-keymap LAYOUT [MODEL [VARIANT [OPTIONS]]]");
    println!("                                        Set X11 keyboard mapping");
    println!("  list-x11-keymap-models                 Show known X11 keyboard mapping models");
    println!("  list-x11-keymap-layouts                Show known X11 keyboard mapping layouts");
    println!("  list-x11-keymap-variants [LAYOUT]      Show known X11 keyboard mapping variants");
    println!("  list-x11-keymap-options                Show known X11 keyboard mapping options");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        status();
        return;
    }

    let cmd = args[1].as_str();
    match cmd {
        "status" => status(),
        "set-locale" => {
            if args.len() < 3 {
                eprintln!("Too few arguments.");
                exit(1);
            }
            set_locale(&args[2..]);
        }
        "list-locales" => list_locales(),
        "set-keymap" => {
            if args.len() < 3 {
                eprintln!("Too few arguments.");
                exit(1);
            }
            set_keymap(&args[2]);
        }
        "list-keymaps" => list_keymaps(),
        "set-x11-keymap" => {
            if args.len() < 3 {
                eprintln!("Too few arguments.");
                exit(1);
            }
            set_x11_keymap(&args[2..]);
        }
        "list-x11-keymap-models" => list_x11_keymaps("models", None),
        "list-x11-keymap-layouts" => list_x11_keymaps("layouts", None),
        "list-x11-keymap-variants" => list_x11_keymaps("variants", args.get(2).map(String::as_str)),
        "list-x11-keymap-options" => list_x11_keymaps("options", None),
        "--version" => print!("systemd 261 (261.2-1-arch)\n"),
        "-h" | "--help" | "help" => print_help(),
        _ => {
            eprintln!("Unknown command '{cmd}'");
            exit(1);
        }
    }
}
