// SPDX-License-Identifier: LGPL-2.1-or-later
//! systemd journal message catalog database support.
//!
//! Binary format and source parsing follow upstream v261
//! `src/libsystemd/sd-journal/catalog.[ch]`.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const SIGNATURE: &[u8; 8] = b"RHHHKSLP";
const HEADER_SIZE: usize = 40;
const ITEM_SIZE: usize = 56;
const LANGUAGE_SIZE: usize = 32;
const DEFAULT_DATABASE: &str = "/var/lib/systemd/catalog/database";
const DEFAULT_SOURCES: &[&str] = &["/usr/local/lib/systemd/catalog", "/usr/lib/systemd/catalog"];

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CatalogKey {
    id: [u8; 16],
    language: String,
}

#[derive(Debug, Clone)]
struct CatalogRecord {
    key: CatalogKey,
    text: String,
}

/// Parsed binary message catalog.
#[derive(Debug, Clone)]
pub struct CatalogDatabase {
    records: Vec<CatalogRecord>,
}

/// Resolve the catalog database path, honoring upstream's `SYSTEMD_CATALOG` override.
#[must_use]
pub fn database_path() -> PathBuf {
    std::env::var_os("SYSTEMD_CATALOG")
        .map_or_else(|| PathBuf::from(DEFAULT_DATABASE), PathBuf::from)
}

/// Resolve catalog source directories for `--update-catalog`.
#[must_use]
pub fn source_directories() -> Vec<PathBuf> {
    if let Some(value) = std::env::var_os("SYSTEMD_CATALOG_SOURCES") {
        if !value.is_empty() {
            return vec![PathBuf::from(value)];
        }
    }
    DEFAULT_SOURCES.iter().map(PathBuf::from).collect()
}

/// Parse an sd-id128 string accepted by catalog commands and `MESSAGE_ID=`.
///
/// # Errors
/// Returns an error when `value` is not a 128-bit hexadecimal identifier.
pub fn parse_id(value: &str) -> anyhow::Result<[u8; 16]> {
    let compact: String = value
        .chars()
        .filter(|character| *character != '-')
        .collect();
    if compact.len() != 32 || !compact.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(anyhow::anyhow!("invalid message ID '{value}'"));
    }
    let mut id = [0u8; 16];
    for (index, byte) in id.iter_mut().enumerate() {
        let start = index * 2;
        *byte = u8::from_str_radix(&compact[start..start + 2], 16)
            .map_err(|_| anyhow::anyhow!("invalid message ID '{value}'"))?;
    }
    Ok(id)
}

/// Render a message ID in the canonical lower-case 32-hex form.
#[must_use]
pub fn format_id(id: &[u8; 16]) -> String {
    let mut output = String::with_capacity(32);
    for byte in id {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

impl CatalogDatabase {
    /// Open and validate an upstream binary catalog database.
    ///
    /// # Errors
    /// Returns an error when the database cannot be read or its binary layout is invalid.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let bytes = fs::read(path)
            .map_err(|error| anyhow::anyhow!("read catalog {}: {error}", path.display()))?;
        if bytes.len() < HEADER_SIZE || &bytes[..8] != SIGNATURE {
            return Err(anyhow::anyhow!(
                "{}: invalid catalog header",
                path.display()
            ));
        }
        let incompatible = read_u32(&bytes, 12)?;
        let header_size = to_usize(read_u64(&bytes, 16)?, "catalog header size")?;
        let n_items = to_usize(read_u64(&bytes, 24)?, "catalog item count")?;
        let item_size = to_usize(read_u64(&bytes, 32)?, "catalog item size")?;
        if incompatible != 0 || header_size < HEADER_SIZE || item_size < ITEM_SIZE || n_items == 0 {
            return Err(anyhow::anyhow!(
                "{}: unsupported catalog header",
                path.display()
            ));
        }
        let items_bytes = item_size
            .checked_mul(n_items)
            .and_then(|size| header_size.checked_add(size))
            .ok_or_else(|| anyhow::anyhow!("{}: catalog item table overflows", path.display()))?;
        if items_bytes > bytes.len() {
            return Err(anyhow::anyhow!(
                "{}: truncated catalog item table",
                path.display()
            ));
        }

        let mut records = Vec::with_capacity(n_items);
        let mut previous: Option<CatalogKey> = None;
        for index in 0..n_items {
            let offset = header_size + index * item_size;
            let mut id = [0u8; 16];
            id.copy_from_slice(&bytes[offset..offset + 16]);
            let language_bytes = &bytes[offset + 16..offset + 16 + LANGUAGE_SIZE];
            let language_end = language_bytes
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(LANGUAGE_SIZE);
            let language = std::str::from_utf8(&language_bytes[..language_end])
                .map_err(|_| anyhow::anyhow!("{}: invalid catalog language", path.display()))?
                .to_owned();
            if language.len() > 31 {
                return Err(anyhow::anyhow!(
                    "{}: catalog language too long",
                    path.display()
                ));
            }
            let string_offset = to_usize(read_u64(&bytes, offset + 48)?, "catalog string offset")?;
            let start = items_bytes.checked_add(string_offset).ok_or_else(|| {
                anyhow::anyhow!("{}: catalog string offset overflows", path.display())
            })?;
            if start >= bytes.len() {
                return Err(anyhow::anyhow!(
                    "{}: catalog string offset out of bounds",
                    path.display()
                ));
            }
            let tail = &bytes[start..];
            let end = tail.iter().position(|byte| *byte == 0).ok_or_else(|| {
                anyhow::anyhow!("{}: unterminated catalog string", path.display())
            })?;
            let text = std::str::from_utf8(&tail[..end])
                .map_err(|_| anyhow::anyhow!("{}: catalog text is not UTF-8", path.display()))?
                .to_owned();
            let key = CatalogKey { id, language };
            if previous.as_ref().is_some_and(|old| old >= &key) {
                return Err(anyhow::anyhow!(
                    "{}: unsorted catalog item table",
                    path.display()
                ));
            }
            previous = Some(key.clone());
            records.push(CatalogRecord { key, text });
        }
        Ok(Self { records })
    }

    /// Return all unique message IDs in database order.
    #[must_use]
    pub fn ids(&self) -> Vec<[u8; 16]> {
        let mut ids = Vec::new();
        for record in &self.records {
            if ids.last() != Some(&record.key.id) {
                ids.push(record.key.id);
            }
        }
        ids
    }

    /// Look up an ID using the current `LC_MESSAGES` language fallback chain.
    #[must_use]
    pub fn lookup(&self, id: &[u8; 16]) -> Option<&str> {
        let locale = current_message_locale();
        self.lookup_locale(id, locale.as_deref())
    }

    /// Look up an ID with an explicit locale. Useful for deterministic tests.
    #[must_use]
    pub fn lookup_locale(&self, id: &[u8; 16], locale: Option<&str>) -> Option<&str> {
        let mut candidates = Vec::new();
        if let Some(locale) = normalize_locale(locale) {
            candidates.push(locale.clone());
            if let Some((base, _)) = locale.split_once('_') {
                if base != locale {
                    candidates.push(base.to_owned());
                }
            }
        }
        candidates.push(String::new());
        candidates.dedup();

        for language in candidates {
            if let Some(record) = self
                .records
                .iter()
                .find(|record| &record.key.id == id && record.key.language == language)
            {
                return Some(&record.text);
            }
        }
        None
    }
}

/// Update an upstream-compatible binary database from catalog source directories.
///
/// # Errors
/// Returns an error when catalog sources are invalid or the database cannot be written.
pub fn update_database(database: &Path, directories: &[PathBuf]) -> anyhow::Result<usize> {
    let files = source_files(directories)?;
    let mut items: BTreeMap<CatalogKey, String> = BTreeMap::new();
    for path in files {
        let content = fs::read_to_string(&path)
            .map_err(|error| anyhow::anyhow!("read catalog source {}: {error}", path.display()))?;
        for (key, payload) in parse_source(&path, &content)? {
            if let Some(previous) = items.get(&key) {
                let combined = combine_entries(&payload, previous);
                items.insert(key, combined);
            } else {
                items.insert(key, payload);
            }
        }
    }
    if items.is_empty() {
        return Ok(0);
    }

    let mut strings = Vec::new();
    let mut encoded_items = Vec::with_capacity(items.len());
    for (key, payload) in &items {
        let offset = u64::try_from(strings.len())?;
        strings.extend_from_slice(payload.as_bytes());
        strings.push(0);
        encoded_items.push((key, offset));
    }

    let mut output = Vec::with_capacity(HEADER_SIZE + ITEM_SIZE * items.len() + strings.len());
    output.extend_from_slice(SIGNATURE);
    output.extend_from_slice(&0u32.to_le_bytes());
    output.extend_from_slice(&0u32.to_le_bytes());
    output.extend_from_slice(&(HEADER_SIZE as u64).to_le_bytes());
    output.extend_from_slice(&(items.len() as u64).to_le_bytes());
    output.extend_from_slice(&(ITEM_SIZE as u64).to_le_bytes());
    debug_assert_eq!(output.len(), HEADER_SIZE);

    for (key, offset) in encoded_items {
        output.extend_from_slice(&key.id);
        let mut language = [0u8; LANGUAGE_SIZE];
        if key.language.len() > 31 {
            return Err(anyhow::anyhow!(
                "catalog language is too long: {}",
                key.language
            ));
        }
        language[..key.language.len()].copy_from_slice(key.language.as_bytes());
        output.extend_from_slice(&language);
        output.extend_from_slice(&offset.to_le_bytes());
    }
    output.extend_from_slice(&strings);

    if let Some(parent) = database.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = database.with_extension(format!("tmp.{}", std::process::id()));
    fs::write(&temporary, output)?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o644))?;
    if let Err(error) = fs::rename(&temporary, database) {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    Ok(items.len())
}

/// Expand upstream catalog `@FIELD@` substitutions using one journal entry.
#[must_use]
pub fn expand_fields<S: std::hash::BuildHasher>(
    text: &str,
    fields: &HashMap<String, Vec<u8>, S>,
) -> String {
    let mut output = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'@' {
            output.push(bytes[index] as char);
            index += 1;
            continue;
        }
        let Some(relative_end) = bytes[index + 1..].iter().position(|byte| *byte == b'@') else {
            output.push('@');
            index += 1;
            continue;
        };
        let end = index + 1 + relative_end;
        let field = &text[index + 1..end];
        if field.is_empty() {
            output.push('@');
        } else if let Some(value) = fields.get(field) {
            output.push_str(&String::from_utf8_lossy(value));
        } else {
            output.push_str(field);
        }
        index = end + 1;
    }
    output
}

/// Find a catalog header value before the body separator.
#[must_use]
pub fn header_value<'a>(text: &'a str, header: &str) -> Option<&'a str> {
    for line in text.lines() {
        if line.is_empty() {
            return None;
        }
        if let Some(value) = line.strip_prefix(header) {
            return Some(value.trim_start_matches([' ', '\t']));
        }
    }
    None
}

/// Prefix used by upstream catalog explanations in the active locale.
#[must_use]
pub fn output_prefix() -> &'static str {
    let locale = std::env::var("LC_ALL")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| {
            std::env::var("LC_CTYPE")
                .ok()
                .filter(|value| !value.is_empty())
        })
        .or_else(|| std::env::var("LANG").ok().filter(|value| !value.is_empty()));
    let utf8_locale = locale.as_deref().is_some_and(|value| {
        let upper = value.to_ascii_uppercase();
        upper.contains("UTF-8") || upper.contains("UTF8")
    });
    if utf8_locale {
        "░░"
    } else {
        "--"
    }
}

fn source_files(directories: &[PathBuf]) -> anyhow::Result<Vec<PathBuf>> {
    let mut by_name: BTreeMap<String, Option<PathBuf>> = BTreeMap::new();
    for directory in directories {
        let entries = match fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(anyhow::anyhow!(
                    "read catalog directory {}: {error}",
                    directory.display()
                ));
            }
        };
        let mut paths: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
        paths.sort();
        for path in paths {
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if !name.ends_with(".catalog") || by_name.contains_key(name) {
                continue;
            }
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink()
                && fs::read_link(&path).ok().as_deref() == Some(Path::new("/dev/null"))
            {
                by_name.insert(name.to_owned(), None);
            } else if metadata.is_file() || metadata.file_type().is_symlink() {
                by_name.insert(name.to_owned(), Some(path));
            }
        }
    }
    Ok(by_name.into_values().flatten().collect())
}

fn parse_source(path: &Path, content: &str) -> anyhow::Result<Vec<(CatalogKey, String)>> {
    let default_language = file_language(path);
    let mut result = Vec::new();
    let mut current_id: Option<[u8; 16]> = None;
    let mut current_language: Option<String> = None;
    let mut payload = String::new();
    let mut empty_line = true;

    for (line_number, raw_line) in content.lines().enumerate() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.is_empty() {
            empty_line = true;
            continue;
        }
        if line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if empty_line {
            if let Some((id, language)) = parse_separator(line, default_language.as_deref())? {
                if let Some(previous_id) = current_id {
                    if payload.is_empty() {
                        return Err(anyhow::anyhow!(
                            "{}:{}: catalog entry has no payload",
                            path.display(),
                            line_number + 1
                        ));
                    }
                    result.push((
                        CatalogKey {
                            id: previous_id,
                            language: current_language
                                .take()
                                .or_else(|| default_language.clone())
                                .unwrap_or_default(),
                        },
                        std::mem::take(&mut payload),
                    ));
                }
                current_id = Some(id);
                current_language = language;
                empty_line = false;
                continue;
            }
        }
        if current_id.is_none() {
            return Err(anyhow::anyhow!(
                "{}:{}: catalog payload appears before a message ID",
                path.display(),
                line_number + 1
            ));
        }
        if empty_line {
            payload.push('\n');
        }
        payload.push_str(line);
        payload.push('\n');
        empty_line = false;
    }

    if let Some(id) = current_id {
        if payload.is_empty() {
            return Err(anyhow::anyhow!(
                "{}: catalog entry has no payload",
                path.display()
            ));
        }
        result.push((
            CatalogKey {
                id,
                language: current_language.or(default_language).unwrap_or_default(),
            },
            payload,
        ));
    }
    Ok(result)
}

fn parse_separator(
    line: &str,
    default_language: Option<&str>,
) -> anyhow::Result<Option<([u8; 16], Option<String>)>> {
    let Some(rest) = line.strip_prefix("-- ") else {
        return Ok(None);
    };
    if rest.len() < 32 {
        return Ok(None);
    }
    let (raw_id, suffix) = rest.split_at(32);
    let Ok(id) = parse_id(raw_id) else {
        return Ok(None);
    };
    if !suffix.is_empty() && !suffix.starts_with(' ') {
        return Ok(None);
    }
    let language = suffix.trim();
    if language.is_empty() {
        return Ok(Some((id, None)));
    }
    if !(2..=31).contains(&language.len()) {
        return Err(anyhow::anyhow!("invalid catalog language '{language}'"));
    }
    if default_language == Some(language) {
        return Ok(Some((id, None)));
    }
    Ok(Some((id, Some(language.to_owned()))))
}

fn file_language(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_str()?;
    let stem = name.strip_suffix(".catalog")?;
    let (_, language) = stem.rsplit_once('.')?;
    (2..=31)
        .contains(&language.len())
        .then(|| language.to_owned())
}

fn combine_entries(new: &str, old: &str) -> String {
    let (new_headers, new_body) = split_headers_body(new);
    let (old_headers, old_body) = split_headers_body(old);
    let mut result = String::with_capacity(new.len() + old.len());
    result.push_str(new_headers);
    result.push_str(old_headers);
    if new_body.is_empty() {
        result.push_str(old_body);
    } else {
        result.push_str(new_body);
    }
    result
}

fn split_headers_body(value: &str) -> (&str, &str) {
    if let Some(index) = value.find("\n\n") {
        let boundary = index + 1;
        (&value[..boundary], &value[boundary..])
    } else {
        (value, "")
    }
}

fn current_message_locale() -> Option<String> {
    for variable in ["LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Ok(value) = std::env::var(variable) {
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

fn normalize_locale(locale: Option<&str>) -> Option<String> {
    let locale = locale?;
    if locale.is_empty() || matches!(locale, "C" | "POSIX") {
        return None;
    }
    let end = locale
        .char_indices()
        .find_map(|(index, character)| matches!(character, '.' | '@').then_some(index))
        .unwrap_or(locale.len());
    if end == 0 || end > 31 {
        return None;
    }
    Some(locale[..end].to_owned())
}

fn read_u32(bytes: &[u8], offset: usize) -> anyhow::Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| anyhow::anyhow!("catalog integer offset overflows"))?;
    let raw: [u8; 4] = bytes
        .get(offset..end)
        .ok_or_else(|| anyhow::anyhow!("truncated catalog integer"))?
        .try_into()?;
    Ok(u32::from_le_bytes(raw))
}

fn read_u64(bytes: &[u8], offset: usize) -> anyhow::Result<u64> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| anyhow::anyhow!("catalog integer offset overflows"))?;
    let raw: [u8; 8] = bytes
        .get(offset..end)
        .ok_or_else(|| anyhow::anyhow!("truncated catalog integer"))?
        .try_into()?;
    Ok(u64::from_le_bytes(raw))
}

fn to_usize(value: u64, label: &str) -> anyhow::Result<usize> {
    usize::try_from(value).map_err(|_| anyhow::anyhow!("{label} does not fit in memory"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "00112233445566778899aabbccddeeff";
    const SECOND: &str = "ffeeddccbbaa99887766554433221100";

    #[test]
    fn id_round_trip_accepts_uuid_spelling() {
        let id = parse_id("00112233-4455-6677-8899-aabbccddeeff").unwrap();
        assert_eq!(format_id(&id), ID);
    }

    #[test]
    fn source_language_and_binary_database_round_trip() {
        let root = tempfile::tempdir().unwrap();
        let sources = root.path().join("catalog");
        fs::create_dir_all(&sources).unwrap();
        fs::write(
            sources.join("test.catalog"),
            format!(
                "-- {ID}\nSubject: Default subject\nDefined-By: test\n\nDefault body @UNIT@.\n\n-- {ID} de\nSubject: Deutscher Betreff\nDefined-By: test\n\nDeutscher Text.\n\n-- {SECOND}\nSubject: Second\nDefined-By: test\n\nSecond body.\n"
            ),
        )
        .unwrap();
        let database = root.path().join("database");
        assert_eq!(update_database(&database, &[sources]).unwrap(), 3);
        let catalog = CatalogDatabase::open(&database).unwrap();
        let id = parse_id(ID).unwrap();
        assert!(catalog
            .lookup_locale(&id, Some("de_DE.UTF-8"))
            .unwrap()
            .contains("Deutscher Betreff"));
        assert!(catalog
            .lookup_locale(&id, Some("fr_FR.UTF-8"))
            .unwrap()
            .contains("Default subject"));
        assert_eq!(catalog.ids().len(), 2);
    }

    #[test]
    fn field_expansion_matches_catalog_semantics() {
        let mut fields = HashMap::new();
        fields.insert("UNIT".into(), b"demo.service".to_vec());
        assert_eq!(
            expand_fields("Unit @UNIT@, missing @MISSING@, literal @@.", &fields),
            "Unit demo.service, missing MISSING, literal @."
        );
    }

    #[test]
    fn duplicate_entry_prefers_new_headers_and_body() {
        let old = "Subject: old\nDefined-By: old\n\nold body\n";
        let new = "Subject: new\n\nnew body\n";
        let combined = combine_entries(new, old);
        assert_eq!(header_value(&combined, "Subject:"), Some("new"));
        assert_eq!(header_value(&combined, "Defined-By:"), Some("old"));
        assert!(combined.ends_with("\nnew body\n"));
    }
}
