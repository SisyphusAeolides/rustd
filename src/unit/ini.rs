// SPDX-License-Identifier: LGPL-2.1-or-later
//! INI tokeniser for systemd unit files.
//!
//! Produces a flat list of `RawEntry { section, key, value }` triples from
//! unit file text.  The caller is responsible for interpreting values.
//!
//! Upstream reference: `src/shared/conf-parser.c config_parse()` (v261)

/// A single parsed unit file entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawEntry {
    /// Section name, e.g. `"Unit"`, `"Service"`, `"Install"`.
    pub section: String,
    /// Key name, e.g. `"Description"`, `"ExecStart"`.
    pub key: String,
    /// Raw value string, specifier-unexpanded.  Empty string means "reset".
    pub value: String,
    /// 1-based line number for diagnostics.
    pub line: usize,
}

/// Parse `text` as a systemd unit file and return all entries in order.
///
/// Entries from unknown sections are included — the caller decides what to
/// accept.  Malformed lines (no `=` outside a section) are silently skipped.
#[must_use]
pub fn parse_unit_text(text: &str) -> Vec<RawEntry> {
    let mut entries = Vec::new();
    let mut current_section = String::new();

    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let lineno = i + 1;
        let trimmed = lines[i].trim();

        // Blank line or comment.
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            i += 1;
            continue;
        }

        // Section header.
        if let Some(inner) = trimmed.strip_prefix('[') {
            if let Some(name) = inner.strip_suffix(']') {
                name.trim().clone_into(&mut current_section);
            }
            i += 1;
            continue;
        }

        // Key = value (with possible continuation lines).
        if let Some(eq_pos) = trimmed.find('=') {
            let key = trimmed[..eq_pos].trim().to_owned();
            let mut value_buf = trimmed[eq_pos + 1..].to_owned();

            // Consume continuation lines (line ending with `\`).
            while value_buf.ends_with('\\') {
                value_buf.pop();
                i += 1;
                if i >= lines.len() {
                    break;
                }
                let cont = lines[i].trim();
                if cont.starts_with('#') || cont.starts_with(';') {
                    continue;
                }
                value_buf.push_str(cont);
            }

            if !current_section.is_empty() && !key.is_empty() {
                entries.push(RawEntry {
                    section: current_section.clone(),
                    key,
                    value: value_buf.trim().to_owned(),
                    line: lineno,
                });
            }
        }

        i += 1;
    }

    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_service() {
        let text = "[Unit]\nDescription=Test Service\nAfter=network.target\n\
                    [Service]\nType=simple\nExecStart=/usr/bin/true\n";
        let entries = parse_unit_text(text);
        assert!(entries
            .iter()
            .any(|e| e.key == "Description" && e.value == "Test Service"));
        assert!(entries
            .iter()
            .any(|e| e.key == "After" && e.value == "network.target"));
        assert!(entries
            .iter()
            .any(|e| e.key == "Type" && e.value == "simple"));
    }

    #[test]
    fn comments_ignored() {
        let text = "# top\n[Unit]\n; inline\nDescription=Foo\n";
        let entries = parse_unit_text(text);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key, "Description");
        assert_eq!(entries[0].value, "Foo");
    }

    #[test]
    fn line_continuation() {
        let text = "[Service]\nExecStart=/usr/bin/foo \\\n  --flag1 \\\n  --flag2\n";
        let entries = parse_unit_text(text);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].value.contains("--flag1"));
        assert!(entries[0].value.contains("--flag2"));
    }

    #[test]
    fn empty_value_reset() {
        let text = "[Unit]\nWants=a.service\nWants=\nWants=b.service\n";
        let entries = parse_unit_text(text);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[1].value, "");
    }

    #[test]
    fn multivalue_accumulates() {
        let text = "[Unit]\nAfter=a.target\nAfter=b.target c.target\n";
        let entries = parse_unit_text(text);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].value, "a.target");
        assert_eq!(entries[1].value, "b.target c.target");
    }

    #[test]
    fn no_section_entries_dropped() {
        let text = "Foo=bar\n[Unit]\nDescription=x\n";
        let entries = parse_unit_text(text);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key, "Description");
    }

    #[test]
    fn installed_service_files_parse() {
        let dir = std::path::Path::new("/usr/lib/systemd/system");
        if !dir.exists() {
            return;
        }
        let mut count = 0usize;
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("service") {
                if let Ok(text) = std::fs::read_to_string(&path) {
                    let _ = parse_unit_text(&text);
                    count += 1;
                }
            }
        }
        assert!(count > 100, "expected >100 service files, got {count}");
    }
}
