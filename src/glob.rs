// SPDX-License-Identifier: LGPL-2.1-or-later
//! `fnmatch(3)`-style matching with `FNM_NOESCAPE` semantics.

/// Match `value` against `pattern` using `*`, `?`, and bracket expressions.
///
/// Backslashes are ordinary characters, matching systemd's use of
/// `fnmatch(3)` with `FNM_NOESCAPE`.
#[must_use]
pub fn matches_no_escape(pattern: &str, value: &str) -> bool {
    matches_bytes(pattern.as_bytes(), value.as_bytes())
}

fn matches_bytes(pattern: &[u8], value: &[u8]) -> bool {
    match pattern {
        [] => value.is_empty(),
        [b'*', rest @ ..] => {
            matches_bytes(rest, value) || (!value.is_empty() && matches_bytes(pattern, &value[1..]))
        }
        [b'?', rest @ ..] => !value.is_empty() && matches_bytes(rest, &value[1..]),
        [b'[', rest @ ..] => match_bracket(rest, value),
        [literal, rest @ ..] => value.first() == Some(literal) && matches_bytes(rest, &value[1..]),
    }
}

fn match_bracket(pattern: &[u8], value: &[u8]) -> bool {
    let Some(&current) = value.first() else {
        return false;
    };
    let Some(end) = pattern.iter().position(|byte| *byte == b']') else {
        return current == b'[' && matches_bytes(pattern, &value[1..]);
    };
    let class = &pattern[..end];
    let (negated, class) = match class.first() {
        Some(b'!' | b'^') => (true, &class[1..]),
        _ => (false, class),
    };
    let mut matches = false;
    let mut index = 0;
    while index < class.len() {
        if index + 2 < class.len() && class[index + 1] == b'-' {
            matches |= class[index] <= current && current <= class[index + 2];
            index += 3;
        } else {
            matches |= class[index] == current;
            index += 1;
        }
    }
    matches != negated && matches_bytes(&pattern[end + 1..], &value[1..])
}

#[cfg(test)]
mod tests {
    use super::matches_no_escape;

    #[test]
    fn fnmatch_noescape_patterns() {
        assert!(matches_no_escape("*.service", "example.service"));
        assert!(matches_no_escape("example-?.service", "example-a.service"));
        assert!(matches_no_escape(
            "example-[ab].service",
            "example-a.service"
        ));
        assert!(matches_no_escape(
            "example-[!b].service",
            "example-a.service"
        ));
        assert!(!matches_no_escape("*.socket", "example.service"));
        assert!(matches_no_escape(
            r"example\*.service",
            r"example\foo.service"
        ));
    }
}
