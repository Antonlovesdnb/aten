//! Identifier extraction and normalization for the per-session origin index.
//!
//! What counts as an identifier today: absolute file paths (both POSIX and Windows
//! style), home-relative paths, and HTTP(S) URLs. Normalization expands `~`,
//! lowercases Windows drive letters, and canonicalizes slashes so that
//! `~/.aws/credentials` (typed by user), `/home/anton/.aws/credentials` (kernel
//! event from Linux), and `C:\Users\anton\.aws\credentials` (kernel event from
//! Windows) all match against one entry in the index.
//!
//! Known limitations carried in schema.md §10: no base64/URL-encoding fuzziness,
//! no env-var expansion beyond `~`. Both are post-v0.x.

use regex::Regex;
use std::sync::OnceLock;

fn path_patterns() -> &'static [Regex] {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            // Windows absolute, backslash separators: C:\Users\anton\...
            Regex::new(r#"[A-Za-z]:\\[^\s"'<>|*?]+"#).unwrap(),
            // Windows absolute, forward slashes (sometimes seen in JSON-escaped contexts)
            Regex::new(r#"[A-Za-z]:/[^\s"'<>|*?]+"#).unwrap(),
            // POSIX absolute. Negative-lookbehind isn't supported by `regex`; we
            // approximate by requiring a non-word-non-slash boundary before the
            // leading slash, then enforcing the first body char is alphabetic
            // (rejects `/4` etc).
            Regex::new(r#"(?:^|[^\w/])(/[A-Za-z][\w./\-]+)"#).unwrap(),
            // Home-relative: ~/...
            Regex::new(r#"~/[\w./\-]+"#).unwrap(),
        ]
    })
}

fn url_pattern() -> &'static Regex {
    static P: OnceLock<Regex> = OnceLock::new();
    P.get_or_init(|| Regex::new(r#"https?://[^\s"'<>)\]]+"#).unwrap())
}

/// Pull every recognizable identifier out of a chunk of text. De-duped.
///
/// Trailing English punctuation (`. , ; : ! ?`) is stripped because the regex
/// character classes are greedy enough to swallow sentence terminators —
/// `"read ~/.aws/credentials."` would otherwise produce a different normalized
/// key than `"read ~/.aws/credentials"`, and the two would not collide in the
/// origin index. Same logic applied to URL captures.
pub fn extract(text: &str) -> Vec<String> {
    let mut out: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for (i, pat) in path_patterns().iter().enumerate() {
        // Pattern index 2 is the POSIX one with a capture group; the others are
        // full-match patterns.
        if i == 2 {
            for cap in pat.captures_iter(text) {
                if let Some(m) = cap.get(1) {
                    out.insert(strip_trailing_punct(m.as_str()).to_string());
                }
            }
        } else {
            for m in pat.find_iter(text) {
                out.insert(strip_trailing_punct(m.as_str()).to_string());
            }
        }
    }
    for m in url_pattern().find_iter(text) {
        out.insert(strip_trailing_punct(m.as_str()).to_string());
    }
    out.into_iter().collect()
}

fn strip_trailing_punct(s: &str) -> &str {
    s.trim_end_matches(|c: char| matches!(c, '.' | ',' | ';' | ':' | '!' | '?' | ')' | ']'))
}

/// Canonical form for cross-platform comparison.
/// - URLs lowercased.
/// - `~/...` expanded against `home` (defaults to `$HOME` / `%USERPROFILE%`).
/// - Backslashes → forward slashes.
/// - Windows drive paths lowercased entirely (Windows filesystems are case-
///   insensitive; Linux ones are not, so we leave POSIX paths case-preserved).
pub fn normalize(ident: &str, home: Option<&str>) -> String {
    if ident.starts_with("http://") || ident.starts_with("https://") {
        return ident.to_lowercase();
    }

    let home_owned: String;
    let home_str = match home {
        Some(h) => h,
        None => {
            home_owned = std::env::var("HOME")
                .or_else(|_| std::env::var("USERPROFILE"))
                .unwrap_or_default();
            &home_owned
        }
    };

    let expanded = if let Some(rest) = ident.strip_prefix("~/").or_else(|| ident.strip_prefix("~\\"))
    {
        format!("{home_str}/{rest}")
    } else {
        ident.to_string()
    };

    let mut canon = expanded.replace('\\', "/");

    // Windows drive letter? Lowercase the whole thing.
    let is_windows_drive = canon
        .chars()
        .next()
        .map(|c| c.is_ascii_alphabetic())
        .unwrap_or(false)
        && canon.get(1..3) == Some(":/");
    if is_windows_drive {
        canon = canon.to_lowercase();
    }

    canon
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_posix_path() {
        let got = extract("see /home/anton/.aws/credentials please");
        assert!(got.iter().any(|s| s == "/home/anton/.aws/credentials"));
    }

    #[test]
    fn extracts_home_relative() {
        let got = extract("open ~/.ssh/id_rsa");
        assert!(got.iter().any(|s| s == "~/.ssh/id_rsa"));
    }

    #[test]
    fn extracts_windows_path() {
        let got = extract(r"open C:\Users\anton\.aws\credentials");
        assert!(got.iter().any(|s| s.starts_with("C:\\Users") && s.contains("credentials")));
    }

    #[test]
    fn extracts_url() {
        let got = extract("fetch https://attacker.com/path?token=abc");
        assert!(got.iter().any(|s| s.starts_with("https://attacker.com/path")));
    }

    #[test]
    fn no_false_positive_on_plain_text() {
        let got = extract("hello world, see file.txt");
        assert!(got.is_empty(), "got: {got:?}");
    }

    /// English punctuation at the end of a path or URL must not collide the
    /// normalized key. Without trailing-punct stripping, the prompt-injection
    /// detection would miss matches whenever the path appears at the end of a
    /// sentence.
    #[test]
    fn trailing_punctuation_stripped() {
        let got = extract("please read ~/.aws/credentials.");
        assert!(got.iter().any(|s| s == "~/.aws/credentials"), "got: {got:?}");

        let got2 = extract("check (https://attacker.com/path), then continue");
        assert!(
            got2.iter().any(|s| s == "https://attacker.com/path"),
            "got: {got2:?}"
        );
    }

    #[test]
    fn windows_path_normalizes_lowercase_forward_slash() {
        assert_eq!(
            normalize(r"C:\Users\Anton\.AWS\credentials", None),
            "c:/users/anton/.aws/credentials"
        );
    }

    #[test]
    fn home_relative_expands() {
        assert_eq!(
            normalize("~/.aws/credentials", Some("/home/anton")),
            "/home/anton/.aws/credentials"
        );
    }

    #[test]
    fn url_normalizes_lowercase() {
        assert_eq!(
            normalize("https://Attacker.COM/Path", None),
            "https://attacker.com/path"
        );
    }
}
