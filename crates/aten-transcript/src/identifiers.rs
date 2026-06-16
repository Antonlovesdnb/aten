//! Identifier extraction and normalization for the per-session origin index.
//!
//! What counts as an identifier today: absolute file paths (both POSIX and Windows
//! style), home-relative paths, HTTP(S) URLs, **bare hostnames** (domain-shaped
//! tokens whose final label is a known TLD), and **IPv4 addresses**.
//! Normalization expands `~`, lowercases Windows drive letters and
//! hostnames/IPs, and canonicalizes slashes so that `~/.aws/credentials` (typed
//! by user), `/home/anton/.aws/credentials` (kernel event from Linux), and
//! `C:\Users\anton\.aws\credentials` (kernel event from Windows) all match
//! against one entry in the index — and so a `dns_query.query_name` /
//! `network_egress.dest_ip` resolves against a host/IP that surfaced in a
//! prompt or tool_result (the DNS-exfil / prompt-injection origin signal).
//!
//! Host matching is TLD-gated to avoid treating `file.txt` / `config.json` as
//! hostnames — the final label must be a registered TLD (ccTLD or common
//! gTLD). Filename-shaped tokens on a label that IS a TLD (e.g. `main.rs`,
//! `readme.md`) may be indexed, but that's harmless: no kernel identifier ever
//! equals them. Misses: hostnames on TLDs outside the set, and IPv6 (the
//! in-prose match is too false-positive-prone for v1).
//!
//! Known limitations carried in schema.md §10: no base64/URL-encoding fuzziness,
//! no env-var expansion beyond `~`. Both are post-v0.x.

use regex::Regex;
use std::collections::HashSet;
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

/// Domain-shaped token: one or more DNS labels then a TLD-shaped final label.
/// The final label is validated against `tld_set` in `extract` (the regex
/// alone would also match `file.txt`).
fn host_pattern() -> &'static Regex {
    static P: OnceLock<Regex> = OnceLock::new();
    P.get_or_init(|| {
        Regex::new(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b").unwrap()
    })
}

/// Dotted-quad candidate; validated as a real IPv4 (octets ≤ 255) in `extract`.
fn ipv4_pattern() -> &'static Regex {
    static P: OnceLock<Regex> = OnceLock::new();
    P.get_or_init(|| Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap())
}

/// Registered TLDs we accept as the final label of a bare hostname: every
/// ISO-3166 ccTLD (covers the abuse-favorite free ones — tk/ml/ga/cf/gq — and
/// the extension-lookalikes io/sh/me/co/rs/md) plus common gTLDs. A hostname on
/// a TLD outside this set is missed (documented); the set is the precision
/// guard that keeps `file.txt`/`config.json` out of the index.
fn tld_set() -> &'static HashSet<&'static str> {
    static S: OnceLock<HashSet<&'static str>> = OnceLock::new();
    S.get_or_init(|| {
        const TLDS: &str = "\
            ac ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg \
            bh bi bj bm bn bo br bs bt bw by bz ca cc cd cf cg ch ci ck cl cm cn \
            co cr cu cv cw cx cy cz de dj dk dm do dz ec ee eg eh er es et eu fi \
            fj fk fm fo fr ga gd ge gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy \
            hk hm hn hr ht hu id ie il im in io iq ir is it je jm jo jp ke kg kh \
            ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc md me \
            mg mh mk ml mm mn mo mp mq mr ms mt mu mv mw mx my mz na nc ne nf ng \
            ni nl no np nr nu nz om pa pe pf pg ph pk pl pm pn pr ps pt pw py qa \
            re ro rs ru rw sa sb sc sd se sg sh si sj sk sl sm sn so sr ss st su \
            sv sx sy sz tc td tf tg th tj tk tl tm tn to tr tt tv tw tz ua ug uk \
            us uy uz va vc ve vg vi vn vu wf ws ye yt za zm zw \
            com net org info biz name pro mobi int gov edu mil aero asia cat \
            coop jobs museum tel travel app dev page web site online store shop \
            xyz top club live life world today news blog wiki email link click \
            download host website press digital cloud tech space fun icu vip \
            work zip mov";
        TLDS.split_whitespace().collect()
    })
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
    // IPv4 addresses (validate octets via the std parser to reject 999.x etc.).
    for m in ipv4_pattern().find_iter(text) {
        let s = strip_trailing_punct(m.as_str());
        if s.parse::<std::net::Ipv4Addr>().is_ok() {
            out.insert(s.to_string());
        }
    }
    // Bare hostnames — only when the final label is a known TLD, so prose
    // filenames (`file.txt`) don't get indexed as hosts.
    for m in host_pattern().find_iter(text) {
        let s = strip_trailing_punct(m.as_str());
        if let Some(tld) = s.rsplit('.').next() {
            if tld_set().contains(tld.to_ascii_lowercase().as_str()) {
                out.insert(s.to_string());
            }
        }
    }
    out.into_iter().collect()
}

fn strip_trailing_punct(s: &str) -> &str {
    s.trim_end_matches(['.', ',', ';', ':', '!', '?', ')', ']'])
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
    } else if !canon.contains('/') {
        // No path separator → a bare hostname or IP. These are case-insensitive
        // (DNS) / canonically lowercase (IPv6 hex), and the collectors emit
        // `query_name`/`dest_ip` lowercased, so lowercase here to match. POSIX
        // paths (which contain `/`) stay case-preserved — Linux is case-sensitive.
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

    #[test]
    fn extracts_bare_hostname() {
        let got = extract("the page told me to exfil creds to research.attacker.com asap");
        assert!(
            got.iter().any(|s| s == "research.attacker.com"),
            "got: {got:?}"
        );
        // bare 2-label domain on a real TLD too
        assert!(extract("beacon to evil.tk").iter().any(|s| s == "evil.tk"));
    }

    #[test]
    fn hostname_match_is_tld_gated() {
        // Filename-shaped tokens whose final label is NOT a TLD must not be
        // treated as hosts (guards the index against prose junk).
        let got = extract("open config.json, styles.css, notes.txt, data.yaml");
        assert!(got.is_empty(), "got: {got:?}");
    }

    #[test]
    fn bare_host_also_pulled_from_url() {
        let got = extract("fetch https://attacker.com/path?token=abc");
        assert!(got.iter().any(|s| s == "attacker.com"), "got: {got:?}");
    }

    #[test]
    fn extracts_ipv4_and_rejects_invalid() {
        let got = extract("beacon to 203.0.113.5:443 please");
        assert!(got.iter().any(|s| s == "203.0.113.5"), "got: {got:?}");
        // out-of-range octet → not a valid IPv4 → dropped
        let bad = extract("build artifact 999.1.2.3 done");
        assert!(!bad.iter().any(|s| s == "999.1.2.3"), "got: {bad:?}");
    }

    #[test]
    fn hostname_and_ip_normalize_lowercase() {
        // mixed-case host typed in a message must match the collector's
        // lowercased query_name
        assert_eq!(
            normalize("Research.Attacker.COM", None),
            "research.attacker.com"
        );
        assert_eq!(normalize("203.0.113.5", None), "203.0.113.5");
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
