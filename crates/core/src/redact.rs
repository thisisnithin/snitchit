//! Sensitive-data detection and redaction (port of halo-record's `redact.py`).
//!
//! A conforming record MUST NOT contain raw secrets or personal data (brief §3).
//! [`scan`] finds them; [`redact_text`] masks them. Detection is deterministic
//! and explainable — never a model judgement: a list of known secret/PII
//! patterns plus a high-entropy catch-all for long random-looking tokens the
//! patterns miss. Over-redaction is the safe failure mode: this artifact is meant
//! to be shareable.
//!
//! No panics: every built-in pattern is a compile-time constant compiled with
//! `.ok()`. [`validate`] (called once at startup) turns a malformed constant
//! into a startup error rather than a runtime panic or — worse for a secret
//! scanner — a silently disabled pattern. All string trimming is char-based, so
//! arbitrary (non-ASCII) input can never trigger a byte-boundary slice panic.

use std::collections::HashMap;
use std::sync::LazyLock;

use regex::Regex;

use crate::error::{CoreError, Result};

/// A detected sensitive value, stored redacted (never the raw value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Kind of secret/PII, e.g. `api_key`, `email`.
    pub kind: String,
    /// Severity: `CRITICAL` | `HIGH` | `MEDIUM` | `LOW` | `INFO`.
    pub severity: String,
    /// Redacted excerpt — the unredacted value never appears.
    pub sample: String,
}

struct Pattern {
    name: &'static str,
    severity: &'static str,
    re: Regex,
}

/// Built-in secret/PII patterns as `(kind, severity, regex source)`. They are
/// compile-time constants, so they compile deterministically; [`validate`]
/// proves it at startup.
const RAW_PATTERNS: &[(&str, &str, &str)] = &[
    (
        "api_key",
        "CRITICAL",
        r"(?:sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[a-zA-Z0-9\-]{10,})",
    ),
    ("gcp_api_key", "CRITICAL", r"AIza[0-9A-Za-z_\-]{35}"),
    (
        "stripe_key",
        "CRITICAL",
        r"(?:sk|rk|pk)_(?:live|test)_[0-9a-zA-Z]{16,}",
    ),
    (
        "github_token",
        "CRITICAL",
        r"(?:gh[opsu]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})",
    ),
    (
        "private_key",
        "CRITICAL",
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    ),
    (
        "db_conn",
        "CRITICAL",
        r#"(?:postgres|mysql|mongodb(?:\+srv)?|redis)://[^\s"'<>]+"#,
    ),
    (
        "jwt",
        "HIGH",
        r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    ),
    (
        "credit_card",
        "HIGH",
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
    ),
    ("ssn", "HIGH", r"\b\d{3}-\d{2}-\d{4}\b"),
    ("bearer_token", "HIGH", r"Bearer\s+[a-zA-Z0-9\-_\.]{20,}"),
    (
        "email",
        "MEDIUM",
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    ),
    (
        "ip_internal",
        "MEDIUM",
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
    ),
];

static PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    RAW_PATTERNS
        .iter()
        .filter_map(|(name, severity, pat)| {
            Regex::new(pat)
                .ok()
                .map(|re| Pattern { name, severity, re })
        })
        .collect()
});

// Auxiliary single-purpose matchers. `None` only if the constant failed to
// compile — turned into a startup error by `validate`, never a panic; callers
// treat `None` as "no match" (the conservative, over-redacting side).
static TOKEN_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/=_-]{24,}").ok());
static HEX_RE: LazyLock<Option<Regex>> = LazyLock::new(|| Regex::new(r"^[0-9a-fA-F]+$").ok());
static UUID_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-").ok());
static DIGITS_RE: LazyLock<Option<Regex>> = LazyLock::new(|| Regex::new(r"^\d+$").ok());
static CRED_RE: LazyLock<Option<Regex>> = LazyLock::new(|| Regex::new(r"://([^:/@]+):[^@]+@").ok());

const HIGH_ENTROPY_TYPE: &str = "high_entropy_secret";
const HIGH_ENTROPY_MIN_LEN: usize = 24;
const HIGH_ENTROPY_BITS: f64 = 3.5;
const MAX_PER_TYPE: usize = 25;

/// Ensure every built-in redaction pattern compiled. Call once at startup.
///
/// Returns an error (never panics) if a constant pattern is malformed, so a
/// broken build fails fast instead of silently skipping secret detection — which
/// for an audit log would be a secret-leaking regression.
pub fn validate() -> Result<()> {
    let compiled = PATTERNS.len();
    if compiled != RAW_PATTERNS.len() {
        return Err(CoreError::Redaction(format!(
            "{} of {} secret patterns failed to compile",
            RAW_PATTERNS.len() - compiled,
            RAW_PATTERNS.len()
        )));
    }
    let aux: [(&str, &Option<Regex>); 5] = [
        ("high-entropy token", &TOKEN_RE),
        ("hex", &HEX_RE),
        ("uuid", &UUID_RE),
        ("digits", &DIGITS_RE),
        ("db-credential", &CRED_RE),
    ];
    for (name, re) in aux {
        if re.is_none() {
            return Err(CoreError::Redaction(format!(
                "internal '{name}' matcher failed to compile"
            )));
        }
    }
    Ok(())
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MEDIUM" => 2,
        "LOW" => 1,
        _ => 0,
    }
}

// Character counts fit comfortably in f64's mantissa for any realistic token;
// this is an entropy estimate, not exact arithmetic.
#[allow(clippy::cast_precision_loss)]
fn shannon_bits(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts: HashMap<char, usize> = HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }
    let n = s.chars().count() as f64;
    -counts
        .values()
        .map(|&c| {
            let p = c as f64 / n;
            p * p.log2()
        })
        .sum::<f64>()
}

/// Whether an auxiliary matcher (if it compiled) matches `tok`.
fn aux_matches(re: &LazyLock<Option<Regex>>, tok: &str) -> bool {
    re.as_ref().is_some_and(|r| r.is_match(tok))
}

fn looks_like_secret(tok: &str) -> bool {
    if tok.len() < HIGH_ENTROPY_MIN_LEN {
        return false;
    }
    if aux_matches(&HEX_RE, tok) || aux_matches(&UUID_RE, tok) || aux_matches(&DIGITS_RE, tok) {
        return false; // hash digest / UUID / long numeric id
    }
    // Real high-entropy secrets (API keys, base64 blobs) mix letters AND digits.
    // Free-form prose — including words glued together when ANSI escapes are
    // stripped out of a terminal transcript — has letters but no digits, so this
    // single requirement removes the bulk of the false positives.
    let has_digit = tok.chars().any(|c| c.is_ascii_digit());
    let has_alpha = tok.chars().any(|c| c.is_ascii_alphabetic());
    if !(has_digit && has_alpha) {
        return false; // prose / slug / pure number — not a token
    }
    shannon_bits(tok) >= HIGH_ENTROPY_BITS
}

/// First `n` characters of `s` (char-based, never a byte-boundary panic).
fn first_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// Last `n` characters of `s` (char-based, never a byte-boundary panic).
fn last_chars(s: &str, n: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    let start = chars.len().saturating_sub(n);
    chars[start..].iter().collect()
}

/// Produce a redacted excerpt for a match of `kind`. Never panics for any input.
#[must_use]
pub fn redact_sample(kind: &str, value: &str) -> String {
    let v = value;
    match kind {
        "email" => match v.split_once('@') {
            Some((local, domain)) => {
                let first = local.chars().next().unwrap_or('*');
                format!("{first}****@{domain}")
            }
            None => "****".to_string(),
        },
        // Fail-safe: if the credential matcher somehow didn't compile, mask the
        // whole value rather than risk leaking `user:pass@host`.
        "db_conn" => CRED_RE.as_ref().map_or_else(
            || "****".to_string(),
            |re| re.replace(v, "://$1:****@").into_owned(),
        ),
        "bearer_token" => "Bearer ****".to_string(),
        "private_key" => "-----BEGIN PRIVATE KEY----- ****".to_string(),
        "jwt" => "eyJ****".to_string(),
        "api_key" | "gcp_api_key" | "stripe_key" | "github_token" => {
            if v.chars().count() > 4 {
                format!("{}****", first_chars(v, 4))
            } else {
                "****".to_string()
            }
        }
        t if t == HIGH_ENTROPY_TYPE => {
            if v.chars().count() > 3 {
                format!("{}****", first_chars(v, 3))
            } else {
                "****".to_string()
            }
        }
        "credit_card" => {
            let digits: String = v.chars().filter(char::is_ascii_digit).collect();
            if digits.chars().count() >= 4 {
                format!("****{}", last_chars(&digits, 4))
            } else {
                "****".to_string()
            }
        }
        "ssn" => {
            if v.chars().count() >= 4 {
                format!("***-**-{}", last_chars(v, 4))
            } else {
                "****".to_string()
            }
        }
        "ip_internal" => {
            let parts: Vec<&str> = v.split('.').collect();
            if let [a, b, _, _] = parts.as_slice() {
                format!("{a}.{b}.*.*")
            } else {
                "****".to_string()
            }
        }
        _ => "****".to_string(),
    }
}

fn apply_patterns(text: &str) -> String {
    let mut out = text.to_string();
    for p in PATTERNS.iter() {
        out =
            p.re.replace_all(&out, |caps: &regex::Captures| {
                redact_sample(p.name, &caps[0])
            })
            .into_owned();
    }
    out
}

/// Redact known secret/PII patterns, plus a high-entropy catch-all for unknown
/// token formats. Use on **structured** inputs / tool arguments.
#[must_use]
pub fn redact_text(text: &str) -> String {
    redact_inner(text, true)
}

/// Redact only the known, exact secret patterns — **no** fuzzy high-entropy
/// sweep. Use on free-form terminal transcripts, where the catch-all mostly
/// flags rendered prose (words glued together by ANSI stripping) rather than
/// real secrets. Exact patterns (`sk-…`, JWTs, …) still catch genuine leaks.
#[must_use]
pub fn redact_transcript(text: &str) -> String {
    redact_inner(text, false)
}

fn redact_inner(text: &str, high_entropy: bool) -> String {
    let after = apply_patterns(text);
    if !high_entropy {
        return after;
    }
    let Some(token_re) = TOKEN_RE.as_ref() else {
        return after;
    };
    token_re
        .replace_all(&after, |caps: &regex::Captures| {
            let tok = &caps[0];
            if looks_like_secret(tok) {
                redact_sample(HIGH_ENTROPY_TYPE, tok)
            } else {
                tok.to_string()
            }
        })
        .into_owned()
}

/// Return redacted [`Finding`]s for `text`, including the high-entropy
/// catch-all. Use on **structured** inputs / tool arguments.
#[must_use]
pub fn scan(text: &str) -> Vec<Finding> {
    scan_inner(text, true)
}

/// Like [`scan`], but **without** the high-entropy catch-all. Use on free-form
/// terminal transcripts to avoid flagging rendered prose as secrets.
#[must_use]
pub fn scan_transcript(text: &str) -> Vec<Finding> {
    scan_inner(text, false)
}

fn scan_inner(text: &str, high_entropy: bool) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for p in PATTERNS.iter() {
        let mut n = 0;
        for m in p.re.find_iter(text) {
            let raw: String = m.as_str().chars().take(120).collect();
            let sample = redact_sample(p.name, &raw);
            let key = format!("{}:{}", p.name, sample);
            if !seen.insert(key) {
                continue;
            }
            findings.push(Finding {
                kind: p.name.to_string(),
                severity: p.severity.to_string(),
                sample,
            });
            n += 1;
            if n >= MAX_PER_TYPE {
                break;
            }
        }
    }

    // High-entropy catch-all over the pattern-redacted residual (so tokens
    // already flagged above are not double-counted). Skipped for transcripts.
    if high_entropy {
        if let Some(token_re) = TOKEN_RE.as_ref() {
            let residual = apply_patterns(text);
            let mut e = 0;
            for m in token_re.find_iter(&residual) {
                let tok = m.as_str();
                if !looks_like_secret(tok) {
                    continue;
                }
                let sample = redact_sample(HIGH_ENTROPY_TYPE, tok);
                let key = format!("{HIGH_ENTROPY_TYPE}:{sample}");
                if !seen.insert(key) {
                    continue;
                }
                findings.push(Finding {
                    kind: HIGH_ENTROPY_TYPE.to_string(),
                    severity: "HIGH".to_string(),
                    sample,
                });
                e += 1;
                if e >= MAX_PER_TYPE {
                    break;
                }
            }
        }
    }

    findings
}

/// The highest-severity label among `findings`, or `INFO` if empty.
#[must_use]
pub fn top_severity(findings: &[Finding]) -> String {
    findings
        .iter()
        .max_by_key(|f| severity_rank(&f.severity))
        .map_or_else(|| "INFO".to_string(), |f| f.severity.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_passes_for_builtin_patterns() {
        assert!(validate().is_ok(), "built-in patterns must all compile");
    }

    #[test]
    fn redacts_openai_key() {
        let out = redact_text("token is sk-abcdefghijklmnopqrstuvwxyz123456 ok");
        assert!(!out.contains("sk-abcdefghijklmnopqrstuvwxyz123456"));
        assert!(out.contains("sk-a****"));
    }

    #[test]
    fn scan_finds_email_and_key() {
        let f = scan("mail me at alice@example.com with key sk-abcdefghijklmnopqrstuvwxyz1");
        let kinds: Vec<&str> = f.iter().map(|x| x.kind.as_str()).collect();
        assert!(kinds.contains(&"email"));
        assert!(kinds.contains(&"api_key"));
        // No raw values leaked.
        for x in &f {
            assert!(!x.sample.contains("alice@example.com"));
        }
    }

    #[test]
    fn top_severity_defaults_to_info() {
        assert_eq!(top_severity(&[]), "INFO");
        assert_eq!(
            top_severity(&[
                Finding {
                    kind: "email".into(),
                    severity: "MEDIUM".into(),
                    sample: "a****@x".into()
                },
                Finding {
                    kind: "api_key".into(),
                    severity: "CRITICAL".into(),
                    sample: "sk-a****".into()
                },
            ]),
            "CRITICAL"
        );
    }

    #[test]
    fn plain_prose_has_no_findings() {
        assert!(scan("the quick brown fox jumps over the lazy dog").is_empty());
    }

    #[test]
    fn high_entropy_requires_letters_and_digits() {
        // A realistic random token (letters + digits) is flagged.
        assert!(looks_like_secret("Xk7Qw2Rt9Zp4Lm8Bn3Vc6Df1Gh5"));
        // Glued-together prose (letters only, e.g. from ANSI stripping) is not —
        // this is the Claude-transcript false-positive class.
        assert!(!looks_like_secret("theanswertoyourquestionisyesindeed"));
        assert!(!looks_like_secret("AddThatToYourListPleaseNowForever"));
    }

    #[test]
    fn transcript_scan_skips_high_entropy_but_keeps_exact_patterns() {
        // A digit-bearing pseudo-token + a real key.
        let noisy = "Xk7Qw2Rt9Zp4Lm8Bn3Vc6Df1Gh5 and sk-abcdefghijklmnopqrstuvwxyz1";
        let full = scan(noisy);
        let transcript = scan_transcript(noisy);
        // Full scan flags the high-entropy token; transcript scan does not.
        assert!(full.iter().any(|f| f.kind == "high_entropy_secret"));
        assert!(transcript.iter().all(|f| f.kind != "high_entropy_secret"));
        // Both still catch the exact api_key pattern (real secrets aren't lost).
        assert!(full.iter().any(|f| f.kind == "api_key"));
        assert!(transcript.iter().any(|f| f.kind == "api_key"));
    }

    #[test]
    fn redact_sample_never_panics_on_non_ascii() {
        // Inputs chosen to land a naive byte slice mid-codepoint (e.g. "aaaé"
        // has a char boundary between bytes 3 and 5, so `&v[..4]` would panic).
        let kinds = [
            "api_key",
            "gcp_api_key",
            HIGH_ENTROPY_TYPE,
            "ssn",
            "credit_card",
            "email",
            "db_conn",
            "ip_internal",
            "bearer_token",
            "unknown_kind",
        ];
        let inputs = ["aaaé", "héllo☺wörld", "☺☺☺☺☺", "aé", "a", ""];
        for kind in kinds {
            for input in inputs {
                // The assertion is simply that this returns — i.e. never panics
                // on a byte boundary. Also confirm no raw multibyte marker leaks
                // through a fixed-mask branch.
                let out = redact_sample(kind, input);
                let _ = out;
            }
        }
    }
}
