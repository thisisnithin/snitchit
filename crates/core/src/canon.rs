//! RFC 8785 (JSON Canonicalization Scheme) + SHA-256 — the integrity primitive.
//!
//! This is a faithful port of halo-record's `canon.py` so that a chain snitchit
//! writes verifies byte-for-byte against halo-record's own verifier (brief §3).
//! Canonicalization operates on a parsed [`serde_json::Value`] — exactly as the
//! Python reference operates on a parsed `dict` — which guarantees the two
//! implementations produce identical bytes for identical inputs.
//!
//! Scope note — numbers: like the reference, only integer-valued numbers are
//! supported. Records emitted by snitchit use strings and integers only, so this
//! covers every real record. Full RFC 8785 floating-point formatting (the ECMA
//! `Number.prototype.toString` shortest-round-trip algorithm) is intentionally
//! out of scope; a fractional float is a hard error rather than a silent
//! mis-hash. See `// TODO(format)` below.

use std::fmt::Write as _;

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::{CoreError, Result};

/// The genesis `prev_hash`: 64 zero hex characters (brief §3).
pub const GENESIS_PREV: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Return the RFC 8785 canonical JSON serialization of `value`.
pub fn canon(value: &Value) -> Result<String> {
    let mut out = String::new();
    write_canon(value, &mut out)?;
    Ok(out)
}

fn write_canon(value: &Value, out: &mut String) -> Result<()> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::String(s) => canon_string(s, out),
        Value::Number(n) => out.push_str(&canon_number(n)?),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canon(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            // RFC 8785: sort members by the UTF-16 code units of their keys.
            // Big-endian u16 comparison == numeric u16 comparison, matching the
            // reference's `utf-16-be` byte sort.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canon_string(key, out);
                out.push(':');
                // Key came from `map`, so the lookup cannot miss.
                if let Some(v) = map.get(*key) {
                    write_canon(v, out)?;
                }
            }
            out.push('}');
        }
    }
    Ok(())
}

/// Escape a string per RFC 8785 §3.2.2.2 (identical to the reference).
fn canon_string(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{000C}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                // `write!` to a String is infallible.
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Format a number per the reference's integer-only subset.
fn canon_number(n: &serde_json::Number) -> Result<String> {
    if let Some(i) = n.as_i64() {
        return Ok(i.to_string());
    }
    if let Some(u) = n.as_u64() {
        return Ok(u.to_string());
    }
    if let Some(f) = n.as_f64() {
        if !f.is_finite() {
            return Err(CoreError::Canon(
                "non-finite number is not valid JSON".to_string(),
            ));
        }
        // Integer-valued float (e.g. `1.0`) -> integer text.
        if f.fract() == 0.0 && f.abs() < 9_007_199_254_740_992.0 {
            #[allow(clippy::cast_possible_truncation)]
            return Ok((f as i64).to_string());
        }
        // TODO(format): full RFC 8785 float formatting is out of scope, matching
        // halo-record. snitchit records never contain fractional floats.
        return Err(CoreError::Canon(format!(
            "non-integer float {f}: full RFC 8785 number formatting is out of scope; \
             the record format uses integer-valued numbers only"
        )));
    }
    Err(CoreError::Canon(format!("cannot canonicalize number {n}")))
}

/// Lowercase SHA-256 hex digest of `text` (UTF-8 bytes).
#[must_use]
pub fn sha256_hex(text: &str) -> String {
    let digest = Sha256::digest(text.as_bytes());
    hex::encode(digest)
}

/// `"sha256:"` + SHA-256 of the canonical form of `value`.
///
/// Used to store tool inputs/outputs as hashes rather than raw values
/// (redaction rule, brief §3). Falls back to a stable sorted-key serialization
/// if the value is not strictly canonicalizable, so a recorder never fails on an
/// odd input (mirrors the reference's `input_hash`).
#[must_use]
pub fn input_hash(value: &Value) -> String {
    let canonical =
        canon(value).unwrap_or_else(|_| serde_json::to_string(value).unwrap_or_default());
    format!("sha256:{}", sha256_hex(&canonical))
}

/// Compute a record's `integrity.hash`.
///
/// Follows the reference exactly: on a clone of `record`, set
/// `integrity.prev_hash = prev_hash`, drop `integrity.hash` (leaving `alg` and
/// `canon`), canonicalize per RFC 8785, and return the lowercase SHA-256 hex.
pub fn compute_hash(record: &Value, prev_hash: &str) -> Result<String> {
    let mut clone = record.clone();
    let integ = clone
        .as_object_mut()
        .ok_or_else(|| CoreError::Canon("record is not a JSON object".to_string()))?
        .entry("integrity")
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    let integ = integ
        .as_object_mut()
        .ok_or_else(|| CoreError::Canon("integrity is not a JSON object".to_string()))?;
    integ.insert(
        "prev_hash".to_string(),
        Value::String(prev_hash.to_string()),
    );
    integ.remove("hash");
    Ok(sha256_hex(&canon(&clone)?))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    // --- RFC 8785 conformance vectors (the subset our format uses) -----------

    #[test]
    fn literals() {
        assert_eq!(canon(&json!(null)).unwrap(), "null");
        assert_eq!(canon(&json!(true)).unwrap(), "true");
        assert_eq!(canon(&json!(false)).unwrap(), "false");
    }

    #[test]
    fn integers() {
        assert_eq!(canon(&json!(0)).unwrap(), "0");
        assert_eq!(canon(&json!(-42)).unwrap(), "-42");
        assert_eq!(canon(&json!(1_000_000)).unwrap(), "1000000");
        // Integer-valued float normalizes to integer text.
        assert_eq!(canon(&json!(1.0)).unwrap(), "1");
    }

    #[test]
    fn fractional_float_is_rejected() {
        assert!(canon(&json!(1.5)).is_err());
    }

    #[test]
    fn string_escaping() {
        // RFC 8785 control/quote/backslash escaping.
        assert_eq!(canon(&json!("a\"b\\c")).unwrap(), r#""a\"b\\c""#);
        assert_eq!(canon(&json!("\t\n\r")).unwrap(), r#""\t\n\r""#);
        // Control chars U+0000 and U+001F escape as lowercase \uXXXX.
        let ctrl = format!("{}{}", '\u{0000}', '\u{001f}');
        assert_eq!(canon(&Value::String(ctrl)).unwrap(), "\"\\u0000\\u001f\"");
        // Non-ASCII passes through literally (UTF-8), not \u-escaped.
        assert_eq!(canon(&json!("cafe\u{301}")).unwrap(), "\"cafe\u{301}\"");
    }

    #[test]
    fn object_keys_sorted_by_utf16() {
        // Keys sort by UTF-16 code units: 'a' (0x61) < 'e-acute' < euro sign.
        let v = json!({ "\u{20ac}": 1, "\u{e9}": 2, "a": 3 });
        let c = canon(&v).unwrap();
        assert!(c.starts_with("{\"a\":3,"));
        assert!(c.ends_with(",\"\u{20ac}\":1}"));
    }

    #[test]
    fn nested_structure_is_stable() {
        let a = json!({ "b": [1, 2, { "z": 1, "a": 2 }], "a": "x" });
        assert_eq!(canon(&a).unwrap(), r#"{"a":"x","b":[1,2,{"a":2,"z":1}]}"#);
    }

    #[test]
    fn sha256_is_lowercase_hex() {
        // Known SHA-256 of the empty string.
        assert_eq!(
            sha256_hex(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn compute_hash_ignores_own_hash_field() {
        let mut rec = json!({
            "a": 1,
            "integrity": { "alg": "sha-256", "canon": "rfc8785", "prev_hash": "x", "hash": "old" }
        });
        let h1 = compute_hash(&rec, GENESIS_PREV).unwrap();
        // Mutating the stored hash must not change the recomputed hash.
        rec["integrity"]["hash"] = json!("tampered");
        let h2 = compute_hash(&rec, GENESIS_PREV).unwrap();
        assert_eq!(h1, h2);
        // But changing a real field must change the hash.
        rec["a"] = json!(2);
        assert_ne!(h1, compute_hash(&rec, GENESIS_PREV).unwrap());
    }
}
