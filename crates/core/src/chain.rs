//! The tamper-evident hash chain (brief §3).
//!
//! Each record's `integrity.prev_hash` points at the previous record's
//! `integrity.hash`; the first record's `prev_hash` is 64 zeros. Any edit to a
//! past record changes its hash and breaks the link, which [`verify_values`]
//! detects and localizes.
//!
//! [`verify_values`] operates on the *parsed* records (as read from the JSONL
//! log), recomputing each hash via [`compute_hash`]. This is deliberately the
//! same algorithm and inputs halo-record's verifier uses, so the two agree on
//! the same file (brief §3).

use serde_json::Value;

use crate::canon::{compute_hash, GENESIS_PREV};
use crate::error::Result;
use crate::event::Event;

/// An append-only, in-memory hash chain of [`Event`]s.
///
/// The source of truth in production is the JSONL log on disk
/// ([`crate::store`]); this type is the pure, I/O-free core used to build and
/// unit-test the chain logic (brief build-order step 3).
#[derive(Debug, Default, Clone)]
pub struct Chain {
    events: Vec<Event>,
    head: Option<String>,
}

impl Chain {
    /// Create an empty chain (head = genesis).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The current chain head hash (genesis zeros if empty).
    #[must_use]
    pub fn head(&self) -> &str {
        self.head.as_deref().unwrap_or(GENESIS_PREV)
    }

    /// Number of records in the chain.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether the chain is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// All records, in order.
    #[must_use]
    pub fn events(&self) -> &[Event] {
        &self.events
    }

    /// Seal `event` against the current head and append it. Returns the new head.
    pub fn append(&mut self, mut event: Event) -> Result<String> {
        let prev = self.head().to_string();
        let hash = event.seal(&prev)?;
        self.events.push(event);
        self.head = Some(hash.clone());
        Ok(hash)
    }

    /// Verify this in-memory chain by serializing each record and recomputing.
    pub fn verify(&self) -> Result<VerifyReport> {
        let values: Vec<Value> = self
            .events
            .iter()
            .map(Event::to_value)
            .collect::<Result<Vec<_>>>()?;
        Ok(verify_values(&values))
    }
}

/// The result of verifying a chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    /// Whether the chain is fully intact.
    pub ok: bool,
    /// Number of records inspected.
    pub count: usize,
    /// The first break, if any: `(zero-based index, human-readable reason)`.
    pub broken_at: Option<(usize, String)>,
}

impl VerifyReport {
    /// A human-readable one-line summary.
    #[must_use]
    pub fn summary(&self) -> String {
        match &self.broken_at {
            None => format!(
                "intact: {} record(s), hash chain verified — tamper-evident to the head",
                self.count
            ),
            Some((i, reason)) => {
                format!("BROKEN at record {i}: {reason}")
            }
        }
    }
}

/// Verify a sequence of parsed records, recomputing the hash chain.
///
/// Reports either intact (with the count) or the exact index where the chain
/// first breaks (brief §3). Uses the same recompute-from-parsed-record algorithm
/// as halo-record's verifier so the two agree on the same file.
#[must_use]
pub fn verify_values(records: &[Value]) -> VerifyReport {
    let mut prev = GENESIS_PREV.to_string();

    for (i, rec) in records.iter().enumerate() {
        let integ = &rec["integrity"];
        let declared_prev = integ["prev_hash"].as_str();
        let declared_hash = integ["hash"].as_str();

        let (Some(declared_prev), Some(declared_hash)) = (declared_prev, declared_hash) else {
            return broken(
                i,
                records.len(),
                "record is missing integrity.prev_hash/hash",
            );
        };

        if declared_prev != prev {
            return broken(
                i,
                records.len(),
                &format!("prev_hash {declared_prev} does not match expected {prev}"),
            );
        }

        match compute_hash(rec, &prev) {
            Ok(recomputed) => {
                if declared_hash != recomputed {
                    return broken(
                        i,
                        records.len(),
                        &format!("hash {declared_hash} does not match recomputed {recomputed}"),
                    );
                }
                prev = declared_hash.to_string();
            }
            Err(e) => return broken(i, records.len(), &format!("cannot recompute hash: {e}")),
        }
    }

    VerifyReport {
        ok: true,
        count: records.len(),
        broken_at: None,
    }
}

fn broken(index: usize, count: usize, reason: &str) -> VerifyReport {
    VerifyReport {
        ok: false,
        count,
        broken_at: Some((index, reason.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;

    fn ev(cmd: &str, n: usize) -> Event {
        Event::shell_command(
            "test-session",
            format!("rec-{n}"),
            "2026-07-15T00:00:00Z".to_string(),
            cmd,
            "output",
            0,
        )
    }

    #[test]
    fn append_links_prev_hash_to_previous_hash() {
        let mut chain = Chain::new();
        assert_eq!(chain.head(), GENESIS_PREV);

        let h1 = chain.append(ev("ls", 1)).unwrap();
        assert_eq!(chain.events()[0].integrity.prev_hash, GENESIS_PREV);
        assert_eq!(chain.events()[0].integrity.hash, h1);

        let h2 = chain.append(ev("pwd", 2)).unwrap();
        assert_eq!(chain.events()[1].integrity.prev_hash, h1);
        assert_eq!(chain.events()[1].integrity.hash, h2);
        assert_eq!(chain.head(), h2);
    }

    #[test]
    fn verify_accepts_an_intact_chain() {
        let mut chain = Chain::new();
        for i in 0..5 {
            chain.append(ev(&format!("cmd-{i}"), i)).unwrap();
        }
        let report = chain.verify().unwrap();
        assert!(report.ok, "{}", report.summary());
        assert_eq!(report.count, 5);
        assert!(report.broken_at.is_none());
    }

    #[test]
    fn verify_detects_a_tampered_record() {
        let mut chain = Chain::new();
        for i in 0..4 {
            chain.append(ev(&format!("cmd-{i}"), i)).unwrap();
        }
        // Serialize, tamper with record #2's payload, then verify the values.
        let mut values: Vec<Value> = chain
            .events()
            .iter()
            .map(|e| e.to_value().unwrap())
            .collect();
        values[2]["action"]["tool"] = Value::String("evil".to_string());

        let report = verify_values(&values);
        assert!(!report.ok);
        // The tampered record's own hash no longer matches its content.
        assert_eq!(report.broken_at.as_ref().map(|(i, _)| *i), Some(2));
    }

    #[test]
    fn verify_detects_a_reordered_chain() {
        let mut chain = Chain::new();
        for i in 0..3 {
            chain.append(ev(&format!("cmd-{i}"), i)).unwrap();
        }
        let mut values: Vec<Value> = chain
            .events()
            .iter()
            .map(|e| e.to_value().unwrap())
            .collect();
        values.swap(1, 2);

        let report = verify_values(&values);
        assert!(!report.ok);
        assert_eq!(report.broken_at.as_ref().map(|(i, _)| *i), Some(1));
    }

    #[test]
    fn empty_chain_verifies() {
        let report = verify_values(&[]);
        assert!(report.ok);
        assert_eq!(report.count, 0);
    }
}
