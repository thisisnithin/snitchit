//! Record identity and timestamps.
//!
//! Kept in the core so every collector stamps records identically: `UUIDv4`
//! `record_id`s and RFC 3339 UTC `ts` values (halo-record's fields, brief §3).

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

/// A fresh `UUIDv4` record id.
#[must_use]
pub fn new_record_id() -> String {
    Uuid::new_v4().to_string()
}

/// The current time as an RFC 3339 UTC string, e.g. `2026-07-15T12:34:56.789Z`.
///
/// Falls back to the Unix epoch if formatting somehow fails, so a recorder never
/// panics on a clock edge (observe-only, brief §8.3).
#[must_use]
pub fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique() {
        assert_ne!(new_record_id(), new_record_id());
    }

    #[test]
    fn timestamp_is_rfc3339_and_utc() {
        let ts = now_rfc3339();
        assert!(OffsetDateTime::parse(&ts, &Rfc3339).is_ok());
        assert!(ts.ends_with('Z') || ts.contains('+'));
    }
}
