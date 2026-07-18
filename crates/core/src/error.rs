//! Error types for the core crate.
//!
//! Every fallible operation in `snitchit-core` returns [`Result`] with one of
//! these variants. Libraries never `panic!`/`unwrap` on runtime-reachable paths
//! (brief §8.3); the binary decides how to report them.

use thiserror::Error;

/// Errors produced by canonicalization, hashing, the chain, and the store.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CoreError {
    /// A value could not be canonicalized per RFC 8785 (JCS).
    #[error("canonicalization failed: {0}")]
    Canon(String),

    /// The hash chain did not verify; carries a human-readable location.
    #[error("chain broken at record {index}: {reason}")]
    ChainBroken {
        /// Zero-based index of the offending record.
        index: usize,
        /// Why the chain failed at this record.
        reason: String,
    },

    /// A record on disk was not valid JSON.
    #[error("record {index}: not valid JSON: {source}")]
    RecordJson {
        /// Zero-based index (line number - 1) of the offending record.
        index: usize,
        /// The underlying serde error.
        source: serde_json::Error,
    },

    /// Serialization/deserialization of a record failed.
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),

    /// An I/O error while reading or appending the log.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// An error surfaced by an [`EventSource`](crate::EventSource) across the
    /// seam. Carries a message so the core need not depend on any collector.
    #[error("event source error: {0}")]
    Source(String),

    /// A built-in redaction pattern failed to compile. Surfaced by
    /// [`redact::validate`](crate::redact::validate) at startup so a broken build
    /// fails fast rather than silently skipping secret detection.
    #[error("redaction unavailable: {0}")]
    Redaction(String),
}

/// Convenience alias for results in this crate.
pub type Result<T> = std::result::Result<T, CoreError>;
