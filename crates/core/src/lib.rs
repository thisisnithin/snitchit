//! `snitchit-core` — the shared, platform-agnostic heart of snitchit.
//!
//! This crate owns everything valuable and portable:
//!
//! - [`Event`] — the canonical record type, mirroring halo-record's Schema v0.1.
//! - [`canon`] — RFC 8785 (JCS) canonicalization + SHA-256, byte-compatible with
//!   halo-record so chains interoperate with its verifier (brief §3).
//! - [`chain`] — the tamper-evident hash chain: append, verify, localize breaks.
//! - [`store`] — the hash-chained JSONL log under `~/.snitchit/` (brief §2, §4).
//! - [`redact`] — secret/PII detection so raw inputs never enter a record.
//! - [`EventSource`] / [`EventSink`] — the one seam collectors implement (§4).
//!
//! No platform-specific behavior lives here: the only `#[cfg]` is compile-time
//! Unix filesystem hardening in [`store`]. Collectors (PTY, hooks, future kernel
//! sources) depend on this crate and fulfill [`EventSource`]; the dependency
//! arrow never points back.

pub mod canon;
pub mod chain;
pub mod clock;
pub mod error;
pub mod event;
pub mod redact;
pub mod source;
pub mod store;

pub use chain::{verify_values, Chain, VerifyReport};
pub use error::{CoreError, Result};
pub use event::{
    Action, ActionType, Agent, Capture, Category, Event, Integrity, Outcome, Payload, Source,
    Status, SCHEMA_VERSION,
};
pub use source::{channel, EventSink, EventSource, EventStream};
pub use store::Store;
