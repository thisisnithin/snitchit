//! Event sources — the collectors, one per tier. Every submodule here is an
//! [`EventSource`](snitchit_core::EventSource) implementation and nothing else
//! lives here; shared support (errors) stays at the crate root.
//!
//! * [`pty`] — tier 1, the terminal surface (no privilege).
//! * [`kernel`] — tier 3, kernel observation via eBPF (Linux, needs privilege).
//! * [`endpoint_security`] — tier 3, kernel observation via Apple Endpoint
//!   Security (macOS, needs privilege). The macOS counterpart to [`kernel`]'s
//!   *exec* capture; the factory picks one by `#[cfg(target_os)]`, never at
//!   runtime.
//! * [`macos_connect`] — tier 3, outbound-connection capture on macOS via
//!   socket-table polling. The counterpart to [`kernel`]'s *connect* capture,
//!   split out because macOS observes exec and connect through different
//!   mechanisms (see the module docs for why, and the fidelity limits).
//!
//! [`netfmt`] holds the one piece of pure logic shared by the two connect
//! backends (destination `host:port` formatting), so their records stay
//! byte-identical.
//!
//! Tier 2 (agent hooks) is not a live source: it's a one-shot parse invoked by
//! `snitchit hook`, so its per-agent code lives in the `snitchit-agents` crate
//! alongside each agent's install wiring, not here.

pub mod pty;

pub(crate) mod netfmt;

#[cfg(target_os = "linux")]
pub mod kernel;

#[cfg(target_os = "macos")]
pub mod endpoint_security;

#[cfg(target_os = "macos")]
pub mod macos_connect;
