//! `snitchit-collectors` — event collectors, each an [`EventSource`].
//!
//! Collectors depend on `snitchit-core` and fulfill its [`EventSource`] contract;
//! the dependency arrow never points back (brief §4). Every collector lives under
//! [`sources`] (one module per tier); shared support (the error type) stays at the
//! crate root. Public types are re-exported here so callers use short paths
//! (`snitchit_collectors::PtyCollector`, `::KernelCollector`, …).
//!
//! [`EventSource`]: snitchit_core::EventSource

pub mod error;
pub mod sources;

pub use error::{CollectorError, Result};
pub use sources::pty::{self, PtyCollector};

#[cfg(target_os = "linux")]
pub use sources::kernel::{self, KernelCollector};

#[cfg(target_os = "macos")]
pub use sources::endpoint_security::{self, EndpointSecurityCollector};

#[cfg(target_os = "macos")]
pub use sources::macos_connect::{self, MacosConnectCollector};
