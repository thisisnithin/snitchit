//! Error types for collectors.

use thiserror::Error;

/// Errors a collector can produce while setting up or running.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CollectorError {
    /// No command was given to wrap.
    #[error("no command given to wrap")]
    EmptyCommand,

    /// The target program could not be resolved to an executable on PATH.
    #[error("command not found on PATH: {0}")]
    NotFound(String),

    /// A PTY-layer failure (allocate, spawn, read/write).
    #[error("pty error: {0}")]
    Pty(String),

    /// An I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// An error bubbling up from the core.
    #[error(transparent)]
    Core(#[from] snitchit_core::CoreError),
}

/// Convenience alias for collector results.
pub type Result<T> = std::result::Result<T, CollectorError>;
