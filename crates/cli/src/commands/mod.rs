//! Subcommand implementations and shared helpers.

pub mod hook;
pub mod install;
pub mod log;
pub mod run;
pub mod verify;
pub mod view;

use std::path::PathBuf;

use anyhow::{Context, Result};
use snitchit_core::store;

/// Resolve a session selector to a log path.
///
/// Accepts an explicit `.jsonl` path, a session id (looked up under
/// `~/.snitchit`), or `None` (the most-recently-modified session).
pub fn resolve_session(session: Option<&str>) -> Result<PathBuf> {
    match session {
        Some(s) => {
            let p = PathBuf::from(s);
            if p.exists() || p.extension().and_then(|e| e.to_str()) == Some("jsonl") {
                Ok(p)
            } else {
                store::session_path(s).context("resolving session path")
            }
        }
        None => store::latest_session()?.context(
            "no recorded sessions found under ~/.snitchit — record one with `snitchit -- <cmd>`",
        ),
    }
}
