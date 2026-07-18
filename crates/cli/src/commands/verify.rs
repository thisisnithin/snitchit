//! `snitchit verify` — walk the chain and report intact / where it breaks.

use std::path::Path;

use anyhow::{Context, Result};
use snitchit_core::{store, verify_values};

/// Verify the log at `path`. Returns whether the chain is intact.
pub fn verify(path: &Path) -> Result<bool> {
    let values =
        store::read_values(path).with_context(|| format!("reading log {}", path.display()))?;
    let report = verify_values(&values);
    println!("{}: {}", path.display(), report.summary());
    Ok(report.ok)
}
