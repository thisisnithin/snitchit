//! Dev helper: emit a small snitchit chain to the path given as argv[1].
//!
//! Used to cross-verify snitchit's output against halo-record's own verifier
//! (brief §3). Not part of the shipped product.

use snitchit_core::clock::{new_record_id, now_rfc3339};
use snitchit_core::event::Event;
use snitchit_core::store::Store;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: emit_chain <path.jsonl>")?;
    let mut store = Store::open(&path)?;
    for cmd in ["ls -la", "cargo build", "git status"] {
        let mut ev = Event::shell_command(
            "demo-session",
            new_record_id(),
            now_rfc3339(),
            cmd,
            "some output",
            0,
        );
        store.append(&mut ev)?;
    }
    println!("wrote 3 records to {path}");
    Ok(())
}
