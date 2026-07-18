//! Dev helper: emit a deliberately varied sample session for previewing the
//! `snitchit view` UI without recording a real agent.
//!
//! Not part of the shipped product. Regenerates `fixtures/sample-session.jsonl`:
//!
//! ```sh
//! cargo run -p snitchit-core --example emit_sample -- fixtures/sample-session.jsonl
//! snitchit view --session fixtures/sample-session.jsonl
//! ```
//!
//! The records are hand-built (not scanned from real input) purely so the
//! preview exercises every UI element at once: both sources (`pty`/`hook`),
//! every `action.type`, every `outcome.status` (incl. `denied`, which the real
//! build path never emits), every severity, and records with/without findings.
//! Everything is deterministic (fixed ids/timestamps) so re-running produces a
//! byte-identical file. `Store::append` seals a real, intact hash chain over
//! them, so the integrity banner shows "intact".

// Dev-only example: the helpers below always return `Some(..)` for call-site
// readability, and the sample-data builder is deliberately one long literal —
// both are fine here in a non-shipped generator.
#![allow(clippy::unnecessary_wraps, clippy::too_many_lines)]

use std::fmt::Write as _;

use snitchit_core::event::{
    Action, ActionType, Agent, Capture, Category, Outcome, Payload, Source,
};
use snitchit_core::{Event, Integrity, Status, Store, SCHEMA_VERSION};

/// A plausible-looking but fake `sha256:` digest for display only (the viewer
/// shows whatever hash is in the record; these records aren't derived from real
/// values). Varying `seed` keeps them visually distinct.
fn fake_hash(seed: &str) -> String {
    let mut h = String::from("sha256:");
    let bytes = seed.as_bytes();
    for i in 0u8..32 {
        let b = bytes[usize::from(i) % bytes.len()].wrapping_add(i);
        let _ = write!(h, "{b:02x}");
    }
    h
}

fn payload(summary: &str, seed: &str) -> Option<Payload> {
    Some(Payload {
        summary: Some(summary.to_string()),
        hash: Some(fake_hash(seed)),
    })
}

fn outcome(status: Status, summary: &str, seed: &str) -> Option<Outcome> {
    Some(Outcome {
        status,
        summary: Some(summary.to_string()),
        hash: Some(fake_hash(seed)),
    })
}

fn source(adapter: &str, via: &str) -> Option<Source> {
    Some(Source {
        adapter: adapter.to_string(),
        via: via.to_string(),
        capture: Capture::Captured,
    })
}

/// Build one record. `integrity` is left default; `Store::append` seals it.
#[allow(clippy::too_many_arguments)]
fn record(
    id: &str,
    ts: &str,
    agent: Option<Agent>,
    source: Option<Source>,
    kind: ActionType,
    category: Category,
    tool: Option<&str>,
    input: Option<Payload>,
    outcome: Option<Outcome>,
    findings: Vec<snitchit_core::event::Finding>,
    severity: &str,
) -> Event {
    Event {
        schema_version: SCHEMA_VERSION.to_string(),
        record_id: id.to_string(),
        session_id: "sample-session".to_string(),
        ts: ts.to_string(),
        parent_id: None,
        agent,
        source,
        action: Action {
            kind,
            category,
            tool: tool.map(str::to_string),
            input,
        },
        outcome,
        findings,
        severity: severity.to_string(),
        integrity: Integrity::default(),
    }
}

fn finding(kind: &str, severity: &str, sample: &str) -> snitchit_core::event::Finding {
    snitchit_core::event::Finding {
        kind: kind.to_string(),
        severity: severity.to_string(),
        sample: sample.to_string(),
    }
}

fn claude() -> Option<Agent> {
    Some(Agent {
        id: "claude-code".to_string(),
        name: "Claude Code".to_string(),
        version: Some("1.0.0".to_string()),
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: emit_sample <path.jsonl>")?;
    // Fresh file so the chain starts at genesis and the output is deterministic.
    let _ = std::fs::remove_file(&path);
    let mut store = Store::open(&path)?;

    let events = vec![
        // 1. PTY: the process invocation. tool_call / ok / no findings.
        record(
            "rec-01-process",
            "2026-07-15T16:40:00Z",
            None,
            source("pty", "snitchit PTY wrapper"),
            ActionType::ToolCall,
            Category::Security,
            Some("claude"),
            payload("claude --model opus", "proc"),
            outcome(Status::Ok, "exit 0: 20194 bytes, 512 line(s)", "proco"),
            vec![],
            "INFO",
        ),
        // 2. PTY: a typed terminal-input line. No outcome (a PTY can't attribute
        //    a per-line exit code).
        record(
            "rec-02-input",
            "2026-07-15T16:40:05Z",
            None,
            source("pty", "snitchit PTY wrapper"),
            ActionType::ToolCall,
            Category::Security,
            Some("terminal-input"),
            payload("please add a health check endpoint", "input"),
            None,
            vec![],
            "INFO",
        ),
        // 3. Hook: a plain file read. read / ok / no findings.
        record(
            "rec-03-read",
            "2026-07-15T16:40:11Z",
            claude(),
            source("hook", "agent hook"),
            ActionType::Read,
            Category::Privacy,
            Some("Read"),
            payload("read src/main.rs", "read"),
            outcome(Status::Ok, "exit 0: 1432 bytes, 40 line(s)", "reado"),
            vec![],
            "INFO",
        ),
        // 4. Hook: reading a .env — flagged, CRITICAL finding.
        record(
            "rec-04-env",
            "2026-07-15T16:40:18Z",
            claude(),
            source("hook", "agent hook"),
            ActionType::Read,
            Category::Privacy,
            Some("Read"),
            payload("read /app/.env", "env"),
            outcome(Status::Ok, "exit 0: 312 bytes, 9 line(s)", "envo"),
            vec![finding("api_key", "CRITICAL", "sk-a****")],
            "CRITICAL",
        ),
        // 5. Hook: a file write. write / ok / a LOW finding (shows the LOW pill,
        //    which the real scanner's patterns don't currently produce).
        record(
            "rec-05-write",
            "2026-07-15T16:40:25Z",
            claude(),
            source("hook", "agent hook"),
            ActionType::Write,
            Category::Safety,
            Some("Write"),
            payload("write config/app.toml", "write"),
            outcome(Status::Ok, "exit 0: 0 bytes, 0 line(s)", "writeo"),
            vec![finding("ip_internal", "LOW", "192.168.*.*")],
            "LOW",
        ),
        // 6. Hook: a web fetch that errored. network / error / MEDIUM finding.
        record(
            "rec-06-fetch",
            "2026-07-15T16:40:33Z",
            claude(),
            source("hook", "agent hook"),
            ActionType::Network,
            Category::Security,
            Some("WebFetch"),
            payload("GET https://api.example.com/v1/users", "fetch"),
            outcome(Status::Error, "exit 1: 88 bytes, 2 line(s)", "fetcho"),
            vec![finding("email", "MEDIUM", "a****@example.com")],
            "MEDIUM",
        ),
        // 7. Hook: a bash command that was denied by policy. tool_call / denied /
        //    HIGH finding.
        record(
            "rec-07-bash",
            "2026-07-15T16:40:41Z",
            claude(),
            source("hook", "agent hook"),
            ActionType::ToolCall,
            Category::Security,
            Some("Bash"),
            payload("curl -H 'Authorization: Bearer ****' https://x", "bash"),
            outcome(Status::Denied, "denied by policy", "basho"),
            vec![finding("bearer_token", "HIGH", "Bearer ****")],
            "HIGH",
        ),
        // 8. Hook: an agent message. agent_message / no tool / no outcome.
        record(
            "rec-08-msg",
            "2026-07-15T16:40:48Z",
            claude(),
            source("hook", "agent hook"),
            ActionType::AgentMessage,
            Category::Reliability,
            None,
            payload("I've added the endpoint and a test for it.", "msg"),
            None,
            vec![],
            "INFO",
        ),
    ];

    let n = events.len();
    for mut ev in events {
        store.append(&mut ev)?;
    }
    println!("wrote {n} sample records to {path}");

    // Also emit a tampered sibling (`*-broken.jsonl`) so the BROKEN integrity
    // banner can be previewed too: take the sealed good chain and alter one
    // record's content without re-sealing, so its stored hash no longer matches
    // — exactly what `verify` is meant to catch.
    let broken_path = path.replace(".jsonl", "-broken.jsonl");
    let good = std::fs::read_to_string(&path)?;
    let tampered = good.replacen("read /app/.env", "read /app/.ENV", 1);
    if tampered == good {
        return Err("could not find the record to tamper for the broken fixture".into());
    }
    std::fs::write(&broken_path, tampered)?;
    println!("wrote a tampered variant to {broken_path}");
    Ok(())
}
