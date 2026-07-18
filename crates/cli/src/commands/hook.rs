//! `snitchit hook` — ingest one agent hook payload (JSON on stdin).
//!
//! Registered into the agent's config by `install`; the agent runs it on
//! every tool use. **Observe-only:** this must never interfere with the agent, so
//! `main` always exits 0 regardless of what happens here (a non-zero exit — 2 in
//! particular — would block the tool). Every step is therefore best-effort.
//!
//! Agent-agnostic by design: `--agent <id>` selects an agent from the
//! [`snitchit_agents`] registry, whose adapter does all the payload parsing.
//! This module only resolves the target session and appends — it never branches
//! on which agent is talking to it.
//!
//! Session correlation: when the agent was launched via `snitchit -- <agent>`,
//! that process exports `SNITCHIT_LOG` (and `SNITCHIT_SESSION`), which the agent
//! and this hook child inherit — so hook events land in the *same* chain as the
//! PTY events. Run standalone (no env), it falls back to a per-agent-session log
//! keyed by the payload's `session_id`.

use std::io::Read;
use std::path::PathBuf;

use snitchit_agents::by_id;
use snitchit_core::clock::{new_record_id, now_rfc3339};
use snitchit_core::event::Event;
use snitchit_core::store::{self, Store};

/// Read a hook payload from stdin (in `agent`'s format) and append a normalized
/// event.
///
/// Infallible by design: every step is best-effort and any problem just returns,
/// so the caller can unconditionally exit 0 and never interfere with the agent.
pub fn run(agent: &str) {
    let mut buf = String::new();
    if std::io::stdin().read_to_string(&mut buf).is_err() || buf.trim().is_empty() {
        return;
    }

    let Some(adapter) = by_id(agent) else {
        return; // unregistered agent id — nothing to do
    };
    let Some(call) = adapter.parse(&buf) else {
        return; // not a tool event this adapter records
    };
    let Some((log_path, session_label)) = target(&call.agent_session_id) else {
        return;
    };

    let mut event = Event::agent_tool_call(
        &session_label,
        new_record_id(),
        now_rfc3339(),
        &call.tool,
        call.kind,
        &call.input,
        call.outcome
            .as_ref()
            .map(|(text, code)| (text.as_str(), *code)),
    );
    append(&log_path, &mut event);
}

/// Append under the store's cross-process lock. Ignore errors (observe-only).
fn append(log_path: &std::path::Path, event: &mut Event) {
    if let Ok(mut store) = Store::open(log_path) {
        let _ = store.append(event);
    }
}

/// Resolve `(log path, session label)`:
/// - inside a `snitchit -- <agent>` session: the inherited `SNITCHIT_LOG` /
///   `SNITCHIT_SESSION`;
/// - standalone: a log keyed by the agent's own `session_id`.
fn target(agent_session_id: &str) -> Option<(PathBuf, String)> {
    if let Some(log) = std::env::var_os("SNITCHIT_LOG") {
        if !log.is_empty() {
            let label = std::env::var("SNITCHIT_SESSION")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| agent_session_id.to_string());
            return Some((PathBuf::from(log), label));
        }
    }
    // Standalone fallback: derive a session from the agent's session id.
    let sid = if agent_session_id.is_empty() {
        "hook".to_string()
    } else {
        format!("agent-{agent_session_id}")
    };
    let path = store::session_path(&sid).ok()?;
    Some((path, sid))
}
