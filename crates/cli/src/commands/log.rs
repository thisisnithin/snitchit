//! `snitchit log` — render a session's recorded timeline.
//!
//! Rendering must not claim more fidelity than the source actually delivered
//! (brief item 3): a PTY-sourced event is the **terminal surface** — a raw
//! process invocation or literal typed input, never a resolved, executed tool
//! call — while a hook-sourced event genuinely is a resolved tool call the
//! agent made. The stored `action.type` is `tool_call` for both (halo-record's
//! schema has no separate "process invocation" bucket, and matching that
//! schema is what makes our chains verify under halo-record's own verifier —
//! see the interop test), but the label/prefixes shown here are chosen per
//! source so a PTY line never reads as if it were a parsed shell command or a
//! resolved tool result.

use std::path::Path;

use anyhow::{Context, Result};
use snitchit_core::event::{ActionType, Event, Status};
use snitchit_core::store;

/// Render the recorded events of the log at `path` as a readable timeline.
pub fn log(path: &Path) -> Result<()> {
    let mut events =
        store::read_events(path).with_context(|| format!("reading log {}", path.display()))?;

    if events.is_empty() {
        println!("no events recorded in {}", path.display());
        return Ok(());
    }

    // Render in chronological order. On-disk order is *append* order, which is
    // not chronological: PTY/kernel events are buffered and flushed at session
    // end, while hook events are written live by separate processes during the
    // session — so a typed prompt can land after the tool calls it caused. The
    // hash chain is verified over on-disk order elsewhere (`verify`); this sort
    // is display-only. `ts` is RFC 3339 UTC, so lexicographic == chronological,
    // and the stable sort keeps append order for equal timestamps.
    events.sort_by(|a, b| a.ts.cmp(&b.ts));

    println!("session: {}", path.display());
    println!("{} event(s)\n", events.len());

    for (i, ev) in events.iter().enumerate() {
        render(i, ev);
    }
    Ok(())
}

fn render(index: usize, ev: &Event) {
    let source = ev.source.as_ref().map_or("?", |s| s.adapter.as_str());
    let tool = ev.action.tool.as_deref().unwrap_or("-");

    println!(
        "[{index}] {ts}  {source}/{kind}  {tool}",
        ts = ev.ts,
        kind = display_kind(ev),
    );

    if let Some(input) = &ev.action.input {
        if let Some(summary) = &input.summary {
            println!("     {}:  {summary}", input_label(ev));
        }
    }
    if let Some(outcome) = &ev.outcome {
        let status = status_str(outcome.status);
        let label = outcome_label(ev);
        match &outcome.summary {
            Some(summary) => println!("     {label}: [{status}] {summary}"),
            None => println!("     {label}: [{status}]"),
        }
    }
    if !ev.findings.is_empty() {
        println!(
            "     findings: {} (top severity {})",
            ev.findings.len(),
            ev.severity
        );
    }
    println!();
}

/// Whether `ev` came from the PTY collector — the terminal surface, not a
/// resolved tool call (see the module doc).
fn is_pty_sourced(ev: &Event) -> bool {
    ev.source.as_ref().is_some_and(|s| s.adapter == "pty")
}

/// Whether `ev` is the PTY collector's heuristic typed-input segmentation
/// (`Event::command_submitted`), as opposed to its process-invocation record.
fn is_terminal_input(ev: &Event) -> bool {
    ev.action.tool.as_deref() == Some("terminal-input")
}

/// The displayed `kind` word. Hook-sourced events show the literal stored
/// schema kind (`tool_call`/`read`/`write`/`network`/`agent_message`) — that's
/// what they genuinely are. PTY-sourced events are relabeled so the closed
/// schema value (always `tool_call` for these — see the module doc) never
/// reads as "a tool was called": a process invocation is labeled `process`,
/// literal typed input is labeled `terminal-input`.
fn display_kind(ev: &Event) -> &'static str {
    if is_pty_sourced(ev) {
        if is_terminal_input(ev) {
            "terminal-input"
        } else {
            "process"
        }
    } else {
        action_kind(ev.action.kind)
    }
}

/// The prefix before the recorded input summary. PTY-sourced: `typed` for
/// literal terminal input, `invoked` for a process invocation (its argv, not a
/// resolved/validated command). Hook-sourced: `in`, since that genuinely is a
/// tool's input arguments.
fn input_label(ev: &Event) -> &'static str {
    if is_pty_sourced(ev) {
        if is_terminal_input(ev) {
            "typed"
        } else {
            "invoked"
        }
    } else {
        "in"
    }
}

/// The prefix before the recorded outcome summary. PTY-sourced: `transcript`
/// — it's the raw (redacted) terminal byte stream, not a structured tool
/// result. Hook-sourced: `out`, a genuine tool result.
fn outcome_label(ev: &Event) -> &'static str {
    if is_pty_sourced(ev) {
        "transcript"
    } else {
        "out"
    }
}

fn action_kind(kind: ActionType) -> &'static str {
    match kind {
        ActionType::ToolCall => "tool_call",
        ActionType::AgentMessage => "agent_message",
        ActionType::Read => "read",
        ActionType::Write => "write",
        ActionType::Network => "network",
    }
}

fn status_str(status: Status) -> &'static str {
    match status {
        Status::Ok => "ok",
        Status::Error => "error",
        Status::Denied => "denied",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snitchit_core::event::Event;

    fn pty_process() -> Event {
        Event::process_run(
            "s",
            "id".to_string(),
            "t".to_string(),
            "opencode",
            "opencode --help",
            "usage: ...",
            0,
        )
    }

    fn pty_input() -> Event {
        Event::command_submitted("s", "id".to_string(), "t".to_string(), "list files")
    }

    fn hook_call() -> Event {
        Event::agent_tool_call(
            "s",
            "id".to_string(),
            "t".to_string(),
            "Bash",
            ActionType::ToolCall,
            "ls -la",
            Some(("total 0", 0)),
        )
    }

    #[test]
    fn pty_process_invocation_is_never_labeled_as_a_tool_call() {
        // The exact confusion this fixes: a bare program name next to
        // "tool_call" reads as "this tool was invoked", when it's really just
        // the process snitchit launched.
        let ev = pty_process();
        assert_eq!(display_kind(&ev), "process");
        assert_ne!(display_kind(&ev), "tool_call");
        assert_eq!(input_label(&ev), "invoked");
        assert_eq!(outcome_label(&ev), "transcript");
    }

    #[test]
    fn pty_terminal_input_is_labeled_as_typed_not_a_command() {
        let ev = pty_input();
        assert_eq!(display_kind(&ev), "terminal-input");
        assert_eq!(input_label(&ev), "typed");
    }

    #[test]
    fn hook_sourced_tool_call_keeps_the_literal_schema_kind() {
        // A hook event genuinely is a resolved tool call — no relabeling.
        let ev = hook_call();
        assert_eq!(display_kind(&ev), "tool_call");
        assert_eq!(input_label(&ev), "in");
        assert_eq!(outcome_label(&ev), "out");
    }
}
