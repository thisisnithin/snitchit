//! Claude Code hook parsing.
//!
//! Claude Code fires a configured command on each tool lifecycle event, passing
//! a JSON payload on stdin. We register on `PostToolUse` (carries both the input
//! and the result). Tool names are `PascalCase` and argument keys `snake_case`.

use serde::Deserialize;
use serde_json::Value;
use snitchit_core::event::ActionType;

use crate::{bounded_summary, exit_code_of, AgentAdapter, NormalizedCall};

impl AgentAdapter for super::Claude {
    fn parse(&self, raw: &str) -> Option<NormalizedCall> {
        let payload: ClaudeHookPayload = serde_json::from_str(raw).ok()?;
        if payload.tool_name.is_empty() {
            return None;
        }
        Some(NormalizedCall {
            kind: claude_kind(&payload.tool_name),
            input: claude_input(&payload.tool_name, &payload.tool_input),
            outcome: claude_outcome(&payload.tool_response),
            tool: payload.tool_name,
            agent_session_id: payload.session_id,
        })
    }
}

/// A Claude Code hook payload (the subset we use). Unknown fields are ignored;
/// missing fields deserialize to defaults so a shape change never panics.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ClaudeHookPayload {
    /// Claude's own session id.
    session_id: String,
    /// The tool that ran, e.g. `Bash`, `Read`, `Edit`, `WebFetch`.
    tool_name: String,
    /// Tool arguments (shape varies by tool).
    tool_input: Value,
    /// Tool result: typically `{ stdout, stderr, exit_code }` (`PostToolUse`).
    tool_response: Value,
}

/// Map a Claude tool name to a halo-record action type.
fn claude_kind(tool: &str) -> ActionType {
    match tool {
        "Read" | "Glob" | "Grep" | "NotebookRead" | "LS" => ActionType::Read,
        "Write" | "Edit" | "MultiEdit" | "NotebookEdit" => ActionType::Write,
        "WebFetch" | "WebSearch" => ActionType::Network,
        // Bash, Task, MCP tools, and anything unknown are generic tool calls.
        _ => ActionType::ToolCall,
    }
}

/// Produce a readable, bounded input summary from a tool's arguments. Never
/// includes file *contents* (only paths); those would bloat the record and are
/// covered by the outcome hash.
fn claude_input(tool: &str, input: &Value) -> String {
    let field = |key: &str| input.get(key).and_then(Value::as_str);
    let picked = match tool {
        "Bash" => field("command"),
        "Read" | "Write" | "Edit" | "MultiEdit" => field("file_path"),
        "NotebookEdit" | "NotebookRead" => field("notebook_path"),
        "WebFetch" | "WebSearch" => field("url").or_else(|| field("query")),
        "Grep" | "Glob" => field("pattern"),
        _ => None,
    };
    bounded_summary(picked, input)
}

/// Extract `(output_text, exit_code)` from a tool response, or `None` when there
/// is no response (e.g. a `PreToolUse` payload).
fn claude_outcome(resp: &Value) -> Option<(String, i32)> {
    if resp.is_null() {
        return None;
    }
    let exit = exit_code_of(resp, "exit_code");
    let text = match (resp.get("stdout"), resp.get("stderr")) {
        (None, None) => serde_json::to_string(resp).unwrap_or_default(),
        (out, err) => {
            let out = out.and_then(Value::as_str).unwrap_or("");
            let err = err.and_then(Value::as_str).unwrap_or("");
            format!("{out}{err}")
        }
    };
    Some((text, exit))
}

#[cfg(test)]
mod tests {
    use super::super::Claude;
    use crate::AgentAdapter;
    use snitchit_core::event::ActionType;

    #[test]
    fn bash_posttooluse_maps_to_tool_call_with_outcome() {
        let call = Claude
            .parse(
                r#"{"hook_event_name":"PostToolUse","session_id":"s1","tool_name":"Bash",
                    "tool_input":{"command":"curl https://example.com"},
                    "tool_response":{"stdout":"ok","stderr":"","exit_code":0}}"#,
            )
            .expect("call");
        assert_eq!(call.tool, "Bash");
        assert!(matches!(call.kind, ActionType::ToolCall));
        assert!(call.outcome.is_some());
        assert!(call.input.contains("curl https://example.com"));
    }

    #[test]
    fn read_maps_to_read_and_uses_file_path() {
        let call = Claude
            .parse(
                r#"{"hook_event_name":"PostToolUse","session_id":"s1","tool_name":"Read",
                    "tool_input":{"file_path":"/etc/hosts"},"tool_response":{}}"#,
            )
            .expect("call");
        assert!(matches!(call.kind, ActionType::Read));
        assert!(call.input.contains("/etc/hosts"));
    }

    #[test]
    fn webfetch_maps_to_network() {
        let call = Claude
            .parse(r#"{"tool_name":"WebFetch","tool_input":{"url":"https://x.com"},"tool_response":{}}"#)
            .expect("call");
        assert!(matches!(call.kind, ActionType::Network));
    }

    #[test]
    fn empty_tool_name_is_skipped() {
        assert!(Claude
            .parse(r#"{"hook_event_name":"SessionStart","session_id":"s1"}"#)
            .is_none());
    }

    #[test]
    fn secret_in_bash_command_is_redacted_in_the_final_event() {
        // Redaction happens when the caller turns a NormalizedCall into an Event
        // (see cli::commands::hook), not inside the adapter — `parse` hands back
        // the raw command verbatim.
        let call = Claude
            .parse(
                r#"{"tool_name":"Bash",
                    "tool_input":{"command":"export TOKEN=sk-abcdefghijklmnopqrstuvwxyz012345"},
                    "tool_response":{"stdout":"","stderr":"","exit_code":0}}"#,
            )
            .expect("call");
        assert!(call.input.contains("sk-abcdefghijklmnopqrstuvwxyz012345"));

        let event = snitchit_core::event::Event::agent_tool_call(
            "sess",
            "id".to_string(),
            "ts".to_string(),
            &call.tool,
            call.kind,
            &call.input,
            call.outcome.as_ref().map(|(t, c)| (t.as_str(), *c)),
        );
        let json = serde_json::to_string(&event).unwrap();
        assert!(!json.contains("sk-abcdefghijklmnopqrstuvwxyz012345"));
    }
}
