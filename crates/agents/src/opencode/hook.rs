//! `OpenCode` hook parsing.
//!
//! `OpenCode` has no "run a command" hook; it loads JS/TS plugins that receive
//! `tool.execute.after(input, output)`. Our generated plugin (see [`install`])
//! forwards each call as JSON to `snitchit hook --agent opencode` with the
//! fields below. Tool names are lowercase and argument keys camelCase.

use serde::Deserialize;
use serde_json::Value;
use snitchit_core::event::ActionType;

use crate::{bounded_summary, AgentAdapter, NormalizedCall};

impl AgentAdapter for super::OpenCode {
    fn parse(&self, raw: &str) -> Option<NormalizedCall> {
        let payload: OpencodeHookPayload = serde_json::from_str(raw).ok()?;
        if payload.tool.is_empty() {
            return None;
        }
        Some(NormalizedCall {
            kind: opencode_kind(&payload.tool),
            input: opencode_input(&payload.tool, &payload.args),
            outcome: opencode_outcome(&payload.result),
            tool: payload.tool,
            agent_session_id: payload.session_id,
        })
    }
}

/// An `OpenCode` tool-call payload, as emitted by snitchit's generated plugin.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct OpencodeHookPayload {
    /// Tool name, e.g. `bash`, `edit`, `read`, `webfetch`.
    tool: String,
    /// `OpenCode` session id.
    session_id: String,
    /// Tool arguments (`output.args`).
    args: Value,
    /// Tool result (`output`), shape varies by tool.
    result: Value,
}

fn opencode_kind(tool: &str) -> ActionType {
    match tool {
        "read" | "glob" | "grep" | "list" | "ls" => ActionType::Read,
        "write" | "edit" | "multiedit" | "patch" => ActionType::Write,
        "webfetch" | "websearch" => ActionType::Network,
        // bash, task, todowrite, MCP tools, unknown → generic tool call.
        _ => ActionType::ToolCall,
    }
}

fn opencode_input(tool: &str, args: &Value) -> String {
    let field = |key: &str| args.get(key).and_then(Value::as_str);
    let picked = match tool {
        "bash" => field("command"),
        "read" | "write" | "edit" | "multiedit" | "patch" => {
            field("filePath").or_else(|| field("file_path"))
        }
        "webfetch" | "websearch" => field("url").or_else(|| field("query")),
        "grep" | "glob" => field("pattern"),
        _ => None,
    };
    bounded_summary(picked, args)
}

fn opencode_outcome(result: &Value) -> Option<(String, i32)> {
    if result.is_null() {
        return None;
    }
    let exit = result
        .get("exit")
        .or_else(|| result.get("exitCode"))
        .and_then(Value::as_i64)
        .and_then(|n| i32::try_from(n).ok())
        .unwrap_or(0);
    let text = result
        .get("output")
        .and_then(Value::as_str)
        .or_else(|| result.get("title").and_then(Value::as_str))
        .map_or_else(
            || serde_json::to_string(result).unwrap_or_default(),
            ToString::to_string,
        );
    Some((text, exit))
}

#[cfg(test)]
mod tests {
    use super::super::OpenCode;
    use crate::AgentAdapter;
    use snitchit_core::event::ActionType;

    #[test]
    fn opencode_bash_maps_to_tool_call() {
        let call = OpenCode
            .parse(
                r#"{"tool":"bash","session_id":"o1","args":{"command":"curl https://x.com"},
                    "result":{"output":"done","exit":0}}"#,
            )
            .expect("call");
        assert_eq!(call.tool, "bash");
        assert!(matches!(call.kind, ActionType::ToolCall));
        assert!(call.input.contains("curl https://x.com"));
    }

    #[test]
    fn opencode_edit_maps_to_write_with_camelcase_path() {
        let call = OpenCode
            .parse(r#"{"tool":"edit","session_id":"o1","args":{"filePath":"/src/main.rs"},"result":{}}"#)
            .expect("call");
        assert!(matches!(call.kind, ActionType::Write));
        assert!(call.input.contains("/src/main.rs"));
    }

    #[test]
    fn opencode_webfetch_maps_to_network_and_empty_tool_skipped() {
        let call = OpenCode
            .parse(r#"{"tool":"webfetch","args":{"url":"https://x.com"},"result":{}}"#)
            .expect("call");
        assert!(matches!(call.kind, ActionType::Network));
        assert!(OpenCode.parse(r#"{"session_id":"o1"}"#).is_none());
    }

    #[test]
    fn opencode_secret_in_command_is_redacted_in_the_final_event() {
        let call = OpenCode
            .parse(
                r#"{"tool":"bash","args":{"command":"echo sk-abcdefghijklmnopqrstuvwxyz012345"},
                    "result":{"output":"","exit":0}}"#,
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
