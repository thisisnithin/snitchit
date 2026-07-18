//! The canonical [`Event`] record — snitchit's on-the-wire and on-disk unit.
//!
//! The shape mirrors halo-record's Schema v0.1 (`halo-record.schema.json`) field
//! for field, so a chain snitchit writes is verifiable by halo-record's own
//! verifier (brief §3). Every collector normalizes its native events into this
//! type *before* they cross the [`EventSource`](crate::EventSource) seam, so no
//! collector-shaped data ever leaks into the core.
//!
//! Redaction rule (adopted from halo-record): raw inputs never enter a record.
//! Commands, outputs, and tool arguments are stored as `sha256:` hashes plus a
//! best-effort redacted summary — never raw values.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::canon::{compute_hash, input_hash, GENESIS_PREV};
use crate::error::Result;
use crate::redact::{self, redact_text, redact_transcript, scan, scan_transcript, top_severity};

/// Schema version we emit and accept (halo-record Schema v0.1).
pub const SCHEMA_VERSION: &str = "0.1";

/// A single tamper-evident record of one agent/shell action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Always `"0.1"`.
    pub schema_version: String,
    /// Unique id for this record (`UUIDv4`).
    pub record_id: String,
    /// Links the record to its session/conversation.
    pub session_id: String,
    /// RFC 3339 UTC timestamp.
    pub ts: String,
    /// The record this one was caused by, for provenance (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    /// Which agent produced the action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<Agent>,
    /// Evidentiary provenance of this record (halo-record extension).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<Source>,
    /// What happened.
    pub action: Action,
    /// The result of the action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<Outcome>,
    /// Redacted sensitive-data findings for this record.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub findings: Vec<Finding>,
    /// Highest finding severity (`INFO` when none).
    pub severity: String,
    /// Hash-chain integrity block.
    pub integrity: Integrity,
}

/// Which agent (or tool) performed the action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Agent {
    /// Stable agent id.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Agent version (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// Evidentiary provenance: `{adapter, via, capture}` (halo-record convention).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Source {
    /// Adapter id, e.g. `pty`, `hook`.
    pub adapter: String,
    /// Human description of the capture path.
    pub via: String,
    /// `captured` (seen at the trust boundary) or `ingested` (from telemetry).
    pub capture: Capture,
}

/// Evidentiary strength of a record's origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capture {
    /// snitchit observed the action directly at the trust boundary. Strongest.
    Captured,
    /// Built from telemetry the vendor already emits. Weaker.
    Ingested,
}

/// The action classification (halo-record `action` object).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Action {
    /// One of the halo-record action types.
    #[serde(rename = "type")]
    pub kind: ActionType,
    /// One of the halo-record categories.
    pub category: Category,
    /// The tool/command name (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// The (redacted-summary + hash) representation of the inputs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input: Option<Payload>,
}

/// Action type enum (matches the schema's `action.type` enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    /// Invoking a tool or running a command.
    ToolCall,
    /// A message emitted by the agent.
    AgentMessage,
    /// A read action.
    Read,
    /// A write action.
    Write,
    /// A network action.
    Network,
}

/// Action category enum (matches the schema's `action.category` enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// Security-relevant (arbitrary code execution, etc.).
    Security,
    /// Safety-relevant.
    Safety,
    /// Reliability-relevant.
    Reliability,
    /// Privacy-relevant.
    Privacy,
}

/// A redacted summary plus a hash of the full canonical value. Raw values never
/// appear here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Payload {
    /// Best-effort redacted summary (truncated).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// `sha256:` + SHA-256 of the canonical value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

/// The outcome of an action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outcome {
    /// `ok` | `error` | `denied`.
    pub status: Status,
    /// Best-effort redacted summary of the result.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// `sha256:` + SHA-256 of the full canonical result.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

/// Outcome status enum (matches the schema's `outcome.status` enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Completed successfully.
    Ok,
    /// Failed.
    Error,
    /// Denied by policy/authorization.
    Denied,
}

/// A redacted sensitive-data finding (schema `findings[]`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Kind of secret/PII.
    #[serde(rename = "type")]
    pub kind: String,
    /// Severity label.
    pub severity: String,
    /// Redacted excerpt (never the raw value).
    pub sample: String,
}

impl From<redact::Finding> for Finding {
    fn from(f: redact::Finding) -> Self {
        Self {
            kind: f.kind,
            severity: f.severity,
            sample: f.sample,
        }
    }
}

/// The hash-chain integrity block (schema `integrity`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Integrity {
    /// Always `sha-256`.
    pub alg: String,
    /// Always `rfc8785`.
    pub canon: String,
    /// Hex SHA-256 of the previous record; 64 zeros for the first record.
    pub prev_hash: String,
    /// Hex SHA-256 of this record (excluding `integrity.hash`), JCS-canonical.
    pub hash: String,
}

impl Default for Integrity {
    fn default() -> Self {
        Self {
            alg: "sha-256".to_string(),
            canon: "rfc8785".to_string(),
            prev_hash: String::new(),
            hash: String::new(),
        }
    }
}

impl Event {
    /// Build a generic command-shaped event: a command plus its output and
    /// exit code, sourced as if by the PTY collector.
    ///
    /// **Not used by any shipped collector** — [`process_run`](Self::process_run)
    /// and [`command_submitted`](Self::command_submitted) are what the real PTY
    /// collector emits, and their docs explain why (a PTY sees terminal bytes,
    /// never a resolved shell command). This exists only as a convenient,
    /// collector-agnostic stand-in for core-crate tests and the `emit_chain`
    /// example, which don't care about PTY-specific fidelity. Do not wire this
    /// into a real collector: `command` here is stored exactly like any other
    /// command-shaped record (hashed + redacted-summary input, transcript-only
    /// outcome) — it is never a semantically resolved, executed shell command.
    #[must_use]
    pub fn shell_command(
        session_id: &str,
        record_id: String,
        ts: String,
        command: &str,
        output: &str,
        exit_code: i32,
    ) -> Self {
        build(Spec {
            session_id,
            record_id,
            ts,
            source: pty_source(),
            kind: ActionType::ToolCall,
            tool: "shell",
            input: command,
            fuzzy_input: true,
            outcome: Some((output, exit_code)),
        })
    }

    /// Build a record for the wrapped process invocation itself (the PTY
    /// collector's primary, honest event): the resolved program as the tool, the
    /// full argv as the redacted+hashed input, and the terminal transcript +
    /// exit code as the outcome.
    #[must_use]
    pub fn process_run(
        session_id: &str,
        record_id: String,
        ts: String,
        program: &str,
        argv_display: &str,
        transcript: &str,
        exit_code: i32,
    ) -> Self {
        build(Spec {
            session_id,
            record_id,
            ts,
            source: pty_source(),
            kind: ActionType::ToolCall,
            tool: program,
            input: argv_display,
            fuzzy_input: true,
            outcome: Some((transcript, exit_code)),
        })
    }

    /// Build a record for a line of terminal input submitted to the agent.
    ///
    /// This is the PTY collector's heuristic input-segmentation event (brief §5):
    /// the observable input surface, not a semantically resolved shell command.
    /// No outcome is attached — a PTY cannot attribute a per-line exit code.
    #[must_use]
    pub fn command_submitted(session_id: &str, record_id: String, ts: String, line: &str) -> Self {
        build(Spec {
            session_id,
            record_id,
            ts,
            source: pty_source(),
            kind: ActionType::ToolCall,
            tool: "terminal-input",
            input: line,
            fuzzy_input: true,
            outcome: None,
        })
    }

    /// Build a record for an agent's in-process tool call, ingested from a hook
    /// (v1.1 hooks collector). `source` is `hook`; `kind` is mapped from the tool
    /// (`Read`/`Write`/`Network`/`ToolCall`). Inputs/outputs are hashed + redacted
    /// with exact-pattern matching only (payloads are free-form).
    #[must_use]
    pub fn agent_tool_call(
        session_id: &str,
        record_id: String,
        ts: String,
        tool: &str,
        kind: ActionType,
        input: &str,
        outcome: Option<(&str, i32)>,
    ) -> Self {
        build(Spec {
            session_id,
            record_id,
            ts,
            source: hook_source(),
            kind,
            tool,
            input,
            fuzzy_input: false,
            outcome,
        })
    }

    /// Build a record for a process the agent's tree `exec`'d, observed at the
    /// kernel via eBPF (v1.2 kernel collector, Linux). `source` is `ebpf`; the
    /// resolved binary path is the tool and the full argv is the redacted+hashed
    /// input. No outcome — an `exec` observation carries no exit code at exec
    /// time.
    ///
    /// Mapped to [`ActionType::ToolCall`]: an `exec` *is* a command/tool
    /// invocation, and this keeps the serialized `action.type` within the
    /// halo-record enum. Adding a new `ActionType` would change that string and
    /// break halo interop, so we never do.
    #[must_use]
    pub fn kernel_exec(
        session_id: &str,
        record_id: String,
        ts: String,
        program: &str,
        argv_display: &str,
    ) -> Self {
        build(Spec {
            session_id,
            record_id,
            ts,
            source: ebpf_source(),
            kind: ActionType::ToolCall,
            tool: program,
            input: argv_display,
            fuzzy_input: false,
            outcome: None,
        })
    }

    /// Build a record for an outbound network connection the agent's tree made,
    /// observed at the kernel via eBPF. `source` is `ebpf`; `kind` is
    /// [`ActionType::Network`]; the destination `host:port` is the
    /// redacted+hashed input. Only the destination is ever seen — no connection
    /// payload bodies enter a record.
    #[must_use]
    pub fn kernel_connect(
        session_id: &str,
        record_id: String,
        ts: String,
        destination: &str,
    ) -> Self {
        build(Spec {
            session_id,
            record_id,
            ts,
            source: ebpf_source(),
            kind: ActionType::Network,
            tool: "connect",
            input: destination,
            fuzzy_input: false,
            outcome: None,
        })
    }

    /// Serialize to a [`serde_json::Value`] for canonicalization/hashing.
    pub fn to_value(&self) -> Result<Value> {
        Ok(serde_json::to_value(self)?)
    }

    /// Seal this event into the chain: set `prev_hash`, compute and set `hash`.
    ///
    /// Returns the new chain head (this record's hash).
    pub fn seal(&mut self, prev_hash: &str) -> Result<String> {
        self.integrity.prev_hash = prev_hash.to_string();
        let value = self.to_value()?;
        let hash = compute_hash(&value, prev_hash)?;
        self.integrity.hash.clone_from(&hash);
        Ok(hash)
    }

    /// The genesis previous-hash constant (64 zeros).
    #[must_use]
    pub fn genesis_prev() -> &'static str {
        GENESIS_PREV
    }
}

/// The inputs to [`build`] — one struct so the constructors stay readable and
/// we avoid a many-argument shared function.
struct Spec<'a> {
    session_id: &'a str,
    record_id: String,
    ts: String,
    source: Source,
    kind: ActionType,
    tool: &'a str,
    /// Redacted-summarized + hashed; raw never stored.
    input: &'a str,
    /// Whether to apply the high-entropy catch-all to the input. `true` for short
    /// structured inputs (prompts, argv); `false` for free-form payloads (hook
    /// tool args, file contents) where it over-fires.
    fuzzy_input: bool,
    /// `Some((output, exit_code))` when a result is known. Output is always
    /// treated as free-form (exact patterns only).
    outcome: Option<(&'a str, i32)>,
}

fn pty_source() -> Source {
    Source {
        adapter: "pty".to_string(),
        via: "snitchit PTY wrapper".to_string(),
        capture: Capture::Captured,
    }
}

fn hook_source() -> Source {
    Source {
        adapter: "hook".to_string(),
        via: "agent hook".to_string(),
        capture: Capture::Captured,
    }
}

fn ebpf_source() -> Source {
    Source {
        adapter: "ebpf".to_string(),
        via: "snitchit eBPF (kernel)".to_string(),
        // Direct kernel observation at the trust boundary — strongest evidence,
        // same classification as the PTY wrapper.
        capture: Capture::Captured,
    }
}

/// The one shared record builder: scan/redact inputs and outputs, then assemble.
fn build(spec: Spec) -> Event {
    let mut redact_findings = if spec.fuzzy_input {
        scan(spec.input)
    } else {
        scan_transcript(spec.input)
    };
    if let Some((output, _)) = spec.outcome {
        // Output is always free-form: exact patterns only, no high-entropy sweep.
        redact_findings.extend(scan_transcript(output));
    }
    let severity = top_severity(&redact_findings);
    let findings: Vec<Finding> = redact_findings.into_iter().map(Into::into).collect();

    let input_summary = if spec.fuzzy_input {
        redact_text(spec.input)
    } else {
        redact_transcript(spec.input)
    };

    let outcome = spec.outcome.map(|(output, exit_code)| {
        // Store *metadata about* the output, never a slice *of* it. A summary
        // derived from output content can leak secrets redaction doesn't
        // recognize (e.g. a custom `KEY=value` in a read `.env`); size + status
        // cannot. The full raw output is still committed to via `hash`, and any
        // known-pattern secret is still surfaced (masked) in `findings`.
        let bytes = output.len();
        let lines = output.lines().count();
        Outcome {
            status: if exit_code == 0 {
                Status::Ok
            } else {
                Status::Error
            },
            summary: Some(format!("exit {exit_code}: {bytes} bytes, {lines} line(s)")),
            hash: Some(input_hash(&Value::String(output.to_string()))),
        }
    });

    Event {
        schema_version: SCHEMA_VERSION.to_string(),
        record_id: spec.record_id,
        session_id: spec.session_id.to_string(),
        ts: spec.ts,
        parent_id: None,
        agent: None,
        source: Some(spec.source),
        action: Action {
            kind: spec.kind,
            category: Category::Security,
            tool: Some(spec.tool.to_string()),
            input: Some(Payload {
                summary: Some(truncate(&input_summary, 200)),
                hash: Some(input_hash(&Value::String(spec.input.to_string()))),
            }),
        },
        outcome,
        findings,
        severity,
        integrity: Integrity::default(),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_command_never_stores_raw_input() {
        let ev = Event::shell_command(
            "sess",
            "id-1".to_string(),
            "2026-07-15T00:00:00Z".to_string(),
            "curl -H 'Authorization: Bearer sk-abcdefghijklmnopqrstuvwxyz1234'",
            "ok",
            0,
        );
        let json = serde_json::to_string(&ev).unwrap();
        assert!(!json.contains("sk-abcdefghijklmnopqrstuvwxyz1234"));
        // Hash of the raw command is present instead.
        assert!(json.contains("sha256:"));
    }

    #[test]
    fn outcome_summary_never_echoes_output_content() {
        // A custom `.env` secret that matches no known pattern (so redaction
        // would not catch it) must still never reach the log: the outcome
        // summary is metadata-only, and only the hash commits to the content.
        let secret = "MY_APP_SECRET=hunter2plsdontleak";
        let ev = Event::agent_tool_call(
            "sess",
            "id-1".to_string(),
            "2026-07-15T00:00:00Z".to_string(),
            "Read",
            ActionType::Read,
            "/app/.env",
            Some((secret, 0)),
        );
        let summary = ev
            .outcome
            .as_ref()
            .and_then(|o| o.summary.as_deref())
            .unwrap_or_default();
        assert!(
            !summary.contains("hunter2plsdontleak"),
            "output content must not appear in the outcome summary, got: {summary}"
        );
        // But the summary still reports size, and the full record commits to the
        // content via a hash (so integrity is preserved without exposure).
        assert!(summary.contains("bytes"));
        let json = serde_json::to_string(&ev).unwrap();
        assert!(!json.contains("hunter2plsdontleak"));
        assert!(json.contains("sha256:"));
    }

    #[test]
    fn nonzero_exit_is_error_status() {
        let ev = Event::shell_command("s", "i".to_string(), "t".to_string(), "false", "", 1);
        assert!(matches!(
            ev.outcome.as_ref().map(|o| o.status),
            Some(Status::Error)
        ));
    }

    #[test]
    fn command_submitted_has_no_outcome() {
        let ev = Event::command_submitted(
            "s",
            "i".to_string(),
            "t".to_string(),
            "please refactor the parser",
        );
        assert!(ev.outcome.is_none());
        assert_eq!(ev.action.tool.as_deref(), Some("terminal-input"));
    }

    #[test]
    fn process_run_records_program_and_exit() {
        let ev = Event::process_run(
            "s",
            "i".to_string(),
            "t".to_string(),
            "claude",
            "claude --help",
            "usage: ...",
            2,
        );
        assert_eq!(ev.action.tool.as_deref(), Some("claude"));
        assert!(matches!(ev.outcome.map(|o| o.status), Some(Status::Error)));
    }

    #[test]
    fn kernel_exec_maps_to_tool_call_and_ebpf_source_without_raw() {
        let ev = Event::kernel_exec(
            "s",
            "i".to_string(),
            "t".to_string(),
            "/usr/bin/curl",
            "curl -H 'Authorization: Bearer sk-abcdefghijklmnopqrstuvwxyz1234' https://x",
        );
        let v = ev.to_value().unwrap();
        assert_eq!(v["action"]["type"], "tool_call");
        assert_eq!(v["source"]["adapter"], "ebpf");
        assert_eq!(v["source"]["capture"], "captured");
        // Raw argv never stored; a hash stands in, and the secret is redacted.
        let json = serde_json::to_string(&ev).unwrap();
        assert!(!json.contains("sk-abcdefghijklmnopqrstuvwxyz1234"));
        assert!(json.contains("sha256:"));
    }

    #[test]
    fn kernel_connect_maps_to_network() {
        let ev = Event::kernel_connect("s", "i".to_string(), "t".to_string(), "93.184.216.34:443");
        let v = ev.to_value().unwrap();
        assert_eq!(v["action"]["type"], "network");
        assert_eq!(v["source"]["adapter"], "ebpf");
        assert_eq!(v["action"]["tool"], "connect");
        assert!(ev.outcome.is_none());
    }

    #[test]
    fn serializes_type_and_enum_names_per_schema() {
        let ev = Event::shell_command("s", "i".to_string(), "t".to_string(), "ls", "", 0);
        let v = ev.to_value().unwrap();
        assert_eq!(v["action"]["type"], "tool_call");
        assert_eq!(v["action"]["category"], "security");
        assert_eq!(v["integrity"]["alg"], "sha-256");
        assert_eq!(v["integrity"]["canon"], "rfc8785");
        assert_eq!(v["source"]["capture"], "captured");
    }
}
