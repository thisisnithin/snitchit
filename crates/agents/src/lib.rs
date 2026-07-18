//! `snitchit-agents` — everything specific to a supported agent, in one place.
//!
//! Each agent (Claude Code, `OpenCode`, …) lives in its own module and provides
//! **both** halves of snitchit's per-agent support:
//!
//! * an [`AgentAdapter`] — parse the agent's hook payload into a
//!   [`NormalizedCall`] (used by `snitchit hook` at runtime); and
//! * an [`AgentIntegration`] — install/uninstall the agent's hook wiring (used
//!   by `snitchit install`).
//!
//! Both are bundled behind the [`Agent`] trait and listed once in [`agents`].
//! **Adding an agent = one new module + one line in [`agents`]** — nothing in
//! any other crate. The CLI's `hook` and `install` commands are thin drivers
//! over this registry and never branch on agent identity.

pub mod claude;
pub mod opencode;

use std::path::PathBuf;

use serde_json::Value;
use snitchit_core::event::ActionType;

/// A tool call, normalized by an [`AgentAdapter`] from its agent's native
/// payload — everything needed to build an [`Event`](snitchit_core::Event)
/// *except* which snitchit session it belongs to (resolved by the caller from
/// `agent_session_id` and/or the ambient `SNITCHIT_SESSION`).
#[derive(Debug, Clone)]
pub struct NormalizedCall {
    /// The tool name, in the agent's own casing (e.g. `Bash` vs `bash`).
    pub tool: String,
    /// The halo-record action classification for this tool.
    pub kind: ActionType,
    /// Redacted-summarized input (raw arguments never stored — see caller).
    pub input: String,
    /// `Some((output_text, exit_code))` when a result is known.
    pub outcome: Option<(String, i32)>,
    /// The agent's own session id (used for standalone log resolution).
    pub agent_session_id: String,
}

/// One agent's hook/plugin payload format (runtime parsing).
///
/// Implementors own their entire parsing story: payload shape, tool-name
/// mapping, argument-key conventions.
pub trait AgentAdapter {
    /// Parse one raw JSON payload (as received on stdin) into a
    /// [`NormalizedCall`], or `None` if it's not a tool event worth recording.
    fn parse(&self, raw: &str) -> Option<NormalizedCall>;
}

/// Where/how to wire an agent up, resolved by the caller from CLI flags. Each
/// integration reads only the field(s) it needs.
#[derive(Debug, Clone)]
pub struct InstallOptions {
    /// Absolute path to the snitchit binary (baked into hook commands so a shell
    /// shim can never redirect it).
    pub exe: PathBuf,
    /// Report intended actions without writing anything.
    pub dry_run: bool,
    /// Override for Claude Code's `settings.json` (else the default location).
    pub claude_settings: Option<PathBuf>,
    /// Override for the `OpenCode` plugin file (else the default location).
    pub opencode_plugin: Option<PathBuf>,
}

/// One agent's install-time wiring (register/remove its hook or plugin).
pub trait AgentIntegration {
    /// Register snitchit's hook/plugin for this agent. Returns a human message.
    fn install(&self, opts: &InstallOptions) -> Result<String>;
    /// Remove exactly what [`install`](AgentIntegration::install) added.
    fn uninstall(&self, opts: &InstallOptions) -> Result<String>;
}

/// A supported agent: both halves plus a stable id.
pub trait Agent: AgentAdapter + AgentIntegration + Send + Sync {
    /// Stable id, matched against `--agent <id>` (case-insensitive) and shown in
    /// install report lines.
    fn id(&self) -> &'static str;
}

/// All supported agents. **Register a new agent here — nowhere else.**
#[must_use]
pub fn agents() -> Vec<Box<dyn Agent>> {
    vec![Box::new(claude::Claude), Box::new(opencode::OpenCode)]
}

/// Look up an agent by id (case-insensitive), or `None` if unknown.
#[must_use]
pub fn by_id(id: &str) -> Option<Box<dyn Agent>> {
    agents()
        .into_iter()
        .find(|a| a.id().eq_ignore_ascii_case(id))
}

/// Error from install/uninstall wiring (a human-readable, contextual message).
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct AgentError(pub String);

/// Result alias for agent wiring.
pub type Result<T> = std::result::Result<T, AgentError>;

// --- shared adapter helpers (used by more than one adapter) -----------------

/// A picked field if non-empty, else a bounded compact dump of the whole value.
pub(crate) fn bounded_summary(picked: Option<&str>, whole: &Value) -> String {
    match picked {
        Some(s) if !s.is_empty() => s.chars().take(400).collect(),
        _ => serde_json::to_string(whole)
            .unwrap_or_default()
            .chars()
            .take(400)
            .collect(),
    }
}

/// Read an integer exit code field, defaulting to 0 (success) if absent.
pub(crate) fn exit_code_of(resp: &Value, field: &str) -> i32 {
    resp.get(field)
        .and_then(Value::as_i64)
        .and_then(|n| i32::try_from(n).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn by_id_is_case_insensitive_and_unknown_is_none() {
        assert!(by_id("Claude").is_some());
        assert!(by_id("OPENCODE").is_some());
        assert!(by_id("cursor").is_none());
    }

    #[test]
    fn exactly_the_icp_agents_are_registered() {
        let ids: Vec<&str> = agents().iter().map(|a| a.id()).collect();
        assert_eq!(ids, vec!["claude", "opencode"]);
    }
}
