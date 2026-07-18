//! Claude Code — hook-payload parsing ([`hook`]) + install wiring ([`install`]).
//!
//! `PascalCase` tool names (`Bash`, `Read`), `snake_case` argument keys
//! (`file_path`); wired via a `PostToolUse` command hook in `settings.json`.

mod hook;
mod install;

/// The Claude Code agent — both its hook adapter and its install integration.
pub struct Claude;

impl crate::Agent for Claude {
    fn id(&self) -> &'static str {
        "claude"
    }
}
