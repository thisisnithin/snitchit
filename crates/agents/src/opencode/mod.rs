//! `OpenCode` — hook-payload parsing ([`hook`]) + install wiring ([`install`]).
//!
//! Lowercase tool names (`bash`, `edit`), camelCase argument keys (`filePath`);
//! wired via a generated JS plugin under `~/.config/opencode/plugins/`.

mod hook;
mod install;

/// The `OpenCode` agent — both its hook adapter and its install integration.
pub struct OpenCode;

impl crate::Agent for OpenCode {
    fn id(&self) -> &'static str {
        "opencode"
    }
}
