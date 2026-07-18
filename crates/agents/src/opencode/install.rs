//! `OpenCode` install wiring: a generated JS plugin under
//! `~/.config/opencode/plugins/` that forwards `tool.execute.after` calls to
//! `snitchit hook --agent opencode`.

use std::fs;
use std::path::{Path, PathBuf};

use crate::{AgentError, AgentIntegration, InstallOptions, Result};

impl AgentIntegration for super::OpenCode {
    fn install(&self, opts: &InstallOptions) -> Result<String> {
        let path = plugin_path(opts)?;
        let content = plugin_js(&opts.exe);
        if fs::read_to_string(&path).is_ok_and(|existing| existing == content) {
            return Ok(format!("already installed at {}", path.display()));
        }
        if opts.dry_run {
            return Ok(format!("would write plugin to {}", path.display()));
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| AgentError(format!("creating {}: {e}", parent.display())))?;
        }
        fs::write(&path, content)
            .map_err(|e| AgentError(format!("writing {}: {e}", path.display())))?;
        Ok(format!("installed plugin at {}", path.display()))
    }

    fn uninstall(&self, opts: &InstallOptions) -> Result<String> {
        let path = plugin_path(opts)?;
        if !path.exists() {
            return Ok(format!("nothing to remove at {}", path.display()));
        }
        // Only remove a file we recognize as ours (by the generated header marker).
        let ours = fs::read_to_string(&path).is_ok_and(|c| {
            c.contains("records OpenCode tool calls into the active snitchit session")
        });
        if !ours {
            return Ok(format!(
                "left unrecognized file at {} untouched",
                path.display()
            ));
        }
        if opts.dry_run {
            return Ok(format!("would remove plugin at {}", path.display()));
        }
        fs::remove_file(&path)
            .map_err(|e| AgentError(format!("removing {}: {e}", path.display())))?;
        Ok(format!("removed plugin at {}", path.display()))
    }
}

/// The `OpenCode` plugin file: the override if given, else
/// `$XDG_CONFIG_HOME/opencode/plugins/snitchit.js` (falling back to
/// `~/.config/opencode/plugins/snitchit.js`).
fn plugin_path(opts: &InstallOptions) -> Result<PathBuf> {
    if let Some(p) = &opts.opencode_plugin {
        return Ok(p.clone());
    }
    let base = if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        PathBuf::from(xdg)
    } else {
        dirs::home_dir()
            .ok_or_else(|| {
                AgentError(
                    "could not determine home directory; pass --opencode-plugin <path>".into(),
                )
            })?
            .join(".config")
    };
    Ok(base.join("opencode").join("plugins").join("snitchit.js"))
}

/// The generated `OpenCode` plugin: on every completed tool call it pipes a JSON
/// payload to `snitchit hook --agent opencode`. Observe-only — any error is
/// swallowed so it never disrupts the agent.
fn plugin_js(exe: &Path) -> String {
    // JSON-encode the path to get a safe JS string literal (handles backslashes).
    let exe_lit = serde_json::to_string(&exe.display().to_string())
        .unwrap_or_else(|_| "\"snitchit\"".to_string());
    format!(
        r#"// snitchit — records OpenCode tool calls into the active snitchit session.
// Installed by `snitchit install`; remove with `snitchit uninstall`.
export const snitchit = async () => ({{
  "tool.execute.after": async (input, output) => {{
    try {{
      const payload = JSON.stringify({{
        tool: (input && input.tool) || "",
        session_id: (input && input.sessionID) || "",
        args: (output && output.args) || {{}},
        result: output || {{}},
      }});
      const proc = Bun.spawn([{exe_lit}, "hook", "--agent", "opencode"],
        {{ stdin: "pipe", stdout: "ignore", stderr: "ignore" }});
      proc.stdin.write(payload);
      proc.stdin.end();
      await proc.exited;
    }} catch (_e) {{ /* observe-only: never disrupt the agent */ }}
  }},
}});
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opencode_plugin_embeds_binary_path_and_agent_flag() {
        let js = plugin_js(Path::new("/home/x/.local/bin/snitchit"));
        assert!(js.contains("tool.execute.after"));
        assert!(js.contains("--agent"));
        assert!(js.contains("opencode"));
        assert!(js.contains("/home/x/.local/bin/snitchit"));
        // The header marker uninstall keys on must be present.
        assert!(js.contains("records OpenCode tool calls into the active snitchit session"));
    }
}
