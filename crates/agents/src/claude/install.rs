//! Claude Code install wiring: a `PostToolUse` entry in `~/.claude/settings.json`.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use crate::{AgentError, AgentIntegration, InstallOptions, Result};

impl AgentIntegration for super::Claude {
    fn install(&self, opts: &InstallOptions) -> Result<String> {
        let path = settings_path(opts)?;
        let command = format!("\"{}\" hook", opts.exe.display());
        let root = read_json(&path)?;
        let (next, changed) = with_hook(root, &command);
        if !changed {
            return Ok(format!("already installed in {}", path.display()));
        }
        if opts.dry_run {
            return Ok(format!(
                "would register PostToolUse hook in {}",
                path.display()
            ));
        }
        write_json(&path, &next)?;
        Ok(format!("registered PostToolUse hook in {}", path.display()))
    }

    fn uninstall(&self, opts: &InstallOptions) -> Result<String> {
        let path = settings_path(opts)?;
        let root = read_json(&path)?;
        let (next, changed) = without_hook(root);
        if !changed {
            return Ok(format!("nothing to remove in {}", path.display()));
        }
        if opts.dry_run {
            return Ok(format!("would remove the hook from {}", path.display()));
        }
        write_json(&path, &next)?;
        Ok(format!("removed the hook from {}", path.display()))
    }
}

/// The settings.json to edit: the override if given, else `~/.claude/settings.json`.
fn settings_path(opts: &InstallOptions) -> Result<PathBuf> {
    if let Some(p) = &opts.claude_settings {
        return Ok(p.clone());
    }
    let home = dirs::home_dir().ok_or_else(|| {
        AgentError("could not determine home directory; pass --claude-settings <path>".into())
    })?;
    Ok(home.join(".claude").join("settings.json"))
}

/// A matcher group registering our hook for all tools.
fn snitchit_group(command: &str) -> Value {
    serde_json::json!({
        "matcher": "*",
        "hooks": [ { "type": "command", "command": command, "timeout": 30 } ]
    })
}

/// Whether a `PostToolUse` matcher group is one snitchit added (a `command` hook
/// pointing at the snitchit binary's `hook` subcommand).
fn is_snitchit_group(group: &Value) -> bool {
    group
        .get("hooks")
        .and_then(Value::as_array)
        .is_some_and(|hooks| {
            hooks.iter().any(|h| {
                h.get("command")
                    .and_then(Value::as_str)
                    .is_some_and(|c| c.contains("snitchit") && c.trim_end().ends_with("hook"))
            })
        })
}

fn post_tool_use(root: &Value) -> Vec<Value> {
    root.get("hooks")
        .and_then(|h| h.get("PostToolUse"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// Return `root` with exactly one snitchit `PostToolUse` hook present, plus
/// whether anything changed (idempotent).
fn with_hook(mut root: Value, command: &str) -> (Value, bool) {
    if !root.is_object() {
        root = Value::Object(Map::new());
    }
    let original = post_tool_use(&root);
    let mut kept: Vec<Value> = original
        .iter()
        .filter(|g| !is_snitchit_group(g))
        .cloned()
        .collect();
    kept.push(snitchit_group(command));
    let changed = kept != original;
    set_post_tool_use(&mut root, kept);
    (root, changed)
}

/// Return `root` with any snitchit `PostToolUse` hook removed, plus whether
/// anything changed.
fn without_hook(mut root: Value) -> (Value, bool) {
    if !root.is_object() {
        return (root, false);
    }
    let original = post_tool_use(&root);
    let kept: Vec<Value> = original
        .iter()
        .filter(|g| !is_snitchit_group(g))
        .cloned()
        .collect();
    let changed = kept.len() != original.len();
    set_post_tool_use(&mut root, kept);
    (root, changed)
}

/// Write `groups` back into `root.hooks.PostToolUse`, cleaning up empty tables.
fn set_post_tool_use(root: &mut Value, groups: Vec<Value>) {
    let Some(obj) = root.as_object_mut() else {
        return;
    };
    let hooks = obj
        .entry("hooks")
        .or_insert_with(|| Value::Object(Map::new()));
    if let Some(hooks_obj) = hooks.as_object_mut() {
        if groups.is_empty() {
            hooks_obj.remove("PostToolUse");
        } else {
            hooks_obj.insert("PostToolUse".to_string(), Value::Array(groups));
        }
        if hooks_obj.is_empty() {
            obj.remove("hooks");
        }
    }
}

fn read_json(path: &Path) -> Result<Value> {
    match fs::read_to_string(path) {
        Ok(s) if s.trim().is_empty() => Ok(Value::Object(Map::new())),
        Ok(s) => serde_json::from_str(&s).map_err(|_| {
            AgentError(format!(
                "{} is not valid JSON; fix or move it first",
                path.display()
            ))
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Value::Object(Map::new())),
        Err(e) => Err(AgentError(format!("reading {}: {e}", path.display()))),
    }
}

fn write_json(path: &Path, value: &Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|e| AgentError(format!("creating {}: {e}", parent.display())))?;
        }
    }
    let mut s = serde_json::to_string_pretty(value)
        .map_err(|e| AgentError(format!("serializing settings.json: {e}")))?;
    s.push('\n');
    fs::write(path, s).map_err(|e| AgentError(format!("writing {}: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hooks_install_preserves_user_config_and_is_idempotent() {
        let cmd = "\"/usr/local/bin/snitchit\" hook";
        let orig: Value = serde_json::json!({
            "model": "opus",
            "hooks": { "PostToolUse": [
                { "matcher": "Bash", "hooks": [ {"type":"command","command":"/my/own.sh"} ] }
            ] }
        });

        let (installed, changed) = with_hook(orig.clone(), cmd);
        assert!(changed);
        assert_eq!(post_tool_use(&installed).len(), 2);
        assert_eq!(installed["model"], "opus");

        let (again, changed2) = with_hook(installed.clone(), cmd);
        assert!(!changed2);
        assert_eq!(again, installed);

        let (removed, changed3) = without_hook(installed);
        assert!(changed3);
        assert_eq!(removed, orig);
    }

    #[test]
    fn hooks_install_on_empty_settings_and_full_removal() {
        let (v, changed) = with_hook(Value::Object(Map::new()), "\"/x/snitchit\" hook");
        assert!(changed);
        let post = post_tool_use(&v);
        assert!(is_snitchit_group(&post[0]));

        let (empty, changed2) = without_hook(v);
        assert!(changed2);
        assert_eq!(empty, Value::Object(Map::new()));
    }
}
