//! Integration test: `snitchit hook` ingests a Claude `PostToolUse` payload into
//! the session named by `SNITCHIT_LOG`, and the result verifies.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_snitchit")
}

fn unique(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("snitchit-hook-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn feed_hook(log: &PathBuf, payload: &str) {
    feed_hook_agent(log, payload, "claude");
}

fn feed_hook_agent(log: &PathBuf, payload: &str, agent: &str) {
    let mut child = Command::new(bin())
        .args(["hook", "--agent", agent])
        .env("SNITCHIT_LOG", log)
        .env("SNITCHIT_SESSION", "itest")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.as_bytes())
        .unwrap();
    let status = child.wait().unwrap();
    // Observe-only: the hook must ALWAYS exit 0, never block the agent.
    assert_eq!(status.code(), Some(0), "hook must always exit 0");
}

#[test]
fn hook_ingests_tool_calls_into_the_session_and_verifies() {
    let dir = unique("ingest");
    let log = dir.join("session.jsonl");

    feed_hook(
        &log,
        r#"{"hook_event_name":"PostToolUse","session_id":"c1","tool_name":"Bash",
            "tool_input":{"command":"ls -la"},
            "tool_response":{"stdout":"total 0","stderr":"","exit_code":0}}"#,
    );
    feed_hook(
        &log,
        r#"{"hook_event_name":"PostToolUse","session_id":"c1","tool_name":"Read",
            "tool_input":{"file_path":"/etc/hosts"},"tool_response":{"exit_code":0}}"#,
    );

    // Two records landed.
    let contents = std::fs::read_to_string(&log).unwrap();
    let lines: Vec<&str> = contents.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 2, "two hook events should be recorded");
    assert!(lines[0].contains("\"adapter\":\"hook\""));
    assert!(lines[0].contains("ls -la"));

    // The chain verifies.
    let verify = Command::new(bin())
        .arg("verify")
        .arg(&log)
        .status()
        .unwrap();
    assert!(verify.success(), "hook-written chain must verify");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn opencode_hook_ingests_tool_calls_and_verifies() {
    let dir = unique("oc");
    let log = dir.join("session.jsonl");

    feed_hook_agent(
        &log,
        r#"{"tool":"bash","session_id":"o1","args":{"command":"curl https://x.com"},
            "result":{"output":"done","exit":0}}"#,
        "opencode",
    );
    feed_hook_agent(
        &log,
        r#"{"tool":"edit","session_id":"o1","args":{"filePath":"/src/main.rs"},"result":{}}"#,
        "opencode",
    );

    let contents = std::fs::read_to_string(&log).unwrap();
    let lines: Vec<&str> = contents.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].contains("\"adapter\":\"hook\""));
    assert!(lines[0].contains("curl https://x.com"));
    assert!(lines[1].contains("/src/main.rs"));

    let verify = Command::new(bin())
        .arg("verify")
        .arg(&log)
        .status()
        .unwrap();
    assert!(verify.success());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn install_wires_shims_and_both_agent_hooks_unconditionally() {
    // No `--hooks` flag exists: a plain `install` must wire the shell shims AND
    // both agents' hooks in one shot — hooks are core setup, not opt-in.
    let dir = unique("install");
    let rc = dir.join("shellrc");
    let settings = dir.join("settings.json");
    let plugin = dir.join("snitchit.js");
    std::fs::write(&rc, "# my rc\n").unwrap();
    std::fs::write(&settings, r#"{"model":"opus"}"#).unwrap();

    let run = |verb: &str| {
        Command::new(bin())
            .args([verb, "--rc"])
            .arg(&rc)
            .arg("--claude-settings")
            .arg(&settings)
            .arg("--opencode-plugin")
            .arg(&plugin)
            .status()
            .unwrap()
    };

    assert!(run("install").success());
    // Shell shims installed.
    let rc_contents = std::fs::read_to_string(&rc).unwrap();
    assert!(rc_contents.contains("command snitchit -- claude"));
    // Claude settings.json gained a PostToolUse hook, kept the user's config.
    let s = std::fs::read_to_string(&settings).unwrap();
    assert!(s.contains("PostToolUse") && s.contains("hook") && s.contains("opus"));
    // OpenCode plugin written.
    let js = std::fs::read_to_string(&plugin).unwrap();
    assert!(js.contains("tool.execute.after") && js.contains("--agent"));

    // Idempotent.
    assert!(run("install").success());

    // Uninstall removes everything.
    assert!(run("uninstall").success());
    let rc_contents = std::fs::read_to_string(&rc).unwrap();
    assert_eq!(
        rc_contents, "# my rc\n",
        "shell rc should be byte-identical"
    );
    let s = std::fs::read_to_string(&settings).unwrap();
    assert!(!s.contains("PostToolUse"), "claude hook should be gone");
    assert!(!plugin.exists(), "opencode plugin should be removed");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn malformed_payload_is_ignored_and_still_exits_zero() {
    let dir = unique("bad");
    let log = dir.join("session.jsonl");
    feed_hook(&log, "this is not json at all");
    // Nothing recorded, but exit 0 (asserted in feed_hook).
    assert!(!log.exists() || std::fs::read_to_string(&log).unwrap().trim().is_empty());
    std::fs::remove_dir_all(&dir).ok();
}
