//! Integration test: `snitchit view --no-open` renders a session's log to a
//! self-contained, offline HTML file — read-only over the existing JSONL.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_snitchit")
}

fn unique(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("snitchit-view-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn feed_hook(log: &PathBuf, payload: &str) {
    let mut child = Command::new(bin())
        .args(["hook", "--agent", "claude"])
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
    assert_eq!(status.code(), Some(0));
}

#[test]
fn view_renders_offline_html_with_all_records_and_no_external_urls() {
    let dir = unique("basic");
    let log = dir.join("session.jsonl");

    // Three records, deliberately varied: a Bash tool call with a secret that
    // must already be redacted by the store layer, a Read, and a WebFetch
    // (network) — enough to exercise several action types / source labeling.
    feed_hook(
        &log,
        r#"{"hook_event_name":"PostToolUse","session_id":"c1","tool_name":"Bash",
            "tool_input":{"command":"echo sk-abcdefghijklmnopqrstuvwxyz012345"},
            "tool_response":{"stdout":"ok","stderr":"","exit_code":0}}"#,
    );
    feed_hook(
        &log,
        r#"{"hook_event_name":"PostToolUse","session_id":"c1","tool_name":"Read",
            "tool_input":{"file_path":"/etc/hosts"},"tool_response":{"exit_code":0}}"#,
    );
    feed_hook(
        &log,
        r#"{"hook_event_name":"PostToolUse","session_id":"c1","tool_name":"WebFetch",
            "tool_input":{"url":"https://example.com/data"},
            "tool_response":{"exit_code":0}}"#,
    );

    let out = dir.join("view.html");
    let status = Command::new(bin())
        .args(["view", "--no-open", "--session"])
        .arg(&log)
        .arg("--out")
        .arg(&out)
        .status()
        .unwrap();
    assert!(status.success(), "snitchit view must succeed");

    let html = std::fs::read_to_string(&out).unwrap();

    // Self-contained: no external URL of any kind may appear anywhere in the
    // page (would violate the no-network/no-CDN constraint), EXCEPT inside the
    // embedded JSON data itself, where a redacted record's summary text may
    // legitimately contain a URL string (e.g. the WebFetch call above) — that
    // is recorded data, not a resource reference the page fetches.
    let script_start = html
        .find(r#"<script type="application/json" id="snitchit-data">"#)
        .expect("embedded data script must be present");
    let script_open_end = html[script_start..].find('>').unwrap() + script_start + 1;
    let script_close = html[script_open_end..].find("</script>").unwrap() + script_open_end;
    let before_data = &html[..script_start];
    let after_data = &html[script_close..];
    for marker in ["http://", "https://"] {
        assert!(
            !before_data.contains(marker) && !after_data.contains(marker),
            "page shell (CSS/JS/markup) must not reference any external URL, found {marker:?}"
        );
    }
    // No CDN/script-src/link-href of any kind.
    assert!(!html.contains("<script src="));
    assert!(!html.contains("<link"));

    // All three records made it in (count "record_id" occurrences within the
    // embedded data only — the app JS also contains the literal string
    // "record_id" once, as a field label, which must not be miscounted).
    let data_blob = &html[script_open_end..script_close];
    let record_id_count = data_blob.matches("\"record_id\"").count();
    assert_eq!(record_id_count, 3, "all recorded events must be embedded");

    // The raw secret must never appear (redaction already happened upstream;
    // the viewer must not somehow surface something the store didn't store).
    assert!(!html.contains("sk-abcdefghijklmnopqrstuvwxyz012345"));

    // Chain is intact (three clean hook appends) — the banner should say so.
    assert!(html.contains("intact"));

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn view_defaults_to_a_temp_file_when_out_is_not_given() {
    let dir = unique("default-out");
    let log = dir.join("session.jsonl");
    feed_hook(
        &log,
        r#"{"tool_name":"Read","session_id":"c1","tool_input":{"file_path":"/etc/hosts"},
            "tool_response":{"exit_code":0}}"#,
    );

    let output = Command::new(bin())
        .args(["view", "--no-open", "--session"])
        .arg(&log)
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("wrote"), "must print the path it wrote to");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn view_never_writes_to_the_session_log_itself() {
    let dir = unique("readonly");
    let log = dir.join("session.jsonl");
    feed_hook(
        &log,
        r#"{"tool_name":"Bash","session_id":"c1","tool_input":{"command":"ls"},
            "tool_response":{"stdout":"","stderr":"","exit_code":0}}"#,
    );
    let before = std::fs::read(&log).unwrap();

    let out = dir.join("view.html");
    let status = Command::new(bin())
        .args(["view", "--no-open", "--session"])
        .arg(&log)
        .arg("--out")
        .arg(&out)
        .status()
        .unwrap();
    assert!(status.success());

    let after = std::fs::read(&log).unwrap();
    assert_eq!(before, after, "view must never mutate the JSONL log");

    std::fs::remove_dir_all(&dir).ok();
}
