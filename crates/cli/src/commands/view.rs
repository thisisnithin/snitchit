//! `snitchit view` — render a session's recorded log as a self-contained,
//! offline static HTML file and open it in the browser.
//!
//! Strictly additive and read-only: this module never writes to `~/.snitchit/`
//! and never touches the core, the schema, or the store's write path — it only
//! calls the same read (`store::read_values`) and integrity
//! (`snitchit_core::verify_values`) functions `log`/`verify` already use, then
//! renders what's already in each record. It invents no data and reconstructs
//! no raw values: the log only ever contains redacted summaries and
//! `sha256:` hashes, and that's exactly what the viewer shows.
//!
//! The **entire** output is one HTML file with the records (as JSON), the CSS,
//! and the JS all inlined — no `<link>`/`<script src>`, no CDN, no fonts, no
//! server, no network calls of any kind. It must open and fully work via
//! `file://` with the browser offline.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use serde_json::Value;
use snitchit_core::{store, verify_values};

use crate::cli::ViewArgs;

/// Render `path`'s log to HTML and (unless `--no-open`) open it in a browser.
pub fn view(path: &Path, args: &ViewArgs) -> Result<()> {
    let values =
        store::read_values(path).with_context(|| format!("reading log {}", path.display()))?;
    let report = verify_values(&values);

    let session_label = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("session")
        .to_string();

    let html = render_html(
        &session_label,
        &values,
        report.ok,
        report.count,
        report.broken_at.as_ref(),
    )
    .context("rendering HTML")?;

    let out_path = match &args.out {
        Some(p) => PathBuf::from(p),
        None => default_out_path(&session_label),
    };
    if let Some(parent) = out_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
    }
    std::fs::write(&out_path, html).with_context(|| format!("writing {}", out_path.display()))?;

    println!("snitchit: wrote {}", out_path.display());

    if args.no_open {
        return Ok(());
    }
    if open_in_browser(&out_path) {
        println!("snitchit: opened in your browser");
    } else {
        println!(
            "snitchit: could not open a browser automatically — open {} manually",
            out_path.display()
        );
    }
    Ok(())
}

/// A deterministic temp path for a session: `<temp>/snitchit/views/<session>.html`.
/// Kept under a dedicated `snitchit/views/` directory (not loose in the temp
/// root) so the derived HTML artifacts stay contained; the fixed name means
/// repeated `view` calls for the same session overwrite rather than pile up.
/// The caller creates the parent directory before writing.
fn default_out_path(session_label: &str) -> PathBuf {
    std::env::temp_dir()
        .join("snitchit")
        .join("views")
        .join(format!("{session_label}.html"))
}

/// Best-effort: try the platform opener. Returns whether it looked like it
/// worked (spawned and exited successfully) — never fails the command if it
/// didn't, per the observe-only/never-block spirit (the caller falls back to
/// printing the path).
fn open_in_browser(path: &Path) -> bool {
    #[cfg(target_os = "macos")]
    {
        Command::new("open")
            .arg(path)
            .status()
            .is_ok_and(|s| s.success())
    }
    #[cfg(target_os = "linux")]
    {
        Command::new("xdg-open")
            .arg(path)
            .status()
            .is_ok_and(|s| s.success())
    }
    #[cfg(target_os = "windows")]
    {
        // `cmd /C start "" <path>` — the empty title arg keeps `start` from
        // treating a quoted path as the window title.
        Command::new("cmd")
            .args(["/C", "start", ""])
            .arg(path)
            .status()
            .is_ok_and(|s| s.success())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = path;
        false
    }
}

/// Build the full, self-contained HTML document.
fn render_html(
    session_label: &str,
    values: &[Value],
    chain_ok: bool,
    chain_count: usize,
    broken_at: Option<&(usize, String)>,
) -> Result<String> {
    let broken_at_json = match broken_at {
        Some((index, reason)) => serde_json::json!({ "index": index, "reason": reason }),
        None => Value::Null,
    };
    let payload = serde_json::json!({
        "session": session_label,
        "verify": { "ok": chain_ok, "count": chain_count, "brokenAt": broken_at_json },
        "records": values,
    });
    let data_json = serde_json::to_string(&payload).context("serializing embedded data")?;
    // Every `<` in the serialized JSON necessarily sits inside a string value
    // (JSON's own structural syntax never contains `<`), so replacing it with
    // the equivalent `<` escape is always valid JSON and can never allow
    // a literal `</script`, `<script`, or `<!--` sequence to appear in the
    // document — the one thing that could break out of the embedding context.
    let data_json_safe = data_json.replace('<', "\\u003c");

    Ok(format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>snitchit — {session_label}</title>
<style>
{CSS}
</style>
</head>
<body>
<div id="app">
  <header id="header">
    <h1>snitchit</h1>
    <div id="session-meta"></div>
    <div id="chain-banner"></div>
  </header>

  <section id="controls">
    <div class="control-group">
      <span class="control-label">Source</span>
      <label><input type="checkbox" class="f-source" value="pty" checked> pty</label>
      <label><input type="checkbox" class="f-source" value="hook" checked> hook</label>
      <label><input type="checkbox" class="f-source" value="ebpf" checked> ebpf</label>
    </div>
    <div class="control-group">
      <span class="control-label">Action</span>
      <label><input type="checkbox" class="f-type" value="tool_call" checked> tool_call</label>
      <label><input type="checkbox" class="f-type" value="read" checked> read</label>
      <label><input type="checkbox" class="f-type" value="write" checked> write</label>
      <label><input type="checkbox" class="f-type" value="network" checked> network</label>
      <label><input type="checkbox" class="f-type" value="agent_message" checked> agent_message</label>
    </div>
    <div class="control-group">
      <span class="control-label">Outcome</span>
      <select id="f-status">
        <option value="">any</option>
        <option value="ok">ok</option>
        <option value="error">error</option>
        <option value="denied">denied</option>
        <option value="__none__">no outcome</option>
      </select>
    </div>
    <div class="control-group">
      <span class="control-label">Min severity</span>
      <select id="f-severity">
        <option value="0">INFO</option>
        <option value="1">LOW</option>
        <option value="2">MEDIUM</option>
        <option value="3">HIGH</option>
        <option value="4">CRITICAL</option>
      </select>
    </div>
    <div class="control-group control-search">
      <input id="f-search" type="text" placeholder="Search tool / input / outcome…">
    </div>
  </section>

  <div id="count"></div>
  <main id="timeline"></main>
</div>

<script type="application/json" id="snitchit-data">{data_json_safe}</script>
<script>
{JS}
</script>
</body>
</html>
"#,
        session_label = session_label,
        CSS = CSS,
        JS = JS,
        data_json_safe = data_json_safe,
    ))
}

const CSS: &str = include_str!("view_assets/style.css");
const JS: &str = include_str!("view_assets/app.js");
