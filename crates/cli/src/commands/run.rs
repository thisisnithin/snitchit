//! `snitchit -- <cmd> [args...]` — wrap the agent, record, and pass through.

use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};
use snitchit_collectors::{CollectorError, PtyCollector};
use snitchit_core::source::EventSource;
use snitchit_core::{channel, clock, Store};

/// Run `argv` under recording and return the child's exit code.
///
/// Design principle #1 (observe-only): if the PTY recorder can't be set up, the
/// agent still runs — we fall back to a direct exec without recording rather
/// than failing the user's command.
pub fn run(argv: &[String]) -> Result<i32> {
    let Some(program) = argv.first() else {
        bail!("nothing to run: use `snitchit -- <command> [args...]`");
    };

    // Never record without a working redaction engine — that could leak raw
    // secrets into the log. Fail fast (this only fails on a broken build).
    snitchit_core::redact::validate()
        .context("redaction engine unavailable — refusing to record")?;

    let session = session_id(program);
    let path =
        snitchit_core::store::session_path(&session).context("computing session log path")?;
    let mut store =
        Store::open(&path).with_context(|| format!("opening log {}", path.display()))?;

    // Correlate any agent hooks fired during this session (if the hooks
    // collector is installed) to THIS log. The wrapped agent — and the
    // `snitchit hook` child it spawns per tool call — inherit these.
    // Safe here: still single-threaded, before any collector thread starts.
    std::env::set_var("SNITCHIT_LOG", &path);
    std::env::set_var("SNITCHIT_SESSION", &session);

    let (sink, stream) = channel();

    // Kernel-observation tier (Linux, eBPF). Started BEFORE the child is spawned
    // so the agent's own fork/exec is already in scope. Best-effort: if it can't
    // load (no privilege, kernel, or BTF) we log and continue with PTY + hooks —
    // never blocking the agent (design principle #1). Scoped to snitchit's own
    // process tree via its pid.
    #[cfg(target_os = "linux")]
    let mut kernel = {
        // Fallback seed: our pid (correct on non-namespaced Linux). Under a pid
        // namespace it won't match the kernel's view, so the collector also
        // self-identifies to the eBPF side via a sentinel probe (see kernel.rs).
        let mut kc = snitchit_collectors::KernelCollector::new(session.clone(), std::process::id());
        match kc.start(sink.clone()) {
            Ok(()) => {
                eprintln!("snitchit: kernel collector active (eBPF: exec + connect)");
                Some(kc)
            }
            Err(e) => {
                eprintln!(
                    "snitchit: kernel collector unavailable ({e}); continuing with PTY + hooks"
                );
                None
            }
        }
    };

    // Kernel-observation tier (macOS) — the counterpart to the Linux eBPF block
    // above, selected by cfg (never a runtime OS branch). macOS observes exec and
    // connect through two different mechanisms, so it starts two collectors, each
    // best-effort and independent: if one is unavailable we log and continue with
    // whatever else works (design principle #1). macOS has no pid namespaces, so
    // our own pid is the kernel-visible tree root.
    //
    //  * Endpoint Security → exec. Needs root + entitlement/dev-mode.
    //  * Socket-table poll  → outbound connect. No entitlement, and no root for
    //    the agent's own tree; best-effort/TCP-only (see the macos_connect docs).
    #[cfg(target_os = "macos")]
    let mut kernel = {
        let mut kc = snitchit_collectors::EndpointSecurityCollector::new(
            session.clone(),
            std::process::id(),
        );
        match kc.start(sink.clone()) {
            Ok(()) => {
                eprintln!("snitchit: kernel collector active (Endpoint Security: exec)");
                Some(kc)
            }
            Err(e) => {
                eprintln!(
                    "snitchit: kernel collector unavailable ({e}); continuing with PTY + hooks"
                );
                None
            }
        }
    };

    #[cfg(target_os = "macos")]
    let mut connect = start_connect_collector(&session, &sink);

    let mut collector = match PtyCollector::new(session.clone(), argv) {
        Ok(c) => c,
        Err(CollectorError::NotFound(p)) => bail!("command not found on PATH: {p}"),
        Err(e) => bail!("cannot set up recorder: {e}"),
    };

    if let Err(e) = collector.start(sink.clone()) {
        eprintln!("snitchit: recording unavailable ({e}); running without recording");
        return fallback_exec(collector.program_path(), &argv[1..]);
    }

    let code = collector.wait().unwrap_or_else(|e| {
        eprintln!("snitchit: {e}");
        1
    });
    let _ = collector.stop();

    // Detach the kernel collector(s) and join their workers (drops their sink
    // clones) before we drain, so emitted events are in the stream and the chain.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if let Some(kc) = &mut kernel {
        let _ = kc.stop();
    }
    #[cfg(target_os = "macos")]
    if let Some(cc) = &mut connect {
        let _ = cc.stop();
    }

    // Release every sink we hold so nothing keeps the stream artificially open,
    // then drain the buffered events into the sealed chain in order.
    drop(sink);
    drop(collector);

    let mut recorded = 0usize;
    for mut event in stream.try_iter() {
        match store.append(&mut event) {
            Ok(()) => recorded += 1,
            Err(e) => eprintln!("snitchit: failed to record an event: {e}"),
        }
    }

    eprintln!(
        "snitchit: recorded {recorded} event(s) to {}",
        path.display()
    );
    Ok(code)
}

/// Start the macOS outbound-connection collector (socket-table polling). Kept
/// out of `run` so that function stays readable; best-effort like every tier.
#[cfg(target_os = "macos")]
fn start_connect_collector(
    session: &str,
    sink: &snitchit_core::source::EventSink,
) -> Option<snitchit_collectors::MacosConnectCollector> {
    let mut cc = snitchit_collectors::MacosConnectCollector::new(session, std::process::id());
    match cc.start(sink.clone()) {
        Ok(()) => {
            eprintln!("snitchit: connect collector active (socket poll: outbound TCP)");
            Some(cc)
        }
        Err(e) => {
            eprintln!("snitchit: connect collector unavailable ({e}); continuing");
            None
        }
    }
}

/// Run the resolved program directly, inheriting stdio (no recording).
fn fallback_exec(program: &Path, args: &[String]) -> Result<i32> {
    let status = Command::new(program)
        .args(args)
        .status()
        .with_context(|| format!("running {} directly", program.display()))?;
    Ok(status.code().unwrap_or(1))
}

/// Derive a filesystem-safe session id from the timestamp and program name.
fn session_id(program: &str) -> String {
    let ts: String = clock::now_rfc3339()
        .chars()
        .filter(char::is_ascii_digit)
        .collect();
    let base = Path::new(program)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("session");
    format!("{ts}-{base}")
}
