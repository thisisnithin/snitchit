//! PTY collector — the terminal-surface collector (brief §2, §5).
//!
//! Spawns the target agent inside a pseudo-terminal and transparently pumps the
//! user's real stdin/stdout through it, so the interactive experience is
//! unchanged. It captures two honest things from the terminal surface — never
//! a resolved, executed command (see [`crate::hook`] for that):
//!
//! - the process invocation itself (resolved program + full argv), and its
//!   exit code and transcript, as one [`Event::process_run`] record;
//! - each line of terminal *input* submitted to the agent, as heuristic
//!   [`Event::command_submitted`] records (brief §5 explicitly allows a
//!   pragmatic segmentation here).
//!
//! Coverage caveat (documented in the README too): a PTY sees the *terminal
//! surface*. An agent's in-process tool calls (file reads/writes it performs
//! internally) never touch this terminal and require the hooks collector
//! ([`crate::hook`]) for that fidelity.
//!
//! Cross-platform: `portable-pty` gives a `forkpty` on Unix and a `ConPTY` on
//! Windows behind one API; `crossterm` gives raw mode and terminal size on both.
//! There is no OS branch in this file.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crossbeam_channel::{Receiver, Sender};
use portable_pty::{native_pty_system, ChildKiller, CommandBuilder, MasterPty, PtySize};
use snitchit_core::clock::{new_record_id, now_rfc3339};
use snitchit_core::event::Event;
use snitchit_core::source::{EventSink, EventSource};
use snitchit_core::CoreError;

use crate::error::{CollectorError, Result};

mod resolve;
use resolve::resolve_program;

/// Map any collector-side error into a core seam error (the `EventSource` trait
/// is defined in the core and speaks `CoreError`).
fn seam(msg: impl std::fmt::Display) -> CoreError {
    CoreError::Source(msg.to_string())
}

/// Wraps an agent in a PTY and records its terminal surface.
pub struct PtyCollector {
    session_id: String,
    program: String,
    program_path: PathBuf,
    args: Vec<String>,
    // Runtime state, populated by `start`.
    child: Option<Box<dyn portable_pty::Child + Send + Sync>>,
    killer: Option<Box<dyn ChildKiller + Send + Sync>>,
    // The resize-watcher thread owns the PTY master for the collector's whole
    // lifetime: it must outlive the child (some platforms tear the pseudo-
    // terminal down early and lose all output if the master drops sooner), and
    // while it's alive it watches for terminal resize (SIGWINCH on Unix,
    // polling on Windows) and propagates the new size via `MasterPty::resize`
    // (TIOCSWINSZ). Told to drop the master via `resize_shutdown`, then joined,
    // in `wait()` — this is what used to be a plain `Option<Box<dyn MasterPty>>`
    // field kept only for its deferred-drop ordering.
    resize_thread: Option<JoinHandle<()>>,
    resize_shutdown: Option<Sender<()>>,
    output_handle: Option<JoinHandle<String>>,
    sink: Option<EventSink>,
    raw_enabled: bool,
}

impl PtyCollector {
    /// Build a collector for `argv` (`[program, args...]`), resolving the program
    /// to a real absolute path (recursion safety, brief §5).
    pub fn new(session_id: impl Into<String>, argv: &[String]) -> Result<Self> {
        let (program, args) = argv.split_first().ok_or(CollectorError::EmptyCommand)?;
        let program_path =
            resolve_program(program).ok_or_else(|| CollectorError::NotFound(program.clone()))?;
        Ok(Self {
            session_id: session_id.into(),
            program: program.clone(),
            program_path,
            args: args.to_vec(),
            child: None,
            killer: None,
            resize_thread: None,
            resize_shutdown: None,
            output_handle: None,
            sink: None,
            raw_enabled: false,
        })
    }

    /// The resolved absolute path of the program to be run.
    #[must_use]
    pub fn program_path(&self) -> &PathBuf {
        &self.program_path
    }

    fn argv_display(&self) -> String {
        std::iter::once(self.program.clone())
            .chain(self.args.iter().cloned())
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Block until the wrapped process exits, emit its `process_run` record, and
    /// return the child's exit code. Restores the terminal on the way out.
    pub fn wait(&mut self) -> Result<i32> {
        let Some(mut child) = self.child.take() else {
            return Err(CollectorError::Pty("collector was not started".to_string()));
        };
        let status = child.wait().map_err(CollectorError::Io)?;

        // Tell the resize-watcher thread to drop the master now that the child
        // is done (platform ordering requirement) so the reader thread then
        // reaches EOF, and join it so the drop has actually happened before we
        // proceed.
        if let Some(tx) = self.resize_shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.resize_thread.take() {
            let _ = h.join();
        }

        let transcript = self
            .output_handle
            .take()
            .and_then(|h| h.join().ok())
            .unwrap_or_default();

        self.restore_terminal();

        let exit_code = i32::try_from(status.exit_code()).unwrap_or(1);

        if let Some(sink) = &self.sink {
            let event = Event::process_run(
                &self.session_id,
                new_record_id(),
                now_rfc3339(),
                &self.program,
                &self.argv_display(),
                &transcript,
                exit_code,
            );
            sink.emit(event);
        }

        Ok(exit_code)
    }

    fn restore_terminal(&mut self) {
        if self.raw_enabled {
            // Best-effort: failing to restore raw mode must not panic.
            let _ = crossterm::terminal::disable_raw_mode();
            self.raw_enabled = false;
        }
    }
}

impl EventSource for PtyCollector {
    fn name(&self) -> &str {
        "pty"
    }

    /// Spawn the child in a PTY and begin pumping I/O in background threads.
    /// Returns promptly; call [`PtyCollector::wait`] to block for exit.
    fn start(&mut self, sink: EventSink) -> snitchit_core::Result<()> {
        let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(seam)?;

        let mut cmd = CommandBuilder::new(&self.program_path);
        cmd.args(&self.args);
        if let Ok(cwd) = std::env::current_dir() {
            cmd.cwd(cwd);
        }

        let child = pair.slave.spawn_command(cmd).map_err(seam)?;
        self.killer = Some(child.clone_killer());

        // Drop the slave so the master reader sees EOF once the child exits.
        drop(pair.slave);

        let mut writer = pair.master.take_writer().map_err(seam)?;
        let mut reader = pair.master.try_clone_reader().map_err(seam)?;

        // Raw mode makes passthrough transparent. Best-effort: if the terminal
        // can't go raw (e.g. not a tty in a test/pipe), we still record.
        self.raw_enabled = crossterm::terminal::enable_raw_mode().is_ok();

        // stdin -> pty, with heuristic input-line segmentation into events.
        // Detached: reading real stdin blocks and is torn down at process exit.
        let stdin_sink = sink.clone();
        let stdin_session = self.session_id.clone();
        thread::spawn(move || pump_stdin(&mut writer, &stdin_sink, &stdin_session));

        // pty -> stdout, accumulating the transcript for the process_run record.
        let output_handle = thread::spawn(move || pump_output(&mut reader));

        let (shutdown_tx, shutdown_rx) = crossbeam_channel::bounded(1);
        self.resize_thread = Some(spawn_resize_watcher(pair.master, shutdown_rx));
        self.resize_shutdown = Some(shutdown_tx);
        self.output_handle = Some(output_handle);
        self.child = Some(child);
        self.sink = Some(sink);
        Ok(())
    }

    /// Terminate the child if it is still running and restore the terminal.
    /// Idempotent.
    fn stop(&mut self) -> snitchit_core::Result<()> {
        if let Some(killer) = &mut self.killer {
            let _ = killer.kill();
        }
        self.restore_terminal();
        Ok(())
    }
}

/// Pump real stdin into the PTY, forwarding every byte verbatim and emitting a
/// `command_submitted` event per input line (Enter-delimited).
fn pump_stdin(writer: &mut Box<dyn Write + Send>, sink: &EventSink, session: &str) {
    // macOS quirk (per portable-pty): for very short-lived children, dropping
    // the writer (which happens when this thread ends) too soon races the
    // reader and can swallow output. This thread owns the writer, so a brief
    // grace period here guarantees it can't drop before the child/reader run.
    #[cfg(target_os = "macos")]
    std::thread::sleep(std::time::Duration::from_millis(20));

    let mut stdin = std::io::stdin();
    let mut buf = [0u8; 1024];
    let mut line: Vec<u8> = Vec::new();
    loop {
        match stdin.read(&mut buf) {
            Ok(0) | Err(_) => break, // EOF or read error
            Ok(n) => {
                let chunk = &buf[..n];
                if writer.write_all(chunk).is_err() {
                    break;
                }
                let _ = writer.flush();
                for &b in chunk {
                    match b {
                        b'\r' | b'\n' => {
                            emit_line(&line, sink, session);
                            line.clear();
                        }
                        0x7f | 0x08 => {
                            line.pop(); // backspace
                        }
                        _ => line.push(b),
                    }
                }
            }
        }
    }
    // Flush any trailing unterminated input.
    emit_line(&line, sink, session);
}

fn emit_line(bytes: &[u8], sink: &EventSink, session: &str) {
    let cleaned = sanitize(bytes);
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        return;
    }
    let event = Event::command_submitted(session, new_record_id(), now_rfc3339(), trimmed);
    sink.emit(event);
}

/// Pump PTY output to real stdout, returning the sanitized transcript.
fn pump_output(reader: &mut Box<dyn Read + Send>) -> String {
    let mut stdout = std::io::stdout();
    let mut buf = [0u8; 4096];
    let mut transcript: Vec<u8> = Vec::new();
    loop {
        match reader.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let chunk = &buf[..n];
                let _ = stdout.write_all(chunk);
                let _ = stdout.flush();
                // TODO(scope): cap transcript memory for very long sessions.
                transcript.extend_from_slice(chunk);
            }
        }
    }
    // Only the sanitized transcript is stored/hashed — never raw control bytes.
    sanitize(&transcript)
}

/// Own `master` for the collector's lifetime: watch for terminal resize and
/// propagate it, until told to stop via `shutdown`, then drop `master`.
///
/// This is the one place resize propagation happens; `wait()` only sends the
/// shutdown signal and joins this thread.
fn spawn_resize_watcher(
    master: Box<dyn MasterPty + Send>,
    shutdown: Receiver<()>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        watch_resize(master.as_ref(), &shutdown);
        drop(master);
    })
}

/// Poll interval for the shutdown channel (and, on Windows, for size changes).
/// Short enough that `wait()` doesn't visibly stall waiting for this thread to
/// notice shutdown; long enough not to busy-loop.
const RESIZE_POLL: Duration = Duration::from_millis(50);

/// Unix: block for `SIGWINCH`, then propagate the new size via `TIOCSWINSZ`
/// (through `MasterPty::resize`). Falls back to just waiting for shutdown if
/// the signal handler can't be installed — resize propagation is best-effort,
/// never fatal (observe-only, brief §8.3).
#[cfg(unix)]
fn watch_resize(master: &dyn MasterPty, shutdown: &Receiver<()>) {
    use signal_hook::consts::SIGWINCH;
    use signal_hook::iterator::Signals;

    let Ok(mut signals) = Signals::new([SIGWINCH]) else {
        let _ = shutdown.recv();
        return;
    };
    loop {
        if shutdown.recv_timeout(RESIZE_POLL).is_ok() {
            return;
        }
        if signals.pending().next().is_some() {
            if let Ok((cols, rows)) = crossterm::terminal::size() {
                let _ = master.resize(PtySize {
                    rows,
                    cols,
                    pixel_width: 0,
                    pixel_height: 0,
                });
            }
        }
    }
}

/// Windows has no `SIGWINCH`; `ConPTY` doesn't auto-propagate console resizes
/// either, so poll the terminal size and resize the pseudoconsole on change.
#[cfg(windows)]
fn watch_resize(master: &dyn MasterPty, shutdown: &Receiver<()>) {
    let mut last = crossterm::terminal::size().ok();
    loop {
        if shutdown.recv_timeout(RESIZE_POLL).is_ok() {
            return;
        }
        if let Ok(current) = crossterm::terminal::size() {
            if Some(current) != last {
                let (cols, rows) = current;
                let _ = master.resize(PtySize {
                    rows,
                    cols,
                    pixel_width: 0,
                    pixel_height: 0,
                });
                last = Some(current);
            }
        }
    }
}

/// Strip ANSI escape sequences and control bytes, yielding readable text.
///
/// Pragmatic (brief §5): handles CSI (`ESC [ … final`) and OSC (`ESC ] … BEL`)
/// sequences and drops remaining C0 control characters. It is not a full
/// terminal emulator. `// TODO(scope): richer terminal parsing if needed.`
fn sanitize(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes);
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            match chars.peek() {
                Some('[') => {
                    chars.next();
                    while let Some(&n) = chars.peek() {
                        chars.next();
                        if ('@'..='~').contains(&n) {
                            break; // CSI final byte
                        }
                    }
                }
                Some(']') => {
                    chars.next();
                    while let Some(&n) = chars.peek() {
                        chars.next();
                        if n == '\u{7}' {
                            break; // OSC terminated by BEL
                        }
                    }
                }
                _ => {
                    chars.next();
                }
            }
            continue;
        }
        // Keep newlines/tabs so multi-line output stays legible; drop other C0.
        if c == '\n' || c == '\t' || (c as u32) >= 0x20 {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_ansi_and_controls() {
        let raw = b"\x1b[31mred\x1b[0m\x07 text\x08";
        assert_eq!(sanitize(raw), "red text");
    }

    #[test]
    fn sanitize_keeps_newlines_and_tabs() {
        assert_eq!(sanitize(b"a\tb\nc"), "a\tb\nc");
    }

    #[test]
    fn sanitize_strips_osc_title_sequence() {
        // OSC 0 ; set-title BEL
        let raw = b"\x1b]0;my title\x07hello";
        assert_eq!(sanitize(raw), "hello");
    }

    #[test]
    fn new_resolves_program() {
        let argv = vec!["cargo".to_string(), "--version".to_string()];
        let c = PtyCollector::new("s", &argv);
        assert!(c.is_ok());
        assert!(c.unwrap().program_path().is_absolute());
    }

    #[test]
    fn new_rejects_empty_and_missing() {
        assert!(PtyCollector::new("s", &[]).is_err());
        assert!(PtyCollector::new("s", &["no-such-bin-xyzzy-42".to_string()]).is_err());
    }
}
