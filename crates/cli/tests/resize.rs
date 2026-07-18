//! Integration test: terminal resize propagates end-to-end through snitchit to
//! the wrapped child (brief item 2 — winsize propagation, automated).
//!
//! We spawn the real `snitchit` binary attached to an OUTER pty we create and
//! control ourselves — standing in for "the real terminal" — wrapping a child
//! that loops calling `stty size` (a direct `TIOCGWINSZ` read, independent of
//! the child's own signal bookkeeping). We then resize the OUTER pty (exactly
//! what a terminal emulator does on a window resize) and confirm the reported
//! size changes to the new one. This exercises the real path: our resize on
//! the outer pty → kernel `SIGWINCH` to snitchit (the process attached to that
//! pty) → snitchit's resize-watcher thread → `MasterPty::resize` (`TIOCSWINSZ`)
//! on snitchit's *own* inner pty → the wrapped `bash` sees the new size.
//!
//! Unix-only: PTYs and `SIGWINCH` are POSIX; Windows has no such signal (the
//! collector polls instead — see `crates/collectors/src/pty.rs`).

#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Read;
use std::time::{Duration, Instant};

use portable_pty::{native_pty_system, CommandBuilder, PtySize};

#[test]
fn resize_propagates_from_the_outer_terminal_to_the_wrapped_child() {
    let pty_system = native_pty_system();
    let outer = pty_system
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("open outer pty");

    // The wrapped child polls its own controlling terminal's size directly via
    // `stty size` (a TIOCGWINSZ ioctl) — independent of whether bash's own
    // WINCH bookkeeping has caught up, so this reflects the live kernel state.
    let mut cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_snitchit"));
    cmd.args([
        "--",
        "bash",
        "-c",
        "while true; do stty size; sleep 0.05; done",
    ]);
    cmd.env(
        "XDG_DATA_HOME",
        std::env::temp_dir().join("snitchit-resize-test"),
    );

    let mut child = outer
        .slave
        .spawn_command(cmd)
        .expect("spawn snitchit in outer pty");
    drop(outer.slave); // reader sees EOF once the child tree exits

    let mut reader = outer.master.try_clone_reader().expect("clone outer reader");

    // Drain output in a background thread so the child never blocks on a full
    // pty buffer; collect it for inspection after we're done.
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let mut acc = String::new();
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    acc.push_str(&String::from_utf8_lossy(&buf[..n]));
                    let _ = tx.send(acc.clone());
                }
            }
        }
    });

    // Give snitchit + bash time to start and print at least one "24 80" line
    // at the original size before we resize.
    wait_until(Duration::from_secs(5), &rx, |s| s.contains("24 80"))
        .expect("child should report the initial 24x80 size before resize");

    // This is exactly what a terminal emulator does on a window resize.
    outer
        .master
        .resize(PtySize {
            rows: 50,
            cols: 200,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("resize outer pty");

    // The wrapped child must observe the NEW size — proof the resize crossed
    // both PTY boundaries (outer -> snitchit -> inner -> child).
    let saw_new_size = wait_until(Duration::from_secs(5), &rx, |s| s.contains("50 200"));

    let _ = child.kill();
    let _ = child.wait();

    assert!(
        saw_new_size.is_ok(),
        "wrapped child never observed the propagated 50x200 size"
    );
}

/// Poll `rx` for up to `timeout`, returning `Ok(())` as soon as `pred` matches
/// the latest accumulated output, or `Err(())` on timeout.
fn wait_until(
    timeout: Duration,
    rx: &std::sync::mpsc::Receiver<String>,
    pred: impl Fn(&str) -> bool,
) -> Result<(), ()> {
    let deadline = Instant::now() + timeout;
    let mut latest = String::new();
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(s) => {
                latest = s;
                if pred(&latest) {
                    return Ok(());
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    if pred(&latest) {
        Ok(())
    } else {
        Err(())
    }
}
