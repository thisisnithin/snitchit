//! Integration tests: signals typed at the (outer, real) terminal reach the
//! wrapped child (brief item 2 — Ctrl-C/Ctrl-D forwarding, automated).
//!
//! Same nested-PTY harness as `resize.rs`: snitchit runs attached to an OUTER
//! pty we control, standing in for the real terminal. We write raw control
//! bytes into the outer pty (exactly what a keyboard driver does) and confirm
//! the WRAPPED child (attached to snitchit's own INNER pty) reacts.
//!
//! Why this works without snitchit doing anything special: snitchit puts its
//! own controlling terminal (the outer pty) into raw mode, which disables the
//! outer terminal's signal generation (`ISIG`) — so Ctrl-C/Ctrl-D pass through
//! as plain bytes rather than becoming signals *there*. Those bytes then flow,
//! unmodified, into the INNER pty snitchit created for the child, whose slave
//! is still in normal cooked mode — so the *kernel* (not any code of ours)
//! converts them into `SIGINT`/EOF for the wrapped child's foreground process
//! group. This is standard PTY nesting semantics; these tests exist to prove
//! it actually holds for this codebase, not to reimplement it.
//!
//! Unix-only: PTYs and signals are POSIX.

#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Read, Write};
use std::time::Duration;

use portable_pty::{native_pty_system, CommandBuilder, PtySize};

fn spawn_in_outer_pty(
    script: &str,
) -> (
    Box<dyn portable_pty::MasterPty + Send>,
    Box<dyn portable_pty::Child + Send + Sync>,
) {
    let outer = native_pty_system()
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("open outer pty");
    let mut cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_snitchit"));
    cmd.args(["--", "bash", "-c", script]);
    cmd.env(
        "XDG_DATA_HOME",
        std::env::temp_dir().join("snitchit-signals-test"),
    );
    let child = outer
        .slave
        .spawn_command(cmd)
        .expect("spawn snitchit in outer pty");
    drop(outer.slave);

    // Drain the outer master in the background so the wrapped process never
    // blocks writing its output into a full pty buffer. Without this, snitchit's
    // output-pump thread stalls flushing to the (undrained) outer terminal and
    // its `wait()` never returns, so the child appears to hang. A real terminal
    // emulator always drains; the sibling `resize.rs` test does the same.
    let mut reader = outer.master.try_clone_reader().expect("clone outer reader");
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = reader.read(&mut buf) {
            if n == 0 {
                break;
            }
        }
    });

    (outer.master, child)
}

#[test]
fn ctrl_c_delivers_sigint_to_the_wrapped_child() {
    // Trap INT, mark that it arrived, exit with a distinctive code. `stty sane`
    // first: signal generation from control chars is the *child's* line-
    // discipline behavior (canonical mode + ISIG), and the inner slave's default
    // termios is not identical across platforms (notably macOS vs Linux). We are
    // testing that snitchit forwards the raw byte, so we pin the child side to a
    // known cooked mode rather than depending on the platform default.
    let (master, mut child) =
        spawn_in_outer_pty("stty sane; trap 'echo GOT_INT; exit 42' INT; sleep 30");
    std::thread::sleep(Duration::from_millis(400)); // let the trap install

    let mut writer = master.take_writer().expect("outer writer");
    writer.write_all(&[0x03]).expect("write ctrl-c"); // ETX / Ctrl-C
    writer.flush().ok();
    drop(writer);

    let status = wait_with_timeout(&mut child, Duration::from_secs(5))
        .expect("child should exit after receiving SIGINT, not hang");
    assert_eq!(
        i32::try_from(status.exit_code()).unwrap_or(-1),
        42,
        "the trap's `exit 42` must be snitchit's own exit code"
    );
}

#[test]
fn ctrl_backslash_delivers_sigquit_to_the_wrapped_child() {
    // `stty sane` pins the child's line discipline (see the SIGINT test).
    let (master, mut child) =
        spawn_in_outer_pty("stty sane; trap 'echo GOT_QUIT; exit 43' QUIT; sleep 30");
    std::thread::sleep(Duration::from_millis(400));

    let mut writer = master.take_writer().expect("outer writer");
    writer.write_all(&[0x1c]).expect("write ctrl-\\"); // FS / Ctrl-\
    writer.flush().ok();
    drop(writer);

    let status = wait_with_timeout(&mut child, Duration::from_secs(5))
        .expect("child should exit after receiving SIGQUIT, not hang");
    assert_eq!(i32::try_from(status.exit_code()).unwrap_or(-1), 43);
}

#[test]
fn ctrl_d_delivers_eof_to_the_wrapped_child() {
    // `cat` with no args echoes stdin until EOF, then exits 0. If Ctrl-D
    // doesn't reach it as EOF, it hangs until the timeout and this test fails.
    // `stty sane` pins the child's line discipline (see the SIGINT test) so VEOF
    // is `^D` in canonical mode regardless of the platform's default termios.
    let (master, mut child) = spawn_in_outer_pty("stty sane; cat > /dev/null; exit 0");
    std::thread::sleep(Duration::from_millis(400));

    let mut writer = master.take_writer().expect("outer writer");
    writer.write_all(&[0x04]).expect("write ctrl-d"); // EOT / Ctrl-D
    writer.flush().ok();
    drop(writer);

    let status = wait_with_timeout(&mut child, Duration::from_secs(5))
        .expect("child should exit after receiving EOF, not hang");
    assert_eq!(status.exit_code(), 0);
}

/// Poll `child.try_wait()` up to `timeout`; `None` on timeout (still running).
fn wait_with_timeout(
    child: &mut Box<dyn portable_pty::Child + Send + Sync>,
    timeout: Duration,
) -> Option<portable_pty::ExitStatus> {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if let Ok(Some(status)) = child.try_wait() {
            return Some(status);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    None
}
