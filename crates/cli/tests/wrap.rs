//! Integration test (brief §8.5): wrapping a trivial command records events,
//! produces a valid chain, and exits with the child's exit code.
//!
//! Unix-only: the PTY path uses `forkpty`. (Windows `ConPTY` hosted under some
//! shells cannot spawn a child console reliably; the tool targets Unix, §2.)

#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_snitchit")
}

fn unique_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("snitchit-it-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn wrap_preserves_exit_code_and_records_a_verifiable_chain() {
    let data = unique_dir("wrap");

    // Wrap a shell that prints and exits non-zero.
    let status = Command::new(bin())
        .args(["--", "sh", "-c", "echo hello from child; exit 7"])
        .env("XDG_DATA_HOME", &data)
        .status()
        .unwrap();
    assert_eq!(
        status.code(),
        Some(7),
        "snitchit must exit with the child's exit code"
    );

    // The recorded chain must verify.
    let verify = Command::new(bin())
        .arg("verify")
        .env("XDG_DATA_HOME", &data)
        .status()
        .unwrap();
    assert!(verify.success(), "recorded chain must verify intact");

    std::fs::remove_dir_all(&data).ok();
}

#[test]
fn wrap_preserves_exit_code_across_the_full_range() {
    // Exit code preservation (brief item 2) must hold for success, ordinary
    // failure, an arbitrary non-zero value, and the 0-255 boundary — not just
    // one hand-picked code.
    for code in [0, 1, 42, 255] {
        let data = unique_dir(&format!("wrap-code-{code}"));
        let status = Command::new(bin())
            .args(["--", "sh", "-c", &format!("exit {code}")])
            .env("XDG_DATA_HOME", &data)
            .status()
            .unwrap();
        assert_eq!(
            status.code(),
            Some(code),
            "snitchit must preserve exit code {code} exactly"
        );
        std::fs::remove_dir_all(&data).ok();
    }
}
