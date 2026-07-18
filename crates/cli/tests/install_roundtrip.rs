//! Integration test (brief §8.5): `install` then `uninstall` leaves the shell
//! rc byte-identical to before, and `install` is idempotent.
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
fn install_is_idempotent_and_uninstall_restores_byte_for_byte() {
    let dir = unique_dir("install");
    let rc = dir.join("shellrc");
    let original = "# my shell rc\nexport PATH=$PATH:/opt/bin\nalias ll='ls -la'\n";
    std::fs::write(&rc, original).unwrap();

    // `install` always wires agent hooks too (no `--hooks` flag exists) — point
    // those at throwaway paths so this test never touches the real machine's
    // ~/.claude/settings.json or ~/.config/opencode/plugins/.
    let settings = dir.join("settings.json");
    let plugin = dir.join("snitchit.js");
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

    // install
    assert!(run("install").success());
    let installed = std::fs::read_to_string(&rc).unwrap();
    assert!(installed.contains("snitchit shims"));
    assert!(installed.contains("command snitchit -- claude"));
    assert_ne!(installed, original);

    // install again — must not duplicate the block
    assert!(run("install").success());
    let installed_twice = std::fs::read_to_string(&rc).unwrap();
    assert_eq!(installed, installed_twice, "install must be idempotent");

    // uninstall — must restore the original exactly
    assert!(run("uninstall").success());
    let restored = std::fs::read_to_string(&rc).unwrap();
    assert_eq!(restored, original, "uninstall must be byte-identical");

    std::fs::remove_dir_all(&dir).ok();
}
