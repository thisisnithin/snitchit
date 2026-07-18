//! Cross-verification (brief §3, §8.5): a chain snitchit writes must pass
//! halo-record's *own* verifier.
//!
//! This test is opt-in because CI has neither Python nor a halo-record checkout
//! (`.context/` is gitignored). Point `SNITCHIT_HALO_SRC` at halo-record's `src`
//! directory to run it; otherwise it is a no-op.
//!
//! ```sh
//! SNITCHIT_HALO_SRC=.context/halo-record/src cargo test -p snitchit-core --test halo_interop
//! ```

use std::process::Command;

use snitchit_core::clock::{new_record_id, now_rfc3339};
use snitchit_core::event::Event;
use snitchit_core::store::Store;

fn python() -> Option<&'static str> {
    ["py", "python3", "python"]
        .into_iter()
        .find(|cand| Command::new(cand).arg("--version").output().is_ok())
}

#[test]
fn halo_record_verifies_a_snitchit_chain() {
    let Ok(halo_src) = std::env::var("SNITCHIT_HALO_SRC") else {
        eprintln!("SNITCHIT_HALO_SRC not set; skipping halo interop cross-check");
        return;
    };
    let Some(py) = python() else {
        eprintln!("no python interpreter found; skipping halo interop cross-check");
        return;
    };

    // Write a small chain via snitchit's own store, mixing every record kind a
    // real session produces — including the kernel-tier exec/connect records.
    // Those go through the SAME constructors on both kernel backends (Linux eBPF
    // and macOS ES/socket-poll), so verifying them here proves halo accepts the
    // record shape both backends emit — they are byte-identical by construction.
    let log = std::env::temp_dir().join(format!("snitchit-halo-{}.jsonl", std::process::id()));
    let _ = std::fs::remove_file(&log);
    {
        let mut store = Store::open(&log).unwrap();
        for cmd in ["ls -la", "cargo build", "git status --porcelain"] {
            let mut ev =
                Event::shell_command("interop", new_record_id(), now_rfc3339(), cmd, "output", 0);
            store.append(&mut ev).unwrap();
        }
        // Kernel-tier exec (both backends call this): program + redacted argv.
        let mut exec = Event::kernel_exec(
            "interop",
            new_record_id(),
            now_rfc3339(),
            "/usr/bin/git",
            "/usr/bin/git commit -m secret",
        );
        store.append(&mut exec).unwrap();
        // Kernel-tier connect (both backends call this): destination host:port.
        for dest in ["1.1.1.1:80", "[2001:db8:0:0:0:0:0:1]:443"] {
            let mut conn = Event::kernel_connect("interop", new_record_id(), now_rfc3339(), dest);
            store.append(&mut conn).unwrap();
        }
    }

    // Verify it with halo-record's verifier.
    let script = format!(
        "import sys; sys.path.insert(0, r'{halo_src}'); \
         from halo_record.verify import verify_log; \
         sys.exit(0 if verify_log(r'{}') else 1)",
        log.display()
    );
    let status = Command::new(py).args(["-c", &script]).status().unwrap();
    std::fs::remove_file(&log).ok();

    assert!(
        status.success(),
        "halo-record's verifier rejected a chain snitchit wrote"
    );
}
