//! Persistence: the hash-chained JSONL log (brief §3, §4).
//!
//! The log is halo-record's on-disk form — one compact JSON record per line,
//! appended in order, each sealed into the hash chain. This is the source of
//! truth (no `SQLite` index in the MVP; the JSONL chain is the required
//! artifact).
//!
//! Storage-location rule (security, brief §2): logs live under `~/.snitchit/`
//! (or `$XDG_DATA_HOME/snitchit` when set), **never** inside the agent's working
//! tree. The recorder (parent) owns the log; the wrapped agent (child) has no
//! reason or easy path to reach it.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::canon::GENESIS_PREV;
use crate::error::{CoreError, Result};
use crate::event::Event;

/// An append-only writer that maintains the hash chain in a JSONL file.
///
/// One `Store` owns a given log file per process. The chain head is cached after
/// open so each append is O(1) rather than re-scanning the file.
#[derive(Debug)]
pub struct Store {
    path: PathBuf,
    head: String,
}

impl Store {
    /// Open (creating parent directories) the log at `path`, reading the current
    /// chain head. The directory is created with restrictive permissions on Unix.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            ensure_dir(parent)?;
        }
        // A transient read failure here (e.g. another process holds the append
        // lock — mandatory on Windows) must not fail open: `append` re-reads the
        // authoritative head under its own lock before every write.
        let head = read_head(&path).unwrap_or_else(|_| GENESIS_PREV.to_string());
        Ok(Self { path, head })
    }

    /// The log file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The current chain head hash (genesis zeros if the log is empty).
    #[must_use]
    pub fn head(&self) -> &str {
        &self.head
    }

    /// Seal `event` against the current head and append it as one JSONL line.
    ///
    /// Cross-process safe: several `snitchit hook` processes (fired by the agent
    /// for parallel tool calls) plus the PTY drain can all target the same log.
    /// We take an exclusive advisory lock on the file, re-read the authoritative
    /// head from disk (our cached head may be stale if another process appended),
    /// seal against it, append, `fsync`, then unlock. `File::lock` is stable
    /// since Rust 1.89.
    pub fn append(&mut self, event: &mut Event) -> Result<()> {
        // Open read+write (not append) so we can both read the head and write
        // through a *single* handle. A second handle would deadlock against our
        // own exclusive lock on Windows, where locks are mandatory.
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false) // we seek + append manually; never truncate
            .open(&self.path)?;
        file.lock()?;

        // Everything between lock and unlock is guarded so a `?` early-return
        // still releases the lock.
        let result = (|| -> Result<String> {
            let mut contents = String::new();
            file.seek(SeekFrom::Start(0))?;
            file.read_to_string(&mut contents)?;
            let head = last_hash(&contents);

            let hash = event.seal(&head)?;
            let line = serde_json::to_string(event)?;

            file.seek(SeekFrom::End(0))?;
            file.write_all(line.as_bytes())?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            Ok(hash)
        })();

        let _ = file.unlock();
        let hash = result?;
        self.head = hash;
        Ok(())
    }
}

/// The base data directory: `$XDG_DATA_HOME/snitchit` if set, else `~/.snitchit`.
pub fn data_dir() -> Result<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
        if !xdg.is_empty() {
            return Ok(PathBuf::from(xdg).join("snitchit"));
        }
    }
    let home = dirs_home().ok_or_else(|| {
        CoreError::Io(std::io::Error::other("could not determine home directory"))
    })?;
    Ok(home.join(".snitchit"))
}

/// The JSONL log path for `session_id` under [`data_dir`].
pub fn session_path(session_id: &str) -> Result<PathBuf> {
    Ok(data_dir()?.join(format!("{}.jsonl", sanitize(session_id))))
}

/// List existing session logs, most-recently-modified first.
pub fn list_sessions() -> Result<Vec<PathBuf>> {
    let dir = data_dir()?;
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut entries: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("jsonl") {
            let mtime = entry
                .metadata()
                .and_then(|m| m.modified())
                .unwrap_or(std::time::UNIX_EPOCH);
            entries.push((mtime, path));
        }
    }
    entries.sort_by_key(|(mtime, _)| std::cmp::Reverse(*mtime));
    Ok(entries.into_iter().map(|(_, p)| p).collect())
}

/// The most-recently-modified session log, if any.
pub fn latest_session() -> Result<Option<PathBuf>> {
    Ok(list_sessions()?.into_iter().next())
}

/// Read every record of a log as raw parsed JSON (for `verify`).
pub fn read_values(path: &Path) -> Result<Vec<Value>> {
    let mut out = Vec::new();
    for (i, line) in read_lines(path)?.into_iter().enumerate() {
        let value: Value = serde_json::from_str(&line)
            .map_err(|source| CoreError::RecordJson { index: i, source })?;
        out.push(value);
    }
    Ok(out)
}

/// Read every record of a log as typed [`Event`]s (for `log` rendering).
pub fn read_events(path: &Path) -> Result<Vec<Event>> {
    let mut out = Vec::new();
    for (i, line) in read_lines(path)?.into_iter().enumerate() {
        let event: Event = serde_json::from_str(&line)
            .map_err(|source| CoreError::RecordJson { index: i, source })?;
        out.push(event);
    }
    Ok(out)
}

// --- internals --------------------------------------------------------------

fn read_lines(path: &Path) -> Result<Vec<String>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut lines = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if !line.trim().is_empty() {
            lines.push(line);
        }
    }
    Ok(lines)
}

fn read_head(path: &Path) -> Result<String> {
    if !path.exists() {
        return Ok(GENESIS_PREV.to_string());
    }
    let contents = fs::read_to_string(path)?;
    Ok(last_hash(&contents))
}

/// The `integrity.hash` of the last non-empty JSONL line, or the genesis zeros.
fn last_hash(contents: &str) -> String {
    contents
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .and_then(|l| serde_json::from_str::<Value>(l).ok())
        .and_then(|v| v["integrity"]["hash"].as_str().map(String::from))
        .unwrap_or_else(|| GENESIS_PREV.to_string())
}

fn dirs_home() -> Option<PathBuf> {
    dirs::home_dir()
}

/// Keep a session id safe as a filename component.
fn sanitize(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches(['.', '_']);
    if trimmed.is_empty() {
        "session".to_string()
    } else {
        trimmed.to_string()
    }
}

fn ensure_dir(dir: &Path) -> Result<()> {
    // Whether we are about to create the leaf ourselves. We only harden dirs we
    // create — never a pre-existing parent like `/tmp` we don't own. The binding
    // is Unix-only so it doesn't warn as unused elsewhere.
    #[cfg(unix)]
    let newly_created = !dir.exists();
    fs::create_dir_all(dir)?;
    // Harden the log directory: owner-only on Unix (the recorder owns it; the
    // wrapped agent must not read/modify it). Compile-time cfg, not a runtime
    // OS branch — the core stays platform-agnostic in behavior. Best-effort:
    // failing to chmod (unowned dir, or a filesystem without Unix perms such as
    // a Windows DrvFs mount) must never fail recording — observe-only, §8.3.
    #[cfg(unix)]
    if newly_created {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::verify_values;

    fn tmp_log() -> PathBuf {
        let mut p = std::env::temp_dir();
        // Unique-ish per-test name without pulling in rand: nanos since epoch.
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        p.push(format!("snitchit-test-{n}.jsonl"));
        p
    }

    fn ev(cmd: &str, n: usize) -> Event {
        Event::shell_command(
            "unit",
            format!("rec-{n}"),
            "2026-07-15T00:00:00Z".to_string(),
            cmd,
            "out",
            0,
        )
    }

    #[test]
    fn append_reload_and_verify_roundtrip() {
        let path = tmp_log();
        {
            let mut store = Store::open(&path).unwrap();
            for i in 0..4 {
                let mut e = ev(&format!("cmd-{i}"), i);
                store.append(&mut e).unwrap();
            }
        }
        // Reopen: head must be recovered from disk.
        let store = Store::open(&path).unwrap();
        assert_ne!(store.head(), GENESIS_PREV);

        let values = read_values(&path).unwrap();
        assert_eq!(values.len(), 4);
        assert!(verify_values(&values).ok);

        // Chain continues correctly across a reopen.
        let mut store = Store::open(&path).unwrap();
        let mut e = ev("cmd-4", 4);
        store.append(&mut e).unwrap();
        let values = read_values(&path).unwrap();
        assert_eq!(values.len(), 5);
        assert!(verify_values(&values).ok);

        fs::remove_file(&path).ok();
    }

    #[test]
    fn concurrent_appends_keep_the_chain_valid() {
        // Each iteration opens a fresh Store (like separate `snitchit hook`
        // processes), so correctness rests entirely on the file lock + head
        // re-read, not on any in-process cache.
        let path = tmp_log();
        let handles: Vec<_> = (0..4)
            .map(|t| {
                let p = path.clone();
                std::thread::spawn(move || {
                    for i in 0..10 {
                        let mut store = Store::open(&p).unwrap();
                        let mut e = ev(&format!("t{t}-cmd{i}"), i);
                        store.append(&mut e).unwrap();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }

        let values = read_values(&path).unwrap();
        assert_eq!(values.len(), 40);
        assert!(
            verify_values(&values).ok,
            "concurrent appends must not break the hash chain"
        );
        fs::remove_file(&path).ok();
    }

    #[test]
    fn tampering_with_the_file_breaks_verification() {
        let path = tmp_log();
        {
            let mut store = Store::open(&path).unwrap();
            for i in 0..3 {
                let mut e = ev(&format!("cmd-{i}"), i);
                store.append(&mut e).unwrap();
            }
        }
        let mut values = read_values(&path).unwrap();
        values[1]["action"]["tool"] = Value::String("hacked".into());
        let report = verify_values(&values);
        assert!(!report.ok);
        assert_eq!(report.broken_at.map(|(i, _)| i), Some(1));
        fs::remove_file(&path).ok();
    }
}
