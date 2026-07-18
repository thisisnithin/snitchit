//! Resolve a target command to a real executable by absolute path.
//!
//! Recursion safety (brief §5): snitchit must invoke the *real* agent binary,
//! never the shell function `install` (§6) adds — otherwise `claude()` →
//! `snitchit -- claude` → `claude()` would loop forever. Shell functions are not
//! executables on `PATH`, so resolving through `PATH` already sidesteps them;
//! as belt-and-suspenders we also skip snitchit's own binary if it somehow
//! resolves (e.g. a stray shim script named like the agent).

use std::path::{Path, PathBuf};

/// Resolve `program` to an absolute executable path, or `None` if not found.
#[must_use]
pub fn resolve_program(program: &str) -> Option<PathBuf> {
    let candidate = Path::new(program);

    // An explicit path (absolute or containing a separator) is used directly.
    if candidate.is_absolute() || program.contains('/') || program.contains('\\') {
        return canonical_if_exists(candidate);
    }

    let self_exe = std::env::current_exe()
        .ok()
        .and_then(|p| p.canonicalize().ok());

    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        for name in candidate_names(program) {
            let full = dir.join(name);
            if !is_executable(&full) {
                continue;
            }
            let Some(canon) = canonical_if_exists(&full) else {
                continue;
            };
            if self_exe.as_ref() == Some(&canon) {
                continue; // never resolve to ourselves — would recurse
            }
            return Some(canon);
        }
    }
    None
}

fn canonical_if_exists(p: &Path) -> Option<PathBuf> {
    if p.exists() {
        p.canonicalize().ok().map(simplify)
    } else {
        None
    }
}

/// On Windows, `canonicalize` returns an extended-length `\\?\C:\…` path that
/// `CreateProcess`/`ConPTY` often can't spawn. Strip the verbatim prefix for a
/// plain path. No-op on Unix.
#[cfg(windows)]
fn simplify(p: PathBuf) -> PathBuf {
    let s = p.to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{rest}"))
    } else if let Some(rest) = s.strip_prefix(r"\\?\") {
        PathBuf::from(rest.to_string())
    } else {
        p
    }
}

#[cfg(not(windows))]
fn simplify(p: PathBuf) -> PathBuf {
    p
}

/// Candidate filenames to try in each PATH directory. On Windows, append the
/// executable extensions from `PATHEXT` when `program` has none.
fn candidate_names(program: &str) -> Vec<String> {
    #[cfg(windows)]
    {
        if Path::new(program).extension().is_some() {
            return vec![program.to_string()];
        }
        let pathext =
            std::env::var("PATHEXT").unwrap_or_else(|_| ".EXE;.CMD;.BAT;.COM".to_string());
        let mut names = vec![program.to_string()];
        for ext in pathext.split(';').filter(|e| !e.is_empty()) {
            names.push(format!("{program}{}", ext.to_lowercase()));
        }
        names
    }
    #[cfg(not(windows))]
    {
        vec![program.to_string()]
    }
}

#[cfg(unix)]
fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    p.metadata()
        .is_ok_and(|m| m.is_file() && (m.permissions().mode() & 0o111 != 0))
}

#[cfg(not(unix))]
fn is_executable(p: &Path) -> bool {
    p.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_a_known_system_tool() {
        // Every supported platform has one of these on PATH.
        let found = resolve_program("cargo")
            .or_else(|| resolve_program("cmd"))
            .or_else(|| resolve_program("sh"));
        assert!(found.is_some(), "expected to resolve a common tool");
        assert!(found.unwrap().is_absolute());
    }

    #[test]
    fn missing_command_is_none() {
        assert!(resolve_program("definitely-not-a-real-binary-xyzzy-42").is_none());
    }
}
