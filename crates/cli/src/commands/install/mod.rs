//! `snitchit install` / `uninstall` — shell shims **and** agent hooks, both
//! mandatory, both wired in one command.
//!
//! `install` does two things unconditionally, every time:
//!
//! 1. Appends a marked block of shell *functions* to the user's rc file so that
//!    typing `claude` (or `opencode`) transparently runs under snitchit.
//!    Functions (not aliases) forward all args with `"$@"`, and call the binary
//!    via `command snitchit` so they never recurse — snitchit in turn resolves
//!    the real agent binary by absolute path (recursion safety, brief §5).
//! 2. Registers every agent's tool-use hooks. Each agent's wiring lives in the
//!    `snitchit-agents` crate (one module per agent); `install`/`uninstall` here
//!    loop over `snitchit_agents::agents()` and never branch on agent identity.
//!
//! There is no flag to install only one of these — hooks are core setup, not an
//! optional add-on, same as the shell shims. A failure wiring one destination
//! (shell rc, one agent's hook) is reported but never blocks the others.
//!
//! `uninstall` removes exactly what `install` added, everywhere: the shell rc
//! block is restored byte-identical to its pre-install state (verified by
//! tests), and each agent's hook/plugin is removed. The raw `snitchit -- claude`
//! form always works regardless of install state.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use snitchit_agents::{agents, InstallOptions};

#[cfg(target_os = "linux")]
use std::process::Command;

use crate::cli::InstallArgs;

const START: &str = "# >>> snitchit shims >>>";
const END: &str = "# <<< snitchit shims <<<";

/// The capabilities the kernel (eBPF) tier needs. Granted to the binary by
/// `install --kernel` so the tier loads without per-run `sudo`.
const KERNEL_CAPS: &str = "cap_bpf,cap_perfmon+ep";

/// The agent ids we install shims for — taken from the `snitchit-agents`
/// registry so a new agent is picked up automatically (register it there only).
fn agent_ids() -> Vec<&'static str> {
    agents().iter().map(|a| a.id()).collect()
}

/// Build the neutral install options the agent integrations consume, from the
/// CLI flags + the resolved binary path.
fn build_opts(args: &InstallArgs, exe: PathBuf) -> InstallOptions {
    InstallOptions {
        exe,
        dry_run: args.dry_run,
        claude_settings: args.claude_settings.as_ref().map(PathBuf::from),
        opencode_plugin: args.opencode_plugin.as_ref().map(PathBuf::from),
    }
}

/// Install the shell shims **and** every agent's hooks.
pub fn install(args: &InstallArgs) -> Result<()> {
    let mut results: Vec<(&'static str, Result<String>)> = vec![("shell", install_shim(args))];

    match snitchit_exe() {
        Ok(exe) => {
            let opts = build_opts(args, exe);
            for agent in agents() {
                results.push((
                    agent.id(),
                    agent.install(&opts).map_err(anyhow::Error::from),
                ));
            }
        }
        Err(e) => results.push(("hooks", Err(e))),
    }

    if args.kernel {
        results.push(("kernel", kernel_caps(false, args.dry_run)));
    }

    let any_ok = results.iter().any(|(_, r)| r.is_ok());
    report_results(&results);
    if !args.dry_run && any_ok {
        println!("snitchit: restart your shell and your agent to pick up all changes");
    }
    first_error_if_all_failed(results)
}

/// Remove the shell shims **and** every agent's hooks.
pub fn uninstall(args: &InstallArgs) -> Result<()> {
    let mut results: Vec<(&'static str, Result<String>)> = vec![("shell", uninstall_shim(args))];
    // uninstall wiring never uses `exe`; resolve best-effort so a missing binary
    // path can't block removal.
    let opts = build_opts(
        args,
        snitchit_exe().unwrap_or_else(|_| PathBuf::from("snitchit")),
    );
    for agent in agents() {
        results.push((
            agent.id(),
            agent.uninstall(&opts).map_err(anyhow::Error::from),
        ));
    }
    if args.kernel {
        results.push(("kernel", kernel_caps(true, args.dry_run)));
    }
    report_results(&results);
    first_error_if_all_failed(results)
}

fn report_results(results: &[(&'static str, Result<String>)]) {
    for (id, r) in results {
        match r {
            Ok(msg) => println!("snitchit: [{id}] {msg}"),
            Err(e) => eprintln!("snitchit: [{id}] skipped: {e:#}"),
        }
    }
}

/// Succeed as long as at least one destination was wired (each result was
/// already reported individually); only surface an error if everything failed.
fn first_error_if_all_failed(results: Vec<(&'static str, Result<String>)>) -> Result<()> {
    if results.iter().all(|(_, r)| r.is_err()) {
        for (_, r) in results {
            r?;
        }
    }
    Ok(())
}

// --- shell shims -------------------------------------------------------------

fn install_shim(args: &InstallArgs) -> Result<String> {
    let rc = target_rc(args)?;
    let is_fish = is_fish(&rc);
    let current = read_or_empty(&rc)?;
    let ids = agent_ids();
    let block = build_block(is_fish, &ids);
    let next = with_block(&current, &block);

    if next == current {
        return Ok(format!("shims already installed in {}", rc.display()));
    }
    if args.dry_run {
        return Ok(format!("would update {}\n\n{block}", rc.display()));
    }
    write_rc(&rc, &next)?;
    Ok(format!(
        "installed shims for {} in {}",
        ids.join(", "),
        rc.display()
    ))
}

fn uninstall_shim(args: &InstallArgs) -> Result<String> {
    let rc = target_rc(args)?;
    let current = read_or_empty(&rc)?;
    let next = remove_block(&current);

    if next == current {
        return Ok(format!("no shims found in {}", rc.display()));
    }
    if args.dry_run {
        return Ok(format!(
            "would remove the snitchit block from {}",
            rc.display()
        ));
    }
    write_rc(&rc, &next)?;
    Ok(format!("removed shims from {}", rc.display()))
}

// --- rc resolution ----------------------------------------------------------

fn target_rc(args: &InstallArgs) -> Result<PathBuf> {
    if let Some(rc) = &args.rc {
        return Ok(PathBuf::from(rc));
    }
    detect_rc().context("could not detect a shell rc file; pass --rc <path>")
}

/// Best-effort rc detection from `$SHELL`.
fn detect_rc() -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    let shell = std::env::var("SHELL").unwrap_or_default();
    if shell.contains("zsh") {
        Some(home.join(".zshrc"))
    } else if shell.contains("fish") {
        Some(home.join(".config").join("fish").join("config.fish"))
    } else {
        // bash and unknown shells default to ~/.bashrc.
        Some(home.join(".bashrc"))
    }
}

fn is_fish(rc: &Path) -> bool {
    rc.to_string_lossy().contains("fish")
}

// --- block construction / editing -------------------------------------------

fn build_block(is_fish: bool, agents: &[&str]) -> String {
    use std::fmt::Write as _;

    let mut b = String::new();
    b.push_str(START);
    b.push('\n');
    b.push_str("# Managed by `snitchit install` — remove with `snitchit uninstall`.\n");
    for agent in agents {
        // `write!` to a String is infallible.
        if is_fish {
            let _ = writeln!(
                b,
                "function {agent}\n    command snitchit -- {agent} $argv\nend"
            );
        } else {
            let _ = writeln!(b, "{agent}() {{ command snitchit -- {agent} \"$@\"; }}");
        }
    }
    b.push_str(END);
    b.push('\n');
    b
}

/// Return `content` with the managed block present exactly once (idempotent).
fn with_block(content: &str, block: &str) -> String {
    let base = remove_block(content);
    if base.is_empty() {
        block.to_string()
    } else {
        // A single '\n' separator we can remove cleanly on uninstall.
        format!("{base}\n{block}")
    }
}

/// Remove the managed block (and the single separator newline `with_block`
/// inserts before it), leaving everything else byte-for-byte unchanged.
fn remove_block(content: &str) -> String {
    let Some(start) = content.find(START) else {
        return content.to_string();
    };
    let Some(end_marker) = content[start..].find(END) else {
        return content.to_string();
    };
    let mut end = start + end_marker + END.len();
    // Consume the newline that terminates the END marker line.
    if content[end..].starts_with('\n') {
        end += 1;
    }
    // Consume the single separator newline immediately before the block.
    let mut begin = start;
    if begin > 0 && content.as_bytes()[begin - 1] == b'\n' {
        begin -= 1;
    }
    format!("{}{}", &content[..begin], &content[end..])
}

// --- io ---------------------------------------------------------------------

fn read_or_empty(rc: &Path) -> Result<String> {
    match fs::read_to_string(rc) {
        Ok(s) => Ok(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e).with_context(|| format!("reading {}", rc.display())),
    }
}

fn write_rc(rc: &Path, content: &str) -> Result<()> {
    if let Some(parent) = rc.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
    }
    fs::write(rc, content).with_context(|| format!("writing {}", rc.display()))
}

// --- agent hooks (Claude Code + `OpenCode`) ---------------------------------

/// The absolute path to this binary — baked into every agent's hook wiring so a
/// shell shim can never redirect it.
fn snitchit_exe() -> Result<PathBuf> {
    std::env::current_exe().context("resolving the snitchit binary path")
}

// Each agent's hook wiring (register/remove its hook or plugin) lives in the
// `snitchit-agents` crate, behind its `AgentIntegration` trait. `install` /
// `uninstall` above loop over `snitchit_agents::agents()` and never branch on
// agent identity — adding an agent touches only that crate.

// --- kernel (eBPF) capabilities ---------------------------------------------

/// Grant (or, if `remove`, revoke) the eBPF capabilities on this binary via
/// `setcap`, so the kernel tier loads without per-run `sudo` — and crucially,
/// the wrapped agent still runs as *you*, never as root. This one-time
/// privileged step is the whole point of `--kernel`: it moves the privilege to
/// install time instead of `sudo`-ing the agent on every launch.
fn kernel_caps(remove: bool, dry_run: bool) -> Result<String> {
    if dry_run {
        return Ok(if remove {
            "would remove the kernel capabilities from the snitchit binary".to_string()
        } else {
            format!("would grant {KERNEL_CAPS} to the snitchit binary (prompts for sudo once)")
        });
    }
    kernel_caps_apply(remove)
}

#[cfg(target_os = "linux")]
fn kernel_caps_apply(remove: bool) -> Result<String> {
    let exe = snitchit_exe()?;
    let exe_str = exe.to_string_lossy().into_owned();

    // `setcap` needs root. If we aren't already root, wrap it in `sudo`, which
    // prompts once interactively. After this succeeds, `snitchit -- <agent>`
    // needs no sudo and the agent runs as the calling user.
    let root = is_root();
    let mut cmd = if root {
        Command::new("setcap")
    } else {
        let mut c = Command::new("sudo");
        c.arg("setcap");
        c
    };
    if remove {
        cmd.arg("-r");
    } else {
        cmd.arg(KERNEL_CAPS);
    }
    cmd.arg(&exe_str);

    let status = cmd.status().with_context(|| {
        format!(
            "running {}setcap — is libcap installed (is `setcap` on PATH)?",
            if root { "" } else { "sudo " }
        )
    })?;
    if !status.success() {
        anyhow::bail!(
            "setcap failed (exit {}). The binary must live on a real filesystem \
             (not a /mnt drvfs mount), and you need sudo rights.",
            status
                .code()
                .map_or_else(|| "signal".to_string(), |c| c.to_string())
        );
    }
    Ok(if remove {
        format!("removed kernel capabilities from {exe_str}")
    } else {
        format!(
            "granted {KERNEL_CAPS} to {exe_str} — the kernel (eBPF) tier now loads \
             without sudo, and your agent still runs as you"
        )
    })
}

#[cfg(not(target_os = "linux"))]
fn kernel_caps_apply(_remove: bool) -> Result<String> {
    anyhow::bail!("the kernel (eBPF) tier is Linux-only; --kernel has no effect on this platform")
}

/// Whether the current process is running as root (euid 0), via `id -u` so we
/// don't pull in a libc dependency just for `geteuid`.
#[cfg(target_os = "linux")]
fn is_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .is_some_and(|s| s.trim() == "0")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_is_idempotent_and_uninstall_is_byte_identical() {
        let original = "# my rc\nexport PATH=$PATH:/x\nalias ll='ls -la'\n";
        let block = build_block(false, &["claude", "opencode"]);

        let once = with_block(original, &block);
        assert!(once.contains(START) && once.contains(END));
        assert!(once.contains("claude() { command snitchit -- claude \"$@\"; }"));

        // Running install again must not duplicate the block.
        let twice = with_block(&once, &block);
        assert_eq!(once, twice);

        // Uninstall restores the original exactly.
        assert_eq!(remove_block(&once), original);
    }

    #[test]
    fn roundtrip_on_file_without_trailing_newline() {
        let original = "export FOO=1"; // no trailing newline
        let block = build_block(false, &["claude", "opencode"]);
        let installed = with_block(original, &block);
        assert_eq!(remove_block(&installed), original);
    }

    #[test]
    fn roundtrip_on_empty_file() {
        let block = build_block(false, &["claude", "opencode"]);
        let installed = with_block("", &block);
        assert_eq!(remove_block(&installed), "");
    }

    #[test]
    fn uninstall_no_op_when_absent() {
        let original = "plain rc\n";
        assert_eq!(remove_block(original), original);
    }

    #[test]
    fn fish_uses_function_syntax() {
        let block = build_block(true, &["claude", "opencode"]);
        assert!(block.contains("function claude"));
        assert!(block.contains("command snitchit -- claude $argv"));
        assert!(block.contains("end\n"));
    }
}
