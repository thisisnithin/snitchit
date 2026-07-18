//! Command-line surface (clap).
//!
//! Default mode is wrap-and-record: `snitchit -- <cmd> [args...]`. The `--`
//! separates snitchit's own args from the agent's. The other verbs are
//! subcommands: `log`, `verify`, `view`, `install`, `uninstall`.

use clap::{Parser, Subcommand};

/// Local-first, observe-only, tamper-evident recorder for terminal AI agents.
#[derive(Debug, Parser)]
#[command(
    name = "snitchit",
    version,
    about,
    long_about = None,
    args_conflicts_with_subcommands = true,
)]
pub struct Cli {
    /// A verb (`log`, `verify`, `install`, `uninstall`). Omit to wrap a command.
    #[command(subcommand)]
    pub command: Option<Command>,

    /// The agent command to run and record, given after `--`,
    /// e.g. `snitchit -- claude`.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub wrapped: Vec<String>,
}

/// snitchit subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Show the recorded timeline of a session (default: the latest).
    Log(SessionArgs),

    /// Verify the integrity of a recorded session's hash chain.
    Verify(SessionArgs),

    /// Render a session's recorded log as a self-contained static HTML file
    /// and open it in the browser. Read-only: never writes to `~/.snitchit/`,
    /// never mutates the chain. No network, no server — one offline HTML file.
    View(ViewArgs),

    /// Install shell shims (`claude`/`opencode` run under snitchit) **and**
    /// register each agent's tool-use hooks — both are core, not optional.
    Install(InstallArgs),

    /// Remove everything `install` added: shell shims and every agent's hooks.
    Uninstall(InstallArgs),

    /// Internal: ingest one agent hook payload (JSON on stdin) into the active
    /// session. Registered into the agent's config by `install`; not meant to
    /// be run by hand. Always exits 0 (never blocks the agent).
    #[command(hide = true)]
    Hook {
        /// Which agent's payload format to expect: `claude` or `opencode`.
        #[arg(long, default_value = "claude")]
        agent: String,
    },
}

/// Selects which recorded session to operate on.
#[derive(Debug, clap::Args)]
pub struct SessionArgs {
    /// Session id or a path to a `.jsonl` log. Defaults to the latest session.
    pub session: Option<String>,
}

/// Options for `view`.
#[derive(Debug, clap::Args)]
pub struct ViewArgs {
    /// Session id or path to render. Defaults to the latest session (same
    /// resolution `log`/`verify` use).
    #[arg(long)]
    pub session: Option<String>,

    /// Write the HTML here instead of a temp file.
    #[arg(long)]
    pub out: Option<String>,

    /// Write the file and print its path without opening a browser.
    #[arg(long)]
    pub no_open: bool,
}

/// Options for `install` / `uninstall`. Every destination below is wired
/// unconditionally — there is no flag to skip the hooks; they're core setup,
/// same as the shell shims.
#[derive(Debug, clap::Args)]
pub struct InstallArgs {
    /// Path to the shell rc file to edit (default: auto-detected).
    #[arg(long)]
    pub rc: Option<String>,

    /// Override Claude Code's settings.json path (default:
    /// `~/.claude/settings.json`).
    #[arg(long)]
    pub claude_settings: Option<String>,

    /// Override the `OpenCode` plugin file path (default:
    /// `~/.config/opencode/plugins/snitchit.js`).
    #[arg(long)]
    pub opencode_plugin: Option<String>,

    /// Also grant this binary the eBPF capabilities (Linux) so the kernel tier
    /// loads without per-run `sudo` — your agent still runs as you, never as
    /// root. Runs `setcap` (prompts for sudo once). `uninstall --kernel` removes
    /// them. No effect off Linux.
    #[arg(long)]
    pub kernel: bool,

    /// Print what would change without writing anything.
    #[arg(long)]
    pub dry_run: bool,
}
