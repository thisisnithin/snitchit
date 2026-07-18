# snitchit

**A local, observe-only recorder for terminal AI coding agents.** Run your agent
*through* snitchit; it records what you typed, the terminal transcript, and (after
`install`) the agent's own tool calls into a hash-chained local log, then gets out
of the way.

**Guarantees:**

- 🌐 **No network, ever.** No telemetry, no phone-home. Everything stays on your machine.
- 👀 **Observe-only.** Never blocks or alters the agent. If recording fails, the agent still runs (direct exec fallback).
- 🔗 **Tamper-*evident*.** The log is a SHA-256 hash chain, so naive edits are caught by `verify`. (It's unsigned/local — see [Integrity](#integrity) for what that does and doesn't buy you.)

```
snitchit -- claude          # run claude, recording everything; exits as claude would
snitchit -- opencode ...    # same, forwarding all args
snitchit log                # print the recorded timeline of the latest session
snitchit verify             # check the integrity of the log
snitchit view               # render the timeline as a self-contained HTML file + open it
snitchit install            # make plain `claude`/`opencode` record automatically
snitchit uninstall          # cleanly reverse `install`
```

## Install

```sh
cargo build --release
install -m 0755 target/release/snitchit ~/.local/bin/snitchit   # or anywhere on PATH
```

Then either wrap explicitly (`snitchit -- claude`), or wire it up so plain
`claude`/`opencode` record automatically:

```sh
snitchit install      # shell shims (zsh/bash/fish) + Claude Code hook + OpenCode plugin
exec $SHELL           # reload your shell
claude                # now runs under snitchit; its tool calls are recorded too
snitchit uninstall    # removes everything install added
```

`install` wires the shims *and* the agent hooks in one shot (hooks aren't a
separate opt-in — they're core setup). Override destinations with `--rc`,
`--claude-settings`, or `--opencode-plugin` for testing or non-default layouts;
a failure wiring one destination never blocks the others. The raw `snitchit --`
form always works regardless of install state.

## What gets captured (three tiers)

snitchit observes at three tiers; each sees what the others can't, all normalized
into one hash chain.

| Tier | Sees | Wired by | Privilege |
|------|------|----------|-----------|
| **1 · Terminal (PTY)** | process invocation, your terminal input, transcript, exit code | `snitchit -- <agent>` | none |
| **2 · In-process (hooks)** | the agent's own tool calls — file reads/writes, bash, web fetches — that never touch the terminal (Claude Code + OpenCode) | `snitchit install` | none |
| **3 · Kernel** | subprocesses the agent tree `exec`s (`git`/`curl`/…) and the outbound connections it opens | `snitchit install --kernel` (Linux) / dev-mode + root (macOS) | Linux: `cap_bpf`+`cap_perfmon` on the binary. macOS: exec needs root + dev-mode; connect needs neither |

> Tier 1 = *what you asked and what was on screen*; tier 2 = *what the agent did
> through its own tools*; tier 3 = *what it did behind both*. Tier-1 input
> segmentation is a pragmatic heuristic, not a shell parser. Tier 3 records
> metadata only (program + redacted argv, `host:port`) — never file contents or
> payloads — and is scoped to the agent's process tree. If it can't load (no
> privilege / kernel / BTF / entitlement) snitchit says so and continues with
> tiers 1–2.
>
> Tier 3 is selected at build time by OS and captures **exec + outbound
> connect** on both, normalized to identical records in the same chain:
> * **Linux** — **eBPF**, hooking `execve`/`connect` at the syscall. Complete.
> * **macOS** — **Apple Endpoint Security** for exec, and **socket-table
>   polling** for connect (ES has no IP-connect event). The connect side is
>   *best-effort*: it samples every ~100ms, so it can miss a connection shorter
>   than that, and it is TCP-only. Complete kernel-level connect capture on macOS
>   would need a NetworkExtension content filter, which requires a restricted
>   Apple entitlement (paid Developer account + provisioning profile) that the
>   clone-and-build path can't sign — see [Enabling the kernel tier — macOS](#enabling-the-kernel-endpoint-security--socket-poll-tier--macos).

### Enabling the kernel (eBPF) tier — Linux

Tiers 1–2 need **no privilege at all** — that's the default and covers most of
the value. Tier 3 sees the kernel, so like every eBPF tool it needs a one-time
capability grant. `install --kernel` does it for you:

```sh
snitchit install --kernel     # prompts for sudo once to grant the binary the eBPF caps
snitchit -- claude            # kernel tier now loads — no sudo, agent runs as YOU
```

That's the whole point: the privilege lives on the *snitchit binary* (two narrow
caps: `cap_bpf`, `cap_perfmon`), granted once at install time — **your agent
never runs as root.** (Don't run `sudo snitchit -- <agent>`: that would launch
the agent itself as root, with its config/auth under `/root`.)

Re-run `snitchit install --kernel` after every rebuild (a fresh binary has no
caps). The binary must be on a real filesystem (not a `/mnt` drvfs mount).
`uninstall --kernel` removes the caps. See `crates/collectors/ebpf/demo.sh` for
an end-to-end proof.

> **WSL2:** `tracefs` is root-locked and resets each boot, so you also need once
> per boot: `sudo chmod -R a+rX /sys/kernel/tracing/events`.

### Enabling the kernel (Endpoint Security + socket-poll) tier — macOS

The macOS kernel tier is two collectors with different needs, so it splits into
two coverage levels — both clone-and-build, no Apple Developer account,
notarization, or provisioning profiles:

**Outbound connect — works with no privilege.** Connection capture polls the
socket table and needs no entitlement and no root for the agent's own tree, so
it works out of the box:

```sh
cargo build --release -p snitchit
snitchit -- claude            # outbound TCP connections recorded, as you
```

It is *best-effort*: it samples every ~100ms (a shorter-lived connection can be
missed) and is TCP-only. That is the honest limit of the entitlement-free path.

**Process exec — needs developer mode + root.** Exec capture uses Apple's
**Endpoint Security** framework, which requires an ES client running as **root**
under system-extension **developer mode**:

```sh
systemextensionsctl developer on          # one-time; reboot afterwards
cargo build --release -p snitchit
sudo ./target/release/snitchit -- claude   # exec + connect both record
```

macOS may also prompt once for **Full Disk Access** (TCC) for the terminal
running snitchit — grant it in System Settings → Privacy & Security. If any
prerequisite is missing, snitchit prints `… collector unavailable …` for that
piece and continues with whatever else works — the agent is never blocked. See
`crates/collectors/endpoint-security/demo.sh` for an end-to-end proof, and
`VERIFICATION.md` for a copy-paste runbook.

> **On complete connect capture.** Catching *every* outbound connection at the
> kernel (like Linux eBPF does) needs a NetworkExtension content filter
> (`NEFilterDataProvider`), which requires the restricted
> `com.apple.developer.networking.networkextension` entitlement — a paid Apple
> Developer account and an Apple-issued provisioning profile. Developer mode
> relaxes *notarization*, not entitlement signing, so the clone-and-build path
> cannot provide it; the socket-poll backend is the closest mechanism that runs
> without it.
>
> The Endpoint Security *entitlement*
> (`com.apple.developer.endpoint-security.client`) is likewise only for shipping
> a **signed** binary to other machines; the clone-and-build path uses developer
> mode instead. There is no `install --kernel` for macOS — exec needs root at run
> time, so `sudo snitchit -- <agent>` (note this launches the agent as root; omit
> `sudo` to keep exec off and everything else as yourself).

## Viewing a session

`snitchit view` renders a session as **one self-contained, fully offline HTML
file** (records, CSS, JS all inlined — no server, network, or CDN; works via
`file://`). Read-only, and shows only the redacted summaries + `sha256:` hashes
already in the log, so it can't reconstruct a raw value. It's a filterable
timeline with an integrity banner.

```sh
snitchit view                     # latest session
snitchit view --session <id>      # a specific session (id or path)
snitchit view --out report.html   # write to a chosen path
snitchit view --no-open           # write + print path, don't launch a browser
```

A committed sample lives under `fixtures/` (`sample-session.jsonl` and
`…-broken.jsonl`) to preview the UI without recording.

## Where the log lives

Appended to `~/.snitchit/<session>.jsonl` (or `$XDG_DATA_HOME/snitchit/`). It's
kept **outside** the agent's working tree so it isn't captured or clobbered
incidentally — this is *not* a security boundary (the agent runs as the same
user, so `0700` only stops other users). There's no option to store it inside
the working directory.

## Record format

snitchit conforms to [halo-record](https://github.com/bkuan001/halo-record)'s
tamper-evident format (Schema v0.1) rather than inventing its own:

- Records link into a **SHA-256 hash chain** (first `prev_hash` is 64 zeros),
  canonicalized with **RFC 8785 (JCS)** — each `hash` is over the JCS bytes
  excluding its own `hash` field.
- **Raw inputs never enter a record.** Commands/args are stored as `sha256:`
  hashes plus redacted summaries. Command/tool **outputs** go further — the
  summary is **metadata only** (status, byte/line count), never a slice of the
  content, since redaction can't guarantee catching a custom-format secret. The
  full output is still committed via its hash, and known-pattern secrets are
  surfaced (masked) in `findings`.

Because the format matches, a snitchit chain verifies under halo-record's own
verifier:

```sh
cargo run -p snitchit-core --example emit_chain -- /tmp/demo.jsonl
python -c "import sys; sys.path.insert(0,'.context/halo-record/src'); \
  from halo_record.verify import verify_log; verify_log('/tmp/demo.jsonl')"
```

(Opt-in interop test: `SNITCHIT_HALO_SRC=/abs/path/to/halo-record/src cargo test
-p snitchit-core --test halo_interop`.)

## Integrity

The hash chain makes the log **tamper-evident against naive edits**: change a
past record without re-sealing the rest and `verify` catches it. The chain is
**unsigned and local**, so it does *not* resist a motivated tamperer — anyone who
can write the file (including a process running as you) can rewrite history,
recompute every hash, and `verify` will pass. Cryptographic
tamper-*resistance* (per-entry ed25519 signatures + external anchoring) is a
planned seam, not a current guarantee.

## Architecture

A Cargo workspace with a low platform seam (mirrors ripgrep/bat):

```
crates/
├─ core/         # Event, EventSource trait, RFC 8785 canon, hash chain, store, redaction
├─ collectors/   # live sources: pty/ (t1), kernel/ (t3 eBPF Linux), endpoint_security/ + macos_connect/ (t3 macOS exec+connect), ebpf/ (kernel-side)
├─ agents/       # per-agent hook parsing (tier 2) + install wiring — adding an agent touches only here
└─ cli/          # thin binary: clap subcommands, log/verify/view rendering
```

`core` defines both the `Event` type and the `EventSource` trait; collectors
depend on core and normalize native events into the canonical `Event` before
they cross the seam (the dependency arrow only points down). Errors: `thiserror`
in libraries, `anyhow` in the binary; no `unwrap`/`expect`/`panic` on fallible
library paths. The macOS kernel backends (Endpoint Security for exec,
socket-poll for connect) slot in behind the same `EventSource` seam as the Linux
eBPF one (selected by `#[cfg(target_os)]`, never a runtime branch), and the one
piece of shared pure logic — `host:port` formatting — lives in `sources/netfmt`
so both backends' records stay byte-identical; per-entry signing lands the same
way without touching core.

## Not yet

Complete (non-polling) macOS connect capture — needs a NetworkExtension content
filter and the restricted Apple entitlement that clone-and-build can't sign;
best-effort socket-poll capture ships today. Also: external hash anchoring /
transparency-log publishing, per-entry ed25519 signatures, team features, any
network feature.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
cargo build --release
```

CI runs all of the above on `ubuntu-latest` and `macos-latest`.

## License

Dual-licensed under [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your
option. Contributions are accepted under the same dual license unless you state
otherwise.
