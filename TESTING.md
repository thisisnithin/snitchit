# Testing snitchit's PTY transparency

This documents how "wrapping a program through snitchit is indistinguishable
from running it directly" is verified — what's automated, what's manual, and
exactly how to reproduce each check yourself.

Everything here targets **Unix** (Linux/macOS). On Windows, the PTY path uses
ConPTY and some of this doesn't apply the same way; see the note at the bottom.

## Automated (run these with `cargo test`)

| Test | What it proves |
|---|---|
| `crates/cli/tests/wrap.rs::wrap_preserves_exit_code_and_records_a_verifiable_chain` | Basic wrap: exit code 7 preserved, chain records and verifies. |
| `crates/cli/tests/wrap.rs::wrap_preserves_exit_code_across_the_full_range` | Exit codes 0, 1, 42, 255 are all preserved exactly — not just one hand-picked value. |
| `crates/cli/tests/signals.rs::ctrl_c_delivers_sigint_to_the_wrapped_child` | A raw `0x03` byte written into the **outer** pty (standing in for a real terminal) reaches the **wrapped child** as `SIGINT` — proven by a bash `trap ... INT` firing and exiting with a distinctive code. |
| `crates/cli/tests/signals.rs::ctrl_backslash_delivers_sigquit_to_the_wrapped_child` | Same, for `SIGQUIT` (`0x1c`, Ctrl-\\). |
| `crates/cli/tests/signals.rs::ctrl_d_delivers_eof_to_the_wrapped_child` | `0x04` (Ctrl-D) reaches the child as EOF on stdin — `cat` exits instead of hanging. |
| `crates/cli/tests/resize.rs::resize_propagates_from_the_outer_terminal_to_the_wrapped_child` | Resizing the **outer** pty (what a terminal emulator does on window resize) propagates through snitchit's `SIGWINCH` handler → `MasterPty::resize` (`TIOCSWINSZ`) → the **wrapped child** observes the new size via a direct `TIOCGWINSZ` read (`stty size`), independent of the child's own signal bookkeeping. |

Run them all:
```sh
cargo test -p snitchit --test wrap --test signals --test resize
```

### How the signal/resize tests actually work

These are not mocks. Each test builds a **second, outer PTY** (via
`portable-pty`, already a dependency) that stands in for "the real terminal" —
exactly the role your actual terminal emulator plays when you run
`snitchit -- claude` normally. The real `snitchit` binary is spawned attached
to that outer pty's slave, wrapping a small `bash` script. The test then:

- writes raw control bytes into the outer pty's write side (what a keyboard
  driver does), or
- calls `resize()` on the outer pty (what a terminal emulator does on a
  window resize),

and asserts on what the **wrapped child** (attached to snitchit's own *inner*
pty, one more hop in) actually observed. This exercises the full real path —
kernel PTY line discipline, snitchit's raw-mode passthrough, its resize
watcher thread, its `MasterPty::resize` call — with no part of the mechanism
faked.

**Why Ctrl-C/Ctrl-D forwarding needs zero special code in snitchit:** snitchit
puts *its own* controlling terminal (the outer pty) into raw mode, which
disables that terminal's signal generation (`ISIG`) — so control bytes pass
through as plain data rather than becoming signals there. Those bytes then
flow, byte-for-byte, into the *inner* pty snitchit created for the child, whose
slave is still in ordinary cooked mode — so the **kernel itself** converts them
into `SIGINT`/`SIGQUIT`/EOF for the wrapped child's foreground process group.
This is standard PTY-nesting semantics; the tests exist to prove it actually
holds for this codebase's spawn setup, not to reimplement it.

**Why resize does need code:** unlike signals, there's no free kernel path from
"my terminal resized" to "the child's terminal is a different size" — the
parent has to notice (`SIGWINCH`) and explicitly propagate it
(`TIOCSWINSZ`/`MasterPty::resize`). This is implemented in
`crates/collectors/src/sources/pty/mod.rs`'s `spawn_resize_watcher`/`watch_resize` (Unix:
blocks for `SIGWINCH` via `signal-hook`; Windows: polls, since there's no
`SIGWINCH` there).

## Manual interactive verification

The automated tests above cover exit codes, signals, and resize as discrete,
scriptable events. The remaining question — "does a full interactive session
*feel* identical, keystroke by keystroke, redraw by redraw?" — was verified
using **`tmux`** as a scripted stand-in for a human at a keyboard. `tmux`
allocates a genuine PTY and injects real keystrokes/escape sequences, so this
is a faithful proxy for manual testing, fully reproducible, and was actually
run (not just described) as part of verifying this codebase — see the exact
commands below to reproduce it yourself, including with your own hands instead
of a script if you'd rather.

### What was tested and the result

Two `tmux` sessions were started side by side: `vim <file>` run **directly**,
and `vim <file>` run **through `snitchit --`**, both at 80×24. Identical
keystrokes were sent to both sessions:

- Insert mode: typed text, `Escape`.
- Normal-mode navigation: `0`, `w`, `cw` (word motion + change).
- `o` (open new line + insert), `A` (append at end of line).
- **Live resize** to 120×40 sent to both sessions mid-edit (`tmux
  resize-window`), while vim was actively displaying a buffer.
- Insert-mode **arrow keys** (`Left`/`Right`) and **Backspace**, which travel
  as multi-byte ANSI escape sequences (`\x1b[D`, `\x1b[C`) — exactly what could
  get corrupted or split by incorrect raw-mode/buffering handling.
- `:wq` to save and quit; separately, `:cq` to quit with an error, to check
  exit-code parity for a full-screen TUI app (not just a shell script).

**Result — all identical between wrapped and direct:**
- The saved file contents matched byte-for-byte after the arrow-key/backspace
  edit sequence (both produced `wXrod` from the same edit script).
- The saved file contents matched byte-for-byte after the longer edit sequence
  (both produced `Hello there end` / `Second line via insert mode`).
- The **rendered terminal pane** captured immediately after the live resize to
  120×40 was **byte-for-byte identical** between wrapped and direct (including
  vim's status-line ruler position `1,15  All`) — proof the resize propagated
  correctly all the way to a real TUI's redraw, not just to a raw `stty size`
  read.
- `:cq` (vim's "quit with error") propagated as exit code `1` through
  snitchit, matching vim's own documented behavior for a shell script wrapping
  it directly.
- No garbled output, no dropped keystrokes, no visible lag were observed at
  any point.

### Reproduce it yourself

```sh
cargo build --release
BIN=target/release/snitchit

# Two side-by-side sessions, one direct, one wrapped:
tmux new-session -d -s direct -x 80 -y 24 'vim /tmp/direct.txt'
tmux new-session -d -s wrapped -x 80 -y 24 "$BIN -- vim /tmp/wrapped.txt"

# Attach to either to drive it by hand and eyeball it:
tmux attach -t wrapped
# ...type normally, press arrow keys, resize your real terminal window,
# Ctrl-C, :wq — it should feel like plain vim throughout.

# Or drive both non-interactively and diff:
tmux send-keys -t direct  'iHello' Escape
tmux send-keys -t wrapped 'iHello' Escape
tmux resize-window -t direct  -x 120 -y 40
tmux resize-window -t wrapped -x 120 -y 40
diff <(tmux capture-pane -t direct -p) <(tmux capture-pane -t wrapped -p)
# no output = identical
```

### No added latency or buffering

Not directly timing-measured (timing is inherently noisy and environment-
dependent), but supported by:
- **Code-level**: both I/O pumps (`pump_stdin`/`pump_output` in
  `crates/collectors/src/sources/pty/mod.rs`) flush after every single read/write — there
  is no batching, buffering window, or delay anywhere in the byte path.
- **Empirically**: the interactive `vim` session above showed no visible lag,
  no dropped/reordered bytes, and no rendering artifacts across a real editing
  session with resize — the kind of test that would surface batching bugs.

## Kernel tier (tier 3) — exec + connect on both OSes

The kernel tier captures **exec + outbound connect** on Linux and macOS,
normalized to identical `Event::kernel_exec` / `Event::kernel_connect` records so
a chain verifies the same regardless of which backend produced it. Backends are
chosen at build time by `#[cfg(target_os)]`:

* `crates/collectors/src/sources/kernel/` — Linux, **eBPF**, exec + connect.
* `.../endpoint_security/` — macOS, **Apple Endpoint Security**, exec.
* `.../macos_connect/` — macOS, **socket-table polling**, connect.

### What runs in CI (no privilege)

The pure/normalization logic is unit-tested and runs in ordinary CI on **both**
OSes — no privilege:

* `sources/netfmt` — shared `host:port` formatting (IPv4/IPv6), tested once,
  compiled into both connect backends. Runs on ubuntu **and** macos.
* `sources/kernel` tests (`cstr`, argv assembly, sockaddr parse, event dispatch)
  — run on ubuntu.
* `sources/endpoint_security` tests (pid-tree fork/exec bookkeeping, argv
  assembly) and `sources/macos_connect` tests (process-tree scoping, outbound
  predicate, 4-tuple dedup) — run on macos.
* `cargo test -p snitchit-core --test halo_interop` cross-checks a chain that
  **includes kernel exec + IPv4/IPv6 connect records** against halo-record's own
  verifier (opt-in; see below).

What CANNOT run in CI: actually attaching eBPF / creating an ES client (both need
kernel privilege). Those are proven by the two `demo.sh` scripts on real hardware.

### halo interop cross-check

Opt-in (CI has no Python/halo checkout). Point it at the halo-record source with
an **absolute** path (the test's CWD is the crate dir, not the repo root):

```sh
SNITCHIT_HALO_SRC="$(pwd)/.context/halo-record/src" \
  cargo test -p snitchit-core --test halo_interop
```

Expected: `OK: 6 record(s) valid, hash chain intact …` — the 6 records include a
`kernel_exec` and two `kernel_connect` (one IPv4, one IPv6), so this asserts halo
accepts the exact records **both** kernel backends emit.

### Linux (eBPF) — exec + connect

```sh
cargo build --release -p snitchit && sudo ./crates/collectors/ebpf/demo.sh
```

Expected: the agent's `uname`/`echo` execs and its `1.1.1.1:53` outbound connect
appear as `ebpf`-sourced records, the secret in argv is redacted, `verify` passes.

### macOS — exec + connect

Two coverage levels, because the two collectors have different privilege needs:

**Connect only, no privilege** (works as a normal user — verified on Darwin 25):

```sh
cargo build --release -p snitchit
./crates/collectors/endpoint-security/demo.sh          # NOT sudo
```

Expected — exec reports unavailable (no ES), connect is captured by the poller:

```
=== kernel-tier records ===
total=…  kernel=1  (exec=0, connect=1)
  network   connect          '1.1.1.1:80'
raw secret leaked (must be False): False
=== chain integrity ===
… intact: … record(s), hash chain verified …
```

**Exec + connect, root + developer mode** (full parity):

```sh
systemextensionsctl developer on          # one-time; reboot afterwards
cargo build --release -p snitchit
sudo ./crates/collectors/endpoint-security/demo.sh
```

Expected — both tiers active, `connect=` is no longer 0:

```
=== kernel-tier records ===
total=…  kernel=≥3  (exec=≥2, connect=≥1)
  tool_call  /usr/bin/uname   'uname -a'
  tool_call  /bin/echo        'echo sk-…'        # summary redacted, hash retained
  network    connect          '1.1.1.1:80'
raw secret leaked (must be False): False
```

The connect backend is best-effort (samples every ~100ms, TCP only); the demo
holds the connection ~1.2s so it is caught deterministically. Complete
kernel-level connect capture would need a NetworkExtension entitlement the
clone-and-build path can't sign — see README and `VERIFICATION.md`.

**Graceful degradation** (design principle #1), confirmed on Darwin 25 as a
normal user: the ES client is refused cleanly (`ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED`),
the connect poller still activates, the wrapped command runs, and records seal
into the chain:

```
snitchit: kernel collector unavailable (… ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED …); continuing with PTY + hooks
snitchit: connect collector active (socket poll: outbound TCP)
snitchit: recorded N event(s) to …
```

A full copy-paste runbook for both platforms is in `VERIFICATION.md`.

## Windows note

The above (Ctrl-C/Ctrl-D/SIGQUIT forwarding, `SIGWINCH`-based resize, the pty
nesting tests) is POSIX-specific and doesn't run on Windows —
`crates/cli/tests/{signals,resize}.rs` and `wrap.rs` are all `#![cfg(unix)]`.
Windows uses ConPTY, which has different resize semantics (polled, not
signal-driven — see the `#[cfg(windows)]` branch of `watch_resize`) and no
POSIX signals at all. CI covers Linux and macOS; Windows is a development
convenience target, not a supported one (brief §2).
