# VERIFICATION — kernel tier (exec + connect) on Linux and macOS

A copy-paste runbook to confirm the three-tier recorder, and specifically the
tier-3 **exec + outbound-connect** capture, on real hardware. Each block lists
the exact command and the exact expected output.

Two backends, identical records:
* **Linux** — eBPF, hooking `execve`/`connect` at the syscall. Complete.
* **macOS** — Endpoint Security for exec (root + dev-mode), socket-table polling
  for connect (no privilege; best-effort, TCP-only).

---

## 0. Runs anywhere, no privilege (also the CI gates)

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
cargo build --release
```

Expected: `fmt` silent (exit 0); `clippy` silent (exit 0); `test` all green;
`build --release` succeeds. CI runs exactly these on `ubuntu-latest` and
`macos-latest`, so the eBPF backend is compiled+unit-tested on Linux and the ES
+ socket-poll backends on macOS, each cleanly excluded from the other OS.

Optional — cross-check records against halo-record's own verifier (needs Python +
a halo-record checkout; use an **absolute** path):

```sh
SNITCHIT_HALO_SRC="$(pwd)/.context/halo-record/src" \
  cargo test -p snitchit-core --test halo_interop
```

Expected: `OK: 6 record(s) valid, hash chain intact …` and the test passes. The
chain includes a `kernel_exec` and two `kernel_connect` (IPv4 + IPv6) records —
the exact shapes both kernel backends emit.

---

## A. Privileged Linux box — eBPF (exec + connect)

Requires root (or `cap_bpf`+`cap_perfmon`) and a BTF-enabled kernel.

```sh
cargo build --release -p snitchit
sudo ./crates/collectors/ebpf/demo.sh
```

Expected (counts may vary; the two `exec` and one `connect` shown must appear):

```
=== eBPF-sourced records ===
total=…  ebpf=…  (exec=≥2, connect=≥1)
  tool_call  uname            'uname -a'
  tool_call  /bin/echo        'echo sk-…'          # summary redacted, hash kept
  network    connect          '1.1.1.1:53'
raw secret leaked (must be False): False

=== chain integrity ===
… intact: … record(s), hash chain verified — tamper-evident to the head
```

Under a pid namespace (WSL2/containers) also run, once per boot:
`sudo chmod -R a+rX /sys/kernel/tracing/events`.

---

## B. macOS box — exec + connect

The macOS kernel tier is two collectors with different privilege needs. Verify
each level.

### B1. Connect only — no privilege (normal user)

```sh
cargo build --release -p snitchit
./crates/collectors/endpoint-security/demo.sh          # NOT sudo
```

Expected — exec reports unavailable, the socket poller captures the connect:

```
note: not root — exec (Endpoint Security) will report unavailable; connect (socket poll) still works
snitchit: kernel collector unavailable (… ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED …); continuing with PTY + hooks
snitchit: connect collector active (socket poll: outbound TCP)

=== kernel-tier records ===
total=…  kernel=1  (exec=0, connect=1)
  network   connect          '1.1.1.1:80'
raw secret leaked (must be False): False

=== chain integrity ===
… intact: … record(s), hash chain verified — tamper-evident to the head
```

This exact result was confirmed on Darwin 25 during development.

### B2. Exec + connect — root + developer mode (full parity)

```sh
systemextensionsctl developer on          # one-time; reboot afterwards
cargo build --release -p snitchit
sudo ./crates/collectors/endpoint-security/demo.sh
```

Grant **Full Disk Access** (TCC) to your terminal if macOS prompts (System
Settings → Privacy & Security). Expected — both tiers active, `connect` no longer 0:

```
snitchit: kernel collector active (Endpoint Security: exec)
snitchit: connect collector active (socket poll: outbound TCP)

=== kernel-tier records ===
total=…  kernel=≥3  (exec=≥2, connect=≥1)
  tool_call  /usr/bin/uname   'uname -a'
  tool_call  /bin/echo        'echo sk-…'          # summary redacted, hash kept
  network    connect          '1.1.1.1:80'
raw secret leaked (must be False): False

=== chain integrity ===
… intact: … record(s), hash chain verified — tamper-evident to the head
```

### Interpreting connect results on macOS

* The connect poller samples every ~100ms and is **TCP-only**. The demo holds its
  connection ~1.2s so capture is deterministic; a real connection shorter than
  the poll interval can be missed. This is the honest limit of the
  entitlement-free path.
* **Complete** kernel-level connect capture (every connection, like Linux eBPF)
  needs a NetworkExtension content filter (`NEFilterDataProvider`), which requires
  the restricted `com.apple.developer.networking.networkextension` entitlement — a
  paid Apple Developer account + provisioning profile. Developer mode does not
  grant it, so the clone-and-build path cannot provide it. If you have a signed
  build with that entitlement, that backend can be added behind the same
  `EventSource` seam and emits the identical `Event::kernel_connect` records.
