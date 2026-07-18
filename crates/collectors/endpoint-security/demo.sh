#!/usr/bin/env bash
# Prove the macOS kernel tier end-to-end — exec + outbound connect — on a Mac.
#
# The macOS counterpart to ../ebpf/demo.sh. Runs a throwaway "agent" under
# snitchit that (a) shells out to other binaries and (b) opens an outbound TCP
# connection, then shows that the kernel tier recorded BOTH — the exec(s) and the
# connect — into the tamper-evident chain, scoped to the agent's process tree,
# with argv/addresses redacted + hashed.
#
# The macOS kernel tier is two collectors with DIFFERENT privilege needs:
#   * exec    — Apple Endpoint Security. Needs root + developer mode (below).
#   * connect — socket-table polling. No entitlement, and no root for the agent's
#               own tree. Best-effort/TCP-only (a connection shorter than the
#               ~100ms poll can be missed; complete capture would need a
#               NetworkExtension entitlement that clone-and-build cannot sign).
#
# So the output depends on how you run it (self-build path, no Apple account):
#   As a normal user:   connect is captured; exec reports "unavailable".
#     cargo build --release -p snitchit && ./crates/collectors/endpoint-security/demo.sh
#   As root + dev mode: BOTH exec and connect are captured (full parity).
#     systemextensionsctl developer on        # one-time, then reboot
#     cargo build --release -p snitchit
#     sudo ./crates/collectors/endpoint-security/demo.sh
#
# Whatever is unavailable, snitchit logs it and keeps recording the rest — the
# agent is never blocked (design principle #1). Needs outbound network to 1.1.1.1.
set -euo pipefail

BIN="${SNITCHIT_BIN:-target/release/snitchit}"
[ -x "$BIN" ] || { echo "build first: cargo build --release -p snitchit"; exit 1; }
[ "$(id -u)" -eq 0 ] || echo "note: not root — exec (Endpoint Security) will report unavailable; connect (socket poll) still works"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/agent.sh" <<'AGENT'
#!/usr/bin/env bash
uname -a >/dev/null                                        # exec: uname
/bin/echo sk-abcdefghijklmnopqrstuvwxyz123456 >/dev/null   # exec: secret in argv (redacted)
# Outbound TCP connect, held ~1.2s so the ~100ms socket poll observes it.
exec 3<>/dev/tcp/1.1.1.1/80 && sleep 1.2 && exec 3>&- || true
AGENT
chmod +x "$WORK/agent.sh"

export XDG_DATA_HOME="$WORK/xdg"
"$BIN" -- bash "$WORK/agent.sh" </dev/null || true

LOG="$(ls -t "$WORK"/xdg/snitchit/*.jsonl | head -1)"
echo
echo "=== kernel-tier records ==="
python3 - "$LOG" <<'PY'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1])]
# Both kernel backends (Linux eBPF and macOS ES/socket-poll) normalize to the
# same records; the source adapter is "ebpf" on purpose so a macOS chain is
# byte-for-byte the shape of a Linux one.
kern = [r for r in rows if r.get("source", {}).get("adapter") == "ebpf"]
print(f"total={len(rows)}  kernel={len(kern)}  "
      f"(exec={sum(r['action']['type']=='tool_call' for r in kern)}, "
      f"connect={sum(r['action']['type']=='network' for r in kern)})")
for r in kern:
    a = r["action"]
    print(f"  {a['type']:9} {a.get('tool'):16} {a['input']['summary']!r}")
raw = "sk-abcdefghijklmnopqrstuvwxyz123456"
print("raw secret leaked (must be False):", raw in open(sys.argv[1]).read())
PY

echo
echo "=== chain integrity ==="
"$BIN" verify "$LOG"
