#!/usr/bin/env bash
# Prove the kernel (eBPF) tier end-to-end on a privileged Linux box.
#
# Runs a throwaway "agent" under snitchit that (a) shells out to other binaries
# and (b) opens an outbound TCP connection, then shows that the eBPF collector
# recorded BOTH — the exec(s) and the connect — into the tamper-evident chain,
# scoped to the agent's process tree, with argv/addresses redacted + hashed.
#
# Requires: root (or CAP_BPF+CAP_PERFMON) and a BTF-enabled kernel.
# Usage:   cargo build --release -p snitchit && sudo ./crates/collectors/ebpf/demo.sh
set -euo pipefail

BIN="${SNITCHIT_BIN:-target/release/snitchit}"
[ -x "$BIN" ] || { echo "build first: cargo build --release -p snitchit"; exit 1; }
[ "$(id -u)" -eq 0 ] || echo "warning: not root — the eBPF tier will report unavailable"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/agent.sh" <<'AGENT'
#!/usr/bin/env bash
uname -a >/dev/null                                   # exec: uname
/bin/echo sk-abcdefghijklmnopqrstuvwxyz123456 >/dev/null   # exec: secret in argv (redacted)
timeout 3 bash -c 'exec 3<>/dev/tcp/1.1.1.1/53' 2>/dev/null || true  # outbound connect
AGENT
chmod +x "$WORK/agent.sh"

export XDG_DATA_HOME="$WORK/xdg"
"$BIN" -- bash "$WORK/agent.sh" </dev/null || true

LOG="$(ls -t "$WORK"/xdg/snitchit/*.jsonl | head -1)"
echo
echo "=== eBPF-sourced records ==="
python3 - "$LOG" <<'PY'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1])]
ebpf = [r for r in rows if r.get("source", {}).get("adapter") == "ebpf"]
print(f"total={len(rows)}  ebpf={len(ebpf)}  "
      f"(exec={sum(r['action']['type']=='tool_call' for r in ebpf)}, "
      f"connect={sum(r['action']['type']=='network' for r in ebpf)})")
for r in ebpf:
    a = r["action"]
    print(f"  {a['type']:9} {a.get('tool'):16} {a['input']['summary']!r}")
raw = "sk-abcdefghijklmnopqrstuvwxyz123456"
print("raw secret leaked (must be False):", raw in open(sys.argv[1]).read())
PY

echo
echo "=== chain integrity ==="
"$BIN" verify "$LOG"
