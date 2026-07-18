#!/usr/bin/env bash
#
# clone-context.sh — (re)clone reference repos into .context/
#
# These are LOCAL REFERENCE codebases for Claude Code, not dependencies:
#   bat, fd, ripgrep, starship  -> quality / structure / platform-seam references
#   halo-record                 -> the record-format we conform to (RFC 8785 + SHA-256 chain)
#
# .context/ is gitignored. Safe to re-run: existing clones are refreshed (git pull),
# missing ones are cloned shallow.
#
# Usage:
#   ./scripts/clone-context.sh          # run from repo root (or anywhere; it finds the root)

set -euo pipefail

# --- resolve repo root (works whether run from root or scripts/) -------------
if git rev-parse --show-toplevel >/dev/null 2>&1; then
  ROOT="$(git rev-parse --show-toplevel)"
else
  # fallback: directory containing this script's parent
  ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi

CONTEXT_DIR="$ROOT/.context"
mkdir -p "$CONTEXT_DIR"

# --- ensure .context/ is gitignored ------------------------------------------
GITIGNORE="$ROOT/.gitignore"
if ! { [ -f "$GITIGNORE" ] && grep -qxF ".context/" "$GITIGNORE"; }; then
  printf '\n# local reference repos (see scripts/clone-context.sh)\n.context/\n' >> "$GITIGNORE"
  echo "Added .context/ to .gitignore"
fi

# --- repos: "url dirname" ----------------------------------------------------
REPOS=(
  "https://github.com/sharkdp/bat bat"
  "https://github.com/sharkdp/fd fd"
  "https://github.com/BurntSushi/ripgrep ripgrep"
  "https://github.com/starship/starship starship"
  "https://github.com/bkuan001/halo-record halo-record"
)

echo "Cloning reference repos into $CONTEXT_DIR"
echo

FAILED=()
for entry in "${REPOS[@]}"; do
  url="${entry%% *}"
  name="${entry##* }"
  dest="$CONTEXT_DIR/$name"

  if [ -d "$dest/.git" ]; then
    echo ">> $name: exists, refreshing"
    if ! git -C "$dest" pull --ff-only --quiet; then
      echo "   (pull failed, leaving existing clone as-is)"
    fi
  else
    echo ">> $name: cloning"
    if ! git clone --depth 1 --quiet "$url" "$dest"; then
      echo "   FAILED to clone $url"
      FAILED+=("$name")
    fi
  fi
done

echo
if [ "${#FAILED[@]}" -eq 0 ]; then
  echo "Done. All reference repos are in .context/"
else
  echo "Done, but these failed (network?): ${FAILED[*]}"
  echo "They are references only — you can continue without them and re-run later."
fi
