#!/bin/bash
# Snapshot the live Suricata rules into the project so they get committed
# alongside the application code. Re-run any time the rules are updated
# (after `update_rules.sh` or after accepting a rule proposal) and commit
# the diff.
#
# Usage:  ./scripts/backup-rules.sh
#
# The script reads from the canonical rules dir (overridable via
# SURICATA_RULES_DIR) and writes into ./suricata-rules/ relative to the
# repo root, preserving file mtimes so git diffs are meaningful.

set -euo pipefail

SRC="${SURICATA_RULES_DIR:-/var/lib/suricata/rules}"
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$PROJECT_ROOT/suricata-rules"

if [ ! -d "$SRC" ]; then
  echo "✗ Source rules dir not found: $SRC" >&2
  echo "  Set SURICATA_RULES_DIR if your install puts rules elsewhere." >&2
  exit 1
fi

echo "→ Source: $SRC"
echo "→ Dest:   $DEST"

# Fresh sync — delete files that no longer exist upstream so the snapshot
# tracks the actual rules state. Use rsync if available for speed, else cp.
if command -v rsync >/dev/null 2>&1; then
  rsync -a --delete --exclude '*.tmp' --exclude '*.swp' "$SRC/" "$DEST/"
else
  rm -rf "$DEST"
  mkdir -p "$DEST"
  cp -a "$SRC/." "$DEST/"
fi

# Quick stats
total_files=$(find "$DEST" -type f | wc -l)
total_size=$(du -sh "$DEST" | awk '{print $1}')
echo "✓ Backed up $total_files files ($total_size)"
echo
echo "Next:"
echo "  git add suricata-rules"
echo "  git commit -m 'rules: snapshot $(date +%Y-%m-%d)'"
echo "  git push"
