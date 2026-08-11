#!/usr/bin/env bash
# Run on 10.1.96.53 to serve the dummy web page.
# Requires sudo because we bind to port 80.

set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
PORT="${DEMO_PORT:-80}"

echo "== NOTICE demo target =="
echo "Serving $DIR on port $PORT ..."
echo "The sshd on this host should already be running for Stage 2."
echo
echo "Verify SSH is reachable:"
ss -ltn 2>/dev/null | grep -E ":22\b" || echo "  (couldn't check ss — ignore if SSH is fine)"
echo
echo "Press Ctrl-C to stop the web server after the demo."
echo

# Kill any prior demo server on this port
sudo -n fuser -k "${PORT}/tcp" 2>/dev/null || true

cd "$DIR"
sudo python3 -m http.server "$PORT"
