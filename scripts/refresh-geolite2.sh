#!/bin/bash
# Refresh the MaxMind GeoLite2 mmdb files. Run weekly to keep DBs current
# (MaxMind updates them twice a week on Tue/Fri).
#
# Reads MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY from project .env
# (which is gitignored — never commit credentials).
#
# Usage:    ./scripts/refresh-geolite2.sh
# Cron:     0 4 * * 0  /path/to/notice/scripts/refresh-geolite2.sh

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="$PROJECT_ROOT/.env"
DEST="$PROJECT_ROOT/geolite2"

if [ ! -f "$ENV_FILE" ]; then
  echo "✗ $ENV_FILE not found. Add MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY to it." >&2
  exit 1
fi

# Read creds from .env (skip blanks/comments)
ACCOUNT_ID=$(grep -E '^MAXMIND_ACCOUNT_ID=' "$ENV_FILE" | head -1 | cut -d= -f2-)
LICENSE_KEY=$(grep -E '^MAXMIND_LICENSE_KEY=' "$ENV_FILE" | head -1 | cut -d= -f2-)

if [ -z "$ACCOUNT_ID" ] || [ -z "$LICENSE_KEY" ]; then
  echo "✗ MAXMIND_ACCOUNT_ID or MAXMIND_LICENSE_KEY missing in $ENV_FILE" >&2
  exit 1
fi

mkdir -p "$DEST"
cd "$DEST"

for db in GeoLite2-City GeoLite2-ASN; do
  echo "→ Refreshing $db"
  TMP="${db}.tar.gz.tmp"
  HTTP_CODE=$(curl -sSL -u "$ACCOUNT_ID:$LICENSE_KEY" -w "%{http_code}" \
    "https://download.maxmind.com/geoip/databases/$db/download?suffix=tar.gz" \
    -o "$TMP" || echo "000")
  if [ "$HTTP_CODE" != "200" ]; then
    echo "  ✗ HTTP $HTTP_CODE — keeping previous $db.mmdb if present"
    rm -f "$TMP"
    continue
  fi
  # Extract into a temp file then atomic-move
  tar -xzf "$TMP" --strip-components=1 --wildcards "*/$db.mmdb" -O > "${db}.mmdb.new"
  rm "$TMP"
  mv "${db}.mmdb.new" "${db}.mmdb"
  echo "  ✓ $db.mmdb refreshed ($(du -h "$db.mmdb" | awk '{print $1}'))"
done

echo
echo "Restart NOTICE (or wait for the next process restart) to pick up the new databases."
