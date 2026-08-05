# GeoLite2 Offline IP Database

This directory holds the **MaxMind GeoLite2** binary databases used by NOTICE for offline IP enrichment (country / city / ASN). Without these files, NOTICE falls back to the on-demand `ip-api.com` HTTP lookup, which is slower and rate-limited.

## What to put here

Two files (both required for full coverage):

```
geolite2/GeoLite2-City.mmdb      ~70 MB — country, country_code, city, lat/lon
geolite2/GeoLite2-ASN.mmdb       ~10 MB — autonomous system number + organisation
```

These are gitignored — keep them out of the repo.

## How to download (one-time, free)

1. Create a free MaxMind account: https://www.maxmind.com/en/geolite2/signup
2. After verifying your email, generate a license key:
   - Go to **Account Dashboard → Manage License Keys → Generate new license key**
3. Download the two mmdb files. Easiest way is the script below — paste your account ID and license key:

   ```bash
   ACCOUNT_ID=YOUR_ACCOUNT_ID
   LICENSE_KEY=YOUR_LICENSE_KEY
   cd geolite2/
   for db in GeoLite2-City GeoLite2-ASN; do
     curl -fsS -u "$ACCOUNT_ID:$LICENSE_KEY" \
       "https://download.maxmind.com/geoip/databases/$db/download?suffix=tar.gz" \
       -o "$db.tar.gz"
     tar -xzf "$db.tar.gz" --strip-components=1 --wildcards "*/$db.mmdb"
     rm "$db.tar.gz"
   done
   ls -la *.mmdb
   ```

4. Confirm the files appear in this directory:

   ```
   GeoLite2-City.mmdb
   GeoLite2-ASN.mmdb
   ```

5. Restart NOTICE — the offline lookup activates automatically. Visit `/api/geoip/status` to confirm the DBs are loaded.

## Auto-update

MaxMind refreshes these databases twice weekly. To keep yours fresh, run the same download script on a cron, e.g. weekly:

```cron
0 4 * * 0  cd /path/to/notice/geolite2 && /path/to/refresh-script.sh
```

## Fallback behaviour

If the mmdb files are missing or unreadable, NOTICE silently falls back to the existing on-demand `ip-api.com` HTTP lookup. The app keeps working; you just lose the offline / no-rate-limit benefit. The status endpoint will indicate which mode is active.
