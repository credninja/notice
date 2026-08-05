# NOTICE — Network Operations & Threat Intelligence Console for Enterprises

A self-hosted SOC console that turns raw Suricata IDS output into a triage-friendly workflow: alerts → auto-promoted incidents → analyst assignment → evidence-backed closure → executive reports.

Built to run on a single Ubuntu server with **stdlib-only Python** (no `pip install -r requirements.txt` needed for the core) — everything from ingestion to the web UI ships in the repo.

---

## Features

### Detection & Ingestion
- Tails Suricata's `eve.json` every 2 seconds — resilient to log rotation and truncation
- Indexes alerts into SQLite (WAL) with 6+ indexes for fast queries
- Byte-offset bookmark in DB — pipeline survives restarts without duplicating or losing alerts

### Alerts
- Grouped view (dedup by SID + src + dst) + Raw view
- Real-time live-alert ticker via Server-Sent Events
- Full-text search across IP / SID / port / signature / owner
- Kill-chain phase classification (7 phases, ~100 signature patterns → MITRE ATT&CK techniques)
- On-demand PCAP retrieval per alert
- Verdict marking (TP / FP / investigating) + bulk verdict actions

### Incident Management
- Auto-promotion from alerts based on declarative rules (severity + IOC score + burst + kill-chain phase + critical-asset flag)
- FP suppression — signatures marked FP ≥2 times in 7 days won't create new incidents
- Analyst assignment with in-app notification bell (30s poll, unread badge)
- Related-history panel per incident: prior TP/FP ratio for the same signature helps triage
- Reopen closed incidents (verdict cleared, phase reset)
- Bulk actions: close as FP/TP, assign, mark investigating, delete
- Personal dashboard: SLA-breached count, oldest open incident age, breakdown by severity
- Evidence upload with SHA-256 hashing (chain of custody)

### Threat Intelligence
- VirusTotal + AbuseIPDB integration (cache-first, rate-limited)
- Offline GeoLite2 lookup (no per-query API cost)
- JA3/JA4 TLS fingerprint matching against known C2 frameworks (Cobalt Strike, Sliver, Havoc, Mythic, Meterpreter, Brute Ratel)

### Analytics
- Passive asset discovery from flow + DNS + DHCP + HTTP + TLS
- Anomaly detection: DGA domains, DNS tunneling, C2 beaconing, port scans, lateral movement
- Attack correlation into multi-phase chains
- MITRE ATT&CK mapping per signature

### Reporting
- Daily incident closure PDF with SVG donut charts + per-incident cards + full RCA sections
- CSV export with all closure fields + evidence file references
- Analyst-selectable per-incident report (tick boxes → generate report for only those incidents)

### Access Control
- Role-based (admin / analyst / viewer) enforced at the middleware level
- Password hashing: PBKDF2-HMAC-SHA256, 310k iterations
- Session cookies (HTTPS-only when TLS active) + CSRF header check on writes
- API key management for programmatic access
- Full audit log of all user actions

---

## Quick Start (5 minutes, existing Suricata)

For a full production deployment (blank server → running SOC), see **[DEPLOYMENT.md](DEPLOYMENT.md)** (also available as [DEPLOYMENT.pdf](DEPLOYMENT.pdf)).

For a quick test on a host that already has Suricata:

```bash
# 1. Clone
git clone https://github.com/credninja/notice.git
cd notice

# 2. Set up Python virtual environment
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
# Optional (only for Sigma rule imports):
pip install PyYAML

# 3. Generate self-signed TLS cert
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
    -keyout certs/key.pem -out certs/cert.pem \
    -subj "/CN=notice.local" \
    -addext "subjectAltName=DNS:notice.local,DNS:localhost,IP:127.0.0.1"

# 4. Confirm you can read eve.json (add yourself to suricata group if needed)
sudo usermod -aG suricata $USER
newgrp suricata
head -1 /var/log/suricata/eve.json > /dev/null && echo "OK"

# 5. Run
python3 app.py
```

Open `https://<server-ip>:8080` — accept the self-signed cert — log in as **admin / admin** — change the admin password immediately.

---

## Configuration

Everything is controlled by environment variables. Create a `.env` file in the repo root:

| Variable | Default | Description |
|----------|---------|-------------|
| `EVE_LOG` | `/var/log/suricata/eve.json` | Path to Suricata's EVE JSON output |
| `HOST` | `0.0.0.0` | Bind interface |
| `PORT` | `8080` | Bind port |
| `AUTH_ENABLED` | `true` | Set to `false` only for isolated testing — this disables ALL authentication |
| `MONITORED_NET` | `10.0.0.0/8` | Your internal address space (must match Suricata's HOME_NET) |
| `VIRUSTOTAL_API_KEY` | *(unset)* | Optional — enables VT enrichment of external IPs |
| `ABUSEIPDB_KEY` | *(unset)* | Optional — enables AbuseIPDB reputation scoring |
| `MAX_LINES` | `1000000` | Max eve.json lines to parse per query |

The `.env` file is gitignored — never commit it.

---

## Roles & Permissions

| Role | Reads | Writes on incidents / evidence / IOCs / alerts | Manages users / rules / policies | Admin panel access |
|------|:-----:|:---:|:---:|:---:|
| **viewer** | ✅ | ❌ | ❌ | ❌ |
| **analyst** | ✅ | ✅ | ❌ | ❌ |
| **admin** | ✅ | ✅ | ✅ | ✅ |

Enforcement lives in `app.py`'s `before_request` hook. See DEPLOYMENT.md §13 for hardening tips.

---

## Project Structure

```
notice/
├── app.py                  # Bottle entry point, HTTPS server, RBAC middleware
├── db.py                   # SQLite schema + seed data (~30 tables)
├── auth.py                 # Sessions, password hashing, RBAC decorators
├── eve_reader.py           # eve.json tail + noise filter
├── pipeline.py             # DB ingestion pipeline (daemon thread)
│
├── analyzers/              # ~40 modules
│   ├── correlation.py      # Kill-chain phase mapping + attack chain builder
│   ├── auto_promote.py     # Alert → incident promotion engine + FP suppression
│   ├── anomaly.py          # DGA / DNS-tunnel / beacon / scan detectors
│   ├── asset_discovery.py  # Passive asset inventory
│   ├── virustotal.py       # VT API client (cache-first, rate-limited)
│   ├── reputation.py       # AbuseIPDB client
│   ├── geoip.py            # GeoLite2 lookups
│   ├── threat_intel.py     # JA3/JA4 → known C2 framework mapping
│   └── ...
│
├── routes/                 # HTTP endpoint modules
│   ├── auth.py             # /api/auth/*  (login, users, API keys)
│   ├── security.py         # /api/alerts
│   ├── incidents.py        # /api/incidents/* (CRUD, bulk, reopen, dashboard)
│   ├── case_mgmt.py        # /api/incidents/<id>/evidence (upload/download/delete)
│   ├── containment.py      # /api/containment/* (block / quarantine / watch)
│   ├── dashboard.py        # /api/dashboard
│   ├── graph.py            # /api/graph (D3 network map)
│   └── ...
│
├── static/
│   ├── index.html          # Single-page app (vanilla JS + D3 + Chart.js)
│   └── pipeline_deep_dive.html   # Printable architecture reference
│
├── DEPLOYMENT.md           # Full deployment manual (blank server → running SOC)
├── DEPLOYMENT.pdf          # Same, printable
└── README.md               # This file
```

Excluded from repo (`.gitignore`): `venv/`, `notice.db*`, `certs/`, `evidence/`, `.env`, `*.pem`, `*.key`, `SECURITY_ASSESSMENT.md` (organization-specific), `suricata-rules/local.rules` (per-network custom rules).

---

## Architecture

```
   NETWORK
      │
      ▼   (mirrored via switch SPAN / TAP)
   ┌─────────────┐
   │  Suricata   │  packet inspection → JSON events
   └──────┬──────┘
          │  writes
          ▼
   ┌─────────────┐
   │  eve.json   │  (rolling append-only log)
   └──────┬──────┘
          │  tailed every 2s
          ▼
   ┌───────────────────────┐
   │  pipeline.py          │  parse alerts + insert into DB
   │  (daemon thread)      │
   └───────┬───────────────┘
           │
           ▼
   ┌─────────────────────┐
   │  SQLite (WAL)       │  indexed on ts / sid / src / dst / severity
   │   - ingested_alerts │
   │   - incidents       │
   │   - assets          │
   │   - evidence        │
   │   - user_notifs     │
   │   - audit_log       │
   └────┬──────────┬─────┘
        │          │
        ▼          ▼
   ┌────────┐  ┌──────────────────┐
   │Analyzers│  │  Bottle server   │  HTTPS :8080
   │(async) │  │  + RBAC + SSE    │
   └────────┘  └────────┬─────────┘
                        │
                        ▼
                 ┌────────────┐
                 │  Browser   │
                 │  (SPA)     │
                 └────────────┘
```

For a deep-dive on each component (correlation engine, auto-promotion engine, evidence chain of custody), see [`static/pipeline_deep_dive.html`](static/pipeline_deep_dive.html).

---

## Development

- **Language:** Python 3.12+ (stdlib only for core; PyYAML optional for Sigma import)
- **Database:** SQLite with WAL journaling (PostgreSQL support via `DATABASE_URL`)
- **Web framework:** Bottle (single-file, embeddable)
- **Frontend:** Vanilla JavaScript + D3.js + Chart.js — no build step
- **Threading:** Threaded WSGI server so long-lived Server-Sent Events streams don't block requests

---

## Documentation

- **[DEPLOYMENT.md](DEPLOYMENT.md)** / **[DEPLOYMENT.pdf](DEPLOYMENT.pdf)** — full step-by-step production deployment guide (14 sections, covers integrating with an existing Suricata instance)
- **[static/pipeline_deep_dive.html](static/pipeline_deep_dive.html)** — architecture reference (correlation, auto-promote, evidence system explained in detail)

---

## Security Notes

- **Default credentials:** `admin / admin` — **change immediately on first login**
- **Self-signed TLS by default** — replace with a proper CA-signed cert (Let's Encrypt via reverse proxy, or your org's PKI) before exposing beyond a trusted network. See DEPLOYMENT.md §13.
- **Never expose to the public internet** without additional authentication (VPN, mTLS, reverse-proxy auth). NOTICE is designed for internal SOC use.
- **API keys are read from env vars only** — nothing hardcoded in the repo.
- **Rate limiting:** 5 failed logins → 15 min lockout per source IP.

---

## License

Internal / organizational use. Add explicit license terms before public release.

---

## Contributing

For internal contributions: open a PR against `main`.

External contributions: welcome as issues + PRs. Please:
- Never commit real network topology, personal names, or organizational identifiers
- Keep new rules generic — asset-specific rules belong in `suricata-rules/local.rules` (gitignored)
- Update DEPLOYMENT.md if you add / change installation steps
