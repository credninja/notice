# NOTICE — Live Attack Simulation for Management Demo

**Scenario:** A simulated attacker at **10.2.139.119** (Windows laptop) runs a 3-stage attack against **10.1.96.53** (internal server: FreeIPA + sshd). NOTICE detects, auto-promotes, and the analyst closes the incident on-screen.

**Duration:** ~4 min attack + ~10 min UI walkthrough.

---

## Pre-flight (do this once, an hour before the demo)

### On the NOTICE host (this box)

```bash
# 1. Install the demo rules
sudo cp /home/notice/Documents/notice/demo/demo.rules /var/lib/suricata/rules/notice-demo.rules

# 2. Add the include to suricata.yaml if it's not there yet
grep -q "notice-demo.rules" /etc/suricata/suricata.yaml || \
  sudo sed -i '/^rule-files:/a\  - /var/lib/suricata/rules/notice-demo.rules' /etc/suricata/suricata.yaml

# 3. Reload Suricata
sudo kill -USR2 $(pgrep -f suricata)

# 4. Confirm the 5 demo rules loaded
sudo grep "5900001\|5900002\|5900003\|5900004\|5900005" /var/log/suricata/suricata.log
```

### On the target — 10.1.96.53

Copy `demo/target/` there and run:

```bash
# On 10.1.96.53, in the demo/target folder:
./setup-target.sh
```

Leaves a `python3 -m http.server 80` running in the foreground. **Keep this terminal open during the demo.**

### On the attacker — 10.2.139.119 (Windows laptop)

Copy `demo/attacker/attack.ps1` to the desktop.

Open PowerShell **as regular user** and confirm:

```powershell
Get-Command ssh.exe   # should exist (Windows OpenSSH client)
Get-Command curl.exe  # should exist (Windows 10+)
```

If either is missing, install them via Settings → Apps → Optional Features → "OpenSSH Client".

---

## Running the demo

### T-0 — Open two browser tabs on the NOTICE host

1. **Tab A** — NOTICE UI: `https://<notice-ip>:8080`, login as `admin`, land on Dashboard.
2. **Tab B** — Alerts page (`#security`) so the live-alert ticker is visible.

### T+0 — Run the attack (from the Windows laptop)

```powershell
cd $HOME\Desktop
.\attack.ps1
```

The script runs 3 stages with 30-second pauses between them:

| Stage | What it does | Suricata rule that fires |
|-------|--------------|--------------------------|
| 1 (0-1 min) | TCP SYN scan of 30 ports on 10.1.96.53 | `sid 5900001` — TCP port scan |
| 2 (1-2 min) | 8 SSH login attempts with bogus creds | `sid 5900002` — SSH brute force |
| 3 (2-4 min) | Path traversal + SQLi curl + sqlmap User-Agent | `sids 5900003 / 5900004 / 5900005` |

**Talk track while the attack runs:** "In a real SOC, this is exactly what the first minute of an attack looks like — a scan to see what's up, then a brute-force attempt, then a targeted web exploit. Watch NOTICE catch each stage in real time."

### T+4 — UI walkthrough

Everything below happens on the NOTICE UI. Speak while you click.

**Step 1 — Alerts page (grouped view)**

- Point out the 3-5 new alert groups from `src 10.2.139.119`.
- Click 🧠 **Story** on the port-scan cluster: "Local LLM narrates what this cluster represents — no cloud call, everything stays on-prem."
- Click 🧠 **Bulk** on the same cluster: "It looked at prior FP ratios and the fact that the source is untrusted — it recommends `bulk_investigate`, not auto-close, because the source is unclassified."

**Step 2 — Incidents page**

- The auto-promotion engine should have created an incident from the port-scan burst.
- Click the incident → **Why Promoted?** button: "It cites the actual factors — high alert burst count, source is unclassified, kill-chain phase is Reconnaissance."
- Click **Analyze**: "LLM reads the incident + 30-day history for this signature and gives a verdict."
- Click **Similar History**: "Any prior closures of the same signature — 0 in a fresh demo, but this is where analyst muscle memory pays off."

**Step 3 — Evidence + close**

- Upload a fake pcap file (any file works — the demo doesn't need real bytes).
- Point out the SHA-256 hash: "Chain of custody. Anyone tampering with the evidence file breaks the hash."
- Click **Close as True Positive**, fill in classification (`Reconnaissance / Scanning`, MITRE `T1046`), impact (`None`), a one-line summary.

**Step 4 — Dashboard + PDF report**

- Back to Dashboard → 🧠 **Situation Report** now reflects the new closure.
- Incidents → **Daily Report** tab → **Generate PDF**: opens a printable PDF with the closure card, evidence hashes, and executive summary written by the local LLM.
- Punchline: "That PDF is the artifact you hand to auditors or an incident-response retainer. Everything from raw alert to signed report happened on one Ubuntu box, no cloud calls."

---

## Recovery (after the demo)

**Attacker box:** nothing to clean up — the script is idempotent.

**Target (10.1.96.53):** Ctrl-C the `setup-target.sh` process.

**NOTICE host:**
```bash
# Remove the demo rules
sudo rm /var/lib/suricata/rules/notice-demo.rules
sudo sed -i '\|/var/lib/suricata/rules/notice-demo.rules|d' /etc/suricata/suricata.yaml
sudo kill -USR2 $(pgrep -f suricata)
```

If you don't remove them, they'll keep firing on any real port scan / SSH brute against your network — that may actually be what you want. Your call.

---

## If a stage doesn't fire an alert

1. **`sudo tail -f /var/log/suricata/eve.json | grep 5900`** during the attack — if nothing appears, the rule didn't load. Re-run the pre-flight install steps.
2. **`sudo suricatasc -c "reload-rules"`** as an alternative to the USR2 kill.
3. Verify the interface Suricata monitors actually sees traffic between `10.2.139.119` and `10.1.96.53`: `sudo tcpdump -i <iface> host 10.2.139.119 and host 10.1.96.53`.
