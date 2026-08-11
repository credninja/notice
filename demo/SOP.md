# NOTICE Demo — SOP (copy-paste)

Three machines involved:

| Role     | Host          | Login user |
|----------|---------------|------------|
| NOTICE   | 10.1.96.71    | notice     |
| Target   | 10.1.96.53    | darlene    |
| Attacker | 10.2.139.119  | IIITH (Windows) |

---

## 1) Start the target server (on 10.1.96.53)

From the NOTICE host:

```bash
ssh darlene@10.1.96.53
```

On `darlene@ipa`:

```bash
cd ~/notice-demo
DEMO_PORT=8080 ./setup-target.sh
```

Leaves a Python web server running on port 8080 in the foreground. **Do not close this terminal until the demo is over.** Ctrl-C to stop after the demo.

Verify from any machine:
```bash
curl -s http://10.1.96.53:8080/ | head -3
```
Should return the ACME login page HTML.

---

## 2) Run the attack (on the Windows laptop 10.2.139.119)

Open **PowerShell** (regular user, no admin needed) and run:

```powershell
cd $HOME\Desktop
powershell -ExecutionPolicy Bypass -File .\attack.ps1
```

Runtime: ~4 minutes. The script prints a cyan banner for each of 3 stages with a 30-second pause between them for narration.

If you ever need to pull a fresh copy of the script:
```powershell
scp notice@10.1.96.71:/home/notice/Documents/notice/demo/attacker/attack.ps1 $HOME\Desktop\attack.ps1
```

---

## 3) Watch it in NOTICE (on 10.1.96.71)

Open `https://10.1.96.71:8080` in a browser (login `admin`), go to **Alerts**. Within 30s of each attack stage you'll see:

| Stage | Rule fires | Signature |
|-------|-----------|-----------|
| 1. Port scan | sid **5900001** | NOTICE DEMO Stage 1 -- TCP port scan (SYN burst) |
| 2. SSH brute | sid **5900002** | NOTICE DEMO Stage 2 -- SSH brute-force attempt |
| 3a. Path traversal | sid **5900003** | NOTICE DEMO Stage 3 -- Path traversal attempt |
| 3b. SQL injection | sid **5900004** | NOTICE DEMO Stage 3 -- SQL injection attempt |
| 3c. sqlmap UA | sid **5900005** | NOTICE DEMO Stage 3 -- Attacker tool detected (sqlmap User-Agent) |

Auto-promotion should create 1-3 incidents from these clusters. Then walk the audience through: Incidents page -> Why Promoted? -> Analyze -> upload evidence -> Close as TP -> Daily Report PDF.

---

## Cleanup after the demo

**On darlene@ipa:** Ctrl-C the `setup-target.sh` terminal.

**On the NOTICE host (only if you want to disable the demo rules):**
```bash
sudo rm /var/lib/suricata/rules/notice-demo.rules
sudo sed -i '\|/var/lib/suricata/rules/notice-demo.rules|d' /etc/suricata/suricata.yaml
sudo kill -USR2 $(pgrep -f suricata)
```

Leaving them in place is fine — they'll fire on any real scan/brute/web-attack against your network, which may be what you want.
