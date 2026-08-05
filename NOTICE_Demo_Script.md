# NOTICE — Management Demo Script
### Network Observation & Threat Intelligence Correlation Engine
**Prepared by:** Cyber Manthan — IIIT Hyderabad
**Duration:** 20-25 minutes
**Classification:** Internal Use Only

---

## Pre-Demo Setup Checklist

- [ ] NOTICE tool running and accessible in browser
- [ ] Browser in full-screen mode
- [ ] Time range set to "1 hour"
- [ ] victim_server.py copied to victim machine (10.3.0.166)
- [ ] attack_sim.py ready on attacker machine (10.2.138.149)
- [ ] Press `T` key to switch to Light mode if using projector
- [ ] PDF report pre-generated for quick reference

---

## OPENING (2 minutes)

**[Slide: NOTICE logo/header visible in browser]**

*Script:*

"Good morning everyone. Today I'm going to walk you through NOTICE — our **Network Observation & Threat Intelligence Correlation Engine**.

This is an in-house security monitoring tool that gives us **real-time visibility** into everything happening on our corporate network — who's communicating with whom, what threats are active, and which of our assets are at risk.

The tool works passively — it monitors all network traffic through **Suricata**, our network intrusion detection system, running **80,000+ detection signatures** plus **77 custom rules** written specifically for our network. It then **correlates** multiple data sources — network flows, DNS queries, TLS handshakes, HTTP traffic, alerts, and anomalies — into a single unified intelligence view.

Let me show you what it can do."

---

## SECTION 1: DASHBOARD (3 minutes)

**[Action: Click Dashboard tab — Press key `1`]**

*Script:*

"This is our real-time network dashboard. At the top you can see the key metrics:"

**[Point to each card]**

- "**Total Traffic** — the volume of data flowing through our network in the last hour"
- "**Total Flows** — individual network conversations"
- "**Unique Sources** — how many internal devices are actively communicating"
- "**Unique Destinations** — external services they're reaching"
- "**Alerts** — security events flagged by our detection engine"

**[Click on 'Unique Sources' card]**

"Every metric is **clickable**. When I click Sources, I immediately see every IP address with the **owner name**, how much data they've sent, and their protocols. Internal assets show as green 'INT', external as orange 'EXT'."

**[Point to Top Destinations table]**

"For external destinations, you'll notice we've enriched each IP with the **actual hostname**, **service provider** — like Google, Microsoft, Meta — and the **country**. Anything going to India shows in green, international traffic shows in orange. Unknown IPs are highlighted in red — these are higher risk."

**[Click: Priority Assets sub-tab]**

"This is our **Priority Assets** view. It ranks every identified internal asset by a calculated **risk score** from 0 to 100. The score weighs:
- Critical alerts: 40%
- High alerts: 30%
- External exposure: 15%
- Traffic volume: 10%

You can see which assets need immediate attention."

---

## SECTION 2: SECURITY ALERTS (2 minutes)

**[Action: Click Security tab — Press key `3`]**

*Script:*

"Here's our **live alert feed** from Suricata. Alerts are classified into four severity levels:"

**[Point to severity cards]**

- "**Critical** — requires immediate response"
- "**High** — significant threat, investigate within hours"
- "**Medium** — potential concern, review during shift"
- "**Low** — informational, for awareness"

**[Click 'High' card to filter]**

"Each severity level is **clickable** — it filters the alert log instantly. Same with the **Alert Categories** section below — I can click any category like 'Misc activity' or 'Not Suspicious Traffic' to see only those alerts."

"This helps our analysts prioritize — instead of scrolling through hundreds of alerts, they can focus on what matters."

---

## SECTION 3: ANOMALY DETECTION (3 minutes)

**[Action: Click Anomalies tab — Press key `5`]**

*Script:*

"This is where NOTICE goes beyond traditional signature matching. Our **anomaly detection engine** uses behavioral analysis to find patterns that deviate from normal baseline."

**[Point to the top cards]**

"We distinguish between three levels:
- **Real Anomalies** — confirmed suspicious behavior with high confidence
- **Suspected** — statistical deviations that need investigation
- **Total Flags** — everything including false positives"

"This classification prevents alert fatigue — analysts know exactly which findings are actionable."

**[Click on a Real Anomaly row to expand reasoning]**

"For every anomaly, NOTICE provides **forensic reasoning** — not just that something is wrong, but **why** it's anomalous. For example:"

*Read the expanded reasoning for the top anomaly*

"This isn't a simple rule match. The tool is explaining its detection logic — what baseline was violated, what threshold triggered, and what security risk it indicates."

**[Point to confidence and detection type columns]**

"We also classify the **detection method** — whether it's statistical, threshold-based, rule-based, or protocol analysis. And the **confidence level** tells you if this is confirmed or needs verification."

---

## SECTION 4: INVESTIGATE (2 minutes)

**[Action: Click Investigate tab — Press key `4`, enter an active IP]**

*Script:*

"When we identify a suspicious IP, we can do a **deep investigation**. Let me look at [type an active IP]."

**[Wait for results to load]**

"Immediately we see a comprehensive profile:
- **Owner name** and asset information
- **Risk indicators** — highlighted in colored badges
- **All connections** this host has made — with each peer enriched to show hostname, service provider, and country
- **DNS queries** — what domains they've been looking up
- **TLS sessions** — encrypted connections with version information
- **Event timeline** — every single network event, newest first"

**[Click on an external IP in the connections table]**

"I can pivot to investigate any peer — click their IP and get the same deep profile. This allows us to trace the complete communication chain."

---

## SECTION 5: LIVE ATTACK DEMO (5 minutes)

**[This is the most impactful section — practice it beforehand]**

*Script:*

"Now I'm going to demonstrate something powerful. I'm going to launch a **real attack simulation** against one of our internal machines, and you'll watch NOTICE detect it **live**."

**[Open terminal 1 — on victim machine 10.3.0.166]**

```
python3 victim_server.py --port 8080
```

"I've started a web service on our test machine. Now watch the Security tab as I launch the attack."

**[Open terminal 2 — on attacker machine 10.2.138.149]**

```
python3 attack_sim.py --port 8080 --slow
```

**[Switch back to browser, Security tab]**

"The attack is now running through 6 phases:

1. **Port scanning** — probing for open services
2. **Web probing** — directory enumeration, looking for sensitive files
3. **SQL injection** — attempting to extract database data
4. **Brute force** — trying common username/password combinations
5. **Data exfiltration** — simulating data theft
6. **C2 beaconing** — mimicking malware calling home"

**[Click Refresh every 30 seconds]**

"Watch — alerts are appearing in real time... There's a **port scan detection**... now **SQL injection attempts**... **brute force login failures**..."

**[Click on the attacker IP 10.2.138.149 to investigate]**

"Now I click the attacker's IP and I can see the **complete attack chain** — every step they took, every payload they sent, the exact timestamps. This is the kind of forensic visibility that helps us understand not just **that** we were attacked, but **how** the attack progressed."

---

## SECTION 6: ASSET INVENTORY (2 minutes)

**[Action: Click Assets tab — Press key `7`]**

*Script:*

"NOTICE maintains a comprehensive asset inventory from three perspectives."

**[Click: Manage sub-tab]**

"**Manage** shows our registered assets — [X] total, with owner names, device types, and notes."

**[Click: Inventory sub-tab]**

"**Inventory** shows what our passive discovery engine has fingerprinted. Without installing any agent, NOTICE infers:
- **Device type** — server, workstation, mobile, IoT
- **Operating system** — from HTTP User-Agents, SSH banners, and TLS fingerprints
- **Applications in use** — Chrome, Firefox, VSCode, WhatsApp, Discord
- **Risk score** per asset"

**[Click: Unregistered/Rogue sub-tab]**

"This is **critical** — these are IP addresses active on our network that are **not** in our asset database. They're grouped by /24 subnet. We've found over **1,600 unregistered IPs** across **[X] subnets**."

**[Click Probe on one subnet]**

"When I click Probe, NOTICE actively fingerprints each device — scanning ports, grabbing service banners, checking TLS certificates. Watch the live progress..."

"For example, we discovered an **Apple AirPlay device** on port 5000 that nobody registered. This is shadow IT — and it's a security risk."

---

## SECTION 7: COMPLIANCE (1 minute)

**[Action: Click Compliance tab — Press key `8`]**

*Script:*

"We enforce **6 active security policies**:
1. No plaintext HTTP
2. No FTP (credentials in cleartext)
3. No unencrypted SMTP
4. No weak SNMP community strings
5. No BitTorrent
6. No deprecated TLS versions"

**[Click Violations sub-tab]**

"This shows real-time policy violations. Right now we have [X] plaintext HTTP flows and [X] deprecated TLS connections that need remediation. Each violation is traceable to a specific asset and timestamp."

---

## SECTION 8: REPORTS (2 minutes)

**[Action: Click Reports tab — Press key `9`, then Download PDF]**

*Script:*

"For executive reporting, NOTICE generates a **professional 12-page PDF report**."

**[Open the downloaded PDF]**

"It includes:
- **Cover page** with Cyber Manthan branding and overall risk score
- **Executive summary** in non-technical language suitable for board presentations
- **Key metrics dashboard** with visual cards
- **Anomaly analysis** with forensic reasoning for each detection
- **Geographic distribution** — showing traffic to [X] countries, distinguishing India from international
- **Internal asset ranking** by risk score
- **Threat & alert summary** with category breakdown
- **Recommendations** — both immediate actions and strategic improvements
- **Final security assessment** with organizational readiness rating"

"This report is designed to answer three questions:
1. **What happened?**
2. **Why does it matter?**
3. **What should we do about it?**"

---

## SECTION 9: THREAT INSIGHTS (1 minute)

**[Action: Click Threat Insights tab — Press key `0`]**

*Script:*

"This tab provides advanced threat analysis:
- **JA4 fingerprinting** — identifies known malware families by their TLS fingerprint, including Cobalt Strike, Metasploit, and Sliver
- **DNS tunneling detection** — uses Shannon entropy analysis to catch data being exfiltrated through DNS queries
- **C2 beaconing detection** — identifies malware calling home by analyzing timing regularity of connections
- **MAC tracking** — discovers devices via DHCP for network inventory"

---

## SECTION 10: DRILL-DOWN (1 minute)

**[Action: Click Drill-Down tab]**

*Script:*

"Finally, our Drill-Down view maps everything to the **NIST Cybersecurity Framework 2.0**. It answers 10 key management questions across six domains:

- **Govern** — What's our overall security posture score?
- **Identify** — What assets do we have? What's shadow IT?
- **Protect** — Are we blocking threats? Using encryption?
- **Detect** — What are we catching? What's the false positive rate?
- **Respond** — How fast are we responding? Are SLAs being met?
- **Recover** — Are we doing root cause analysis? Learning from incidents?"

"This gives leadership a **framework-aligned** view of our security program maturity."

---

## CLOSING (2 minutes)

*Script:*

"To summarize what NOTICE gives us:

**Visibility** — Every device, every connection, every protocol on our 10.0.0.0/8 network. Over 1,600 devices discovered passively.

**Detection** — 80,000+ Suricata signatures, behavioral anomaly detection, and 77 custom rules tailored to our environment.

**Enrichment** — Every IP enriched with owner name, hostname, service provider, country, and risk score. We see intelligence, not raw logs.

**Correlation** — Flows + alerts + DNS + TLS + HTTP + anomalies all correlated per asset. One click gives the complete picture.

**Action** — Every finding comes with severity, forensic reasoning, and recommended response. Incidents are tracked with SLA compliance.

**Zero cost** — Built entirely in-house using open-source components: Python, Suricata, Emerging Threats Pro rules.

**Zero agents** — Completely passive. No software installed on any endpoint."

*Pause*

"Are there any questions?"

---

## APPENDIX: EXPECTED QUESTIONS & ANSWERS

| Question | Answer |
|----------|--------|
| How much does this cost? | Zero licensing cost. Built with open-source tools — Python (free), Suricata (free), ET Pro rules (academic license). Only cost is the server hardware running it. |
| What if traffic is encrypted? | We see all metadata — who talks to whom, when, how much, TLS versions, JA3 fingerprints, DNS queries, certificate details. We don't need content for most detections. |
| Can it block attacks? | Currently detection-only (IDS mode). Suricata can switch to IPS mode for inline blocking. We recommend keeping it in IDS mode first to tune rules, then enable IPS for confirmed threats. |
| How real-time is it? | Alerts appear within seconds. Dashboard refreshes on demand. The tool reads Suricata's live log file continuously. |
| How is the risk score calculated? | Weighted formula: Critical alerts (40%), High alerts (30%), Medium alerts (20%), Unique attacking IPs (10%). Maximum score 100. Documented and auditable. |
| How many assets do we monitor? | 31 registered assets with owners. 1,647+ IPs discovered passively. 780+ unregistered/rogue devices identified. |
| What about the unregistered devices? | The Inventory tab lists all of them grouped by subnet. We can actively probe any of them to identify OS, services, and TLS certificates. The goal is to register them or block them. |
| Can we use this for compliance? | Yes — the Drill-Down tab maps directly to NIST CSF 2.0. The Compliance tab enforces 6 active policies. Reports are formatted for management presentation. |
| What's different from commercial tools? | We built exactly what we need, tuned for our 10.0.0.0/8 network. 77 custom rules target our specific assets. Commercial tools are generic. Also — zero recurring license cost. |
| Can other teams use it? | Yes — it's a web application accessible from any browser on the network via HTTPS. No installation needed for viewers. |

---

## KEYBOARD SHORTCUTS FOR SMOOTH DEMO

| Key | Action |
|-----|--------|
| `1`-`0` | Switch tabs instantly (1=Dashboard, 3=Security, 5=Anomalies, 7=Assets, 9=Reports) |
| `R` | Refresh current page |
| `T` | Toggle Light/Dark mode (use Light for projector) |
| `E` | Export current table as CSV |
| `/` | Focus search bar |
| `?` | Show all shortcuts |

**Pro tip:** Press `T` to switch to Light mode before connecting to the projector — it's much more readable on white screens.

---

## DEMO FLOW DIAGRAM

```
OPENING (2 min)
    |
    v
DASHBOARD (3 min) -----> Priority Assets
    |
    v
SECURITY (2 min) -------> Clickable severity filters
    |
    v
ANOMALIES (3 min) ------> Expand forensic reasoning
    |
    v
INVESTIGATE (2 min) ----> Deep IP profile
    |
    v
LIVE ATTACK (5 min) ----> Start victim_server
    |                      Start attack_sim
    |                      Watch alerts appear live
    |                      Investigate attacker IP
    v
ASSETS (2 min) ---------> Manage / Inventory / Rogue
    |
    v
COMPLIANCE (1 min) -----> Policies + Violations
    |
    v
REPORTS (2 min) --------> Download PDF, show sections
    |
    v
THREAT INSIGHTS (1 min)
    |
    v
DRILL-DOWN (1 min) -----> NIST CSF 2.0 mapping
    |
    v
CLOSING (2 min) --------> Summary + Q&A
```

---

*Document prepared by NOTICE Security Monitor*
*Cyber Manthan — IIIT Hyderabad*
*Classification: Internal Use Only*
