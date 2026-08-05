"""
Passive Asset Discovery Engine
================================
Builds a comprehensive asset inventory purely from the IDS engine's
eve.json network monitoring data — no active scanning.

Data Sources Used:
  - Flow records (IP, ports, protocols, bytes, timestamps)
  - DHCP events (MAC address, assigned IP, hostname)
  - DNS queries (hostname resolution, query patterns)
  - HTTP events (User-Agent for OS/device fingerprinting)
  - TLS handshakes (JA3 fingerprints, SNI, TLS version)
  - SSH events (client/server software versions)
  - mDNS events (local device discovery)
  - Alert events (security posture)

Asset Attributes Extracted:
  - IP address (current + history via DHCP)
  - MAC address (from DHCP)
  - Hostname (from DNS, DHCP, mDNS, HTTP Host)
  - Device type (inferred: server, workstation, mobile, IoT, network)
  - Operating system (inferred from User-Agent, SSH, TLS)
  - Open/observed ports and services
  - Applications in use
  - First seen / last seen
  - Communication peers (internal + external)
  - Risk score (behavioral)
  - Role classification (web server, database, endpoint, etc.)
"""

import math
from collections import defaultdict, Counter
from eve_reader import iter_events, is_internal, is_ipv4
from db import get_db


# OS fingerprinting patterns from User-Agent strings
OS_PATTERNS = [
    ("Windows 11", ["Windows NT 10.0", "Windows NT 11"]),
    ("Windows 10", ["Windows NT 10.0"]),
    ("Windows 7", ["Windows NT 6.1"]),
    ("macOS", ["Macintosh", "Mac OS X"]),
    ("iOS", ["iPhone", "iPad", "iPod"]),
    ("Android", ["Android"]),
    ("Ubuntu", ["Ubuntu"]),
    ("Debian", ["Debian"]),
    ("Linux", ["Linux", "X11"]),
    ("ChromeOS", ["CrOS"]),
]

# Device type inference from observed behavior
SERVER_PORTS = {22, 53, 80, 443, 445, 3306, 5432, 8080, 8443, 5000, 3389, 25, 110, 143, 993, 995}
IOT_INDICATORS = {"ssdp", "mdns", "coap", "mqtt"}
NETWORK_DEVICE_PORTS = {161, 162, 179, 520}  # SNMP, BGP, RIP

# Known application patterns
APP_PATTERNS = {
    "spotify": {"ports": {57621, 4070}, "ua_match": "spotify"},
    "discord": {"sni_match": "discord"},
    "teams": {"sni_match": "teams.microsoft"},
    "zoom": {"sni_match": "zoom.us"},
    "slack": {"sni_match": "slack"},
    "vscode": {"sni_match": "vscode", "ua_match": "vscode"},
    "chrome": {"ua_match": "chrome"},
    "firefox": {"ua_match": "firefox"},
    "safari": {"ua_match": "safari"},
    "outlook": {"sni_match": "outlook"},
    "whatsapp": {"sni_match": "whatsapp"},
    "apt": {"ua_match": "apt-http", "ua_match2": "debian apt"},
}


def discover_assets(minutes=None):
    """
    Perform passive asset discovery from the IDS engine's eve.json.
    Returns comprehensive asset inventory.
    """
    # Per-IP data collection
    assets = defaultdict(lambda: {
        "ips": set(),
        "mac": "",
        "hostnames": set(),
        "os_hints": Counter(),
        "user_agents": Counter(),
        "server_ports": set(),       # Ports this IP listens on (dst_port when it's dst)
        "client_ports": set(),       # Ports this IP connects to as client
        "protocols": Counter(),      # App-layer protocols
        "transport": Counter(),      # TCP/UDP/ICMP
        "services_observed": set(),
        "applications": set(),
        "ja3_hashes": Counter(),
        "tls_versions": Counter(),
        "ssh_client": set(),
        "ssh_server": set(),
        "dns_queries": Counter(),    # Domains queried
        "peers_internal": set(),
        "peers_external": set(),
        "bytes_in": 0,
        "bytes_out": 0,
        "flows": 0,
        "alerts": [],
        "alert_count": 0,
        "anomaly_count": 0,
        "first_seen": "",
        "last_seen": "",
        "vlan": set(),
        "dhcp_hostname": "",
        "mdns_names": set(),
        "http_hosts_visited": Counter(),
    })

    # DHCP MAC-to-IP mapping
    mac_ip_map = {}

    # Process all events
    for ev in iter_events(minutes=minutes):
        etype = ev.get("event_type")
        src = ev.get("src_ip", "")
        dst = ev.get("dest_ip", "")
        ts = ev.get("timestamp", "")
        dp = ev.get("dest_port", 0)
        sp = ev.get("src_port", 0)
        proto = ev.get("proto", "")
        app_proto = ev.get("app_proto", "")

        if not is_ipv4(src):
            continue

        # Skip multicast/broadcast for asset building
        is_mcast = dst.startswith("224.") or dst.startswith("239.") or dst.startswith("255.") or dst == "0.0.0.0"

        # Update timestamps for internal IPs
        for ip in (src, dst):
            if not is_internal(ip) or not is_ipv4(ip):
                continue
            a = assets[ip]
            a["ips"].add(ip)
            if not a["first_seen"] or ts < a["first_seen"]:
                a["first_seen"] = ts
            if not a["last_seen"] or ts > a["last_seen"]:
                a["last_seen"] = ts
            vlan = ev.get("vlan", [])
            if vlan:
                for v in (vlan if isinstance(vlan, list) else [vlan]):
                    a["vlan"].add(v)

        # ── DHCP: MAC address + hostname extraction ──
        if etype == "dhcp":
            dhcp = ev.get("dhcp", {})
            mac = dhcp.get("client_mac", "")
            assigned_ip = dhcp.get("assigned_ip", "")
            hostname = dhcp.get("hostname", "")
            if assigned_ip and is_internal(assigned_ip):
                a = assets[assigned_ip]
                if mac:
                    a["mac"] = mac
                    mac_ip_map[mac] = assigned_ip
                if hostname:
                    a["dhcp_hostname"] = hostname
                    a["hostnames"].add(hostname)

        # ── Flow: bytes, ports, protocols, peers ──
        elif etype == "flow":
            flow = ev.get("flow", {})
            b_out = flow.get("bytes_toserver", 0)
            b_in = flow.get("bytes_toclient", 0)

            if is_internal(src):
                a = assets[src]
                a["bytes_out"] += b_out
                a["bytes_in"] += b_in
                a["flows"] += 1
                if proto:
                    a["transport"][proto] += 1
                if app_proto and app_proto != "failed":
                    a["protocols"][app_proto] += 1
                    a["services_observed"].add(app_proto)
                a["client_ports"].add(dp)
                if not is_mcast:
                    peer = dst
                    if is_internal(peer):
                        a["peers_internal"].add(peer)
                    else:
                        a["peers_external"].add(peer)

            if is_internal(dst) and not is_mcast:
                a = assets[dst]
                a["server_ports"].add(dp)
                a["bytes_in"] += b_out
                a["bytes_out"] += b_in
                a["flows"] += 1

        # ── HTTP: User-Agent for OS/app fingerprinting ──
        elif etype == "http":
            http = ev.get("http", {})
            ua = http.get("http_user_agent", "")
            host = http.get("hostname", "")
            if is_internal(src):
                a = assets[src]
                if ua:
                    a["user_agents"][ua] += 1
                    # OS detection
                    os_name = _detect_os(ua)
                    if os_name:
                        a["os_hints"][os_name] += 1
                    # App detection
                    apps = _detect_apps_from_ua(ua)
                    a["applications"].update(apps)
                if host:
                    a["http_hosts_visited"][host] += 1

        # ── DNS: hostname resolution, query patterns ──
        elif etype == "dns":
            dns = ev.get("dns", {})
            if dns.get("type") == "request" and is_internal(src):
                for q in dns.get("queries", []):
                    rrname = q.get("rrname", "")
                    if rrname:
                        assets[src]["dns_queries"][rrname] += 1
            # DNS answers for hostname mapping
            if dns.get("type") == "response":
                for ans in dns.get("answers", []):
                    rdata = ans.get("rdata", "")
                    rrname = ans.get("rrname", "")
                    if rdata and is_ipv4(rdata) and is_internal(rdata) and rrname:
                        assets[rdata]["hostnames"].add(rrname.rstrip("."))

        # ── TLS: JA3, version, SNI for app detection ──
        elif etype == "tls":
            tls = ev.get("tls", {})
            if is_internal(src):
                a = assets[src]
                ja3 = tls.get("ja3", {})
                if isinstance(ja3, dict):
                    h = ja3.get("hash", "")
                else:
                    h = str(ja3) if ja3 else ""
                if h:
                    a["ja3_hashes"][h] += 1
                version = tls.get("version", "")
                if version:
                    a["tls_versions"][version] += 1
                sni = tls.get("sni", "")
                if sni:
                    apps = _detect_apps_from_sni(sni)
                    a["applications"].update(apps)

        # ── SSH: software fingerprinting ──
        elif etype == "ssh":
            ssh = ev.get("ssh", {})
            client_sw = ssh.get("client", {}).get("software_version", "")
            server_sw = ssh.get("server", {}).get("software_version", "")
            if is_internal(src) and client_sw:
                assets[src]["ssh_client"].add(client_sw)
                os_hint = _detect_os_from_ssh(client_sw)
                if os_hint:
                    assets[src]["os_hints"][os_hint] += 1
            if is_internal(dst) and server_sw:
                assets[dst]["ssh_server"].add(server_sw)
                os_hint = _detect_os_from_ssh(server_sw)
                if os_hint:
                    assets[dst]["os_hints"][os_hint] += 1

        # ── mDNS: local device names ──
        elif etype == "mdns":
            mdns = ev.get("mdns", {})
            if is_internal(src):
                answers = mdns.get("answers", [])
                for ans in answers:
                    name = ans.get("rrname", "")
                    if name and ".local" in name:
                        assets[src]["mdns_names"].add(name.rstrip("."))
                        assets[src]["hostnames"].add(name.split(".")[0])

        # ── Alerts ──
        elif etype == "alert":
            alert = ev.get("alert", {})
            for ip in (src, dst):
                if is_internal(ip):
                    a = assets[ip]
                    a["alert_count"] += 1
                    if len(a["alerts"]) < 5:
                        a["alerts"].append({
                            "signature": alert.get("signature", ""),
                            "severity": alert.get("severity", 3),
                            "timestamp": ts,
                        })

        # ── Anomalies ──
        elif etype == "anomaly":
            for ip in (src, dst):
                if is_internal(ip):
                    assets[ip]["anomaly_count"] += 1

    # Load known assets from DB for merging
    known_assets = _load_known_assets()

    # Build final inventory — only identified (registered) internal assets
    inventory = []
    for ip, data in assets.items():
        if not is_internal(ip) or data["flows"] == 0:
            continue
        if ip not in known_assets:
            continue

        # Determine device type
        device_type = _classify_device(data)

        # Determine OS
        os_name = data["os_hints"].most_common(1)[0][0] if data["os_hints"] else "Unknown"

        # Determine role
        role = _classify_role(data, device_type)

        # Best hostname
        hostname = (data["dhcp_hostname"]
                    or (list(data["mdns_names"])[0] if data["mdns_names"] else "")
                    or (list(data["hostnames"])[0] if data["hostnames"] else ""))

        # Risk score
        risk_score, risk_factors = _compute_risk(data, known_assets)

        # Is it a known/registered asset?
        known = ip in known_assets
        known_info = known_assets.get(ip, {})

        # Top applications
        top_apps = sorted(data["applications"])[:10]

        # Top services
        top_services = [f"{p}:{s}" for s, c in data["protocols"].most_common(5) for p in [s]]

        # Top DNS domains
        top_domains = [d for d, _ in data["dns_queries"].most_common(5)]

        # Top peers
        top_int_peers = list(data["peers_internal"])[:10]
        top_ext_peers = list(data["peers_external"])[:10]

        inventory.append({
            "ip": ip,
            "mac": data["mac"],
            "hostname": hostname,
            "hostnames_all": sorted(list(data["hostnames"]))[:5],
            "device_type": device_type,
            "os": os_name,
            "role": role,
            "owner": known_info.get("owner", ""),
            "department": known_info.get("department", ""),
            "registered": known,
            "rogue": not known and data["flows"] > 5,
            # Traffic stats
            "bytes_in": data["bytes_in"],
            "bytes_out": data["bytes_out"],
            "bytes_total": data["bytes_in"] + data["bytes_out"],
            "flows": data["flows"],
            # Network profile
            "server_ports": sorted(list(data["server_ports"] & SERVER_PORTS))[:10],
            "observed_services": sorted(list(data["services_observed"]))[:10],
            "transport_protocols": dict(data["transport"]),
            "applications": top_apps,
            "top_domains": top_domains,
            # Peers
            "internal_peers": len(data["peers_internal"]),
            "external_peers": len(data["peers_external"]),
            "top_internal_peers": top_int_peers,
            "top_external_peers": top_ext_peers,
            # Fingerprinting
            "ja3_count": len(data["ja3_hashes"]),
            "top_ja3": [h for h, _ in data["ja3_hashes"].most_common(3)],
            "tls_versions": dict(data["tls_versions"]),
            "ssh_client_software": sorted(list(data["ssh_client"]))[:3],
            "ssh_server_software": sorted(list(data["ssh_server"]))[:3],
            "user_agents": [ua for ua, _ in data["user_agents"].most_common(3)],
            "mac_address": data["mac"],
            "vlan": sorted(list(data["vlan"])),
            "mdns_names": sorted(list(data["mdns_names"]))[:5],
            # Timeline
            "first_seen": data["first_seen"],
            "last_seen": data["last_seen"],
            # Security
            "alert_count": data["alert_count"],
            "anomaly_count": data["anomaly_count"],
            "alerts": data["alerts"],
            "risk_score": risk_score,
            "risk_factors": risk_factors,
        })

    # Sort by traffic volume (most active first)
    inventory.sort(key=lambda x: -x["bytes_total"])

    # Summary statistics
    device_types = Counter(a["device_type"] for a in inventory)
    os_dist = Counter(a["os"] for a in inventory if a["os"] != "Unknown")
    registered_count = sum(1 for a in inventory if a["registered"])
    rogue_count = sum(1 for a in inventory if a["rogue"])

    return {
        "assets": inventory,
        "summary": {
            "total_discovered": len(inventory),
            "registered": registered_count,
            "unregistered": len(inventory) - registered_count,
            "rogue_detected": rogue_count,
            "device_types": dict(device_types),
            "os_distribution": dict(os_dist),
            "with_mac": sum(1 for a in inventory if a["mac"]),
            "with_hostname": sum(1 for a in inventory if a["hostname"]),
        },
        "mac_ip_map": mac_ip_map,
    }


def _load_known_assets():
    """Load registered assets from DB."""
    try:
        conn = get_db()
        rows = conn.execute("SELECT ip, owner, hostname, department, asset_type FROM assets WHERE scope='internal'").fetchall()
        conn.close()
        return {r["ip"]: {"owner": r["owner"] or "", "hostname": r["hostname"] or "",
                          "department": r["department"] or "", "type": r["asset_type"] or ""} for r in rows}
    except Exception:
        return {}


def _detect_os(ua):
    """Detect OS from HTTP User-Agent string."""
    ua_lower = ua.lower()
    for os_name, patterns in OS_PATTERNS:
        for p in patterns:
            if p.lower() in ua_lower:
                return os_name
    return ""


def _detect_os_from_ssh(sw):
    """Detect OS from SSH software version."""
    sw_lower = sw.lower()
    if "ubuntu" in sw_lower:
        return "Ubuntu"
    if "debian" in sw_lower:
        return "Debian"
    if "openssh" in sw_lower:
        return "Linux"
    if "windows" in sw_lower or "microsoft" in sw_lower:
        return "Windows"
    return ""


def _detect_apps_from_ua(ua):
    """Detect applications from User-Agent."""
    apps = set()
    ua_lower = ua.lower()
    for app_name, patterns in APP_PATTERNS.items():
        ua_match = patterns.get("ua_match", "")
        ua_match2 = patterns.get("ua_match2", "")
        if ua_match and ua_match in ua_lower:
            apps.add(app_name)
        if ua_match2 and ua_match2 in ua_lower:
            apps.add(app_name)
    return apps


def _detect_apps_from_sni(sni):
    """Detect applications from TLS SNI."""
    apps = set()
    sni_lower = sni.lower()
    for app_name, patterns in APP_PATTERNS.items():
        sni_match = patterns.get("sni_match", "")
        if sni_match and sni_match in sni_lower:
            apps.add(app_name)
    return apps


def _classify_device(data):
    """Classify device type based on traffic behavior."""
    server_ports_seen = data["server_ports"] & SERVER_PORTS
    has_server_activity = len(server_ports_seen) >= 2
    has_http_server = 80 in data["server_ports"] or 443 in data["server_ports"] or 8080 in data["server_ports"]
    has_dns_server = 53 in data["server_ports"]
    has_snmp = 161 in data["server_ports"] or 162 in data["server_ports"]

    # Network device indicators
    if has_snmp or data["server_ports"] & NETWORK_DEVICE_PORTS:
        return "Network Device"

    # Server indicators: listens on well-known ports + high inbound traffic ratio
    if has_dns_server:
        return "DNS Server"
    if has_server_activity or has_http_server:
        if data["bytes_in"] > data["bytes_out"] * 2:
            return "Server"
        return "Server"

    # IoT indicators
    protos = set(data["protocols"].keys())
    if protos & IOT_INDICATORS:
        if data["flows"] < 100 and len(data["peers_external"]) < 5:
            return "IoT Device"

    # Mobile indicators
    os_hints = set(data["os_hints"].keys())
    if os_hints & {"iOS", "Android"}:
        return "Mobile"

    # Default: workstation/endpoint
    return "Workstation"


def _classify_role(data, device_type):
    """Classify the role/function of the device."""
    if device_type == "DNS Server":
        return "DNS Resolver"
    if device_type == "Network Device":
        return "Network Infrastructure"
    if device_type == "Server":
        ports = data["server_ports"]
        if 80 in ports or 443 in ports or 8080 in ports:
            return "Web Server"
        if 3306 in ports or 5432 in ports:
            return "Database Server"
        if 22 in ports and len(ports) < 3:
            return "SSH Server"
        if 25 in ports or 587 in ports:
            return "Mail Server"
        if 445 in ports or 139 in ports:
            return "File Server"
        return "Application Server"
    if device_type == "Mobile":
        return "Mobile Endpoint"
    if device_type == "IoT Device":
        return "IoT Endpoint"
    return "User Endpoint"


def _compute_risk(data, known_assets):
    """Compute risk score (0-100) for an asset."""
    score = 0
    factors = []

    # Unregistered device
    if data["ips"] and not any(ip in known_assets for ip in data["ips"]):
        score += 15
        factors.append("Unregistered device")

    # Alerts
    if data["alert_count"] > 0:
        crit = sum(1 for a in data["alerts"] if a["severity"] <= 2)
        if crit > 0:
            score += min(crit * 10, 30)
            factors.append(f"{crit} critical/high alerts")
        else:
            score += min(data["alert_count"] * 3, 15)
            factors.append(f"{data['alert_count']} alerts")

    # Anomalies
    if data["anomaly_count"] > 5:
        score += 10
        factors.append(f"{data['anomaly_count']} anomalies")

    # High external exposure
    ext_peers = len(data["peers_external"])
    if ext_peers > 50:
        score += 15
        factors.append(f"High external exposure ({ext_peers} peers)")
    elif ext_peers > 20:
        score += 5

    # Server ports exposed
    if len(data["server_ports"] & SERVER_PORTS) > 3:
        score += 10
        factors.append(f"Multiple server ports open ({len(data['server_ports'] & SERVER_PORTS)})")

    # Deprecated TLS
    deprecated = sum(v for k, v in data["tls_versions"].items() if k in {"TLSv1", "TLS 1.0", "TLS 1.1"})
    if deprecated > 0:
        score += 10
        factors.append(f"Deprecated TLS ({deprecated} connections)")

    return min(score, 100), factors
