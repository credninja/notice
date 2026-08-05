"""
User Identity Mapping Engine
===============================
Maps IP addresses to user identities by correlating:
  - Asset database (owner field)
  - DHCP events (hostname -> usually contains username)
  - HTTP User-Agent (OS/device info)
  - Kerberos/NTLM in SMB (if visible to the IDS engine)
  - mDNS device names (personal device names)
  - SSH client banners

Builds an identity map: IP -> {username, device_name, os, department, confidence}
"""

from collections import defaultdict, Counter
from eve_reader import iter_events, is_internal, is_ipv4
from db import get_db
import re


def build_identity_map(minutes=None):
    """
    Build a comprehensive IP-to-user identity map from all available sources.
    Returns: {ip: {username, device_name, os, source, confidence, ...}}
    """
    identities = defaultdict(lambda: {
        "sources": {},       # source_type -> value
        "usernames": Counter(),
        "device_names": Counter(),
        "os_hints": Counter(),
        "hostnames": set(),
    })

    # Source 1: Asset database (highest confidence)
    conn = get_db()
    assets = conn.execute("SELECT ip, owner, hostname, department, asset_type, os FROM assets WHERE scope='internal'").fetchall()
    conn.close()

    for a in assets:
        ip = a["ip"]
        if a["owner"]:
            identities[ip]["sources"]["asset_db"] = a["owner"]
            identities[ip]["usernames"][a["owner"]] += 10  # high weight
        if a["hostname"]:
            identities[ip]["device_names"][a["hostname"]] += 10
            identities[ip]["hostnames"].add(a["hostname"])
        if a["os"]:
            identities[ip]["os_hints"][a["os"]] += 10

    # Source 2-6: Network traffic analysis
    for ev in iter_events(minutes=minutes):
        etype = ev.get("event_type")
        src = ev.get("src_ip", "")
        dst = ev.get("dest_ip", "")

        # Source 2: DHCP (hostname often contains username or device name)
        if etype == "dhcp":
            dhcp = ev.get("dhcp", {})
            assigned_ip = dhcp.get("assigned_ip", "")
            hostname = dhcp.get("hostname", "")
            if assigned_ip and is_internal(assigned_ip) and hostname:
                identities[assigned_ip]["sources"]["dhcp"] = hostname
                identities[assigned_ip]["hostnames"].add(hostname)
                # Extract username from hostname patterns
                username = _extract_username_from_hostname(hostname)
                if username:
                    identities[assigned_ip]["usernames"][username] += 5
                identities[assigned_ip]["device_names"][hostname] += 5

        # Source 3: mDNS (device names like "Rishik's MacBook Air")
        elif etype == "mdns":
            if not is_internal(src):
                continue
            mdns = ev.get("mdns", {})
            for ans in mdns.get("answers", []):
                name = ans.get("rrname", "")
                if name and ".local" in name:
                    device_name = name.split(".")[0]
                    identities[src]["sources"]["mdns"] = device_name
                    identities[src]["device_names"][device_name] += 3
                    # Extract username from device name
                    username = _extract_username_from_device(device_name)
                    if username:
                        identities[src]["usernames"][username] += 3

        # Source 4: HTTP User-Agent (OS and device info)
        elif etype == "http":
            if not is_internal(src):
                continue
            http = ev.get("http", {})
            ua = http.get("http_user_agent", "")
            if ua:
                os_name = _detect_os_from_ua(ua)
                if os_name:
                    identities[src]["os_hints"][os_name] += 1
                # Check for username in HTTP headers (some apps leak this)
                auth = http.get("http_authorization", "")
                if auth and "basic" in auth.lower():
                    identities[src]["sources"]["http_auth"] = "(auth detected)"

        # Source 5: SSH (username sometimes visible in banner)
        elif etype == "ssh":
            ssh = ev.get("ssh", {})
            if is_internal(src):
                client_sw = ssh.get("client", {}).get("software_version", "")
                if client_sw:
                    identities[src]["sources"]["ssh_client"] = client_sw
                    os_hint = _detect_os_from_ssh(client_sw)
                    if os_hint:
                        identities[src]["os_hints"][os_hint] += 2

        # Source 6: SMB/Kerberos (if the IDS engine parsed it)
        elif etype == "smb":
            smb = ev.get("smb", {})
            ntlmssp = smb.get("ntlmssp", {})
            if ntlmssp:
                user = ntlmssp.get("user", "")
                domain = ntlmssp.get("domain", "")
                host = ntlmssp.get("host", "")
                if user and is_internal(src):
                    identities[src]["sources"]["ntlm"] = f"{domain}\\{user}"
                    identities[src]["usernames"][user] += 8  # high confidence
                if host and is_internal(src):
                    identities[src]["device_names"][host] += 8

    # Build final identity map
    result = {}
    for ip, data in identities.items():
        if not is_internal(ip):
            continue

        # Best username
        username = ""
        if data["usernames"]:
            username = data["usernames"].most_common(1)[0][0]

        # Best device name
        device_name = ""
        if data["device_names"]:
            device_name = data["device_names"].most_common(1)[0][0]

        # Best OS
        os_name = ""
        if data["os_hints"]:
            os_name = data["os_hints"].most_common(1)[0][0]

        # Confidence level
        source_count = len(data["sources"])
        if "asset_db" in data["sources"] or "ntlm" in data["sources"]:
            confidence = "high"
        elif source_count >= 2:
            confidence = "medium"
        elif source_count >= 1:
            confidence = "low"
        else:
            confidence = "none"

        if username or device_name or data["sources"]:
            result[ip] = {
                "ip": ip,
                "username": username,
                "device_name": device_name,
                "os": os_name,
                "confidence": confidence,
                "sources": data["sources"],
                "source_count": source_count,
                "all_usernames": dict(data["usernames"]),
                "all_device_names": dict(data["device_names"]),
                "hostnames": sorted(list(data["hostnames"]))[:5],
            }

    return result


def get_identity_for_ip(ip, identity_map=None):
    """Get identity info for a single IP. Returns dict or empty dict."""
    if identity_map is None:
        identity_map = build_identity_map(minutes=60)
    return identity_map.get(ip, {})


def _extract_username_from_hostname(hostname):
    """Extract probable username from DHCP hostname."""
    h = hostname.lower().strip()
    # Common patterns: "DESKTOP-RISHIK", "rishik-pc", "LAPTOP-VINIT"
    patterns = [
        r"(?:desktop|laptop|pc|nb|ws)[-_](\w+)",  # DESKTOP-USERNAME
        r"(\w+)[-_](?:desktop|laptop|pc|nb|ws)",   # USERNAME-PC
        r"(\w+)s?[-_](?:macbook|imac|iphone|ipad)",  # Rishik's-MacBook
    ]
    for pat in patterns:
        m = re.search(pat, h)
        if m:
            name = m.group(1)
            if len(name) >= 3 and name not in ("the", "this", "home", "work", "test", "admin", "user"):
                return name.title()
    return ""


def _extract_username_from_device(device_name):
    """Extract username from mDNS device name like 'Rishik's MacBook Air'."""
    # Pattern: "Name's Device"
    m = re.match(r"([A-Za-z]+)(?:'s?\s)", device_name)
    if m:
        name = m.group(1)
        if len(name) >= 3 and name.lower() not in ("the", "this", "my"):
            return name.title()
    return ""


def _detect_os_from_ua(ua):
    """Detect OS from HTTP User-Agent."""
    ua_l = ua.lower()
    if "windows nt 10" in ua_l: return "Windows 10/11"
    if "windows nt 6.1" in ua_l: return "Windows 7"
    if "macintosh" in ua_l or "mac os" in ua_l: return "macOS"
    if "iphone" in ua_l or "ipad" in ua_l: return "iOS"
    if "android" in ua_l: return "Android"
    if "ubuntu" in ua_l: return "Ubuntu"
    if "linux" in ua_l: return "Linux"
    if "cros" in ua_l: return "ChromeOS"
    return ""


def _detect_os_from_ssh(sw):
    """Detect OS from SSH software version."""
    sw_l = sw.lower()
    if "ubuntu" in sw_l: return "Ubuntu"
    if "debian" in sw_l: return "Debian"
    if "openssh" in sw_l: return "Linux"
    if "windows" in sw_l: return "Windows"
    return ""
