#!/usr/bin/env python3
"""
Active Asset Probe — Network-Based Asset Fingerprinting
=========================================================
For unregistered/unknown internal IPs, actively probe to discover:

  - Open ports and running services
  - Service versions (banner grabbing)
  - OS fingerprinting (from service banners, TTL, TCP window)
  - TLS/SSL certificate details (CBOM — Cryptographic BOM)
  - SSH version and key exchange algorithms
  - HTTP server info and technologies
  - SNMP system description (if accessible)
  - DNS reverse lookup

This builds a partial SBOM/CBOM from network-visible information.
Full SBOM/HBOM/AIBOM requires endpoint agent access.

IMPORTANT: Only probe internal (10.0.0.0/8) IPs.
"""

import socket
import ssl
import struct
import json
import time
import concurrent.futures
from datetime import datetime
from collections import defaultdict
from eve_reader import is_internal, is_ipv4
from db import get_db


# Ports to probe for service discovery
PROBE_PORTS = [
    22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161,
    443, 445, 993, 995, 1433, 1521, 3306, 3389,
    5000, 5432, 5900, 6379, 8000, 8080, 8443, 8888,
    9090, 9200, 27017,
]

# Well-known service names
PORT_SERVICE = {
    22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    161: "SNMP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5000: "HTTP-Alt", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8000: "HTTP-Alt", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
    8888: "HTTP-Alt", 9090: "HTTP-Alt", 9200: "Elasticsearch", 27017: "MongoDB",
}

# Quantum-vulnerable cipher suites (for QBOM)
QUANTUM_VULNERABLE_CIPHERS = {
    "RSA", "ECDHE-RSA", "DHE-RSA", "ECDHE-ECDSA",
}

# Post-quantum safe indicators
PQ_SAFE_INDICATORS = {"X25519Kyber768", "ML-KEM", "CRYSTALS"}


def get_unregistered_ips(minutes=60):
    """Get internal IPs seen in traffic but NOT in the asset database."""
    from analyzers.asset_discovery import discover_assets

    # Get all IPs seen in traffic
    all_discovery = discover_assets.__wrapped__(minutes) if hasattr(discover_assets, '__wrapped__') else None

    # Fallback: scan eve.json directly for unique internal IPs
    from eve_reader import iter_events
    seen_ips = set()
    for ev in iter_events(minutes=minutes):
        for key in ("src_ip", "dest_ip"):
            ip = ev.get(key, "")
            if is_ipv4(ip) and is_internal(ip):
                seen_ips.add(ip)

    # Load registered assets
    conn = get_db()
    registered = set(r["ip"] for r in conn.execute("SELECT ip FROM assets WHERE scope='internal'").fetchall())
    conn.close()

    # Unregistered = seen but not registered
    unregistered = seen_ips - registered
    # Filter out multicast/broadcast
    unregistered = {ip for ip in unregistered if not ip.startswith("224.") and not ip.startswith("239.")
                    and not ip.startswith("255.") and ip != "0.0.0.0"}

    return sorted(unregistered)


def probe_single_ip(ip, timeout=3):
    """
    Actively probe a single IP address to fingerprint it.
    Returns comprehensive asset profile.
    """
    if not is_internal(ip):
        return {"error": "Only internal IPs can be probed"}

    result = {
        "ip": ip,
        "probe_time": datetime.now().isoformat(),
        "alive": False,
        "open_ports": [],
        "services": [],
        "os_guess": "Unknown",
        "os_evidence": [],
        "hostname": "",
        # Partial SBOM (what we can see from network)
        "sbom": {
            "detected_software": [],
            "note": "Full SBOM requires endpoint agent. This shows network-visible software only.",
        },
        # CBOM (Cryptographic BOM)
        "cbom": {
            "tls_certificates": [],
            "cipher_suites": [],
            "tls_versions": [],
            "ssh_algorithms": [],
            "crypto_issues": [],
            "note": "Cryptographic inventory from TLS/SSH handshakes.",
        },
        # QBOM (Quantum-readiness)
        "qbom": {
            "quantum_vulnerable": [],
            "quantum_safe": [],
            "readiness": "Unknown",
            "note": "Assessment of post-quantum cryptography readiness.",
        },
        # HBOM partial (from SNMP/banners)
        "hbom": {
            "hardware_hints": [],
            "note": "Full HBOM requires physical access or agent. Shows network-inferred hardware info.",
        },
        # AIBOM
        "aibom": {
            "note": "AI BOM cannot be detected from network probing. Requires application-level inventory.",
            "detected": False,
        },
    }

    # 1. Reverse DNS
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        result["hostname"] = hostname
    except (socket.herror, socket.gaierror, OSError):
        pass

    # 2. Port scanning
    open_ports = _scan_ports(ip, timeout=timeout)
    result["open_ports"] = open_ports
    result["alive"] = len(open_ports) > 0

    if not result["alive"]:
        # Try ICMP ping
        ping_ok = _ping(ip)
        if ping_ok:
            result["alive"] = True
            result["ping_only"] = True
            result["os_guess"] = "Alive (ping) — no open TCP ports found (host firewall may be blocking)"
            # Still try the remaining probes even without open ports
            return result
        else:
            result["os_guess"] = "Unreachable — host is down or on a non-routable VLAN"
            return result

    # 3. Service fingerprinting on open ports
    for port in open_ports:
        svc = _fingerprint_service(ip, port, timeout)
        if svc:
            result["services"].append(svc)
            # Add to SBOM
            if svc.get("software"):
                result["sbom"]["detected_software"].append({
                    "name": svc["software"],
                    "version": svc.get("version", ""),
                    "port": port,
                    "source": "banner-grab",
                })

    # 4. TLS/SSL probing (CBOM)
    tls_ports = [p for p in open_ports if p in (443, 8443, 993, 995, 465)] + \
                [p for p in open_ports if p in (80, 8080, 8000, 5000, 9090)]
    for port in tls_ports[:3]:
        tls_info = _probe_tls(ip, port, timeout)
        if tls_info:
            result["cbom"]["tls_certificates"].append(tls_info.get("cert", {}))
            result["cbom"]["cipher_suites"].extend(tls_info.get("ciphers", []))
            result["cbom"]["tls_versions"].append(tls_info.get("version", ""))
            # QBOM assessment
            for cipher in tls_info.get("ciphers", []):
                for qv in QUANTUM_VULNERABLE_CIPHERS:
                    if qv in cipher:
                        result["qbom"]["quantum_vulnerable"].append(cipher)
                for pq in PQ_SAFE_INDICATORS:
                    if pq in cipher:
                        result["qbom"]["quantum_safe"].append(cipher)
            # Crypto issues
            ver = tls_info.get("version", "")
            if ver and ("TLSv1.0" in ver or "TLSv1.1" in ver or "SSLv3" in ver):
                result["cbom"]["crypto_issues"].append(f"Deprecated TLS version: {ver}")

    # 5. SSH probing (CBOM)
    if 22 in open_ports:
        ssh_info = _probe_ssh(ip, timeout)
        if ssh_info:
            result["cbom"]["ssh_algorithms"] = ssh_info.get("kex_algorithms", [])
            if ssh_info.get("software"):
                result["sbom"]["detected_software"].append({
                    "name": ssh_info["software"],
                    "version": "",
                    "port": 22,
                    "source": "ssh-banner",
                })
                # OS hint from SSH
                sw = ssh_info["software"].lower()
                if "ubuntu" in sw:
                    result["os_evidence"].append(("Ubuntu Linux", "SSH banner"))
                elif "debian" in sw:
                    result["os_evidence"].append(("Debian Linux", "SSH banner"))
                elif "openssh" in sw:
                    result["os_evidence"].append(("Linux/Unix", "SSH banner"))

    # 6. HTTP probing (SBOM — server software)
    http_ports = [p for p in open_ports if p in (80, 8080, 8000, 5000, 8443, 8888, 9090, 443)]
    for port in http_ports[:2]:
        http_info = _probe_http(ip, port, timeout)
        if http_info:
            if http_info.get("server"):
                result["sbom"]["detected_software"].append({
                    "name": http_info["server"],
                    "version": "",
                    "port": port,
                    "source": "http-header",
                })
            if http_info.get("powered_by"):
                result["sbom"]["detected_software"].append({
                    "name": http_info["powered_by"],
                    "version": "",
                    "port": port,
                    "source": "http-header",
                })
            # OS hint from server header
            server = (http_info.get("server") or "").lower()
            if "ubuntu" in server:
                result["os_evidence"].append(("Ubuntu Linux", "HTTP Server header"))
            elif "debian" in server:
                result["os_evidence"].append(("Debian Linux", "HTTP Server header"))
            elif "windows" in server or "iis" in server:
                result["os_evidence"].append(("Windows", "HTTP Server header"))

    # 7. SNMP probing (HBOM)
    if 161 in open_ports:
        snmp_info = _probe_snmp(ip, timeout)
        if snmp_info:
            result["hbom"]["hardware_hints"].append(snmp_info)

    # 8. OS determination
    result["os_guess"] = _determine_os(result)

    # 9. QBOM readiness assessment
    if result["qbom"]["quantum_safe"]:
        result["qbom"]["readiness"] = "Partial"
    elif result["qbom"]["quantum_vulnerable"]:
        result["qbom"]["readiness"] = "Vulnerable"
    else:
        result["qbom"]["readiness"] = "Unknown (no TLS observed)"

    return result


def probe_batch(ips, timeout=2, max_workers=10):
    """Probe multiple IPs in parallel."""
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(probe_single_ip, ip, timeout): ip for ip in ips}
        for future in concurrent.futures.as_completed(futures):
            ip = futures[future]
            try:
                result = future.result(timeout=30)
                results.append(result)
            except Exception as e:
                results.append({"ip": ip, "error": str(e), "alive": False})
    results.sort(key=lambda x: x.get("ip", ""))
    return results


# ── Internal probe functions ──

def _scan_ports(ip, timeout=2):
    """TCP connect scan on common ports."""
    open_ports = []
    for port in PROBE_PORTS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            s.close()
        except (socket.error, OSError):
            pass
    return open_ports


def _ping(ip):
    """ICMP ping using system ping command, then fall back to TCP."""
    import subprocess
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            capture_output=True, text=True, timeout=3
        )
        if result.returncode == 0:
            return True
    except (subprocess.TimeoutExpired, OSError):
        pass
    # TCP fallback on more ports
    for port in [80, 443, 22, 135, 445, 8080, 3389, 5000, 8443, 53]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            if s.connect_ex((ip, port)) == 0:
                s.close()
                return True
            s.close()
        except (socket.error, OSError):
            pass
    return False


def _fingerprint_service(ip, port, timeout=2):
    """Banner grab a service."""
    svc_name = PORT_SERVICE.get(port, f"port-{port}")
    result = {"port": port, "service": svc_name, "banner": "", "software": "", "version": ""}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        # Some services send banners immediately
        try:
            banner = s.recv(1024).decode("utf-8", errors="replace").strip()
            result["banner"] = banner[:200]
            # Extract software from banner
            if "SSH" in banner:
                result["software"] = banner.split("\r")[0].split("\n")[0]
            elif "220" in banner and ("SMTP" in banner or "mail" in banner.lower()):
                result["software"] = banner
            elif "MySQL" in banner or "MariaDB" in banner:
                result["software"] = banner[:50]
        except socket.timeout:
            # Send HTTP probe for web ports
            if port in (80, 8080, 8000, 5000, 8443, 8888, 9090):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                try:
                    resp = s.recv(2048).decode("utf-8", errors="replace")
                    result["banner"] = resp[:200]
                except socket.timeout:
                    pass
        s.close()
    except (socket.error, OSError):
        pass
    return result


def _probe_tls(ip, port, timeout=3):
    """Probe TLS to get certificate and cipher info."""
    result = {"cert": {}, "ciphers": [], "version": ""}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if cert:
                    result["cert"] = {
                        "subject": str(cert.get("subject", "")),
                        "issuer": str(cert.get("issuer", "")),
                        "not_before": cert.get("notBefore", ""),
                        "not_after": cert.get("notAfter", ""),
                        "serial": cert.get("serialNumber", ""),
                    }
                result["version"] = ssock.version()
                cipher = ssock.cipher()
                if cipher:
                    result["ciphers"] = [f"{cipher[0]} ({cipher[1]}, {cipher[2]} bit)"]
    except (ssl.SSLError, socket.error, OSError, ConnectionRefusedError):
        pass
    return result if result["version"] or result["cert"] else None


def _probe_ssh(ip, timeout=3):
    """Get SSH banner and algorithms."""
    result = {"software": "", "kex_algorithms": []}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, 22))
        banner = s.recv(1024).decode("utf-8", errors="replace").strip()
        result["software"] = banner.split("\r")[0].split("\n")[0]
        s.close()
    except (socket.error, OSError):
        pass
    return result if result["software"] else None


def _probe_http(ip, port, timeout=3):
    """Get HTTP server headers."""
    result = {"server": "", "powered_by": "", "headers": {}}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.sendall(f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode())
        resp = s.recv(4096).decode("utf-8", errors="replace")
        s.close()
        for line in resp.split("\r\n"):
            if line.lower().startswith("server:"):
                result["server"] = line.split(":", 1)[1].strip()
            elif line.lower().startswith("x-powered-by:"):
                result["powered_by"] = line.split(":", 1)[1].strip()
    except (socket.error, OSError):
        pass
    return result if result["server"] or result["powered_by"] else None


def _probe_snmp(ip, timeout=2):
    """Simple SNMP sysDescr query (community: public)."""
    # SNMPv1 GET sysDescr.0 with community "public"
    snmp_get = bytes.fromhex(
        "302902010004067075626c6963a01c0204000000010201000201003010300e060"
        "82b060102010101000500"
    )
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(snmp_get, (ip, 161))
        data, _ = s.recvfrom(4096)
        s.close()
        # Very basic parsing — extract string after OID
        decoded = data.decode("utf-8", errors="replace")
        if len(decoded) > 30:
            return {"sys_descr": decoded[30:].strip()[:200], "community": "public (WEAK!)"}
    except (socket.error, OSError):
        pass
    return None


def _determine_os(result):
    """Best-effort OS determination from all evidence."""
    if result["os_evidence"]:
        # Pick most common OS hint
        from collections import Counter
        os_counter = Counter(e[0] for e in result["os_evidence"])
        return os_counter.most_common(1)[0][0]

    # Infer from open ports
    ports = set(result["open_ports"])
    if ports & {135, 139, 445, 3389}:
        return "Windows (inferred from ports)"
    if ports & {22} and not ports & {135, 445}:
        return "Linux/Unix (inferred from ports)"

    return "Unknown"
