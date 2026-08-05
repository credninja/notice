#!/usr/bin/env python3
"""
NOTICE Victim Web Server — Fake Vulnerable Service for Demo
=============================================================
Runs on the demo victim machine to accept and respond to
attack traffic so Suricata captures full HTTP payloads.

This is NOT a real vulnerable app — it just responds to all
requests with realistic-looking responses so Suricata's HTTP
parser can log complete request/response data in eve.json.

Usage (on the target host):
  sudo python3 victim_server.py         # Port 80 (needs sudo)
  python3 victim_server.py --port 8080  # Port 8080 (no sudo)

Then run attack_sim.py from the attacker machine with matching port:
  python3 attack_sim.py --victim <target-ip> --port 8080
"""

import http.server
import argparse
import json
import time
import random


class VulnerableHandler(http.server.BaseHTTPRequestHandler):
    """Fake web server that responds to all requests realistically."""

    # Suppress default logging — we print our own
    def log_message(self, fmt, *args):
        ts = time.strftime("%H:%M:%S")
        print(f"  {ts} [{self.command}] {self.path}  <-  {self.client_address[0]}")

    def _send(self, code, body, content_type="text/html"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Server", "Apache/2.4.52 (Ubuntu)")
        self.send_header("X-Powered-By", "PHP/8.1.2")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        path = self.path.lower()

        # Root / index
        if self.path in ("/", "/index.html"):
            self._send(200, """<!DOCTYPE html>
<html><head><title>Company Portal</title></head>
<body><h1>Welcome to Internal Portal</h1>
<p>Employee Management System v3.2.1</p>
<ul><li><a href="/login">Login</a></li>
<li><a href="/dashboard">Dashboard</a></li>
<li><a href="/search">Search</a></li></ul>
</body></html>""")

        # Login page
        elif "/login" in path:
            self._send(200, """<!DOCTYPE html>
<html><head><title>Login</title></head>
<body><h2>Employee Login</h2>
<form method="POST" action="/login">
<input name="username" placeholder="Username"><br>
<input name="password" type="password" placeholder="Password"><br>
<button type="submit">Login</button></form>
</body></html>""")

        # Admin panels — return 403 (Suricata sees the attempt)
        elif any(x in path for x in ["/admin", "/wp-admin", "/phpmyadmin", "/console", "/actuator"]):
            self._send(403, "<html><body><h1>403 Forbidden</h1><p>Access denied.</p></body></html>")

        # Sensitive files — return fake content
        elif "/.env" in path:
            self._send(200, "DB_HOST=localhost\nDB_USER=root\nDB_PASS=supersecret123\nSECRET_KEY=a1b2c3d4e5\n",
                       "text/plain")
        elif "/.git" in path:
            self._send(200, "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n", "text/plain")
        elif "/robots.txt" in path:
            self._send(200, "User-agent: *\nDisallow: /admin\nDisallow: /backup\nDisallow: /config\n",
                       "text/plain")

        # Search page (reflects input — XSS/SQLi detection)
        elif "/search" in path:
            query = self.path.split("q=")[1] if "q=" in self.path else ""
            self._send(200, f"""<!DOCTYPE html>
<html><head><title>Search Results</title></head>
<body><h2>Search Results for: {query}</h2>
<p>No results found for your query.</p>
<p>Error: near syntax error at "{query[:50]}"</p>
</body></html>""")

        # API endpoints
        elif "/api/status" in path:
            self._send(200, json.dumps({"status": "ok", "uptime": random.randint(1000, 99999),
                                        "version": "3.2.1"}), "application/json")
        elif "/api" in path:
            self._send(200, json.dumps({"endpoints": ["/api/status", "/api/users", "/api/upload"]}),
                       "application/json")

        # Nmap probe path
        elif "trinity" in path.lower() or "nice%20ports" in path.lower() or "nice ports" in path.lower():
            self._send(200, "<html><body>It works!</body></html>")

        # LFI simulation — return fake file content
        elif "/page" in path and "file=" in path:
            self._send(200, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
                       "text/plain")

        # Command injection endpoint
        elif "/ping" in path:
            self._send(200, f"PING result:\nuid=0(root) gid=0(root) groups=0(root)\n", "text/plain")

        # Info/debug pages
        elif "/phpinfo" in path or "/info.php" in path:
            self._send(200, "<html><body><h1>PHP Info</h1><p>PHP Version 8.1.2</p><p>System: Linux</p></body></html>")

        # Everything else — 404
        else:
            self._send(404, f"<html><body><h1>404 Not Found</h1><p>{self.path} was not found.</p></body></html>")

    def do_POST(self):
        # Read POST body
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="replace") if content_length > 0 else ""

        path = self.path.lower()

        # Login attempts — always return 401 (triggers brute force detection)
        if "/login" in path:
            self._send(401, """<!DOCTYPE html>
<html><body><h2>Login Failed</h2>
<p>Invalid username or password. Attempt logged.</p>
<p>Your IP has been recorded for security monitoring.</p>
</body></html>""")

        # File upload endpoint
        elif "/upload" in path:
            self._send(200, json.dumps({"status": "received", "size": len(body)}), "application/json")

        # Command endpoint (C2 simulation)
        elif "/command" in path or "/cmd" in path or "/exec" in path:
            self._send(200, json.dumps({"result": "noop", "next_checkin": 5}), "application/json")

        # API catch-all
        elif "/api" in path:
            self._send(200, json.dumps({"status": "ok"}), "application/json")

        # Default
        else:
            self._send(200, "<html><body><h1>OK</h1></body></html>")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Server", "Apache/2.4.52 (Ubuntu)")
        self.end_headers()


def main():
    parser = argparse.ArgumentParser(description="NOTICE Victim Web Server for Demo")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on (default: 8080)")
    parser.add_argument("--bind", type=str, default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    args = parser.parse_args()

    print("=" * 55)
    print("  NOTICE Victim Web Server — Demo Only")
    print(f"  Listening on {args.bind}:{args.port}")
    print("  Ctrl+C to stop")
    print("=" * 55)
    print()

    server = http.server.HTTPServer((args.bind, args.port), VulnerableHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped")
        server.server_close()


if __name__ == "__main__":
    main()
