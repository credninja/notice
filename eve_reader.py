"""
Shared eve.json reader utilities for all Notice modules.
"""

import json
import os
import ipaddress
from datetime import datetime, timedelta

EVE_LOG = os.environ.get("EVE_LOG", "/var/log/suricata/eve.json")
SUBNET = ipaddress.ip_network("10.0.0.0/8")
MAX_LINES = int(os.environ.get("MAX_LINES", 1000000))


def is_internal(ip_str):
    try:
        return ipaddress.ip_address(ip_str) in SUBNET
    except ValueError:
        return False


def is_ipv4(ip_str):
    try:
        return isinstance(ipaddress.ip_address(ip_str), ipaddress.IPv4Address)
    except ValueError:
        return False


NOISE_SIGNATURES = (
    # Legacy — user-off-hours, P2P chat, streaming
    "OFFHOURS", "Spotify P2P", "Discord", "Printing Protocol",
    "Cloudflare Page Developer",
    "STUN Binding", "Microsoft Connection Test",
    "External IP Lookup", "External IP Address Lookup",
    "IP Lookup Domain", "ipify", "check.torproject",
    "Alibaba Cloud CDN", "aliyuncs", "Android Device Connectivity",
    "AI Service Domain", "Observed UA-CPU Header",
    "GNU/Linux APT User-Agent",

    # Per-user "Excessive Outbound Connections" — normal browser traffic
    "Excessive Outbound Connections",

    # Long / uncommon TCP sessions — high FP rate on legit long-lived connections
    "EXT2INT C2 Long unrecognized",
    "Long unrecognized TCP session",
    "Outbound Connection on Uncommon High Port",
    "Persistent Outbound TCP to Non-Standard Port",

    # Network discovery / scans that trigger on legitimate infrastructure
    "SSDP UPnP Discovery",
    "ARP Sweep",
    "Reverse DNS Sweep",
    "Excessive DNS Queries from Single Host",
    "Windows Update P2P",

    # Port scans — Suricata thresholds catch legit tools like nmap tests + scanner boxes
    "Vertical Port Scan",
    "Horizontal Port Scan",
    "Internal Horizontal Port Scan",
    "Port Scan Against Identified Workstation",
    "Port Scan Against Monitored Server",
    "Slow Stealth Scan",
    "Internal Port Scan against",

    # DNS length/entropy heuristics — modern CDNs use long domains
    "DNS Query with Long Subdomain",

    # HTTP beaconing on generic patterns — CDN keep-alives look like beaconing
    "Possible HTTP Beaconing",

    # Chat / info-level ET rules
    "Observed Discord Domain",
    "Discord Chat Service Domain",
    "Session Traversal Utilities for NAT",
)

NOISE_CATEGORIES = frozenset({
    "Not Suspicious Traffic",
    "Device Retrieving External IP Address Detected",
})

MONITORED_NET = ipaddress.ip_network("10.1.96.0/23")


def is_monitored(ip_str):
    try:
        return ipaddress.ip_address(ip_str) in MONITORED_NET
    except ValueError:
        return False


def is_noise_alert(signature, category):
    if category in NOISE_CATEGORIES:
        return True
    return any(n in signature for n in NOISE_SIGNATURES)


def tail_lines(filepath, max_lines):
    """Read last max_lines from a file efficiently. Returns oldest-first."""
    out = list(_iter_lines_reverse(filepath, max_lines))
    out.reverse()
    return out


def _iter_lines_reverse(filepath, max_lines):
    """Generator yielding raw lines from end of file, newest-first.

    Streams in 1 MiB chunks, so consumers can break early once they've seen
    enough data (e.g. when timestamps drop below a window cutoff). This is
    much faster than reading all max_lines into memory upfront.
    """
    try:
        with open(filepath, "rb") as f:
            f.seek(0, 2)
            end = f.tell()
            if end == 0:
                return
            chunk_size = 1024 * 1024
            pos = end
            remainder = b""
            yielded = 0
            while pos > 0 and yielded < max_lines:
                read_size = min(chunk_size, pos)
                pos -= read_size
                f.seek(pos)
                chunk = f.read(read_size) + remainder
                split = chunk.split(b"\n")
                remainder = split[0]
                # Yield newest-first within the chunk
                for part in reversed(split[1:]):
                    if part:
                        yield part
                        yielded += 1
                        if yielded >= max_lines:
                            return
            if remainder and yielded < max_lines:
                yield remainder
    except FileNotFoundError:
        return


def iter_events(event_types=None, minutes=None, src_ip=None, dest_ip=None,
                ip_filter=None, max_lines=None):
    """
    Yield parsed eve.json events matching filters, newest-first.

    For time-windowed queries (minutes != None), reading stops early once
    we've seen enough consecutive events older than the cutoff — so a
    `minutes=60` query on a 1.5 GB log only parses the last ~10K lines
    instead of the full 1M-line tail.

    Order: events are yielded NEWEST-FIRST. Callers that need chronological
    order should sort after collection; none currently depend on order.

    Args:
        event_types: set of event_type strings to include, or None for all
        minutes: only events within last N minutes
        src_ip: filter by source IP
        dest_ip: filter by destination IP
        ip_filter: filter where src or dest matches this IP
        max_lines: override MAX_LINES
    """
    cutoff = None
    if minutes:
        cutoff = datetime.now().astimezone() - timedelta(minutes=minutes)

    # Tolerance for slightly out-of-order timestamps before declaring "we're done".
    # Suricata can write events slightly out of order across worker threads, so we
    # don't break on the first old event — only after a sustained run of them.
    OLD_BUDGET = 500
    consecutive_old = 0

    limit = max_lines or MAX_LINES
    for raw in _iter_lines_reverse(EVE_LOG, limit):
        try:
            ev = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue

        # Cheap filters first — avoid timestamp parsing cost when event_type doesn't match
        if event_types and ev.get("event_type") not in event_types:
            continue

        if cutoff:
            try:
                ts = datetime.fromisoformat(ev["timestamp"])
            except (KeyError, ValueError):
                continue
            if ts < cutoff:
                consecutive_old += 1
                if consecutive_old > OLD_BUDGET:
                    return
                continue
            consecutive_old = 0

        ev_src = ev.get("src_ip", "")
        ev_dst = ev.get("dest_ip", "")

        if src_ip and ev_src != src_ip:
            continue
        if dest_ip and ev_dst != dest_ip:
            continue
        if ip_filter and ev_src != ip_filter and ev_dst != ip_filter:
            continue

        yield ev
