"""
C2 Beaconing detection.
Identifies hosts that communicate with external IPs at regular intervals,
a classic indicator of command-and-control (C2) malware.

Detection method:
1. Collect flow timestamps per (internal_ip, external_ip) pair
2. Compute inter-arrival times (deltas between consecutive connections)
3. Calculate jitter (standard deviation / mean of deltas)
4. Low jitter + high frequency = likely beacon
"""

import math
from collections import defaultdict
from eve_reader import iter_events, is_internal, is_ipv4
from datetime import datetime

# Thresholds
MIN_CONNECTIONS = 8  # Minimum flows to analyze
MAX_JITTER = 0.35  # Jitter ratio (stddev/mean) - below this = regular
MIN_INTERVAL = 5  # Minimum mean interval in seconds (ignore sub-5s bursts)
MAX_INTERVAL = 7200  # Max mean interval (2 hours) - beyond this is unlikely C2


def detect_beaconing(minutes=None):
    """
    Detect C2 beaconing by analyzing flow timing patterns.
    Returns suspicious pairs sorted by beacon score.
    """
    # Collect timestamps per (src_internal, dst_external) pair
    pairs = defaultdict(lambda: {
        "timestamps": [], "bytes": 0, "app_protos": set(), "dest_ports": set(),
    })

    for ev in iter_events(event_types={"flow"}, minutes=minutes):
        src = ev.get("src_ip", "")
        dst = ev.get("dest_ip", "")
        if not is_ipv4(src) or not is_ipv4(dst):
            continue

        # Only internal -> external flows
        if not is_internal(src) or is_internal(dst):
            continue
        # Skip multicast/broadcast
        if dst.startswith("224.") or dst.startswith("255."):
            continue

        ts = ev.get("timestamp", "")
        flow = ev.get("flow", {})
        flow_start = flow.get("start", ts)

        info = pairs[(src, dst)]
        info["timestamps"].append(flow_start)
        info["bytes"] += flow.get("bytes_toserver", 0) + flow.get("bytes_toclient", 0)
        ap = ev.get("app_proto", "")
        if ap and ap != "failed":
            info["app_protos"].add(ap)
        dp = ev.get("dest_port", 0)
        if dp:
            info["dest_ports"].add(dp)

    # Analyze each pair
    beacons = []
    for (src, dst), info in pairs.items():
        if len(info["timestamps"]) < MIN_CONNECTIONS:
            continue

        result = _analyze_timing(info["timestamps"])
        if not result:
            continue

        mean_interval, jitter, regularity_score, intervals = result
        if regularity_score < 40:
            continue

        beacons.append({
            "src_ip": src,
            "dest_ip": dst,
            "score": regularity_score,
            "connection_count": len(info["timestamps"]),
            "mean_interval_sec": round(mean_interval, 1),
            "mean_interval_human": _format_interval(mean_interval),
            "jitter": round(jitter, 4),
            "bytes": info["bytes"],
            "app_protos": list(info["app_protos"]),
            "dest_ports": sorted(list(info["dest_ports"]))[:5],
            "first_seen": min(info["timestamps"]),
            "last_seen": max(info["timestamps"]),
            "interval_histogram": _build_histogram(intervals),
        })

    beacons.sort(key=lambda x: -x["score"])

    # Group by source host
    host_summary = defaultdict(lambda: {"beacon_count": 0, "max_score": 0, "targets": []})
    for b in beacons:
        hs = host_summary[b["src_ip"]]
        hs["beacon_count"] += 1
        hs["max_score"] = max(hs["max_score"], b["score"])
        if len(hs["targets"]) < 10:
            hs["targets"].append({
                "dest_ip": b["dest_ip"],
                "score": b["score"],
                "interval": b["mean_interval_human"],
            })

    host_list = [
        {"host": h, "beacon_count": v["beacon_count"],
         "max_score": v["max_score"], "targets": v["targets"]}
        for h, v in host_summary.items()
    ]
    host_list.sort(key=lambda x: -x["max_score"])

    return {
        "beacons": beacons[:100],
        "host_summary": host_list,
        "total_beacons": len(beacons),
        "total_hosts": len(host_summary),
        "total_pairs_analyzed": len(pairs),
    }


def _analyze_timing(timestamps):
    """
    Analyze timing regularity. Returns (mean_interval, jitter, score, intervals) or None.
    """
    # Parse timestamps and sort
    parsed = []
    for ts in timestamps:
        try:
            dt = datetime.fromisoformat(ts)
            parsed.append(dt.timestamp())
        except (ValueError, TypeError):
            continue

    if len(parsed) < MIN_CONNECTIONS:
        return None

    parsed.sort()

    # Compute intervals between consecutive connections
    intervals = [parsed[i + 1] - parsed[i] for i in range(len(parsed) - 1)]
    # Remove zero-intervals (multiple events at same second)
    intervals = [i for i in intervals if i > 0]

    if len(intervals) < MIN_CONNECTIONS - 1:
        return None

    mean_interval = sum(intervals) / len(intervals)

    # Filter out noise
    if mean_interval < MIN_INTERVAL or mean_interval > MAX_INTERVAL:
        return None

    # Standard deviation
    variance = sum((i - mean_interval) ** 2 for i in intervals) / len(intervals)
    stddev = math.sqrt(variance)

    # Jitter = coefficient of variation (stddev / mean)
    jitter = stddev / mean_interval if mean_interval > 0 else 999

    # Score: 0-100 based on regularity
    score = _compute_beacon_score(jitter, len(intervals), mean_interval)

    return mean_interval, jitter, score, intervals


def _compute_beacon_score(jitter, count, mean_interval):
    """
    Compute beacon likelihood score (0-100).
    Lower jitter + higher count + reasonable interval = higher score.
    """
    score = 0

    # Jitter component (0-50 points): lower jitter = more suspicious
    if jitter < 0.05:
        score += 50  # Nearly perfect regularity
    elif jitter < 0.1:
        score += 40
    elif jitter < 0.2:
        score += 30
    elif jitter < MAX_JITTER:
        score += 20
    else:
        return 0  # Too irregular

    # Count component (0-30 points): more connections = more confident
    if count >= 50:
        score += 30
    elif count >= 20:
        score += 20
    elif count >= 10:
        score += 15
    else:
        score += 5

    # Interval component (0-20 points): typical C2 intervals
    if 10 <= mean_interval <= 300:
        score += 20  # 10s - 5min: very common C2 interval
    elif 300 < mean_interval <= 900:
        score += 15  # 5-15 min: still suspicious
    elif 900 < mean_interval <= 3600:
        score += 10  # 15min - 1hr: slow beacon
    else:
        score += 5

    return min(score, 100)


def _format_interval(seconds):
    """Human-readable interval."""
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        return f"{seconds / 60:.1f}m"
    return f"{seconds / 3600:.1f}h"


def _build_histogram(intervals, bins=10):
    """Build a simple histogram of intervals for visualization."""
    if not intervals:
        return []
    mn, mx = min(intervals), max(intervals)
    if mn == mx:
        return [{"min": mn, "max": mx, "count": len(intervals)}]
    step = (mx - mn) / bins
    hist = []
    for i in range(bins):
        lo = mn + i * step
        hi = mn + (i + 1) * step
        count = sum(1 for v in intervals if lo <= v < hi or (i == bins - 1 and v == mx))
        hist.append({"min": round(lo, 1), "max": round(hi, 1), "count": count})
    return hist
