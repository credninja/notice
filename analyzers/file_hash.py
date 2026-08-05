"""
File Hash Extraction — extract file metadata and hashes from
Suricata fileinfo events for threat hunting and IOC matching.
"""

from collections import defaultdict
from eve_reader import iter_events, is_internal


def extract_file_hashes(minutes=None):
    """
    Scan eve.json for fileinfo events and extract file metadata + hashes.
    Returns file list with MD5/SHA1/SHA256, source/dest, protocol, size.
    """
    files = []
    hash_index = defaultdict(list)
    src_host_files = defaultdict(lambda: {"count": 0, "total_bytes": 0, "unique_hashes": set()})
    ext_counts = defaultdict(int)
    proto_counts = defaultdict(int)

    seen_hashes = set()

    for ev in iter_events(event_types={"fileinfo"}, minutes=minutes):
        fi = ev.get("fileinfo", {})
        if not fi:
            continue

        src = ev.get("src_ip", "")
        dst = ev.get("dest_ip", "")
        ts = ev.get("timestamp", "")
        app_proto = ev.get("app_proto", "")
        src_port = ev.get("src_port", 0)
        dst_port = ev.get("dest_port", 0)

        filename = fi.get("filename", "")
        size = fi.get("size", 0)
        state = fi.get("state", "")
        stored = fi.get("stored", False)
        md5 = fi.get("md5", "")
        sha1 = fi.get("sha1", "")
        sha256 = fi.get("sha256", "")

        primary_hash = sha256 or sha1 or md5
        if not primary_hash:
            continue

        ext = ""
        if filename and "." in filename:
            ext = filename.rsplit(".", 1)[-1].lower()

        direction = "download"
        if is_internal(src) and not is_internal(dst):
            direction = "upload"
        elif is_internal(src) and is_internal(dst):
            direction = "lateral"

        dedup_key = f"{primary_hash}:{src}:{dst}"
        if dedup_key in seen_hashes:
            continue
        seen_hashes.add(dedup_key)

        entry = {
            "timestamp": ts,
            "src_ip": src,
            "dest_ip": dst,
            "src_port": src_port,
            "dest_port": dst_port,
            "app_proto": app_proto,
            "filename": filename,
            "size": size,
            "state": state,
            "stored": stored,
            "md5": md5,
            "sha1": sha1,
            "sha256": sha256,
            "extension": ext,
            "direction": direction,
        }
        files.append(entry)

        if primary_hash:
            hash_index[primary_hash].append({
                "src": src, "dst": dst, "ts": ts, "filename": filename,
            })

        internal_host = src if is_internal(src) else dst
        hf = src_host_files[internal_host]
        hf["count"] += 1
        hf["total_bytes"] += size
        hf["unique_hashes"].add(primary_hash)

        if ext:
            ext_counts[ext] += 1
        if app_proto:
            proto_counts[app_proto] += 1

    files.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

    suspicious_extensions = {"exe", "dll", "scr", "bat", "cmd", "ps1", "vbs",
                             "js", "jar", "msi", "hta", "wsf", "com", "pif"}
    suspicious_files = [f for f in files if f["extension"] in suspicious_extensions]

    multi_source_hashes = []
    for h, appearances in hash_index.items():
        sources = set(a["src"] for a in appearances)
        if len(sources) > 1:
            multi_source_hashes.append({
                "hash": h,
                "source_count": len(sources),
                "sources": sorted(sources)[:10],
                "filename": appearances[0]["filename"],
            })
    multi_source_hashes.sort(key=lambda x: -x["source_count"])

    host_summary = []
    for host, info in src_host_files.items():
        host_summary.append({
            "host": host,
            "file_count": info["count"],
            "total_bytes": info["total_bytes"],
            "unique_hashes": len(info["unique_hashes"]),
        })
    host_summary.sort(key=lambda x: -x["file_count"])

    return {
        "files": files[:200],
        "summary": {
            "total_files": len(files),
            "unique_hashes": len(hash_index),
            "suspicious_files": len(suspicious_files),
            "total_bytes": sum(f["size"] for f in files),
            "multi_source_hashes": len(multi_source_hashes),
        },
        "suspicious_files": suspicious_files[:50],
        "multi_source_hashes": multi_source_hashes[:20],
        "extension_distribution": dict(ext_counts),
        "protocol_distribution": dict(proto_counts),
        "host_summary": host_summary[:30],
    }
