"""
GeoLite2 offline IP enrichment.

Reads the MaxMind GeoLite2-City and GeoLite2-ASN binary databases from
the project's `geolite2/` directory (overridable via GEOLITE2_DIR env var).

Returns the same dict shape used by analyzers/geoip.py so it's a
drop-in alternative to the on-demand ip-api.com lookup:

    {country, country_code, city, isp, org}

Design notes
- Reader objects are opened once and reused (geoip2 readers are
  thread-safe for the lookup methods we use).
- If either file is missing/unreadable we report `available=False` and
  the caller falls back to the HTTP path. No exceptions propagate.
- City DB has no ISP field (that's a Pro-only feature). We populate
  `org` from the ASN DB and leave `isp` empty when the ASN DB is also
  unavailable.
"""

import os
import threading

_LOCK = threading.Lock()
_CITY_READER = None
_ASN_READER = None
_LOAD_ATTEMPTED = False
_LOAD_ERRORS = []  # human-readable messages; empty means "all good"


def _project_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _db_dir():
    return os.environ.get("GEOLITE2_DIR") or os.path.join(_project_root(), "geolite2")


def _ensure_loaded():
    """Lazy-load the readers on first use; cache the outcome."""
    global _CITY_READER, _ASN_READER, _LOAD_ATTEMPTED, _LOAD_ERRORS
    if _LOAD_ATTEMPTED:
        return
    with _LOCK:
        if _LOAD_ATTEMPTED:
            return
        _LOAD_ATTEMPTED = True
        try:
            import geoip2.database  # noqa: F401
        except ImportError as e:
            _LOAD_ERRORS.append(f"geoip2 library not installed: {e}")
            return

        from geoip2.database import Reader
        d = _db_dir()
        city_path = os.path.join(d, "GeoLite2-City.mmdb")
        asn_path = os.path.join(d, "GeoLite2-ASN.mmdb")

        if os.path.exists(city_path):
            try:
                _CITY_READER = Reader(city_path)
            except Exception as e:
                _LOAD_ERRORS.append(f"GeoLite2-City.mmdb load failed: {e}")
        else:
            _LOAD_ERRORS.append(f"GeoLite2-City.mmdb not found at {city_path}")

        if os.path.exists(asn_path):
            try:
                _ASN_READER = Reader(asn_path)
            except Exception as e:
                _LOAD_ERRORS.append(f"GeoLite2-ASN.mmdb load failed: {e}")
        else:
            _LOAD_ERRORS.append(f"GeoLite2-ASN.mmdb not found at {asn_path}")


def is_available():
    """True if at least the City DB is loaded (ASN is a bonus)."""
    _ensure_loaded()
    return _CITY_READER is not None


def status():
    """Diagnostic info for the /api/geoip/status endpoint."""
    _ensure_loaded()
    info = {
        "available": _CITY_READER is not None,
        "city_db_loaded": _CITY_READER is not None,
        "asn_db_loaded": _ASN_READER is not None,
        "errors": list(_LOAD_ERRORS),
        "db_dir": _db_dir(),
        "mode": "offline" if _CITY_READER is not None else "fallback (ip-api.com)",
    }
    # Add metadata if the City DB is loaded
    if _CITY_READER is not None:
        try:
            md = _CITY_READER.metadata()
            info["city_build_epoch"] = md.build_epoch
            info["city_node_count"] = md.node_count
        except Exception:
            pass
    if _ASN_READER is not None:
        try:
            md = _ASN_READER.metadata()
            info["asn_build_epoch"] = md.build_epoch
        except Exception:
            pass
    return info


def lookup(ip):
    """Resolve a single IP via offline DBs. Returns the standard 5-key dict
    on success, or None if the offline DBs are unavailable / IP not found.

    Uses None (not empty dict) as the miss sentinel so callers know to fall
    back to HTTP rather than caching a useless empty result.
    """
    _ensure_loaded()
    if _CITY_READER is None:
        return None
    out = {"country": "", "country_code": "", "city": "", "isp": "", "org": ""}
    try:
        c = _CITY_READER.city(ip)
        out["country"] = (c.country.name or "") if c.country else ""
        out["country_code"] = (c.country.iso_code or "") if c.country else ""
        out["city"] = (c.city.name or "") if c.city else ""
    except Exception:
        # IP not in DB (e.g. private RFC1918), or other lookup miss.
        return None
    if _ASN_READER is not None:
        try:
            a = _ASN_READER.asn(ip)
            org = a.autonomous_system_organization or ""
            asn = a.autonomous_system_number
            if asn and org:
                out["org"] = f"AS{asn} {org}"
            elif org:
                out["org"] = org
        except Exception:
            pass
    return out


def close():
    """Release readers (mainly useful for tests)."""
    global _CITY_READER, _ASN_READER
    with _LOCK:
        for r in (_CITY_READER, _ASN_READER):
            try:
                if r is not None:
                    r.close()
            except Exception:
                pass
        _CITY_READER = None
        _ASN_READER = None
