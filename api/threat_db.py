"""Known-threat database (blocklist) for phishing detection.

Two layers:

1. **Local blocklist** (``data/known_malicious.json``) — admin-curated entries
   added via the ``POST /threat`` endpoint. Each entry stores a URL, domain or
   suffix pattern, optional source/notes, and is timestamped + audited.

2. **Community feed (optional)** — pulled at runtime from a configurable URL
   (PhishTank CSV, OpenPhish, or any simple list) and cached to
   ``data/cache/threat_feed.json`` with a TTL. Disabled by default so the
   system stays fully self-contained; enable with ``PHISHGUARD_THREAT_FEED_URL``.

A matched known-threat is a *strong* signal but never a hard verdict by itself:
it is fed into the multi-engine vote (``threat_db_engine``) just like every
other engine. A reputable-domain override is intentionally NOT supported here —
a hit stays a hit.
"""

import csv
import io
import json
import logging
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

KNOWN_PATH = Path(__file__).resolve().parents[1] / "data" / "known_malicious.json"
FEED_CACHE_PATH = Path(__file__).resolve().parents[1] / "data" / "cache" / "threat_feed.json"
AUDIT_PATH = Path(__file__).resolve().parents[1] / "data" / "audit" / "threat.jsonl"

_known_lock = threading.RLock()
_audit_lock = threading.Lock()

MAX_VALUE_LEN = 512


def _now() -> float:
    return time.time()


def _audit(action: str, value: str, **extra) -> None:
    try:
        with _audit_lock:
            AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
            entry = {"ts": _now(), "action": action, "value": value, **extra}
            with open(AUDIT_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        logger.exception("Failed to write threat audit log")


# --------------------------------------------------------------------------
# Local blocklist
# --------------------------------------------------------------------------

def load_known() -> dict:
    """Return {value: {added_at, added_by, source, notes}} from local blocklist."""
    with _known_lock:
        if not KNOWN_PATH.exists():
            return {}
        try:
            raw = json.loads(KNOWN_PATH.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}
        if isinstance(raw, list):
            now = _now()
            return {str(v): {"added_at": now, "added_by": "migration",
                             "source": "legacy", "notes": ""} for v in raw}
        if not isinstance(raw, dict):
            return {}
        return {str(k): v for k, v in raw.items() if isinstance(v, dict)}


def save_known(entries: dict) -> None:
    with _known_lock:
        KNOWN_PATH.parent.mkdir(parents=True, exist_ok=True)
        KNOWN_PATH.write_text(
            json.dumps(entries, indent=2, ensure_ascii=False), encoding="utf-8"
        )


def add_entry(value: str, added_by: str = "admin", source: str = "manual",
              notes: str = "") -> dict:
    """Add a URL / domain / suffix pattern to the local blocklist. Audited."""
    value = value.strip().lower()
    if not value:
        return {"status": "error", "error": "Value cannot be empty"}
    if len(value) > MAX_VALUE_LEN:
        return {"status": "error", "error": f"Value too long (max {MAX_VALUE_LEN})"}
    with _known_lock:
        entries = load_known()
        if value in entries:
            return {"status": "error", "error": "Entry already exists", "value": value}
        entries[value] = {
            "added_at": _now(),
            "added_by": added_by,
            "source": source,
            "notes": notes or "",
        }
        save_known(entries)
    _audit("add", value, added_by=added_by, source=source, notes=notes)
    logger.info("Threat entry added: %s by %s", value, added_by)
    return {"status": "ok", "value": value}


def remove_entry(value: str, removed_by: str = "admin") -> dict:
    """Remove an entry from the local blocklist. Audited."""
    value = value.strip().lower()
    with _known_lock:
        entries = load_known()
        existed = entries.pop(value, None)
        if existed:
            save_known(entries)
    if existed:
        _audit("remove", value, removed_by=removed_by)
        logger.info("Threat entry removed: %s by %s", value, removed_by)
    return {"status": "ok", "value": value, "existed": bool(existed)}


# --------------------------------------------------------------------------
# Community feed (optional)
# --------------------------------------------------------------------------

def _load_feed_cache() -> dict:
    if not FEED_CACHE_PATH.exists():
        return {}
    try:
        return json.loads(FEED_CACHE_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _save_feed_cache(data: dict) -> None:
    FEED_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    FEED_CACHE_PATH.write_text(
        json.dumps(data, ensure_ascii=False), encoding="utf-8"
    )


def _fetch_feed(url: str, timeout: float = 15.0) -> dict:
    """Download and normalize a community threat feed.

    Supports plain-line lists, PhishTank-style CSV (url column), or a
    single-column feed. Returns {value: {source, notes}}.

    PhishTank CSV has a header row like ``phish_id,url,phish_detail_url,...`` so
    the URL is NOT necessarily the first column — we parse the header and read
    the ``url`` column by name. Feeds without a ``url`` column (or a plain line
    list) fall back to treating each line as a URL.
    """
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "phishguard-threat-feed"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read(65536 * 32).decode("utf-8", errors="replace")

    entries: dict = {}
    lines = [ln.strip() for ln in body.splitlines() if ln.strip()]
    if not lines:
        return entries

    header = None
    url_col = None
    is_csv = "," in lines[0]
    if is_csv:
        try:
            header = next(csv.reader(io.StringIO(lines[0])))
        except (csv.Error, StopIteration):
            header = None
        if header:
            lower = [h.strip().lower() for h in header]
            if any(h in ("url", "phishing_url", "phish_url", "target_url") for h in lower):
                # Header row found — locate the URL column by name.
                for i, h in enumerate(lower):
                    if h in ("url", "phishing_url", "phish_url", "target_url"):
                        url_col = i
                        break
                # Skip the header row itself (processed above).
                lines = lines[1:]

    def _url_from_row(row: list[str]) -> str | None:
        if url_col is not None:
            if url_col < len(row):
                return row[url_col]
            return None
        # No URL column detected: scan columns for a plausible URL.
        for cell in row:
            if "://" in cell:
                return cell
        return None

    for ln in lines:
        value = ln
        if is_csv:
            try:
                row = next(csv.reader(io.StringIO(ln)))
            except (csv.Error, StopIteration):
                continue
            if not row:
                continue
            candidate = _url_from_row(row)
            if not candidate:
                continue
            value = candidate
        value = value.strip().lower().strip("\"'")
        if not value or "://" not in value or len(value) > MAX_VALUE_LEN:
            continue
        entries.setdefault(value, {"source": "community_feed", "notes": ""})
    return entries


def refresh_feed(url: str | None = None, force: bool = False) -> dict:
    """Refresh the community feed cache if stale. No-op when feed URL is unset."""
    import os
    feed_url = url or os.environ.get("PHISHGUARD_THREAT_FEED_URL", "")
    if not feed_url:
        return {}
    ttl_hours = float(os.environ.get("PHISHGUARD_THREAT_FEED_REFRESH_HOURS", "24"))
    cache = _load_feed_cache()
    fetched_at = cache.get("_fetched_at", 0)
    entries = cache.get("entries", {})
    if not force and fetched_at and (time.time() - float(fetched_at)) < ttl_hours * 3600:
        return entries
    try:
        entries = _fetch_feed(feed_url)
        _save_feed_cache({"_fetched_at": time.time(), "source": feed_url, "entries": entries})
        logger.info("Threat feed refreshed: %d entries from %s", len(entries), feed_url)
    except Exception:
        logger.exception("Threat feed refresh failed for %s", feed_url)
    return entries


# --------------------------------------------------------------------------
# Lookup
# --------------------------------------------------------------------------

def _normalize_hostname(url: str) -> str:
    try:
        return (urlparse(url).netloc or urlparse(url).hostname or "").lower().split(":")[0]
    except Exception:
        return ""


def match_threat(url: str, feed: dict | None = None) -> dict | None:
    """Return a threat match dict or None.

    Matching priority:
      1. exact URL
      2. exact hostname
      3. registered-domain suffix (last N labels of hostname == value)
      4. hostname suffix (value is a trailing label sequence, e.g. "paypa1.com")
    """
    url = (url or "").strip().lower()
    if not url:
        return None
    host = _normalize_hostname(url)
    feed_entries = feed if feed is not None else refresh_feed()
    known = load_known()

    all_entries: dict[str, dict] = {}
    all_entries.update({k: {**v, "layer": "local"} for k, v in known.items()})
    for k, v in (feed_entries or {}).items():
        all_entries.setdefault(k, {**v, "layer": "community_feed"})

    def _labels_of(s: str) -> list[str]:
        return [p for p in s.split(".") if p]

    def _suffix_match(needle: str, candidate: str) -> bool:
        """True if needle equals candidate or is a subdomain of it."""
        n_parts = _labels_of(needle)
        c_parts = _labels_of(candidate)
        if not n_parts or not c_parts:
            return False
        if needle == candidate:
            return True
        return len(n_parts) > len(c_parts) and n_parts[-len(c_parts):] == c_parts

    # 1. exact URL match
    for value, meta in all_entries.items():
        if "://" in value and value == url:
            return _mk_match(url, value, meta)
    # 2/3/4. hostname-based matches (exact, registered-domain, suffix)
    host_parts = _labels_of(host)
    for value, meta in all_entries.items():
        if "://" in value:
            continue
        if value == host:
            return _mk_match(url, value, meta)
        if _suffix_match(host, value):
            return _mk_match(url, value, meta)
    return None


def _mk_match(url: str, value: str, meta: dict) -> dict:
    return {
        "matched": True,
        "value": value,
        "url": url,
        "layer": meta.get("layer", "local"),
        "source": meta.get("source", ""),
        "notes": meta.get("notes", ""),
    }


def get_all() -> dict:
    known = load_known()
    feed = refresh_feed()
    now = _now()
    entries = []
    for v, m in known.items():
        entries.append({
            "value": v, "layer": "local", "source": m.get("source", ""),
            "notes": m.get("notes", ""), "added_by": m.get("added_by", ""),
            "added_at": m.get("added_at"), "age_days": round((now - float(m.get("added_at", now))) / 86400, 1) if m.get("added_at") else None,
        })
    for v, m in (feed or {}).items():
        entries.append({
            "value": v, "layer": "community_feed", "source": m.get("source", ""),
            "notes": m.get("notes", ""), "added_by": "", "added_at": None, "age_days": None,
        })
    return {
        "count": len(entries),
        "local_count": len(known),
        "community_count": len(feed or {}),
        "feed_enabled": bool(__import__("os").environ.get("PHISHGUARD_THREAT_FEED_URL", "")),
        "entries": entries,
    }
