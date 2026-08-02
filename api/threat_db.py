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
import os
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

# --------------------------------------------------------------------------
# In-memory lookup snapshot (request path never touches the network or disk)
# --------------------------------------------------------------------------

_snapshot_lock = threading.RLock()
_snapshot = None            # _ThreatSnapshot | None
_local_version = 0          # bumped when the local blocklist changes

_feed_lock = threading.RLock()
_feed_entries: dict = {}    # current community-feed entries {value: meta}
_feed_source = ""
_feed_fetched_at = 0.0
_feed_loaded = False        # initial on-disk cache load attempted
_feed_refresh_started = False  # a background refresh is in flight


class _ThreatSnapshot:
    """Immutable snapshot of local + feed entries with O(1)/O(labels) indexes."""

    __slots__ = ("version", "known", "feed", "exact_urls", "exact_hosts", "meta")

    def __init__(self, version: int, known: dict, feed: dict) -> None:
        self.version = version
        self.known = dict(known)
        self.feed = dict(feed)
        meta: dict = {}
        for value, m in known.items():
            meta[value] = {**m, "layer": "local"}
        for value, m in feed.items():
            meta.setdefault(value, {**m, "layer": "community_feed"})
        self.meta = meta
        self.exact_urls = frozenset(v for v in meta if "://" in v)
        self.exact_hosts = frozenset(v for v in meta if "://" not in v)


def _now() -> float:
    return time.time()


def _bump_local_version() -> None:
    """Invalidate the lookup snapshot after a local blocklist change."""
    global _local_version, _snapshot
    with _snapshot_lock:
        _local_version += 1
        _snapshot = None


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
    _bump_local_version()
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
        _bump_local_version()
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


def _feed_url() -> str:
    return os.environ.get("PHISHGUARD_THREAT_FEED_URL", "")


def _feed_ttl_hours() -> float:
    return float(os.environ.get("PHISHGUARD_THREAT_FEED_REFRESH_HOURS", "24"))


def _feed_is_stale(now: float | None = None) -> bool:
    now = _now() if now is None else now
    if not _feed_fetched_at:
        return True
    return (now - _feed_fetched_at) >= _feed_ttl_hours() * 3600


def _load_feed_from_cache() -> None:
    """Load the on-disk feed cache into memory (fast, no network)."""
    global _feed_entries, _feed_fetched_at, _feed_source, _feed_loaded
    cache = _load_feed_cache()
    fetched_at = cache.get("_fetched_at", 0)
    if fetched_at:
        _feed_entries = cache.get("entries", {}) or {}
        _feed_fetched_at = float(fetched_at)
        _feed_source = cache.get("source", "")
    _feed_loaded = True


def _invalidate_snapshot() -> None:
    global _snapshot
    with _snapshot_lock:
        _snapshot = None


def _refresh_feed_background(url: str) -> None:
    """Fetch + cache the feed off the request path. On failure keep the old data."""
    try:
        entries = _fetch_feed(url)
        with _feed_lock:
            global _feed_entries, _feed_fetched_at, _feed_source
            _feed_entries = entries
            _feed_fetched_at = _now()
            _feed_source = url
        _invalidate_snapshot()
        _save_feed_cache({"_fetched_at": _feed_fetched_at, "source": url, "entries": entries})
        logger.info("Threat feed refreshed: %d entries from %s", len(entries), url)
    except Exception:
        logger.exception("Threat feed refresh failed for %s", url)
    finally:
        with _feed_lock:
            global _feed_refresh_started
            _feed_refresh_started = False


def ensure_feed_refresh(url: str | None = None, force: bool = False) -> dict:
    """Populate the in-memory feed snapshot without blocking the caller.

    Returns the current in-memory feed entries immediately. If a disk cache
    exists it is loaded synchronously (fast, local). A stale/forced feed is
    refreshed in a single background thread — never in the request path.
    """
    feed_url = url or _feed_url()
    with _feed_lock:
        global _feed_loaded, _feed_refresh_started
        if not feed_url:
            _feed_loaded = True
            return _feed_entries
        if not _feed_loaded:
            _load_feed_from_cache()
        if (force or _feed_is_stale()) and not _feed_refresh_started:
            _feed_refresh_started = True
            threading.Thread(target=_refresh_feed_background, args=(feed_url,),
                             daemon=True).start()
        return _feed_entries


def refresh_feed(url: str | None = None, force: bool = False) -> dict:
    """Non-blocking feed refresh: returns current entries, refreshes in background.

    Legacy callers (GET /threat) can keep using this — it never blocks on the
    network anymore.
    """
    return ensure_feed_refresh(url=url, force=force)


def _get_snapshot() -> _ThreatSnapshot:
    """Return the current lookup snapshot, rebuilding only when inputs change."""
    ensure_feed_refresh()
    global _snapshot
    with _snapshot_lock:
        if _snapshot is None or _snapshot.version != _local_version:
            _snapshot = _ThreatSnapshot(_local_version, load_known(), _feed_entries)
        return _snapshot


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

    **Non-blocking**: reads the in-memory snapshot only — never fetches the
    feed and never touches the network or disk. A community-feed refresh runs
    in a background thread and swaps in a new snapshot when done.

    Matching priority:
      1. exact URL
      2. exact hostname
      3. registered-domain / hostname suffix (most specific label sequence wins)

    Lookup is O(1) for exact URL/hostname via frozensets and O(labels of
    hostname) for suffix matches (each trailing label suffix is a set probe),
    instead of a linear scan over every entry.
    """
    url = (url or "").strip().lower()
    if not url:
        return None
    host = _normalize_hostname(url)
    if feed is not None:
        # Explicit feed override: build a throwaway snapshot (still no network).
        snap = _ThreatSnapshot(-1, load_known(), feed)
    else:
        snap = _get_snapshot()

    # 1. exact URL
    if url in snap.exact_urls:
        return _mk_match(url, url, snap.meta[url])
    # 2. exact hostname
    if host in snap.exact_hosts:
        return _mk_match(url, host, snap.meta[host])
    # 3/4. suffix: walk host labels from most specific to least, set-probe each
    if snap.exact_hosts:
        labels = host.split(".")
        for i in range(len(labels)):
            cand = ".".join(labels[i:])
            if cand in snap.exact_hosts:
                return _mk_match(url, cand, snap.meta[cand])
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
    snap = _get_snapshot()
    now = _now()
    entries = []
    for v, m in snap.known.items():
        entries.append({
            "value": v, "layer": "local", "source": m.get("source", ""),
            "notes": m.get("notes", ""), "added_by": m.get("added_by", ""),
            "added_at": m.get("added_at"), "age_days": round((now - float(m.get("added_at", now))) / 86400, 1) if m.get("added_at") else None,
        })
    for v, m in snap.feed.items():
        entries.append({
            "value": v, "layer": "community_feed", "source": m.get("source", ""),
            "notes": m.get("notes", ""), "added_by": "", "added_at": None, "age_days": None,
        })
    return {
        "count": len(entries),
        "local_count": len(snap.known),
        "community_count": len(snap.feed),
        "feed_enabled": bool(_feed_url()),
        "entries": entries,
    }
