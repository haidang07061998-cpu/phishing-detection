import json
import logging
import threading
import time
from pathlib import Path

logger = logging.getLogger(__name__)

DYNAMIC_PATH = Path(__file__).resolve().parents[1] / "data" / "dynamic_whitelist.json"
AUDIT_PATH = Path(__file__).resolve().parents[1] / "data" / "audit" / "whitelist.jsonl"
_dynamic_lock = threading.RLock()
_audit_lock = threading.Lock()

# Admin-verified reputable domains (no expiry, trusted to host their own subdomains).
STATIC_DOMAINS = {
    "google.com", "googleapis.com", "googleusercontent.com",
    "gmail.com", "youtube.com", "youtu.be", "blogspot.com",
    "google.vn",
    "microsoft.com", "office.com", "office365.com",
    "live.com", "outlook.com", "azure.com",
    "github.com", "githubusercontent.com",
    "facebook.com", "fb.com", "fbcdn.net",
    "instagram.com", "whatsapp.com",
    "apple.com", "icloud.com",
    "amazon.com", "aws.amazon.com",
    "twitter.com", "x.com", "linkedin.com",
    "telegram.org", "discord.com", "slack.com",
    "gitlab.com", "bitbucket.org", "npmjs.com",
    "docker.com", "stackoverflow.com",
    "wikipedia.org", "wikimedia.org",
    "netflix.com", "spotify.com", "adobe.com",
    "paypal.com", "ebay.com",
    "zoom.us", "dropbox.com",
    "cloudflare.com",
    "vietnamnet.vn", "vnexpress.net", "tuoitre.vn",
    "thanhnien.vn", "dantri.com.vn", "nguoiduatin.vn",
    "vov.vn", "baomoi.com", "cafef.vn", "cafebiz.vn",
    "zalo.me", "chotot.com", "batdongsan.com.vn",
    "tiki.vn", "shopee.vn", "thegioididong.com",
    "vietcombank.com.vn", "techcombank.com.vn",
    "acb.com.vn", "vpbank.com.vn", "mbbank.com.vn",
    "vietinbank.vn", "bidv.com.vn",
}

# Registered domains whose SUBDOMAINS host third-party/user content.
# A known-reputable status on these must NOT extend trust to arbitrary subdomains
# (e.g. <user>.github.io, <blog>.blogspot.com, <site>.netlify.app).
USER_CONTENT_DOMAINS = {
    "github.io", "githubusercontent.com", "googleusercontent.com",
    "blogspot.com", "wordpress.com", "medium.com", "wixsite.com",
    "webflow.io", "squarespace.com", "weebly.com", "ghost.io",
    "netlify.app", "vercel.app", "pages.dev", "firebaseapp.com",
    "web.app", "azurewebsites.net", "cloudfront.net", "s3.amazonaws.com",
    "r2.dev", "workers.dev", "herokuapp.com", "neocities.org",
    "notion.site", "gitbook.io", "readme.io", "substack.com",
}

# Dynamic entries expire after this many days unless re-added.
DEFAULT_TTL_DAYS = 30
MIN_TTL_DAYS = 1
MAX_TTL_DAYS = 365


def _now() -> float:
    return time.time()


def _audit(action: str, domain: str, **extra) -> None:
    """Append one line to the whitelist audit log (data/audit/whitelist.jsonl)."""
    try:
        with _audit_lock:
            AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
            entry = {"ts": _now(), "action": action, "domain": domain, **extra}
            with open(AUDIT_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        logger.exception("Failed to write whitelist audit log")


def load_dynamic() -> dict:
    """Load dynamic entries as {domain: {added_at, expires_at, source, added_by, reason}}."""
    with _dynamic_lock:
        if not DYNAMIC_PATH.exists():
            return {}
        try:
            raw = json.loads(DYNAMIC_PATH.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}
        # Backward compat: legacy file was a plain list of domains.
        if isinstance(raw, list):
            dynamic = {
                str(d): {"added_at": _now(), "expires_at": _now() + DEFAULT_TTL_DAYS * 86400,
                         "source": "legacy", "added_by": "migration", "reason": "legacy entry"}
                for d in raw
            }
            _purge_expired_locked(dynamic)
            return dynamic
        if not isinstance(raw, dict):
            return {}
        dynamic = {str(k): v for k, v in raw.items() if isinstance(v, dict)}
        _purge_expired_locked(dynamic)
        return dynamic


def _purge_expired_locked(dynamic: dict) -> None:
    """Drop expired entries, auditing each revocation. Caller must hold _dynamic_lock."""
    now = _now()
    expired = [d for d, e in dynamic.items() if _entry_expired(e, now)]
    for d in expired:
        dynamic.pop(d, None)
        _audit("expire", d, reason="ttl_expired")


def _entry_expired(entry: dict, now: float | None = None) -> bool:
    if not isinstance(entry, dict):
        return True
    expires = entry.get("expires_at")
    if not expires:
        return False  # no expiry recorded -> keep
    try:
        return float(expires) <= (now if now is not None else _now())
    except (TypeError, ValueError):
        return False


def save_dynamic(domains: dict) -> None:
    with _dynamic_lock:
        DYNAMIC_PATH.parent.mkdir(parents=True, exist_ok=True)
        DYNAMIC_PATH.write_text(
            json.dumps(domains, indent=2, ensure_ascii=False), encoding="utf-8"
        )


def get_domain_status(hostname: str, registered_domain: str | None = None) -> dict:
    """Return a REPUTATION SIGNAL (never a verdict) for a hostname.

    - known_reputable_domain: registered domain is in static or active dynamic lists
    - source: 'static' | 'dynamic' | None
    - expires_at: dynamic expiry timestamp (None for static)
    - subdomain_trusted: whether the full hostname is covered by the reputation.
      Subdomains of USER_CONTENT_DOMAINS are NOT trusted.
    """
    rd = (registered_domain or hostname or "").lower().lstrip("www.")
    status = {
        "known_reputable_domain": False,
        "source": None,
        "expires_at": None,
        "subdomain_trusted": False,
        "reason": "",
    }
    if not rd:
        return status

    host = (hostname or "").lower()
    has_subdomain = bool(host) and host != rd and not host.startswith("www.")

    def _subdomain_trusted() -> bool:
        # No subdomain -> the registered domain itself is covered.
        # Subdomain present + user-content host -> NOT covered by parent reputation.
        return not has_subdomain or rd not in USER_CONTENT_DOMAINS

    if rd in STATIC_DOMAINS:
        status["known_reputable_domain"] = True
        status["source"] = "static"
        status["subdomain_trusted"] = _subdomain_trusted()
        return status

    dynamic = load_dynamic()
    entry = dynamic.get(rd)
    if entry and not _entry_expired(entry):
        status["known_reputable_domain"] = True
        status["source"] = entry.get("source", "dynamic")
        status["expires_at"] = entry.get("expires_at")
        status["reason"] = entry.get("reason", "")
        status["subdomain_trusted"] = _subdomain_trusted()
    return status


def is_whitelisted(domain: str) -> bool:
    """Backward-compat helper: True when the registered domain is a known reputable one."""
    return get_domain_status(domain, domain)["known_reputable_domain"]


def add_dynamic(domain: str, added_by: str = "admin", ttl_days: int = DEFAULT_TTL_DAYS,
                reason: str = "") -> dict:
    """Add a domain to the dynamic list. Requires admin privileges (caller checks).

    Entries are time-limited (ttl_days) and every add is audited.
    """
    if not domain:
        return {"status": "error", "error": "Domain cannot be empty"}
    domain = domain.strip().lower().lstrip("www.")
    ttl_days = max(MIN_TTL_DAYS, min(int(ttl_days), MAX_TTL_DAYS))
    now = _now()
    with _dynamic_lock:
        dynamic = load_dynamic()
        dynamic[domain] = {
            "added_at": now,
            "expires_at": now + ttl_days * 86400,
            "source": "dynamic",
            "added_by": added_by,
            "reason": reason or "",
        }
        save_dynamic(dynamic)
    _audit("add", domain, added_by=added_by, ttl_days=ttl_days, reason=reason)
    logger.info("Domain whitelisted (dynamic): %s by %s (ttl=%dd)", domain, added_by, ttl_days)
    return {"status": "ok", "domain": domain, "source": "dynamic",
            "expires_at": now + ttl_days * 86400}


def remove_dynamic(domain: str, removed_by: str = "admin", reason: str = "") -> dict:
    """Revoke a dynamic whitelist entry. Audited."""
    domain = domain.strip().lower()
    with _dynamic_lock:
        dynamic = load_dynamic()
        existed = dynamic.pop(domain, None)
        if existed:
            save_dynamic(dynamic)
    if existed:
        _audit("remove", domain, removed_by=removed_by, reason=reason)
        logger.info("Domain revoked from whitelist: %s by %s", domain, removed_by)
    return {"status": "ok", "domain": domain, "existed": bool(existed)}


def get_all() -> dict:
    dynamic = load_dynamic()
    now = _now()
    entries = {}
    for d, e in dynamic.items():
        expires = e.get("expires_at")
        entries[d] = {
            "added_at": e.get("added_at"),
            "expires_at": expires,
            "source": e.get("source"),
            "added_by": e.get("added_by"),
            "reason": e.get("reason"),
            "ttl_remaining_days": round((float(expires) - now) / 86400, 1) if expires else None,
        }
    return {
        "static_count": len(STATIC_DOMAINS),
        "static_domains": sorted(STATIC_DOMAINS),
        "user_content_domains": sorted(USER_CONTENT_DOMAINS),
        "dynamic_count": len(entries),
        "dynamic_domains": entries,
        "ttl_days_default": DEFAULT_TTL_DAYS,
    }
