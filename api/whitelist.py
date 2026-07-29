import json
import logging
import threading
from pathlib import Path

logger = logging.getLogger(__name__)

DYNAMIC_PATH = Path(__file__).resolve().parents[1] / "data" / "dynamic_whitelist.json"
_dynamic_lock = threading.Lock()

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

MIN_SCANS_FOR_AUTO_WHITELIST = 5
MAX_SCORE_FOR_AUTO_WHITELIST = 15


def load_dynamic() -> set:
    with _dynamic_lock:
        if DYNAMIC_PATH.exists():
            try:
                return set(json.loads(DYNAMIC_PATH.read_text(encoding="utf-8")))
            except (json.JSONDecodeError, OSError):
                return set()
        return set()


def save_dynamic(domains: set) -> None:
    with _dynamic_lock:
        DYNAMIC_PATH.parent.mkdir(parents=True, exist_ok=True)
        DYNAMIC_PATH.write_text(
            json.dumps(sorted(domains), indent=2), encoding="utf-8"
        )


def is_whitelisted(domain: str) -> bool:
    if not domain:
        return False
    if domain in STATIC_DOMAINS:
        return True
    dynamic = load_dynamic()
    return domain in dynamic


def maybe_add_dynamic(reputation: dict, domain: str) -> bool:
    if not domain or domain in STATIC_DOMAINS:
        return False
    scans = reputation.get("scans", 0)
    avg_score = reputation.get("avg_score", 100)
    if scans >= MIN_SCANS_FOR_AUTO_WHITELIST and avg_score <= MAX_SCORE_FOR_AUTO_WHITELIST:
        dynamic = load_dynamic()
        if domain not in dynamic:
            dynamic.add(domain)
            save_dynamic(dynamic)
            logger.info("Auto-whitelisted domain: %s (scans=%d, avg_score=%.1f)", domain, scans, avg_score)
            return True
    return False


def get_all() -> dict:
    dynamic = load_dynamic()
    return {
        "static_count": len(STATIC_DOMAINS),
        "static_domains": sorted(STATIC_DOMAINS),
        "dynamic_count": len(dynamic),
        "dynamic_domains": sorted(dynamic),
    }


def add_dynamic(domain: str) -> dict:
    dynamic = load_dynamic()
    dynamic.add(domain)
    save_dynamic(dynamic)
    return {"status": "ok", "domain": domain, "source": "dynamic"}


def remove_dynamic(domain: str) -> dict:
    dynamic = load_dynamic()
    dynamic.discard(domain)
    save_dynamic(dynamic)
    return {"status": "ok", "domain": domain}
