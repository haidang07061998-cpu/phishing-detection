"""
Webhook configuration and dispatch.

Production hardening:
- URL must pass the SSRF/URL-safety policy (``validate_url``).
- Host must be in the configured allowlist (``PHISHGUARD_WEBHOOK_ALLOWLIST``)
  when one is set; empty allowlist disables the feature unless a key is given.
- Every dispatch payload is signed with HMAC-SHA256 using
  ``PHISHGUARD_WEBHOOK_SECRET`` and sent as ``X-PhishGuard-Signature``.
- Dispatch runs in a background thread with a bounded timeout and a retry
  queue with exponential backoff (``PHISHGUARD_WEBHOOK_RETRIES``). Retries are
  scheduled via a delay queue (min-heap keyed by ``next_attempt_at``), so a
  failing webhook never blocks delivery of other events.
- Every delivery attempt is appended to an audit log
  (``data/audit/webhooks.jsonl``).
"""

import hashlib
import heapq
import hmac
import itertools
import json
import logging
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

if str(Path(__file__).resolve().parents[1]) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from api import config
from src.security.url_safety import validate_url
from api.utils import get_registered_domain

logger = logging.getLogger(__name__)

CONFIG_PATH = Path(__file__).resolve().parents[1] / "data" / "webhook_config.json"
AUDIT_PATH = Path(__file__).resolve().parents[1] / "data" / "audit" / "webhooks.jsonl"
_config_lock = threading.Lock()
_audit_lock = threading.Lock()
_worker_started = False
_worker_lock = threading.Lock()

BACKOFF_BASE_SECONDS = 2.0
SIGNATURE_HEADER = "X-PhishGuard-Signature"


# --------------------------------------------------------------------------
# Persistence
# --------------------------------------------------------------------------

def load_config() -> dict:
    with _config_lock:
        if CONFIG_PATH.exists():
            try:
                return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                return {}
        return {}


def save_config(cfg: dict) -> None:
    with _config_lock:
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


def _audit(entry: dict) -> None:
    try:
        with _audit_lock:
            AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
            with open(AUDIT_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        logger.exception("Failed to write webhook audit log")


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------

def _host_allowed(hostname: str) -> bool:
    allowlist = config.WEBHOOK_ALLOWLIST
    if not allowlist:
        return False
    reg = get_registered_domain(f"http://{hostname}/") or hostname
    return reg in allowlist or hostname in allowlist


def validate_webhook_url(url: str) -> str | None:
    """Return an error string if *url* is not an acceptable webhook target."""
    check = validate_url(url)
    if not check["valid"]:
        return f"webhook URL rejected by safety policy: {check['reason']}"
    if not _host_allowed(check["hostname"]):
        return f"webhook host '{check['hostname']}' is not in the allowlist"
    return None


def set_webhook(url: str, events: list[str] | None = None) -> dict:
    if not url or not isinstance(url, str):
        return {"status": "error", "error": "webhook URL is required"}
    if events is not None and not isinstance(events, list):
        return {"status": "error", "error": "events must be a list of strings"}
    events = events or ["scan.completed"]
    for ev in events:
        if not isinstance(ev, str) or not ev.strip():
            return {"status": "error", "error": "events must be non-empty strings"}

    err = validate_webhook_url(url)
    if err:
        return {"status": "error", "error": err}

    cfg = load_config()
    cfg["url"] = url
    cfg["events"] = events
    cfg["enabled"] = True
    save_config(cfg)
    logger.info("Webhook configured: %s (events=%s)", url, events)
    return {"status": "ok", "config": cfg}


def delete_webhook() -> dict:
    cfg = load_config()
    if cfg:
        cfg["enabled"] = False
        save_config(cfg)
    return {"status": "ok"}


def get_webhook() -> dict:
    cfg = load_config()
    return cfg if cfg else {"enabled": False}


# --------------------------------------------------------------------------
# Signature
# --------------------------------------------------------------------------

def _sign_payload(payload: bytes) -> str:
    secret = (config.WEBHOOK_SECRET or "").encode("utf-8")
    digest = hmac.new(secret, payload, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


# --------------------------------------------------------------------------
# Dispatch (async + delay/retry queue)
# --------------------------------------------------------------------------

# Delay queue: a min-heap keyed by `next_attempt_at` (monotonic clock). The
# single worker only ever waits until the earliest due item, so a webhook in
# backoff does NOT hold up delivery of other (possibly healthy) events.
_dispatch_cond = threading.Condition()
_dispatch_heap: list[tuple[float, int, dict]] = []
_dispatch_seq = itertools.count()


def _enqueue(item: dict, delay: float = 0.0) -> None:
    """Push a delivery item, optionally scheduled `delay` seconds from now."""
    with _dispatch_cond:
        heapq.heappush(_dispatch_heap, (time.monotonic() + delay, next(_dispatch_seq), item))
        _dispatch_cond.notify()


def _next_ready() -> dict:
    """Block until an item is due (or a new item arrives); return the due item."""
    with _dispatch_cond:
        while True:
            now = time.monotonic()
            if _dispatch_heap and _dispatch_heap[0][0] <= now:
                return heapq.heappop(_dispatch_heap)[2]
            if _dispatch_heap:
                _dispatch_cond.wait(timeout=_dispatch_heap[0][0] - now)
            else:
                _dispatch_cond.wait()


def dispatch(event: str, payload: dict) -> None:
    cfg = load_config()
    if not cfg.get("enabled") or not cfg.get("url"):
        return
    if event not in cfg.get("events", []):
        return
    _enqueue({"url": cfg["url"], "event": event, "payload": payload, "attempt": 0})
    _ensure_worker()


def _ensure_worker() -> None:
    global _worker_started
    with _worker_lock:
        if _worker_started:
            return
        _worker_started = True
        threading.Thread(target=_worker_loop, daemon=True).start()


def _worker_loop() -> None:
    while True:
        item = _next_ready()
        try:
            _deliver(item)
        except Exception:
            logger.exception("webhook delivery error")


def _deliver(item: dict) -> None:
    url, event = item["url"], item["event"]
    attempt = item.get("attempt", 0)
    max_retries = max(config.WEBHOOK_MAX_RETRIES, 0)

    try:
        body = json.dumps({"event": event, "payload": item["payload"]}).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            headers={
                "Content-Type": "application/json",
                SIGNATURE_HEADER: _sign_payload(body),
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=config.WEBHOOK_TIMEOUT) as resp:
            status = getattr(resp, "status", 200)
            _audit({
                "ts": time.time(),
                "url": url,
                "event": event,
                "status": status,
                "ok": True,
                "attempt": attempt + 1,
            })
            return
    except Exception as exc:  # noqa: BLE001
        _audit({
            "ts": time.time(),
            "url": url,
            "event": event,
            "status": None,
            "ok": False,
            "attempt": attempt + 1,
            "error": str(exc),
        })
        if attempt < max_retries:
            backoff = BACKOFF_BASE_SECONDS * (2 ** attempt)
            logger.warning("Webhook %s failed (attempt %d), retrying in %.1fs: %s",
                           url, attempt + 1, backoff, exc)
            item["attempt"] = attempt + 1
            _enqueue(item, delay=backoff)
