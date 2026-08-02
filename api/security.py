"""
Security helpers for the Flask API: API-key auth and per-IP rate limiting.

Both are implemented as decorators so individual routes can opt in:

    @app.route("/predict", methods=["POST"])
    @rate_limit(minute=30, hour=300)
    @require_api_key
    def predict(): ...

Ordering matters: ``@rate_limit`` must wrap ``@require_api_key`` so the
rate limiter runs first and unauthenticated floods are throttled before the
auth check. When auth is disabled (no keys configured) the decorators are
no-ops, preserving dev mode behaviour.

Multi-user key management
-------------------------
Keys come from two sources:

- **Env keys** (``PHISHGUARD_API_KEYS``) — legacy admin keys, always granted
  the full ``admin`` scope. Convenient for self-hosting/deployment.
- **Registry keys** (``data/api_keys.json``) — managed at runtime via the
  ``/keys`` admin endpoints. Each key stores a SHA-256 hash of the secret, a
  human name, an optional expiry timestamp, an optional IP allowlist, and the
  set of scopes it can access. The plaintext secret is returned only once at
  creation time.

Scopes: ``admin`` (manage keys, whitelist, threats), ``scan`` (predict /
domain / ip), ``feedback``, ``reports``.
"""

import hashlib
import json
import secrets
import threading
import time
from collections import deque
from functools import wraps
from pathlib import Path

from flask import jsonify, request

from api import config

# --------------------------------------------------------------------------
# Key registry
# --------------------------------------------------------------------------

KEY_REGISTRY_PATH = Path(__file__).resolve().parents[1] / "data" / "api_keys.json"
KEY_AUDIT_PATH = Path(__file__).resolve().parents[1] / "data" / "audit" / "api_keys.jsonl"
_key_lock = threading.RLock()

SCOPES = ("admin", "scan", "feedback", "reports")
DEFAULT_SCOPES = ("scan", "feedback", "reports")


def _registry() -> dict:
    """Return {key_id: {name, key_hash, scopes, expires_at, ip_allowlist, created_at}}."""
    if not KEY_REGISTRY_PATH.exists():
        return {}
    try:
        data = json.loads(KEY_REGISTRY_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    return data if isinstance(data, dict) else {}


def _save_registry(reg: dict) -> None:
    KEY_REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
    KEY_REGISTRY_PATH.write_text(json.dumps(reg, indent=2, ensure_ascii=False), encoding="utf-8")


def _audit_key(action: str, key_id: str, **extra) -> None:
    try:
        KEY_AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        entry = {"ts": time.time(), "action": action, "key_id": key_id, **extra}
        with open(KEY_AUDIT_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass


def create_api_key(name: str, scopes=None, expires_at: float | None = None,
                   ip_allowlist: list[str] | None = None, created_by: str = "admin") -> dict:
    """Create a registry API key. Returns the plaintext secret ONCE."""
    name = (name or "unnamed").strip()[:64]
    valid_scopes = set(scopes or DEFAULT_SCOPES) & set(SCOPES)
    if not valid_scopes:
        valid_scopes = set(DEFAULT_SCOPES)
    if ip_allowlist:
        ip_allowlist = [ip.strip() for ip in ip_allowlist if ip.strip()]
    key_id = "key_" + secrets.token_hex(4)
    secret = secrets.token_urlsafe(24)
    with _key_lock:
        reg = _registry()
        reg[key_id] = {
            "name": name,
            "key_hash": hashlib.sha256(secret.encode()).hexdigest(),
            "scopes": sorted(valid_scopes),
            "expires_at": float(expires_at) if expires_at else None,
            "ip_allowlist": ip_allowlist or [],
            "created_at": time.time(),
            "created_by": created_by,
        }
        _save_registry(reg)
    _audit_key("create", key_id, name=name, scopes=sorted(valid_scopes), created_by=created_by)
    return {"status": "ok", "key_id": key_id, "api_key": secret, "name": name,
            "scopes": sorted(valid_scopes), "expires_at": reg[key_id]["expires_at"]}


def revoke_api_key(key_id: str, revoked_by: str = "admin") -> dict:
    key_id = key_id.strip()
    with _key_lock:
        reg = _registry()
        existed = reg.pop(key_id, None)
        if existed:
            _save_registry(reg)
    if existed:
        _audit_key("revoke", key_id, revoked_by=revoked_by)
    return {"status": "ok", "key_id": key_id, "existed": bool(existed)}


def list_api_keys() -> dict:
    reg = _registry()
    now = time.time()
    keys = []
    for key_id, k in reg.items():
        expires = k.get("expires_at")
        keys.append({
            "key_id": key_id,
            "name": k.get("name", ""),
            "scopes": k.get("scopes", []),
            "expires_at": expires,
            "expired": bool(expires and expires <= now),
            "ip_allowlist": k.get("ip_allowlist", []),
            "created_at": k.get("created_at"),
            "created_by": k.get("created_by", ""),
        })
    return {
        "env_keys": sorted(config.API_KEYS),
        "env_auth_enabled": config.AUTH_ENABLED,
        "registry_count": len(keys),
        "keys": keys,
    }


def _hash_key(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def _lookup_registry(secret: str) -> dict | None:
    """Return registry entry matching the secret hash, else None."""
    digest = _hash_key(secret)
    with _key_lock:
        for key_id, k in _registry().items():
            if k.get("key_hash") == digest:
                return {**k, "key_id": key_id}
    return None


def _key_is_valid(secret: str) -> dict | None:
    """Resolve a presented secret to its effective capabilities.

    Env keys get full admin scope. Registry keys must not be expired and must
    originate from an allowed IP. Returns {key_id, scopes, source, ip} or None.
    """
    if secret in config.API_KEYS:
        return {"key_id": None, "name": "env", "scopes": {"admin"},
                "source": "env", "ip": _client_ip()}
    entry = _lookup_registry(secret)
    if not entry:
        return None
    expires = entry.get("expires_at")
    if expires and float(expires) <= time.time():
        return None
    allowlist = entry.get("ip_allowlist") or []
    if allowlist and _client_ip() not in allowlist:
        return None
    return {"key_id": entry.get("key_id"), "name": entry.get("name", ""),
            "scopes": set(entry.get("scopes") or []),
            "source": "registry", "ip": _client_ip()}

# --------------------------------------------------------------------------
# Rate limiting (in-memory sliding window, thread-safe)
# --------------------------------------------------------------------------

_rate_lock = threading.Lock()
_rate_minute: dict[str, deque] = {}
_rate_hour: dict[str, deque] = {}

# Bounded-memory guard: idle (empty) buckets are swept away periodically and
# when the combined IP table grows large — prevents unbounded growth on a
# long-lived public server with many unique IPs.
SWEEP_THRESHOLD = 100_000
SWEEP_INTERVAL = 300.0  # seconds between opportunistic sweeps
_last_sweep_at = [0.0]  # boxed monotonic clock of last sweep


def _client_ip() -> str:
    # NEVER trust X-Forwarded-For here: a client can send arbitrary values and
    # bypass rate limiting / the IP allowlist. If the API runs behind a trusted
    # reverse proxy, app.py installs werkzeug's ProxyFix (when
    # PHISHGUARD_TRUST_PROXY is set), which validates the proxy chain and
    # rewrites request.remote_addr to the real client address. Without ProxyFix
    # we use the TCP peer address, which is not spoofable at this layer.
    return request.remote_addr or "unknown"


def _prune(history: deque, window_seconds: float, now: float) -> None:
    while history and history[0] <= now - window_seconds:
        history.popleft()


def _record_or_limit(store: dict, ip: str, limit: int, window_seconds: float) -> bool:
    """Prune, evict empty IP buckets, then record the request.

    Returns True if the IP is over *limit* (no request recorded). An IP whose
    window fully expires is removed from *store* so idle IPs do not accumulate
    forever.
    """
    now = time.monotonic()
    bucket = store.get(ip)
    if bucket is None:
        store[ip] = deque([now])
        return False
    _prune(bucket, window_seconds, now)
    if not bucket:
        del store[ip]
        store[ip] = deque([now])
        return False
    if len(bucket) >= limit:
        return True
    bucket.append(now)
    return False


def _maybe_sweep() -> None:
    """Drop empty buckets periodically / when the IP table grows large.

    Must hold ``_rate_lock``. A no-op at most once every ``SWEEP_INTERVAL``
    seconds unless the table exceeds ``SWEEP_THRESHOLD``, so the per-request
    cost is negligible while idle IPs are evicted in bounded time.
    """
    now = time.monotonic()
    if (len(_rate_minute) + len(_rate_hour)) < SWEEP_THRESHOLD and \
            (now - _last_sweep_at[0]) < SWEEP_INTERVAL:
        return
    _last_sweep_at[0] = now
    for store in (_rate_minute, _rate_hour):
        for ip in list(store.keys()):
            bucket = store.get(ip)
            if bucket is not None:
                _prune(bucket, 3600, now)
                if not bucket:
                    del store[ip]


def rate_limit(minute: int | None = None, hour: int | None = None):
    """
    Decorator enforcing per-IP rate limits (sliding window).

    Args:
        minute: max requests per minute (None = skip).
        hour: max requests per hour (None = skip).
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            ip = _client_ip()
            with _rate_lock:
                if minute and _record_or_limit(_rate_minute, ip, minute, 60):
                    return jsonify({
                        "error": "Rate limit exceeded. Please slow down and try again later.",
                        "limit": minute,
                    }), 429
                if hour and _record_or_limit(_rate_hour, ip, hour, 3600):
                    return jsonify({
                        "error": "Hourly rate limit exceeded. Please try again later.",
                        "limit": hour,
                    }), 429
                _maybe_sweep()
            return fn(*args, **kwargs)
        return wrapper
    return decorator


# --------------------------------------------------------------------------
# API key authentication
# --------------------------------------------------------------------------

API_KEY_HEADER = "X-API-Key"


def require_api_key(fn=None, *, scope: str | None = None):
    """Decorator requiring a valid ``X-API-Key`` header (no-op when auth disabled).

    When ``scope`` is given, the key must be an env admin key OR include the
    requested scope in its registry scopes.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not config.AUTH_ENABLED and not _registry():
                return func(*args, **kwargs)
            key = request.headers.get(API_KEY_HEADER, "")
            effective = _key_is_valid(key)
            if effective is None:
                return jsonify({"error": "Missing or invalid API key."}), 401
            if scope and "admin" not in effective["scopes"] and scope not in effective["scopes"]:
                return jsonify({"error": f"This API key lacks the '{scope}' scope."}), 403
            request.api_key = effective
            return func(*args, **kwargs)
        return wrapper
    return decorator if fn is None else decorator(fn)


# --------------------------------------------------------------------------
# Payload size guard
# --------------------------------------------------------------------------

def reject_oversized_html(fn):
    """
    Decorator that rejects HTML payloads larger than the configured cap.

    The route function must place the incoming HTML under the key ``html`` in
    its JSON body; this decorator reads it and short-circuits with 413.
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        body = request.get_json(silent=True) or {}
        html = body.get("html")
        if html is not None:
            if not isinstance(html, str):
                return jsonify({"error": "'html' must be a string."}), 400
            if len(html.encode("utf-8")) > config.MAX_HTML_BYTES:
                return jsonify({
                    "error": f"HTML too large (max {config.MAX_HTML_BYTES} bytes).",
                }), 413
        return fn(*args, **kwargs)
    return wrapper
