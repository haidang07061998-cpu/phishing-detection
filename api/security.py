"""
Security helpers for the Flask API: API-key auth and per-IP rate limiting.

Both are implemented as decorators so individual routes can opt in:

    @app.route("/predict", methods=["POST"])
    @rate_limit(minute=30, hour=300)
    @require_api_key
    def predict(): ...

Ordering matters: ``@rate_limit`` must wrap ``@require_api_key`` so the
rate limiter runs first and unauthenticated floods are throttled before the
auth check. When auth is disabled (no ``API_KEYS`` configured) the decorators
are no-ops, preserving dev mode behaviour.
"""

import threading
import time
from collections import defaultdict, deque
from functools import wraps

from flask import jsonify, request

from api import config

# --------------------------------------------------------------------------
# Rate limiting (in-memory sliding window, thread-safe)
# --------------------------------------------------------------------------

_rate_lock = threading.Lock()
_rate_minute: dict[str, deque] = defaultdict(deque)
_rate_hour: dict[str, deque] = defaultdict(deque)


def _client_ip() -> str:
    # Honour reverse-proxy header but never trust it blindly: fall back to
    # remote_addr when absent.
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[0].strip() or request.remote_addr or "unknown"
    return request.remote_addr or "unknown"


def _prune(history: deque, window_seconds: float, now: float) -> None:
    while history and history[0] <= now - window_seconds:
        history.popleft()


def _is_rate_limited(bucket: deque, limit: int, window_seconds: float) -> bool:
    now = time.monotonic()
    with _rate_lock:
        _prune(bucket, window_seconds, now)
        if len(bucket) < limit:
            bucket.append(now)
            return False
        return True


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
            if minute and _is_rate_limited(_rate_minute[ip], minute, 60):
                return jsonify({
                    "error": "Rate limit exceeded. Please slow down and try again later.",
                    "limit": minute,
                }), 429
            if hour and _is_rate_limited(_rate_hour[ip], hour, 3600):
                return jsonify({
                    "error": "Hourly rate limit exceeded. Please try again later.",
                    "limit": hour,
                }), 429
            return fn(*args, **kwargs)
        return wrapper
    return decorator


# --------------------------------------------------------------------------
# API key authentication
# --------------------------------------------------------------------------

API_KEY_HEADER = "X-API-Key"


def require_api_key(fn):
    """Decorator requiring a valid ``X-API-Key`` header (no-op when auth disabled)."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not config.AUTH_ENABLED:
            return fn(*args, **kwargs)
        key = request.headers.get(API_KEY_HEADER, "")
        if key not in config.API_KEYS:
            return jsonify({"error": "Missing or invalid API key."}), 401
        return fn(*args, **kwargs)
    return wrapper


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
