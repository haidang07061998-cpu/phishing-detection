"""
Central configuration for the Flask API, read from environment variables.

All production-hardening knobs live here so they can be set at deploy time
without touching code:

- ``PHISHGUARD_ENV``            ``development`` (default) or ``production``
- ``PHISHGUARD_API_KEYS``      comma-separated API keys; empty = auth disabled (dev)
- ``PHISHGUARD_ALLOWED_ORIGINS`` comma-separated CORS origins
- ``PHISHGUARD_MAX_JSON_BYTES``  max request body size
- ``PHISHGUARD_MAX_HTML_BYTES``  max client-provided HTML size
- ``PHISHGUARD_RATE_MIN``        max requests per IP per minute
- ``PHISHGUARD_RATE_HOUR``       max requests per IP per hour
- ``PHISHGUARD_WEBHOOK_ALLOWLIST`` comma-separated webhook host allowlist
- ``PHISHGUARD_WEBHOOK_SECRET``  HMAC signing secret for webhook dispatch
- ``PHISHGUARD_WEBHOOK_TIMEOUT`` webhook dispatch timeout (seconds)
- ``PHISHGUARD_WEBHOOK_RETRIES`` max retry attempts for webhook dispatch

Inference / scoring knobs:
- ``PHISHGUARD_TEMPERATURE``      temperature scaling factor (default 2.8, or data/models/temperature.json)
- ``PHISHGUARD_ENSEMBLE_FOLDS``   number of fold checkpoints to average (default 1; 5 = full ensemble)
- ``PHISHGUARD_COMPUTE_IMPORTANCE`` compute per-request feature importance via backward pass (default True)
- ``PHISHGUARD_EXTRACT_CACHE_TTL`` TTL seconds for DNS/SSL extraction cache (default 300; 0 = off)
- ``PHISHGUARD_BATCH_WORKERS``    threads for /predict/batch (default 1 = sequential)
"""

import os

# --------------------------------------------------------------------------
# Environment
# --------------------------------------------------------------------------

ENV = os.environ.get("PHISHGUARD_ENV", "development").strip().lower()
IS_PRODUCTION = ENV == "production"


def ensure_production_auth(registry_count: int = 0) -> None:
    """Fail fast when running in production without any API keys configured.

    An unauthenticated API in production silently exposes every scan, the
    blocklist and history to the public internet. Refuse to start instead.

    ``registry_count`` is the number of keys already present in the runtime
    key registry (``data/api_keys.json``); either env keys or a pre-seeded
    registry satisfies the requirement.
    """
    if not IS_PRODUCTION:
        return
    if not API_KEYS and registry_count == 0:
        raise RuntimeError(
            "API keys are required in production. Set PHISHGUARD_API_KEYS "
            "(server-side env keys) or pre-seed the key registry "
            "(data/api_keys.json) before starting the API."
        )


# --------------------------------------------------------------------------
# Authentication
# --------------------------------------------------------------------------

def _csv(name: str, default: str = "") -> list[str]:
    raw = os.environ.get(name, default)
    return [part.strip() for part in raw.split(",") if part.strip()]

API_KEYS = set(_csv("PHISHGUARD_API_KEYS"))
AUTH_ENABLED = bool(API_KEYS)

# --------------------------------------------------------------------------
# CORS
# --------------------------------------------------------------------------

ALLOWED_ORIGINS = _csv(
    "PHISHGUARD_ALLOWED_ORIGINS",
    "http://localhost:3000,http://127.0.0.1:3000",
)

# --------------------------------------------------------------------------
# Payload limits
# --------------------------------------------------------------------------

MAX_JSON_BYTES = int(os.environ.get("PHISHGUARD_MAX_JSON_BYTES", str(2 * 1024 * 1024)))   # 2 MiB
MAX_HTML_BYTES = int(os.environ.get("PHISHGUARD_MAX_HTML_BYTES", str(2 * 1024 * 1024)))   # 2 MiB

# --------------------------------------------------------------------------
# Rate limiting
# --------------------------------------------------------------------------

RATE_MIN = int(os.environ.get("PHISHGUARD_RATE_MIN", "60"))
RATE_HOUR = int(os.environ.get("PHISHGUARD_RATE_HOUR", "600"))

# --------------------------------------------------------------------------
# Webhook
# --------------------------------------------------------------------------

WEBHOOK_ALLOWLIST = set(_csv("PHISHGUARD_WEBHOOK_ALLOWLIST"))
WEBHOOK_SECRET = os.environ.get("PHISHGUARD_WEBHOOK_SECRET", "")
WEBHOOK_TIMEOUT = float(os.environ.get("PHISHGUARD_WEBHOOK_TIMEOUT", "10"))
WEBHOOK_MAX_RETRIES = int(os.environ.get("PHISHGUARD_WEBHOOK_RETRIES", "3"))

# --------------------------------------------------------------------------
# Inference / scoring
# --------------------------------------------------------------------------

TEMPERATURE = float(os.environ.get("PHISHGUARD_TEMPERATURE", "2.8"))
ENSEMBLE_FOLDS = int(os.environ.get("PHISHGUARD_ENSEMBLE_FOLDS", "1"))
COMPUTE_IMPORTANCE = os.environ.get("PHISHGUARD_COMPUTE_IMPORTANCE", "1").strip().lower() in ("1", "true", "yes", "on")
EXTRACT_CACHE_TTL = float(os.environ.get("PHISHGUARD_EXTRACT_CACHE_TTL", "300"))
BATCH_WORKERS = int(os.environ.get("PHISHGUARD_BATCH_WORKERS", "1"))

# --------------------------------------------------------------------------
# Known-threat database (blocklist)
# --------------------------------------------------------------------------

# Optional community feed URL (PhishTank CSV / OpenPhish / plain list). Empty
# disables the feed and keeps the system fully self-contained.
THREAT_FEED_URL = os.environ.get("PHISHGUARD_THREAT_FEED_URL", "")
THREAT_FEED_REFRESH_HOURS = float(os.environ.get("PHISHGUARD_THREAT_FEED_REFRESH_HOURS", "24"))
