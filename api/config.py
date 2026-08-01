"""
Central configuration for the Flask API, read from environment variables.

All production-hardening knobs live here so they can be set at deploy time
without touching code:

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
"""

import os

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
