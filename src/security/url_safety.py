"""
URL safety layer — SSRF / internal-network scan protection.

All outbound network operations triggered by a user-supplied URL must pass
through this module first. It blocks requests to private/reserved networks,
validates the real resolved IPs (DNS), checks every redirect hop, and caps
response size so the API cannot be abused to probe internal infrastructure.

Design decisions:
- IPv4/IPv6 handled uniformly through ``ipaddress``.
- DNS resolution is done with a bounded lifetime so a dead/malicious DNS
  server cannot hang the request forever.
- ``safe_get`` follows redirects manually so each hop is re-validated before
  a new request is issued (a redirect into 10.0.0.0/8 is rejected, not
  followed).
- Response bodies are streamed and truncated at ``MAX_RESPONSE_BYTES``.

NOTE: this is a defense-in-depth layer, NOT a complete network sandbox.
For a hard guarantee against DNS-rebinding / exotic evasion the outbound
fetcher should additionally run in a dedicated container/VM (no route to the
internal network). See docker/ for the recommended deployment.
"""

import ipaddress
import socket
from urllib.parse import urljoin, urlparse

import requests

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

MAX_REDIRECTS = 5
MAX_RESPONSE_BYTES = 2 * 1024 * 1024  # 2 MiB
DNS_TIMEOUT = 5
REQUEST_TIMEOUT = 8

# Reserved/internal hostnames that must never be resolved from user input.
BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "broadcasthost",
    "gateway",
    "local",
}

# Suffixes that indicate an internal/reserved namespace.
BLOCKED_SUFFIXES = (
    ".local",
    ".internal",
    ".lan",
    ".intranet",
    ".home.arpa",
    ".corp",
    ".localhost",
    ".test",
    ".invalid",
)

ALLOWED_SCHEMES = ("http", "https")

# --------------------------------------------------------------------------
# IP classification
# --------------------------------------------------------------------------


def is_blocked_ip(ip: str) -> bool:
    """Return True if *ip* (IPv4 or IPv6 string) is non-global/reserved."""
    try:
        addr = ipaddress.ip_address(ip.split("%")[0].strip("[]"))
    except ValueError:
        # Unparseable -> treat as blocked (never dial an address we can't vet).
        return True
    if addr.is_multicast:
        return True
    if addr.is_loopback:
        return True
    if addr.is_link_local:
        return True
    if addr.is_private:
        return True
    if addr.is_reserved:
        return True
    if addr.is_unspecified:
        return True
    if getattr(addr, "is_test_net", False):
        return True
    if not addr.is_global:
        return True
    # 100.64.0.0/10 (CGNAT) is not flagged private by ipaddress in all versions.
    if addr.version == 4:
        n = int(addr)
        if int(ipaddress.ip_address("100.64.0.0")) <= n <= int(ipaddress.ip_address("100.127.255.255")):
            return True
    return False


def _hostname_is_internal(hostname: str) -> bool:
    h = hostname.lower().rstrip(".")
    if h in BLOCKED_HOSTNAMES:
        return True
    for suffix in BLOCKED_SUFFIXES:
        if h.endswith(suffix) or h == suffix.lstrip("."):
            return True
    return False


def _is_raw_ip(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname.split("%")[0].strip("[]"))
        return True
    except ValueError:
        return False


def _resolve_ips(hostname: str) -> list[str]:
    """Resolve A/AAAA records for *hostname* with a bounded timeout."""
    import dns.resolver

    ips: list[str] = []
    for rtype in ("A", "AAAA"):
        try:
            answers = dns.resolver.resolve(hostname, rtype, lifetime=DNS_TIMEOUT)
            ips.extend(str(r) for r in answers)
        except Exception:
            continue
    return ips


# --------------------------------------------------------------------------
# URL validation
# --------------------------------------------------------------------------


def validate_url(url: str) -> dict:
    """
    Validate that *url* targets a globally routable host.

    Returns:
        {
            "valid": bool,
            "hostname": str,
            "resolved_ips": list[str],
            "reason": str,          # human-readable block reason
        }

    Performs: scheme check -> hostname deny-list -> raw-IP check ->
    DNS resolution -> every resolved IP must be global.
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return _invalid(url, "malformed URL")

    scheme = (parsed.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        return _invalid(url, f"scheme '{scheme}' is not allowed")

    hostname = parsed.hostname
    if not hostname:
        return _invalid(url, "missing hostname")

    hostname = hostname.lower().rstrip(".")
    if _hostname_is_internal(hostname):
        return _invalid(url, f"internal/reserved hostname '{hostname}'")

    if _is_raw_ip(hostname):
        if is_blocked_ip(hostname):
            return _invalid(url, f"IP address '{hostname}' is reserved/private")
        return {
            "valid": True,
            "hostname": hostname,
            "resolved_ips": [hostname],
            "reason": "",
        }

    ips = _resolve_ips(hostname)
    if not ips:
        # DNS did not answer; treat as invalid so we never dial an unknown IP.
        return _invalid(url, f"could not resolve '{hostname}'")

    blocked = [ip for ip in ips if is_blocked_ip(ip)]
    if blocked:
        return _invalid(url, f"'{hostname}' resolves to non-global IP(s): {blocked}")

    return {"valid": True, "hostname": hostname, "resolved_ips": ips, "reason": ""}


def _invalid(url: str, reason: str) -> dict:
    return {"valid": False, "hostname": "", "resolved_ips": [], "reason": reason}


class UnsafeURLError(Exception):
    """Raised when a URL fails the SSRF/URL-safety policy."""


def ensure_safe_url(url: str) -> dict:
    """Like :func:`validate_url` but raises :class:`UnsafeURLError` on failure."""
    result = validate_url(url)
    if not result["valid"]:
        raise UnsafeURLError(result["reason"])
    return result


# --------------------------------------------------------------------------
# Safe outbound HTTP
# --------------------------------------------------------------------------


def safe_get(
    url: str,
    max_redirects: int = MAX_REDIRECTS,
    max_response_bytes: int = MAX_RESPONSE_BYTES,
    timeout: float = REQUEST_TIMEOUT,
    headers: dict | None = None,
) -> dict:
    """
    Perform a redirect-checked, size-capped HTTP GET.

    Returns:
        {
            "ok": bool,
            "status_code": int | None,
            "final_url": str,
            "redirect_count": int,
            "cross_domain_redirect": bool | None,
            "content": bytes,           # truncated at max_response_bytes
            "truncated": bool,
            "error": str,
        }
    """
    current = url
    history: list[str] = []
    seen: set[str] = set()
    session = requests.Session()
    session.max_redirects = max_redirects
    req_headers = {
        "User-Agent": "Mozilla/5.0 (compatible; PhishGuard/1.0)",
        **(headers or {}),
    }

    try:
        for _ in range(max_redirects + 1):
            check = validate_url(current)
            if not check["valid"]:
                return _safe_get_error(
                    url, current, history, f"blocked: {check['reason']}"
                )
            if current in seen:
                return _safe_get_error(
                    url, current, history, "redirect loop detected"
                )
            seen.add(current)

            try:
                resp = session.get(
                    current,
                    timeout=timeout,
                    allow_redirects=False,
                    headers=req_headers,
                    stream=True,
                )
            except requests.exceptions.TooManyRedirects:
                return _safe_get_error(
                    url, current, history, f"too many redirects (> {max_redirects})"
                )
            except requests.exceptions.RequestException as exc:
                return _safe_get_error(url, current, history, str(exc))

            try:
                if resp.is_redirect and "location" in resp.headers:
                    location = resp.headers["location"]
                    resp.close()
                    history.append(current)
                    next_url = urljoin(current, location)
                    if next_url == current:
                        return _safe_get_error(url, current, history, "redirect loop detected")
                    current = next_url
                    continue

                # Final response: stream body up to the size cap.
                chunks: list[bytes] = []
                total = 0
                truncated = False
                try:
                    for chunk in resp.iter_content(chunk_size=65536):
                        if not chunk:
                            continue
                        total += len(chunk)
                        if total > max_response_bytes:
                            truncated = True
                            break
                        chunks.append(chunk)
                finally:
                    resp.close()

                original_host = urlparse(url).hostname or ""
                final_host = urlparse(resp.url).hostname or ""
                cross = (
                    original_host != final_host
                    if original_host and final_host
                    else None
                )

                return {
                    "ok": True,
                    "status_code": resp.status_code,
                    "final_url": resp.url,
                    "redirect_count": len(history),
                    "cross_domain_redirect": cross,
                    "content": b"".join(chunks),
                    "truncated": truncated,
                    "error": "",
                }
            except Exception:
                return _safe_get_error(url, current, history, "request failed")

        return _safe_get_error(
            url, current, history, f"too many redirects (> {max_redirects})"
        )
    finally:
        session.close()


def _safe_get_error(original_url, current_url, history, error: str) -> dict:
    original_host = urlparse(original_url).hostname or ""
    final_host = urlparse(current_url).hostname or ""
    cross = original_host != final_host if original_host and final_host else None
    return {
        "ok": False,
        "status_code": None,
        "final_url": current_url,
        "redirect_count": len(history),
        "cross_domain_redirect": cross,
        "content": b"",
        "truncated": False,
        "error": error,
    }
