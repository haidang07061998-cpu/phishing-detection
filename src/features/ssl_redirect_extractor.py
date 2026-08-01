"""
SSL certificate and HTTP redirect feature extractor for phishing detection.

Extracts 5 features per URL:
    ssl_valid, ssl_age_days, ssl_issuer_trusted,
    redirect_count, cross_domain_redirect

Uses requests with 5-second timeout per URL.
Failed requests return -1 for all features.
"""

import ssl
import socket
import datetime
import sys
from pathlib import Path
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.backends import default_backend

if str(Path(__file__).resolve().parents[2]) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.security.url_safety import safe_get, validate_url


TRUSTED_CA_KEYWORDS = [
    "let's encrypt", "digicert", "comodo", "globalsign",
    "geotrust", "godaddy", "thawte", "verisign", "sectigo",
    "entrust", "rapidssl", "identrust", "buypass",
    "google trust services", "gts", "google",
    "amazon", "ssl corporation", "cloudflare",
]


def get_certificate_info(hostname: str, port: int = 443, timeout: int = 5) -> dict:
    result = {
        "ssl_valid": -1,
        "ssl_age_days": -1,
        "ssl_issuer_trusted": -1,
    }
    try:
        check = validate_url(f"https://{hostname}:{port}/")
        if not check["valid"]:
            return result

        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(cert_der, default_backend())

                result["ssl_valid"] = 1

                not_before = cert.not_valid_before_utc
                not_after = cert.not_valid_after_utc
                now = datetime.datetime.now(datetime.timezone.utc)

                if not_before and now >= not_before and now <= not_after:
                    result["ssl_valid"] = 1
                else:
                    result["ssl_valid"] = 0

                if not_before:
                    age = (now - not_before).days
                    result["ssl_age_days"] = max(age, 0)

                issuer = cert.issuer
                issuer_str = ""
                for attr in issuer:
                    if attr.oid._name == "organizationName":
                        issuer_str = attr.value.lower()
                        break
                if not issuer_str:
                    issuer_str = str(issuer).lower()

                result["ssl_issuer_trusted"] = 1 if any(
                    kw in issuer_str for kw in TRUSTED_CA_KEYWORDS
                ) else 0
    except Exception:
        pass
    return result


def check_redirects(url: str, timeout: int = 5, max_redirects: int = 5) -> dict:
    result = {
        "redirect_count": -1,
        "cross_domain_redirect": -1,
        "final_url": "",
    }
    try:
        original_domain = urlparse(url).hostname or ""
        info = safe_get(url, max_redirects=max_redirects, timeout=timeout)
        if not info["ok"]:
            return result

        result["redirect_count"] = info["redirect_count"]

        final_domain = urlparse(info["final_url"]).hostname or ""
        if original_domain and final_domain:
            result["cross_domain_redirect"] = 1 if original_domain != final_domain else 0
        else:
            result["cross_domain_redirect"] = -1

        if result["redirect_count"] > 0:
            result["final_url"] = info["final_url"]
    except Exception:
        pass
    return result


def extract_ssl_redirect_features(url: str) -> dict:
    """
    Extract SSL certificate and redirect behaviour features for a URL.

    Args:
        url: Full URL string.

    Returns:
        dict with 5 keys: ssl_valid, ssl_age_days, ssl_issuer_trusted,
                           redirect_count, cross_domain_redirect.
    """
    hostname = urlparse(url).hostname or ""
    features = {"ssl_valid": -1, "ssl_age_days": -1, "ssl_issuer_trusted": -1,
                "redirect_count": -1, "cross_domain_redirect": -1, "final_url": ""}

    if url.startswith("https://") and hostname:
        cert_info = get_certificate_info(hostname)
        features.update(cert_info)

    redirect_info = check_redirects(url)
    features.update(redirect_info)

    return features


def extract_ssl_redirect_batch(urls: list[str], show_progress: bool = True) -> list[dict]:
    from tqdm import tqdm
    results = []
    iterator = tqdm(urls, desc="SSL/Redirect") if show_progress else urls
    for url in iterator:
        results.append(extract_ssl_redirect_features(url))
    return results


if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "http://bit.ly/3abcde",
    ]
    for url in test_urls:
        feats = extract_ssl_redirect_features(url)
        print(f"URL: {url}")
        for k, v in feats.items():
            print(f"  {k}: {v}")
        print()
