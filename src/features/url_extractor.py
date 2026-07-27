"""
URL feature extractor for phishing detection.

Extracts 12 structural features from a URL string:
    url_length, domain_length, path_length, entropy, special_char_ratio,
    digit_ratio, subdomain_count, has_https, has_ip_address,
    suspicious_keywords, url_depth, tld_in_path
"""

import re
import math
from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = [
    "login", "secure", "verify", "account", "update",
    "banking", "confirm", "signin", "password", "reset",
    "authenticate", "paypal", "webscr", "free", "bonus",
]


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    for c in set(text):
        p = text.count(c) / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def has_ip_address(domain: str) -> bool:
    ip_pattern = re.compile(
        r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
    )
    return 1 if ip_pattern.match(domain) else 0


def extract_url_features(url: str) -> dict:
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.hostname or ""
    path = parsed.path or ""
    full_url = url.strip()

    # Remove port from domain for subdomain counting
    domain_clean = domain.split(":")[0] if ":" in domain else domain
    domain_parts = domain_clean.split(".")

    # Basic lengths
    url_length = len(full_url)
    domain_length = len(domain_clean)
    path_length = len(path)

    # Entropy
    entropy = shannon_entropy(full_url)

    # Character ratios
    special_chars = sum(1 for c in full_url if c in "@-_?.&=%+#~!")
    digit_chars = sum(1 for c in full_url if c.isdigit())
    total_chars = max(len(full_url), 1)
    special_char_ratio = round(special_chars / total_chars, 4)
    digit_ratio = round(digit_chars / total_chars, 4)

    # Subdomain count
    # For a domain like "mail.google.com", subdomains = ["mail", "google", "com"]
    # subdomain_count = len(parts) - 2 (subtract SLD and TLD)
    # Handle co.uk, com.au etc.
    if len(domain_parts) >= 2:
        subdomain_count = max(0, len(domain_parts) - 2)
    else:
        subdomain_count = 0

    # Protocol
    has_https = 1 if parsed.scheme == "https" else 0

    # IP address check
    ip_flag = has_ip_address(domain_clean)

    # Suspicious keywords in full URL (lowercased)
    url_lower = full_url.lower()
    keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)

    # URL depth — number of path segments
    path_segments = [s for s in path.split("/") if s]
    url_depth = len(path_segments)

    # TLD in path — check if any known TLD appears in the path
    common_tlds = {
        "com", "org", "net", "gov", "edu", "mil", "io", "co", "uk",
        "au", "de", "jp", "fr", "ca", "ru", "cn", "in", "br", "pl",
        "html", "php", "asp", "jsp",
    }
    path_lower = path.lower()
    tld_in_path_flag = 1 if any(f".{tld}" in path_lower for tld in common_tlds) else 0

    return {
        "url_length": url_length,
        "domain_length": domain_length,
        "path_length": path_length,
        "entropy": entropy,
        "special_char_ratio": special_char_ratio,
        "digit_ratio": digit_ratio,
        "subdomain_count": subdomain_count,
        "has_https": has_https,
        "has_ip_address": ip_flag,
        "suspicious_keywords": keyword_count,
        "url_depth": url_depth,
        "tld_in_path": tld_in_path_flag,
    }


SUSPICIOUS_TLDS = {
    '.xyz', '.top', '.club', '.loan', '.click',
    '.gq', '.ml', '.tk', '.cf', '.ga', '.pw',
    '.work', '.date', '.faith', '.racing', '.win',
    '.bid', '.trade', '.webcam', '.science', '.review',
    '.country', '.kim', '.men', '.download', '.party',
}

URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
    'is.gd', 'buff.ly', 'shorturl.at', 'tiny.cc', 'tr.im',
    'cli.gs', 'yfrog.com', 'migre.me', 'ff.im', 'ur1.ca',
    'v.gd', 'twitthis.com', 'r.im', 'snipurl.com',
    'cuturl.com', 'tiny.pl', 'bc.vc', 'su.pr',
}


def check_suspicious_tld(url: str) -> int:
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            return 1
    return 0


def is_url_shortener(url: str) -> bool:
    parsed = urlparse(url)
    domain = (parsed.netloc or parsed.hostname or "").lower()
    domain = domain.split(":")[0]
    return domain in URL_SHORTENERS


def extract_url_features_batch(urls: list[str]) -> list[dict]:
    return [extract_url_features(u) for u in urls]


if __name__ == "__main__":
    test_urls = [
        "https://www.google.com/search?q=hello",
        "http://login.secure-bank.com/verify/account/update",
        "http://192.168.1.1/login.php",
        "https://mail.google.com/mail/u/0/#inbox",
        "http://bit.ly/3abcde",
    ]
    for url in test_urls:
        feats = extract_url_features(url)
        print(f"URL: {url}")
        for k, v in feats.items():
            print(f"  {k}: {v}")
        print()
