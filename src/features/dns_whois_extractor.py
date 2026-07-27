"""
DNS and WHOIS feature extractor for phishing detection.

Extracts 8 features per domain:
    a_record_count, mx_record_count, ns_record_count, ttl,
    domain_age_days, registrar, is_privacy_protected, country

Results are cached by domain in data/cache/whois_cache.json to
avoid redundant network queries and rate-limiting.
"""

import json
import datetime
from pathlib import Path
from urllib.parse import urlparse

import dns.resolver
import dns.reversename
import whois

CACHE_PATH = Path(__file__).resolve().parents[2] / "data" / "cache" / "whois_cache.json"


def _load_cache() -> dict:
    if CACHE_PATH.exists():
        return json.loads(CACHE_PATH.read_text(encoding="utf-8"))
    return {}


def _save_cache(cache: dict) -> None:
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    CACHE_PATH.write_text(json.dumps(cache, indent=2, default=str), encoding="utf-8")


def _extract_domain(url: str) -> str:
    parsed = urlparse(url)
    hostname = parsed.hostname or parsed.netloc or url
    hostname = hostname.split(":")[0]
    return hostname


def query_dns(domain: str) -> dict:
    result = {
        "a_record_count": -1,
        "mx_record_count": -1,
        "ns_record_count": -1,
        "ttl": -1,
        "resolved_ips": [],
        "ptr_record": "",
    }
    try:
        answers = dns.resolver.resolve(domain, "A", lifetime=5)
        result["a_record_count"] = len(answers)
        ips = [str(r) for r in answers]
        result["resolved_ips"] = ips
        if answers:
            result["ttl"] = answers.rrset.ttl if answers.rrset else -1
        if ips:
            try:
                rev = dns.reversename.from_address(ips[0])
                ptr = dns.resolver.resolve(rev, "PTR", lifetime=5)
                if ptr:
                    result["ptr_record"] = str(ptr[0]).rstrip(".")
            except Exception:
                pass
    except Exception:
        pass
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=5)
        result["mx_record_count"] = len(answers)
    except Exception:
        pass
    try:
        answers = dns.resolver.resolve(domain, "NS", lifetime=5)
        result["ns_record_count"] = len(answers)
    except Exception:
        pass
    return result


def query_whois(domain: str) -> dict:
    result = {
        "domain_age_days": -1,
        "registrar": "",
        "is_privacy_protected": -1,
        "country": "",
    }
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            age = (datetime.datetime.now(datetime.timezone.utc) - creation).days
            result["domain_age_days"] = max(age, 0)

        reg = w.registrar
        if reg:
            result["registrar"] = str(reg) if isinstance(reg, str) else str(reg[0])

        result["is_privacy_protected"] = 1 if w.emails and "whoisprivacy" in str(w.emails).lower() else 0

        country = w.country
        if country:
            result["country"] = str(country) if isinstance(country, str) else str(country[0])
    except Exception:
        pass
    return result


def extract_dns_whois_features(url: str, use_cache: bool = True) -> dict:
    """
    Extract DNS and WHOIS features for the domain of the given URL.

    Args:
        url: Full URL string.
        use_cache: If True, cache results by domain to avoid repeated queries.

    Returns:
        dict with up to 8 keys: a_record_count, mx_record_count, ns_record_count,
        ttl, domain_age_days, registrar, is_privacy_protected, country.
    """
    domain = _extract_domain(url)

    if use_cache:
        cache = _load_cache()
        if domain in cache:
            return cache[domain]

    dns_result = query_dns(domain)
    whois_result = query_whois(domain)

    combined = {**dns_result, **whois_result}

    if use_cache:
        cache[domain] = combined
        _save_cache(cache)

    return combined


def extract_dns_whois_batch(urls: list[str], use_cache: bool = True, show_progress: bool = True) -> list[dict]:
    from tqdm import tqdm
    results = []
    iterator = tqdm(urls, desc="DNS/WHOIS") if show_progress else urls
    for url in iterator:
        results.append(extract_dns_whois_features(url, use_cache=use_cache))
    return results


if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "https://github.com",
    ]
    for url in test_urls:
        feats = extract_dns_whois_features(url, use_cache=False)
        print(f"URL: {url}")
        for k, v in feats.items():
            print(f"  {k}: {v}")
        print()
