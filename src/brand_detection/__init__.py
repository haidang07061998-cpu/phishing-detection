"""
Brand detection module for phishing detection.

Detects brand impersonation in URLs and page content via:
1. Known brand keywords in domain name
2. Typosquatted variants in URL
3. Brand names in page title/content
"""

import re
from urllib.parse import urlparse

BRAND_DATABASE = {
    "paypal": ["paypal", "paypai", "paypa1", "payp4l"],
    "google": ["google", "googie", "go0gle", "g00gle", "goog1e", "googl"],
    "apple": ["apple", "app1e", "appie", "ipp1e", "appl"],
    "microsoft": ["microsoft", "mlcrosoft", "micr0s0ft"],
    "facebook": ["facebook", "faceb00k", "faceboook", "faceb0ok"],
    "amazon": ["amazon", "amaz0n", "amazn", "arnazon", "ama zon"],
    "netflix": ["netflix", "netf1ix", "n3tflix", "net flix"],
    "linkedin": ["linkedin", "linked1n", "l1nkedin"],
    "dropbox": ["dropbox", "dr0pbox"],
    "instagram": ["instagram", "instagr4m", "1nstagram"],
    "twitter": ["twitter", "tw1tter", "twit er"],
    "whatsapp": ["whatsapp", "whats4pp"],
    "dhl": ["dhl", "deutsche-post"],
    "fedex": ["fedex", "f3dex"],
    "hsbc": ["hsbc", "h5bc"],
    "bankofamerica": ["bankofamerica", "bank of america"],
    "wellsfargo": ["wellsfargo", "wells fargo"],
    "visa": ["visa", "vlSa", "v1sa"],
    "mastercard": ["mastercard", "master card", "mast3rcard"],
    "ebay": ["ebay", "eb4y", "3bay"],
    "adobe": ["adobe", "ad0be"],
}

BRAND_TLDS = {"com", "org", "net", "co", "io", "app", "dev", "info", "biz", "online", "site", "xyz"}
LEGITIMATE_DOMAINS = {
    "paypal": {"paypal.com", "www.paypal.com"},
    "google": {"google.com", "www.google.com", "accounts.google.com", "mail.google.com"},
    "apple": {"apple.com", "www.apple.com"},
    "microsoft": {"microsoft.com", "www.microsoft.com"},
    "facebook": {"facebook.com", "www.facebook.com"},
    "amazon": {"amazon.com", "www.amazon.com"},
    "netflix": {"netflix.com", "www.netflix.com"},
    "linkedin": {"linkedin.com", "www.linkedin.com"},
    "dropbox": {"dropbox.com", "www.dropbox.com"},
    "instagram": {"instagram.com", "www.instagram.com"},
    "twitter": {"twitter.com", "www.twitter.com"},
    "whatsapp": {"whatsapp.com", "www.whatsapp.com"},
    "dhl": {"dhl.com", "www.dhl.com"},
    "fedex": {"fedex.com", "www.fedex.com"},
    "hsbc": {"hsbc.com", "www.hsbc.com"},
    "bankofamerica": {"bankofamerica.com", "www.bankofamerica.com"},
    "wellsfargo": {"wellsfargo.com", "www.wellsfargo.com"},
    "visa": {"visa.com", "www.visa.com"},
    "mastercard": {"mastercard.com", "www.mastercard.com"},
    "ebay": {"ebay.com", "www.ebay.com"},
    "adobe": {"adobe.com", "www.adobe.com"},
}


def _is_legitimate(domain, brand):
    legit = LEGITIMATE_DOMAINS.get(brand, set())
    return domain in legit

def detect_brands_in_url(url: str) -> list[dict]:
    parsed = urlparse(url)
    domain = (parsed.netloc or parsed.hostname or "").lower()
    path = (parsed.path or "").lower()
    domain_parts = domain.split(".")

    matches = []
    seen_brands = set()

    for brand, variants in BRAND_DATABASE.items():
        if _is_legitimate(domain, brand):
            continue
        for part in domain_parts:
            for v in variants:
                if v in part and part not in BRAND_TLDS:
                    if brand not in seen_brands:
                        matches.append({
                            "brand": brand,
                            "variant": v,
                            "location": "domain",
                            "value": part,
                            "confidence": 0.95 if v == brand else 0.85,
                        })
                        seen_brands.add(brand)
                    break
            if brand in seen_brands:
                break

    for brand, variants in BRAND_DATABASE.items():
        if brand in seen_brands:
            continue
        for v in variants:
            if v in path and len(v) >= 3:
                matches.append({
                    "brand": brand,
                    "variant": v,
                    "location": "path",
                    "value": v,
                    "confidence": 0.7,
                })
                break

    return matches


def detect_brands_in_text(text: str) -> list[dict]:
    if not text:
        return []
    text_lower = text.lower()
    matches = []
    seen = set()
    for brand, variants in BRAND_DATABASE.items():
        if brand in seen:
            continue
        for v in variants:
            pattern = r'\b' + re.escape(v) + r'\b'
            if re.search(pattern, text_lower):
                matches.append({
                    "brand": brand,
                    "variant": v,
                    "location": "text",
                    "confidence": 0.65,
                })
                seen.add(brand)
                break
    return matches


def get_brand_risk_score(url: str, page_text: str = "") -> dict:
    url_matches = detect_brands_in_url(url)
    text_matches = detect_brands_in_text(page_text) if page_text else []
    all_matches = url_matches + text_matches
    unique_brands = set(m["brand"] for m in all_matches)

    if not unique_brands:
        return {
            "has_brand_impersonation": False,
            "brands_detected": [],
            "max_confidence": 0.0,
            "risk_score": 0.0,
        }

    max_conf = max(m["confidence"] for m in all_matches)
    has_domain_match = any(m["location"] == "domain" and m["confidence"] >= 0.8 for m in url_matches)
    has_path_match = any(m["location"] == "path" for m in url_matches)

    risk = 0.0
    if has_domain_match:
        risk = 0.6 + 0.3 * max_conf
    elif has_path_match:
        risk = 0.4 + 0.2 * max_conf
    elif text_matches:
        risk = 0.3 + 0.15 * max_conf

    return {
        "has_brand_impersonation": has_domain_match or has_path_match,
        "brands_detected": sorted(unique_brands),
        "max_confidence": round(max_conf, 2),
        "risk_score": round(min(risk, 1.0), 4),
        "matches": all_matches,
    }


if __name__ == "__main__":
    test_urls = [
        "https://www.paypal.com/webscr",
        "http://secure-paypa1.com/login/verify",
        "https://www.google.com/search",
        "http://faceb00k-login.com/reset",
        "https://app1e-id-verify.com/account",
        "http://bit.ly/3abcde",
        "https://github.com",
    ]
    for url in test_urls:
        result = get_brand_risk_score(url)
        print(f"URL: {url}")
        print(f"  Brands: {result['brands_detected']}")
        print(f"  Impersonation: {result['has_brand_impersonation']}")
        print(f"  Risk score: {result['risk_score']:.4f}")
        print()