"""
Brand detection module for phishing detection.

Detects brand impersonation in URLs and page content via:
1. Known brand keywords in domain name (typosquatting)
2. Brand + security keywords in domain (combosquatting)
3. Homograph attack detection (Unicode homoglyphs)
4. Brand names in page title/content
"""

import re
import unicodedata
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

COMBOSQUAT_KEYWORDS = {
    "secure", "login", "signin", "verify", "account", "update",
    "support", "help", "service", "security", "confirm", "reset",
    "authenticate", "validation", "billing", "payment", "checkout",
    "recover", "unlock", "restrict", "alert", "notice",
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

HOMOGLYPH_MAP = {
    'a': 'а',  # Cyrillic а
    'e': 'е',  # Cyrillic е
    'o': 'о',  # Cyrillic о
    'c': 'с',  # Cyrillic с
    'p': 'р',  # Cyrillic р
    'x': 'х',  # Cyrillic х
    'y': 'у',  # Cyrillic у
    'i': 'і',  # Cyrillic і
    'k': 'к',  # Cyrillic к
    'm': 'м',  # Cyrillic м
    't': 'т',  # Cyrillic т
    'b': 'ь',  # Cyrillic ь
}


def _normalize_homograph(text: str) -> str:
    """Convert homoglyph characters to their ASCII equivalents."""
    result = []
    for ch in text.lower():
        try:
            name = unicodedata.name(ch, "")
            # If it looks like a Latin letter but is actually Unicode, map it
            if 'LATIN' not in name and 'CYRILLIC' in name:
                for ascii_ch, cyrillic_ch in HOMOGLYPH_MAP.items():
                    if ch == cyrillic_ch:
                        result.append(ascii_ch)
                        break
                else:
                    result.append(ch)
            else:
                result.append(ch)
        except ValueError:
            result.append(ch)
    return "".join(result)


def _levenshtein_similarity(s1: str, s2: str) -> float:
    """Compute similarity ratio between two strings using Levenshtein distance."""
    if not s1 or not s2:
        return 0.0
    if len(s1) < len(s2):
        s1, s2 = s2, s1
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            cost = 0 if c1 == c2 else 1
            curr.append(min(curr[j] + 1, prev[j + 1] + 1, prev[j] + cost))
        prev = curr
    max_len = max(len(s1), len(s2))
    return 1.0 - prev[-1] / max_len if max_len > 0 else 0.0


def _generate_context(match: dict, url: str) -> str:
    """Generate a human-readable context message for a brand match."""
    brand = match["brand"].title()
    location = match["location"]
    confidence = match["confidence"]
    variant = match.get("variant", "")

    if location == "domain":
        if variant == brand.lower():
            if confidence >= 0.95:
                return (f"Exact brand name '{brand}' found in domain. "
                        f"The page pretends to be from {brand} but is hosted on an unauthorized domain.")
            return (f"Brand name '{brand}' detected in domain. "
                    f"This domain is not the official {brand} website.")
        elif confidence >= 0.85:
            return (f"Typosquatting detected: '{variant}' is a visual variation of '{brand}'. "
                    f"This technique tricks users into thinking they are visiting the real {brand} site.")
        return (f"Suspicious domain pattern: '{variant}' resembles '{brand}'. "
                f"Possible impersonation attempt.")
    elif location == "path":
        return (f"Brand reference '{brand}' found in URL path. "
                f"Legitimate sites rarely include third-party brand names in their paths.")
    elif location == "text":
        return (f"Brand name '{brand}' appears in the page content. "
                f"Combined with the suspicious URL, this suggests a phishing page impersonating {brand}.")
    return ""


def _is_combosquatting(domain: str, brand: str) -> bool:
    """Detect combosquatting: brand + security keyword (e.g., paypal-security.com)."""
    domain_lower = domain.lower()
    brand_lower = brand.lower()
    if brand_lower not in domain_lower:
        return False
    for kw in COMBOSQUAT_KEYWORDS:
        if kw in domain_lower:
            return True
    return False


def _is_legitimate(domain, brand):
    legit = LEGITIMATE_DOMAINS.get(brand, set())
    return domain in legit


def detect_brands_in_url(url: str) -> list[dict]:
    parsed = urlparse(url)
    domain = (parsed.netloc or parsed.hostname or "").lower()
    path = (parsed.path or "").lower()
    domain_parts = domain.split(".")

    # Normalize homograph attacks
    domain_normalized = _normalize_homograph(domain)

    matches = []
    seen_brands = set()

    for brand, variants in BRAND_DATABASE.items():
        if _is_legitimate(domain, brand):
            continue

        # Check homograph attack
        if domain_normalized != domain:
            brand_normalized = _normalize_homograph(brand)
            for part in domain_parts:
                part_normalized = _normalize_homograph(part)
                if brand_normalized in part_normalized and part not in BRAND_TLDS:
                    if brand not in seen_brands:
                        matches.append({
                            "brand": brand,
                            "variant": part,
                            "location": "domain",
                            "value": part,
                            "confidence": 0.9,
                            "technique": "homograph",
                            "context": _generate_context({
                                "brand": brand, "variant": part,
                                "location": "domain", "confidence": 0.9
                            }, url),
                        })
                        seen_brands.add(brand)
                    break
            if brand in seen_brands:
                continue

        # Check combosquatting
        if _is_combosquatting(domain, brand):
            matches.append({
                "brand": brand,
                "variant": f"{brand}-*",
                "location": "domain",
                "value": domain,
                "confidence": 0.85,
                "technique": "combosquatting",
                "context": (f"Combosquatting detected: domain contains both '{brand.title()}' "
                           f"and a security-related keyword. This is a common phishing technique "
                           f"to create URLs that look official."),
            })
            seen_brands.add(brand)
            continue

        # Check typosquatting via Levenshtein similarity
        for part in domain_parts:
            for v in variants:
                if v in part and part not in BRAND_TLDS:
                    if brand not in seen_brands:
                        sim = _levenshtein_similarity(v, brand)
                        matches.append({
                            "brand": brand,
                            "variant": v,
                            "location": "domain",
                            "value": part,
                            "confidence": 0.95 if v == brand else (0.85 if sim > 0.7 else 0.75),
                            "technique": "typosquatting" if v != brand else "exact_match",
                            "context": _generate_context({
                                "brand": brand, "variant": v,
                                "location": "domain", "confidence": 0.95 if v == brand else 0.85
                            }, url),
                        })
                        seen_brands.add(brand)
                    break
            if brand in seen_brands:
                break

    # Check path-based brand references
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
                    "technique": "path_reference",
                    "context": _generate_context({
                        "brand": brand, "variant": v,
                        "location": "path", "confidence": 0.7
                    }, url),
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
                    "technique": "text_match",
                    "context": _generate_context({
                        "brand": brand, "variant": v,
                        "location": "text", "confidence": 0.65
                    }, ""),
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
            "contexts": [],
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

    contexts = [m.get("context", "") for m in all_matches if m.get("context")]
    techniques = [m.get("technique", "unknown") for m in all_matches]

    return {
        "has_brand_impersonation": has_domain_match or has_path_match,
        "brands_detected": sorted(unique_brands),
        "max_confidence": round(max_conf, 2),
        "risk_score": round(min(risk, 1.0), 4),
        "matches": all_matches,
        "contexts": contexts,
        "techniques": list(set(techniques)),
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