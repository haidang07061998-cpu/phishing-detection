"""Multi-engine analysis system for phishing detection.

Simulates VirusTotal-style multi-engine architecture with 4 virtual engines:
1. AI Model Engine — Gated Fusion deep learning model
2. DNS Infrastructure Engine — DNS records, SSL, domain age
3. URL Pattern Engine — URL features, keywords, TLD
4. Brand Impersonation Engine — brand name detection

Each engine returns {score: 0-100, verdict: str, details: str}
Final result via weighted voting + temperature-scaled calibration.
"""

import re
from urllib.parse import urlparse
from src.features.url_extractor import check_suspicious_tld, is_url_shortener

REPUTABLE_ASNS = {
    "15169",  # Google
    "16509",  # Amazon
    "14618",  # Amazon (Virginia)
    "20547",  # Amazon (Ireland)
    "8075",   # Microsoft
    "13335",  # Cloudflare
    "32934",  # Facebook/Meta
    "54113",  # Fastly
    "20940",  # Akamai
    "16625",  # Akamai
    "21342",  # Akamai
    "45102",  # Alibaba Cloud
    "36492",  # Apple
    "6185",   # Apple
    "714",    # Apple
    "55002",  # Apple
    "2906",   # Netflix
    "3",      # MIT
    "17378",  # VNPT (Vietnam)
    "7552",   # Viettel (Vietnam)
    "18403",  # FPT Telecom (Vietnam)
    "38731",  # Vietcombank / VN banking
}

RISKY_ASN_KEYWORDS = [
    "hosting", "vps", "vpn", "proxy", "anonymous",
    "datacenter", "colo", "dedicated",
]


PHISHING_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update",
    "confirm", "authenticate", "password", "credential", "banking",
    "payment", "wallet", "transaction", "security", "alert",
    "suspended", "restricted", "unusual", "activity", "blocked",
]


def _get_domain(url: str) -> str:
    try:
        return (urlparse(url).netloc or urlparse(url).hostname or "").lower().split(":")[0]
    except Exception:
        return ""


def _get_tld(url: str) -> str:
    domain = _get_domain(url)
    parts = domain.split(".")
    if len(parts) < 2:
        return ""
    return "." + parts[-1]


def ai_engine(model_prediction: float, tab_features: dict, feature_importance: dict,
              dns: dict, ssl: dict) -> dict:
    base_score = round(model_prediction * 100, 1)
    url_has_ip = tab_features.get("has_ip_address", 0) if tab_features else 0
    keywords = tab_features.get("suspicious_keywords", 0) if tab_features else 0
    ssl_trusted = ssl.get("ssl_issuer_trusted", -1) if ssl else -1
    a_count = dns.get("a_record_count", -1) if dns else -1
    domain_age = dns.get("domain_age_days", -1) if dns else -1
    details = []
    if base_score >= 50:
        details.append("AI model detected phishing patterns")
    if keywords > 0:
        details.append(f"{int(keywords)} suspicious keyword(s) found")
    if url_has_ip:
        details.append("IP address used in URL")
    if ssl_trusted == 1:
        details.append("SSL certificate from trusted CA")
    if a_count >= 2:
        details.append("Multiple A records (CDN/redundancy)")
    if domain_age >= 365:
        details.append(f"Domain established ({domain_age // 365}y)")
    if base_score < 30:
        details.append("URL appears benign")
    score = base_score
    if base_score >= 60:
        verdict = "phishing"
    elif base_score >= 30:
        verdict = "suspicious"
    else:
        verdict = "safe"
    return {"score": score, "verdict": verdict, "details": "; ".join(details[:6])}


def dns_infra_engine(dns: dict, ssl: dict) -> dict:
    score = 0
    details = []
    a_count = dns.get("a_record_count", -1) if dns else -1
    mx_count = dns.get("mx_record_count", -1) if dns else -1
    ns_count = dns.get("ns_record_count", -1) if dns else -1
    ttl = dns.get("ttl", -1) if dns else -1
    domain_age = dns.get("domain_age_days", -1) if dns else -1
    privacy = dns.get("is_privacy_protected", -1) if dns else -1
    ssl_valid = ssl.get("ssl_valid", -1) if ssl else -1
    ssl_issuer = ssl.get("ssl_issuer_trusted", -1) if ssl else -1
    if a_count <= 0 and mx_count <= 0 and ns_count <= 0:
        if domain_age > 0:
            score += 25
            details.append("No DNS on subdomain (parent domain exists)")
        else:
            score += 50
            details.append("No DNS records found")
    else:
        if a_count >= 2:
            details.append(f"{a_count} A records (redundant infra)")
        elif a_count == 1:
            score += 10
            details.append("Single A record")
        else:
            score += 20
            details.append("No A records")
        if mx_count >= 1:
            details.append(f"{mx_count} MX records (email configured)")
        else:
            score += 15
            details.append("No MX records")
        if ns_count >= 2:
            details.append(f"{ns_count} NS records")
        else:
            score += 10
            details.append("Few nameservers")
    if domain_age > 0:
        if domain_age < 30:
            score += 30
            details.append("Domain registered <30 days ago")
        elif domain_age < 365:
            score += 10
            details.append("Domain <1 year old")
        else:
            details.append(f"Established {domain_age // 365}y domain")
    else:
        score += 20
        details.append("Unknown domain age")
    if ssl_valid == 1:
        if ssl_issuer == 1:
            details.append("SSL from trusted issuer")
        else:
            score += 15
            details.append("SSL issuer not in trusted list")
    else:
        score += 40
        details.append("No valid SSL certificate")
    # ASN-based scoring
    asn = str(dns.get("asn", "")) if dns else ""
    asn_desc = dns.get("asn_description", "").lower() if dns else ""
    asn_country = dns.get("asn_country", "") if dns else ""
    if asn and asn in REPUTABLE_ASNS:
        score -= 15
        if asn == "15169":
            details.append("Google ASN — strong reputation")
        elif asn == "13335":
            details.append("Cloudflare ASN — CDN trusted")
        else:
            details.append("Known reputable ASN")
    elif asn_desc:
        if any(kw in asn_desc for kw in ("google", "cloudflare", "facebook", "amazon", "aws", "microsoft", "azure")):
            score -= 12
            details.append(f"Reputable provider: {asn_desc.split('/')[0][:30]}")
        elif any(kw in asn_desc for kw in RISKY_ASN_KEYWORDS):
            score += 10
            details.append(f"Hosting/VPN ASN: {asn_desc.split('/')[0][:30]}")
    elif not asn:
        score += 5
        details.append("No ASN information")
    score = min(score, 99)
    if score >= 60:
        verdict = "phishing"
    elif score >= 30:
        verdict = "suspicious"
    else:
        verdict = "safe"
    return {"score": score, "verdict": verdict, "details": "; ".join(details[:6])}


def url_pattern_engine(url: str, tab_features: dict) -> dict:
    score = 0
    details = []
    domain = _get_domain(url)
    parsed = urlparse(url)
    path = parsed.path or ""
    susp_tld = check_suspicious_tld(url)
    is_short = is_url_shortener(url)
    if susp_tld:
        score += 40
        details.append("Suspicious TLD detected")
    if is_short:
        score += 15
        details.append("URL shortener service")
    features = tab_features or {}
    url_len = features.get("url_length", len(url))
    if url_len > 100:
        score += 15
        details.append(f"Long URL ({url_len} chars)")
    elif url_len > 75:
        score += 5
    domain_len = features.get("domain_length", len(domain))
    if domain_len > 30:
        score += 15
        details.append(f"Long domain ({domain_len} chars)")
    entropy = features.get("entropy", 0)
    if entropy > 4.5:
        score += 15
        details.append(f"High entropy ({entropy:.1f})")
    has_ip = features.get("has_ip_address", 0)
    if has_ip:
        score += 40
        details.append("Raw IP in URL")
    subdomains = features.get("subdomain_count", 0)
    if subdomains > 2:
        score += 15
        details.append(f"Many subdomains ({subdomains})")
    keywords = features.get("suspicious_keywords", 0)
    if keywords > 0:
        score += 20 * min(keywords, 3)
        details.append(f"{int(keywords)} phishing keyword(s)")
    tld_in_path = features.get("tld_in_path", 0)
    if tld_in_path:
        score += 20
        details.append("TLD embedded in path")
    has_https = features.get("has_https", 0)
    if not has_https:
        score += 10
        details.append("No HTTPS")
    if re.search(r'@', url):
        score += 30
        details.append("'@' redirect trick")
    if re.search(r'--', domain):
        score += 10
        details.append("Hyphenated domain")
    score = min(score, 99)
    if score >= 60:
        verdict = "phishing"
    elif score >= 30:
        verdict = "suspicious"
    else:
        verdict = "safe"
    return {"score": score, "verdict": verdict, "details": "; ".join(details[:6])}


def brand_engine(url: str, text: str, brand_info: dict) -> dict:
    score = 0
    details = []
    if brand_info and brand_info.get("has_brand_impersonation"):
        score = min(int(brand_info.get("risk_score", 0.5) * 100), 99)
        brands = brand_info.get("brands_detected", [])
        if brands:
            details.append(f"Impersonates: {', '.join(brands[:3])}")
        techniques = brand_info.get("techniques", [])
        if techniques:
            details.append(f"Technique: {', '.join(techniques[:2])}")
        contexts = brand_info.get("contexts", [])
        if contexts:
            details.append(contexts[0][:80])
    else:
        keyword_hits = [kw for kw in PHISHING_KEYWORDS if kw in url.lower() or (text and kw in text.lower())]
        if keyword_hits:
            score = min(len(keyword_hits) * 10, 50)
            details.append(f"Phishing keywords: {', '.join(keyword_hits[:6])}")
    if score >= 60:
        verdict = "phishing"
    elif score >= 30:
        verdict = "suspicious"
    else:
        verdict = "safe"
    return {"score": score, "verdict": verdict, "details": "; ".join(details[:3]) or "No brand signals"}


ENGINE_WEIGHTS = {
    "ai_model": 4,
    "dns_infrastructure": 2,
    "url_pattern": 2,
    "brand": 1,
}


def combine_engines(results: dict) -> dict:
    total_weight = sum(ENGINE_WEIGHTS.values())
    weighted_sum = 0
    engine_details = {}
    for name, result in results.items():
        w = ENGINE_WEIGHTS.get(name, 1)
        weighted_sum += result["score"] * w
        engine_details[name] = {
            "score": result["score"],
            "verdict": result["verdict"],
            "details": result["details"],
            "weight": w,
        }
    final_score = round(weighted_sum / total_weight, 1)
    if final_score >= 60:
        final_verdict = "phishing"
    elif final_score >= 30:
        final_verdict = "suspicious"
    else:
        final_verdict = "safe"
    return {
        "final_score": final_score,
        "final_verdict": final_verdict,
        "engines": engine_details,
    }
