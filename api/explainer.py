"""Natural language explanation generator for phishing detection.

Generates human-readable verdict summaries, key findings, and risk narratives
from multi-engine analysis results. Template-based (no LLM API required),
with structure compatible for future LLM augmentation.
"""

import re
from urllib.parse import urlparse

RISK_LABELS = {
    "phishing": {"label": "Phishing", "icon": "\u26A0", "color": "red"},
    "suspicious": {"label": "Suspicious", "icon": "\u26A0", "color": "yellow"},
    "safe": {"label": "Safe", "icon": "\u2713", "color": "green"},
}

FINDING_TEMPLATES = {
    "brand_impersonation": "Brand impersonation detected: {brands}",
    "suspicious_tld": "Suspicious TLD extension (.{tld}) is disproportionately used by phishing campaigns",
    "no_dns": "Domain has no DNS records — typical of freshly registered phishing domains",
    "young_domain": "Domain registered only {days} days ago — a common phishing characteristic",
    "old_domain": "Domain established {years} years — reduces likelihood of malicious intent",
    "low_ttl": "Low TTL ({ttl}s) indicates CDN or load-balanced infrastructure",
    "ssl_valid": "Valid HTTPS certificate from trusted issuer — positive signal",
    "ssl_invalid": "No valid SSL certificate — unusual for legitimate services",
    "privacy_protected": "WHOIS privacy protection enabled — common but can hide malicious registrants",
    "high_entropy": "High URL entropy ({entropy:.1f}) suggests random/obfuscated string pattern",
    "ip_url": "URL uses raw IP address instead of domain — legitimate services rarely do this",
    "long_url": "Unusually long URL ({length} chars) — often used to hide malicious intent",
    "many_subdomains": "{count} subdomain levels make the true domain harder to identify",
    "phishing_keywords": "URL contains {count} security-related keywords ({keywords}) commonly used in phishing",
    "shortener": "URL shortener service can redirect to arbitrary destinations",
    "cross_domain_redirect": "URL redirects to a different domain ({dest}) — verify destination legitimacy",
    "redirect_to_reputable": "URL redirects to {dest}, a known reputable domain — destination reputation noted, but the redirect itself still warrants caution",
    "no_html": "No HTML content analyzed — behavioral signals unavailable",
    "reputation_known": "Domain scanned {n} times before (avg score: {avg:.0f}/100) — {trend}",
    "subdomain_warning": "Subdomain \"{sub}\" on registered domain \"{reg}\" — parent domain {parent_verdict}",
    "reputable_asn": "Hosted on {asn} (reputable provider) — lowers risk",
    "risky_asn": "Hosted on {desc} — common among phishing campaigns",
    "engine_consensus": "{n} of {total} analysis engines agree: {verdict}",
    "engine_split": "Engines disagree: {ai}, {dns}, {url}, {brand}",
    "known_threat": "URL/hostname is listed in the known-threat database (source: {source}) — previously reported as phishing",
}


def _get_domain(url: str) -> str:
    try:
        return (urlparse(url).netloc or urlparse(url).hostname or "").lower().split(":")[0]
    except Exception:
        return ""


def _get_tld(url: str) -> str:
    parts = _get_domain(url).split(".")
    return parts[-1] if len(parts) >= 2 else ""


def _get_path(url: str) -> str:
    try:
        return urlparse(url).path
    except Exception:
        return ""


def generate_explanation(result: dict) -> dict:
    """Generate natural language explanation from analysis result."""
    url = result.get("url", "")
    domain = _get_domain(url)
    tld = _get_tld(url)
    path = _get_path(url)
    whitelist_status = result.get("whitelist_status", {}) or {}
    aggregate_score = result.get("aggregate_score", 0)
    final_verdict = "safe"
    if aggregate_score >= 60:
        final_verdict = "phishing"
    elif aggregate_score >= 30:
        final_verdict = "suspicious"
    engines = result.get("engine_results", {}).get("engines", {})
    brand = result.get("brand_analysis", {})
    dns = result.get("dns_whois", {})
    ssl = result.get("ssl_redirect", {})
    features = result.get("features", {})
    sub_info = result.get("subdomain_info")
    reputation = result.get("reputation", {})

    findings = []
    score_contributors = []

    # Analyze engine results
    engine_verdicts = {}
    for name, data in engines.items():
        engine_verdicts[name] = data.get("verdict", "safe")
    phishing_count = sum(1 for v in engine_verdicts.values() if v == "phishing")
    susp_count = sum(1 for v in engine_verdicts.values() if v == "suspicious")
    safe_count = sum(1 for v in engine_verdicts.values() if v == "safe")
    total_engines = len(engine_verdicts)

    if phishing_count >= 3:
        findings.append(FINDING_TEMPLATES["engine_consensus"].format(n=phishing_count, total=total_engines, verdict="phishing"))
    elif safe_count == total_engines:
        findings.append(f"All {total_engines} analysis engines consider this URL safe")
    elif phishing_count > 0 and safe_count > 0:
        ai_v = engine_verdicts.get("ai_model", "n/a")
        dns_v = engine_verdicts.get("dns_infrastructure", "n/a")
        url_v = engine_verdicts.get("url_pattern", "n/a")
        br_v = engine_verdicts.get("brand", "n/a")
        findings.append(FINDING_TEMPLATES["engine_split"].format(ai=ai_v, dns=dns_v, url=url_v, brand=br_v))

    # Brand impersonation
    has_brand = brand.get("has_brand_impersonation", False)
    if has_brand:
        brands = brand.get("brands_detected", [])
        findings.append(FINDING_TEMPLATES["brand_impersonation"].format(
            brands=", ".join(brands[:3])
        ))
        score_contributors.append(f"Brand impersonation ({', '.join(brands[:2])})")

    # Known-threat database hit (strong signal)
    threat_match = result.get("threat_match")
    if threat_match and threat_match.get("matched"):
        findings.append(FINDING_TEMPLATES["known_threat"].format(
            source=threat_match.get("source") or threat_match.get("layer", "unknown")
        ))
        score_contributors.append("Known-threat database match")

    # Subdomain note
    if sub_info:
        parent_verdict = "safe" if safe_count == total_engines else "may be compromised or used for phishing"
        findings.append(FINDING_TEMPLATES["subdomain_warning"].format(
            sub=sub_info["subdomain"], reg=sub_info["registered_domain"],
            parent_verdict=parent_verdict
        ))

    # DNS/WHOIS signals
    if dns:
        a_count = dns.get("a_record_count", -1)
        mx_count = dns.get("mx_record_count", -1)
        domain_age = dns.get("domain_age_days", -1)
        ttl_val = dns.get("ttl", -1)
        privacy = dns.get("is_privacy_protected", -1)
        asn_desc = dns.get("asn_description", "")

        if a_count <= 0 and mx_count <= 0:
            if domain_age <= 0:
                findings.append(FINDING_TEMPLATES["no_dns"])
            else:
                pass  # subdomain without records, handled by subdomain_warning
        if domain_age > 0:
            if domain_age < 30:
                findings.append(FINDING_TEMPLATES["young_domain"].format(days=domain_age))
                score_contributors.append(f"Domain age ({domain_age} days)")
            elif domain_age >= 365:
                findings.append(FINDING_TEMPLATES["old_domain"].format(years=domain_age // 365))
        if ttl_val >= 0 and ttl_val < 300 and a_count >= 2:
            findings.append(FINDING_TEMPLATES["low_ttl"].format(ttl=ttl_val))
        if privacy == 1:
            findings.append(FINDING_TEMPLATES["privacy_protected"])
        if asn_desc:
            from api.engines import REPUTABLE_ASNS, RISKY_ASN_KEYWORDS
            asn = str(dns.get("asn", ""))
            desc_lower = asn_desc.lower()
            if asn in REPUTABLE_ASNS:
                findings.append(FINDING_TEMPLATES["reputable_asn"].format(asn=asn_desc.split("/")[0][:40]))
            elif any(kw in desc_lower for kw in RISKY_ASN_KEYWORDS):
                findings.append(FINDING_TEMPLATES["risky_asn"].format(desc=asn_desc.split("/")[0][:40]))

    # SSL signals
    if ssl:
        ssl_valid = ssl.get("ssl_valid", -1)
        if ssl_valid == 1:
            findings.append(FINDING_TEMPLATES["ssl_valid"])
        else:
            findings.append(FINDING_TEMPLATES["ssl_invalid"])
            score_contributors.append("Missing SSL certificate")

    # URL features
    if features:
        entropy = features.get("entropy", 0)
        if entropy > 4.5:
            findings.append(FINDING_TEMPLATES["high_entropy"].format(entropy=entropy))
            score_contributors.append("High URL entropy")
        has_ip = features.get("has_ip_address", 0)
        if has_ip:
            findings.append(FINDING_TEMPLATES["ip_url"])
            score_contributors.append("IP address in URL")
        url_len = features.get("url_length", 0)
        if url_len > 100:
            findings.append(FINDING_TEMPLATES["long_url"].format(length=url_len))
        sub_count = features.get("subdomain_count", 0)
        if sub_count > 2:
            findings.append(FINDING_TEMPLATES["many_subdomains"].format(count=sub_count))
            score_contributors.append(f"{sub_count} subdomain levels")
        keywords = features.get("suspicious_keywords", 0)
        if keywords > 0:
            kw_list = ["login", "verify", "secure", "account", "update", "confirm", "password", "banking", "payment"]
            found = [kw for kw in kw_list if kw in url.lower() or kw in path.lower()]
            findings.append(FINDING_TEMPLATES["phishing_keywords"].format(
                count=int(keywords), keywords=", ".join(found[:4])
            ))
            score_contributors.append(f"{int(keywords)} phishing keyword(s)")
        is_short = result.get("is_shortener", False)
        if is_short:
            findings.append(FINDING_TEMPLATES["shortener"])

    # Suspicious TLD
    susp_tld = result.get("suspicious_tld", 0)
    if susp_tld:
        findings.append(FINDING_TEMPLATES["suspicious_tld"].format(tld=tld))
        score_contributors.append(f"Suspicious TLD (.{tld})")

    # Redirect analysis
    cr = ssl.get("cross_domain_redirect", -1) if ssl else -1
    expanded_url = result.get("expanded_url") or result.get("effective_url") or ""
    if cr == 1 and expanded_url:
        from api.whitelist import get_domain_status as _wl_status
        from api.utils import get_registered_domain as _get_rd
        final_domain = _get_rd(expanded_url)
        if final_domain and _wl_status(expanded_url, final_domain).get("known_reputable_domain"):
            findings.append(FINDING_TEMPLATES["redirect_to_reputable"].format(dest=final_domain))
        else:
            findings.append(FINDING_TEMPLATES["cross_domain_redirect"].format(dest=expanded_url[:60]))
            score_contributors.append("Cross-domain redirect")

    # Reputation / whitelist signal (never a verdict on its own)
    if whitelist_status.get("known_reputable_domain"):
        if whitelist_status.get("subdomain_trusted"):
            source = whitelist_status.get("source", "unknown")
            findings.append(
                f"Registered domain is a known reputable domain (source: {source}) — "
                "full analysis still performed; reputation only lowers the risk estimate."
            )
        else:
            findings.append(
                "Registered domain is reputable, but this subdomain is user content "
                "(e.g. <user>.github.io) — reputation does NOT extend here."
            )

    # HTML analysis
    html_provided = result.get("html_provided", False)
    if not html_provided:
        findings.append(FINDING_TEMPLATES["no_html"])

    # Reputation
    if reputation and reputation.get("scans", 0) > 0:
        avg = reputation.get("avg_score", 0)
        n = reputation.get("scans", 0)
        trend = "risk score consistent with this scan" if abs(avg - aggregate_score) < 15 else "previous scans show different risk levels"
        findings.append(FINDING_TEMPLATES["reputation_known"].format(n=n, avg=avg, trend=trend))

    # Build verdict summary: focus on WHY, not WHAT (gauge already shows the verdict)
    if final_verdict == "phishing":
        reasons = score_contributors[:3]
        if reasons:
            head = reasons[0][0].upper() + reasons[0][1:]
            summary = f"{head} triggered the highest alert"
            if len(reasons) > 1:
                summary += f", compounded by {reasons[1].lower()}"
            summary += "."
        else:
            summary = "Multiple analysis engines converged on a phishing classification — no single dominant factor identified."
    elif final_verdict == "suspicious":
        reasons = score_contributors[:2]
        if reasons:
            head = reasons[0][0].upper() + reasons[0][1:]
            summary = f"{head} raises concern"
            if len(reasons) > 1:
                summary += f", together with {reasons[1].lower()}"
            summary += "."
        else:
            summary = f"{'Some signals'} warrant verification before interaction — score: {aggregate_score:.0f}/100."
    else:
        if total_engines > 0:
            summary = f"All {total_engines} analysis engines returned benign — no phishing indicators detected."
        else:
            summary = "No phishing indicators detected."

    # Recommendations
    if final_verdict == "phishing":
        recs = [
            "Do not enter any personal information on this page",
            "Report the URL to your security team or email provider",
            "If this arrived via email, mark the sender as phishing",
        ]
    elif final_verdict == "suspicious":
        recs = [
            "Verify the URL manually by typing the official domain directly",
            "Avoid entering credentials unless you are certain of the destination",
            "If unsure, contact the organization through official channels",
        ]
    else:
        recs = [
            "No immediate action required",
        ]
    if not html_provided and final_verdict != "safe":
        recs.append("Upload the HTML content for deeper DOM-based behavioral analysis")
    if sub_info and final_verdict != "safe":
        recs.append(f"Verify that {sub_info['registered_domain']} is authorized to host the service you expect")

    return {
        "verdict_summary": summary,
        "key_findings": findings[:6],
        "risk_factors": score_contributors[:4],
        "recommendations": recs[:4],
    }
