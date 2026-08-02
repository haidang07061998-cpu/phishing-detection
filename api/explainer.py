"""Natural language explanation generator for phishing detection.

Generates human-readable verdict summaries, key findings, and risk narratives
from multi-engine analysis results. Template-based (no LLM API required),
with structure compatible for future LLM augmentation.

Supports two languages via the ``lang`` parameter: ``"en"`` (default) and
``"vi"``. Non-technical data (URLs, model names, engine names, codes) is never
translated — only the generated narrative is localized.
"""

import re
from urllib.parse import urlparse

RISK_LABELS = {
    "phishing": {"label": "Phishing", "icon": "\u26A0", "color": "red"},
    "suspicious": {"label": "Suspicious", "icon": "\u26A0", "color": "yellow"},
    "safe": {"label": "Safe", "icon": "\u2713", "color": "green"},
}

# ---------------------------------------------------------------------------
# Bilingual templates. {placeholders} are filled at runtime; values like
# domain names, brand names, scores, ASNs and TLDs stay in their original form.
# ---------------------------------------------------------------------------
LANG = {
    "en": {
        # Findings
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
        "all_engines_safe": "All {n} analysis engines consider this URL safe",
        "whitelist_subdomain_trusted": "Registered domain is a known reputable domain (source: {source}) — full analysis still performed; reputation only lowers the risk estimate.",
        "whitelist_user_content": "Registered domain is reputable, but this subdomain is user content (e.g. <user>.github.io) — reputation does NOT extend here.",
        # Score contributors (embedded in the verdict summary)
        "sc_brand": "Brand impersonation ({brands})",
        "sc_threat_db": "Known-threat database match",
        "sc_domain_age": "Domain age ({days} days)",
        "sc_missing_ssl": "Missing SSL certificate",
        "sc_high_entropy": "High URL entropy",
        "sc_ip_in_url": "IP address in URL",
        "sc_subdomains": "{count} subdomain levels",
        "sc_keywords": "{count} phishing keyword(s)",
        "sc_suspicious_tld": "Suspicious TLD (.{tld})",
        "sc_cross_redirect": "Cross-domain redirect",
        # Verdict summaries
        "summary_phishing": "{head} triggered the highest alert",
        "summary_phishing_more": ", compounded by {factor}",
        "summary_phishing_none": "Multiple analysis engines converged on a phishing classification — no single dominant factor identified.",
        "summary_suspicious": "{head} raises concern",
        "summary_suspicious_more": ", together with {factor}",
        "summary_suspicious_none": "Some signals warrant verification before interaction — score: {score:.0f}/100.",
        "summary_safe_engines": "All {n} analysis engines returned benign — no phishing indicators detected.",
        "summary_safe": "No phishing indicators detected.",
        # Recommendations
        "rec_phishing_1": "Do not enter any personal information on this page",
        "rec_phishing_2": "Report the URL to your security team or email provider",
        "rec_phishing_3": "If this arrived via email, mark the sender as phishing",
        "rec_suspicious_1": "Verify the URL manually by typing the official domain directly",
        "rec_suspicious_2": "Avoid entering credentials unless you are certain of the destination",
        "rec_suspicious_3": "If unsure, contact the organization through official channels",
        "rec_safe": "No immediate action required",
        "rec_upload_html": "Upload the HTML content for deeper DOM-based behavioral analysis",
        "rec_verify_owner": "Verify that {reg} is authorized to host the service you expect",
        # Reputation trend
        "trend_same": "risk score consistent with this scan",
        "trend_diff": "previous scans show different risk levels",
        # Subdomain parent verdict
        "parent_safe": "safe",
        "parent_suspicious": "may be compromised or used for phishing",
    },
    "vi": {
        # Findings
        "brand_impersonation": "Phát hiện giả mạo thương hiệu: {brands}",
        "suspicious_tld": "Phần mở rộng TLD đáng ngờ (.{tld}) thường bị các chiến dịch phishing lạm dụng",
        "no_dns": "Tên miền không có bản ghi DNS — đặc trưng của các tên miền phishing mới đăng ký",
        "young_domain": "Tên miền mới đăng ký {days} ngày trước — đặc điểm phổ biến của phishing",
        "old_domain": "Tên miền đã tồn tại {years} năm — giảm khả năng có ý đồ xấu",
        "low_ttl": "TTL thấp ({ttl}s) cho thấy hạ tầng CDN hoặc cân bằng tải",
        "ssl_valid": "Chứng chỉ HTTPS hợp lệ từ nhà phát hành đáng tin cậy — tín hiệu tích cực",
        "ssl_invalid": "Không có chứng chỉ SSL hợp lệ — bất thường đối với dịch vụ hợp pháp",
        "privacy_protected": "Đã bật bảo vệ quyền riêng tư WHOIS — phổ biến nhưng có thể che giấu người đăng ký độc hại",
        "high_entropy": "Độ entropy URL cao ({entropy:.1f}) gợi ý chuỗi ngẫu nhiên/che giấu",
        "ip_url": "URL dùng địa chỉ IP thay vì tên miền — dịch vụ hợp pháp hiếm khi làm vậy",
        "long_url": "URL dài bất thường ({length} ký tự) — thường dùng để che giấu ý đồ xấu",
        "many_subdomains": "{count} cấp subdomain khiến tên miền thật khó nhận diện hơn",
        "phishing_keywords": "URL chứa {count} từ khóa liên quan bảo mật ({keywords}) thường dùng trong phishing",
        "shortener": "Dịch vụ rút gọn URL có thể chuyển hướng đến các đích tùy ý",
        "cross_domain_redirect": "URL chuyển hướng đến tên miền khác ({dest}) — hãy xác minh tính hợp pháp của đích",
        "redirect_to_reputable": "URL chuyển hướng đến {dest}, một tên miền uy tín đã biết — đã ghi nhận uy tín của đích, nhưng bản thân việc chuyển hướng vẫn cần thận trọng",
        "no_html": "Không có nội dung HTML để phân tích — các tín hiệu hành vi không khả dụng",
        "reputation_known": "Tên miền đã được quét {n} lần trước đó (điểm trung bình: {avg:.0f}/100) — {trend}",
        "subdomain_warning": "Subdomain \"{sub}\" trên tên miền đã đăng ký \"{reg}\" — tên miền cha {parent_verdict}",
        "reputable_asn": "Lưu trữ trên {asn} (nhà cung cấp uy tín) — giảm rủi ro",
        "risky_asn": "Lưu trữ trên {desc} — phổ biến trong các chiến dịch phishing",
        "engine_consensus": "{n}/{total} công cụ phân tích đồng thuận: {verdict}",
        "engine_split": "Các công cụ không đồng thuận: {ai}, {dns}, {url}, {brand}",
        "known_threat": "URL/tên miền nằm trong cơ sở dữ liệu mối đe dọa (nguồn: {source}) — từng được báo cáo là phishing",
        "all_engines_safe": "Cả {n} công cụ phân tích đều coi URL này an toàn",
        "whitelist_subdomain_trusted": "Tên miền đã đăng ký là tên miền uy tín đã biết (nguồn: {source}) — vẫn thực hiện phân tích đầy đủ; uy tín chỉ làm giảm ước tính rủi ro.",
        "whitelist_user_content": "Tên miền đã đăng ký uy tín, nhưng subdomain này là nội dung người dùng (ví dụ <user>.github.io) — uy tín KHÔNG áp dụng ở đây.",
        # Score contributors
        "sc_brand": "Giả mạo thương hiệu ({brands})",
        "sc_threat_db": "Khớp cơ sở dữ liệu mối đe dọa",
        "sc_domain_age": "Tuổi tên miền ({days} ngày)",
        "sc_missing_ssl": "Thiếu chứng chỉ SSL",
        "sc_high_entropy": "Entropy URL cao",
        "sc_ip_in_url": "Địa chỉ IP trong URL",
        "sc_subdomains": "{count} cấp subdomain",
        "sc_keywords": "{count} từ khóa phishing",
        "sc_suspicious_tld": "TLD đáng ngờ (.{tld})",
        "sc_cross_redirect": "Chuyển hướng chéo tên miền",
        # Verdict summaries
        "summary_phishing": "{head} đã kích hoạt mức cảnh báo cao nhất",
        "summary_phishing_more": ", cùng với {factor}",
        "summary_phishing_none": "Nhiều công cụ phân tích cùng kết luận phishing — không có yếu tố đơn lẻ nào nổi trội.",
        "summary_suspicious": "{head} gây mối lo ngại",
        "summary_suspicious_more": ", cùng với {factor}",
        "summary_suspicious_none": "Một số tín hiệu cần xác minh trước khi tương tác — điểm: {score:.0f}/100.",
        "summary_safe_engines": "Cả {n} công cụ phân tích đều trả kết quả lành tính — không phát hiện dấu hiệu phishing.",
        "summary_safe": "Không phát hiện dấu hiệu phishing.",
        # Recommendations
        "rec_phishing_1": "Không nhập bất kỳ thông tin cá nhân nào trên trang này",
        "rec_phishing_2": "Báo cáo URL cho đội ngũ bảo mật hoặc nhà cung cấp email",
        "rec_phishing_3": "Nếu URL này đến qua email, hãy đánh dấu người gửi là phishing",
        "rec_suspicious_1": "Xác minh URL thủ công bằng cách nhập trực tiếp tên miền chính thức",
        "rec_suspicious_2": "Tránh nhập thông tin đăng nhập trừ khi bạn chắc chắn về đích",
        "rec_suspicious_3": "Nếu không chắc chắn, hãy liên hệ tổ chức qua kênh chính thức",
        "rec_safe": "Không cần hành động ngay",
        "rec_upload_html": "Tải lên nội dung HTML để phân tích hành vi DOM sâu hơn",
        "rec_verify_owner": "Xác minh rằng {reg} được ủy quyền lưu trữ dịch vụ bạn mong đợi",
        # Reputation trend
        "trend_same": "điểm rủi ro khớp với lần quét này",
        "trend_diff": "các lần quét trước cho thấy mức rủi ro khác",
        # Subdomain parent verdict
        "parent_safe": "an toàn",
        "parent_suspicious": "có thể bị xâm phạm hoặc dùng để phishing",
    },
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


def _fmt(tmpl: str, **kw) -> str:
    """Fill {placeholders}. Uses positional-safe formatting (no .format crash
    on stray braces) by replacing tokens individually."""
    for k, v in kw.items():
        tmpl = tmpl.replace("{" + k + "}", str(v))
    return tmpl


def generate_explanation(result: dict, lang: str = "en") -> dict:
    """Generate natural language explanation from analysis result.

    ``lang`` selects the template language (``"en"`` or ``"vi"``). Technical
    values embedded into the text (domains, brands, scores, ASNs, TLDs) are
    never translated.
    """
    T = LANG.get(lang, LANG["en"])
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
        findings.append(_fmt(T["engine_consensus"], n=phishing_count, total=total_engines, verdict="phishing"))
    elif safe_count == total_engines:
        findings.append(_fmt(T["all_engines_safe"], n=total_engines))
    elif phishing_count > 0 and safe_count > 0:
        ai_v = engine_verdicts.get("ai_model", "n/a")
        dns_v = engine_verdicts.get("dns_infrastructure", "n/a")
        url_v = engine_verdicts.get("url_pattern", "n/a")
        br_v = engine_verdicts.get("brand", "n/a")
        findings.append(_fmt(T["engine_split"], ai=ai_v, dns=dns_v, url=url_v, brand=br_v))

    # Brand impersonation
    has_brand = brand.get("has_brand_impersonation", False)
    if has_brand:
        brands = brand.get("brands_detected", [])
        findings.append(_fmt(T["brand_impersonation"], brands=", ".join(brands[:3])))
        score_contributors.append(_fmt(T["sc_brand"], brands=", ".join(brands[:2])))

    # Known-threat database hit (strong signal)
    threat_match = result.get("threat_match")
    if threat_match and threat_match.get("matched"):
        findings.append(_fmt(
            T["known_threat"],
            source=threat_match.get("source") or threat_match.get("layer", "unknown"),
        ))
        score_contributors.append(T["sc_threat_db"])

    # Subdomain note
    if sub_info:
        parent_verdict = T["parent_safe"] if safe_count == total_engines else T["parent_suspicious"]
        findings.append(_fmt(
            T["subdomain_warning"],
            sub=sub_info["subdomain"], reg=sub_info["registered_domain"],
            parent_verdict=parent_verdict,
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
                findings.append(T["no_dns"])
            else:
                pass  # subdomain without records, handled by subdomain_warning
        if domain_age > 0:
            if domain_age < 30:
                findings.append(_fmt(T["young_domain"], days=domain_age))
                score_contributors.append(_fmt(T["sc_domain_age"], days=domain_age))
            elif domain_age >= 365:
                findings.append(_fmt(T["old_domain"], years=domain_age // 365))
        if ttl_val >= 0 and ttl_val < 300 and a_count >= 2:
            findings.append(_fmt(T["low_ttl"], ttl=ttl_val))
        if privacy == 1:
            findings.append(T["privacy_protected"])
        if asn_desc:
            from api.engines import REPUTABLE_ASNS, RISKY_ASN_KEYWORDS
            asn = str(dns.get("asn", ""))
            desc_lower = asn_desc.lower()
            if asn in REPUTABLE_ASNS:
                findings.append(_fmt(T["reputable_asn"], asn=asn_desc.split("/")[0][:40]))
            elif any(kw in desc_lower for kw in RISKY_ASN_KEYWORDS):
                findings.append(_fmt(T["risky_asn"], desc=asn_desc.split("/")[0][:40]))

    # SSL signals
    if ssl:
        ssl_valid = ssl.get("ssl_valid", -1)
        if ssl_valid == 1:
            findings.append(T["ssl_valid"])
        else:
            findings.append(T["ssl_invalid"])
            score_contributors.append(T["sc_missing_ssl"])

    # URL features
    if features:
        entropy = features.get("entropy", 0)
        if entropy > 4.5:
            findings.append(_fmt(T["high_entropy"], entropy=entropy))
            score_contributors.append(T["sc_high_entropy"])
        has_ip = features.get("has_ip_address", 0)
        if has_ip:
            findings.append(T["ip_url"])
            score_contributors.append(T["sc_ip_in_url"])
        url_len = features.get("url_length", 0)
        if url_len > 100:
            findings.append(_fmt(T["long_url"], length=url_len))
        sub_count = features.get("subdomain_count", 0)
        if sub_count > 2:
            findings.append(_fmt(T["many_subdomains"], count=sub_count))
            score_contributors.append(_fmt(T["sc_subdomains"], count=sub_count))
        keywords = features.get("suspicious_keywords", 0)
        if keywords > 0:
            kw_list = ["login", "verify", "secure", "account", "update", "confirm", "password", "banking", "payment"]
            found = [kw for kw in kw_list if kw in url.lower() or kw in path.lower()]
            findings.append(_fmt(
                T["phishing_keywords"],
                count=int(keywords), keywords=", ".join(found[:4]),
            ))
            score_contributors.append(_fmt(T["sc_keywords"], count=int(keywords)))
        is_short = result.get("is_shortener", False)
        if is_short:
            findings.append(T["shortener"])

    # Suspicious TLD
    susp_tld = result.get("suspicious_tld", 0)
    if susp_tld:
        findings.append(_fmt(T["suspicious_tld"], tld=tld))
        score_contributors.append(_fmt(T["sc_suspicious_tld"], tld=tld))

    # Redirect analysis
    cr = ssl.get("cross_domain_redirect", -1) if ssl else -1
    expanded_url = result.get("expanded_url") or result.get("effective_url") or ""
    if cr == 1 and expanded_url:
        from api.whitelist import get_domain_status as _wl_status
        from api.utils import get_registered_domain as _get_rd
        final_domain = _get_rd(expanded_url)
        if final_domain and _wl_status(expanded_url, final_domain).get("known_reputable_domain"):
            findings.append(_fmt(T["redirect_to_reputable"], dest=final_domain))
        else:
            findings.append(_fmt(T["cross_domain_redirect"], dest=expanded_url[:60]))
            score_contributors.append(T["sc_cross_redirect"])

    # Reputation / whitelist signal (never a verdict on its own)
    if whitelist_status.get("known_reputable_domain"):
        if whitelist_status.get("subdomain_trusted"):
            source = whitelist_status.get("source", "unknown")
            findings.append(_fmt(T["whitelist_subdomain_trusted"], source=source))
        else:
            findings.append(T["whitelist_user_content"])

    # HTML analysis
    html_provided = result.get("html_provided", False)
    if not html_provided:
        findings.append(T["no_html"])

    # Reputation
    if reputation and reputation.get("scans", 0) > 0:
        avg = reputation.get("avg_score", 0)
        n = reputation.get("scans", 0)
        trend = T["trend_same"] if abs(avg - aggregate_score) < 15 else T["trend_diff"]
        findings.append(_fmt(T["reputation_known"], n=n, avg=avg, trend=trend))

    # Build verdict summary: focus on WHY, not WHAT (gauge already shows the verdict)
    if final_verdict == "phishing":
        reasons = score_contributors[:3]
        if reasons:
            head = reasons[0][0].upper() + reasons[0][1:]
            summary = _fmt(T["summary_phishing"], head=head)
            if len(reasons) > 1:
                summary += _fmt(T["summary_phishing_more"], factor=reasons[1].lower())
            summary += "."
        else:
            summary = T["summary_phishing_none"]
    elif final_verdict == "suspicious":
        reasons = score_contributors[:2]
        if reasons:
            head = reasons[0][0].upper() + reasons[0][1:]
            summary = _fmt(T["summary_suspicious"], head=head)
            if len(reasons) > 1:
                summary += _fmt(T["summary_suspicious_more"], factor=reasons[1].lower())
            summary += "."
        else:
            summary = _fmt(T["summary_suspicious_none"], score=aggregate_score)
    else:
        if total_engines > 0:
            summary = _fmt(T["summary_safe_engines"], n=total_engines)
        else:
            summary = T["summary_safe"]

    # Recommendations
    if final_verdict == "phishing":
        recs = [T["rec_phishing_1"], T["rec_phishing_2"], T["rec_phishing_3"]]
    elif final_verdict == "suspicious":
        recs = [T["rec_suspicious_1"], T["rec_suspicious_2"], T["rec_suspicious_3"]]
    else:
        recs = [T["rec_safe"]]
    if not html_provided and final_verdict != "safe":
        recs.append(T["rec_upload_html"])
    if sub_info and final_verdict != "safe":
        recs.append(_fmt(T["rec_verify_owner"], reg=sub_info["registered_domain"]))

    return {
        "verdict_summary": summary,
        "key_findings": findings[:6],
        "risk_factors": score_contributors[:4],
        "recommendations": recs[:4],
    }
