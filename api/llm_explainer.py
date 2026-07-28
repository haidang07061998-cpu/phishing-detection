import json
import traceback
import urllib.request
import urllib.error

OLLAMA_URL = "http://localhost:11434"
OLLAMA_MODEL = "llama3.2:3b"


def _v(val, missing="N/A"):
    """Return value or N/A marker."""
    if val is None:
        return missing
    if isinstance(val, (int, float)) and val == -1:
        return missing
    if isinstance(val, str) and val == "":
        return missing
    return str(val)


def _build_context(result: dict) -> str:
    lines = []
    lines.append(f"URL: {result.get('url', 'N/A')}")
    score = result.get("aggregate_score", 0)
    lines.append(f"Risk Score: {score}/100")
    verdict = "phishing" if score >= 60 else "suspicious" if score >= 30 else "safe"
    lines.append(f"Verdict: {verdict}")

    # Availability flags — LLM must respect these
    html_provided = result.get("html_provided", False)
    lines.append(f"HTML Content: {'AVAILABLE' if html_provided else 'NOT PROVIDED'}")

    dns = result.get("dns_whois") or {}
    has_dns = dns.get("a_record_count", -1) >= 0
    lines.append(f"DNS Data: {'AVAILABLE' if has_dns else 'NOT AVAILABLE'}")

    ssl = result.get("ssl_redirect") or {}
    has_ssl = ssl.get("ssl_valid", -1) >= 0
    lines.append(f"SSL Data: {'AVAILABLE' if has_ssl else 'NOT AVAILABLE'}")

    exp = result.get("explanation") or {}
    if exp.get("key_findings"):
        lines.append(f"Key Findings: {'; '.join(exp['key_findings'])}")
    if exp.get("risk_factors"):
        lines.append(f"Risk Factors: {'; '.join(exp['risk_factors'])}")

    brand = result.get("brand_analysis") or {}
    if brand.get("has_brand_impersonation"):
        lines.append(f"Brand Impersonation: {', '.join(brand.get('brands_detected', []))}")
    else:
        lines.append("Brand Impersonation: none detected")

    sub = result.get("subdomain_info")
    if sub:
        lines.append(f"Subdomain: '{sub['subdomain']}' on '{sub['registered_domain']}'")
    else:
        lines.append("Subdomain: none")

    lines.append(f"DNS A-records: {_v(dns.get('a_record_count'))}, MX-records: {_v(dns.get('mx_record_count'))}")
    lines.append(f"Domain Age: {_v(dns.get('domain_age_days'))} days")
    lines.append(f"ASN: {_v(dns.get('asn_description', ''))}")

    lines.append(f"SSL Valid: {_v(ssl.get('ssl_valid'))}, Redirect Count: {_v(ssl.get('redirect_count'))}")

    feats = result.get("features") or {}
    lines.append(f"URL Length: {_v(feats.get('url_length'))}, Entropy: {_v(feats.get('entropy'))}")
    lines.append(f"Suspicious Keywords: {_v(feats.get('suspicious_keywords'))}, Subdomain Count: {_v(feats.get('subdomain_count'))}")

    lines.append(f"Whitelisted: {result.get('whitelisted', False)}")

    engines = result.get("engine_results", {}).get("engines", {})
    for name, data in engines.items():
        lines.append(f"Engine '{name}': {data.get('verdict', '?')} (score={data.get('score', '?')})")

    return "\n".join(lines)


def _ollama_available() -> bool:
    try:
        req = urllib.request.Request(f"{OLLAMA_URL}/api/tags", method="GET")
        urllib.request.urlopen(req, timeout=2)
        return True
    except Exception:
        return False


def _explain_ollama(context: str, question: str) -> str | None:
    try:
        prompt = (
            "You are a phishing detection AI assistant. You MUST follow these rules:\n"
            "1. ONLY use data explicitly listed in SCAN RESULTS below.\n"
            "2. NEVER make up or infer data that is not present.\n"
            "3. If a field says N/A or NOT AVAILABLE, state that the data could not be retrieved.\n"
            "4. If HTML, DNS, or SSL is NOT AVAILABLE, acknowledge the limitation in your answer.\n"
            "5. Be concise: answer in 2-3 sentences. Do not repeat the question.\n\n"
            f"SCAN RESULTS:\n{context}\n\n"
            f"USER QUESTION: {question}\n\n"
            "ANSWER:"
        )
        body = json.dumps({
            "model": OLLAMA_MODEL, "prompt": prompt, "stream": False,
            "options": {"num_predict": 300, "temperature": 0.2},
        }).encode()
        req = urllib.request.Request(
            f"{OLLAMA_URL}/api/generate", data=body,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        resp = urllib.request.urlopen(req, timeout=60)
        data = json.loads(resp.read().decode())
        return data.get("response", "").strip() or None
    except Exception:
        traceback.print_exc()
        return None


def explain(result: dict, question: str) -> str | None:
    if not _ollama_available():
        return None
    return _explain_ollama(_build_context(result), question)
